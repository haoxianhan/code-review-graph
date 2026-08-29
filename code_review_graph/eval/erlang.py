"""Read-only evaluation support for the Erlang ``server_flexible`` corpus.

The evaluator deliberately treats the target repository as an external input.
It reads Git metadata, generated-data markers, and tool versions, but never
executes a project configuration script or a project build task.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = 1
MANIFEST_KIND = "erlang_evaluation_manifest"
CORPUS_KIND = "erlang_evaluation_corpus"
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
GENERATED_REV_RE = re.compile(r"DATA_REV=(?P<value>[^\n\r]+)")
GENERATED_TIME_RE = re.compile(r'DATA_COMMIT_TIME="(?P<value>[^"]+)"')
GENERATED_AUTHOR_RE = re.compile(r'DATA_AUTHOR="(?P<value>[^"]*)"')
GENERATED_MESSAGE_RE = re.compile(r'DATA_MESSAGE="(?P<value>.*)"')
CFG_REV_RE = re.compile(r'data_revision\s*=>\s*"(?P<value>[^"]+)"')
CFG_VERSION_RE = re.compile(r'cfg_version\s*=>\s*"(?P<value>[^"]+)"')
SVN_TIME_RE = re.compile(r'svn_revision\s*=>\s*<<"(?P<value>[^"]+)"')
OTP_PATH_RE = re.compile(r"^\s*otp_path\s*:\s*[\"'](?P<value>[^\"']+)", re.MULTILINE)

REQUIRED_MANIFEST_KEYS = {
    "schema_version",
    "kind",
    "target",
    "revision",
    "dependencies",
    "generated_data",
    "toolchain",
    "evaluation",
}
REQUIRED_CORPUS_KEYS = {"schema_version", "kind", "manifest", "cases", "metrics"}
CASE_CATEGORIES = {
    "local_callers",
    "remote_callers",
    "shared_header_records",
    "behaviour_callbacks",
    "supervisor_mfa",
    "common_test",
    "eunit",
    "generated_data",
    "dynamic_unresolved",
    "fallback_unavailable",
    "stale_cache",
}
DIAGNOSTIC_SEVERITIES = {"info", "warning", "error"}
TOOL_STATUSES = {
    "available",
    "available_via_rebar3",
    "not_checked",
    "unavailable",
}

MODULE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = MODULE_ROOT / "evaluate" / "erlang" / "server_flexible.manifest.json"
DEFAULT_CORPUS = MODULE_ROOT / "evaluate" / "erlang" / "corpus.json"


def _error(source: str, message: str) -> ValueError:
    return ValueError(f"{source}: {message}")


def _mapping(value: object, source: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(source, "expected an object")
    return value


def _string(value: object, source: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        expectation = "non-empty string" if nonempty else "string"
        raise _error(source, f"expected {expectation}")
    return value


def _list(value: object, source: str) -> list[Any]:
    if not isinstance(value, list):
        raise _error(source, "expected an array")
    return value


def _sha(value: object, source: str, *, full: bool = False) -> str:
    result = _string(value, source)
    pattern = HEX_SHA_RE if full else SHA_RE
    if not pattern.fullmatch(result):
        raise _error(source, "expected a hexadecimal Git revision")
    return result


def _validate_diagnostics(value: object, source: str) -> None:
    for index, item in enumerate(_list(value, source)):
        diagnostic = _mapping(item, f"{source}[{index}]")
        _string(diagnostic.get("code"), f"{source}[{index}].code")
        severity = _string(diagnostic.get("severity"), f"{source}[{index}].severity")
        if severity not in DIAGNOSTIC_SEVERITIES:
            raise _error(f"{source}[{index}].severity", f"unsupported value {severity!r}")
        _string(diagnostic.get("message"), f"{source}[{index}].message")


def validate_manifest(manifest: object, source: str = "<manifest>") -> None:
    """Validate the checked-in manifest contract.

    Validation is intentionally strict for identity and provenance fields. It
    is permissive for additive metadata so future tool adapters can extend the
    manifest without making older evaluators unable to read it.
    """

    document = _mapping(manifest, source)
    missing = REQUIRED_MANIFEST_KEYS - set(document)
    if missing:
        raise _error(source, f"missing keys: {', '.join(sorted(missing))}")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise _error(source, f"unsupported schema_version {document.get('schema_version')!r}")
    if document.get("kind") != MANIFEST_KIND:
        raise _error(source, f"expected kind {MANIFEST_KIND!r}")

    target = _mapping(document["target"], f"{source}.target")
    _string(target.get("name"), f"{source}.target.name")
    _string(target.get("path"), f"{source}.target.path")
    _string(target.get("remote"), f"{source}.target.remote")

    revision = _mapping(document["revision"], f"{source}.revision")
    _sha(revision.get("requested"), f"{source}.revision.requested")
    _sha(revision.get("observed"), f"{source}.revision.observed")
    if not isinstance(revision.get("working_tree_clean"), bool):
        raise _error(f"{source}.revision.working_tree_clean", "expected boolean")
    baseline_status = _string(revision.get("baseline_status"), f"{source}.revision.baseline_status")
    if baseline_status not in {"clean", "non_clean", "unavailable"}:
        raise _error(f"{source}.revision.baseline_status", "unsupported baseline status")
    dirty_paths = _list(revision.get("dirty_paths", []), f"{source}.revision.dirty_paths")
    for index, path in enumerate(dirty_paths):
        _string(path, f"{source}.revision.dirty_paths[{index}]")
    if revision["working_tree_clean"] and dirty_paths:
        raise _error(source, "clean working tree cannot contain dirty_paths")
    if baseline_status == "clean" and not revision["working_tree_clean"]:
        raise _error(source, "clean baseline must have a clean working tree")

    dependencies = _mapping(document["dependencies"], f"{source}.dependencies")
    for index, lockfile in enumerate(
        _list(dependencies.get("lockfiles", []), f"{source}.dependencies.lockfiles")
    ):
        lock = _mapping(lockfile, f"{source}.dependencies.lockfiles[{index}]")
        _string(lock.get("path"), f"{source}.dependencies.lockfiles[{index}].path")
        digest = _string(lock.get("sha256"), f"{source}.dependencies.lockfiles[{index}].sha256")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise _error(f"{source}.dependencies.lockfiles[{index}].sha256", "expected SHA-256")
    for index, item in enumerate(
        _list(dependencies.get("submodules", []), f"{source}.dependencies.submodules")
    ):
        submodule = _mapping(item, f"{source}.dependencies.submodules[{index}]")
        _string(submodule.get("path"), f"{source}.dependencies.submodules[{index}].path")
        _sha(
            submodule.get("gitlink_revision"),
            f"{source}.dependencies.submodules[{index}].gitlink_revision",
            full=True,
        )
        _sha(
            submodule.get("checkout_revision"),
            f"{source}.dependencies.submodules[{index}].checkout_revision",
            full=True,
        )
        if not isinstance(submodule.get("working_tree_clean"), bool):
            raise _error(
                f"{source}.dependencies.submodules[{index}].working_tree_clean",
                "expected boolean",
            )

    generated = _mapping(document["generated_data"], f"{source}.generated_data")
    _string(generated.get("revision"), f"{source}.generated_data.revision")
    _string(generated.get("config_version"), f"{source}.generated_data.config_version")
    for index, item in enumerate(
        _list(generated.get("paths", []), f"{source}.generated_data.paths")
    ):
        _string(item, f"{source}.generated_data.paths[{index}]")

    toolchain = _mapping(document["toolchain"], f"{source}.toolchain")
    tools = _mapping(toolchain.get("tools"), f"{source}.toolchain.tools")
    if not tools:
        raise _error(f"{source}.toolchain.tools", "must not be empty")
    for name, item in tools.items():
        tool = _mapping(item, f"{source}.toolchain.tools.{name}")
        command = _list(tool.get("command"), f"{source}.toolchain.tools.{name}.command")
        if not command:
            raise _error(f"{source}.toolchain.tools.{name}.command", "must not be empty")
        for index, token in enumerate(command):
            _string(token, f"{source}.toolchain.tools.{name}.command[{index}]")
        status = _string(tool.get("status"), f"{source}.toolchain.tools.{name}.status")
        if status not in TOOL_STATUSES:
            raise _error(f"{source}.toolchain.tools.{name}.status", "unsupported tool status")
    configuration = _mapping(toolchain.get("configuration"), f"{source}.toolchain.configuration")
    for index, item in enumerate(
        _list(configuration.get("files", []), f"{source}.toolchain.configuration.files")
    ):
        _string(item, f"{source}.toolchain.configuration.files[{index}]")
    if configuration.get("execute_during_discovery") is not False:
        raise _error(
            f"{source}.toolchain.configuration.execute_during_discovery",
            "must be false",
        )

    _mapping(document["evaluation"], f"{source}.evaluation")
    _validate_diagnostics(document.get("diagnostics", []), f"{source}.diagnostics")


def _validate_endpoint(value: object, source: str) -> None:
    if isinstance(value, str):
        if not value:
            raise _error(source, "endpoint string must not be empty")
        return
    endpoint = _mapping(value, source)
    if "file" in endpoint:
        path = _string(endpoint["file"], f"{source}.file")
        if Path(path).is_absolute() or "\\" in path:
            raise _error(f"{source}.file", "must be repository-relative POSIX path")
    if "symbol" in endpoint:
        _string(endpoint["symbol"], f"{source}.symbol")
    if "arity" in endpoint and (
        not isinstance(endpoint["arity"], int) or isinstance(endpoint["arity"], bool)
    ):
        raise _error(f"{source}.arity", "expected integer")


def _validate_relation(value: object, source: str) -> None:
    relation = _mapping(value, source)
    _string(relation.get("relation"), f"{source}.relation")
    if "source" in relation:
        _validate_endpoint(relation["source"], f"{source}.source")
    if "target" in relation:
        _validate_endpoint(relation["target"], f"{source}.target")
    if "reason" in relation:
        _string(relation["reason"], f"{source}.reason")


def validate_corpus(corpus: object, source: str = "<corpus>") -> None:
    """Validate corpus case shape and reject machine-specific source paths."""

    document = _mapping(corpus, source)
    missing = REQUIRED_CORPUS_KEYS - set(document)
    if missing:
        raise _error(source, f"missing keys: {', '.join(sorted(missing))}")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise _error(source, f"unsupported schema_version {document.get('schema_version')!r}")
    if document.get("kind") != CORPUS_KIND:
        raise _error(source, f"expected kind {CORPUS_KIND!r}")
    _string(document.get("manifest"), f"{source}.manifest")
    cases = _list(document["cases"], f"{source}.cases")
    if not cases:
        raise _error(f"{source}.cases", "must not be empty")
    ids: set[str] = set()
    for index, item in enumerate(cases):
        case_source = f"{source}.cases[{index}]"
        case = _mapping(item, case_source)
        case_id = _string(case.get("id"), f"{case_source}.id")
        if case_id in ids:
            raise _error(f"{case_source}.id", f"duplicate case id {case_id!r}")
        ids.add(case_id)
        category = _string(case.get("category"), f"{case_source}.category")
        if category not in CASE_CATEGORIES:
            raise _error(f"{case_source}.category", f"unsupported category {category!r}")
        _string(case.get("description"), f"{case_source}.description")
        query = _mapping(case.get("query"), f"{case_source}.query")
        _string(query.get("kind"), f"{case_source}.query.kind")
        _validate_endpoint(query.get("target"), f"{case_source}.query.target")
        expected = _mapping(case.get("expected"), f"{case_source}.expected")
        for relation_kind in ("positive", "negative", "unresolved"):
            relations = _list(
                expected.get(relation_kind, []), f"{case_source}.expected.{relation_kind}"
            )
            for relation_index, relation in enumerate(relations):
                _validate_relation(
                    relation, f"{case_source}.expected.{relation_kind}[{relation_index}]"
                )
        review = _mapping(case.get("review"), f"{case_source}.review")
        _string(review.get("status"), f"{case_source}.review.status")
        _string(review.get("reviewer"), f"{case_source}.review.reviewer")
        if "required_diagnostics" in case:
            for diagnostic_index, code in enumerate(
                _list(case["required_diagnostics"], f"{case_source}.required_diagnostics")
            ):
                _string(code, f"{case_source}.required_diagnostics[{diagnostic_index}]")
    _mapping(document["metrics"], f"{source}.metrics")


def _load_json(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise _error(str(path), str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise _error(str(path), f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc


def load_manifest(path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load and validate an Erlang evaluation manifest."""

    manifest_path = Path(path)
    document = _load_json(manifest_path)
    validate_manifest(document, str(manifest_path))
    return dict(document)


def load_corpus(path: str | Path = DEFAULT_CORPUS) -> dict[str, Any]:
    """Load and validate the checked-in golden corpus scaffold."""

    corpus_path = Path(path)
    document = _load_json(corpus_path)
    validate_corpus(document, str(corpus_path))
    return dict(document)


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat(timespec="seconds")


def _short_output(value: str, limit: int = 4096) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Run a bounded, argv-based command and preserve its diagnostics."""

    argv = [str(token) for token in command]
    result: dict[str, Any] = {
        "command": argv,
        "cwd": str(cwd) if cwd is not None else None,
    }
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        result.update({"returncode": None, "stdout": "", "stderr": str(exc), "error": "not_found"})
        return result
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        result.update(
            {
                "returncode": None,
                "stdout": _short_output(stdout),
                "stderr": _short_output(stderr),
                "error": "timeout",
            }
        )
        return result
    result.update(
        {
            "returncode": completed.returncode,
            "stdout": _short_output(completed.stdout),
            "stderr": _short_output(completed.stderr),
        }
    )
    return result


def _diagnostic(code: str, severity: str, message: str, **details: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"code": code, "severity": severity, "message": message}
    if details:
        item["details"] = details
    return item


def _discover_executable(
    name: str,
    version_args: Sequence[str],
    *,
    probe_root: Path,
    timeout: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = shutil.which(name)
    tool: dict[str, Any] = {
        "command": [name, *version_args],
        "path": path,
        "status": "available" if path else "unavailable",
        "version": None,
        "probe": None,
    }
    diagnostics: list[dict[str, Any]] = []
    if path is None:
        tool["reason"] = "command_not_found"
        diagnostics.append(
            _diagnostic(
                f"{name}_unavailable",
                "warning",
                f"{name} is not available on PATH; Generic indexing remains usable.",
                command=tool["command"],
            )
        )
        return tool, diagnostics

    probe = _run_command([path, *version_args], cwd=probe_root, timeout=timeout)
    tool["probe"] = probe
    output = (probe.get("stdout", "") or "").strip() or (probe.get("stderr", "") or "").strip()
    tool["version_output"] = output
    tool["version"] = output.splitlines()[0] if output else None
    if probe.get("returncode") != 0:
        tool["status"] = "not_checked"
        diagnostics.append(
            _diagnostic(
                f"{name}_probe_failed",
                "warning",
                f"{name} was found but its bounded version probe failed.",
                command=tool["command"],
                returncode=probe.get("returncode"),
                stderr=probe.get("stderr", ""),
            )
        )
    return tool, diagnostics


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _match_text(pattern: re.Pattern[str], text: str | None) -> str | None:
    if text is None:
        return None
    match = pattern.search(text)
    return match.group("value") if match else None


def _discover_generated_data(
    target_root: Path, expected: Mapping[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    paths = [target_root / str(item) for item in expected.get("paths", [])]
    revision_file = target_root / "tools" / "gen_data" / "data_rev_info"
    structure_file = target_root / "tools" / "gen_data" / "server_cfg_structure_version"
    revision_text = _read_text(revision_file)
    structure_text = _read_text(structure_file)
    generated: dict[str, Any] = {
        "revision": _match_text(GENERATED_REV_RE, revision_text),
        "commit_time": _match_text(GENERATED_TIME_RE, revision_text),
        "author": _match_text(GENERATED_AUTHOR_RE, revision_text),
        "message": _match_text(GENERATED_MESSAGE_RE, revision_text),
        "config_version": _match_text(CFG_VERSION_RE, structure_text),
        "structure_revision": _match_text(CFG_REV_RE, structure_text),
        "structure_timestamp": _match_text(SVN_TIME_RE, structure_text),
        "marker_files": {
            str(path.relative_to(target_root)): path.is_file()
            for path in (revision_file, structure_file)
        },
        "counts": {},
    }
    for path in paths:
        if path.is_dir():
            generated["counts"][str(path.relative_to(target_root))] = sum(
                1 for child in path.rglob("*") if child.is_file()
            )
        else:
            generated["counts"][str(path.relative_to(target_root))] = None

    diagnostics: list[dict[str, Any]] = []
    if generated["revision"] is None or generated["config_version"] is None:
        diagnostics.append(
            _diagnostic(
                "generated_data_markers_unavailable",
                "warning",
                "Generated-data revision markers could not be read.",
                revision_file=str(revision_file),
                structure_file=str(structure_file),
            )
        )
    for key in ("revision", "config_version"):
        observed = generated[key]
        expected_value = expected.get("revision" if key == "revision" else "config_version")
        if observed is not None and observed != expected_value:
            diagnostics.append(
                _diagnostic(
                    "generated_data_revision_mismatch",
                    "warning",
                    f"Generated-data {key} differs from the checked-in manifest.",
                    expected=expected_value,
                    observed=observed,
                )
            )
    return generated, diagnostics


def _parse_status_lines(output: str) -> list[str]:
    paths: list[str] = []
    for line in output.splitlines():
        if not line:
            continue
        value = line[3:] if len(line) >= 3 else line
        if " -> " in value:
            value = value.rsplit(" -> ", 1)[-1]
        paths.append(value)
    return paths


def _discover_submodules(target_root: Path) -> list[dict[str, Any]]:
    result = _run_command(["git", "submodule", "status", "--recursive"], cwd=target_root)
    if result.get("returncode") != 0:
        return []
    submodules: list[dict[str, Any]] = []
    for line in result.get("stdout", "").splitlines():
        match = re.match(r"^(?P<prefix>[ +-U])(?P<revision>[0-9a-fA-F]{40})\s+(?P<path>\S+)", line)
        if not match:
            continue
        path = match.group("path")
        submodule_root = target_root / path
        expected = _run_command(["git", "ls-tree", "HEAD", "--", path], cwd=target_root)
        gitlink = None
        gitlink_match = re.search(r"160000 commit ([0-9a-fA-F]{40})\s+", expected.get("stdout", ""))
        if gitlink_match:
            gitlink = gitlink_match.group(1)
        nested_status = _run_command(
            ["git", "status", "--short", "--untracked-files=all"], cwd=submodule_root
        )
        submodules.append(
            {
                "path": path,
                "gitlink_revision": gitlink,
                "checkout_revision": match.group("revision"),
                "prefix": match.group("prefix"),
                "gitlink_matches_checkout": gitlink == match.group("revision"),
                "working_tree_clean": nested_status.get("returncode") == 0
                and not nested_status.get("stdout", "").strip(),
                "dirty_paths": _parse_status_lines(nested_status.get("stdout", "")),
            }
        )
    return submodules


def _discover_repository(target_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []
    target_root = target_root.expanduser().resolve()
    repository: dict[str, Any] = {
        "path": str(target_root),
        "exists": target_root.is_dir(),
        "top_level": None,
        "revision": None,
        "branch": None,
        "remote": None,
        "working_tree_clean": None,
        "dirty_paths": [],
        "submodules": [],
    }
    if not target_root.is_dir():
        diagnostics.append(
            _diagnostic(
                "target_missing",
                "error",
                "Target repository directory does not exist.",
                path=str(target_root),
            )
        )
        return repository, diagnostics

    top_level_result = _run_command(["git", "rev-parse", "--show-toplevel"], cwd=target_root)
    top_level_text = top_level_result.get("stdout", "").strip()
    if top_level_result.get("returncode") != 0:
        diagnostics.append(
            _diagnostic(
                "target_not_git", "error", "Target directory is not a standalone Git repository."
            )
        )
        return repository, diagnostics
    repository["top_level"] = str(Path(top_level_text).resolve())
    if Path(top_level_text).resolve() != target_root:
        diagnostics.append(
            _diagnostic(
                "target_not_standalone",
                "error",
                "Git resolves the target to an enclosing repository; refusing to inspect it "
                "as a target.",
                resolved_top_level=repository["top_level"],
            )
        )
        return repository, diagnostics

    revision_result = _run_command(["git", "rev-parse", "HEAD"], cwd=target_root)
    repository["revision"] = revision_result.get("stdout", "").strip() or None
    branch_result = _run_command(["git", "symbolic-ref", "--short", "-q", "HEAD"], cwd=target_root)
    repository["branch"] = branch_result.get("stdout", "").strip() or None
    remote_result = _run_command(["git", "remote", "get-url", "origin"], cwd=target_root)
    repository["remote"] = remote_result.get("stdout", "").strip() or None
    status_result = _run_command(
        ["git", "status", "--short", "--untracked-files=all"], cwd=target_root
    )
    repository["dirty_paths"] = _parse_status_lines(status_result.get("stdout", ""))
    repository["working_tree_clean"] = (
        status_result.get("returncode") == 0 and not repository["dirty_paths"]
    )
    repository["submodules"] = _discover_submodules(target_root)
    return repository, diagnostics


def _discover_toolchain(
    target_root: Path,
    manifest_toolchain: Mapping[str, Any],
    *,
    timeout: float,
    probe_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    tools: dict[str, Any] = {}
    diagnostics: list[dict[str, Any]] = []
    probes = {
        "erl": [
            "-noshell",
            "-eval",
            'io:format("otp=~s~nerts=~s~n", '
            '[erlang:system_info(otp_release), erlang:system_info(version)]), halt().',
        ],
        "rebar3": ["version"],
        "dialyzer": ["--version"],
        "elp": ["--version"],
        "erlang_ls": ["--version"],
        "elp-ls": ["--version"],
    }
    for name, args in probes.items():
        tool, tool_diagnostics = _discover_executable(
            name, args, probe_root=probe_root, timeout=timeout
        )
        tools[name] = tool
        diagnostics.extend(tool_diagnostics)

    rebar = tools["rebar3"]
    xref_available = rebar.get("status") == "available"
    tools["xref"] = {
        "command": ["rebar3", "xref"],
        "path": rebar.get("path"),
        "status": "available_via_rebar3" if xref_available else "unavailable",
        "version": None,
        "reason": "xref is a rebar3 task; task execution is disabled during discovery",
    }
    if not xref_available:
        diagnostics.append(
            _diagnostic(
                "xref_unavailable",
                "warning",
                "rebar3 is unavailable, so the configured xref task cannot be invoked.",
                command=["rebar3", "xref"],
            )
        )

    configured_otp_path = None
    config_path = target_root / "erlang_ls.config"
    config_text = _read_text(config_path)
    configured_otp_path = _match_text(OTP_PATH_RE, config_text)
    runtime_output = tools["erl"].get("version_output") or ""
    runtime_otp = None
    runtime_erts = None
    otp_match = re.search(r"otp=(\S+)", runtime_output)
    erts_match = re.search(r"erts=(\S+)", runtime_output)
    if otp_match:
        runtime_otp = otp_match.group(1)
    if erts_match:
        runtime_erts = erts_match.group(1)
    toolchain: dict[str, Any] = {
        "tools": tools,
        "runtime": {
            "otp_release": runtime_otp,
            "erts_version": runtime_erts,
            "configured_otp_path": configured_otp_path,
        },
        "configuration": {
            "files": [
                str(target_root / "rebar.config"),
                str(target_root / "rebar.config.script"),
                str(target_root / "erlang_ls.config"),
                str(target_root / ".elp_lint.toml"),
            ],
            "execute_during_discovery": False,
            "observed": {
                "rebar_config_script_present": (target_root / "rebar.config.script").is_file(),
                "erlang_ls_config_present": config_path.is_file(),
                "elp_lint_config_present": (target_root / ".elp_lint.toml").is_file(),
            },
        },
    }
    if configured_otp_path and runtime_otp:
        configured_match = re.search(r"(?:kerl/)?([0-9]+(?:\.[0-9]+)+)", configured_otp_path)
        if configured_match and not runtime_otp.startswith(configured_match.group(1)):
            diagnostics.append(
                _diagnostic(
                    "otp_config_runtime_mismatch",
                    "warning",
                    "erlang_ls.config points at a different OTP release than the runtime probe.",
                    configured_otp_path=configured_otp_path,
                    runtime_otp_release=runtime_otp,
                )
            )

    expected_tools = manifest_toolchain.get("tools", {})
    if isinstance(expected_tools, Mapping):
        for name, expected_item in expected_tools.items():
            if name not in tools or not isinstance(expected_item, Mapping):
                continue
            current = tools[name]
            expected_status = expected_item.get("status")
            current_status = current.get("status")
            if expected_status == "unavailable" and current_status not in {
                "unavailable",
                "not_checked",
            }:
                diagnostics.append(
                    _diagnostic(
                        "tool_availability_changed",
                        "warning",
                        f"{name} is available now but was unavailable when the manifest "
                        "was observed.",
                        expected=expected_status,
                        observed=current_status,
                    )
                )
            expected_path = expected_item.get("path")
            if expected_path and current.get("path") and expected_path != current.get("path"):
                diagnostics.append(
                    _diagnostic(
                        "tool_path_changed",
                        "warning",
                        f"{name} resolves to a different executable path.",
                        expected=expected_path,
                        observed=current.get("path"),
                    )
                )
    return toolchain, diagnostics


def _compare_manifest_revision(
    repository: Mapping[str, Any], manifest_revision: Mapping[str, Any]
) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    observed = repository.get("revision")
    expected = manifest_revision.get("observed")
    if observed and expected and observed != expected:
        diagnostics.append(
            _diagnostic(
                "git_revision_mismatch",
                "warning",
                "Target HEAD differs from the observed manifest revision.",
                expected=expected,
                observed=observed,
            )
        )
    clean = repository.get("working_tree_clean")
    expected_clean = manifest_revision.get("working_tree_clean")
    if isinstance(clean, bool) and isinstance(expected_clean, bool) and clean != expected_clean:
        diagnostics.append(
            _diagnostic(
                "working_tree_state_changed",
                "warning",
                "Target working-tree cleanliness differs from the manifest.",
                expected=expected_clean,
                observed=clean,
            )
        )
    if clean is False:
        diagnostics.append(
            _diagnostic(
                "target_worktree_dirty",
                "warning",
                "The target checkout is dirty and cannot be adopted as a clean baseline.",
                dirty_paths=repository.get("dirty_paths", []),
            )
        )
    return diagnostics


def _compare_lockfiles(target_root: Path, dependencies: Mapping[str, Any]) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    for item in dependencies.get("lockfiles", []):
        if not isinstance(item, Mapping):
            continue
        relative_path = item.get("path")
        if not isinstance(relative_path, str):
            continue
        path = target_root / relative_path
        if not path.is_file():
            diagnostics.append(
                _diagnostic(
                    "lockfile_missing",
                    "warning",
                    "A manifest lockfile is missing.",
                    path=relative_path,
                )
            )
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != item.get("sha256"):
            diagnostics.append(
                _diagnostic(
                    "lockfile_changed",
                    "warning",
                    "A manifest lockfile changed since observation.",
                    path=relative_path,
                    expected=item.get("sha256"),
                    observed=digest,
                )
            )
    return diagnostics


def _cache_state(target_root: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    cache_paths = manifest.get("analysis", {}).get("cache_paths", [])
    state: list[dict[str, Any]] = []
    for relative_path in cache_paths if isinstance(cache_paths, list) else []:
        if not isinstance(relative_path, str):
            continue
        path = target_root / relative_path
        state.append(
            {
                "path": relative_path,
                "present": path.exists(),
                "kind": "directory" if path.is_dir() else "file" if path.is_file() else None,
                "revision_key": None,
                "status": "unkeyed" if path.exists() else "absent",
            }
        )
    return {"paths": state, "stale_evidence_policy": "reject_revision_mismatch"}


def _corpus_summary(
    corpus: Mapping[str, Any], target_root: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cases = corpus.get("cases", [])
    categories: list[str] = []
    for case in cases:
        if isinstance(case, Mapping) and isinstance(case.get("category"), str):
            categories.append(case["category"])
    categories = sorted(set(categories))
    summary = {
        "case_count": len(cases),
        "case_ids": [case.get("id") for case in cases if isinstance(case, Mapping)],
        "categories": categories,
        "required_categories": sorted(CASE_CATEGORIES),
        "all_required_categories_present": CASE_CATEGORIES.issubset(categories),
    }
    diagnostics: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        paths: set[str] = set()
        query = case.get("query")
        if isinstance(query, Mapping):
            target = query.get("target")
            if isinstance(target, Mapping) and isinstance(target.get("file"), str):
                paths.add(target["file"])
        expected = case.get("expected")
        if isinstance(expected, Mapping):
            for relation_kind in ("positive", "negative", "unresolved"):
                for relation in expected.get(relation_kind, []):
                    if not isinstance(relation, Mapping):
                        continue
                    for endpoint_kind in ("source", "target"):
                        endpoint = relation.get(endpoint_kind)
                        if isinstance(endpoint, Mapping) and isinstance(endpoint.get("file"), str):
                            paths.add(endpoint["file"])
        for relative_path in sorted(paths):
            path = target_root / relative_path
            if not path.is_file():
                diagnostics.append(
                    _diagnostic(
                        "corpus_anchor_missing",
                        "warning",
                        "A corpus anchor does not exist in the target checkout.",
                        case=case.get("id"),
                        path=relative_path,
                    )
                )
    if not summary["all_required_categories_present"]:
        diagnostics.append(
            _diagnostic(
                "corpus_categories_incomplete",
                "warning",
                "The corpus does not cover every planned Erlang evaluation category.",
                missing=sorted(CASE_CATEGORIES - set(categories)),
            )
        )
    return summary, diagnostics


def discover_environment(
    manifest: Mapping[str, Any],
    corpus: Mapping[str, Any],
    *,
    target_root: str | Path | None = None,
    timeout: float = 5.0,
    probe_root: str | Path | None = None,
) -> dict[str, Any]:
    """Discover repository, generated-data, cache, and toolchain state.

    ``probe_root`` is intentionally separate from ``target_root``. Version
    probes run from this controlled directory so a call made inside the target
    checkout cannot accidentally evaluate its ``rebar.config.script``.
    """

    manifest_target = _mapping(manifest["target"], "manifest.target")
    root = Path(target_root or str(manifest_target["path"])).expanduser().resolve()
    safe_probe_root = Path(probe_root or MODULE_ROOT).expanduser().resolve()
    repository, diagnostics = _discover_repository(root)
    generated, generated_diagnostics = _discover_generated_data(
        root, _mapping(manifest["generated_data"], "manifest.generated_data")
    )
    diagnostics.extend(generated_diagnostics)
    toolchain, tool_diagnostics = _discover_toolchain(
        root,
        _mapping(manifest["toolchain"], "manifest.toolchain"),
        timeout=timeout,
        probe_root=safe_probe_root,
    )
    diagnostics.extend(tool_diagnostics)
    diagnostics.extend(
        _compare_manifest_revision(repository, _mapping(manifest["revision"], "manifest.revision"))
    )
    diagnostics.extend(
        _compare_lockfiles(root, _mapping(manifest["dependencies"], "manifest.dependencies"))
    )
    corpus_summary, corpus_diagnostics = _corpus_summary(corpus, root)
    diagnostics.extend(corpus_diagnostics)

    expected_submodules = {
        item.get("path"): item
        for item in _mapping(manifest["dependencies"], "manifest.dependencies").get(
            "submodules", []
        )
        if isinstance(item, Mapping) and isinstance(item.get("path"), str)
    }
    for submodule in repository.get("submodules", []):
        expected = expected_submodules.get(submodule.get("path"))
        if expected and expected.get("gitlink_revision") != submodule.get("gitlink_revision"):
            diagnostics.append(
                _diagnostic(
                    "submodule_gitlink_changed",
                    "warning",
                    "A submodule gitlink differs from the manifest.",
                    path=submodule.get("path"),
                    expected=expected.get("gitlink_revision"),
                    observed=submodule.get("gitlink_revision"),
                )
            )
        if not submodule.get("gitlink_matches_checkout", True):
            diagnostics.append(
                _diagnostic(
                    "submodule_checkout_mismatch",
                    "warning",
                    "A submodule checkout does not match its recorded gitlink.",
                    path=submodule.get("path"),
                    gitlink=submodule.get("gitlink_revision"),
                    checkout=submodule.get("checkout_revision"),
                )
            )

    if (root / "rebar.config.script").is_file():
        diagnostics.append(
            _diagnostic(
                "project_config_script_not_executed",
                "info",
                "rebar.config.script is present; discovery intentionally did not execute it.",
                path="rebar.config.script",
            )
        )

    errors = [item for item in diagnostics if item.get("severity") == "error"]
    adoption_verdict = "not_ready"
    if errors:
        adoption_verdict = "blocked"
    elif repository.get("working_tree_clean") is False:
        adoption_verdict = "not_ready_non_clean_checkout"
    elif any(item.get("severity") == "warning" for item in diagnostics):
        adoption_verdict = "not_ready_with_diagnostics"
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "erlang_evaluation_observation",
        "observed_at": _utc_now(),
        "manifest": str(DEFAULT_MANIFEST),
        "target": {"name": manifest_target.get("name"), "path": str(root)},
        "repository": repository,
        "generated_data": generated,
        "toolchain": toolchain,
        "cache": _cache_state(root, manifest),
        "corpus": corpus_summary,
        "diagnostics": diagnostics,
        "adoption_verdict": adoption_verdict,
        "generic_indexing": "independent_of_semantic_tool_availability",
    }
    return result


def run_evaluation(
    manifest_path: str | Path = DEFAULT_MANIFEST,
    corpus_path: str | Path = DEFAULT_CORPUS,
    *,
    target_root: str | Path | None = None,
    timeout: float = 5.0,
    probe_root: str | Path | None = None,
) -> dict[str, Any]:
    """Load artifacts and return one structured, non-mutating observation."""

    manifest = load_manifest(manifest_path)
    corpus = load_corpus(corpus_path)
    result = discover_environment(
        manifest,
        corpus,
        target_root=target_root,
        timeout=timeout,
        probe_root=probe_root,
    )
    result["manifest"] = str(Path(manifest_path).resolve())
    result["corpus_artifact"] = str(Path(corpus_path).resolve())
    return result


def _human_report(result: Mapping[str, Any]) -> str:
    diagnostics = result.get("diagnostics", [])
    lines = [
        f"target: {result.get('target', {}).get('name')} ({result.get('target', {}).get('path')})",
        f"adoption_verdict: {result.get('adoption_verdict')}",
        f"corpus_cases: {result.get('corpus', {}).get('case_count', 0)}",
        f"diagnostics: {len(diagnostics)}",
    ]
    for item in diagnostics:
        lines.append(f"- [{item.get('severity')}] {item.get('code')}: {item.get('message')}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for the read-only evaluator."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--target-root", type=Path, default=None)
    parser.add_argument("--probe-root", type=Path, default=MODULE_ROOT)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output")
    args = parser.parse_args(argv)
    try:
        result = run_evaluation(
            args.manifest,
            args.corpus,
            target_root=args.target_root,
            timeout=args.timeout,
            probe_root=args.probe_root,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.as_json:
        print(
            json.dumps(result, ensure_ascii=True, indent=2 if args.pretty else None, sort_keys=True)
        )
    else:
        print(_human_report(result))
    return 0


__all__ = [
    "DEFAULT_CORPUS",
    "DEFAULT_MANIFEST",
    "discover_environment",
    "load_corpus",
    "load_manifest",
    "main",
    "run_evaluation",
    "validate_corpus",
    "validate_manifest",
]


if __name__ == "__main__":
    raise SystemExit(main())
