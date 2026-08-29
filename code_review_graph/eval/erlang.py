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
ADAPTER_MANIFEST_SCHEMA_VERSION = 1
ADAPTER_MANIFEST_KIND = "erlang_adapter_manifest"
ERLANG_ADAPTERS = ("generic", "elp", "xref", "dialyzer")
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
DEFAULT_ADAPTER_MANIFEST_DIR = MODULE_ROOT / "evaluate" / "erlang" / "adapters"
DEFAULT_ADAPTER_MANIFESTS = {
    name: DEFAULT_ADAPTER_MANIFEST_DIR / f"{name}.manifest.json"
    for name in ERLANG_ADAPTERS
}

ADAPTER_MANIFEST_REQUIRED_KEYS = {
    "schema_version",
    "kind",
    "adapter",
    "target",
    "activation",
    "contract",
    "invocation",
    "timeout",
    "failure",
    "output",
    "provenance",
    "cache",
    "sandbox",
    "enforcement",
}
ADAPTER_MANIFEST_FAILURE_EVENTS = (
    "missing_tool",
    "nonzero_exit",
    "timeout",
    "malformed_output",
)
ADAPTER_MANIFEST_PROVENANCE_FIELDS = {
    "source",
    "tool",
    "tool_version",
    "otp_version",
    "repository",
    "source_revision",
    "generated_data_revision",
    "configuration_digest",
    "query_kind",
    "query_targets",
    "status",
    "analysis_key",
    "command",
    "duration_seconds",
    "cache_state",
}
ADAPTER_MANIFEST_CACHE_FIELDS = {
    "repository",
    "source_revision",
    "generated_data_revision",
    "configuration_digest",
    "tool",
    "tool_version",
    "otp_version",
    "query_kind",
    "query_targets",
}
ADAPTER_MANIFEST_STATUSES = {
    "ok",
    "optional",
    "unavailable",
    "degraded",
    "failed",
    "malformed",
    "timeout",
    "stale",
    "mismatch",
    "not_applicable",
}


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


def _validate_string_list(value: object, source: str, *, allow_empty: bool = True) -> list[str]:
    """Validate a JSON string array and return its normalized values."""
    values = _list(value, source)
    result: list[str] = []
    for index, item in enumerate(values):
        result.append(_string(item, f"{source}[{index}]"))
    if not allow_empty and not result:
        raise _error(source, "must not be empty")
    return result


def _validate_relative_path(value: object, source: str) -> str:
    path = _string(value, source)
    if Path(path).is_absolute() or "\\" in path:
        raise _error(source, "must be a repository-relative POSIX path or placeholder")
    parts = Path(path).parts
    if ".." in parts:
        raise _error(source, "must not escape the execution workspace")
    return path


def _validate_adapter_failure_event(value: object, source: str) -> None:
    event = _mapping(value, source)
    status = _string(event.get("status"), f"{source}.status")
    if status not in ADAPTER_MANIFEST_STATUSES:
        raise _error(f"{source}.status", f"unsupported adapter status {status!r}")
    codes = _validate_string_list(event.get("diagnostic_codes", []), f"{source}.diagnostic_codes")
    if status not in {"ok", "not_applicable"} and not codes:
        raise _error(f"{source}.diagnostic_codes", "must identify an observable diagnostic")
    _string(event.get("action"), f"{source}.action")
    fallback = event.get("fallback", "generic_graph")
    _string(fallback, f"{source}.fallback")


def validate_adapter_manifest(manifest: object, source: str = "<adapter-manifest>") -> None:
    """Validate one checked-in Erlang adapter execution manifest.

    The manifest is intentionally declarative.  It records the boundary a
    deployment must provide; the current semantic adapters do not load these
    files at runtime, so external adapters explicitly report that policy
    enforcement is caller-owned.
    """

    document = _mapping(manifest, source)
    missing = ADAPTER_MANIFEST_REQUIRED_KEYS - set(document)
    if missing:
        raise _error(source, f"missing keys: {', '.join(sorted(missing))}")
    if document.get("schema_version") != ADAPTER_MANIFEST_SCHEMA_VERSION:
        raise _error(
            source,
            f"unsupported schema_version {document.get('schema_version')!r}",
        )
    if document.get("kind") != ADAPTER_MANIFEST_KIND:
        raise _error(source, f"expected kind {ADAPTER_MANIFEST_KIND!r}")
    adapter = _string(document.get("adapter"), f"{source}.adapter").casefold()
    if adapter not in ERLANG_ADAPTERS:
        raise _error(f"{source}.adapter", f"unsupported adapter {adapter!r}")

    target = _mapping(document["target"], f"{source}.target")
    _string(target.get("name"), f"{source}.target.name")
    scope = _string(target.get("scope"), f"{source}.target.scope")
    if scope not in {"repository_root", "workspace"}:
        raise _error(f"{source}.target.scope", f"unsupported scope {scope!r}")

    activation = _mapping(document["activation"], f"{source}.activation")
    mode = _string(activation.get("mode"), f"{source}.activation.mode")
    if mode not in {"always", "explicit_opt_in", "never"}:
        raise _error(f"{source}.activation.mode", f"unsupported mode {mode!r}")
    if not isinstance(activation.get("required"), bool):
        raise _error(f"{source}.activation.required", "expected boolean")
    _string(activation.get("fallback"), f"{source}.activation.fallback")

    contract = _mapping(document["contract"], f"{source}.contract")
    _string(contract.get("role"), f"{source}.contract.role")
    _validate_string_list(contract.get("evidence_kinds", []), f"{source}.contract.evidence_kinds")
    _validate_string_list(contract.get("query_kinds", []), f"{source}.contract.query_kinds")

    invocation = _mapping(document["invocation"], f"{source}.invocation")
    argv = _validate_string_list(
        invocation.get("argv", []), f"{source}.invocation.argv", allow_empty=adapter == "generic"
    )
    if adapter != "generic" and not argv:
        raise _error(f"{source}.invocation.argv", "external adapters require an argv template")
    if not isinstance(invocation.get("shell"), bool):
        raise _error(f"{source}.invocation.shell", "expected boolean")
    if invocation.get("shell"):
        raise _error(f"{source}.invocation.shell", "shell execution is forbidden")
    invocation_cwd = _string(invocation.get("cwd"), f"{source}.invocation.cwd")
    if invocation_cwd not in {"repository_root", "workspace", "probe_root", "not_applicable"}:
        raise _error(f"{source}.invocation.cwd", f"unsupported cwd policy {invocation_cwd!r}")
    _string(invocation.get("stdin"), f"{source}.invocation.stdin")
    _validate_string_list(
        invocation.get("environment_allowlist", []),
        f"{source}.invocation.environment_allowlist",
    )
    allowlist = _mapping(
        invocation.get("command_allowlist"), f"{source}.invocation.command_allowlist"
    )
    _validate_string_list(
        allowlist.get("executables"),
        f"{source}.invocation.command_allowlist.executables",
    )
    _validate_string_list(
        allowlist.get("subcommands"),
        f"{source}.invocation.command_allowlist.subcommands",
    )
    _validate_string_list(
        allowlist.get("flags"),
        f"{source}.invocation.command_allowlist.flags",
    )
    executables = allowlist.get("executables")
    subcommands = allowlist.get("subcommands")
    if adapter != "generic" and (
        not isinstance(executables, list)
        or not executables
        or not isinstance(subcommands, list)
        or not subcommands
    ):
        raise _error(
            f"{source}.invocation.command_allowlist",
            "external adapters require executable and subcommand allowlists",
        )
    if not isinstance(allowlist.get("reject_shell_metacharacters"), bool):
        raise _error(
            f"{source}.invocation.command_allowlist.reject_shell_metacharacters",
            "expected boolean",
        )
    if not allowlist["reject_shell_metacharacters"]:
        raise _error(
            f"{source}.invocation.command_allowlist.reject_shell_metacharacters",
            "must be true",
        )
    if adapter == "generic" and argv:
        raise _error(f"{source}.invocation.argv", "Generic adapter must not execute a command")

    timeout = _mapping(document["timeout"], f"{source}.timeout")
    default_seconds = timeout.get("default_seconds")
    max_seconds = timeout.get("max_seconds")
    for field_name, value in (("default_seconds", default_seconds), ("max_seconds", max_seconds)):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise _error(f"{source}.timeout.{field_name}", "expected a non-negative number")
    probe_seconds = timeout.get("version_probe_seconds")
    if (
        not isinstance(probe_seconds, (int, float))
        or isinstance(probe_seconds, bool)
        or probe_seconds < 0
    ):
        raise _error(
            f"{source}.timeout.version_probe_seconds",
            "expected a non-negative number",
        )
    if adapter != "generic" and (default_seconds <= 0 or max_seconds <= 0):
        raise _error(f"{source}.timeout", "external adapters require a positive timeout")
    if max_seconds < default_seconds or max_seconds > 300:
        raise _error(
            f"{source}.timeout.max_seconds",
            "must bound the default timeout and be <= 300",
        )
    _string(timeout.get("on_exceeded"), f"{source}.timeout.on_exceeded")
    if not isinstance(timeout.get("return_code"), int) or isinstance(
        timeout.get("return_code"), bool
    ):
        raise _error(f"{source}.timeout.return_code", "expected integer")

    failure = _mapping(document["failure"], f"{source}.failure")
    events = _mapping(failure.get("events"), f"{source}.failure.events")
    for event_name in ADAPTER_MANIFEST_FAILURE_EVENTS:
        if event_name not in events:
            raise _error(f"{source}.failure.events", f"missing event {event_name!r}")
        _validate_adapter_failure_event(events[event_name], f"{source}.failure.events.{event_name}")
    for event_name, event in events.items():
        if event_name not in ADAPTER_MANIFEST_FAILURE_EVENTS:
            _validate_adapter_failure_event(event, f"{source}.failure.events.{event_name}")
    _string(failure.get("default_status"), f"{source}.failure.default_status")
    _string(failure.get("fallback"), f"{source}.failure.fallback")

    output = _mapping(document["output"], f"{source}.output")
    _string(output.get("format"), f"{source}.output.format")
    _string(output.get("stream"), f"{source}.output.stream")
    max_bytes = output.get("max_bytes")
    if max_bytes is not None and (
        not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0
    ):
        raise _error(f"{source}.output.max_bytes", "expected a positive integer or null")
    malformed = _mapping(output.get("malformed"), f"{source}.output.malformed")
    _validate_adapter_failure_event(malformed, f"{source}.output.malformed")

    provenance = _mapping(document["provenance"], f"{source}.provenance")
    required_fields = set(
        _validate_string_list(
            provenance.get("required_fields"),
            f"{source}.provenance.required_fields",
            allow_empty=False,
        )
    )
    missing_provenance = ADAPTER_MANIFEST_PROVENANCE_FIELDS - required_fields
    if missing_provenance:
        raise _error(
            f"{source}.provenance.required_fields",
            f"missing fields: {', '.join(sorted(missing_provenance))}",
        )
    if adapter == "dialyzer" and "plt_identity" not in required_fields:
        raise _error(
            f"{source}.provenance.required_fields",
            "Dialyzer provenance must include plt_identity",
        )
    _string(provenance.get("source"), f"{source}.provenance.source")
    _string(provenance.get("tool"), f"{source}.provenance.tool")
    for field_name in ("command_recorded", "raw_output_recorded"):
        if not isinstance(provenance.get(field_name), bool):
            raise _error(f"{source}.provenance.{field_name}", "expected boolean")

    cache = _mapping(document["cache"], f"{source}.cache")
    if not isinstance(cache.get("enabled"), bool):
        raise _error(f"{source}.cache.enabled", "expected boolean")
    key_fields = set(
        _validate_string_list(
            cache.get("key_fields"),
            f"{source}.cache.key_fields",
            allow_empty=False,
        )
    )
    missing_cache_fields = ADAPTER_MANIFEST_CACHE_FIELDS - key_fields
    if missing_cache_fields:
        raise _error(
            f"{source}.cache.key_fields",
            f"missing fields: {', '.join(sorted(missing_cache_fields))}",
        )
    if adapter == "dialyzer" and "plt_identity" not in key_fields:
        raise _error(f"{source}.cache.key_fields", "Dialyzer cache keys must include plt_identity")
    key_algorithm = _string(cache.get("key_algorithm"), f"{source}.cache.key_algorithm")
    if not key_algorithm.casefold().startswith("sha256"):
        raise _error(f"{source}.cache.key_algorithm", "must use SHA-256")
    _string(cache.get("path_template"), f"{source}.cache.path_template")
    _string(cache.get("stale_policy"), f"{source}.cache.stale_policy")
    if not isinstance(cache.get("atomic_write"), bool):
        raise _error(f"{source}.cache.atomic_write", "expected boolean")

    sandbox = _mapping(document["sandbox"], f"{source}.sandbox")
    sandbox_cwd = _string(sandbox.get("cwd"), f"{source}.sandbox.cwd")
    if adapter != "generic" and sandbox_cwd != invocation_cwd:
        raise _error(f"{source}.sandbox.cwd", "must match invocation.cwd")
    for field_name in ("read_paths", "write_paths"):
        paths = _validate_string_list(sandbox.get(field_name), f"{source}.sandbox.{field_name}")
        for index, path in enumerate(paths):
            _validate_relative_path(path, f"{source}.sandbox.{field_name}[{index}]")
    network = _string(sandbox.get("network"), f"{source}.sandbox.network")
    if network not in {"none", "deny", "allow", "controlled"}:
        raise _error(f"{source}.sandbox.network", f"unsupported network policy {network!r}")
    if adapter != "generic" and network not in {"deny", "controlled"}:
        raise _error(
            f"{source}.sandbox.network",
            "external adapters require a denied/controlled network",
        )
    _string(sandbox.get("project_code_execution"), f"{source}.sandbox.project_code_execution")
    _string(sandbox.get("config_scripts"), f"{source}.sandbox.config_scripts")
    if not isinstance(sandbox.get("outside_workspace"), str):
        raise _error(f"{source}.sandbox.outside_workspace", "expected string policy")
    if "allow_target_writes" in sandbox and not isinstance(sandbox["allow_target_writes"], bool):
        raise _error(f"{source}.sandbox.allow_target_writes", "expected boolean")

    enforcement = _mapping(document["enforcement"], f"{source}.enforcement")
    runtime_enforced = enforcement.get("runtime_policy_enforced")
    if not isinstance(runtime_enforced, bool):
        raise _error(f"{source}.enforcement.runtime_policy_enforced", "expected boolean")
    enforcement_status = _string(enforcement.get("status"), f"{source}.enforcement.status")
    if enforcement_status not in {"intrinsic", "enforced", "described_only", "unavailable"}:
        raise _error(f"{source}.enforcement.status", f"unsupported status {enforcement_status!r}")
    if not runtime_enforced:
        _string(enforcement.get("degraded_status"), f"{source}.enforcement.degraded_status")
        _string(enforcement.get("diagnostic_code"), f"{source}.enforcement.diagnostic_code")


def _adapter_manifest_paths(
    directory: str | Path = DEFAULT_ADAPTER_MANIFEST_DIR,
    paths: Mapping[str, str | Path] | Sequence[str | Path] | None = None,
) -> dict[str, Path]:
    root = Path(directory).expanduser().resolve()
    if paths is None:
        return {name: root / f"{name}.manifest.json" for name in ERLANG_ADAPTERS}
    if isinstance(paths, Mapping):
        values = {str(name).casefold(): Path(path) for name, path in paths.items()}
    else:
        values = {}
        for path in paths:
            candidate = Path(path)
            values[candidate.name.removesuffix(".manifest.json").casefold()] = candidate
    if set(values) != set(ERLANG_ADAPTERS):
        missing = set(ERLANG_ADAPTERS) - set(values)
        extra = set(values) - set(ERLANG_ADAPTERS)
        details = []
        if missing:
            details.append(f"missing: {', '.join(sorted(missing))}")
        if extra:
            details.append(f"unknown: {', '.join(sorted(extra))}")
        raise _error("adapter_manifests", "; ".join(details))
    result: dict[str, Path] = {}
    for name, path in values.items():
        resolved = path if path.is_absolute() else root / path
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise _error(
                f"adapter_manifests.{name}",
                "path escapes the manifest directory",
            ) from exc
        result[name] = resolved
    return result


def load_adapter_manifests(
    directory: str | Path = DEFAULT_ADAPTER_MANIFEST_DIR,
    *,
    paths: Mapping[str, str | Path] | Sequence[str | Path] | None = None,
) -> dict[str, dict[str, Any]]:
    """Load and validate all four checked-in Erlang adapter manifests."""
    manifest_paths = _adapter_manifest_paths(directory, paths)
    loaded: dict[str, dict[str, Any]] = {}
    for name, path in manifest_paths.items():
        if not path.is_file():
            raise _error(str(path), "adapter manifest is missing")
        document = _load_json(path)
        validate_adapter_manifest(document, str(path))
        if str(document.get("adapter", "")).casefold() != name:
            raise _error(str(path), f"adapter name does not match expected {name!r}")
        loaded[name] = dict(document)
    return loaded


def inspect_adapter_manifests(
    directory: str | Path = DEFAULT_ADAPTER_MANIFEST_DIR,
    *,
    paths: Mapping[str, str | Path] | Sequence[str | Path] | None = None,
) -> dict[str, Any]:
    """Return an observable policy status without raising on bad artifacts."""
    try:
        manifests = load_adapter_manifests(directory, paths=paths)
    except (OSError, TypeError, ValueError) as exc:
        return {
            "status": "unavailable",
            "runtime_policy_enforced": False,
            "manifests": [],
            "diagnostics": [
                _diagnostic(
                    "adapter_manifest_unavailable",
                    "warning",
                    f"No valid Erlang adapter policy is available: {exc}",
                )
            ],
        }
    unenforced = [
        name
        for name, manifest in manifests.items()
        if not manifest["enforcement"]["runtime_policy_enforced"]
    ]
    diagnostics = [
        _diagnostic(
            "adapter_manifest_policy_not_enforced",
            "warning",
            "Adapter manifest is descriptive; runtime sandbox enforcement remains caller-owned.",
            adapters=unenforced,
        )
    ] if unenforced else []
    return {
        "status": "degraded" if unenforced else "ok",
        "runtime_policy_enforced": not unenforced,
        "manifests": sorted(manifests),
        "diagnostics": diagnostics,
    }


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

    # Adapter policies are additive to the original evaluation-manifest
    # schema.  When present, validate the index here; ``load_manifest`` then
    # loads each referenced child manifest and applies the full contract.
    adapter_index = document.get("adapters", document.get("adapter_manifests"))
    if adapter_index is not None:
        index = _mapping(adapter_index, f"{source}.adapters")
        directory = _validate_relative_path(
            index.get("directory"), f"{source}.adapters.directory"
        )
        if not directory:
            raise _error(f"{source}.adapters.directory", "must not be empty")
        files = _mapping(index.get("files"), f"{source}.adapters.files")
        if set(str(key).casefold() for key in files) != set(ERLANG_ADAPTERS):
            raise _error(
                f"{source}.adapters.files",
                f"must list exactly: {', '.join(ERLANG_ADAPTERS)}",
            )
        for name, value in files.items():
            child_path = _validate_relative_path(value, f"{source}.adapters.files.{name}")
            if not child_path.endswith(".manifest.json"):
                raise _error(
                    f"{source}.adapters.files.{name}",
                    "must point to a .manifest.json file",
                )
        runtime_policy = _string(
            index.get("runtime_policy"), f"{source}.adapters.runtime_policy"
        )
        if runtime_policy not in {"enforced", "described_only", "mixed"}:
            raise _error(
                f"{source}.adapters.runtime_policy",
                f"unsupported runtime policy {runtime_policy!r}",
            )
        _string(index.get("invalid_policy_status"), f"{source}.adapters.invalid_policy_status")
        _string(
            index.get("invalid_policy_diagnostic"),
            f"{source}.adapters.invalid_policy_diagnostic",
        )


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


def load_manifest(
    path: str | Path = DEFAULT_MANIFEST,
    *,
    load_adapters: bool = True,
) -> dict[str, Any]:
    """Load an evaluation manifest and, by default, its adapter policies."""

    manifest_path = Path(path)
    document = _load_json(manifest_path)
    validate_manifest(document, str(manifest_path))
    adapter_index = document.get("adapters", document.get("adapter_manifests"))
    if load_adapters and adapter_index is not None:
        index = _mapping(adapter_index, f"{manifest_path}.adapters")
        directory = manifest_path.parent / str(index["directory"])
        child_paths = {
            str(name).casefold(): directory / str(child)
            for name, child in _mapping(index["files"], f"{manifest_path}.adapters.files").items()
        }
        document["_adapter_manifests"] = load_adapter_manifests(
            directory,
            paths=child_paths,
        )
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


def execute_corpus(
    manifest: Mapping[str, Any],
    corpus: Mapping[str, Any],
    *,
    target_root: str | Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the read-only portion of each corpus case.

    This deliberately does not invoke a project build, configuration script,
    or semantic tool.  It verifies that every case is executable against the
    selected checkout and reports the remaining graph/lifecycle work as
    ``not_run`` rather than treating an unmeasured case as a pass.
    """
    target = _mapping(manifest["target"], "manifest.target")
    root = Path(target_root or str(target["path"])).expanduser().resolve()
    case_results: list[dict[str, Any]] = []
    for case in corpus.get("cases", []):
        if not isinstance(case, Mapping):
            continue
        case_id = str(case.get("id", "unknown"))
        paths: set[str] = set()
        query = case.get("query")
        if isinstance(query, Mapping):
            endpoint = query.get("target")
            if isinstance(endpoint, Mapping) and isinstance(endpoint.get("file"), str):
                paths.add(endpoint["file"])
        expected = case.get("expected")
        if isinstance(expected, Mapping):
            for relation_kind in ("positive", "negative", "unresolved"):
                relations = expected.get(relation_kind, [])
                if not isinstance(relations, list):
                    continue
                for relation in relations:
                    if not isinstance(relation, Mapping):
                        continue
                    for endpoint_kind in ("source", "target"):
                        endpoint = relation.get(endpoint_kind)
                        if isinstance(endpoint, Mapping) and isinstance(endpoint.get("file"), str):
                            paths.add(endpoint["file"])
        missing = sorted(path for path in paths if not (root / path).is_file())
        if not root.is_dir():
            status = "blocked"
            reason = "target_missing"
        elif missing:
            status = "blocked"
            reason = "anchor_missing"
        elif dry_run:
            status = "dry_run"
            reason = "execution_disabled"
        else:
            status = "ready_for_graph_execution"
            reason = "graph_execution_not_implemented"
        case_results.append(
            {
                "id": case_id,
                "category": case.get("category"),
                "status": status,
                "reason": reason,
                "anchors": sorted(paths),
                "missing_anchors": missing,
            }
        )
    lifecycle = {
        phase: {
            "status": "not_run",
            "reason": "lifecycle execution is not enabled by this read-only evaluator",
        }
        for phase in (
            "full_build",
            "incremental_update",
            "watch",
            "forget",
            "standalone_postprocess",
        )
    }
    blocked = sum(item["status"] == "blocked" for item in case_results)
    return {
        "status": "blocked" if blocked else "dry_run" if dry_run else "not_run",
        "dry_run": dry_run,
        "case_results": case_results,
        "lifecycle": lifecycle,
        "metrics": {
            "status": "not_run",
            "precision": None,
            "recall_at_10": None,
            "impact": None,
            "latency": None,
            "adoption_pass": False,
        },
    }


def discover_environment(
    manifest: Mapping[str, Any],
    corpus: Mapping[str, Any],
    *,
    target_root: str | Path | None = None,
    manifest_root: str | Path | None = None,
    timeout: float = 5.0,
    probe_root: str | Path | None = None,
    dry_run: bool = False,
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
    adapter_policy: dict[str, Any]
    adapter_index = manifest.get("adapters", manifest.get("adapter_manifests"))
    if adapter_index is None:
        adapter_policy = inspect_adapter_manifests()
    else:
        index = _mapping(adapter_index, "manifest.adapters")
        index_root = Path(manifest_root or MODULE_ROOT / "evaluate" / "erlang").resolve()
        adapter_directory = index_root / str(index["directory"])
        child_paths = {
            str(name).casefold(): adapter_directory / str(child)
            for name, child in _mapping(index["files"], "manifest.adapters.files").items()
        }
        adapter_policy = inspect_adapter_manifests(adapter_directory, paths=child_paths)
    diagnostics.extend(adapter_policy.get("diagnostics", []))
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
    corpus_execution = execute_corpus(
        manifest, corpus, target_root=root, dry_run=dry_run
    )

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
        "adapter_policy": adapter_policy,
        "cache": _cache_state(root, manifest),
        "corpus": corpus_summary,
        "corpus_execution": corpus_execution,
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
    dry_run: bool = False,
) -> dict[str, Any]:
    """Load artifacts and return one structured, non-mutating observation."""

    # Keep evaluation observable even when a policy artifact is missing or
    # malformed.  ``discover_environment`` turns that condition into an
    # ``adapter_policy.status = unavailable`` diagnostic instead of aborting
    # the read-only observation; callers that need strict startup validation
    # can use the default ``load_manifest`` behavior directly.
    manifest = load_manifest(manifest_path, load_adapters=False)
    corpus = load_corpus(corpus_path)
    result = discover_environment(
        manifest,
        corpus,
        target_root=target_root,
        manifest_root=Path(manifest_path).resolve().parent,
        timeout=timeout,
        probe_root=probe_root,
        dry_run=dry_run,
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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check corpus anchors without graph or lifecycle execution",
    )
    args = parser.parse_args(argv)
    try:
        result = run_evaluation(
            args.manifest,
            args.corpus,
            target_root=args.target_root,
            timeout=args.timeout,
            probe_root=args.probe_root,
            dry_run=args.dry_run,
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
    "ADAPTER_MANIFEST_KIND",
    "ADAPTER_MANIFEST_SCHEMA_VERSION",
    "DEFAULT_ADAPTER_MANIFEST_DIR",
    "DEFAULT_ADAPTER_MANIFESTS",
    "DEFAULT_CORPUS",
    "DEFAULT_MANIFEST",
    "ERLANG_ADAPTERS",
    "discover_environment",
    "execute_corpus",
    "inspect_adapter_manifests",
    "load_corpus",
    "load_manifest",
    "load_adapter_manifests",
    "main",
    "run_evaluation",
    "validate_adapter_manifest",
    "validate_corpus",
    "validate_manifest",
]


if __name__ == "__main__":
    raise SystemExit(main())
