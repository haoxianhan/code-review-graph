"""Executable, fail-closed evaluation for the Erlang ``server_flexible`` corpus.

The checked-in manifest describes an external checkout.  This runner treats
that checkout as read-only: discovery and parsing read from it, while every
GraphStore used for a build or lifecycle check lives in a temporary directory.
An adoption result is deliberately different from a benchmark result.  A
missing measurement is represented by ``not_run``/``None`` and can never make
the adoption gate pass.

The module is intentionally independent of :mod:`code_review_graph.eval.erlang`
so the original artifact-observation API remains compatible.  It can be used
as a library or with ``python -m code_review_graph.eval.erlang_adoption``.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..erlang_integration import ErlangIntegrationConfig
from ..forget import forget_files
from ..graph import GraphEdge, GraphNode, GraphStore
from ..incremental import full_build, incremental_update, watch
from ..parser import normalize_file_path
from ..postprocessing import run_post_processing
from .erlang import (
    DEFAULT_CORPUS,
    DEFAULT_MANIFEST,
    TOOL_STATUSES,
    _discover_repository,
    discover_environment,
    load_corpus,
    load_manifest,
    validate_artifact_pair,
    validate_corpus,
    validate_manifest,
)

SCHEMA_VERSION = 1
RESULT_KIND = "erlang_adoption_evaluation"
DEFAULT_OUTPUT_STEM = "server_flexible_adoption"
_CORPUS_CONTRACT_VERSION = 1
_KNOWN_CASE_STATUSES = frozenset({"executed", "not_run", "blocked", "error"})
_KNOWN_LIFECYCLE_STATUSES = frozenset({"executed", "not_run", "blocked", "error"})
_SUPPORTED_QUERIES = frozenset(
    {
        "callers_of",
        "references",
        "references_to",
        "implementers_of",
        "tests_for",
        "mfa",
        "diagnostics",
        "cache",
    }
)
_SEMANTIC_CASE_TOOLS = {
    "supervisor_mfa": frozenset({"xref", "elp"}),
    "stale_cache": frozenset({"elp", "xref", "dialyzer"}),
}
_FUNCTION_CATEGORIES = frozenset({"local_callers", "remote_callers"})
_MODULE_CATEGORIES = frozenset({"shared_header_records", "generated_data"})
_MAX_ERLANG_ARITY = 255
_LIFECYCLE_PHASES = (
    "full_build",
    "incremental_update",
    "watch",
    "forget",
    "standalone_postprocess",
)
_REQUIRED_ADOPTION_GATES = frozenset(
    {
        "target_available",
        "standalone_git",
        "pinned_revision",
        "clean_baseline",
        "working_tree_state_known",
        "remote_identity",
        "dependencies_consistent",
        "generated_data_consistent",
        "runtime_policy_enforced",
        "semantic_tools",
        "semantic_adapters_executed",
        "precision_100",
        "all_cases_executed",
        "all_cases_measured",
        "missing_anchors",
        "no_forbidden_matches",
        "unresolved_contract",
        "required_diagnostics",
        "recall_at_10",
        "impact_coverage",
        "latency_budget",
        "lifecycle_parity",
        "lifecycle_errors",
        "diagnostics_observable",
        "top_level_diagnostics",
    }
)
_REQUIRED_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "status",
        "run",
        "target",
        "environment",
        "gates",
        "cases",
        "lifecycle",
        "metrics",
        "adoption",
        "diagnostics",
        "corpus_contract",
    }
)
_REQUIRED_METRIC_KEYS = frozenset(
    {
        "status",
        "cases_scored",
        "precision",
        "recall",
        "recall_at_10",
        "forbidden_matches",
        "latency",
        "impact",
    }
)

# Lifecycle runners may add diagnostics and resolver-specific fields, but the
# phase's core evidence must always be present and typed.  Keeping the minimum
# contract here prevents a generic ``status: ok`` envelope from being reused
# for a different phase or from hiding a missing measurement.
_LIFECYCLE_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "full_build": frozenset({"files_parsed", "errors", "total_nodes", "total_edges"}),
    "incremental_update": frozenset({"files_updated", "errors", "changed_files", "graph_changed"}),
    "standalone_postprocess": frozenset(
        {"bare_edges_resolved", "fts_indexed", "signatures_computed"}
    ),
    "forget": frozenset({"forgotten", "reparsed", "embeddings_purged"}),
    "watch": frozenset({"events", "updates", "graph_changed", "notifications"}),
}
_LIFECYCLE_COUNT_FIELDS: frozenset[str] = frozenset(
    {
        "files_parsed",
        "files_updated",
        "stale_files_removed",
        "total_nodes",
        "total_edges",
        "bare_edges_resolved",
        "cpp_scoped_edges_resolved",
        "fts_indexed",
        "signatures_computed",
        "flows_detected",
        "communities_detected",
        "embeddings_purged",
    }
)
_LIFECYCLE_LIST_FIELDS: frozenset[str] = frozenset(
    {"changed_files", "dependent_files", "forgotten", "reparsed"}
)
_LIFECYCLE_BOOL_FIELDS: frozenset[str] = frozenset(
    {"graph_changed", "relation_layout_changed"}
)
_GENERATED_DATA_MARKERS: tuple[str, ...] = (
    "tools/gen_data/data_rev_info",
    "tools/gen_data/server_cfg_structure_version",
)
_LATENCY_REQUIRED_OPERATIONS: tuple[str, ...] = ("full_build", "targeted_query")
_LATENCY_MIN_SAMPLES = 1


def _diagnostic(code: str, severity: str, message: str, **details: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"code": code, "severity": severity, "message": message}
    if details:
        item["details"] = details
    return item


def _json_default(value: Any) -> Any:
    """Convert result values to deterministic JSON without leaking objects."""
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, set):
        return sorted(value)
    if hasattr(value, "to_dict"):
        try:
            return value.to_dict()
        except Exception:  # pragma: no cover - defensive reporting boundary
            return str(value)
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_json_default
    )


def _canonical_path(value: str | Path) -> Path:
    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return Path(value).expanduser().absolute()


def _safe_relative_path(value: Any, root: Path, source: str) -> str:
    """Validate and resolve one artifact path below *root*.

    The lower-level observation helpers intentionally accept plain mappings
    and join their path fields with the target root.  Validate those fields
    before discovery so a corpus/manifest cannot make an evaluator inspect a
    parent directory (including through an existing symlink).
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source}: expected a non-empty relative path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{source}: path contains control characters")
    # Treat Windows drive/UNC spellings as absolute even when running on POSIX.
    if "\\" in value or Path(value).is_absolute() or re.match(r"^[A-Za-z]:($|/)", value):
        raise ValueError(f"{source}: path must be repository-relative POSIX")
    parts = value.split("/")
    if any(part == ".." for part in parts):
        raise ValueError(f"{source}: path must not contain '..'")
    root_path = _canonical_path(root)
    try:
        candidate = (root_path / value).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{source}: could not resolve path safely") from exc
    try:
        relative = candidate.relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"{source}: resolved path escapes target checkout") from exc
    return relative.as_posix()


def _validate_endpoint_path(endpoint: Any, root: Path, source: str) -> None:
    if isinstance(endpoint, Mapping) and "file" in endpoint:
        _safe_relative_path(endpoint.get("file"), root, f"{source}.file")
    elif isinstance(endpoint, str) and "::" in endpoint:
        # Qualified graph identities use ``relative/file::symbol``. A plain
        # ``module:function/arity`` endpoint has no path component.
        path, _separator, _symbol = endpoint.partition("::")
        _safe_relative_path(path, root, f"{source}.path")


def _validate_artifact_paths(
    manifest: Mapping[str, Any], corpus: Mapping[str, Any], root: Path
) -> None:
    """Reject every target-relative path before read-only discovery starts."""
    dependencies = manifest.get("dependencies", {})
    if isinstance(dependencies, Mapping):
        for index, item in enumerate(dependencies.get("lockfiles", [])):
            if isinstance(item, Mapping):
                _safe_relative_path(
                    item.get("path"), root, f"manifest.dependencies.lockfiles[{index}].path"
                )
        for index, item in enumerate(dependencies.get("submodules", [])):
            if isinstance(item, Mapping):
                _safe_relative_path(
                    item.get("path"), root, f"manifest.dependencies.submodules[{index}].path"
                )
    generated = manifest.get("generated_data", {})
    if isinstance(generated, Mapping):
        for index, value in enumerate(generated.get("paths", [])):
            _safe_relative_path(value, root, f"manifest.generated_data.paths[{index}]")
    revision = manifest.get("revision", {})
    if isinstance(revision, Mapping):
        for index, value in enumerate(revision.get("dirty_paths", [])):
            _safe_relative_path(value, root, f"manifest.revision.dirty_paths[{index}]")
    toolchain = manifest.get("toolchain", {})
    configuration = toolchain.get("configuration", {}) if isinstance(toolchain, Mapping) else {}
    if isinstance(configuration, Mapping):
        for index, value in enumerate(configuration.get("files", [])):
            _safe_relative_path(value, root, f"manifest.toolchain.configuration.files[{index}]")
    analysis = manifest.get("analysis", {})
    if isinstance(analysis, Mapping):
        for index, value in enumerate(analysis.get("cache_paths", [])):
            _safe_relative_path(value, root, f"manifest.analysis.cache_paths[{index}]")

    cases = corpus.get("cases", [])
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            continue
        case_source = f"corpus.cases[{index}]"
        query = case.get("query")
        if isinstance(query, Mapping):
            _validate_endpoint_path(query.get("target"), root, f"{case_source}.query.target")
        expected = case.get("expected")
        if isinstance(expected, Mapping):
            for relation_kind in ("positive", "negative", "unresolved"):
                relations = expected.get(relation_kind, [])
                if not isinstance(relations, list):
                    continue
                for relation_index, relation in enumerate(relations):
                    if not isinstance(relation, Mapping):
                        continue
                    relation_source = f"{case_source}.expected.{relation_kind}[{relation_index}]"
                    _validate_endpoint_path(
                        relation.get("source"), root, f"{relation_source}.source"
                    )
                    _validate_endpoint_path(
                        relation.get("target"), root, f"{relation_source}.target"
                    )
        impact = case.get("impact")
        if isinstance(impact, Mapping):
            # ``expected`` is the legacy spelling accepted by
            # ``_impact_metric`` when ``critical_dependents`` is omitted.
            # Validate both spellings before any impact calculation so a
            # corpus cannot smuggle a parent/absolute path through the
            # fallback field.
            for field in (
                "changed_files",
                "changed",
                "critical_dependents",
                "expected",
            ):
                values = impact.get(field, [])
                if isinstance(values, list):
                    for value_index, value in enumerate(values):
                        _safe_relative_path(
                            value,
                            root,
                            f"{case_source}.impact.{field}[{value_index}]",
                        )
    impact_entries = corpus.get("impact")
    if isinstance(impact_entries, list):
        for entry_index, entry in enumerate(impact_entries):
            if not isinstance(entry, Mapping):
                continue
            for field in (
                "changed_files",
                "changed",
                "critical_dependents",
                "expected",
            ):
                values = entry.get(field, [])
                if isinstance(values, list):
                    for value_index, value in enumerate(values):
                        _safe_relative_path(
                            value,
                            root,
                            f"corpus.impact[{entry_index}].{field}[{value_index}]",
                        )


def _parse_erlang_arity(value: Any) -> int | None:
    """Parse an Erlang arity while bounding conversion and BEAM semantics."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= _MAX_ERLANG_ARITY else None
    if isinstance(value, str):
        text = value.strip()
        # A valid BEAM arity is at most three decimal digits.  The length
        # check also avoids Python's large-int conversion limit on malformed
        # corpus strings.
        if not text.isdigit() or len(text) > 3:
            return None
        parsed = int(text)
        return parsed if parsed <= _MAX_ERLANG_ARITY else None
    return None


def _split_erlang_symbol(value: Any, explicit_arity: Any = None) -> tuple[str, int | None] | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    parsed_explicit = _parse_erlang_arity(explicit_arity) if explicit_arity is not None else None
    if explicit_arity is not None and parsed_explicit is None:
        return None
    if "/" not in text:
        return text, parsed_explicit
    name, raw_arity = text.rsplit("/", 1)
    parsed = _parse_erlang_arity(raw_arity)
    if not name or parsed is None:
        return None
    if parsed_explicit is not None and parsed != parsed_explicit:
        return None
    return name, parsed


def _node_symbol_matches(node: GraphNode, symbol: Any, arity: Any = None) -> bool:
    # Clauses are syntax/navigation children of a callable Function or Test;
    # they are deliberately not independent semantic endpoints.  Keeping
    # them out of symbol matching prevents a file-qualified function anchor
    # from becoming ambiguous as soon as the Generic parser exposes clauses.
    if node.kind == "Clause":
        return False
    parsed = _split_erlang_symbol(symbol, arity)
    if parsed is None:
        return False
    name, parsed_arity = parsed
    module_name: str | None = None
    if ":" in name:
        module_name, name = name.split(":", 1)
    elif "." in name:
        module_name, name = name.rsplit(".", 1)
    if node.name != name:
        return False
    if module_name is not None and node.parent_name != module_name:
        return False
    if parsed_arity is None:
        return True
    extra = node.extra if isinstance(node.extra, Mapping) else {}
    node_arity = _parse_erlang_arity(extra.get("arity"))
    if node_arity is None:
        tail = node.qualified_name.rsplit("::", 1)[-1]
        node_parts = _split_erlang_symbol(tail)
        node_arity = node_parts[1] if node_parts else None
    return node_arity == parsed_arity


def _mfa_parts(value: Any) -> tuple[str, str, int] | None:
    """Parse a bounded ``module:function/arity`` or dot-style MFA."""
    if not isinstance(value, str) or "/" not in value:
        return None
    function, raw_arity = value.rsplit("/", 1)
    arity = _parse_erlang_arity(raw_arity)
    if arity is None:
        return None
    if ":" in function:
        module, name = function.split(":", 1)
    elif "." in function:
        module, name = function.rsplit(".", 1)
    else:
        return None
    module = module.strip("'")
    name = name.strip("'")
    return (module, name, arity) if module and name else None


def _dynamic_mfa_spelling(value: Any) -> str | None:
    """Return a symbolic unresolved MFA, excluding malformed numeric forms."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if "::" in text:
        text = text.rsplit("::", 1)[-1]
    if not _looks_like_erlang_mfa(text):
        return None
    function, raw_arity = text.rsplit("/", 1)
    # A descriptive identifier (the corpus uses ``arity``) represents a
    # dynamic apply.  Hyphenated prose and numeric out-of-range values are
    # malformed MFAs and must never become self-matching aliases.
    if raw_arity.isdigit() or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@]*", raw_arity):
        return None
    if ":" not in function and "." not in function:
        return None
    return text


def _relative_path(value: str | Path, root: Path) -> str:
    """Normalize a graph path to a repository-relative POSIX spelling."""
    raw = str(value).replace("\\", "/")
    candidate = Path(raw)
    if not candidate.is_absolute():
        # Graph rows normally contain absolute paths, while hand-built test
        # stores often contain relative paths.
        candidate = root / candidate
    try:
        return candidate.resolve(strict=False).relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return raw.lstrip("./")


def _load_manifest_artifact(
    value: str | Path | Mapping[str, Any],
) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, Mapping):
        validate_manifest(value)
        return dict(value), None
    path = Path(value)
    return load_manifest(path), path.resolve()


def _load_corpus_artifact(
    value: str | Path | Mapping[str, Any],
) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, Mapping):
        validate_corpus(value)
        return dict(value), None
    path = Path(value)
    return load_corpus(path), path.resolve()


def _invoke_with_optional_config(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Call lifecycle helpers while remaining friendly to small test doubles."""
    parameters: Mapping[str, inspect.Parameter]
    try:
        parameters = inspect.signature(function).parameters
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
        )
    except (TypeError, ValueError):
        accepts_kwargs = True
        parameters = {}
    if accepts_kwargs:
        return function(*args, **kwargs)
    # Test doubles often expose only the positional lifecycle contract.  Drop
    # optional keyword arguments they do not advertise while preserving any
    # explicitly supported argument (notably ``changed_files`` and
    # ``erlang_config``).
    for name in tuple(kwargs):
        if name not in parameters:
            kwargs.pop(name, None)
    return function(*args, **kwargs)


def _tool_available(environment: Mapping[str, Any], name: str) -> bool:
    tools = environment.get("toolchain", {}).get("tools", {})
    item = tools.get(name, {}) if isinstance(tools, Mapping) else {}
    return isinstance(item, Mapping) and item.get("status") in {
        "available",
        "available_via_rebar3",
    }


def _available_semantic_tools(environment: Mapping[str, Any]) -> set[str]:
    return {
        name
        for name in ("elp", "xref", "dialyzer")
        if _tool_available(environment, name)
    }


def _repository_gates(
    manifest: Mapping[str, Any],
    environment: Mapping[str, Any],
    root: Path,
    *,
    allow_dirty: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Return hard/soft gates and whether a temporary graph may be built."""
    repository = environment.get("repository", {})
    if not isinstance(repository, Mapping):
        repository = {}
    revision = manifest.get("revision", {})
    if not isinstance(revision, Mapping):
        revision = {}
    requested = revision.get("requested")
    manifest_observed = revision.get("observed")
    observed = repository.get("revision")
    exists = bool(repository.get("exists")) and root.is_dir()
    standalone_git = bool(repository.get("top_level")) and (
        _canonical_path(str(repository.get("top_level"))) == root
    )
    # A pinned adoption baseline must agree with both revision values recorded
    # in the manifest and the revision currently checked out.  Comparing only
    # ``requested`` would allow a stale ``revision.observed`` marker to pass.
    revision_consistent = (
        isinstance(requested, str)
        and isinstance(manifest_observed, str)
        and isinstance(observed, str)
        and requested == manifest_observed == observed
    )
    pinned = exists and standalone_git and revision_consistent
    clean_observed = repository.get("working_tree_clean") is True
    dirty_observed = repository.get("working_tree_clean") is False
    # ``None`` means Git status could not be established; an override may
    # acknowledge a known dirty tree, but it must never bless an unknown one.
    clean = clean_observed or (allow_dirty and dirty_observed)

    dependency_clean = True
    raw_observed_submodules = repository.get("submodules")
    malformed_submodules: list[str] = []
    if isinstance(raw_observed_submodules, list):
        observed_submodules = raw_observed_submodules
    else:
        # ``discover_environment`` always supplies a list.  Treat a missing or
        # malformed container as unknown rather than silently interpreting it
        # as an empty dependency set.
        observed_submodules = []
        malformed_submodules.append("repository.submodules")
    observed_submodule_paths = {
        str(item.get("path"))
        for item in observed_submodules
        if isinstance(item, Mapping) and isinstance(item.get("path"), str)
    }
    expected_dependencies = manifest.get("dependencies", {})
    expected_submodules = (
        {
            str(item.get("path"))
            for item in expected_dependencies.get("submodules", [])
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        }
        if isinstance(expected_dependencies, Mapping)
        else set()
    )
    missing_submodules = sorted(expected_submodules - observed_submodule_paths)
    unexpected_submodules = sorted(observed_submodule_paths - expected_submodules)
    expected_submodule_map = (
        {
            str(item.get("path")): item
            for item in expected_dependencies.get("submodules", [])
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        }
        if isinstance(expected_dependencies, Mapping)
        else {}
    )
    gitlink_mismatches: list[str] = []
    checkout_mismatches: list[str] = []
    seen_submodule_paths: set[str] = set()
    for index, item in enumerate(observed_submodules):
        if not isinstance(item, Mapping):
            malformed_submodules.append(f"repository.submodules[{index}]")
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path:
            malformed_submodules.append(f"repository.submodules[{index}].path")
            continue
        if path in seen_submodule_paths:
            malformed_submodules.append(f"repository.submodules[{index}].path_duplicate")
        seen_submodule_paths.add(path)
        path_key = path if isinstance(path, str) else None
        expected_item = (
            expected_submodule_map.get(path_key) if path_key is not None else None
        )
        if isinstance(expected_item, Mapping):
            # Manifest validation guarantees these fields for checked-in
            # artifacts.  Keep the runtime boundary defensive as well: a
            # hand-built environment must not pass merely because both sides
            # happen to contain ``None`` (or another malformed value).
            for field in ("gitlink_revision", "checkout_revision"):
                expected_value = expected_item.get(field)
                observed_value = item.get(field)
                if expected_value is not None and (
                    not isinstance(observed_value, str) or not observed_value
                ):
                    malformed_submodules.append(
                        f"repository.submodules[{index}].{field}"
                    )
        if isinstance(expected_item, Mapping) and expected_item.get("gitlink_revision") != item.get(
            "gitlink_revision"
        ):
            gitlink_mismatches.append(str(path))
        # The gitlink records the revision pinned by the superproject, while
        # checkout_revision records what is actually checked out below that
        # path.  They are intentionally independent: a submodule may have a
        # valid superproject gitlink but still contain a different checkout.
        # Treat a missing observed checkout revision as a mismatch whenever
        # the manifest declares one; otherwise an incomplete observation could
        # silently satisfy the dependency gate.
        if isinstance(expected_item, Mapping) and expected_item.get(
            "checkout_revision"
        ) != item.get("checkout_revision"):
            checkout_mismatches.append(str(path))
    if (
        missing_submodules
        or unexpected_submodules
        or gitlink_mismatches
        or checkout_mismatches
        or malformed_submodules
    ):
        dependency_clean = False
    for item in observed_submodules:
        if not isinstance(item, Mapping):
            continue
        if not item.get("gitlink_matches_checkout", True) or not item.get(
            "working_tree_clean", True
        ):
            dependency_clean = False
    diagnostic_codes = {
        str(item.get("code"))
        for item in environment.get("diagnostics", [])
        if isinstance(item, Mapping)
    }
    if {
        "lockfile_changed",
        "lockfile_missing",
        "submodule_gitlink_changed",
        "submodule_checkout_mismatch",
        "submodule_missing",
    }.intersection(diagnostic_codes):
        dependency_clean = False

    expected_remote = (
        manifest.get("target", {}).get("remote")
        if isinstance(manifest.get("target"), Mapping)
        else None
    )
    # A missing remote is an auxiliary/unverified state, but it should not
    # prevent a read-only exploratory graph run.  An observed mismatch is a
    # hard identity failure because it can point the evaluator at the wrong
    # project.
    remote_identity = not (isinstance(expected_remote, str) and expected_remote)
    remote_mismatch = False
    observed_remote = repository.get("remote")
    if isinstance(expected_remote, str) and expected_remote:
        remote_identity = isinstance(observed_remote, str) and observed_remote == expected_remote
        remote_mismatch = observed_remote is not None and not remote_identity

    gates: dict[str, Any] = {
        "target_exists": exists,
        "standalone_git": standalone_git,
        "pinned_revision": pinned,
        "clean_baseline": clean_observed,
        "working_tree_state_known": isinstance(repository.get("working_tree_clean"), bool),
        "remote_identity": remote_identity,
        "remote_mismatch": remote_mismatch,
        "dirty_override": bool(allow_dirty and dirty_observed),
        "dependencies_consistent": dependency_clean,
    }
    diagnostics: list[dict[str, Any]] = []
    if not exists:
        diagnostics.append(
            _diagnostic("target_missing", "error", "Target checkout is missing.", path=str(root))
        )
    elif not standalone_git:
        diagnostics.append(
            _diagnostic("target_not_git", "error", "Target is not an independent Git checkout.")
        )
    elif not pinned:
        diagnostics.append(
            _diagnostic(
                "pinned_revision_mismatch",
                "error",
                "Target or manifest revision does not match the pinned baseline.",
                expected=requested,
                manifest_observed=manifest_observed,
                observed=observed,
            )
        )
    if not clean_observed:
        diagnostics.append(
            _diagnostic(
                "target_worktree_dirty",
                "warning" if allow_dirty and dirty_observed else "error",
                (
                    "A dirty checkout is not an adoption baseline; execution is exploratory only."
                    if dirty_observed
                    else "Target working-tree state could not be established; refusing execution."
                ),
                dirty_paths=repository.get("dirty_paths", []),
            )
        )
    if isinstance(expected_remote, str) and expected_remote:
        if remote_mismatch:
            diagnostics.append(
                _diagnostic(
                    "target_remote_mismatch",
                    "error",
                    "Target remote does not match the manifest identity.",
                    expected=expected_remote,
                    observed=observed_remote,
                )
            )
        elif not remote_identity:
            diagnostics.append(
                _diagnostic(
                    "target_remote_unavailable",
                    "warning",
                    "Target remote could not be observed; repository identity is auxiliary only.",
                    expected=expected_remote,
                )
            )
    if not dependency_clean:
        diagnostics.append(
            _diagnostic(
                "dependency_state_mismatch",
                "error",
                "Lockfile or submodule state does not match the pinned baseline.",
                missing_submodules=missing_submodules,
                unexpected_submodules=unexpected_submodules,
                gitlink_mismatches=sorted(gitlink_mismatches),
                checkout_mismatches=sorted(checkout_mismatches),
                malformed_submodules=sorted(malformed_submodules),
            )
        )
    if malformed_submodules:
        diagnostics.append(
            _diagnostic(
                "submodule_observation_malformed",
                "error",
                "Observed submodule metadata is malformed or incomplete.",
                paths=sorted(malformed_submodules),
            )
        )
    if checkout_mismatches:
        diagnostics.append(
            _diagnostic(
                "submodule_checkout_mismatch",
                "error",
                "A submodule checkout revision is missing or differs from the manifest.",
                paths=sorted(checkout_mismatches),
            )
        )
    # A dirty override intentionally never makes the adoption gate pass, but
    # it permits a local exploratory graph run when the caller explicitly asks.
    can_build = (
        exists and standalone_git and pinned and dependency_clean and clean and not remote_mismatch
    )
    return gates, diagnostics, can_build


def _normalise_repository_observation(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize the fields returned by the read-only Git observer.

    Paths and unordered status collections are canonicalized before comparing
    them with a serialized report.  This keeps validation deterministic while
    still treating every observed value as evidence rather than as a caller
    supplied verdict.
    """
    normalized = dict(value)
    path = normalized.get("path")
    if isinstance(path, str) and path:
        normalized["path"] = str(_canonical_path(path))
    top_level = normalized.get("top_level")
    if isinstance(top_level, str) and top_level:
        normalized["top_level"] = str(_canonical_path(top_level))
    dirty_paths = normalized.get("dirty_paths")
    if isinstance(dirty_paths, list):
        normalized["dirty_paths"] = sorted(str(item) for item in dirty_paths)
    submodules = normalized.get("submodules")
    if isinstance(submodules, list):
        normalized["submodules"] = sorted(
            [
                (
                    dict(item)
                    if isinstance(item, Mapping)
                    else {"__malformed__": repr(item)}
                )
                for item in submodules
            ],
            key=lambda item: str(item.get("path", "")),
        )
    return normalized


def _validate_repository_observation(
    target: Mapping[str, Any], repository: Mapping[str, Any]
) -> dict[str, Any]:
    """Recompute raw target observations and reject stale/forged reports.

    Adoption reports are commonly persisted and validated later, so checking
    only relationships between their own fields is insufficient.  Git and
    filesystem facts are cheap, read-only observations; when the target is
    present we obtain them again and compare the complete discovery payload.
    Missing/non-Git targets use the same empty shape as ``discover_environment``
    and are still checked for internally impossible values.
    """
    target_path = target.get("path")
    if not isinstance(target_path, str) or not target_path:
        raise ValueError("result.target.path: expected non-empty string")
    root = _canonical_path(target_path)
    recorded = _normalise_repository_observation(repository)
    recorded_path = recorded.get("path")
    if not isinstance(recorded_path, str) or _canonical_path(recorded_path) != root:
        raise ValueError("result.environment.repository.path: inconsistent with target.path")
    if not isinstance(recorded.get("exists"), bool):
        raise ValueError("result.environment.repository.exists: expected boolean")

    try:
        observed, _diagnostics = _discover_repository(root)
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        raise ValueError(
            "result.environment.repository: could not recompute read-only observation"
        ) from exc
    expected = _normalise_repository_observation(observed)

    # ``_discover_repository`` always returns the same complete shape.  Keep
    # the comparison explicit so an additive future field cannot accidentally
    # become a required compatibility break in old reports.
    fields = (
        "path",
        "exists",
        "top_level",
        "revision",
        "branch",
        "remote",
        "working_tree_clean",
        "dirty_paths",
        "submodules",
    )
    for field in fields:
        # Remote identity is checked after the report's gate/verdict reducer.
        # Deferring that one field preserves the useful ``adoption.verdict``
        # diagnostic when a caller consistently forges the remote and gate
        # values together, while still returning the fresh observation for a
        # final exact comparison before validation succeeds.
        if field == "remote":
            continue
        if recorded.get(field) != expected.get(field):
            raise ValueError(
                f"result.environment.repository.{field}: inconsistent with current checkout"
            )

    if target.get("observed_revision") != recorded.get("revision"):
        raise ValueError("result.target.observed_revision: inconsistent with repository.revision")
    if target.get("working_tree_clean") != recorded.get("working_tree_clean"):
        raise ValueError(
            "result.target.working_tree_clean: inconsistent with repository.working_tree_clean"
        )

    # A pinned report can only claim the gate when the requested revision is
    # the revision actually observed.  The manifest's separate ``observed``
    # field is unavailable for in-memory reports, so do not infer a positive
    # gate when the producer already reported a mismatch.
    if target.get("requested_revision") is not None and not isinstance(
        target.get("requested_revision"), str
    ):
        raise ValueError("result.target.requested_revision: expected string or null")
    return expected


def _node_record(node: GraphNode, root: Path) -> dict[str, Any]:
    return {
        "kind": node.kind,
        "name": node.name,
        "qualified_name": node.qualified_name,
        "file_path": _relative_path(node.file_path, root),
        "line_start": node.line_start,
        "line_end": node.line_end,
        "language": node.language,
        "parent_name": node.parent_name,
        "params": node.params,
        "return_type": node.return_type,
        "is_test": bool(node.is_test),
        "extra": node.extra if isinstance(node.extra, Mapping) else {},
    }


def _edge_record(edge: GraphEdge, root: Path) -> dict[str, Any]:
    return {
        "kind": edge.kind,
        "source": edge.source_qualified,
        "target": edge.target_qualified,
        "file_path": _relative_path(edge.file_path, root),
        "line": edge.line,
        "extra": edge.extra if isinstance(edge.extra, Mapping) else {},
        "confidence": edge.confidence,
        "confidence_tier": edge.confidence_tier,
    }


def graph_fingerprint(store: GraphStore, root: str | Path) -> str:
    """Hash graph content while excluding database ids and update timestamps."""
    root_path = _canonical_path(root)
    nodes = sorted(
        (_node_record(node, root_path) for node in store.get_all_nodes(exclude_files=False)),
        key=lambda value: (value["qualified_name"], value["kind"]),
    )
    edges = sorted(
        (_edge_record(edge, root_path) for edge in _all_edges(store)),
        key=lambda value: (
            value["kind"],
            value["source"],
            value["target"],
            value["file_path"],
            value["line"],
        ),
    )
    return hashlib.sha256(_canonical_json({"nodes": nodes, "edges": edges}).encode()).hexdigest()


def _portable_graph_value(value: Any, root: Path) -> Any:
    """Normalize checkout-specific path prefixes in graph evidence.

    A fresh forget baseline is built in a temporary mirror, so absolute paths
    in qualified node/edge identities (and in adapter metadata) have a
    different prefix even when the graph is semantically identical.  Keep
    non-path strings untouched while replacing occurrences rooted at the
    supplied checkout with stable repository-relative spellings.
    """
    if isinstance(value, Mapping):
        return {key: _portable_graph_value(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_portable_graph_value(item, root) for item in value]
    if isinstance(value, tuple):
        return tuple(_portable_graph_value(item, root) for item in value)
    if not isinstance(value, str):
        return value
    text = value.replace("\\", "/")
    root_text = normalize_file_path(root).rstrip("/")
    if text == root_text:
        return "."
    marker = root_text + "/"
    if text.startswith(marker):
        return text[len(marker) :]
    # Qualified identities embed the file path before ``::``.  Metadata may
    # also contain a rooted path inside a larger command/provenance string.
    if marker in text:
        text = text.replace(marker, "")
    return text


def _portable_graph_fingerprint(store: GraphStore, root: str | Path) -> str:
    """Hash graph content independently of the temporary checkout prefix."""
    root_path = _canonical_path(root)
    nodes = sorted(
        (
            _portable_graph_value(_node_record(node, root_path), root_path)
            for node in store.get_all_nodes(exclude_files=False)
        ),
        key=lambda value: (value["qualified_name"], value["kind"]),
    )
    edges = sorted(
        (
            _portable_graph_value(_edge_record(edge, root_path), root_path)
            for edge in _all_edges(store)
        ),
        key=lambda value: (
            value["kind"],
            value["source"],
            value["target"],
            value["file_path"],
            value["line"],
        ),
    )
    return hashlib.sha256(_canonical_json({"nodes": nodes, "edges": edges}).encode()).hexdigest()


def _all_edges(store: GraphStore) -> list[GraphEdge]:
    rows = store._conn.execute("SELECT * FROM edges ORDER BY id").fetchall()
    return [store._row_to_edge(row) for row in rows]


def _looks_like_erlang_mfa(value: str) -> bool:
    """Return whether *value* has the shape of an Erlang MFA spelling.

    This deliberately only detects the structural marker (a module separator
    before ``/``).  Validation of the arity and atom spelling remains the
    responsibility of :func:`_mfa_parts`/``_split_erlang_symbol``.
    """
    if "/" not in value:
        return False
    function_part = value.rsplit("/", 1)[0]
    return ":" in function_part or "." in function_part


def _safe_endpoint_file(value: Any, root: Path) -> str | None:
    """Normalize a corpus endpoint file without permitting checkout escape."""
    if not isinstance(value, str):
        return None
    try:
        return _safe_relative_path(value, root, "endpoint.file")
    except ValueError:
        return None


def _qualified_path_info(value: Any, root: Path) -> tuple[Path, str, str] | None:
    """Return ``(absolute_file, relative_file, symbol)`` for a safe identity."""
    if not isinstance(value, str) or "::" not in value:
        return None
    path_text, symbol_text = value.split("::", 1)
    path_text = path_text.strip().replace("\\", "/")
    symbol_text = symbol_text.strip()
    if not path_text or not symbol_text or "::" in symbol_text:
        return None
    root_path = _canonical_path(root)
    path_value = Path(path_text)
    # Graph rows produced by the lifecycle builder commonly carry absolute
    # paths.  They are safe to inspect only when their resolved location stays
    # below the repository root.  Corpus/artifact endpoints still go through
    # ``_safe_endpoint_file`` and remain relative-only.
    is_windows_absolute = bool(re.match(r"^[A-Za-z]:($|/)", path_text))
    if is_windows_absolute:
        return None
    if path_value.is_absolute():
        candidate = path_value
    else:
        if any(part == ".." for part in path_text.split("/")):
            return None
        candidate = root_path / path_value
    try:
        absolute = candidate.resolve(strict=False)
        relative = absolute.relative_to(root_path).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None
    if "/" in symbol_text and _split_erlang_symbol(symbol_text) is None:
        return None
    return absolute, relative, symbol_text


def _endpoint_aliases(endpoint: Any, root: Path, store: GraphStore | None = None) -> set[str]:
    """Produce exact, conservative aliases for a corpus endpoint."""
    values: set[str] = set()
    if isinstance(endpoint, str):
        text = endpoint.strip().replace("\\", "/")
        if not text:
            return values
        if "::" in text:
            path, suffix = text.split("::", 1)
            suffix = suffix.strip()
            # Qualified identities are still repository paths.  Do not let an
            # absolute path, ``..`` component, or symlink escape participate in
            # endpoint matching, and reject malformed function arities before
            # retaining the raw spelling as an alias.
            relative = _safe_endpoint_file(path, root)
            if relative is None or not suffix or "::" in suffix:
                return values
            parsed_suffix = _split_erlang_symbol(suffix)
            if "/" in suffix and parsed_suffix is None:
                return values
            aliases = {f"{relative}::{suffix}"}
            if parsed_suffix is not None:
                symbol_name, symbol_arity = parsed_suffix
                canonical_suffix = (
                    f"{symbol_name}/{symbol_arity}"
                    if symbol_arity is not None
                    else symbol_name
                )
                aliases.add(f"{relative}::{canonical_suffix}")
                if ":" in symbol_name:
                    module_name, function_name = symbol_name.split(":", 1)
                    dot_name = f"{module_name}.{function_name}"
                    aliases.add(
                        f"{relative}::{dot_name}/{symbol_arity}"
                        if symbol_arity is not None
                        else f"{relative}::{dot_name}"
                    )
                elif "." in symbol_name:
                    module_name, function_name = symbol_name.rsplit(".", 1)
                    colon_name = f"{module_name}:{function_name}"
                    aliases.add(
                        f"{relative}::{colon_name}/{symbol_arity}"
                        if symbol_arity is not None
                        else f"{relative}::{colon_name}"
                    )
                if store is not None:
                    matching_nodes = [
                        node
                        for node in store.get_nodes_by_file(
                            normalize_file_path(_canonical_path(root) / relative)
                        )
                        if _node_symbol_matches(node, suffix)
                    ]
                    if len(matching_nodes) == 1:
                        aliases.add(matching_nodes[0].qualified_name)
            return aliases

        # A string that looks like an MFA must be valid before *any* alias is
        # retained.  Otherwise ``m:f/999`` would match itself as a raw string.
        if _looks_like_erlang_mfa(text):
            parsed = _mfa_parts(text)
            if parsed is None:
                return values
            module, name, parsed_arity = parsed
            values.update(
                {
                    text,
                    f"{module}:{name}/{parsed_arity}",
                    f"{module}.{name}/{parsed_arity}",
                }
            )
            if (
                store is not None
                and store.count_erlang_mfa(
                    module, name, parsed_arity, repo_root=root
                )
                == 1
            ):
                mfa_nodes = store.find_erlang_mfa(
                    module, name, parsed_arity, limit=2, repo_root=root
                )
                if len(mfa_nodes) == 1:
                    values.add(mfa_nodes[0].qualified_name)
            return values
        values.add(text)
        return values
    if not isinstance(endpoint, Mapping):
        return values
    file_name = endpoint.get("file")
    symbol = endpoint.get("symbol")
    endpoint_arity: Any = endpoint.get("arity")
    has_file = "file" in endpoint
    file_rel = _safe_endpoint_file(file_name, root)
    if has_file and file_rel is None:
        return set()
    if file_rel:
        # A bare file alias is valid only for a file-only endpoint.  Retaining
        # it for ``{file, symbol}`` lets a wrong symbol match a file edge.
        if symbol is None:
            values.update({file_rel, normalize_file_path(root / file_rel)})
    if symbol is not None:
        symbol_text = str(symbol)
        parsed_symbol = _split_erlang_symbol(symbol_text, endpoint_arity)
        if parsed_symbol is not None:
            symbol_name, symbol_arity = parsed_symbol
            canonical_symbol = (
                f"{symbol_name}/{symbol_arity}" if symbol_arity is not None else symbol_name
            )
        else:
            # Invalid arity/symbol combinations are deliberately unmatchable.
            canonical_symbol = None
        if file_rel:
            if canonical_symbol is None:
                return set()
            values.add(f"{file_rel}::{canonical_symbol}")
            # Accept both Erlang separator spellings when the corpus includes
            # a module-qualified symbol but keep the file constraint intact.
            if ":" in canonical_symbol:
                module_name, function_arity = canonical_symbol.split(":", 1)
                values.add(f"{file_rel}::{module_name}.{function_arity}")
            elif "." in canonical_symbol:
                module_name, function_arity = canonical_symbol.rsplit(".", 1)
                values.add(f"{file_rel}::{module_name}:{function_arity}")
            if store is not None:
                matching_nodes = [
                    node
                    for node in store.get_nodes_by_file(normalize_file_path(root / file_rel))
                    if _node_symbol_matches(node, symbol, endpoint_arity)
                ]
                # A symbol-only file-qualified endpoint is safe only when it
                # identifies one node. In particular, do not let ``run``
                # resolve to an arbitrary member of an overloaded module.
                if len(matching_nodes) == 1:
                    matched_node = matching_nodes[0]
                    values.add(matched_node.qualified_name)
        elif canonical_symbol is not None:
            # A symbol-only endpoint intentionally has no file constraint.
            values.add(canonical_symbol)
            if ":" in canonical_symbol and "/" in canonical_symbol:
                module, function_arity = canonical_symbol.split(":", 1)
                values.add(f"{module}.{function_arity}")
    return values


def _edge_endpoint_aliases(value: str, root: Path, store: GraphStore) -> set[str]:
    qualified = _qualified_path_info(value, root)
    if "::" in value and qualified is None:
        return set()
    if qualified is not None:
        absolute_path, relative_path, symbol_text = qualified
        aliases = {f"{relative_path}::{symbol_text}"}
        parsed_symbol = _split_erlang_symbol(symbol_text)
        if parsed_symbol is not None:
            symbol_name, symbol_arity = parsed_symbol
            suffix = f"/{symbol_arity}" if symbol_arity is not None else ""
            # File-qualified corpus endpoints commonly name only the
            # function (``file::run/0``), while graph identities include the
            # owning module (``file::module.run/0``).  The file constraint is
            # retained for this alias, so it cannot cross-match another file.
            if ":" in symbol_name:
                _module, function = symbol_name.split(":", 1)
                aliases.add(f"{relative_path}::{function}{suffix}")
            elif "." in symbol_name:
                _module, function = symbol_name.rsplit(".", 1)
                aliases.add(f"{relative_path}::{function}{suffix}")
        file_nodes: dict[str, GraphNode] = {}
        for file_key in (normalize_file_path(absolute_path), relative_path):
            for candidate in store.get_nodes_by_file(file_key):
                file_nodes[candidate.qualified_name] = candidate
        matching_nodes = [
            node for node in file_nodes.values() if _node_symbol_matches(node, symbol_text)
        ]
        if len(matching_nodes) == 1:
            aliases.add(matching_nodes[0].qualified_name)
        return aliases
    aliases = {
        value,
        value.replace("\\", "/"),
    }
    node = store.get_node(value)
    if node is not None:
        aliases.add(node.qualified_name)
    if "::" in value:
        return aliases
    # Generic Erlang nodes use ``module.function/arity`` while corpus/tool
    # endpoints often use ``module:function/arity``.
    tail = value.rsplit("::", 1)[-1]
    if "/" in tail and "." in tail:
        function, arity = tail.rsplit("/", 1)
        # A dot in the arity (for example ``foo/1.0``) is not a dot-style
        # MFA.  Keep malformed edge identities unmatchable instead of
        # allowing ``rsplit`` to raise or broadening the alias set.
        if "." not in function:
            return aliases
        module, name = function.rsplit(".", 1)
        parsed_arity = _parse_erlang_arity(arity)
        if parsed_arity is not None:
            aliases.update(
                {
                    f"{module}:{name}/{parsed_arity}",
                }
            )
    return aliases


def _target_mfa(target: Any) -> tuple[str, str, int] | None:
    """Extract an exact MFA from either a string or a symbol-only endpoint."""
    if isinstance(target, str):
        return _mfa_parts(target.strip())
    if isinstance(target, Mapping) and not isinstance(target.get("file"), str):
        symbol = target.get("symbol")
        arity = target.get("arity")
        if isinstance(symbol, str):
            parsed = _split_erlang_symbol(symbol, arity)
            if parsed is not None:
                name, parsed_arity = parsed
                if parsed_arity is not None:
                    if ":" in name:
                        module, function = name.split(":", 1)
                    elif "." in name:
                        module, function = name.rsplit(".", 1)
                    else:
                        return None
                    return module.strip("'"), function.strip("'"), parsed_arity
    return None


def _target_mfa_ambiguous(
    target: Any,
    store: GraphStore,
    *,
    repo_root: str | Path | None = None,
) -> bool:
    """Return whether an exact MFA resolves to multiple nodes in scope."""
    parsed = _target_mfa(target)
    return (
        parsed is not None
        and store.count_erlang_mfa(*parsed, repo_root=repo_root) > 1
    )


def _endpoint_matches(value: str, endpoint: Any, root: Path, store: GraphStore) -> bool:
    predicted = _edge_endpoint_aliases(value, root, store)
    expected = _endpoint_aliases(endpoint, root, store)
    return bool(predicted.intersection(expected))


def _contract_path_alias(value: Any, root: Path) -> str | None:
    """Return a stable repository-relative alias for a qualified endpoint."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if "::" not in text:
        return text or None
    qualified = _qualified_path_info(text, root)
    if qualified is None:
        return None
    _absolute, relative, symbol = qualified
    return f"{relative}::{symbol}"


def _endpoint_descriptor(endpoint: Any, root: Path) -> dict[str, Any]:
    """Describe an endpoint using only repository-relative, pure data.

    ``score_case`` historically asks a live ``GraphStore`` to expand MFA
    aliases.  Result validation runs after that store is closed, so the
    corpus contract carries this small descriptor and uses it for matching.
    The descriptor deliberately keeps file, function, and MFA constraints
    separate; a same-named function in a foreign file must not satisfy a
    file-qualified expectation.
    """
    descriptor: dict[str, Any] = {
        "file": None,
        "symbol": None,
        "module": None,
        "arity": None,
        "mfa": None,
        "dynamic": None,
        "literal": None,
        "qualified": None,
    }
    if isinstance(endpoint, str):
        text = endpoint.strip().replace("\\", "/")
        if not text:
            return descriptor
        if "::" in text:
            qualified = _qualified_path_info(text, root)
            if qualified is None:
                return descriptor
            _absolute, relative, suffix = qualified
            descriptor["file"] = relative
            descriptor["qualified"] = f"{relative}::{suffix}"
            parsed = _split_erlang_symbol(suffix)
            if parsed is not None:
                name, arity = parsed
                descriptor["symbol"] = name
                descriptor["arity"] = arity
                if ":" in name:
                    module, function = name.split(":", 1)
                    descriptor["module"] = module.strip("'")
                    descriptor["symbol"] = function.strip("'")
                elif "." in name:
                    module, function = name.rsplit(".", 1)
                    descriptor["module"] = module.strip("'")
                    descriptor["symbol"] = function.strip("'")
                if descriptor["module"] and arity is not None:
                    descriptor["mfa"] = (
                        descriptor["module"], descriptor["symbol"], arity
                    )
            return descriptor
        parsed_mfa = _mfa_parts(text)
        if parsed_mfa is not None:
            module, function, arity = parsed_mfa
            descriptor.update(
                {
                    "module": module,
                    "symbol": function,
                    "arity": arity,
                    "mfa": parsed_mfa,
                }
            )
            return descriptor
        dynamic = _dynamic_mfa_spelling(text)
        if dynamic is not None:
            descriptor["dynamic"] = dynamic
        else:
            descriptor["literal"] = text
        return descriptor
    if not isinstance(endpoint, Mapping):
        return descriptor
    if "file" in endpoint:
        descriptor["file"] = _safe_endpoint_file(endpoint.get("file"), root)
    symbol_value = endpoint.get("symbol")
    explicit_arity = endpoint.get("arity") if "arity" in endpoint else None
    if isinstance(symbol_value, str):
        parsed = _split_erlang_symbol(symbol_value, explicit_arity)
        if parsed is not None:
            name, arity = parsed
            descriptor["arity"] = arity
            if ":" in name:
                module, function = name.split(":", 1)
                descriptor["module"] = module.strip("'")
                descriptor["symbol"] = function.strip("'")
            elif "." in name:
                module, function = name.rsplit(".", 1)
                descriptor["module"] = module.strip("'")
                descriptor["symbol"] = function.strip("'")
            else:
                descriptor["symbol"] = name.strip("'")
            if descriptor["module"] and arity is not None:
                descriptor["mfa"] = (
                    descriptor["module"], descriptor["symbol"], arity
                )
        else:
            # Invalid endpoint arities are intentionally unmatchable.
            descriptor["symbol"] = None
    elif symbol_value is not None:
        descriptor["symbol"] = str(symbol_value)
    if descriptor["file"] is not None and descriptor["symbol"] is not None:
        suffix = str(descriptor["symbol"])
        if descriptor["arity"] is not None:
            suffix = f"{suffix}/{descriptor['arity']}"
        if descriptor["module"]:
            suffix = f"{descriptor['module']}.{suffix}"
        descriptor["qualified"] = f"{descriptor['file']}::{suffix}"
    return descriptor


def _prediction_descriptor(value: Any, root: Path) -> dict[str, Any]:
    """Describe a prediction endpoint without consulting a graph store."""
    return _endpoint_descriptor(value, root)


def _normalise_contract_aliases(aliases: Any, root: Path) -> list[str]:
    if not isinstance(aliases, (list, tuple, set)):
        return []
    normalized: set[str] = set()
    for alias in aliases:
        if not isinstance(alias, str) or not alias.strip():
            continue
        value = _contract_path_alias(alias, root)
        if value is not None:
            normalized.add(value)
    return sorted(normalized)


def _endpoint_binding(endpoint: Any, root: Path, store: GraphStore | None) -> dict[str, Any]:
    """Freeze endpoint aliases needed by validation after the graph closes."""
    descriptor = _endpoint_descriptor(endpoint, root)
    aliases: set[str] = set()
    if store is not None:
        aliases.update(_endpoint_aliases(endpoint, root, store))
    # Structural aliases make dry-run/externally supplied contracts useful and
    # ensure the binding remains understandable without a graph database.
    if descriptor.get("literal"):
        aliases.add(descriptor["literal"])
    if descriptor.get("dynamic"):
        aliases.add(descriptor["dynamic"])
    mfa = descriptor.get("mfa")
    if isinstance(mfa, tuple) and len(mfa) == 3:
        module, symbol, arity = mfa
        aliases.update({f"{module}:{symbol}/{arity}", f"{module}.{symbol}/{arity}"})
    qualified = descriptor.get("qualified")
    if isinstance(qualified, str):
        aliases.add(qualified)
    normalized = _normalise_contract_aliases(aliases, root)
    qualified_aliases = sorted(alias for alias in normalized if "::" in alias)
    return {
        "aliases": normalized,
        "qualified_aliases": qualified_aliases,
        "file": descriptor.get("file"),
        "symbol": descriptor.get("symbol"),
        "module": descriptor.get("module"),
        "arity": descriptor.get("arity"),
        "mfa": list(mfa) if isinstance(mfa, tuple) else None,
        "dynamic": descriptor.get("dynamic"),
        "literal": descriptor.get("literal"),
    }


def _contract_endpoint_matches(
    predicted_value: Any, binding: Mapping[str, Any], root: Path
) -> bool:
    """Match one prediction endpoint against an immutable contract binding."""
    if not isinstance(binding, Mapping):
        return False
    predicted = _prediction_descriptor(predicted_value, root)
    expected_file = binding.get("file")
    if expected_file is not None and predicted.get("file") != expected_file:
        return False
    expected_mfa = binding.get("mfa")
    if isinstance(expected_mfa, list) and len(expected_mfa) == 3:
        if tuple(expected_mfa) != predicted.get("mfa"):
            return False
        # A live store may have resolved a bare MFA to one qualified node.  If
        # the prediction is qualified, require that exact frozen file alias;
        # this rejects a foreign file reusing the same MFA.
        qualified_aliases = binding.get("qualified_aliases")
        predicted_qualified = predicted.get("qualified")
        if (
            isinstance(qualified_aliases, list)
            and qualified_aliases
            and predicted.get("file") is not None
            and predicted_qualified not in qualified_aliases
        ):
            return False
        return True
    expected_dynamic = binding.get("dynamic")
    if expected_dynamic is not None:
        return predicted.get("dynamic") == expected_dynamic
    expected_symbol = binding.get("symbol")
    if (
        expected_file is not None
        and expected_symbol is None
        and expected_mfa is None
        and binding.get("literal") is None
        and binding.get("dynamic") is None
    ):
        # A file-only corpus endpoint intentionally accepts any identity from
        # that file, while still rejecting a same-named endpoint elsewhere.
        return predicted.get("file") == expected_file
    if expected_symbol is not None:
        if predicted.get("symbol") != expected_symbol:
            return False
        expected_module = binding.get("module")
        if expected_module is not None and predicted.get("module") != expected_module:
            return False
        expected_arity = binding.get("arity")
        return expected_arity is None or predicted.get("arity") == expected_arity
    expected_literal = binding.get("literal")
    if expected_literal is not None:
        return predicted.get("literal") == expected_literal
    aliases = set(binding.get("aliases", [])) if isinstance(binding.get("aliases"), list) else set()
    predicted_aliases = set()
    qualified = predicted.get("qualified")
    if isinstance(qualified, str):
        predicted_aliases.add(qualified)
    if isinstance(predicted_value, str):
        text = predicted_value.strip().replace("\\", "/")
        if text:
            predicted_aliases.add(text)
    return bool(aliases.intersection(predicted_aliases))


def _contract_relation_matches(
    predicted: Mapping[str, Any],
    expected: Mapping[str, Any],
    root: Path,
) -> bool:
    if str(predicted.get("relation", "")).casefold() != str(
        expected.get("relation", "")
    ).casefold():
        return False
    matching = expected.get("matching")
    if not isinstance(matching, Mapping):
        return False
    target_binding = matching.get("target")
    if not _contract_endpoint_matches(predicted.get("target"), target_binding, root):
        return False
    if "source" in expected:
        source_binding = matching.get("source")
        if not _contract_endpoint_matches(predicted.get("source"), source_binding, root):
            return False
    return True


def _contract_unresolved_relation_matches(
    predicted: Mapping[str, Any],
    expected: Mapping[str, Any],
    root: Path,
) -> bool:
    if _contract_relation_matches(predicted, expected, root):
        return True
    if str(predicted.get("relation", "")).casefold() != str(
        expected.get("relation", "")
    ).casefold():
        return False
    matching = expected.get("matching")
    if not isinstance(matching, Mapping):
        return False
    if "source" in expected and not _contract_endpoint_matches(
        predicted.get("source"), matching.get("source"), root
    ):
        return False
    target_binding = matching.get("target")
    if not isinstance(target_binding, Mapping):
        return False
    expected_dynamic = target_binding.get("dynamic")
    predicted_dynamic = _dynamic_mfa_spelling(predicted.get("target"))
    if expected_dynamic is not None:
        return expected_dynamic == predicted_dynamic
    expected_mfa = target_binding.get("mfa")
    predicted_mfa = _mfa_parts(
        predicted.get("target", "").rsplit("::", 1)[-1]
    ) if isinstance(predicted.get("target"), str) else None
    return isinstance(expected_mfa, list) and tuple(expected_mfa) == predicted_mfa


def _canonical_endpoint_value(endpoint: Any, root: Path) -> Any:
    """Normalize one corpus endpoint into portable JSON data."""
    if isinstance(endpoint, str):
        text = endpoint.strip().replace("\\", "/")
        if "::" in text:
            qualified = _qualified_path_info(text, root)
            if qualified is not None:
                _absolute, relative, suffix = qualified
                parsed = _split_erlang_symbol(suffix)
                if parsed is not None:
                    name, arity = parsed
                    suffix = f"{name}/{arity}" if arity is not None else name
                return f"{relative}::{suffix}"
        parsed = _mfa_parts(text)
        if parsed is not None:
            module, name, arity = parsed
            return f"{module}:{name}/{arity}"
        return text
    if isinstance(endpoint, Mapping):
        normalized: dict[str, Any] = {}
        for key in sorted(endpoint, key=str):
            value = endpoint[key]
            if key == "file" and isinstance(value, str):
                safe = _safe_endpoint_file(value, root)
                normalized[key] = safe if safe is not None else value.replace("\\", "/")
            elif key == "arity":
                parsed_arity = _parse_erlang_arity(value)
                normalized[key] = parsed_arity if parsed_arity is not None else value
            elif key == "symbol" and isinstance(value, str):
                parsed = _split_erlang_symbol(value, endpoint.get("arity"))
                if parsed is not None:
                    name, arity = parsed
                    normalized[key] = name
                    if "arity" not in endpoint and arity is not None:
                        normalized["arity"] = arity
                else:
                    normalized[key] = value.strip()
            else:
                normalized[key] = _canonical_contract_value(value, root)
        return normalized
    return _canonical_contract_value(endpoint, root)


def _canonical_contract_value(value: Any, root: Path) -> Any:
    """Canonicalize arbitrary JSON-like corpus metadata."""
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_contract_value(value[key], root)
            for key in sorted(value, key=str)
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_contract_value(item, root) for item in value]
    if isinstance(value, set):
        return sorted(_canonical_contract_value(item, root) for item in value)
    if isinstance(value, Path):
        return value.as_posix()
    return value


def _canonical_contract_relation(
    relation: Mapping[str, Any], root: Path, store: GraphStore | None
) -> dict[str, Any]:
    canonical: dict[str, Any] = {}
    for key in sorted(relation, key=str):
        if key in {"source", "target"}:
            canonical[key] = _canonical_endpoint_value(relation.get(key), root)
        else:
            canonical[str(key)] = _canonical_contract_value(relation.get(key), root)
    if "relation" in canonical:
        canonical["relation"] = str(canonical["relation"])
    # Matching data is deliberately separate from the canonical source
    # payload.  It may contain graph-derived qualified aliases, while the
    # digest remains stable across temporary GraphStore locations.
    matching: dict[str, Any] = {
        "target": _endpoint_binding(canonical.get("target"), root, store),
    }
    if "source" in canonical:
        matching["source"] = _endpoint_binding(canonical.get("source"), root, store)
    canonical["matching"] = matching
    return canonical


def _contract_payload(contract: Mapping[str, Any], *, include_matching: bool) -> dict[str, Any]:
    """Return canonical contract data with optional graph-derived bindings."""
    cases: list[dict[str, Any]] = []
    raw_cases = contract.get("cases", [])
    if isinstance(raw_cases, list):
        for case in raw_cases:
            if not isinstance(case, Mapping):
                continue
            copied = _canonical_contract_value(dict(case), Path("."))
            if not isinstance(copied, dict):
                continue
            if not include_matching:
                expected = copied.get("expected")
                if isinstance(expected, Mapping):
                    expected_copy = dict(expected)
                    for relation_kind in ("positive", "negative", "unresolved"):
                        relations = expected_copy.get(relation_kind)
                        if isinstance(relations, list):
                            expected_copy[relation_kind] = [
                                {
                                    key: value
                                    for key, value in relation.items()
                                    if key != "matching"
                                }
                                for relation in relations
                                if isinstance(relation, Mapping)
                            ]
                    copied["expected"] = expected_copy
            cases.append(copied)
    return {"version": contract.get("version"), "cases": cases}


def _contract_digest_payload(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return the complete digest input, excluding the digest field itself."""
    return _contract_payload(contract, include_matching=True)


def _contract_source_payload(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return the source-corpus portion of a contract for external comparison."""
    return _contract_payload(contract, include_matching=False)


def _build_corpus_contract(
    corpus: Mapping[str, Any], root: Path, store: GraphStore | None
) -> dict[str, Any]:
    """Freeze the case/query/expected contract into a portable result field."""
    contract_cases: list[dict[str, Any]] = []
    raw_cases = corpus.get("cases", [])
    if isinstance(raw_cases, Sequence) and not isinstance(raw_cases, (str, bytes, bytearray)):
        for case in raw_cases:
            if not isinstance(case, Mapping):
                continue
            expected_raw = case.get("expected", {})
            expected_mapping = expected_raw if isinstance(expected_raw, Mapping) else {}
            expected: dict[str, Any] = {}
            for relation_kind in ("positive", "negative", "unresolved"):
                raw_relations = expected_mapping.get(relation_kind, [])
                if not isinstance(raw_relations, list):
                    raw_relations = []
                expected[relation_kind] = [
                    _canonical_contract_relation(relation, root, store)
                    for relation in raw_relations
                    if isinstance(relation, Mapping)
                ]
            if expected_mapping.get("allow_empty") is True:
                expected["allow_empty"] = True
            contract_case: dict[str, Any] = {
                "id": case.get("id"),
                "category": case.get("category"),
                "description": _canonical_contract_value(case.get("description"), root),
                "query": _canonical_contract_value(case.get("query", {}), root),
                "expected": expected,
                "required_diagnostics": _canonical_contract_value(
                    case.get("required_diagnostics", []), root
                ),
                "review": _canonical_contract_value(case.get("review", {}), root),
            }
            if isinstance(case.get("impact"), Mapping):
                contract_case["impact"] = _canonical_contract_value(case["impact"], root)
            # ``allow_empty`` can live in review in legacy corpora; record the
            # effective value so validation does not need the source artifact.
            contract_case["allow_empty"] = _allows_empty(case)
            contract_cases.append(contract_case)
    contract: dict[str, Any] = {
        "version": _CORPUS_CONTRACT_VERSION,
        "cases": contract_cases,
    }
    digest = hashlib.sha256(
        _canonical_json(_contract_source_payload(contract)).encode("utf-8")
    ).hexdigest()
    contract["digest"] = digest
    return contract


def _edge_matches_query_target(
    edge: GraphEdge,
    target: Any,
    node: GraphNode | None,
    root: Path,
    store: GraphStore,
) -> bool:
    """Match a query target while retaining unique unresolved MFA candidates."""
    if _endpoint_matches(edge.target_qualified, target, root, store):
        return True
    if node is None or not isinstance(target, Mapping) or not isinstance(target.get("file"), str):
        return False
    # A Generic cross-file edge is often intentionally bare. It may be shown
    # as a candidate for a file-qualified query only when its exact MFA maps
    # to one repository-local definition. The later scorer still distinguishes
    # this unresolved target from a file-qualified expected relation.
    if node.kind not in {"Function", "Test"}:
        return False
    node_arity = _parse_erlang_arity(
        node.extra.get("arity") if isinstance(node.extra, Mapping) else None
    )
    if node_arity is None:
        node_tail = node.qualified_name.rsplit("::", 1)[-1]
        node_parts = _split_erlang_symbol(node_tail)
        node_arity = node_parts[1] if node_parts else None
    module = node.parent_name
    if not isinstance(module, str) or node_arity is None:
        return False
    edge_mfa = _mfa_parts(edge.target_qualified.rsplit("::", 1)[-1])
    if edge_mfa != (module, node.name, node_arity):
        return False
    return store.count_erlang_mfa(
        module,
        node.name,
        node_arity,
        repo_root=root,
    ) == 1


def _resolve_query_node(target: Any, root: Path, store: GraphStore) -> GraphNode | None:
    if isinstance(target, Mapping):
        file_name = target.get("file")
        symbol = target.get("symbol")
        if isinstance(file_name, str):
            file_rel = _safe_endpoint_file(file_name, root)
            if file_rel is None:
                return None
            file_path = normalize_file_path(_canonical_path(root) / file_rel)
            nodes = store.get_nodes_by_file(file_path)
            if symbol is None:
                return next((node for node in nodes if node.kind == "File"), None)
            arity = target.get("arity")
            exact = [node for node in nodes if _node_symbol_matches(node, symbol, arity)]
            # A file-qualified target without an arity is only safe when it
            # resolves to one node.  Picking the first overloaded function
            # would make a wrong-arity caller look like a golden hit.
            if len(exact) != 1:
                # A module target is represented by one Class node in the
                # Generic Erlang graph; accepting that unique node remains
                # useful for module-level queries while preserving ambiguity
                # fail-closed behavior for functions.
                classes = [node for node in exact if node.kind == "Class"]
                if len(classes) == 1 and len(exact) == len(classes):
                    return classes[0]
                return None
            return (
                sorted(exact, key=lambda node: (node.kind, node.qualified_name))[0]
                if exact
                else None
            )
    if isinstance(target, str):
        text = target.strip().replace("\\", "/")
        if "::" in text:
            path_text, symbol_text = text.split("::", 1)
            symbol_text = symbol_text.strip()
            if not path_text or not symbol_text or "::" in symbol_text:
                return None
            # Corpus/query paths are repository-relative POSIX spellings.  An
            # absolute path, lexical ``..``, or symlink escape is rejected
            # before consulting the graph so a qualified string cannot bypass
            # the artifact boundary.
            if (
                any(part == ".." for part in path_text.split("/"))
                or Path(path_text).is_absolute()
                or re.match(r"^[A-Za-z]:($|/)", path_text)
            ):
                return None
            root_path = _canonical_path(root)
            candidate_path = Path(path_text)
            candidate_path = root_path / candidate_path
            try:
                candidate_path = candidate_path.resolve(strict=False)
                candidate_path.relative_to(root_path)
            except (OSError, RuntimeError, ValueError):
                return None
            file_keys = [normalize_file_path(candidate_path)]
            relative_key = candidate_path.relative_to(root_path).as_posix()
            if relative_key not in file_keys:
                file_keys.append(relative_key)
            nodes_by_qn: dict[str, GraphNode] = {}
            for file_key in file_keys:
                for candidate in store.get_nodes_by_file(file_key):
                    nodes_by_qn[candidate.qualified_name] = candidate
                direct = store.get_node(f"{file_key}::{symbol_text}")
                if direct is not None:
                    nodes_by_qn[direct.qualified_name] = direct
            if "/" in symbol_text and _split_erlang_symbol(symbol_text) is None:
                return None
            exact = [
                node
                for node in nodes_by_qn.values()
                if _node_symbol_matches(node, symbol_text)
            ]
            if len(exact) == 1:
                return exact[0]
            # A module/file anchor may be represented by a single Class node;
            # function overloads remain intentionally ambiguous.
            classes = [node for node in exact if node.kind == "Class"]
            if len(classes) == 1 and len(exact) == len(classes):
                return classes[0]
            return None

        node = store.get_node(text)
        if node is not None:
            return node
        # Exact Erlang MFA resolution avoids broad name matching.
        if ":" in text and "/" in text:
            try:
                module, rest = text.split(":", 1)
                name, raw_arity = rest.rsplit("/", 1)
                parsed_arity = _parse_erlang_arity(raw_arity)
                if parsed_arity is not None:
                    matches = store.find_erlang_mfa(
                        module.strip("'"),
                        name.strip("'"),
                        parsed_arity,
                        limit=2,
                        repo_root=root,
                    )
                    if len(matches) == 1:
                        return matches[0]
            except (ValueError, TypeError, OverflowError):
                return None
        # Strings that look like an MFA but fail validation must never fall
        # through to broad text search; a malformed arity is not a symbol
        # name and must remain unmatchable.
        if _looks_like_erlang_mfa(text) and _mfa_parts(text) is None:
            return None
        candidates = [node for node in store.search_nodes(text, limit=20) if node.name == text]
        return candidates[0] if len(candidates) == 1 else None
    return None


def _query_edges(
    store: GraphStore, root: Path, query: Mapping[str, Any]
) -> tuple[list[GraphEdge], str | None]:
    kind = str(query.get("kind", ""))
    target = query.get("target")
    node = _resolve_query_node(target, root, store)
    target_values = _endpoint_aliases(target, root, store)
    edges: list[GraphEdge] = []

    # A bare MFA is authoritative only when it identifies one repository
    # definition.  Otherwise alias matching would return every same-named
    # call and turn an ambiguous query into a false-positive result.
    if _target_mfa_ambiguous(target, store, repo_root=root):
        return [], None

    # A file-qualified function target with no unique node is ambiguous. Do
    # not fall back to bare aliases, which could merge overloads or same-name
    # functions from another file into one query result.
    if node is None and isinstance(target, Mapping) and isinstance(target.get("file"), str):
        file_rel = _safe_endpoint_file(target.get("file"), root)
        if file_rel is None:
            return [], None
        file_nodes = store.get_nodes_by_file(
            normalize_file_path(_canonical_path(root) / file_rel)
        )
        matching_nodes = [
            candidate
            for candidate in file_nodes
            if _node_symbol_matches(candidate, target.get("symbol"), target.get("arity"))
        ]
        if len(matching_nodes) > 1:
            return [], None

    if kind in {"callers_of", "references", "references_to", "implementers_of"}:
        edge_kind = {
            "callers_of": "CALLS",
            "references": "REFERENCES",
            "references_to": "REFERENCES",
            "implementers_of": "IMPLEMENTS",
        }[kind]
        if node is not None:
            edges.extend(
                edge
                for edge in store.iter_edges_by_target(node.qualified_name)
                if edge.kind == edge_kind
            )
            # Bare Erlang edges are intentionally retained as candidates; an
            # exact target alias is enough to inspect them, but not to claim a
            # function-level semantic resolution.
            if kind in {"callers_of", "references", "references_to", "implementers_of"}:
                # Canonical incoming edges were indexed above.  Only bare
                # endpoints can need alias/MFA reconciliation; avoid
                # materializing every edge in a large repository for each
                # targeted review query.
                bare_values: list[str] = []
                if node.kind in {"Function", "Test"}:
                    node_extra = node.extra if isinstance(node.extra, Mapping) else {}
                    raw_arity = node_extra.get("arity")
                    if raw_arity is None:
                        node_tail = node.qualified_name.rsplit("::", 1)[-1]
                        parsed_tail = _split_erlang_symbol(node_tail)
                        raw_arity = parsed_tail[1] if parsed_tail else None
                    if isinstance(raw_arity, int) and 0 <= raw_arity <= _MAX_ERLANG_ARITY:
                        bare_values.extend(
                            [
                                f"{node.name}/{raw_arity}",
                                f"{node.parent_name}:{node.name}/{raw_arity}",
                                f"{node.parent_name}.{node.name}/{raw_arity}",
                            ]
                        )
                if bare_values:
                    placeholders = ",".join("?" for _ in bare_values)
                    rows = store._conn.execute(
                        f"SELECT * FROM edges WHERE kind = ? "
                        f"AND target_qualified IN ({placeholders}) ORDER BY id",
                        (edge_kind, *bare_values),
                    ).fetchall()
                else:
                    rows = []
                for row in rows:
                    edge = store._row_to_edge(row)
                    if _edge_matches_query_target(edge, target, node, root, store):
                        edges.append(edge)
        else:
            candidate_edges: list[GraphEdge]
            if target_values:
                values = sorted(value for value in target_values if isinstance(value, str))
                placeholders = ",".join("?" for _ in values)
                rows = store._conn.execute(
                    f"SELECT * FROM edges WHERE kind = ? "
                    f"AND target_qualified IN ({placeholders}) ORDER BY id",
                    (edge_kind, *values),
                ).fetchall()
                candidate_edges = [store._row_to_edge(row) for row in rows]
            else:
                candidate_edges = []
            for edge in candidate_edges:
                if edge.kind == edge_kind and (
                    edge.target_qualified in target_values
                    or _endpoint_matches(edge.target_qualified, target, root, store)
                ):
                    edges.append(edge)
    elif kind == "tests_for":
        if node is not None:
            if node.kind == "File":
                # A file-qualified test anchor asks which production edges
                # point at tests in that file.  This is useful for corpus
                # cases that freeze a Common Test/EUnit suite path.
                node_file = normalize_file_path(node.file_path)
                rows = store._conn.execute(
                    "SELECT * FROM edges WHERE kind = 'TESTED_BY' "
                    "AND target_qualified LIKE ? ORDER BY id",
                    (node_file + "::%",),
                ).fetchall()
                edges.extend(store._row_to_edge(row) for row in rows)
            else:
                # TESTED_BY is stored as source=production, target=test.
                # Querying incoming edges here silently returns no tests for
                # a production function and makes the adoption corpus
                # under-report coverage.
                edges.extend(
                    edge
                    for edge in store.iter_edges_by_source(node.qualified_name)
                    if edge.kind == "TESTED_BY"
                )
        if isinstance(target, Mapping) and isinstance(target.get("file"), str):
            relative = _safe_endpoint_file(target.get("file"), root)
            if relative is None:
                return [], None
            rows = store._conn.execute(
                "SELECT * FROM edges WHERE kind = 'TESTED_BY' "
                "AND target_qualified LIKE ? ORDER BY id",
                (normalize_file_path(_canonical_path(root) / relative) + "::%",),
            ).fetchall()
            for row in rows:
                edge = store._row_to_edge(row)
                if _relative_path(edge.target_qualified.split("::", 1)[0], root) == relative:
                    if edge not in edges:
                        edges.append(edge)
    return sorted(
        edges, key=lambda edge: (edge.kind, edge.source_qualified, edge.target_qualified, edge.line)
    ), node.qualified_name if node else None


def _predicted_relation(edge: GraphEdge, root: Path, store: GraphStore) -> dict[str, Any]:
    return {
        "relation": edge.kind,
        "source": edge.source_qualified,
        "target": edge.target_qualified,
        "source_file": _relative_path(edge.source_qualified.split("::", 1)[0], root),
        "target_file": _relative_path(edge.target_qualified.split("::", 1)[0], root)
        if "::" in edge.target_qualified
        else None,
        "line": edge.line,
        "extra": edge.extra if isinstance(edge.extra, Mapping) else {},
        "confidence": edge.confidence,
        "confidence_tier": edge.confidence_tier,
    }


def _relation_matches(
    predicted: Mapping[str, Any], expected: Mapping[str, Any], root: Path, store: GraphStore
) -> bool:
    if (
        str(predicted.get("relation", "")).casefold()
        != str(expected.get("relation", "")).casefold()
    ):
        return False
    if not _endpoint_matches(str(predicted.get("target", "")), expected.get("target"), root, store):
        return False
    if "source" in expected and not _endpoint_matches(
        str(predicted.get("source", "")), expected.get("source"), root, store
    ):
        return False
    return True


def _prediction_is_unresolved(predicted: Mapping[str, Any]) -> bool:
    """Return whether a prediction is explicitly an unresolved candidate."""
    target = predicted.get("target")
    extra = predicted.get("extra")
    if isinstance(extra, Mapping):
        resolution = str(extra.get("resolution", "")).casefold()
        # An explicit resolver result is authoritative.  In particular, a
        # resolved edge can retain a bare MFA spelling for compatibility; the
        # spelling alone must not override the semantic status.
        if resolution in {"resolved", "confirmed", "authoritative"}:
            return False
        if resolution in {"unresolved", "ambiguous"}:
            return True
        if any(
            key in extra and bool(extra.get(key))
            for key in ("unresolved_targets", "ambiguous_targets")
        ) or any(
            key in extra and bool(extra.get(key))
            for key in ("unresolved_target_count", "ambiguous_target_count")
        ):
            return True
    # Generic Erlang edges use a bare MFA/name until a resolver proves the
    # repository-local definition.  A qualified ``file::symbol`` target is a
    # resolved identity and must not satisfy an unresolved expectation.
    return isinstance(target, str) and "::" not in target


def _unresolved_relation_matches(
    predicted: Mapping[str, Any], expected: Mapping[str, Any], root: Path, store: GraphStore
) -> bool:
    """Match an unresolved expectation, including a later-resolved MFA."""
    if _relation_matches(predicted, expected, root, store):
        return True
    if (
        str(predicted.get("relation", "")).casefold()
        != str(expected.get("relation", "")).casefold()
    ):
        return False
    expected_target = expected.get("target")
    expected_mfa = _target_mfa(expected_target)
    if expected_mfa is None and isinstance(expected_target, str):
        expected_mfa = _mfa_parts(expected_target)
    if "source" in expected and not _endpoint_matches(
        str(predicted.get("source", "")), expected.get("source"), root, store
    ):
        return False
    predicted_target = predicted.get("target")
    if not isinstance(predicted_target, str):
        return False
    if expected_mfa is None:
        # Dynamic apply targets may intentionally use a symbolic arity (for
        # example ``module:function/arity``).  Keep this narrow escape hatch in
        # the unresolved contract; malformed numeric/prose MFAs remain
        # unmatchable in ordinary relation scoring.
        expected_dynamic = _dynamic_mfa_spelling(expected_target)
        predicted_dynamic = _dynamic_mfa_spelling(predicted_target)
        return expected_dynamic is not None and expected_dynamic == predicted_dynamic
    predicted_mfa = _mfa_parts(predicted_target.rsplit("::", 1)[-1])
    return predicted_mfa == expected_mfa


def _allows_empty(case: Mapping[str, Any]) -> bool:
    expected = case.get("expected")
    if isinstance(expected, Mapping) and expected.get("allow_empty") is True:
        return True
    review = case.get("review")
    if isinstance(review, Mapping) and review.get("allow_empty") is True:
        return True
    return False


def score_case(
    case: Mapping[str, Any],
    predicted: Sequence[Mapping[str, Any]],
    *,
    root: str | Path,
    store: GraphStore | None,
    relation_matcher: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] | None = None,
    unresolved_relation_matcher: Callable[
        [Mapping[str, Any], Mapping[str, Any]], bool
    ]
    | None = None,
) -> dict[str, Any]:
    """Score one executed corpus case without counting unresolved anchors."""
    root_path = _canonical_path(root)
    if store is None and (relation_matcher is None or unresolved_relation_matcher is None):
        raise ValueError("score_case requires a graph store or contract matchers")
    relation_matches = relation_matcher or (
        lambda candidate, expected_item: _relation_matches(
            candidate, expected_item, root_path, store  # type: ignore[arg-type]
        )
    )
    unresolved_relation_matches = unresolved_relation_matcher or (
        lambda candidate, expected_item: _unresolved_relation_matches(
            candidate, expected_item, root_path, store  # type: ignore[arg-type]
        )
    )
    expected = case.get("expected", {})
    if not isinstance(expected, Mapping):
        expected = {}
    positive = [item for item in expected.get("positive", []) if isinstance(item, Mapping)]
    negative = [item for item in expected.get("negative", []) if isinstance(item, Mapping)]
    unresolved = [item for item in expected.get("unresolved", []) if isinstance(item, Mapping)]

    # Classify explicit unresolved candidates before scoring resolved edges.
    # Such candidates are evidence that the evaluator deliberately retained
    # uncertainty, not resolved relations, so they must not dilute precision
    # or occupy the top-10 resolved ranking. Unexpected unresolved candidates
    # remain ordinary false positives.
    unresolved_remaining = list(unresolved)
    unresolved_candidate_indexes: set[int] = set()
    unresolved_seen: list[Mapping[str, Any]] = []
    resolved_unresolved_matches = 0
    for candidate_index, candidate in enumerate(predicted):
        matches_unresolved = [
            item
            for item in unresolved
            if unresolved_relation_matches(candidate, item)
        ]
        if not matches_unresolved:
            continue
        if not _prediction_is_unresolved(candidate):
            # A resolved relation that lands on any intentionally unresolved
            # expectation is a contradiction, regardless of candidate order.
            resolved_unresolved_matches += 1
            continue
        # Explicit unresolved candidates satisfy expectations one-to-one.  A
        # duplicate candidate remains a normal prediction and cannot inflate
        # the unresolved-observed count.
        match_index = next(
            (
                index
                for index, item in enumerate(unresolved_remaining)
                if unresolved_relation_matches(candidate, item)
            ),
            None,
        )
        if match_index is not None:
            item = unresolved_remaining.pop(match_index)
            unresolved_candidate_indexes.add(candidate_index)
            unresolved_seen.append(item)

    matched: list[Mapping[str, Any]] = []
    resolved_predictions = [
        candidate
        for index, candidate in enumerate(predicted)
        if index not in unresolved_candidate_indexes
    ]
    remaining = list(resolved_predictions)
    for item in positive:
        match_index = next(
            (
                index
                for index, candidate in enumerate(remaining)
                if relation_matches(candidate, item)
            ),
            None,
        )
        if match_index is not None:
            matched.append(remaining.pop(match_index))
    true_positive = len(matched)
    predicted_count = len(resolved_predictions)
    expected_count = len(positive)
    allow_empty = _allows_empty(case)
    precision: float | None
    recall: float | None
    if predicted_count == 0 and expected_count == 0:
        precision = recall = 1.0 if allow_empty else None
    else:
        precision = true_positive / predicted_count if predicted_count else 0.0
        recall = true_positive / expected_count if expected_count else None
    forbidden = sum(
        1
        for candidate in predicted
        if any(relation_matches(candidate, item) for item in negative)
    )
    # An intentionally unresolved anchor requires an explicit candidate.  A
    # missing prediction is an unmeasured/failed case, while a resolved edge
    # contradicts the contract even if the same endpoint otherwise matches.
    unresolved_satisfied = (
        (
            bool(unresolved)
            and len(unresolved_seen) == len(unresolved)
            and resolved_unresolved_matches == 0
        )
        if unresolved
        else None
    )
    # Recall@10 is a one-to-one hit count over the ranked prefix.  Counting
    # every matching prediction independently would let duplicate edges inflate
    # the numerator (and could even produce recall values above 1.0).  Keep a
    # separate expected-relation pool so the full-list precision/recall match
    # semantics are preserved while the top-10 metric reflects rank.
    ranked_hits = 0
    ranked_remaining = list(positive)
    for candidate in resolved_predictions[:10]:
        match_index = next(
            (
                index
                for index, item in enumerate(ranked_remaining)
                if relation_matches(candidate, item)
            ),
            None,
        )
        if match_index is not None:
            ranked_hits += 1
            ranked_remaining.pop(match_index)
    return {
        "status": "executed",
        "case_id": case.get("id"),
        "predicted_count": predicted_count,
        "unresolved_prediction_count": len(unresolved_candidate_indexes),
        "expected_positive_count": expected_count,
        "true_positive": true_positive,
        "false_positive": max(0, predicted_count - true_positive),
        "forbidden_matches": forbidden,
        "precision": precision,
        "recall": recall,
        "ranked_true_positive": ranked_hits,
        "recall_at_10": (
            ranked_hits / expected_count if expected_count else (1.0 if allow_empty else None)
        ),
        "unresolved_expected_count": len(unresolved),
        "unresolved_observed_count": len(unresolved_seen),
        "resolved_unresolved_match_count": resolved_unresolved_matches,
        "unresolved_satisfied": unresolved_satisfied,
        "measurement_complete": (precision is not None and (expected_count > 0 or allow_empty))
        or (bool(unresolved) and expected_count == 0 and unresolved_satisfied is True),
        "predictions": list(predicted),
    }


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    # Nearest-rank interpolation is deterministic and works for one sample.
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _finite_nonnegative(value: Any) -> float | None:
    """Return a finite non-negative number, or ``None`` for malformed input."""
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _nonnegative_count(value: Any) -> int | None:
    """Parse a count without accepting booleans or lossy fractional values."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        try:
            return int(value.strip())
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _latency_metric(
    samples: Mapping[str, Sequence[float]],
    sample_provenance: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Summarize measured durations and retain their evidence binding.

    The old report only carried percentile summaries.  Those summaries could
    be edited without changing the lifecycle/case records that supposedly
    produced them.  Keep one bounded record per accepted input sample so the
    result validator can tie each duration back to its lifecycle phase or
    targeted corpus case and recompute the percentiles.
    """
    by_operation: dict[str, Any] = {}
    sample_records: dict[str, list[dict[str, Any]]] = {}
    all_samples: list[float] = []
    invalid_total = 0
    if not isinstance(samples, Mapping):
        return {
            "status": "not_run",
            "samples": 0,
            "invalid_samples": 1,
            "p50_ms": None,
            "p95_ms": None,
            "by_operation": {},
            "sample_provenance": {},
        }
    provenance_map = sample_provenance if isinstance(sample_provenance, Mapping) else {}
    for operation in sorted(samples, key=str):
        values: list[float] = []
        invalid = 0
        raw_value: Any = samples[operation]
        if isinstance(raw_value, Sequence) and not isinstance(
            raw_value, (str, bytes, bytearray)
        ):
            raw_values: Sequence[Any] = raw_value
        else:
            raw_values = [raw_value]
        raw_provenance = provenance_map.get(operation, ())
        if isinstance(raw_provenance, Sequence) and not isinstance(
            raw_provenance, (str, bytes, bytearray)
        ):
            provenance_values: Sequence[Any] = raw_provenance
        else:
            provenance_values = ()
        records: list[dict[str, Any]] = []
        for index, value in enumerate(raw_values):
            metadata = provenance_values[index] if index < len(provenance_values) else None
            if isinstance(metadata, Mapping):
                provenance = dict(metadata)
            else:
                provenance = {
                    "source": "timings",
                    "operation": str(operation),
                    "sample_index": index,
                }
            # The duration belongs in the provenance record itself.  Keep the
            # original value for invalid samples so the validator can fail
            # closed instead of silently dropping malformed evidence.
            records.append({"duration_seconds": value, "provenance": provenance})
            if isinstance(value, bool):
                invalid += 1
                continue
            try:
                parsed = float(value)
            except (TypeError, ValueError, OverflowError):
                invalid += 1
                continue
            if math.isfinite(parsed) and parsed >= 0:
                values.append(parsed)
            else:
                invalid += 1
        sample_records[str(operation)] = records
        invalid_total += invalid
        all_samples.extend(values)
        by_operation[operation] = {
            "samples": len(values),
            "invalid_samples": invalid,
            "p50_ms": round((_percentile(values, 0.50) or 0.0) * 1000, 3) if values else None,
            "p95_ms": round((_percentile(values, 0.95) or 0.0) * 1000, 3) if values else None,
        }
    return {
        "status": "executed" if all_samples else "not_run",
        "samples": len(all_samples),
        "invalid_samples": invalid_total,
        "p50_ms": round((_percentile(all_samples, 0.50) or 0.0) * 1000, 3) if all_samples else None,
        "p95_ms": round((_percentile(all_samples, 0.95) or 0.0) * 1000, 3) if all_samples else None,
        "by_operation": by_operation,
        "sample_provenance": sample_records,
    }


def _latency_source_records(
    lifecycle: Mapping[str, Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    environment: Mapping[str, Any],
    operations: Mapping[str, Sequence[float]],
) -> dict[str, list[dict[str, Any]]]:
    """Return the durations that a result is allowed to report.

    Lifecycle timings and targeted-query timings are already present in the
    public envelope.  Reconstructing this list gives the validator a stable
    provenance boundary without trusting a percentile or an arbitrary sample
    array supplied by the producer.
    """
    repository = environment.get("repository", {})
    generated_data = environment.get("generated_data", {})
    cache = environment.get("cache", {})
    common: dict[str, Any] = {
        "repository": repository.get("path") if isinstance(repository, Mapping) else None,
        "source_revision": (
            repository.get("revision") if isinstance(repository, Mapping) else None
        ),
        "generated_data_revision": (
            generated_data.get("revision") if isinstance(generated_data, Mapping) else None
        ),
        "cache_state": (
            cache.get("stale_evidence_policy") if isinstance(cache, Mapping) else None
        ),
    }
    records: dict[str, list[dict[str, Any]]] = {}
    for operation in (
        "full_build",
        "incremental_update",
        "standalone_postprocess",
        "forget",
        "watch",
    ):
        if operation not in operations:
            continue
        phase = lifecycle.get(operation)
        if not isinstance(phase, Mapping):
            continue
        duration = phase.get("duration_seconds")
        if _finite_nonnegative(duration) is None:
            continue
        records[operation] = [
            {
                "duration_seconds": duration,
                "provenance": {
                    **common,
                    "source": "lifecycle",
                    "phase": operation,
                    "status": phase.get("status"),
                },
            }
        ]

    query_records: list[dict[str, Any]] = []
    for item in cases:
        if not isinstance(item, Mapping):
            continue
        duration = item.get("duration_seconds")
        if _finite_nonnegative(duration) is None:
            continue
        query_records.append(
            {
                "duration_seconds": duration,
                "provenance": {
                    **common,
                    "source": "case",
                    "case_id": item.get("id"),
                    "query_kind": item.get("query_kind"),
                },
            }
        )
    if query_records:
        records["targeted_query"] = query_records
    return records


def _validate_latency_contract(
    latency: Mapping[str, Any],
    lifecycle: Mapping[str, Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    environment: Mapping[str, Any],
) -> None:
    """Validate latency samples, provenance, and minimum operation coverage."""
    provenance = latency.get("sample_provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("result.metrics.latency.sample_provenance: expected object")
    by_operation = latency.get("by_operation")
    if not isinstance(by_operation, Mapping):
        raise ValueError("result.metrics.latency.by_operation: expected object")

    # Rebuild the only samples that this evaluator can legitimately emit.  A
    # report copied from another run, or one with a hand-written duration,
    # therefore cannot pass merely by supplying matching percentile numbers.
    expected_records = _latency_source_records(
        lifecycle,
        cases,
        environment,
        {str(name): () for name in by_operation},
    )
    reported_operations = set(by_operation)
    provenance_operations = set(provenance)
    if provenance_operations != reported_operations:
        raise ValueError(
            "result.metrics.latency.sample_provenance: operations are inconsistent"
        )
    if set(expected_records) != reported_operations:
        raise ValueError(
            "result.metrics.latency: operations are inconsistent with lifecycle evidence"
        )

    all_values: list[float] = []
    for operation, summary in by_operation.items():
        if not isinstance(operation, str) or not operation:
            raise ValueError("result.metrics.latency.by_operation: invalid operation name")
        if not isinstance(summary, Mapping):
            raise ValueError(f"result.metrics.latency.by_operation.{operation}: expected object")
        records = provenance.get(operation)
        if not isinstance(records, list):
            raise ValueError(
                f"result.metrics.latency.sample_provenance.{operation}: expected array"
            )
        expected = expected_records.get(operation, [])
        if len(records) != len(expected):
            raise ValueError(
                f"result.metrics.latency.sample_provenance.{operation}: inconsistent sample count"
            )
        values: list[float] = []
        for index, (record, expected_record) in enumerate(zip(records, expected)):
            if not isinstance(record, Mapping):
                raise ValueError(
                    f"result.metrics.latency.sample_provenance.{operation}[{index}]: "
                    "expected object"
                )
            duration = _finite_nonnegative(record.get("duration_seconds"))
            expected_duration = _finite_nonnegative(expected_record.get("duration_seconds"))
            if duration is None or expected_duration is None or not math.isclose(
                duration, expected_duration, rel_tol=1e-9, abs_tol=1e-9
            ):
                raise ValueError(
                    f"result.metrics.latency.sample_provenance.{operation}[{index}]: "
                    "duration is inconsistent with lifecycle evidence"
                )
            record_provenance = record.get("provenance")
            expected_provenance = expected_record.get("provenance")
            if not isinstance(record_provenance, Mapping):
                raise ValueError(
                    f"result.metrics.latency.sample_provenance.{operation}[{index}].provenance: "
                    "expected object"
                )
            for key, expected_value in expected_provenance.items():
                if record_provenance.get(key) != expected_value:
                    raise ValueError(
                        f"result.metrics.latency.sample_provenance.{operation}[{index}]"
                        ".provenance: "
                        f"inconsistent {key}"
                    )
            values.append(duration)
        sample_count = _nonnegative_count(summary.get("samples"))
        invalid_count = _nonnegative_count(summary.get("invalid_samples"))
        if sample_count != len(values) or invalid_count != 0:
            raise ValueError(
                f"result.metrics.latency.by_operation.{operation}: inconsistent sample evidence"
            )
        expected_p50 = round((_percentile(values, 0.50) or 0.0) * 1000, 3) if values else None
        expected_p95 = round((_percentile(values, 0.95) or 0.0) * 1000, 3) if values else None
        if summary.get("p50_ms") != expected_p50 or summary.get("p95_ms") != expected_p95:
            raise ValueError(
                f"result.metrics.latency.by_operation.{operation}: percentiles are inconsistent"
            )
        all_values.extend(values)

    if latency.get("samples") != len(all_values) or latency.get("invalid_samples") != 0:
        raise ValueError("result.metrics.latency: sample totals are inconsistent with provenance")
    expected_p50 = round((_percentile(all_values, 0.50) or 0.0) * 1000, 3) if all_values else None
    expected_p95 = round((_percentile(all_values, 0.95) or 0.0) * 1000, 3) if all_values else None
    if latency.get("p50_ms") != expected_p50 or latency.get("p95_ms") != expected_p95:
        raise ValueError("result.metrics.latency: percentiles are inconsistent with provenance")

    if latency.get("status") == "executed":
        for operation in _LATENCY_REQUIRED_OPERATIONS:
            summary = by_operation.get(operation)
            if (
                not isinstance(summary, Mapping)
                or _nonnegative_count(summary.get("samples")) is None
                or int(summary.get("samples", 0)) < _LATENCY_MIN_SAMPLES
                or not isinstance(provenance.get(operation), list)
                or len(provenance.get(operation, [])) < _LATENCY_MIN_SAMPLES
            ):
                raise ValueError(
                    f"result.metrics.latency: executed metrics require at least "
                    f"{_LATENCY_MIN_SAMPLES} {operation} sample"
                )


_SPECIAL_QUERY_KINDS = frozenset({"mfa", "diagnostics", "cache"})
_NON_AUTHORITATIVE_SEMANTIC_STATUSES = frozenset(
    {
        "unavailable",
        "mismatch",
        "timeout",
        "failed",
        "malformed",
        "stale",
        "degraded",
    }
)


def _record_value(record: Any, name: str, default: Any = None) -> Any:
    """Read a field from a semantic dataclass or a bounded mapping."""
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def _record_provenance_value(record: Any, name: str, default: Any = None) -> Any:
    provenance = _record_value(record, "provenance", {})
    if isinstance(provenance, Mapping):
        return provenance.get(name, default)
    return getattr(provenance, name, default)


def _semantic_record_current(record: Any) -> bool:
    """Accept only evidence that is not explicitly unavailable or stale."""
    for value in (
        _record_value(record, "status"),
        _record_provenance_value(record, "status"),
    ):
        if value is None or str(value).strip() == "":
            continue
        if str(value).casefold() in _NON_AUTHORITATIVE_SEMANTIC_STATUSES:
            return False
    return True


def _query_mfa_parts(target: Any) -> tuple[str | None, str, int] | None:
    """Parse a query MFA, retaining an optional module qualification."""
    if isinstance(target, Mapping):
        symbol = target.get("symbol")
        explicit_arity = target.get("arity")
    else:
        symbol = target
        explicit_arity = None
    parsed = _split_erlang_symbol(symbol, explicit_arity)
    if parsed is None or parsed[1] is None:
        return None
    name, arity = parsed
    module: str | None = None
    if ":" in name:
        module, name = name.split(":", 1)
    elif "." in name:
        module, name = name.rsplit(".", 1)
    if not name or not isinstance(arity, int):
        return None
    return module.strip("'") if module else None, name.strip("'"), arity


def _semantic_mfa_parts(value: Any) -> tuple[str | None, str, int] | None:
    """Parse an evidence target while accepting qualified graph identities."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if "::" in text:
        text = text.rsplit("::", 1)[-1]
    parsed = _mfa_parts(text)
    if parsed is not None:
        return parsed
    parsed_symbol = _split_erlang_symbol(text)
    if parsed_symbol is None:
        return None
    name, arity = parsed_symbol
    if arity is None:
        return None
    if ":" in name:
        module, function = name.split(":", 1)
    elif "." in name:
        module, function = name.rsplit(".", 1)
    else:
        return None, name, arity
    return module.strip("'"), function.strip("'"), arity


def _semantic_endpoint_allowed(value: Any, root: Path) -> bool:
    """Keep semantic records repository-scoped before exposing them."""
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip().replace("\\", "/")
    if "::" in text:
        return _qualified_path_info(text, root) is not None
    if Path(text).is_absolute() or re.match(r"^[A-Za-z]:($|/)", text):
        try:
            Path(text).resolve(strict=False).relative_to(_canonical_path(root))
        except (OSError, RuntimeError, ValueError):
            return False
    return True


def _semantic_mfa_target_matches(value: Any, query_target: Any, root: Path) -> bool:
    query_parts = _query_mfa_parts(query_target)
    if query_parts is None or not _semantic_endpoint_allowed(value, root):
        return False
    evidence_parts = _semantic_mfa_parts(value)
    if evidence_parts is None:
        return False
    query_module, query_name, query_arity = query_parts
    evidence_module, evidence_name, evidence_arity = evidence_parts
    return (
        evidence_name == query_name
        and evidence_arity == query_arity
        and (query_module is None or evidence_module == query_module)
    )


def _canonical_query_mfa(target: Any) -> str | None:
    parsed = _query_mfa_parts(target)
    if parsed is None:
        return None
    module, name, arity = parsed
    return f"{module + ':' if module else ''}{name}/{arity}"


def _semantic_prediction(
    record: Any,
    root: Path,
    *,
    relation: str | None = None,
    target: str | None = None,
    resolution: str = "resolved",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Convert explicit semantic evidence into the evaluator prediction shape."""
    source_value = _record_value(record, "source")
    target_value = _record_value(record, "target")
    if not isinstance(source_value, str) or not isinstance(target_value, str):
        return None
    if not _semantic_endpoint_allowed(source_value, root) or not _semantic_endpoint_allowed(
        target_value, root
    ):
        return None
    metadata = _record_value(record, "metadata", {})
    values = dict(metadata) if isinstance(metadata, Mapping) else {}
    if extra:
        values.update(extra)
    values.setdefault("resolution", resolution)
    if target is not None and target != target_value:
        values.setdefault("evidence_target", target_value)
    source = source_value
    prediction_target = target if target is not None else target_value
    source_file = (
        _relative_path(source.split("::", 1)[0], root) if "::" in source else source
    )
    target_file = (
        _relative_path(prediction_target.split("::", 1)[0], root)
        if "::" in prediction_target
        else None
    )
    raw_line = _record_value(record, "line")
    line = raw_line if isinstance(raw_line, int) and not isinstance(raw_line, bool) else 0
    if line < 0:
        line = 0
    raw_confidence = values.get("confidence", 1.0)
    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError, OverflowError):
        confidence = 1.0
    if not math.isfinite(confidence):
        confidence = 1.0
    confidence = min(1.0, max(0.0, confidence))
    tier = values.get("confidence_tier", "SEMANTIC")
    if not isinstance(tier, str) or not tier:
        tier = "SEMANTIC"
    return {
        "relation": relation or str(_record_value(record, "kind", "")),
        "source": source,
        "target": prediction_target,
        "source_file": source_file or "semantic",
        "target_file": target_file,
        "line": line,
        "extra": values,
        "confidence": confidence,
        "confidence_tier": tier,
    }


def _query_tool_name(query: Mapping[str, Any]) -> str | None:
    target = query.get("target")
    value = target.get("tool", target.get("symbol")) if isinstance(target, Mapping) else target
    if not isinstance(value, str):
        return None
    value = value.strip().casefold()
    return value if re.fullmatch(r"[a-z][a-z0-9_-]*", value) else None


def _environment_tool(environment: Mapping[str, Any] | None, name: str) -> Mapping[str, Any] | None:
    if not isinstance(environment, Mapping):
        return None
    toolchain = environment.get("toolchain", {})
    tools = toolchain.get("tools", {}) if isinstance(toolchain, Mapping) else {}
    if not isinstance(tools, Mapping):
        return None
    for key, value in tools.items():
        if str(key).casefold() == name and isinstance(value, Mapping):
            return value
    return None


def _diagnostic_matches_tool(record: Any, tool: str) -> bool:
    code = str(_record_value(record, "code", "")).casefold()
    metadata = _record_value(record, "metadata", {})
    metadata_tool = metadata.get("tool") if isinstance(metadata, Mapping) else None
    provenance_tool = _record_provenance_value(record, "tool")
    if isinstance(metadata_tool, str) and metadata_tool.casefold() == tool:
        return True
    if isinstance(provenance_tool, str) and provenance_tool.casefold() == tool:
        return True
    if code in {f"{tool}_unavailable", f"{tool}-unavailable"}:
        return True
    return tool in code and "unavailable" in code


def _diagnostic_prediction(
    tool: str,
    record: Any,
    *,
    code: str,
    message: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = _record_value(record, "metadata", {}) if record is not None else {}
    extra = dict(metadata) if isinstance(metadata, Mapping) else {}
    if details:
        extra.update(details)
    extra.update({"diagnostic_code": code, "resolution": "unresolved", "tool": tool})
    return {
        "relation": "TOOL_UNAVAILABLE",
        "source": "environment",
        "target": tool,
        "source_file": "environment",
        "target_file": None,
        "line": 0,
        "extra": extra,
        "confidence": 1.0,
        "confidence_tier": "DIAGNOSTIC",
    }


def _special_query_predictions(
    query: Mapping[str, Any],
    store: GraphStore,
    root: Path,
    environment: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Run the bounded read-only handlers for semantic-only corpus queries."""
    kind = str(query.get("kind", "")).casefold()
    if kind == "mfa":
        if _query_mfa_parts(query.get("target")) is None:
            return [], "invalid_mfa_target"
        try:
            semantic_records = store.get_semantic_evidence(limit=1_000)
        except Exception:
            return [], "semantic_evidence_unavailable"
        predictions: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        query_target = query.get("target")
        query_mfa = _canonical_query_mfa(query_target)
        for record in semantic_records:
            relation = _record_value(record, "kind", _record_value(record, "relation", ""))
            if str(relation).casefold() != "supervises" or not _semantic_record_current(record):
                continue
            target_value = _record_value(record, "target")
            if not _semantic_mfa_target_matches(target_value, query_target, root):
                continue
            source_value = _record_value(record, "source")
            key = (str(source_value), str(target_value), int(_record_value(record, "line", 0) or 0))
            if key in seen:
                continue
            seen.add(key)
            # A symbol-only corpus target intentionally omits the module. Keep
            # the query spelling in the scored target while retaining the
            # explicit evidence target in ``extra``.
            query_parts = _query_mfa_parts(query_target)
            target_override = (
                query_mfa
                if query_mfa and query_parts is not None and query_parts[0] is None
                else None
            )
            prediction = _semantic_prediction(
                record,
                root,
                relation="SUPERVISES",
                target=target_override,
                extra={"evidence_source": _record_provenance_value(record, "source", "semantic")},
            )
            if prediction is not None:
                predictions.append(prediction)
        return predictions, None if predictions else "semantic_evidence_unavailable"

    if kind == "diagnostics":
        tool = _query_tool_name(query)
        if tool is None:
            return [], "invalid_diagnostic_target"
        environment_tool = _environment_tool(environment, tool)
        status = str(environment_tool.get("status", "")).casefold() if environment_tool else ""
        records: list[Any] = []
        if isinstance(environment, Mapping):
            raw = environment.get("diagnostics", [])
            if isinstance(raw, list):
                records.extend(raw)
        try:
            records.extend(store.get_semantic_diagnostics(limit=1_000))
        except Exception:
            pass
        matching = [record for record in records if _diagnostic_matches_tool(record, tool)]
        unavailable = status == "unavailable" or any(
            str(_record_value(record, "code", "")).casefold().endswith("_unavailable")
            or str(_record_value(record, "status", "")).casefold() == "unavailable"
            for record in matching
        )
        if unavailable:
            record = matching[0] if matching else environment_tool
            code = str(_record_value(record, "code", f"{tool}_unavailable"))
            message = str(
                _record_value(
                    record,
                    "message",
                    f"{tool} is unavailable; Generic evidence remains authoritative.",
                )
            )
            details = {
                "observed_status": status or "unavailable",
                "command": environment_tool.get("command") if environment_tool else None,
            }
            return [
                _diagnostic_prediction(
                    tool, record, code=code, message=message, details=details
                )
            ], None
        if not environment_tool and not matching:
            return [], "diagnostic_snapshot_unavailable"
        # An available tool with no warning is a measured empty diagnostic set.
        return [], None

    if kind == "cache":
        target = query.get("target")
        revision = (
            target.get("revision", target.get("symbol"))
            if isinstance(target, Mapping)
            else target
        )
        if not isinstance(revision, str) or not revision.strip():
            return [], "invalid_cache_target"
        revision = revision.strip()
        cache = environment.get("cache", {}) if isinstance(environment, Mapping) else {}
        raw_paths = cache.get("paths", []) if isinstance(cache, Mapping) else []
        if not isinstance(raw_paths, list):
            raw_paths = []
        rejected: list[dict[str, Any]] = []
        observed = False
        unsafe = False
        for state in raw_paths:
            if not isinstance(state, Mapping):
                continue
            raw_path = state.get("path")
            safe_path = _safe_endpoint_file(raw_path, root)
            if safe_path is None:
                unsafe = unsafe or raw_path is not None
                continue
            present = state.get("present", True)
            if present is not True:
                continue
            observed = True
            cache_status = str(state.get("status", "")).casefold()
            revision_key = state.get("revision_key")
            rejected_state = (
                cache_status in {"unkeyed", "stale", "mismatch", "rejected", "invalid", "unknown"}
                or not isinstance(revision_key, str)
                or not revision_key
                or revision_key != revision
            )
            if rejected_state:
                rejected.append(
                    {
                        "path": safe_path,
                        "status": cache_status or "unkeyed",
                        "revision_key": revision_key,
                    }
                )
        if rejected:
            predictions = [
                {
                    "relation": "CACHE_REJECTED",
                    "source": "cache",
                    "target": revision,
                    "source_file": "cache",
                    "target_file": None,
                    "line": 0,
                    "extra": {
                        "resolution": "unresolved",
                        "cache_path": item["path"],
                        "cache_status": item["status"],
                        "revision_key": item["revision_key"],
                        "reason": "stale_or_unkeyed_cache",
                    },
                    "confidence": 1.0,
                    "confidence_tier": "CACHE",
                }
                for item in rejected
            ]
            return predictions, None
        if unsafe and not observed:
            return [], "cache_state_outside_target"
        if not raw_paths:
            return [], "cache_state_unavailable"
        # A present cache entry with the exact revision key is usable; an
        # empty result is intentional and remains measurable by the scorer.
        return [], None

    return [], "unsupported_query_kind"


def _run_case(
    case: Mapping[str, Any],
    store: GraphStore,
    root: Path,
    environment: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    query = case.get("query", {})
    if not isinstance(query, Mapping) or str(query.get("kind")) not in _SUPPORTED_QUERIES:
        return {
            "id": case.get("id"),
            "category": case.get("category"),
            "status": "not_run",
            "reason": "unsupported_query_kind",
            "predictions": [],
        }, time.perf_counter() - started
    query_kind = str(query.get("kind", "")).casefold()
    if query_kind in _SPECIAL_QUERY_KINDS:
        predictions, special_reason = _special_query_predictions(query, store, root, environment)
        if special_reason is not None:
            return {
                "id": case.get("id"),
                "category": case.get("category"),
                "status": "not_run",
                "query_kind": query.get("kind"),
                "resolved_target": None,
                "reason": special_reason,
                "predictions": [],
            }, time.perf_counter() - started
        scored = score_case(case, predictions, root=root, store=store)
        scored.update(
            {
                "id": case.get("id"),
                "category": case.get("category"),
                "query_kind": query.get("kind"),
                "resolved_target": None,
                "duration_seconds": time.perf_counter() - started,
                "reason": "semantic_query_executed",
            }
        )
        return scored, scored["duration_seconds"]
    edges, resolved_target = _query_edges(store, root, query)
    predictions = [_predicted_relation(edge, root, store) for edge in edges]
    scored = score_case(case, predictions, root=root, store=store)
    scored.update(
        {
            "id": case.get("id"),
            "category": case.get("category"),
            "query_kind": query.get("kind"),
            "resolved_target": resolved_target,
            "duration_seconds": time.perf_counter() - started,
            "reason": "graph_query_executed",
        }
    )
    return scored, scored["duration_seconds"]


def _case_anchor_paths(case: Mapping[str, Any], root: str | Path = ".") -> list[str]:
    paths: set[str] = set()
    root_path = _canonical_path(root)

    def add_endpoint(endpoint: Any) -> None:
        if isinstance(endpoint, Mapping):
            file_name = endpoint.get("file")
            if isinstance(file_name, str):
                relative = _safe_endpoint_file(file_name, root_path)
                if relative is not None:
                    paths.add(relative)
            return
        if isinstance(endpoint, str) and "::" in endpoint:
            path_name, _separator, _symbol = endpoint.partition("::")
            relative = _safe_endpoint_file(path_name, root_path)
            if relative is not None:
                paths.add(relative)
    query = case.get("query")
    if isinstance(query, Mapping):
        add_endpoint(query.get("target"))
    expected = case.get("expected")
    if isinstance(expected, Mapping):
        for relation_kind in ("positive", "negative", "unresolved"):
            for relation in expected.get(relation_kind, []):
                if not isinstance(relation, Mapping):
                    continue
                for endpoint_kind in ("source", "target"):
                    add_endpoint(relation.get(endpoint_kind))
    return sorted(paths)


def _case_tool_reason(case: Mapping[str, Any], available_tools: set[str]) -> str | None:
    query_kind = (
        str(case.get("query", {}).get("kind", "")).casefold()
        if isinstance(case.get("query"), Mapping)
        else ""
    )
    # Special handlers can report unavailable/stale state themselves.  Do not
    # short-circuit them merely because the optional semantic tool is absent;
    # diagnostics and cache observations are useful precisely in that case.
    if query_kind not in _SPECIAL_QUERY_KINDS:
        required = _SEMANTIC_CASE_TOOLS.get(str(case.get("category")))
        if required and not required.intersection(available_tools):
            return "semantic_tool_unavailable"
    return None


def _evaluate_case_results(
    corpus: Mapping[str, Any],
    root: Path,
    *,
    reason: str | None,
    available_tools: set[str],
    observed_diagnostic_codes: set[str],
    store: GraphStore | None,
    timings: dict[str, Sequence[float]],
    environment: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute and score every corpus case, preserving explicit not-run states."""
    results: list[dict[str, Any]] = []
    cases = corpus.get("cases", [])
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes, bytearray)):
        return results
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        base: dict[str, Any] = {
            "id": case.get("id"),
            "category": case.get("category"),
            "anchors": _case_anchor_paths(case, root),
        }
        required = case.get("required_diagnostics", [])
        if not isinstance(required, list):
            required = []
        required = [code for code in required if isinstance(code, str)]
        base["required_diagnostics"] = required
        base["observed_diagnostics"] = sorted(set(required).intersection(observed_diagnostic_codes))
        base["required_diagnostics_satisfied"] = set(required).issubset(observed_diagnostic_codes)
        expected = case.get("expected")
        unresolved = (
            expected.get("unresolved", [])
            if isinstance(expected, Mapping) and isinstance(expected.get("unresolved", []), list)
            else []
        )
        base["unresolved_expected_count"] = sum(
            1 for item in unresolved if isinstance(item, Mapping)
        )
        missing = [path for path in base["anchors"] if not (root / path).is_file()]
        base["missing_anchors"] = missing
        if reason is not None:
            base.update({"status": "not_run", "reason": reason, "predictions": []})
        elif missing:
            base.update({"status": "not_run", "reason": "anchor_missing", "predictions": []})
        else:
            tool_reason = _case_tool_reason(case, available_tools)
            if tool_reason:
                base.update({"status": "not_run", "reason": tool_reason, "predictions": []})
            elif store is None:
                base.update({"status": "not_run", "reason": "graph_not_built", "predictions": []})
            else:
                executed, duration = _run_case(case, store, root, environment)
                base.update(executed)
                if executed.get("status") == "executed":
                    timings["targeted_query"] = [
                        *timings.get("targeted_query", ()),
                        duration,
                    ]
        results.append(base)
    return results


def _empty_lifecycle(reason: str) -> dict[str, dict[str, Any]]:
    return {
        phase: {
            "status": "not_run",
            "reason": reason,
            "duration_seconds": None,
            # A lifecycle phase is not proven merely because it was skipped.
            # Keep an explicit false value so consumers cannot interpret a
            # missing parity field as an implicit pass.
            "parity": False,
        }
        for phase in _LIFECYCLE_PHASES
    }


def _lifecycle_call(
    function: Callable[..., Any],
    root: Path,
    store: GraphStore,
    *,
    changed_files: list[str] | None = None,
    erlang_config: Any = None,
) -> Any:
    # The evaluator is Generic-only by default.  A caller may explicitly
    # supply an integration config for an isolated adapter run; never inherit
    # ambient ``CRG_ERLANG_*`` settings implicitly here.
    config = (
        ErlangIntegrationConfig(enabled=False)
        if erlang_config is None
        else ErlangIntegrationConfig.from_value(erlang_config)
    )
    kwargs: dict[str, Any] = {"erlang_config": config}
    if changed_files is not None:
        kwargs["changed_files"] = changed_files
    return _invoke_with_optional_config(function, root, store, **kwargs)


def _require_lifecycle_count(value: Any, phase: str, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(f"{phase} runner returned invalid {field}")


def _require_lifecycle_list(value: Any, phase: str, field: str) -> None:
    if not isinstance(value, list):
        raise TypeError(f"{phase} runner returned invalid {field}")
    if field in {"changed_files", "dependent_files", "forgotten", "reparsed"} and any(
        not isinstance(item, str) or not item for item in value
    ):
        raise TypeError(f"{phase} runner returned invalid {field}")


def _validate_lifecycle_payload_shape(value: Mapping[str, Any], phase: str) -> None:
    """Validate the phase-specific core fields without applying failure policy."""
    required = _LIFECYCLE_REQUIRED_FIELDS.get(phase)
    if required is None:
        raise ValueError(f"unsupported lifecycle phase {phase!r}")

    # Runners may include their phase as an explicit discriminator.  Treat it
    # as a contract field rather than accepting an envelope produced for a
    # different lifecycle call.  Omitted phase remains valid for the concrete
    # built-in helpers, whose return values predate this discriminator.
    if "phase" in value:
        declared_phase = value["phase"]
        if not isinstance(declared_phase, str):
            raise TypeError(f"{phase} runner returned invalid phase")
        if declared_phase != phase:
            raise ValueError(
                f"{phase} runner returned envelope for phase {declared_phase!r}"
            )

    # A status is optional for the built-in summaries, but when a runner emits
    # one it must be a string.  Coercing arbitrary values (for example, an
    # integer or ``None``) would make malformed evidence look successful.
    if "status" in value and not isinstance(value["status"], str):
        raise TypeError(f"{phase} runner returned invalid status")
    missing = required - set(value)
    if missing:
        raise ValueError(
            f"{phase} runner returned incomplete envelope: missing {', '.join(sorted(missing))}"
        )

    # All numeric counters in the public lifecycle summaries are bounded
    # integers.  Unknown additive counters remain allowed for forward
    # compatibility, while known counters cannot smuggle booleans or negatives.
    for field in _LIFECYCLE_COUNT_FIELDS.intersection(value):
        _require_lifecycle_count(value[field], phase, field)
    for field in _LIFECYCLE_LIST_FIELDS.intersection(value):
        _require_lifecycle_list(value[field], phase, field)
    for field in _LIFECYCLE_BOOL_FIELDS.intersection(value):
        if not isinstance(value[field], bool):
            raise TypeError(f"{phase} runner returned invalid {field}")

    errors = value.get("errors")
    if phase in {"full_build", "incremental_update"}:
        if not isinstance(errors, list) or any(not isinstance(item, Mapping) for item in errors):
            raise TypeError(f"{phase} runner returned malformed errors")
    elif errors is not None and (
        not isinstance(errors, list) or any(not isinstance(item, Mapping) for item in errors)
    ):
        raise TypeError(f"{phase} runner returned malformed errors")

    warnings = value.get("warnings")
    if warnings is not None and (
        not isinstance(warnings, list)
        or any(not isinstance(item, (str, Mapping)) for item in warnings)
    ):
        raise TypeError(f"{phase} runner returned malformed warnings")

    # Watch evidence is a serialized boundary, so keep all three activity
    # measurements as bounded counters.  Accepting arbitrary event arrays
    # would make ``[{}]`` or ``["fake"]`` indistinguishable from a real cycle
    # once the reducer only looked at list length.
    if phase == "watch":
        for field in ("events", "updates", "notifications"):
            _require_lifecycle_count(value[field], phase, field)


def _checked_lifecycle_result(
    value: Any, phase: str, *, reject_errors: bool = True, reject_warnings: bool = True
) -> dict[str, Any]:
    """Require a serializable successful lifecycle envelope from a runner."""
    if not isinstance(value, Mapping):
        raise TypeError(f"{phase} runner must return a mapping")
    result = dict(value)
    if not result:
        raise ValueError(f"{phase} runner returned an empty result")
    try:
        # Do not allow arbitrary runner objects to leak into the report.  The
        # normalizer is intentionally strict here; lifecycle summaries are an
        # external evidence boundary, not an opaque Python object channel.
        json.dumps(result, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise TypeError(f"{phase} runner returned non-serializable data") from exc
    _validate_lifecycle_payload_shape(result, phase)
    errors = result.get("errors")
    if reject_errors and errors:
        raise RuntimeError(f"{phase} runner reported {len(errors)} error(s)")
    warnings = result.get("warnings")
    if reject_warnings and warnings:
        raise RuntimeError(f"{phase} runner reported {len(warnings)} warning(s)")
    raw_status = result.get("status")
    status = raw_status.casefold() if isinstance(raw_status, str) else ""
    if status in {"error", "failed", "blocked", "not_run", "dry_run"}:
        raise RuntimeError(f"{phase} runner returned status {status!r}")
    if status and status not in {"ok", "executed", "success", "completed"}:
        raise RuntimeError(f"{phase} runner returned unsupported status {status!r}")
    return result


def _watch_activity_evidence(payload: Mapping[str, Any]) -> tuple[bool, dict[str, int]]:
    """Return whether a watch smoke payload proves a real notification cycle.

    A syntactically valid envelope with all counters set to zero only proves
    that a runner returned.  The adoption contract needs an observed event,
    an applied update, and a delivered notification before it can claim that
    the watch path was exercised.
    """
    counts: dict[str, int] = {}
    for field in ("events", "updates", "notifications"):
        value = payload.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            counts[field] = value
        else:  # ``_validate_lifecycle_payload_shape`` normally catches this.
            counts[field] = 0
    return all(counts[field] > 0 for field in counts), counts


def _valid_fingerprint(value: Any) -> str | None:
    """Return a canonical graph fingerprint supplied by an isolated runner."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        return None
    return value


def _lifecycle_parity_from_evidence(
    phase: str,
    item: Mapping[str, Any],
    *,
    require_reported: bool = True,
) -> bool:
    """Derive lifecycle parity from the phase's explicit evidence fields.

    ``parity`` is retained as a public summary field, but it is never the
    sole source of truth.  Each phase has a small, deterministic evidence
    contract so a forged boolean cannot turn an unexercised lifecycle path
    into a passing adoption gate.
    """
    if item.get("status") != "executed":
        expected = False
    elif phase == "full_build":
        payload = item.get("result")
        errors = payload.get("errors") if isinstance(payload, Mapping) else None
        expected = isinstance(errors, list) and not errors
    elif phase == "incremental_update":
        payload = item.get("result")
        errors = payload.get("errors") if isinstance(payload, Mapping) else None
        files_updated = payload.get("files_updated") if isinstance(payload, Mapping) else None
        changed_files = payload.get("changed_files") if isinstance(payload, Mapping) else None
        graph_changed = payload.get("graph_changed") if isinstance(payload, Mapping) else None
        baseline = _valid_fingerprint(item.get("baseline_fingerprint"))
        observed = _valid_fingerprint(item.get("observed_fingerprint"))
        expected = (
            item.get("update_evidence") is True
            and isinstance(errors, list)
            and not errors
            and isinstance(files_updated, int)
            and not isinstance(files_updated, bool)
            and files_updated > 0
            and isinstance(changed_files, list)
            and bool(changed_files)
            and graph_changed is True
            and baseline is not None
            and observed is not None
            and baseline == observed
        )
    elif phase == "standalone_postprocess":
        reference = _valid_fingerprint(item.get("reference_fingerprint"))
        observed = _valid_fingerprint(item.get("observed_fingerprint"))
        first = _valid_fingerprint(item.get("first_post_fingerprint"))
        expected = (
            item.get("idempotence") is True
            and item.get("reference_match") is True
            and reference is not None
            and observed is not None
            and first is not None
            and first == observed
            and observed == reference
        )
    elif phase == "watch":
        payload = item.get("result")
        activity, _counts = (
            _watch_activity_evidence(payload)
            if isinstance(payload, Mapping)
            else (False, {})
        )
        reference = _valid_fingerprint(item.get("reference_fingerprint"))
        observed = _valid_fingerprint(item.get("observed_fingerprint"))
        expected = (
            item.get("activity_evidence") is True
            and activity
            and item.get("reference_match") is True
            and reference is not None
            and observed == reference
        )
    elif phase == "forget":
        payload = item.get("result")
        target = item.get("forgotten")
        forgotten = payload.get("forgotten") if isinstance(payload, Mapping) else None
        reference = _valid_fingerprint(item.get("baseline_fingerprint"))
        observed = _valid_fingerprint(item.get("observed_fingerprint"))
        expected = (
            item.get("target_absent") is True
            and isinstance(target, str)
            and bool(target)
            and isinstance(forgotten, list)
            and target in forgotten
            and reference is not None
            and observed is not None
            and reference == observed
        )
    else:
        expected = False

    if require_reported:
        return item.get("parity") is True and expected
    return expected


def _fresh_forget_fingerprint(
    root: Path,
    temp_root: Path,
    target: str,
    *,
    erlang_config: Any,
) -> str:
    """Build a clean checkout without *target* and return its graph digest.

    ``forget_files`` deliberately keeps the source file on disk, so rebuilding
    against the original checkout would discover the forgotten file again.
    The evaluator therefore uses a temporary filesystem mirror and removes the
    target only from that mirror.  The target checkout itself remains strictly
    read-only.
    """
    relative_target = _relative_path(target, root).replace("\\", "/")
    relative_parts = tuple(part for part in relative_target.split("/") if part)
    if not relative_parts or relative_target.startswith("/") or ".." in relative_parts:
        raise ValueError(f"forget target is not contained by repository root: {target!r}")

    with tempfile.TemporaryDirectory(prefix="crg-forget-baseline-", dir=str(temp_root)) as context:
        mirror_root = Path(context) / "repo"
        shutil.copytree(
            root,
            mirror_root,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".code-review-graph"),
        )
        mirror_target = mirror_root.joinpath(*relative_parts)
        if mirror_target.is_symlink() or mirror_target.is_file():
            mirror_target.unlink()
        elif mirror_target.is_dir():
            shutil.rmtree(mirror_target)

        baseline_store = GraphStore(Path(context) / "graph.db")
        try:
            # Always use the concrete rebuild/postprocess implementations for
            # this reference graph.  An injected lifecycle runner is a test or
            # adapter boundary and must not be invoked a second time merely to
            # establish the forget baseline (doing so would invalidate
            # exactly-once execution accounting).
            build_result = _lifecycle_call(
                full_build,
                mirror_root,
                baseline_store,
                erlang_config=erlang_config,
            )
            build_payload = _checked_lifecycle_result(
                build_result, "full_build", reject_errors=False
            )
            build_errors = build_payload.get("errors")
            if isinstance(build_errors, list) and build_errors:
                raise RuntimeError(
                    f"fresh forget baseline build reported {len(build_errors)} error(s)"
                )
            # The temporary database lives beside ``mirror_root`` rather than
            # at the analyzed repository path.  Pass the explicit root so the
            # Erlang header resolver does not infer the wrong scope.  Keep the
            # invocation signature-tolerant for injected one-argument test
            # doubles and downstream callers.
            post_result = _invoke_with_optional_config(
                run_post_processing,
                baseline_store,
                repo_root=mirror_root,
            )
            _checked_lifecycle_result(post_result, "standalone_postprocess")
            return _portable_graph_fingerprint(baseline_store, mirror_root)
        finally:
            baseline_store.close()


def _checkout_snapshot(root: Path) -> str:
    """Hash checkout files while excluding mutable analysis state.

    The adoption target is an external input.  A snapshot around the isolated
    watch smoke makes an accidental target write observable without relying on
    Git status (which does not report content restored before the check).
    """
    root = _canonical_path(root)
    digest = hashlib.sha256()
    if not root.is_dir():
        return digest.hexdigest()
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name
            for name in directories
            if name not in {".git", ".code-review-graph"}
            and not (current_path / name).is_symlink()
        )
        for name in sorted(filenames):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            digest.update(relative.encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
            if path.is_symlink():
                digest.update(b"symlink\0")
                digest.update(os.readlink(path).encode("utf-8", "surrogateescape"))
                digest.update(b"\0")
                continue
            try:
                with path.open("rb") as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            except OSError as exc:
                raise RuntimeError(f"could not snapshot target file {relative}") from exc
            digest.update(b"\0")
    return digest.hexdigest()


def _run_isolated_watch_smoke(
    root: Path,
    temp_root: Path,
    *,
    timeout: float,
    erlang_config: Any = None,
) -> dict[str, Any]:
    """Run one real watcher cycle against a disposable checkout mirror.

    The target is never passed to :func:`watch` because that function writes a
    transient health marker under its repository root.  The mirror has its own
    graph store and is removed by the caller's temporary-directory lifecycle.
    """
    bounded_timeout = min(max(float(timeout), 0.1), 30.0)
    with tempfile.TemporaryDirectory(prefix="crg-watch-smoke-", dir=str(temp_root)) as context:
        context_root = Path(context)
        mirror_root = context_root / "repo"
        shutil.copytree(
            root,
            mirror_root,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".code-review-graph"),
        )
        source_files = sorted(
            path
            for path in mirror_root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and path.suffix in {".erl", ".hrl"}
        )
        if not source_files:
            raise RuntimeError("watch smoke requires an Erlang source file")

        store = GraphStore(context_root / "graph.db")
        stop_event = threading.Event()
        ready_event = threading.Event()
        update_event = threading.Event()
        callback_count = 0
        callback_lock = threading.Lock()
        failures: list[BaseException] = []
        thread: threading.Thread | None = None
        try:
            build_result = _lifecycle_call(
                full_build,
                mirror_root,
                store,
                erlang_config=erlang_config,
            )
            build_payload = _checked_lifecycle_result(
                build_result,
                "full_build",
                reject_errors=False,
            )
            errors = build_payload.get("errors")
            if isinstance(errors, list) and errors:
                raise RuntimeError(f"watch smoke mirror build reported {len(errors)} error(s)")
            post_result = _invoke_with_optional_config(
                run_post_processing,
                store,
                repo_root=mirror_root,
            )
            _checked_lifecycle_result(post_result, "standalone_postprocess")
            reference_fingerprint = _portable_graph_fingerprint(store, mirror_root)

            def on_files_updated(updated_store: GraphStore) -> dict[str, Any]:
                nonlocal callback_count
                with callback_lock:
                    callback_count += 1
                result = run_post_processing(updated_store, repo_root=mirror_root)
                if isinstance(result, Mapping) and result.get("warnings"):
                    raise RuntimeError("watch smoke postprocess returned warnings")
                update_event.set()
                return result if isinstance(result, dict) else {}

            def run_watcher() -> None:
                try:
                    watch(
                        mirror_root,
                        store,
                        on_files_updated=on_files_updated,
                        stop_event=stop_event,
                        erlang_config=(
                            ErlangIntegrationConfig(enabled=False)
                            if erlang_config is None
                            else erlang_config
                        ),
                        ready_event=ready_event,
                    )
                except BaseException as exc:  # surfaced at this bounded boundary
                    failures.append(exc)
                    ready_event.set()
                    update_event.set()

            thread = threading.Thread(
                target=run_watcher,
                name="crg-adoption-watch-smoke",
                daemon=True,
            )
            thread.start()
            deadline = time.monotonic() + bounded_timeout
            ready = ready_event.wait(max(0.0, deadline - time.monotonic()))
            if failures:
                raise RuntimeError("watch smoke failed during startup") from failures[0]
            if not ready:
                raise TimeoutError("watch smoke did not reach its live phase before timeout")

            source = source_files[0]
            raw_source = source.read_bytes()
            first_newline = raw_source.find(b"\n")
            if first_newline < 0:
                triggered_source = raw_source + b" "
            else:
                triggered_source = (
                    raw_source[:first_newline] + b" " + raw_source[first_newline:]
                )
            source.write_bytes(triggered_source)
            updated = update_event.wait(max(0.0, deadline - time.monotonic()))
            if updated:
                update_event.clear()
                source.write_bytes(raw_source)
                restored = update_event.wait(max(0.0, deadline - time.monotonic()))
            else:
                restored = False
            stop_event.set()
            thread.join(max(0.0, min(bounded_timeout, deadline - time.monotonic())))
            if thread.is_alive():
                raise TimeoutError("watch smoke did not stop before timeout")
            if failures:
                raise RuntimeError(
                    "watch smoke failed while processing the trigger"
                ) from failures[0]
            if not updated or not restored or callback_count < 2:
                raise TimeoutError(
                    "watch smoke did not observe both update and restore notifications"
                )
            observed_fingerprint = _portable_graph_fingerprint(store, mirror_root)
            return {
                "events": callback_count,
                "updates": callback_count,
                "graph_changed": observed_fingerprint != reference_fingerprint,
                "notifications": callback_count,
                "reference_fingerprint": reference_fingerprint,
                "observed_fingerprint": observed_fingerprint,
            }
        finally:
            stop_event.set()
            if thread is not None and thread.is_alive():
                thread.join(bounded_timeout)
            if thread is None or not thread.is_alive():
                store.close()
            else:
                # A filesystem event may already be inside incremental update
                # when the bounded smoke deadline expires.  Closing the shared
                # SQLite connection here races that worker and turns a timeout
                # into a misleading "closed database" warning.  Let a small
                # daemon finalizer close it after the watcher exits; the
                # evaluator still returns within its requested bound.
                def close_after_watch() -> None:
                    thread.join()
                    store.close()

                threading.Thread(
                    target=close_after_watch,
                    name="crg-adoption-watch-cleanup",
                    daemon=True,
                ).start()


def _run_lifecycle(
    root: Path,
    temp_root: Path,
    *,
    graph_runner: Callable[..., Any] | None = None,
    lifecycle_runner: Callable[..., Any] | None = None,
    watch_smoke: bool = False,
    watch_timeout: float = 5.0,
    erlang_config: Any = None,
) -> tuple[GraphStore, dict[str, Any], dict[str, Sequence[float]], list[dict[str, Any]]]:
    """Build a temporary graph and exercise bounded non-watch lifecycle paths."""
    store = GraphStore(temp_root / "graph.db")
    lifecycle = _empty_lifecycle("lifecycle execution was not reached")
    timings: dict[str, Sequence[float]] = {}
    diagnostics: list[dict[str, Any]] = []
    full_build_reference: GraphStore | None = None
    started = time.perf_counter()
    try:
        if graph_runner is None:
            build_result = _lifecycle_call(full_build, root, store, erlang_config=erlang_config)
        else:
            build_result = _invoke_with_optional_config(
                graph_runner,
                root,
                store,
                erlang_config=erlang_config,
            )
        duration = time.perf_counter() - started
        build_payload = _checked_lifecycle_result(build_result, "full_build", reject_errors=False)
        build_errors = build_payload.get("errors")
        if not isinstance(build_errors, list):
            build_errors = []
        build_has_errors = bool(build_errors)
        lifecycle["full_build"] = {
            "status": "error" if build_has_errors else "executed",
            "duration_seconds": duration,
            "result": build_payload,
            "parity": not build_has_errors,
        }
        if isinstance(build_payload.get("stage_timing"), Mapping):
            lifecycle["full_build"]["stage_timing"] = dict(
                build_payload["stage_timing"]
            )
        timings["full_build"] = [duration]
        if build_has_errors:
            diagnostics.append(
                _diagnostic(
                    "graph_build_errors",
                    "error",
                    "Generic graph build returned parse errors.",
                    count=len(build_errors),
                )
            )
            return store, lifecycle, timings, diagnostics

        baseline_fingerprint = graph_fingerprint(store, root)
        if lifecycle_runner is None:
            # Keep an exact snapshot of the completed full-build graph.  The
            # standalone phase must converge to this graph after applying the
            # same derived processing; a second postprocess pass alone only
            # proves idempotence and can miss a divergence from a fresh build.
            try:
                full_build_reference = GraphStore(temp_root / "full-build-reference.db")
                store._conn.backup(full_build_reference._conn)
                full_build_reference._conn.commit()
            except Exception as exc:
                diagnostics.append(
                    _diagnostic(
                        "full_build_reference_unavailable",
                        "warning",
                        "Could not snapshot the full-build graph for lifecycle parity.",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                if full_build_reference is not None:
                    full_build_reference.close()
                    full_build_reference = None
        source_files = sorted(
            _relative_path(path, root)
            for path in store.get_all_files()
            if _relative_path(path, root).endswith((".erl", ".hrl", ".app.src"))
        )
        incremental_targets = source_files[:1]

        started = time.perf_counter()
        try:
            if lifecycle_runner is None:
                update_result = _lifecycle_call(
                    incremental_update,
                    root,
                    store,
                    changed_files=incremental_targets,
                    erlang_config=erlang_config,
                )
            else:
                update_result = _invoke_with_optional_config(
                    lifecycle_runner,
                    "incremental_update",
                    root,
                    store,
                    changed_files=incremental_targets,
                    erlang_config=erlang_config,
                )
            update_payload = _checked_lifecycle_result(update_result, "incremental_update")
            update_duration = time.perf_counter() - started
            update_fingerprint = graph_fingerprint(store, root)
            raw_files_updated = update_payload.get("files_updated")
            files_updated = (
                raw_files_updated
                if isinstance(raw_files_updated, int) and not isinstance(raw_files_updated, bool)
                else 0
            )
            # Equality with the pre-update fingerprint is meaningful only when
            # the runner actually processed at least one file.  Otherwise an
            # unchanged/no-op update would be reported as a successful parity
            # check without exercising incremental reconciliation at all.
            update_parity = files_updated > 0 and baseline_fingerprint == update_fingerprint
            if files_updated <= 0:
                diagnostics.append(
                    _diagnostic(
                        "incremental_update_no_change",
                        "warning",
                        "Incremental lifecycle phase produced no file-update evidence; "
                        "parity is unverified.",
                        files_updated=raw_files_updated,
                        changed_files=incremental_targets,
                    )
                )
            lifecycle["incremental_update"] = {
                "status": "executed",
                "duration_seconds": update_duration,
                "result": update_payload,
                "parity": update_parity,
                "update_evidence": files_updated > 0,
                "baseline_fingerprint": baseline_fingerprint,
                "observed_fingerprint": update_fingerprint,
            }
            if isinstance(update_payload.get("stage_timing"), Mapping):
                lifecycle["incremental_update"]["stage_timing"] = dict(
                    update_payload["stage_timing"]
                )
            timings["incremental_update"] = [update_duration]
        except Exception as exc:
            diagnostics.append(
                _diagnostic(
                    "incremental_update_failed",
                    "error",
                    "Incremental lifecycle phase failed.",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            lifecycle["incremental_update"] = {
                "status": "error",
                "duration_seconds": time.perf_counter() - started,
                "reason": f"{type(exc).__name__}: {exc}",
                "parity": False,
            }

        started = time.perf_counter()
        try:
            if lifecycle_runner is None:
                post_result = _invoke_with_optional_config(
                    run_post_processing,
                    store,
                    repo_root=root,
                )
            else:
                post_result = _invoke_with_optional_config(
                    lifecycle_runner,
                    "standalone_postprocess",
                    root,
                    store,
                    erlang_config=erlang_config,
                )
            post_payload = _checked_lifecycle_result(post_result, "standalone_postprocess")
            post_duration = time.perf_counter() - started
            first_post_fingerprint = graph_fingerprint(store, root)
            reference_fingerprint: str | None = None
            if full_build_reference is not None:
                try:
                    reference_result = run_post_processing(
                        full_build_reference,
                        repo_root=root,
                    )
                    _checked_lifecycle_result(
                        reference_result,
                        "standalone_postprocess",
                    )
                    reference_fingerprint = graph_fingerprint(
                        full_build_reference,
                        root,
                    )
                finally:
                    full_build_reference.close()
                    full_build_reference = None
            elif lifecycle_runner is not None:
                reference_fingerprint = _valid_fingerprint(
                    post_payload.get("full_build_reference_fingerprint")
                )
                if reference_fingerprint is None:
                        diagnostics.append(
                            _diagnostic(
                                "standalone_reference_unavailable",
                                "warning",
                                "An isolated lifecycle runner did not provide a valid "
                                "full-build reference fingerprint.",
                            )
                        )

            # Post-processing may legitimately resolve bare endpoints on its
            # first invocation. Verify both convergence to the full-build
            # reference and idempotence of the second invocation.
            if lifecycle_runner is None:
                second_post_result = _invoke_with_optional_config(
                    run_post_processing,
                    store,
                    repo_root=root,
                )
                _checked_lifecycle_result(
                    second_post_result,
                    "standalone_postprocess",
                )
            else:
                second_post_result = _invoke_with_optional_config(
                    lifecycle_runner,
                    "standalone_postprocess",
                    root,
                    store,
                    erlang_config=erlang_config,
                )
                _checked_lifecycle_result(second_post_result, "standalone_postprocess")
            post_fingerprint = graph_fingerprint(store, root)
            idempotence = first_post_fingerprint == post_fingerprint
            reference_match = (
                reference_fingerprint is not None
                and post_fingerprint == reference_fingerprint
            )
            lifecycle["standalone_postprocess"] = {
                "status": "executed",
                "duration_seconds": post_duration,
                "result": post_payload,
                "parity": idempotence and reference_match,
                "idempotence": idempotence,
                "reference_match": reference_match,
                "baseline_fingerprint": baseline_fingerprint,
                "first_post_fingerprint": first_post_fingerprint,
                "reference_fingerprint": reference_fingerprint,
                "observed_fingerprint": post_fingerprint,
            }
            if isinstance(post_payload.get("postprocess_timing"), Mapping):
                lifecycle["standalone_postprocess"]["stage_timing"] = dict(
                    post_payload["postprocess_timing"]
                )
            timings["standalone_postprocess"] = [post_duration]
        except Exception as exc:
            diagnostics.append(
                _diagnostic(
                    "standalone_postprocess_failed",
                    "error",
                    "Standalone postprocess lifecycle phase failed.",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            lifecycle["standalone_postprocess"] = {
                "status": "error",
                "duration_seconds": time.perf_counter() - started,
                "reason": f"{type(exc).__name__}: {exc}",
                "parity": False,
            }

        # A real observer writes a health marker under the repository root;
        # therefore it is never started by the default read-only evaluator.
        # A caller-supplied lifecycle runner may provide an isolated smoke test.
        if watch_smoke and lifecycle_runner is None:
            started = time.perf_counter()
            target_snapshot = _checkout_snapshot(root)
            try:
                watch_payload = _run_isolated_watch_smoke(
                    root,
                    temp_root,
                    timeout=watch_timeout,
                    erlang_config=erlang_config,
                )
                if _checkout_snapshot(root) != target_snapshot:
                    raise RuntimeError("isolated watch smoke changed the target checkout")
                watch_payload = _checked_lifecycle_result(watch_payload, "watch")
                watch_after = _valid_fingerprint(watch_payload.get("observed_fingerprint"))
                if watch_after is None:
                    raise ValueError("isolated watch smoke did not return an observed fingerprint")
                watch_reference = _valid_fingerprint(watch_payload.get("reference_fingerprint"))
                if watch_reference is None:
                    watch_reference = _valid_fingerprint(
                        watch_payload.get("full_build_reference_fingerprint")
                    )
                watch_reference_match = (
                    watch_reference is not None and watch_after == watch_reference
                )
                watch_activity, watch_counts = _watch_activity_evidence(watch_payload)
                watch_duration = time.perf_counter() - started
                lifecycle["watch"] = {
                    "status": "executed",
                    "duration_seconds": watch_duration,
                    "result": watch_payload,
                    "parity": watch_activity and watch_reference_match,
                    "activity_evidence": watch_activity,
                    "reference_match": watch_reference_match,
                    "reference_fingerprint": watch_reference,
                    "observed_fingerprint": watch_after,
                }
                timings["watch"] = [watch_duration]
            except Exception as exc:
                target_changed = False
                try:
                    target_changed = _checkout_snapshot(root) != target_snapshot
                except Exception:
                    # The original watch failure remains the primary error;
                    # an unreadable target is still fail-closed below.
                    pass
                diagnostic_code = "target_write_detected" if target_changed else "watch_failed"
                diagnostic_message = (
                    "Isolated watch smoke changed the target checkout."
                    if target_changed
                    else "Isolated watch smoke failed."
                )
                diagnostics.append(
                    _diagnostic(
                        diagnostic_code,
                        "error",
                        diagnostic_message,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                lifecycle["watch"] = {
                    "status": "error",
                    "duration_seconds": time.perf_counter() - started,
                    "reason": f"{type(exc).__name__}: {exc}",
                    "parity": False,
                }
        elif lifecycle_runner is not None and watch_smoke:
            started = time.perf_counter()
            try:
                watch_result = _invoke_with_optional_config(
                    lifecycle_runner,
                    "watch",
                    root,
                    store,
                    erlang_config=erlang_config,
                )
                watch_payload = _checked_lifecycle_result(watch_result, "watch")
                watch_after = graph_fingerprint(store, root)
                watch_activity, watch_counts = _watch_activity_evidence(watch_payload)
                watch_reference = _valid_fingerprint(
                    watch_payload.get("reference_fingerprint")
                )
                if watch_reference is None:
                    watch_reference = _valid_fingerprint(
                        watch_payload.get("full_build_reference_fingerprint")
                    )
                watch_reference_match = (
                    watch_reference is not None and watch_after == watch_reference
                )
                # A before/after equality is not a reference graph.  Requiring
                # an isolated runner to provide one prevents a no-op watch
                # smoke from being reported as lifecycle parity.
                watch_parity = (
                    watch_activity
                    and watch_reference_match
                )
                if not watch_activity:
                    diagnostics.append(
                        _diagnostic(
                            "watch_activity_unverified",
                            "warning",
                            "Watch smoke returned no complete event/update/notification evidence.",
                            **watch_counts,
                        )
                    )
                elif watch_reference is None:
                    diagnostics.append(
                        _diagnostic(
                            "watch_reference_unavailable",
                            "warning",
                            "Watch smoke did not provide a valid reference fingerprint.",
                        )
                    )
                elif not watch_reference_match:
                    diagnostics.append(
                        _diagnostic(
                            "watch_reference_mismatch",
                            "warning",
                            "Watch smoke graph does not match its supplied reference fingerprint.",
                            reference_fingerprint=watch_reference,
                            observed_fingerprint=watch_after,
                        )
                    )
                lifecycle["watch"] = {
                    "status": "executed",
                    "duration_seconds": time.perf_counter() - started,
                    "result": watch_payload,
                    "parity": watch_parity,
                    "activity_evidence": watch_activity,
                    "reference_match": watch_reference_match,
                    "reference_fingerprint": watch_reference,
                    "observed_fingerprint": watch_after,
                }
            except Exception as exc:
                diagnostics.append(
                    _diagnostic(
                        "watch_failed",
                        "error",
                        "Watch lifecycle phase failed.",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                lifecycle["watch"] = {
                    "status": "error",
                    "duration_seconds": time.perf_counter() - started,
                    "reason": f"{type(exc).__name__}: {exc}",
                    "parity": False,
                }
        else:
            lifecycle["watch"] = {
                "status": "not_run",
                "reason": "watch_smoke_disabled_read_only_boundary"
                if not watch_smoke
                else "watch_requires_isolated_runner",
                "duration_seconds": None,
                "parity": False,
            }

        files = [
            path
            for path in store.get_all_files()
            if _relative_path(path, root).endswith((".erl", ".hrl", ".app.src"))
        ]
        if files:
            forget_store = GraphStore(temp_root / "forget.db")
            try:
                if lifecycle_runner is None:
                    forget_build_result = _lifecycle_call(
                        full_build,
                        root,
                        forget_store,
                        erlang_config=erlang_config,
                    )
                    _checked_lifecycle_result(forget_build_result, "full_build")
                else:
                    forget_build_result = _invoke_with_optional_config(
                        lifecycle_runner,
                        "full_build",
                        root,
                        forget_store,
                        erlang_config=erlang_config,
                    )
                    _checked_lifecycle_result(forget_build_result, "full_build")
                target = sorted(files)[0]
                started = time.perf_counter()
                if lifecycle_runner is None:
                    # ``forget_files`` uses ``None`` to mean "consult the
                    # environment" for its public API.  The adoption runner's
                    # default is deliberately Generic-only, so pass an
                    # explicit disabled config when no opt-in was supplied;
                    # otherwise an ambient CRG_ERLANG_ENABLED could make this
                    # one phase execute semantic tools unexpectedly.
                    forget_config = (
                        ErlangIntegrationConfig(enabled=False)
                        if erlang_config is None
                        else erlang_config
                    )
                    forget_kwargs: dict[str, Any] = {"erlang_config": forget_config}
                    forget_result = _invoke_with_optional_config(
                        forget_files,
                        forget_store,
                        root,
                        [target],
                        **forget_kwargs,
                    )
                else:
                    forget_result = _invoke_with_optional_config(
                        lifecycle_runner,
                        "forget",
                        root,
                        forget_store,
                        [target],
                        erlang_config=erlang_config,
                    )
                forget_payload = _checked_lifecycle_result(forget_result, "forget")
                forget_duration = time.perf_counter() - started
                target_absent = target not in forget_store.get_all_files()
                forget_parity = False
                forget_baseline_fingerprint: str | None = None
                forget_observed_fingerprint: str | None = None
                forget_evidence_error: str | None = None
                try:
                    forget_observed_fingerprint = _portable_graph_fingerprint(
                        forget_store, root
                    )
                    forget_baseline_fingerprint = _fresh_forget_fingerprint(
                        root,
                        temp_root,
                        target,
                        erlang_config=erlang_config,
                    )
                    forget_parity = (
                        target_absent
                        and forget_observed_fingerprint == forget_baseline_fingerprint
                    )
                    if not forget_parity:
                        diagnostics.append(
                            _diagnostic(
                                "forget_parity_mismatch",
                                "error",
                                "Forget graph differs from a fresh build without the target file.",
                                target=target,
                                target_absent=target_absent,
                                observed_fingerprint=forget_observed_fingerprint,
                                baseline_fingerprint=forget_baseline_fingerprint,
                            )
                        )
                except Exception as exc:
                    forget_evidence_error = f"{type(exc).__name__}: {exc}"
                    diagnostics.append(
                        _diagnostic(
                            "forget_parity_unavailable",
                            "error",
                            "Could not build a fresh baseline for forget parity.",
                            target=target,
                            error=forget_evidence_error,
                        )
                    )
                if (
                    forget_evidence_error is None
                    and (
                        forget_baseline_fingerprint is None
                        or forget_observed_fingerprint is None
                    )
                ):
                    # A phase cannot be reported as executed when its
                    # independent parity reference was never measured.  Keep
                    # the failure explicit so the adoption verdict is blocked
                    # and the result validator does not require absent hashes.
                    forget_evidence_error = "parity fingerprints unavailable"
                forget_record: dict[str, Any] = {
                    "status": "error" if forget_evidence_error is not None else "executed",
                    "duration_seconds": forget_duration,
                    "result": forget_payload,
                    "forgotten": target,
                    "target_absent": target_absent,
                    "parity": forget_parity,
                    "baseline_fingerprint": forget_baseline_fingerprint,
                    "observed_fingerprint": forget_observed_fingerprint,
                }
                if forget_evidence_error is not None:
                    forget_record["reason"] = forget_evidence_error
                lifecycle["forget"] = forget_record
                timings["forget"] = [forget_duration]
            except Exception as exc:
                diagnostics.append(
                    _diagnostic(
                        "forget_failed",
                        "error",
                        "Forget lifecycle phase failed.",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                lifecycle["forget"] = {
                    "status": "error",
                    "duration_seconds": time.perf_counter() - started,
                    "reason": f"{type(exc).__name__}: {exc}",
                    "parity": False,
                }
            finally:
                forget_store.close()
        else:
            lifecycle["forget"] = {
                "status": "not_run",
                "reason": "no_erlang_file_to_forget",
                "duration_seconds": None,
                "parity": False,
            }
        return store, lifecycle, timings, diagnostics
    except Exception as exc:
        diagnostics.append(
            _diagnostic(
                "full_build_failed",
                "error",
                "Full build lifecycle phase failed.",
                error=f"{type(exc).__name__}: {exc}",
            )
        )
        lifecycle["full_build"] = {
            "status": "error",
            "duration_seconds": time.perf_counter() - started,
            "reason": f"{type(exc).__name__}: {exc}",
            "parity": False,
        }
        diagnostics.append(_diagnostic("graph_build_failed", "error", str(exc)))
        return store, lifecycle, timings, diagnostics
    finally:
        if full_build_reference is not None:
            full_build_reference.close()


def _impact_metric(corpus: Mapping[str, Any], store: GraphStore, root: Path) -> dict[str, Any]:
    """Score optional independent impact ground truth supplied by a corpus."""
    entries: list[Any] = []
    top_level_entries = corpus.get("impact")
    if isinstance(top_level_entries, list):
        entries.extend(top_level_entries)
    cases = corpus.get("cases", [])
    if isinstance(cases, Sequence) and not isinstance(cases, (str, bytes, bytearray)):
        for case in cases:
            if isinstance(case, Mapping) and isinstance(case.get("impact"), Mapping):
                entries.append(case["impact"])
    if not isinstance(entries, list) or not entries:
        return {"status": "not_run", "coverage": None, "reason": "impact_ground_truth_not_declared"}
    expected: set[str] = set()
    predicted: set[str] = set()
    covered: set[str] = set()
    false_positive_count = 0
    disallowed_false_positive_count = 0
    false_positive_allowed = False
    entry_results: list[dict[str, Any]] = []
    invalid_entries = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            invalid_entries += 1
            continue
        changed = entry.get("changed_files", entry.get("changed"))
        critical = entry.get("critical_dependents", entry.get("expected", []))
        if (
            not isinstance(changed, list)
            or not isinstance(critical, list)
            or not all(isinstance(path, str) and path for path in changed)
            or not all(isinstance(path, str) and path for path in critical)
        ):
            invalid_entries += 1
            continue
        try:
            # Keep this helper safe when called directly, outside the public
            # preflight path validation in ``run_adoption_evaluation``.
            changed_relative = [
                _safe_relative_path(
                    path,
                    root,
                    f"impact[{index}].changed_files[{path_index}]",
                )
                for path_index, path in enumerate(changed)
            ]
            critical_relative = [
                _safe_relative_path(
                    path,
                    root,
                    f"impact[{index}].critical_dependents[{path_index}]",
                )
                for path_index, path in enumerate(critical)
            ]
        except ValueError:
            invalid_entries += 1
            continue
        false_positive_allowed = false_positive_allowed or bool(
            entry.get("allow_false_positives") is True
            or entry.get("false_positive_allowed") is True
        )
        try:
            max_depth = int(entry.get("max_depth", 2))
        except (TypeError, ValueError, OverflowError):
            invalid_entries += 1
            continue
        if max_depth < 0:
            invalid_entries += 1
            continue
        try:
            changed_abs = [normalize_file_path(root / path) for path in changed_relative]
            result = store.get_impact_radius(changed_abs, max_depth=max_depth, max_nodes=10_000)
        except Exception as exc:  # noqa: BLE001 - malformed graph evidence is fail-closed
            invalid_entries += 1
            entry_results.append(
                {
                    "index": index,
                    "expected": sorted(critical_relative),
                    "predicted": [],
                    "covered": [],
                    "coverage": None,
                    "false_positive_count": 0,
                    "false_positive_allowed": False,
                    "status": "error",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        entry_predicted = {_relative_path(path, root) for path in result.get("impacted_files", [])}
        entry_expected = set(critical_relative)
        entry_covered = entry_expected.intersection(entry_predicted)
        entry_false_positive = entry_predicted - entry_expected
        entry_allowed = bool(
            entry.get("allow_false_positives") is True
            or entry.get("false_positive_allowed") is True
        )
        false_positive_allowed = false_positive_allowed or entry_allowed
        false_positive_count += len(entry_false_positive)
        if not entry_allowed:
            disallowed_false_positive_count += len(entry_false_positive)
        expected.update(entry_expected)
        predicted.update(entry_predicted)
        covered.update(entry_covered)
        entry_results.append(
            {
                "index": index,
                "expected": sorted(entry_expected),
                "predicted": sorted(entry_predicted),
                "covered": sorted(entry_covered),
                "coverage": (len(entry_covered) / len(entry_expected) if entry_expected else None),
                "false_positive_count": len(entry_false_positive),
                "false_positive_allowed": entry_allowed,
            }
        )
    if not entry_results or not expected or invalid_entries:
        return {"status": "not_run", "coverage": None, "reason": "impact_ground_truth_empty"}
    all_entries_covered = all(item.get("coverage") == 1.0 for item in entry_results)
    return {
        "status": "executed",
        "expected": sorted(expected),
        "predicted": sorted(predicted),
        "covered": sorted(covered),
        "coverage": len(covered) / len(expected),
        "all_entries_covered": all_entries_covered,
        "entries": entry_results,
        "false_positive_count": false_positive_count,
        "disallowed_false_positive_count": disallowed_false_positive_count,
        "false_positive_allowed": false_positive_allowed,
    }


def _aggregate_metrics(
    case_results: Sequence[Mapping[str, Any]],
    timings: Mapping[str, Sequence[float]],
    corpus: Mapping[str, Any],
    store: GraphStore | None,
    root: Path,
    lifecycle: Mapping[str, Mapping[str, Any]] | None = None,
    environment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    scored = [
        item
        for item in case_results
        if item.get("status") == "executed" and item.get("precision") is not None
    ]
    predicted = sum(int(item.get("predicted_count", 0)) for item in scored)
    true_positive = sum(int(item.get("true_positive", 0)) for item in scored)
    expected = sum(int(item.get("expected_positive_count", 0)) for item in scored)
    precision = true_positive / predicted if predicted else None
    recall = true_positive / expected if expected else None

    recall_at_10 = _recall_at_10_from_cases(scored)
    lifecycle_map = lifecycle if isinstance(lifecycle, Mapping) else {}
    environment_map = environment if isinstance(environment, Mapping) else {}
    repository_observation = environment_map.get("repository", {})
    generated_observation = environment_map.get("generated_data", {})
    cache_observation = environment_map.get("cache", {})
    common_provenance = {
        "repository": (
            str(repository_observation.get("path"))
            if isinstance(repository_observation, Mapping)
            and isinstance(repository_observation.get("path"), str)
            else str(_canonical_path(root))
        ),
        "source_revision": (
            repository_observation.get("revision")
            if isinstance(repository_observation, Mapping)
            else None
        ),
        "generated_data_revision": (
            generated_observation.get("revision")
            if isinstance(generated_observation, Mapping)
            else None
        ),
        "cache_state": (
            cache_observation.get("stale_evidence_policy")
            if isinstance(cache_observation, Mapping)
            else None
        ),
    }
    sample_provenance: dict[str, list[dict[str, Any]]] = {}
    for operation in (timings if isinstance(timings, Mapping) else {}):
        operation_name = str(operation)
        if operation_name == "targeted_query":
            # ``_evaluate_case_results`` appends targeted-query durations in
            # the same order as executed cases.  Bind each sample to the
            # immutable case id and query kind rather than to a bare index.
            sample_provenance[operation_name] = [
                {
                    **common_provenance,
                    "source": "case",
                    "case_id": item.get("id"),
                    "query_kind": item.get("query_kind"),
                }
                for item in case_results
                if item.get("status") == "executed"
                and item.get("duration_seconds") is not None
            ]
        else:
            phase = lifecycle_map.get(operation_name)
            sample_provenance[operation_name] = [
                {
                    **common_provenance,
                    "source": "lifecycle",
                    "phase": operation_name,
                    "status": phase.get("status")
                    if isinstance(phase, Mapping)
                    else "executed",
                }
                for _ in (
                    timings.get(operation, ())
                    if isinstance(timings, Mapping)
                    else ()
                )
            ]
    result: dict[str, Any] = {
        "status": "executed" if scored else "not_run",
        "cases_scored": len(scored),
        "precision": precision,
        "recall": recall,
        "recall_at_10": recall_at_10,
        "forbidden_matches": sum(int(item.get("forbidden_matches", 0)) for item in case_results),
        "latency": _latency_metric(timings, sample_provenance),
    }
    if store is not None:
        result["impact"] = _impact_metric(corpus, store, root)
    else:
        result["impact"] = {"status": "not_run", "coverage": None, "reason": "graph_not_built"}
    return result


def _recall_at_10_from_cases(
    case_results: Sequence[Mapping[str, Any]],
) -> dict[str, float | None]:
    """Recompute grouped Recall@10 from per-case ranked hit evidence."""
    groups: dict[str, dict[str, int]] = {
        "function": {"hit": 0, "expected": 0},
        "module": {"hit": 0, "expected": 0},
    }
    for item in case_results:
        if item.get("status") != "executed" or item.get("precision") is None:
            continue
        category = str(item.get("category"))
        group = (
            "function"
            if category in _FUNCTION_CATEGORIES
            else "module"
            if category in _MODULE_CATEGORIES
            else None
        )
        if group:
            # ``true_positive`` is calculated over the complete prediction
            # list and therefore cannot represent Recall@10.  Scored cases
            # carry the bounded, one-to-one top-10 hit count separately.
            groups[group]["hit"] += int(item.get("ranked_true_positive", 0))
            groups[group]["expected"] += int(item.get("expected_positive_count", 0))
    return {
        group: (values["hit"] / values["expected"] if values["expected"] else None)
        for group, values in groups.items()
    }


_DEFAULT_REQUIRED_SEMANTIC_ADAPTERS = frozenset({"elp", "xref", "dialyzer"})


def _adapter_manifest_names(policy: Mapping[str, Any]) -> set[str]:
    """Return the declared adapter names in a policy summary.

    ``inspect_adapter_manifests`` exposes names as a list, while callers that
    construct an in-memory result sometimes provide the loaded manifests as a
    mapping.  Accept both forms at this boundary and normalize case once.
    """
    declared = policy.get("manifests")
    if isinstance(declared, Mapping):
        return {str(name).casefold() for name in declared if str(name)}
    if isinstance(declared, Sequence) and not isinstance(declared, (str, bytes, bytearray)):
        return {str(name).casefold() for name in declared if isinstance(name, str) and name}
    return set()


def _adapter_manifest_activations(policy: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Extract activation records from the compact or loaded policy forms."""
    candidates: list[Any] = [policy.get("manifest_activation")]
    for key in ("manifest_details", "adapter_manifests"):
        details = policy.get(key)
        if isinstance(details, Mapping):
            candidates.append(details)
    declared = policy.get("manifests")
    if isinstance(declared, Mapping):
        candidates.append(declared)
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        result: dict[str, Mapping[str, Any]] = {}
        for name, value in candidate.items():
            if not isinstance(value, Mapping):
                continue
            activation = value.get("activation", value)
            if isinstance(activation, Mapping):
                result[str(name).casefold()] = activation
        if result:
            return result
    return {}


def _semantic_required_adapters(environment: Mapping[str, Any]) -> set[str]:
    """Derive required semantic adapters from immutable manifest policy data.

    External adapters are optional when their manifest says
    ``explicit_opt_in`` and ``required: false``.  If only the legacy name list
    is available, retain the conservative historical requirement rather than
    silently treating an incomplete policy as proof that no adapter is needed.
    """
    policy = environment.get("adapter_policy", {})
    if not isinstance(policy, Mapping):
        return set(_DEFAULT_REQUIRED_SEMANTIC_ADAPTERS)
    names = _adapter_manifest_names(policy)
    activations = _adapter_manifest_activations(policy)
    if not names and activations:
        names = set(activations)
    if not names:
        return set(_DEFAULT_REQUIRED_SEMANTIC_ADAPTERS)
    required: set[str] = set()
    for name in names:
        if name == "generic":
            continue
        activation = activations.get(name)
        if not isinstance(activation, Mapping):
            # A policy name without its activation contract is unverified.
            required.add(name)
            continue
        mode = str(activation.get("mode", "")).casefold()
        if activation.get("required") is True or mode != "explicit_opt_in":
            required.add(name)
    return required


def _compact_adapter_policy(
    environment: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Keep policy identity and activation semantics in the result envelope."""
    raw = environment.get("adapter_policy", {})
    policy = dict(raw) if isinstance(raw, Mapping) else {}
    loaded = manifest.get("_adapter_manifests")
    if isinstance(loaded, Mapping):
        names = sorted(str(name).casefold() for name in loaded)
        policy["manifests"] = names
        activation: dict[str, dict[str, Any]] = {}
        for name, item in loaded.items():
            if not isinstance(item, Mapping):
                continue
            value = item.get("activation")
            if not isinstance(value, Mapping):
                continue
            activation[str(name).casefold()] = {
                "mode": value.get("mode"),
                "required": value.get("required"),
            }
        if activation:
            policy["manifest_activation"] = activation
    return policy


def _adapter_runtime_policy_enforced(environment: Mapping[str, Any]) -> bool:
    """Return whether every declared adapter has an enforced runtime policy.

    Generic-only evaluation has no external execution boundary and is treated
    as not applicable.  Once a semantic adapter is declared, however, an
    absent or false ``runtime_policy_enforced`` value is an explicit lack of
    isolation and cannot support a primary adoption verdict.
    """
    policy = environment.get("adapter_policy")
    if not isinstance(policy, Mapping):
        # An absent policy cannot prove that a semantic execution boundary is
        # enforced.  Generic-only callers still remain auxiliary because the
        # semantic execution gate itself has no valid envelope.
        return False
    names = _adapter_manifest_names(policy)
    semantic_names = names - {"generic"}
    if not semantic_names:
        return True
    return policy.get("runtime_policy_enforced") is True


def _generated_data_consistency(
    environment: Mapping[str, Any], corpus: Mapping[str, Any] | None
) -> tuple[bool, bool, str | None]:
    """Check generated-data markers against the immutable manifest contract.

    The check is applicable only when both artifacts explicitly exercise the
    generated-data category.  This keeps small Generic fixtures usable while
    making a declared generated-data corpus fail closed on missing markers,
    missing paths, or revision/configuration drift.
    """
    observed = environment.get("generated_data")
    contract = environment.get("generated_data_contract")
    if not isinstance(contract, Mapping) and isinstance(observed, Mapping):
        # Public result envelopes carry the expected values under ``expected``
        # so validation does not need to reopen the manifest artifact.
        candidate = observed.get("expected")
        if isinstance(candidate, Mapping):
            contract = candidate
    cases = corpus.get("cases", []) if isinstance(corpus, Mapping) else []
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes, bytearray)):
        cases = []
    corpus_declared = any(
        isinstance(item, Mapping) and item.get("category") == "generated_data"
        for item in cases
    )
    if not isinstance(contract, Mapping) or not corpus_declared:
        return True, False, None

    if not isinstance(observed, Mapping):
        return False, True, "generated_data_unavailable"
    expected_revision = contract.get("revision")
    expected_config = contract.get("config_version")
    observed_revision = observed.get("revision")
    observed_config = observed.get("config_version")
    if (
        not isinstance(expected_revision, str)
        or not expected_revision
        or not isinstance(expected_config, str)
        or not expected_config
        or not isinstance(observed_revision, str)
        or not observed_revision
        or not isinstance(observed_config, str)
        or not observed_config
    ):
        return False, True, "generated_data_markers_unavailable"
    if observed_revision != expected_revision or observed_config != expected_config:
        return False, True, "generated_data_revision_mismatch"

    marker_files = observed.get("marker_files")
    if not isinstance(marker_files, Mapping) or any(
        marker_files.get(marker) is not True for marker in _GENERATED_DATA_MARKERS
    ):
        return False, True, "generated_data_markers_unavailable"

    expected_paths = contract.get("paths", [])
    counts = observed.get("counts")
    if not isinstance(expected_paths, list) or not isinstance(counts, Mapping):
        return False, True, "generated_data_paths_unavailable"
    for path in expected_paths:
        if not isinstance(path, str) or not path:
            return False, True, "generated_data_paths_unavailable"
        # ``_discover_generated_data`` records ``None`` when an expected
        # generated directory/file is absent or unreadable.  A non-negative
        # count is the only reliable positive evidence for the declared
        # directory layout used by the adoption corpus.
        count = counts.get(path)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return False, True, "generated_data_paths_unavailable"

    return True, True, None


def _diagnostics_contract(corpus: Mapping[str, Any]) -> dict[str, Any]:
    metrics = corpus.get("metrics")
    if not isinstance(metrics, Mapping):
        return {}
    contract = metrics.get("diagnostics")
    return dict(contract) if isinstance(contract, Mapping) else {}


def _top_level_diagnostics_gate(
    observed_codes: set[str], contract: Mapping[str, Any]
) -> bool:
    """Evaluate the corpus-level diagnostic requirement from observed codes."""
    required = contract.get("required")
    if required is True:
        return bool(observed_codes)
    if not isinstance(required, list):
        return True
    if not required:
        return True
    required_codes = [item for item in required if isinstance(item, str)]
    return bool(observed_codes) and len(required_codes) == len(required) and set(
        required_codes
    ).issubset(observed_codes)


def _semantic_execution_state(
    environment: Mapping[str, Any], lifecycle: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Inspect lifecycle envelopes for *executed* adapter evidence.

    Tool availability discovered during preflight is deliberately insufficient
    for an adoption gate.  The evaluator normally disables semantic adapters;
    only an injected, isolated lifecycle runner that returns a successful
    integration envelope can satisfy this gate.
    """
    required = _semantic_required_adapters(environment)
    policy_enforced = _adapter_runtime_policy_enforced(environment)
    seen: set[str] = set()
    statuses: dict[str, str] = {}
    envelopes = 0
    failures: list[str] = []
    for phase_name in _LIFECYCLE_PHASES:
        phase = lifecycle.get(phase_name)
        if not isinstance(phase, Mapping):
            continue
        # A payload attached to a skipped/error phase is not executable
        # evidence.  Counting it would let a hand-edited lifecycle envelope
        # satisfy the semantic gate without that phase actually running.
        if phase.get("status") != "executed":
            continue
        payload = phase.get("result")
        if not isinstance(payload, Mapping):
            continue
        integration = payload.get("erlang_integration")
        if not isinstance(integration, Mapping):
            # An injected runner may expose the envelope directly.
            integration = payload if "adapters" in payload else None
        if not isinstance(integration, Mapping):
            continue
        envelopes += 1
        overall = str(integration.get("status", "not_run")).casefold()
        if overall not in {"ok", "executed"}:
            failures.append(overall)
        adapters = integration.get("adapters")
        if isinstance(adapters, Mapping):
            for name, item in adapters.items():
                adapter_name = str(name).casefold()
                status = (
                    str(item.get("status", "not_run")).casefold()
                    if isinstance(item, Mapping)
                    else str(item).casefold()
                )
                statuses[adapter_name] = status
                if status in {"ok", "executed"}:
                    seen.add(adapter_name)
                elif status not in {"skipped", "disabled", "not_run"}:
                    failures.append(f"{adapter_name}:{status}")
        for collection_name in ("evidence", "diagnostics"):
            collection = integration.get(collection_name, [])
            if not isinstance(collection, list):
                continue
            for record in collection:
                if not isinstance(record, Mapping):
                    continue
                provenance = record.get("provenance")
                tool = (
                    provenance.get("tool")
                    if isinstance(provenance, Mapping)
                    else record.get("tool")
                )
                if isinstance(tool, str) and tool:
                    seen.add(tool.casefold())
    # Provenance records alone do not prove that an adapter actually ran: a
    # stale cache or a hand-written envelope could contain the same tool name.
    # Restrict successful evidence to adapters declared by the policy.  The
    # Generic adapter is always-on baseline indexing, so it must never satisfy
    # this semantic-adapter gate.  When no adapter names are available at all,
    # retain the conservative legacy requirement set as the allow-list.
    policy = environment.get("adapter_policy", {})
    declared = _adapter_manifest_names(policy) if isinstance(policy, Mapping) else set()
    if not declared and isinstance(policy, Mapping):
        declared = set(_adapter_manifest_activations(policy))
    semantic_declared = {name for name in declared if name != "generic"}
    allowed_success = semantic_declared or (required if not declared else set())
    explicit_success = {
        name
        for name, status in statuses.items()
        if status in {"ok", "executed"} and name in allowed_success
    }
    # Even when every optional adapter is explicitly marked ``required: false``,
    # promotion still needs proof that at least one declared semantic adapter
    # ran.  A generic/disabled envelope alone is not semantic execution.
    valid = (
        policy_enforced
        and bool(envelopes)
        and bool(explicit_success)
        and not failures
        and required.issubset(explicit_success)
    )
    reason: str | None
    if valid:
        reason = None
    elif not policy_enforced:
        reason = "adapter_runtime_policy_not_enforced"
    else:
        reason = "semantic_adapter_execution_not_verified"
    return {
        "status": "executed" if valid else "not_run",
        "required": sorted(required),
        "observed": sorted(seen),
        "statuses": statuses,
        "envelopes": envelopes,
        "valid": valid,
        "policy_enforced": policy_enforced,
        "reason": reason,
    }


def _adoption_gates(
    gates: Mapping[str, Any],
    environment: Mapping[str, Any],
    case_results: Sequence[Mapping[str, Any]],
    lifecycle: Mapping[str, Mapping[str, Any]],
    metrics: Mapping[str, Any],
    corpus: Mapping[str, Any] | None = None,
    diagnostic_codes: set[str] | None = None,
) -> dict[str, Any]:
    available_tools = _available_semantic_tools(environment)
    semantic_execution = _semantic_execution_state(environment, lifecycle)
    semantic_complete = bool(semantic_execution.get("valid"))
    generated_data_ok, generated_data_applicable, _generated_data_reason = (
        _generated_data_consistency(environment, corpus)
    )
    all_cases_executed = bool(case_results) and all(
        item.get("status") == "executed" for item in case_results
    )
    missing_anchors_ok = all(
        not item.get("missing_anchors") for item in case_results if isinstance(item, Mapping)
    )
    measured_cases_ok = (
        all(
            item.get("measurement_complete") is True
            for item in case_results
            if item.get("status") == "executed"
        )
        and all_cases_executed
    )
    precision_ok = (
        metrics.get("precision") == 1.0
        and int(metrics.get("cases_scored", 0)) > 0
        and all_cases_executed
        and measured_cases_ok
        and int(metrics.get("forbidden_matches", 0)) == 0
    )
    recalls = metrics.get("recall_at_10", {})
    function_recall = (
        _finite_nonnegative(recalls.get("function")) if isinstance(recalls, Mapping) else None
    )
    module_recall = (
        _finite_nonnegative(recalls.get("module")) if isinstance(recalls, Mapping) else None
    )
    recall_ok = (
        function_recall is not None
        and module_recall is not None
        and function_recall <= 1.0
        and module_recall <= 1.0
        and function_recall >= 0.9
        and module_recall >= 0.9
    )
    impact = metrics.get("impact", {})
    impact_ok = (
        isinstance(impact, Mapping)
        and impact.get("status") == "executed"
        and impact.get("coverage") == 1.0
        and impact.get("all_entries_covered") is True
        and (int(impact.get("disallowed_false_positive_count", 0)) == 0)
    )
    latency = metrics.get("latency", {})
    budget = environment.get("evaluation", {})
    # The manifest stores budgets in milliseconds; use explicit values only.
    budget_ms = budget.get("latency_budget_ms", {}) if isinstance(budget, Mapping) else {}
    full_budget = (
        _finite_nonnegative(budget_ms.get("full_build_p95"))
        if isinstance(budget_ms, Mapping)
        else None
    )
    targeted_budget = (
        _finite_nonnegative(budget_ms.get("targeted_query_p95"))
        if isinstance(budget_ms, Mapping)
        else None
    )
    latency_map = latency if isinstance(latency, Mapping) else {}
    by_operation = latency_map.get("by_operation", {})
    full_latency = by_operation.get("full_build", {}) if isinstance(by_operation, Mapping) else {}
    targeted_latency = (
        by_operation.get("targeted_query", {}) if isinstance(by_operation, Mapping) else {}
    )
    full_p95 = (
        _finite_nonnegative(full_latency.get("p95_ms"))
        if isinstance(full_latency, Mapping)
        else None
    )
    targeted_p95 = (
        _finite_nonnegative(targeted_latency.get("p95_ms"))
        if isinstance(targeted_latency, Mapping)
        else None
    )
    invalid_latency_samples = _nonnegative_count(latency_map.get("invalid_samples"))
    latency_samples_complete = all(
        isinstance(by_operation, Mapping)
        and isinstance(by_operation.get(operation), Mapping)
        and _nonnegative_count(by_operation[operation].get("samples")) is not None
        and int(by_operation[operation].get("samples", 0)) >= _LATENCY_MIN_SAMPLES
        for operation in _LATENCY_REQUIRED_OPERATIONS
    )
    latency_provenance_complete = isinstance(
        latency_map.get("sample_provenance"), Mapping
    ) and all(
        isinstance(latency_map["sample_provenance"].get(operation), list)
        and len(latency_map["sample_provenance"].get(operation, []))
        >= _LATENCY_MIN_SAMPLES
        for operation in _LATENCY_REQUIRED_OPERATIONS
    )
    latency_ok = (
        latency_map.get("status") == "executed"
        and invalid_latency_samples == 0
        and latency_samples_complete
        and latency_provenance_complete
        and full_budget is not None
        and targeted_budget is not None
        and full_p95 is not None
        and targeted_p95 is not None
        and full_p95 <= full_budget
        and targeted_p95 <= targeted_budget
    )
    lifecycle_names = _LIFECYCLE_PHASES
    lifecycle_errors = any(
        isinstance(lifecycle.get(name), Mapping)
        and lifecycle[name].get("status") in {"error", "blocked"}
        for name in lifecycle_names
    )
    lifecycle_ok = all(
        isinstance(lifecycle.get(name), Mapping)
        and _lifecycle_parity_from_evidence(name, lifecycle[name])
        for name in lifecycle_names
    )
    unresolved_cases = [
        item for item in case_results if int(item.get("unresolved_expected_count", 0) or 0) > 0
    ]
    unresolved_ok = not unresolved_cases or all(
        item.get("status") == "executed"
        and item.get("measurement_complete") is True
        and item.get("unresolved_satisfied") is True
        for item in unresolved_cases
    )
    required_diagnostic_cases = [
        item
        for item in case_results
        if isinstance(item.get("required_diagnostics"), list) and item.get("required_diagnostics")
    ]
    required_diagnostics_ok = not required_diagnostic_cases or all(
        item.get("status") == "executed" and item.get("required_diagnostics_satisfied") is True
        for item in required_diagnostic_cases
    )
    no_forbidden_matches = int(metrics.get("forbidden_matches", 0)) == 0
    observed_diagnostics = [
        item for item in environment.get("diagnostics", []) if isinstance(item, Mapping)
    ]
    observed_codes = set(diagnostic_codes or ())
    observed_codes.update(
        str(item.get("code")) for item in observed_diagnostics if isinstance(item.get("code"), str)
    )
    diagnostics_observable = bool(
        observed_codes.intersection(
            {
                "required_tool_unavailable",
                "required_tool_version_mismatch",
                "otp_config_runtime_mismatch",
                "project_otp_configuration_stale",
                "xref_unavailable",
                "dialyzer_unavailable",
            }
        )
    ) or bool(available_tools)
    diagnostics_contract = _diagnostics_contract(corpus or {})
    top_level_diagnostics_ok = _top_level_diagnostics_gate(observed_codes, diagnostics_contract)

    adoption_gates = {
        "target_available": bool(gates.get("target_exists")),
        "standalone_git": bool(gates.get("standalone_git")),
        "pinned_revision": bool(gates.get("pinned_revision")),
        "clean_baseline": bool(gates.get("clean_baseline")),
        "working_tree_state_known": bool(gates.get("working_tree_state_known")),
        "remote_identity": bool(gates.get("remote_identity")),
        "dependencies_consistent": bool(gates.get("dependencies_consistent")),
        "generated_data_consistent": generated_data_ok,
        "runtime_policy_enforced": _adapter_runtime_policy_enforced(environment),
        "semantic_tools": semantic_complete,
        "semantic_adapters_executed": semantic_complete,
        "precision_100": precision_ok,
        "all_cases_executed": all_cases_executed,
        "all_cases_measured": measured_cases_ok,
        "missing_anchors": missing_anchors_ok,
        "no_forbidden_matches": no_forbidden_matches,
        "unresolved_contract": unresolved_ok,
        "required_diagnostics": required_diagnostics_ok,
        "recall_at_10": recall_ok,
        "impact_coverage": impact_ok,
        "latency_budget": latency_ok,
        "lifecycle_parity": lifecycle_ok,
        "lifecycle_errors": not lifecycle_errors,
        "diagnostics_observable": diagnostics_observable,
        "top_level_diagnostics": top_level_diagnostics_ok,
    }
    # A dirty baseline is a valid reason to defer adoption, but not a reason
    # to label the external checkout unusable.  Revision/identity failures
    # remain hard blocked; dependency drift is hard only when the tree itself
    # is otherwise clean (a dirty submodule is already covered by the
    # auxiliary dirty-baseline verdict).
    full_build = lifecycle.get("full_build", {})
    graph_build_failed = isinstance(full_build, Mapping) and full_build.get("status") in {
        "error",
        "blocked",
    }
    hard_failure = (
        not all(
            adoption_gates[name]
            for name in (
                "target_available",
                "standalone_git",
                "pinned_revision",
                "working_tree_state_known",
            )
        )
        or graph_build_failed
        or lifecycle_errors
        or bool(gates.get("remote_mismatch"))
        or (
            bool(adoption_gates.get("clean_baseline"))
            and not bool(adoption_gates.get("dependencies_consistent"))
        )
        or (generated_data_applicable and not generated_data_ok)
    )
    if hard_failure:
        verdict = "blocked"
    elif all(adoption_gates.values()):
        verdict = "primary"
    else:
        verdict = "auxiliary"
    return {
        "verdict": verdict,
        "pass": verdict == "primary",
        "gates": adoption_gates,
        "semantic": {
            "available": sorted(available_tools),
            "execution": semantic_execution,
        },
    }


def _assemble_adoption_result(
    manifest_doc: Mapping[str, Any],
    manifest_path: Path | None,
    corpus_path: Path | None,
    manifest_target: Any,
    environment: Mapping[str, Any],
    gates: Mapping[str, Any],
    diagnostics: list[dict[str, Any]],
    available_tools: set[str],
    corpus_doc: Mapping[str, Any],
    case_results: Sequence[Mapping[str, Any]],
    lifecycle: Mapping[str, Mapping[str, Any]],
    timings: Mapping[str, Sequence[float]],
    store: GraphStore | None,
    root: Path,
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """Compute metrics, gates, and the validated public result envelope."""
    metrics = _aggregate_metrics(
        case_results,
        timings,
        corpus_doc,
        store,
        root,
        lifecycle=lifecycle,
        environment=environment,
    )
    result_adapter_policy = _compact_adapter_policy(environment, manifest_doc)
    result_generated_data = dict(
        environment.get("generated_data", {})
        if isinstance(environment.get("generated_data"), Mapping)
        else {}
    )
    generated_contract = manifest_doc.get("generated_data")
    if isinstance(generated_contract, Mapping):
        # Keep the expected values beside the observed markers so a result can
        # be validated independently of the source manifest path.
        result_generated_data["expected"] = {
            key: generated_contract.get(key)
            for key in ("revision", "config_version", "paths")
        }
    adoption_environment = dict(environment)
    adoption_environment["adapter_policy"] = result_adapter_policy
    adoption_environment["generated_data"] = result_generated_data
    adoption_environment["generated_data_contract"] = generated_contract
    (
        generated_data_ok,
        generated_data_applicable,
        generated_data_reason,
    ) = _generated_data_consistency(adoption_environment, corpus_doc)
    if generated_data_applicable and not generated_data_ok:
        diagnostics.append(
            _diagnostic(
                "generated_data_gate_failed",
                "error",
                "Generated-data markers are unavailable or do not match the manifest contract.",
                reason=generated_data_reason,
            )
        )
    observed_codes = {
        str(item.get("code"))
        for item in diagnostics
        if isinstance(item, Mapping) and isinstance(item.get("code"), str)
    }
    adoption = _adoption_gates(
        gates,
        adoption_environment,
        case_results,
        lifecycle,
        metrics,
        corpus_doc,
        observed_codes,
    )
    # A dirty exploratory run is always auxiliary, even when an explicit
    # override allowed the temporary graph to be built.
    if not gates.get("clean_baseline") and adoption["verdict"] == "primary":
        adoption = {**adoption, "verdict": "auxiliary", "pass": False}
    corpus_contract = _build_corpus_contract(corpus_doc, root, store)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "run": {
            "mode": "dry_run" if dry_run else "adoption",
            "read_only_target": True,
            "manifest": str(manifest_path) if manifest_path else None,
            "corpus": str(corpus_path) if corpus_path else None,
        },
        "target": {
            "name": manifest_target.get("name") if isinstance(manifest_target, Mapping) else None,
            "path": str(root),
            "expected_remote": manifest_target.get("remote")
            if isinstance(manifest_target, Mapping)
            else None,
            "requested_revision": manifest_doc.get("revision", {}).get("requested")
            if isinstance(manifest_doc.get("revision"), Mapping)
            else None,
            "observed_revision": environment.get("repository", {}).get("revision")
            if isinstance(environment.get("repository"), Mapping)
            else None,
            "working_tree_clean": environment.get("repository", {}).get("working_tree_clean")
            if isinstance(environment.get("repository"), Mapping)
            else None,
        },
        "environment": {
            "repository": environment.get("repository", {}),
            "toolchain": environment.get("toolchain", {}),
            "generated_data": result_generated_data,
            "available_semantic_tools": sorted(available_tools),
            "cache": environment.get("cache", {}),
            # Preserve the policy inputs used to decide which semantic
            # adapters are required.  Without this compact evidence a report
            # validator would have to trust ``adoption.semantic.execution``
            # supplied by the producer.
            "adapter_policy": result_adapter_policy,
            "diagnostics_contract": _diagnostics_contract(corpus_doc),
        },
        "gates": gates,
        "cases": list(case_results),
        "lifecycle": lifecycle,
        "metrics": metrics,
        "adoption": adoption,
        "diagnostics": diagnostics,
        "corpus_contract": corpus_contract,
    }
    result["status"] = (
        "blocked" if adoption["verdict"] == "blocked" else "ok" if adoption["pass"] else "auxiliary"
    )
    validate_evaluation_result(result)
    return result


def _validate_contract_binding(binding: Any, field: str) -> None:
    if not isinstance(binding, Mapping):
        raise ValueError(f"{field}: expected object")
    aliases = binding.get("aliases")
    qualified_aliases = binding.get("qualified_aliases")
    if not isinstance(aliases, list) or any(
        not isinstance(value, str) or not value for value in aliases
    ):
        raise ValueError(f"{field}.aliases: expected string array")
    if len(set(aliases)) != len(aliases):
        raise ValueError(f"{field}.aliases: duplicate alias")
    if not isinstance(qualified_aliases, list) or any(
        not isinstance(value, str) or "::" not in value for value in qualified_aliases
    ):
        raise ValueError(f"{field}.qualified_aliases: expected qualified string array")
    if not set(qualified_aliases).issubset(set(aliases)):
        raise ValueError(f"{field}.qualified_aliases: not a subset of aliases")
    for key in ("file", "symbol", "module", "dynamic", "literal"):
        value = binding.get(key)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{field}.{key}: expected string or null")
    arity = binding.get("arity")
    if arity is not None and _parse_erlang_arity(arity) != arity:
        raise ValueError(f"{field}.arity: expected bounded integer or null")
    mfa = binding.get("mfa")
    if mfa is not None:
        if not isinstance(mfa, list) or len(mfa) != 3:
            raise ValueError(f"{field}.mfa: expected module/function/arity array or null")
        if any(not isinstance(value, str) for value in mfa[:2]) or (
            _parse_erlang_arity(mfa[2]) != mfa[2]
        ):
            raise ValueError(f"{field}.mfa: malformed MFA")


def _validate_corpus_contract(
    contract: Any,
    result_cases: Sequence[Mapping[str, Any]],
    root: Path,
    corpus: Mapping[str, Any] | None = None,
) -> list[Mapping[str, Any]]:
    """Validate and return immutable expected relation records from a result."""
    if not isinstance(contract, Mapping):
        raise ValueError("result.corpus_contract: expected object")
    if contract.get("version") != _CORPUS_CONTRACT_VERSION:
        raise ValueError("result.corpus_contract.version: unsupported version")
    contract_cases = contract.get("cases")
    if not isinstance(contract_cases, list):
        raise ValueError("result.corpus_contract.cases: expected array")
    digest = contract.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("result.corpus_contract.digest: expected lowercase SHA-256")
    expected_digest = hashlib.sha256(
        _canonical_json(_contract_source_payload(contract)).encode("utf-8")
    ).hexdigest()
    if digest != expected_digest:
        raise ValueError("result.corpus_contract.digest: inconsistent with cases")
    if len(contract_cases) != len(result_cases):
        raise ValueError("result.corpus_contract.cases: inconsistent with result.cases")
    ids: set[str] = set()
    normalized_cases: list[Mapping[str, Any]] = []
    for index, contract_case in enumerate(contract_cases):
        if not isinstance(contract_case, Mapping):
            raise ValueError(f"result.corpus_contract.cases[{index}]: expected object")
        case_id = contract_case.get("id")
        category = contract_case.get("category")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"result.corpus_contract.cases[{index}].id: expected non-empty string")
        if case_id in ids:
            raise ValueError(f"result.corpus_contract.cases[{index}].id: duplicate case id")
        ids.add(case_id)
        if not isinstance(category, str) or not category:
            raise ValueError(
                f"result.corpus_contract.cases[{index}].category: expected non-empty string"
            )
        result_case = result_cases[index]
        if result_case.get("id") != case_id or result_case.get("category") != category:
            raise ValueError(
                f"result.corpus_contract.cases[{index}]: id/category inconsistent with result.cases"
            )
        expected = contract_case.get("expected")
        if not isinstance(expected, Mapping):
            raise ValueError(f"result.corpus_contract.cases[{index}].expected: expected object")
        for relation_kind in ("positive", "negative", "unresolved"):
            relations = expected.get(relation_kind)
            if not isinstance(relations, list):
                raise ValueError(
                    f"result.corpus_contract.cases[{index}].expected."
                    f"{relation_kind}: expected array"
                )
            for relation_index, relation in enumerate(relations):
                field = (
                    f"result.corpus_contract.cases[{index}].expected."
                    f"{relation_kind}[{relation_index}]"
                )
                if not isinstance(relation, Mapping):
                    raise ValueError(f"{field}: expected object")
                if not isinstance(relation.get("relation"), str) or not relation.get("relation"):
                    raise ValueError(f"{field}.relation: expected non-empty string")
                matching = relation.get("matching")
                if not isinstance(matching, Mapping):
                    raise ValueError(f"{field}.matching: expected object")
                if "target" not in matching:
                    raise ValueError(f"{field}.matching.target: missing field")
                _validate_contract_binding(matching.get("target"), f"{field}.matching.target")
                if "source" in relation:
                    if "source" not in matching:
                        raise ValueError(f"{field}.matching.source: missing field")
                    _validate_contract_binding(matching.get("source"), f"{field}.matching.source")
        allow_empty = contract_case.get("allow_empty")
        if not isinstance(allow_empty, bool):
            raise ValueError(f"result.corpus_contract.cases[{index}].allow_empty: expected boolean")
        normalized_cases.append(contract_case)

    # When the source corpus is available, compare its canonical source payload
    # as well as the checksum.  This gives callers an authoritative binding
    # instead of trusting a report that edited both contract fields and digest.
    if corpus is not None:
        source_contract = _build_corpus_contract(corpus, root, None)
        if _contract_source_payload(source_contract) != _contract_source_payload(contract):
            raise ValueError("result.corpus_contract: does not match source corpus")
    return normalized_cases


def validate_evaluation_result(
    result: Mapping[str, Any],
    corpus: str | Path | Mapping[str, Any] | None = None,
) -> None:
    """Validate the no-fabrication invariants of an adoption result."""
    if not isinstance(result, Mapping):
        raise ValueError("result: expected object")
    missing = _REQUIRED_RESULT_KEYS - set(result)
    if missing:
        raise ValueError(f"result: missing keys: {', '.join(sorted(missing))}")
    if result.get("kind") != RESULT_KIND:
        raise ValueError(f"result.kind: expected {RESULT_KIND!r}")
    if result.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("result.schema_version: unsupported schema version")
    status = result.get("status")
    if status not in {"ok", "auxiliary", "blocked"}:
        raise ValueError("result.status: unsupported value")

    run = result.get("run")
    if not isinstance(run, Mapping):
        raise ValueError("result.run: expected object")
    if run.get("mode") not in {"adoption", "dry_run"}:
        raise ValueError("result.run.mode: unsupported value")
    if run.get("read_only_target") is not True:
        raise ValueError("result.run.read_only_target: must be true")
    for key in ("manifest", "corpus"):
        if run.get(key) is not None and not isinstance(run.get(key), str):
            raise ValueError(f"result.run.{key}: expected string or null")

    target = result.get("target")
    if not isinstance(target, Mapping):
        raise ValueError("result.target: expected object")
    if not isinstance(target.get("name"), str) or not target.get("name"):
        raise ValueError("result.target.name: expected non-empty string")
    if not isinstance(target.get("path"), str) or not target.get("path"):
        raise ValueError("result.target.path: expected non-empty string")
    for key in ("requested_revision", "observed_revision", "expected_remote"):
        if target.get(key) is not None and not isinstance(target.get(key), str):
            raise ValueError(f"result.target.{key}: expected string or null")
    if target.get("working_tree_clean") is not None and not isinstance(
        target.get("working_tree_clean"), bool
    ):
        raise ValueError("result.target.working_tree_clean: expected boolean or null")
    target_record = target

    environment = result.get("environment")
    if not isinstance(environment, Mapping):
        raise ValueError("result.environment: expected object")
    for key in (
        "repository",
        "toolchain",
        "generated_data",
        "cache",
        "adapter_policy",
        "diagnostics_contract",
    ):
        if not isinstance(environment.get(key), Mapping):
            raise ValueError(f"result.environment.{key}: expected object")
    repository = environment["repository"]
    recomputed_repository = _validate_repository_observation(target, repository)
    toolchain = environment["toolchain"]
    toolchain_tools = toolchain.get("tools")
    if not isinstance(toolchain_tools, Mapping):
        raise ValueError("result.environment.toolchain.tools: expected object")
    if not toolchain_tools:
        raise ValueError("result.environment.toolchain.tools: must not be empty")
    for name, tool in toolchain_tools.items():
        if not isinstance(name, str) or not name:
            raise ValueError("result.environment.toolchain.tools: invalid tool name")
        if not isinstance(tool, Mapping):
            raise ValueError(
                f"result.environment.toolchain.tools.{name}: expected object"
            )
        tool_status = tool.get("status")
        if not isinstance(tool_status, str) or not tool_status:
            raise ValueError(
                f"result.environment.toolchain.tools.{name}.status: expected string"
            )
        if tool_status not in TOOL_STATUSES:
            raise ValueError(
                f"result.environment.toolchain.tools.{name}.status: unsupported value"
            )
    if "remote" in repository and repository.get("remote") is not None and not isinstance(
        repository.get("remote"), str
    ):
        raise ValueError("result.environment.repository.remote: expected string or null")
    available_tools = environment.get("available_semantic_tools")
    if not isinstance(available_tools, list) or any(
        not isinstance(item, str) for item in available_tools
    ):
        raise ValueError("result.environment.available_semantic_tools: expected string array")
    if len(set(available_tools)) != len(available_tools):
        raise ValueError("result.environment.available_semantic_tools: duplicate tool")
    expected_available_tools = _available_semantic_tools(environment)
    if set(available_tools) != expected_available_tools:
        raise ValueError(
            "result.environment.available_semantic_tools: inconsistent with toolchain"
        )

    generated_data = environment["generated_data"]
    generated_expected = generated_data.get("expected")
    if not isinstance(generated_expected, Mapping):
        raise ValueError("result.environment.generated_data.expected: expected object")
    for field in ("revision", "config_version"):
        value = generated_expected.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"result.environment.generated_data.expected.{field}: expected string")
    expected_paths = generated_expected.get("paths")
    if not isinstance(expected_paths, list) or any(
        not isinstance(item, str) or not item for item in expected_paths
    ):
        raise ValueError("result.environment.generated_data.expected.paths: expected string array")
    for field in ("revision", "config_version"):
        value = generated_data.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError(f"result.environment.generated_data.{field}: expected string or null")
    marker_files = generated_data.get("marker_files")
    if not isinstance(marker_files, Mapping) or any(
        not isinstance(marker_files.get(marker), bool) for marker in _GENERATED_DATA_MARKERS
    ):
        raise ValueError("result.environment.generated_data.marker_files: invalid marker map")
    counts = generated_data.get("counts")
    if not isinstance(counts, Mapping):
        raise ValueError("result.environment.generated_data.counts: expected object")
    for path, count in counts.items():
        if not isinstance(path, str) or not path:
            raise ValueError("result.environment.generated_data.counts: invalid path")
        if count is not None and (
            isinstance(count, bool) or not isinstance(count, int) or count < 0
        ):
            raise ValueError(f"result.environment.generated_data.counts.{path}: invalid count")

    adapter_policy = environment["adapter_policy"]
    policy_names = adapter_policy.get("manifests")
    if isinstance(policy_names, Mapping):
        policy_names = list(policy_names)
    if not isinstance(policy_names, list) or any(
        not isinstance(item, str) or not item for item in policy_names
    ):
        raise ValueError("result.environment.adapter_policy.manifests: expected string array")
    if len({item.casefold() for item in policy_names}) != len(policy_names):
        raise ValueError("result.environment.adapter_policy.manifests: duplicate adapter")
    manifest_activation = adapter_policy.get("manifest_activation", {})
    if not isinstance(manifest_activation, Mapping):
        raise ValueError("result.environment.adapter_policy.manifest_activation: expected object")
    policy_name_set = {item.casefold() for item in policy_names}
    for name, activation in manifest_activation.items():
        if not isinstance(name, str) or not name:
            raise ValueError("result.environment.adapter_policy.manifest_activation: invalid name")
        if name.casefold() not in policy_name_set:
            raise ValueError(
                "result.environment.adapter_policy.manifest_activation: unknown adapter"
            )
        if not isinstance(activation, Mapping):
            raise ValueError(
                f"result.environment.adapter_policy.manifest_activation.{name}: expected object"
            )
        if not isinstance(activation.get("mode"), str) or not activation.get("mode"):
            raise ValueError(
                f"result.environment.adapter_policy.manifest_activation.{name}.mode: "
                "expected non-empty string"
            )
        if not isinstance(activation.get("required"), bool):
            raise ValueError(
                f"result.environment.adapter_policy.manifest_activation.{name}.required: "
                "expected boolean"
            )
    diagnostics_contract = environment["diagnostics_contract"]
    required_diagnostic_spec = diagnostics_contract.get("required")
    if (
        required_diagnostic_spec is not None
        and required_diagnostic_spec is not True
        and not isinstance(required_diagnostic_spec, list)
    ):
        raise ValueError(
            "result.environment.diagnostics_contract.required: "
            "expected true, array, or null"
        )
    if isinstance(required_diagnostic_spec, list) and any(
        not isinstance(item, str) or not item for item in required_diagnostic_spec
    ):
        raise ValueError("result.environment.diagnostics_contract.required: expected string array")

    gates = result.get("gates")
    if not isinstance(gates, Mapping):
        raise ValueError("result.gates: expected object")
    for key in (
        "target_exists",
        "standalone_git",
        "pinned_revision",
        "clean_baseline",
        "working_tree_state_known",
        "dependencies_consistent",
        "dirty_override",
    ):
        if not isinstance(gates.get(key), bool):
            raise ValueError(f"result.gates.{key}: expected boolean")
    for key in ("remote_identity", "remote_mismatch"):
        if not isinstance(gates.get(key), bool):
            raise ValueError(f"result.gates.{key}: expected boolean")

    # Remote identity is a raw observation, not a free-form verdict input.
    # Recompute the mismatch flag from the expected manifest remote and the
    # observed repository remote so a report cannot turn an auxiliary result
    # into an apparently verified one (or vice versa) by editing one boolean.
    expected_remote = target.get("expected_remote")
    observed_remote = repository.get("remote")
    if isinstance(expected_remote, str) and expected_remote:
        expected_remote_identity = isinstance(observed_remote, str) and (
            observed_remote == expected_remote
        )
        expected_remote_mismatch = observed_remote is not None and not expected_remote_identity
    else:
        expected_remote_identity = True
        expected_remote_mismatch = False
    if gates["remote_identity"] != expected_remote_identity:
        raise ValueError("result.gates.remote_identity: inconsistent with repository identity")
    if gates["remote_mismatch"] != expected_remote_mismatch:
        raise ValueError("result.gates.remote_mismatch: inconsistent with repository identity")

    metrics = result.get("metrics")
    if not isinstance(metrics, Mapping):
        raise ValueError("result.metrics: expected object")
    missing_metrics = _REQUIRED_METRIC_KEYS - set(metrics)
    if missing_metrics:
        raise ValueError(f"result.metrics: missing keys: {', '.join(sorted(missing_metrics))}")
    metric_status = metrics.get("status")
    if metric_status not in {"executed", "not_run", "blocked", "error"}:
        raise ValueError("result.metrics.status: unsupported value")
    count_fields = ("cases_scored", "forbidden_matches")
    for key in count_fields:
        value = metrics.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"result.metrics.{key}: expected non-negative integer")

    def check_ratio(value: Any, field: str) -> None:
        if value is None:
            return
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"result.{field}: expected number or null")
        if not math.isfinite(float(value)) or not 0 <= float(value) <= 1:
            raise ValueError(f"result.{field}: expected finite number in [0, 1]")

    for key in ("precision", "recall"):
        check_ratio(metrics.get(key), f"metrics.{key}")
    if metric_status == "not_run" and any(
        metrics.get(key) is not None for key in ("precision", "recall")
    ):
        raise ValueError("result.metrics: not_run metrics must be null")
    recall_at_10 = metrics.get("recall_at_10")
    if not isinstance(recall_at_10, Mapping):
        raise ValueError("result.metrics.recall_at_10: expected object")
    for key in ("function", "module"):
        if key not in recall_at_10:
            raise ValueError(f"result.metrics.recall_at_10: missing {key}")
        check_ratio(recall_at_10.get(key), f"metrics.recall_at_10.{key}")
    latency = metrics.get("latency")
    if not isinstance(latency, Mapping):
        raise ValueError("result.metrics.latency: expected object")
    impact = metrics.get("impact")
    if not isinstance(impact, Mapping):
        raise ValueError("result.metrics.impact: expected object")

    def check_count(value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"result.{field}: expected non-negative integer")
        return value

    def check_string_list(value: Any, field: str) -> list[str]:
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ValueError(f"result.{field}: expected non-empty string array")
        return value

    def check_nonnegative_number(value: Any, field: str, *, nullable: bool = True) -> None:
        if value is None and nullable:
            return
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"result.{field}: expected finite non-negative number")
        if not math.isfinite(float(value)) or float(value) < 0:
            raise ValueError(f"result.{field}: expected finite non-negative number")

    # Latency is a measured surface, so reject NaN/inf, negative values, and
    # internally contradictory sample summaries before they can influence a
    # budget gate.
    latency_status = latency.get("status")
    if latency_status not in {"executed", "not_run", "blocked", "error"}:
        raise ValueError("result.metrics.latency.status: unsupported value")
    latency_samples = check_count(latency.get("samples"), "metrics.latency.samples")
    latency_invalid = check_count(
        latency.get("invalid_samples"), "metrics.latency.invalid_samples"
    )
    check_nonnegative_number(latency.get("p50_ms"), "metrics.latency.p50_ms")
    check_nonnegative_number(latency.get("p95_ms"), "metrics.latency.p95_ms")
    if (
        latency.get("p50_ms") is not None
        and latency.get("p95_ms") is not None
        and float(latency["p50_ms"]) > float(latency["p95_ms"])
    ):
        raise ValueError("result.metrics.latency: p50_ms must not exceed p95_ms")
    by_operation = latency.get("by_operation")
    if not isinstance(by_operation, Mapping):
        raise ValueError("result.metrics.latency.by_operation: expected object")
    operation_samples = 0
    operation_invalid = 0
    for operation, summary in by_operation.items():
        if not isinstance(operation, str) or not operation:
            raise ValueError("result.metrics.latency.by_operation: invalid operation name")
        if not isinstance(summary, Mapping):
            raise ValueError(f"result.metrics.latency.by_operation.{operation}: expected object")
        operation_samples += check_count(
            summary.get("samples"), f"metrics.latency.by_operation.{operation}.samples"
        )
        operation_invalid += check_count(
            summary.get("invalid_samples"),
            f"metrics.latency.by_operation.{operation}.invalid_samples",
        )
        check_nonnegative_number(
            summary.get("p50_ms"), f"metrics.latency.by_operation.{operation}.p50_ms"
        )
        check_nonnegative_number(
            summary.get("p95_ms"), f"metrics.latency.by_operation.{operation}.p95_ms"
        )
        if (
            summary.get("p50_ms") is not None
            and summary.get("p95_ms") is not None
            and float(summary["p50_ms"]) > float(summary["p95_ms"])
        ):
            raise ValueError(
                f"result.metrics.latency.by_operation.{operation}: "
                "p50_ms must not exceed p95_ms"
            )
    if operation_samples != latency_samples or operation_invalid != latency_invalid:
        raise ValueError("result.metrics.latency: sample totals are inconsistent")
    if latency_status == "executed" and (
        latency_samples == 0 or latency.get("p50_ms") is None or latency.get("p95_ms") is None
    ):
        raise ValueError("result.metrics.latency: executed metrics require measured samples")
    if latency_status == "not_run" and (
        latency_samples != 0
        or latency.get("p50_ms") is not None
        or latency.get("p95_ms") is not None
    ):
        raise ValueError("result.metrics.latency: not_run metrics must be empty")

    impact_status = impact.get("status")
    if impact_status not in {"executed", "not_run", "blocked", "error"}:
        raise ValueError("result.metrics.impact.status: unsupported value")
    check_ratio(impact.get("coverage"), "metrics.impact.coverage")
    if impact_status == "executed":
        for key in ("expected", "predicted", "covered", "entries"):
            if not isinstance(impact.get(key), list):
                raise ValueError(f"result.metrics.impact.{key}: expected array")
        impact_expected = check_string_list(impact["expected"], "metrics.impact.expected")
        impact_predicted = check_string_list(impact["predicted"], "metrics.impact.predicted")
        impact_covered = check_string_list(impact["covered"], "metrics.impact.covered")
        impact_entries = impact["entries"]
        if not impact_entries:
            raise ValueError("result.metrics.impact.entries: executed metrics require entries")
        if not set(impact_covered).issubset(set(impact_expected)) or not set(
            impact_covered
        ).issubset(set(impact_predicted)):
            raise ValueError("result.metrics.impact.covered: not a subset of expected/predicted")
        if not impact_expected or impact.get("coverage") is None:
            raise ValueError("result.metrics.impact: executed metrics require expected entries")
        if not math.isclose(
            float(impact["coverage"]), len(set(impact_covered)) / len(set(impact_expected))
        ):
            raise ValueError("result.metrics.impact.coverage: inconsistent with covered entries")
        if not isinstance(impact.get("all_entries_covered"), bool):
            raise ValueError("result.metrics.impact.all_entries_covered: expected boolean")
        if not isinstance(impact.get("false_positive_allowed"), bool):
            raise ValueError("result.metrics.impact.false_positive_allowed: expected boolean")
        check_count(
            impact.get("false_positive_count"), "metrics.impact.false_positive_count"
        )
        check_count(
            impact.get("disallowed_false_positive_count"),
            "metrics.impact.disallowed_false_positive_count",
        )
        entry_false_positive = 0
        entry_disallowed = 0
        entry_allowed = False
        entry_expected_union: set[str] = set()
        entry_predicted_union: set[str] = set()
        entry_covered_union: set[str] = set()
        for index, entry in enumerate(impact_entries):
            if not isinstance(entry, Mapping):
                raise ValueError(f"result.metrics.impact.entries[{index}]: expected object")
            entry_expected = check_string_list(
                entry.get("expected"), f"metrics.impact.entries[{index}].expected"
            )
            entry_predicted = check_string_list(
                entry.get("predicted"), f"metrics.impact.entries[{index}].predicted"
            )
            entry_covered = check_string_list(
                entry.get("covered"), f"metrics.impact.entries[{index}].covered"
            )
            entry_expected_set = set(entry_expected)
            entry_predicted_set = set(entry_predicted)
            entry_covered_set = set(entry_covered)
            if not entry_covered_set.issubset(entry_expected_set) or not entry_covered_set.issubset(
                entry_predicted_set
            ):
                raise ValueError(
                    f"result.metrics.impact.entries[{index}].covered: "
                    "not a subset of expected/predicted"
                )
            entry_coverage = (
                len(entry_covered_set) / len(entry_expected_set)
                if entry_expected_set
                else None
            )
            reported_entry_coverage = entry.get("coverage")
            check_ratio(
                reported_entry_coverage,
                f"metrics.impact.entries[{index}].coverage",
            )
            if entry_coverage is None:
                if reported_entry_coverage is not None:
                    raise ValueError(
                        f"result.metrics.impact.entries[{index}].coverage: "
                        "empty expected set must have null coverage"
                    )
            elif reported_entry_coverage is None or not math.isclose(
                float(reported_entry_coverage), entry_coverage
            ):
                raise ValueError(
                    f"result.metrics.impact.entries[{index}].coverage: "
                    "inconsistent with covered entries"
                )
            entry_false_positive_value = check_count(
                entry.get("false_positive_count"),
                f"metrics.impact.entries[{index}].false_positive_count",
            )
            if not isinstance(entry.get("false_positive_allowed"), bool):
                raise ValueError(
                    f"result.metrics.impact.entries[{index}].false_positive_allowed: "
                    "expected boolean"
                )
            expected_entry_false_positive = len(entry_predicted_set - entry_expected_set)
            if entry_false_positive_value != expected_entry_false_positive:
                raise ValueError(
                    f"result.metrics.impact.entries[{index}].false_positive_count: "
                    "inconsistent with expected/predicted"
                )
            entry_false_positive += entry_false_positive_value
            if not entry["false_positive_allowed"]:
                entry_disallowed += entry_false_positive_value
            entry_allowed = entry_allowed or entry["false_positive_allowed"]
            entry_expected_union.update(entry_expected_set)
            entry_predicted_union.update(entry_predicted_set)
            entry_covered_union.update(entry_covered_set)
        if entry_expected_union != set(impact_expected):
            raise ValueError(
                "result.metrics.impact.expected: inconsistent with entries"
            )
        if entry_predicted_union != set(impact_predicted):
            raise ValueError(
                "result.metrics.impact.predicted: inconsistent with entries"
            )
        if entry_covered_union != set(impact_covered):
            raise ValueError(
                "result.metrics.impact.covered: inconsistent with entries"
            )
        expected_impact_coverage = len(entry_covered_union) / len(entry_expected_union)
        if impact.get("coverage") is None or not math.isclose(
            float(impact["coverage"]), expected_impact_coverage
        ):
            raise ValueError(
                "result.metrics.impact.coverage: inconsistent with entries"
            )
        if entry_false_positive != int(impact["false_positive_count"]):
            raise ValueError(
                "result.metrics.impact.false_positive_count: inconsistent with entries"
            )
        if entry_disallowed != int(impact["disallowed_false_positive_count"]):
            raise ValueError(
                "result.metrics.impact.disallowed_false_positive_count: inconsistent with entries"
            )
        if entry_allowed != impact["false_positive_allowed"]:
            raise ValueError(
                "result.metrics.impact.false_positive_allowed: inconsistent with entries"
            )
        expected_all_covered = all(
            entry.get("coverage") == 1.0 for entry in impact_entries
        )
        if expected_all_covered != impact["all_entries_covered"]:
            raise ValueError("result.metrics.impact.all_entries_covered: inconsistent with entries")
    elif impact_status == "not_run":
        if impact.get("coverage") is not None:
            raise ValueError("result.metrics.impact: not_run coverage must be null")

    adoption = result.get("adoption")
    if not isinstance(adoption, Mapping):
        raise ValueError("result.adoption: expected object")
    verdict = adoption.get("verdict")
    if verdict not in {"primary", "auxiliary", "blocked"}:
        raise ValueError("result.adoption.verdict: unsupported value")
    if not isinstance(adoption.get("pass"), bool):
        raise ValueError("result.adoption.pass: expected boolean")
    if adoption["pass"] != (verdict == "primary"):
        raise ValueError("result.adoption.pass: inconsistent with verdict")
    adoption_gates = adoption.get("gates")
    if not isinstance(adoption_gates, Mapping):
        raise ValueError("result.adoption.gates: expected object")
    missing_adoption_gates = _REQUIRED_ADOPTION_GATES - set(adoption_gates)
    if missing_adoption_gates:
        raise ValueError(
            "result.adoption.gates: missing keys: " + ", ".join(sorted(missing_adoption_gates))
        )
    if any(not isinstance(adoption_gates.get(key), bool) for key in _REQUIRED_ADOPTION_GATES):
        raise ValueError("result.adoption.gates: all required values must be boolean")
    semantic = adoption.get("semantic")
    if not isinstance(semantic, Mapping):
        raise ValueError("result.adoption.semantic: expected object")
    if not isinstance(semantic.get("available"), list) or any(
        not isinstance(item, str) for item in semantic.get("available", [])
    ):
        raise ValueError("result.adoption.semantic.available: expected string array")
    if not isinstance(semantic.get("execution"), Mapping):
        raise ValueError("result.adoption.semantic.execution: expected object")
    semantic_available = semantic["available"]
    if len(set(semantic_available)) != len(semantic_available):
        raise ValueError("result.adoption.semantic.available: duplicate tool")
    if set(semantic_available) != set(available_tools):
        raise ValueError(
            "result.adoption.semantic.available: inconsistent with "
            "environment.available_semantic_tools"
        )
    execution = semantic["execution"]
    if execution.get("status") not in {"executed", "not_run"}:
        raise ValueError("result.adoption.semantic.execution.status: unsupported value")
    if not isinstance(execution.get("valid"), bool):
        raise ValueError("result.adoption.semantic.execution.valid: expected boolean")
    if execution["valid"] != (execution["status"] == "executed"):
        raise ValueError("result.adoption.semantic.execution: status/valid mismatch")
    for key in ("required", "observed"):
        check_string_list(execution.get(key), f"adoption.semantic.execution.{key}")
        values = execution[key]
        if len(set(values)) != len(values):
            raise ValueError(f"result.adoption.semantic.execution.{key}: duplicate adapter")
    statuses = execution.get("statuses")
    if not isinstance(statuses, Mapping) or any(
        not isinstance(name, str) or not name or not isinstance(value, str) or not value
        for name, value in statuses.items()
    ):
        raise ValueError("result.adoption.semantic.execution.statuses: expected string map")
    check_count(execution.get("envelopes"), "adoption.semantic.execution.envelopes")
    if not isinstance(execution.get("policy_enforced"), bool):
        raise ValueError("result.adoption.semantic.execution.policy_enforced: expected boolean")
    if execution["valid"] and execution["envelopes"] == 0:
        raise ValueError("result.adoption.semantic.execution: executed state needs an envelope")
    if execution.get("reason") is not None and not isinstance(execution.get("reason"), str):
        raise ValueError("result.adoption.semantic.execution.reason: expected string or null")

    cases = result.get("cases")
    if not isinstance(cases, list):
        raise ValueError("result.cases: expected array")
    case_ids: set[str] = set()
    for case_index, item in enumerate(cases):
        if not isinstance(item, Mapping):
            raise ValueError("result.cases[]: expected object")
        if item.get("status") not in _KNOWN_CASE_STATUSES:
            raise ValueError("result.cases.status: unsupported value")
        if not isinstance(item.get("id"), str) or not item.get("id"):
            raise ValueError("result.cases.id: expected non-empty string")
        if item["id"] in case_ids:
            raise ValueError("result.cases.id: duplicate case id")
        case_ids.add(item["id"])
        if not isinstance(item.get("category"), str) or not item.get("category"):
            raise ValueError("result.cases.category: expected non-empty string")
        if not isinstance(item.get("predictions"), list):
            raise ValueError("result.cases.predictions: expected array")
        for prediction_index, prediction in enumerate(item["predictions"]):
            if not isinstance(prediction, Mapping):
                raise ValueError(
                    f"result.cases[{case_index}].predictions[{prediction_index}]: expected object"
                )
            for key in ("relation", "source", "target", "source_file", "confidence_tier"):
                if not isinstance(prediction.get(key), str) or not prediction.get(key):
                    raise ValueError(
                        f"result.cases[{case_index}].predictions[{prediction_index}].{key}: "
                        "expected non-empty string"
                    )
            target_file = prediction.get("target_file")
            if target_file is not None and (
                not isinstance(target_file, str) or not target_file
            ):
                raise ValueError(
                    f"result.cases[{case_index}].predictions[{prediction_index}].target_file: "
                    "expected string or null"
                )
            check_count(
                prediction.get("line"),
                f"cases[{case_index}].predictions[{prediction_index}].line",
            )
            confidence = prediction.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise ValueError(
                    f"result.cases[{case_index}].predictions[{prediction_index}].confidence: "
                    "expected finite number in [0, 1]"
                )
            if not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
                raise ValueError(
                    f"result.cases[{case_index}].predictions[{prediction_index}].confidence: "
                    "expected finite number in [0, 1]"
                )
            if not isinstance(prediction.get("extra"), Mapping):
                raise ValueError(
                    f"result.cases[{case_index}].predictions[{prediction_index}].extra: "
                    "expected object"
                )
        for key in ("anchors", "missing_anchors", "required_diagnostics", "observed_diagnostics"):
            if key not in item:
                raise ValueError(f"result.cases[{case_index}].{key}: missing field")
            check_string_list(item[key], f"cases[{case_index}].{key}")
        if not set(item["missing_anchors"]).issubset(set(item["anchors"])):
            raise ValueError(f"cases[{case_index}].missing_anchors: not a subset of anchors")
        if not set(item["observed_diagnostics"]).issubset(
            set(item["required_diagnostics"])
        ):
            raise ValueError(
                f"cases[{case_index}].observed_diagnostics: not a subset of required_diagnostics"
            )
        for key in ("required_diagnostics_satisfied",):
            if key in item and not isinstance(item[key], bool):
                raise ValueError(f"cases[{case_index}].{key}: expected boolean")
        if "unresolved_expected_count" in item:
            check_count(
                item["unresolved_expected_count"],
                f"cases[{case_index}].unresolved_expected_count",
            )
        if "duration_seconds" in item:
            check_nonnegative_number(
                item["duration_seconds"], f"cases[{case_index}].duration_seconds"
            )
        if "reason" in item and not isinstance(item["reason"], str):
            raise ValueError(f"cases[{case_index}].reason: expected string")
        if item.get("status") == "executed":
            if not isinstance(item.get("measurement_complete"), bool):
                raise ValueError("result.cases.measurement_complete: expected boolean")
            for key in ("precision", "recall"):
                check_ratio(item.get(key), f"cases.{key}")
            count_keys = (
                "predicted_count",
                "unresolved_prediction_count",
                "expected_positive_count",
                "true_positive",
                "false_positive",
                "forbidden_matches",
                "ranked_true_positive",
                "unresolved_expected_count",
                "unresolved_observed_count",
                "resolved_unresolved_match_count",
            )
            counts = {
                key: check_count(item.get(key), f"cases[{case_index}].{key}")
                for key in count_keys
            }
            if counts["predicted_count"] + counts["unresolved_prediction_count"] != len(
                item["predictions"]
            ):
                raise ValueError(f"cases[{case_index}]: prediction counts are inconsistent")
            if counts["true_positive"] > counts["predicted_count"]:
                raise ValueError(f"cases[{case_index}].true_positive: exceeds predicted_count")
            if counts["false_positive"] != counts["predicted_count"] - counts["true_positive"]:
                raise ValueError(f"cases[{case_index}].false_positive: inconsistent count")
            if counts["ranked_true_positive"] > min(
                10, counts["predicted_count"], counts["expected_positive_count"]
            ):
                raise ValueError(
                    f"cases[{case_index}].ranked_true_positive: exceeds top-10 bounds"
                )
            if counts["ranked_true_positive"] > counts["true_positive"]:
                raise ValueError(
                    f"cases[{case_index}].ranked_true_positive: exceeds true_positive"
                )
            case_recall_at_10 = item.get("recall_at_10")
            check_ratio(case_recall_at_10, f"cases[{case_index}].recall_at_10")
            if counts["expected_positive_count"] and case_recall_at_10 is None:
                raise ValueError(
                    f"cases[{case_index}].recall_at_10: expected measured value"
                )
            if counts["expected_positive_count"] and case_recall_at_10 is not None:
                expected_case_recall_at_10 = (
                    counts["ranked_true_positive"] / counts["expected_positive_count"]
                )
                if not math.isclose(float(case_recall_at_10), expected_case_recall_at_10):
                    raise ValueError(
                        f"cases[{case_index}].recall_at_10: inconsistent ranked count"
                    )
            if counts["unresolved_observed_count"] > counts["unresolved_expected_count"]:
                raise ValueError(
                    f"cases[{case_index}].unresolved_observed_count: exceeds expected count"
                )
            if counts["predicted_count"] and item.get("precision") is not None:
                if not math.isclose(
                    float(item["precision"]),
                    counts["true_positive"] / counts["predicted_count"],
                ):
                    raise ValueError(f"cases[{case_index}].precision: inconsistent count")
            if counts["expected_positive_count"] and item.get("recall") is not None:
                if not math.isclose(
                    float(item["recall"]),
                    counts["true_positive"] / counts["expected_positive_count"],
                ):
                    raise ValueError(f"cases[{case_index}].recall: inconsistent count")
            if not isinstance(item.get("unresolved_satisfied"), (bool, type(None))):
                raise ValueError(
                    f"cases[{case_index}].unresolved_satisfied: expected boolean or null"
                )

    # Every new result is bound to the exact case/query/expected corpus that
    # produced it.  Prefer an explicitly supplied corpus; otherwise reopen the
    # recorded artifact when it is still available on disk.  Reports copied
    # without their source corpus remain verifiable through the embedded
    # contract digest and frozen matcher bindings.
    source_corpus: Mapping[str, Any] | None = None
    if corpus is not None:
        if isinstance(corpus, Mapping):
            validate_corpus(corpus)
            source_corpus = corpus
        else:
            source_corpus, _source_corpus_path = _load_corpus_artifact(corpus)
    elif isinstance(run.get("corpus"), str) and run.get("corpus"):
        source_path = Path(str(run["corpus"]))
        if source_path.is_file():
            source_corpus, _source_corpus_path = _load_corpus_artifact(source_path)

    contract_cases = _validate_corpus_contract(
        result.get("corpus_contract"), cases, _canonical_path(str(target["path"])), source_corpus
    )
    contract_root = _canonical_path(str(target["path"]))
    contract_derived_fields = (
        "predicted_count",
        "unresolved_prediction_count",
        "expected_positive_count",
        "true_positive",
        "false_positive",
        "forbidden_matches",
        "ranked_true_positive",
        "recall",
        "recall_at_10",
        "unresolved_expected_count",
        "unresolved_observed_count",
        "resolved_unresolved_match_count",
        "unresolved_satisfied",
        "measurement_complete",
    )
    for case_index, result_case in enumerate(cases):
        contract_case = contract_cases[case_index]
        expected_contract = contract_case.get("expected")
        if not isinstance(expected_contract, Mapping):
            raise ValueError(
                f"result.corpus_contract.cases[{case_index}].expected: expected object"
            )
        unresolved_contract = expected_contract.get("unresolved", [])
        expected_unresolved_count = (
            len(unresolved_contract) if isinstance(unresolved_contract, list) else 0
        )
        if result_case.get("unresolved_expected_count") != expected_unresolved_count:
            raise ValueError(
                f"cases[{case_index}].unresolved_expected_count: inconsistent with corpus contract"
            )
        if result_case.get("status") != "executed":
            continue
        scoring_case: dict[str, Any] = {
            "id": contract_case.get("id"),
            "expected": dict(expected_contract),
        }
        if contract_case.get("allow_empty") is True:
            scoring_case["expected"]["allow_empty"] = True
        predictions = result_case.get("predictions")
        if not isinstance(predictions, list):  # structural validation above should catch this
            raise ValueError(f"cases[{case_index}].predictions: expected array")
        rescored = score_case(
            scoring_case,
            predictions,
            root=contract_root,
            store=None,
            relation_matcher=lambda candidate, expected: _contract_relation_matches(
                candidate, expected, contract_root
            ),
            unresolved_relation_matcher=(
                lambda candidate, expected: _contract_unresolved_relation_matches(
                    candidate, expected, contract_root
                )
            ),
        )
        for field in contract_derived_fields:
            actual = result_case.get(field)
            expected_value = rescored.get(field)
            if isinstance(expected_value, float) or isinstance(actual, float):
                if expected_value is None or actual is None:
                    if expected_value is not actual:
                        raise ValueError(
                            f"cases[{case_index}].{field}: inconsistent with corpus contract"
                        )
                elif not math.isclose(float(actual), float(expected_value)):
                    raise ValueError(
                        f"cases[{case_index}].{field}: inconsistent with corpus contract"
                    )
            elif actual != expected_value:
                raise ValueError(
                    f"cases[{case_index}].{field}: inconsistent with corpus contract"
                )

    lifecycle = result.get("lifecycle")
    if not isinstance(lifecycle, Mapping):
        raise ValueError("result.lifecycle: expected object")
    if set(lifecycle) != set(_LIFECYCLE_PHASES):
        raise ValueError("result.lifecycle: all required phases must be present")
    for name, item in lifecycle.items():
        if not isinstance(item, Mapping):
            raise ValueError(f"result.lifecycle.{name}: expected object")
        if item.get("status") not in _KNOWN_LIFECYCLE_STATUSES:
            raise ValueError(f"result.lifecycle.{name}.status: unsupported value")
        duration = item.get("duration_seconds")
        if duration is not None and (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration))
            or float(duration) < 0
        ):
            raise ValueError(f"result.lifecycle.{name}.duration_seconds: invalid value")
        if not isinstance(item.get("parity"), bool):
            raise ValueError(f"result.lifecycle.{name}.parity: expected boolean")
        if "target_absent" in item and not isinstance(item.get("target_absent"), bool):
            raise ValueError(f"result.lifecycle.{name}.target_absent: expected boolean")
        if "reason" in item and not isinstance(item.get("reason"), str):
            raise ValueError(f"result.lifecycle.{name}.reason: expected string")
        phase_result = item.get("result")
        if phase_result is not None:
            if not isinstance(phase_result, Mapping):
                raise ValueError(f"result.lifecycle.{name}.result: expected object")
            try:
                _validate_lifecycle_payload_shape(phase_result, name)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"result.lifecycle.{name}.result: {exc}"
                ) from exc
        if item.get("status") == "executed":
            if not isinstance(phase_result, Mapping):
                raise ValueError(f"result.lifecycle.{name}.result: executed phase needs an object")

            # The nested runner envelope is an evidence boundary too.  A
            # producer must not mark the outer phase as executed while carrying
            # an inner failure/not-run status (or an unknown status string).
            payload_status = phase_result.get("status")
            if isinstance(payload_status, str):
                normalized_payload_status = payload_status.casefold()
                if normalized_payload_status in {
                    "error",
                    "failed",
                    "blocked",
                    "not_run",
                    "dry_run",
                }:
                    raise ValueError(
                        f"result.lifecycle.{name}.result.status: "
                        f"runner reported {normalized_payload_status!r}"
                    )
                if normalized_payload_status and normalized_payload_status not in {
                    "ok",
                    "executed",
                    "success",
                    "completed",
                }:
                    raise ValueError(
                        f"result.lifecycle.{name}.result.status: unsupported value"
                    )

            # Executed lifecycle records carry phase-specific evidence.  The
            # public parity bit must agree with that evidence; a report cannot
            # promote a forged ``parity: true`` by editing only the summary.
            evidence_parity = _lifecycle_parity_from_evidence(
                name,
                item,
                require_reported=False,
            )
            if item["parity"] != evidence_parity:
                raise ValueError(
                    f"result.lifecycle.{name}.parity: inconsistent with evidence"
                )

            if name == "incremental_update":
                if not isinstance(item.get("update_evidence"), bool):
                    raise ValueError(
                        "result.lifecycle.incremental_update.update_evidence: "
                        "expected boolean"
                    )
                for field in ("baseline_fingerprint", "observed_fingerprint"):
                    value = item.get(field)
                    if _valid_fingerprint(value) is None:
                        raise ValueError(
                            f"result.lifecycle.incremental_update.{field}: "
                            "invalid fingerprint"
                        )
                files_updated = phase_result.get("files_updated")
                changed_files = phase_result.get("changed_files")
                graph_changed = phase_result.get("graph_changed")
                expected_update_evidence = files_updated > 0
                if item["update_evidence"] != expected_update_evidence:
                    raise ValueError(
                        "result.lifecycle.incremental_update.update_evidence: "
                        "inconsistent with files_updated"
                    )
                if expected_update_evidence and (
                    not isinstance(changed_files, list)
                    or not changed_files
                    or graph_changed is not True
                ):
                    raise ValueError(
                        "result.lifecycle.incremental_update: positive update evidence "
                        "requires changed_files and graph_changed=true"
                    )
            elif name == "standalone_postprocess":
                for field in ("idempotence", "reference_match"):
                    if not isinstance(item.get(field), bool):
                        raise ValueError(
                            f"result.lifecycle.standalone_postprocess.{field}: "
                            "expected boolean"
                        )
                first = _valid_fingerprint(item.get("first_post_fingerprint"))
                observed = _valid_fingerprint(item.get("observed_fingerprint"))
                reference_value = item.get("reference_fingerprint")
                reference = _valid_fingerprint(reference_value)
                for field in ("first_post_fingerprint", "observed_fingerprint"):
                    value = item.get(field)
                    if _valid_fingerprint(value) is None:
                        raise ValueError(
                            f"result.lifecycle.standalone_postprocess.{field}: "
                            "invalid fingerprint"
                        )
                if reference_value is not None and reference is None:
                    raise ValueError(
                        "result.lifecycle.standalone_postprocess.reference_fingerprint: "
                        "invalid fingerprint"
                    )
                expected_idempotence = (
                    first is not None and observed is not None and first == observed
                )
                if item["idempotence"] != expected_idempotence:
                    raise ValueError(
                        "result.lifecycle.standalone_postprocess.idempotence: "
                        "inconsistent with fingerprints"
                    )
                expected_reference_match = (
                    reference is not None and observed is not None and observed == reference
                )
                if item["reference_match"] != expected_reference_match:
                    raise ValueError(
                        "result.lifecycle.standalone_postprocess.reference_match: "
                        "inconsistent with fingerprints"
                    )
            elif name == "watch":
                for field in ("activity_evidence", "reference_match"):
                    if not isinstance(item.get(field), bool):
                        raise ValueError(
                            f"result.lifecycle.watch.{field}: expected boolean"
                        )
                observed_value = item.get("observed_fingerprint")
                observed = _valid_fingerprint(observed_value)
                reference_value = item.get("reference_fingerprint")
                reference = _valid_fingerprint(reference_value)
                if observed is None:
                    raise ValueError(
                        "result.lifecycle.watch.observed_fingerprint: invalid fingerprint"
                    )
                if reference_value is not None and reference is None:
                    raise ValueError(
                        "result.lifecycle.watch.reference_fingerprint: invalid fingerprint"
                    )
                if item["activity_evidence"] != (
                    _watch_activity_evidence(phase_result)[0]
                ):
                    raise ValueError(
                        "result.lifecycle.watch.activity_evidence: inconsistent with result"
                    )
                expected_reference_match = (
                    reference is not None and observed is not None and observed == reference
                )
                if item["reference_match"] != expected_reference_match:
                    raise ValueError(
                        "result.lifecycle.watch.reference_match: inconsistent with fingerprints"
                    )
            elif name == "forget":
                target = item.get("forgotten")
                forgotten = phase_result.get("forgotten")
                if not isinstance(target, str) or not target:
                    raise ValueError(
                        "result.lifecycle.forget.forgotten: expected non-empty string"
                    )
                if not isinstance(forgotten, list) or target not in forgotten:
                    raise ValueError(
                        "result.lifecycle.forget.forgotten: inconsistent with result"
                    )
                if not isinstance(item.get("target_absent"), bool):
                    raise ValueError(
                        "result.lifecycle.forget.target_absent: expected boolean"
                    )
                for field in ("baseline_fingerprint", "observed_fingerprint"):
                    value = item.get(field)
                    if _valid_fingerprint(value) is None:
                        raise ValueError(
                            f"result.lifecycle.forget.{field}: invalid fingerprint"
                        )
        elif item["parity"] is not False:
            raise ValueError(
                f"result.lifecycle.{name}.parity: non-executed phase must be false"
            )

    _validate_latency_contract(latency, lifecycle, cases, environment)

    diagnostics = result.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise ValueError("result.diagnostics: expected array")
    for item in diagnostics:
        if not isinstance(item, Mapping):
            raise ValueError("result.diagnostics[]: expected object")
        if not isinstance(item.get("code"), str) or not item.get("code"):
            raise ValueError("result.diagnostics[].code: expected non-empty string")
        if item.get("severity") not in {"info", "warning", "error"}:
            raise ValueError("result.diagnostics[].severity: unsupported value")
        if not isinstance(item.get("message"), str) or not item.get("message"):
            raise ValueError("result.diagnostics[].message: expected non-empty string")
        if "details" in item and not isinstance(item.get("details"), Mapping):
            raise ValueError("result.diagnostics[].details: expected object")

    # Re-run the small, deterministic semantic-state reducer over the
    # lifecycle envelopes.  This checks the required adapter set against the
    # manifest activation policy and checks every reported status/count rather
    # than trusting the producer's summary object.
    expected_execution = _semantic_execution_state(environment, lifecycle)
    for key in ("status", "valid", "envelopes", "reason", "policy_enforced"):
        if execution.get(key) != expected_execution.get(key):
            raise ValueError(
                f"result.adoption.semantic.execution.{key}: inconsistent with lifecycle"
            )
    for key in ("required", "observed"):
        if execution.get(key) != expected_execution.get(key):
            raise ValueError(
                f"result.adoption.semantic.execution.{key}: inconsistent with adapter policy"
            )
    if execution.get("statuses") != expected_execution.get("statuses"):
        raise ValueError(
            "result.adoption.semantic.execution.statuses: inconsistent with lifecycle"
        )

    # Recompute every gate that is derivable from this result envelope.  This
    # prevents a producer (or a hand-edited report) from changing a metric or
    # lifecycle record while leaving a stale green gate behind.
    raw_to_adoption = {
        "target_available": "target_exists",
        "standalone_git": "standalone_git",
        "pinned_revision": "pinned_revision",
        "clean_baseline": "clean_baseline",
        "working_tree_state_known": "working_tree_state_known",
        "remote_identity": "remote_identity",
        "dependencies_consistent": "dependencies_consistent",
    }
    for adoption_name, raw_name in raw_to_adoption.items():
        if adoption_gates[adoption_name] != gates[raw_name]:
            raise ValueError(
                f"result.adoption.gates.{adoption_name}: inconsistent with result.gates.{raw_name}"
            )
    requested_revision = target_record.get("requested_revision")
    observed_revision = repository.get("revision")
    expected_pinned_revision = (
        isinstance(requested_revision, str)
        and bool(requested_revision)
        and isinstance(observed_revision, str)
        and requested_revision == observed_revision
    )
    if gates["pinned_revision"] and not expected_pinned_revision:
        raise ValueError(
            "result.target.requested_revision: inconsistent with observed repository revision"
        )

    executed_cases = [item for item in cases if item.get("status") == "executed"]
    scored_cases = [item for item in executed_cases if item.get("precision") is not None]
    expected_all_cases_executed = bool(cases) and len(executed_cases) == len(cases)
    expected_missing_anchors = bool(cases) and all(
        "anchors" in item
        and "missing_anchors" in item
        and not item["missing_anchors"]
        for item in cases
    )
    expected_all_cases_measured = expected_all_cases_executed and all(
        item.get("measurement_complete") is True for item in executed_cases
    )
    expected_forbidden = sum(int(item.get("forbidden_matches", 0)) for item in cases)
    expected_precision_100 = (
        metrics.get("precision") == 1.0
        and int(metrics["cases_scored"]) > 0
        and expected_all_cases_executed
        and expected_all_cases_measured
        and expected_forbidden == 0
    )
    expected_unresolved = all(
        item.get("status") == "executed"
        and item.get("measurement_complete") is True
        and item.get("unresolved_satisfied") is True
        for item in cases
        if int(item.get("unresolved_expected_count", 0) or 0) > 0
    )
    expected_required_diagnostics = all(
        item.get("status") == "executed"
        and item.get("required_diagnostics_satisfied") is True
        for item in cases
        if item.get("required_diagnostics")
    )
    expected_recall_values = _recall_at_10_from_cases(scored_cases)
    reported_recall_values = metrics.get("recall_at_10")
    if not isinstance(reported_recall_values, Mapping):
        raise ValueError("result.metrics.recall_at_10: expected object")
    for group, expected_value in expected_recall_values.items():
        actual_value = reported_recall_values.get(group)
        if expected_value is None:
            if actual_value is not None:
                raise ValueError(
                    f"result.metrics.recall_at_10.{group}: inconsistent with result.cases"
                )
        elif actual_value is None or not math.isclose(float(actual_value), expected_value):
            raise ValueError(
                f"result.metrics.recall_at_10.{group}: inconsistent with result.cases"
            )
    expected_recall = False
    if isinstance(reported_recall_values, Mapping):
        function_recall = expected_recall_values.get("function")
        module_recall = expected_recall_values.get("module")
        expected_recall = (
            isinstance(function_recall, (int, float))
            and not isinstance(function_recall, bool)
            and math.isfinite(float(function_recall))
            and 0.9 <= float(function_recall) <= 1.0
            and isinstance(module_recall, (int, float))
            and not isinstance(module_recall, bool)
            and math.isfinite(float(module_recall))
            and 0.9 <= float(module_recall) <= 1.0
        )
    observed_codes = {
        item["code"] for item in diagnostics if isinstance(item.get("code"), str)
    }
    expected_top_level_diagnostics = _top_level_diagnostics_gate(
        observed_codes, environment["diagnostics_contract"]
    )
    # Generated-data consistency is derived from the immutable expected
    # contract embedded in the result and from the categories actually
    # represented by its cases.  Recompute it here so a producer cannot flip
    # the gate after discovery (or hide a revision/marker mismatch).
    expected_generated_data, generated_data_applicable, _generated_data_reason = (
        _generated_data_consistency(environment, {"cases": cases})
    )
    expected_runtime_policy = _adapter_runtime_policy_enforced(environment)
    expected_impact = (
        impact.get("status") == "executed"
        and impact.get("coverage") == 1.0
        and impact.get("all_entries_covered") is True
        and int(impact.get("disallowed_false_positive_count", 0)) == 0
    )
    lifecycle_errors_expected = any(
        lifecycle[name].get("status") in {"error", "blocked"} for name in _LIFECYCLE_PHASES
    )
    # A parity gate can only be green when every phase was actually executed
    # and its explicit evidence derives the reported parity assertion.
    lifecycle_parity_expected = all(
        _lifecycle_parity_from_evidence(name, lifecycle[name])
        for name in _LIFECYCLE_PHASES
    )
    observed_codes = {
        item["code"] for item in diagnostics if isinstance(item.get("code"), str)
    }
    expected_diagnostics_observable = bool(
        observed_codes.intersection(
            {
                "required_tool_unavailable",
                "required_tool_version_mismatch",
                "otp_config_runtime_mismatch",
                "project_otp_configuration_stale",
                "xref_unavailable",
                "dialyzer_unavailable",
            }
        )
        or available_tools
    )
    derived_gates = {
        "generated_data_consistent": expected_generated_data,
        "runtime_policy_enforced": expected_runtime_policy,
        "semantic_tools": bool(execution.get("valid")),
        "semantic_adapters_executed": bool(execution.get("valid")),
        "precision_100": expected_precision_100,
        "all_cases_executed": expected_all_cases_executed,
        "all_cases_measured": expected_all_cases_measured,
        "missing_anchors": expected_missing_anchors,
        "no_forbidden_matches": expected_forbidden == 0,
        "unresolved_contract": expected_unresolved,
        "required_diagnostics": expected_required_diagnostics,
        "recall_at_10": expected_recall,
        "impact_coverage": expected_impact,
        "lifecycle_parity": lifecycle_parity_expected,
        "lifecycle_errors": not lifecycle_errors_expected,
        "diagnostics_observable": expected_diagnostics_observable,
        "top_level_diagnostics": expected_top_level_diagnostics,
    }
    for name, expected_value in derived_gates.items():
        if adoption_gates[name] != expected_value:
            raise ValueError(f"result.adoption.gates.{name}: inconsistent with result contents")
    expected_metric_status = "executed" if scored_cases else "not_run"
    if metric_status != expected_metric_status:
        raise ValueError("result.metrics.status: inconsistent with result.cases")
    if int(metrics["cases_scored"]) != len(scored_cases):
        raise ValueError("result.metrics.cases_scored: inconsistent with result.cases")
    if int(metrics["forbidden_matches"]) != expected_forbidden:
        raise ValueError("result.metrics.forbidden_matches: inconsistent with result.cases")
    aggregate_predicted = sum(int(item.get("predicted_count", 0)) for item in scored_cases)
    aggregate_true_positive = sum(int(item.get("true_positive", 0)) for item in scored_cases)
    aggregate_expected = sum(int(item.get("expected_positive_count", 0)) for item in scored_cases)
    aggregate_precision = (
        aggregate_true_positive / aggregate_predicted if aggregate_predicted else None
    )
    aggregate_recall = (
        aggregate_true_positive / aggregate_expected if aggregate_expected else None
    )
    for field, expected_value in (("precision", aggregate_precision), ("recall", aggregate_recall)):
        actual = metrics.get(field)
        if expected_value is None:
            if actual is not None:
                raise ValueError(f"result.metrics.{field}: inconsistent with result.cases")
        elif actual is None or not math.isclose(float(actual), expected_value):
            raise ValueError(f"result.metrics.{field}: inconsistent with result.cases")

    full_build_failed = lifecycle["full_build"].get("status") in {"error", "blocked"}
    expected_hard_failure = (
        not all(
            adoption_gates[name]
            for name in (
                "target_available",
                "standalone_git",
                "pinned_revision",
                "working_tree_state_known",
            )
        )
        or full_build_failed
        or lifecycle_errors_expected
        or gates["remote_mismatch"]
        or (
            adoption_gates["clean_baseline"]
            and not adoption_gates["dependencies_consistent"]
        )
        or (generated_data_applicable and not expected_generated_data)
    )
    expected_verdict = (
        "blocked"
        if expected_hard_failure
        else "primary"
        if all(adoption_gates.values())
        else "auxiliary"
    )
    if verdict != expected_verdict:
        raise ValueError("result.adoption.verdict: inconsistent with gates and lifecycle")

    expected_status = {"primary": "ok", "auxiliary": "auxiliary", "blocked": "blocked"}[verdict]
    if status != expected_status:
        raise ValueError("result.status: inconsistent with adoption verdict")
    if repository.get("remote") != recomputed_repository.get("remote"):
        raise ValueError(
            "result.environment.repository.remote: inconsistent with current checkout"
        )


def run_adoption_evaluation(
    manifest: str | Path | Mapping[str, Any] = DEFAULT_MANIFEST,
    corpus: str | Path | Mapping[str, Any] = DEFAULT_CORPUS,
    *,
    target_root: str | Path | None = None,
    probe_root: str | Path | None = None,
    timeout: float = 5.0,
    dry_run: bool = False,
    allow_dirty: bool = False,
    watch_smoke: bool = False,
    erlang_config: Any = None,
    graph_runner: Callable[..., Any] | None = None,
    lifecycle_runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run a repeatable adoption evaluation against a pinned external checkout."""
    manifest_doc, manifest_path = _load_manifest_artifact(manifest)
    corpus_doc, corpus_path = _load_corpus_artifact(corpus)
    validate_artifact_pair(
        manifest_doc,
        corpus_doc,
        manifest_path=manifest_path,
        corpus_path=corpus_path,
    )
    manifest_target = manifest_doc.get("target", {})
    configured_root = manifest_target.get("path") if isinstance(manifest_target, Mapping) else None
    root = _canonical_path(target_root or str(configured_root or ""))
    # This must precede discover_environment: its observation helpers join
    # manifest/corpus path fields to the target and may read them.
    _validate_artifact_paths(manifest_doc, corpus_doc, root)
    environment = discover_environment(
        manifest_doc,
        corpus_doc,
        target_root=root,
        manifest_root=manifest_path.parent if manifest_path else None,
        timeout=timeout,
        probe_root=_canonical_path(probe_root or Path(__file__).resolve().parents[2]),
        dry_run=True,
    )
    # ``discover_environment`` intentionally reports observed state only;
    # retain the declared gate budgets alongside it for this runner.
    environment["evaluation"] = manifest_doc.get("evaluation", {})
    gates, gate_diagnostics, can_build = _repository_gates(
        manifest_doc,
        environment,
        root,
        allow_dirty=allow_dirty,
    )
    diagnostics = (
        list(environment.get("diagnostics", []))
        if isinstance(environment.get("diagnostics"), list)
        else []
    )
    diagnostics.extend(gate_diagnostics)
    available_tools = _available_semantic_tools(environment)
    observed_diagnostic_codes = {
        str(item.get("code"))
        for item in diagnostics
        if isinstance(item, Mapping) and isinstance(item.get("code"), str)
    }
    lifecycle = _empty_lifecycle("preflight_gate_failed")
    case_results: list[dict[str, Any]] = []
    timings: dict[str, Sequence[float]] = {}
    store: GraphStore | None = None
    temp_context: tempfile.TemporaryDirectory[str] | None = None

    try:
        if can_build and not dry_run:
            temp_context = tempfile.TemporaryDirectory(prefix="crg-erlang-adoption-")
            try:
                store, lifecycle, timings, lifecycle_diagnostics = _run_lifecycle(
                    root,
                    Path(temp_context.name),
                    graph_runner=graph_runner,
                    lifecycle_runner=lifecycle_runner,
                    watch_smoke=watch_smoke,
                    watch_timeout=timeout,
                    erlang_config=erlang_config,
                )
                diagnostics.extend(lifecycle_diagnostics)
                build_failed = lifecycle.get("full_build", {}).get("status") in {
                    "error",
                    "blocked",
                }
                if build_failed:
                    can_build = False
            except Exception as exc:  # pragma: no cover - defensive lifecycle boundary
                diagnostics.append(_diagnostic("lifecycle_runner_failed", "error", str(exc)))
                lifecycle["full_build"] = {
                    "status": "error",
                    "reason": f"{type(exc).__name__}: {exc}",
                    "duration_seconds": None,
                    "parity": False,
                }
                can_build = False

        # Lifecycle diagnostics can carry required corpus codes, so collect
        # them after the runner has completed rather than only at preflight.
        observed_diagnostic_codes = {
            str(item.get("code"))
            for item in diagnostics
            if isinstance(item, Mapping) and isinstance(item.get("code"), str)
        }
        reason = None
        if dry_run:
            reason = "dry_run"
        elif not can_build:
            reason = next(
                (
                    code
                    for code in (
                        "target_missing",
                        "target_not_git",
                        "target_not_standalone",
                        "pinned_revision_mismatch",
                        "target_remote_mismatch",
                        "dependency_state_mismatch",
                        "target_worktree_dirty",
                        "graph_build_errors",
                        "graph_build_failed",
                        "lifecycle_runner_failed",
                    )
                    if any(
                        item.get("code") == code
                        for item in diagnostics
                        if isinstance(item, Mapping)
                    )
                ),
                "preflight_gate_failed",
            )
        case_results = _evaluate_case_results(
            corpus_doc,
            root,
            reason=reason,
            available_tools=available_tools,
            observed_diagnostic_codes=observed_diagnostic_codes,
            store=store,
            timings=timings,
            environment=environment,
        )

        return _assemble_adoption_result(
            manifest_doc,
            manifest_path,
            corpus_path,
            manifest_target,
            environment,
            gates,
            diagnostics,
            available_tools,
            corpus_doc,
            case_results,
            lifecycle,
            timings,
            store,
            root,
            dry_run=dry_run,
        )
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:
                # Preserve the original evaluation/validation exception.  A
                # close failure is still local to the temporary store.
                pass
        if temp_context is not None:
            temp_context.cleanup()


# Friendly aliases for callers that use the artifact's terminology.
evaluate_adoption = run_adoption_evaluation
evaluate_corpus = run_adoption_evaluation


def render_adoption_report(result: Mapping[str, Any]) -> str:
    """Render a concise deterministic Markdown report."""
    validate_evaluation_result(result)
    target = result.get("target", {})
    adoption = result.get("adoption", {})
    metrics = result.get("metrics", {})
    lines = [
        f"# Erlang Adoption Evaluation: {target.get('name', 'unknown')}",
        "",
        f"- Verdict: `{adoption.get('verdict')}`",
        f"- Pass: `{str(bool(adoption.get('pass'))).lower()}`",
        f"- Target revision: `{target.get('observed_revision')}`",
        f"- Clean baseline: `{str(bool(target.get('working_tree_clean'))).lower()}`",
        f"- Read-only target: `{str(bool(result.get('run', {}).get('read_only_target'))).lower()}`",
        "",
        "## Metrics",
        "",
        f"- Precision: `{metrics.get('precision')}`",
        f"- Recall: `{metrics.get('recall')}`",
        f"- Recall@10: `{_canonical_json(metrics.get('recall_at_10'))}`",
        f"- Impact: `{_canonical_json(metrics.get('impact'))}`",
        f"- Latency: `{_canonical_json(metrics.get('latency'))}`",
        "",
        "## Cases",
        "",
        "| Case | Category | Status | Precision | Recall | Reason |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for case in result.get("cases", []):
        if not isinstance(case, Mapping):
            continue
        lines.append(
            f"| {case.get('id')} | {case.get('category')} | {case.get('status')} | "
            f"{case.get('precision')} | {case.get('recall')} | {case.get('reason', '')} |"
        )
    lines.extend(["", "## Lifecycle", ""])
    for name in sorted(result.get("lifecycle", {})):
        item = result["lifecycle"][name]
        lines.append(f"- `{name}`: `{item.get('status')}` ({item.get('reason', 'measured')})")
    lines.extend(["", "## Diagnostics", ""])
    for item in result.get("diagnostics", []):
        if isinstance(item, Mapping):
            lines.append(f"- [{item.get('severity')}] `{item.get('code')}`: {item.get('message')}")
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _validate_report_stem(stem: Any) -> str:
    """Accept only one ordinary filename stem for report output."""
    if not isinstance(stem, str) or not stem or stem in {".", ".."}:
        raise ValueError("stem must be a non-empty filename component")
    if any(ord(char) < 32 or ord(char) == 127 for char in stem):
        raise ValueError("stem contains control characters")
    if (
        "/" in stem
        or "\\" in stem
        or Path(stem).is_absolute()
        or re.match(r"^[A-Za-z]:($|/)", stem)
    ):
        raise ValueError("stem must be a single filename component")
    return stem


def write_adoption_report(
    result: Mapping[str, Any],
    output_dir: str | Path,
    *,
    stem: str = DEFAULT_OUTPUT_STEM,
) -> dict[str, Path]:
    """Write deterministic JSON and Markdown reports atomically.

    Reports may not be written inside the evaluated target checkout; this
    prevents an output operation from turning a clean adoption baseline dirty.
    """
    validate_evaluation_result(result)
    safe_stem = _validate_report_stem(stem)
    output = _canonical_path(output_dir)
    target_path = (
        result.get("target", {}).get("path") if isinstance(result.get("target"), Mapping) else None
    )
    if target_path:
        try:
            output.relative_to(_canonical_path(str(target_path)))
        except ValueError:
            pass
        else:
            raise ValueError("output_dir must be outside the evaluated target checkout")
    json_path = output / f"{safe_stem}.json"
    markdown_path = output / f"{safe_stem}.md"
    encoded = (
        json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2, default=_json_default)
        + "\n"
    )
    _atomic_write(json_path, encoded)
    _atomic_write(markdown_path, render_adoption_report(result))
    return {"json": json_path, "markdown": markdown_path}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--target-root", type=Path, default=None)
    parser.add_argument("--probe-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--allow-dirty", action="store_true", help="Run exploratory graph work on a dirty checkout"
    )
    parser.add_argument(
        "--watch-smoke", action="store_true", help="Record an explicit bounded watch smoke request"
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_adoption_evaluation(
            args.manifest,
            args.corpus,
            target_root=args.target_root,
            probe_root=args.probe_root,
            timeout=args.timeout,
            dry_run=args.dry_run,
            allow_dirty=args.allow_dirty,
            watch_smoke=args.watch_smoke,
        )
        paths = write_adoption_report(result, args.output_dir) if args.output_dir else None
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.as_json:
        print(
            json.dumps(
                result,
                sort_keys=True,
                ensure_ascii=True,
                indent=2 if args.pretty else None,
                default=_json_default,
            )
        )
    else:
        print(render_adoption_report(result), end="")
    if paths:
        print(f"reports: {paths['json']} {paths['markdown']}", file=sys.stderr)
    return 0 if result.get("adoption", {}).get("verdict") != "blocked" else 1


if __name__ == "__main__":  # pragma: no cover - exercised through CLI tests
    raise SystemExit(main())


__all__ = [
    "DEFAULT_OUTPUT_STEM",
    "RESULT_KIND",
    "SCHEMA_VERSION",
    "evaluate_adoption",
    "evaluate_corpus",
    "graph_fingerprint",
    "main",
    "render_adoption_report",
    "run_adoption_evaluation",
    "score_case",
    "validate_evaluation_result",
    "write_adoption_report",
]
