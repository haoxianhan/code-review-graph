"""Shared utilities for tool sub-modules."""

from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from ..graph import GraphStore, _bound_semantic_value
from ..incremental import find_project_root, get_db_path
from ..parser import normalize_file_path

_PROVENANCE_READ_TIMEOUT_SECONDS = 0.05
_PROVENANCE_GIT_TIMEOUT_SECONDS = 1.0

logger = logging.getLogger(__name__)

# Semantic adapters are optional and may return arbitrarily large metadata.
# Keep review/query responses bounded independently from persistence limits.
_SEMANTIC_RESPONSE_RECORD_LIMIT = 32
_SEMANTIC_RESPONSE_VALUE_DEPTH = 4
_SEMANTIC_RESPONSE_RECORD_CHARS = 32_000
_SEMANTIC_MATCH_TEXT_CHARS = 4_096


def _semantic_response_record(value: Any) -> dict[str, Any] | None:
    """Convert one persisted semantic record to a bounded JSON mapping."""
    try:
        if hasattr(value, "to_dict"):
            value = value.to_dict()
        if not isinstance(value, dict):
            value = dict(value) if isinstance(value, Mapping) else None
        if not isinstance(value, dict):
            return None
        bounded = _bound_semantic_value(value, max_depth=_SEMANTIC_RESPONSE_VALUE_DEPTH)
        if not isinstance(bounded, dict):
            return None
        encoded = json.dumps(
            bounded, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            default=str,
        )
        if len(encoded) <= _SEMANTIC_RESPONSE_RECORD_CHARS:
            return bounded
        # Preserve identity/location/provenance if a malformed adapter managed
        # to exceed the normal bounded value budget.
        keep = {
            key: bounded[key]
            for key in (
                "evidence_id", "diagnostic_id", "kind", "code", "source",
                "target", "file_path", "line", "column", "severity", "status",
                "provenance",
            )
            if key in bounded
        }
        bounded = _bound_semantic_value(keep, max_depth=3)
        return bounded if isinstance(bounded, dict) else None
    except (TypeError, ValueError, OSError, RecursionError, OverflowError):
        return None


def _semantic_match_values(value: Any) -> set[str]:
    """Return conservative comparable spellings for an endpoint/path value."""
    if value is None:
        return set()
    text = str(value).strip()
    if not text:
        return set()
    # Endpoint values can originate in a user query.  Keep matching bounded
    # even when a caller submits an unexpectedly large target string.
    text = text[:_SEMANTIC_MATCH_TEXT_CHARS]
    normalized = text.replace("\\", "/")
    values = {text, normalized}
    tail = normalized.rsplit("::", 1)[-1]
    values.add(tail)

    # ELP/xref commonly use module:function/arity while Generic nodes use a
    # path-qualified module.function/arity suffix.  Keep both spellings in
    # the comparison set without treating arbitrary colons in file paths as
    # Erlang separators.
    if "/" in tail:
        function_part, separator, arity = tail.rpartition("/")
        if separator and arity.isdigit() and "." in function_part:
            module, function = function_part.rsplit(".", 1)
            if module and function:
                values.add(f"{module}:{function}/{arity}")
        if separator and arity.isdigit() and ":" in function_part:
            module, function = function_part.rsplit(":", 1)
            if module and function:
                values.add(f"{module}.{function}/{arity}")
    return {item.casefold() for item in values if item}


def _semantic_record_matches(
    record: Mapping[str, Any],
    *,
    endpoints: set[str],
    files: set[str],
    diagnostic: bool = False,
) -> bool:
    """Filter semantic records to the query/review scope without guessing."""
    if not endpoints and not files:
        return True
    record_values: set[str] = set()
    for key in ("source", "source_qualified", "target", "target_qualified"):
        record_values.update(_semantic_match_values(record.get(key)))
    raw_file = record.get("file_path")
    file_values = _semantic_match_values(raw_file)
    if endpoints and record_values.intersection(endpoints):
        return True
    if files:
        for candidate in file_values:
            if any(candidate == wanted or candidate.endswith("/" + wanted) for wanted in files):
                return True
    # Diagnostics without a source location can still describe the requested
    # run, but only when their provenance names one of the requested targets.
    # Never let an unrelated, target-less warning leak into a scoped response.
    if diagnostic:
        provenance = record.get("provenance")
        if isinstance(provenance, Mapping):
            for target in provenance.get("query_targets", ()) or ():
                if _semantic_match_values(target).intersection(endpoints):
                    return True
        if not endpoints and not files and not raw_file and not record_values:
            return True
    return False


def _read_semantic_context(
    store: GraphStore,
    root: Path,
    *,
    endpoints: Iterable[str] = (),
    files: Iterable[str] = (),
    limit: int = _SEMANTIC_RESPONSE_RECORD_LIMIT,
    include_evidence: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    """Read bounded, repository-scoped semantic evidence/diagnostics.

    Reads are deliberately best effort: an old database, a malformed optional
    row, or a missing semantic table must never break Generic graph queries.
    """
    endpoint_values: set[str] = set()
    for endpoint in endpoints:
        endpoint_values.update(_semantic_match_values(endpoint))
    file_values: set[str] = set()
    for file_path in files:
        text = str(file_path).strip().replace("\\", "/").casefold()
        if text:
            file_values.add(text)
            try:
                file_values.add(normalize_file_path(root / file_path).casefold())
            except (TypeError, ValueError, OSError):
                pass
    try:
        repository = normalize_file_path(root)
        bounded_limit = max(1, min(int(limit), _SEMANTIC_RESPONSE_RECORD_LIMIT))
    except (TypeError, ValueError, OverflowError):
        repository = normalize_file_path(root)
        bounded_limit = _SEMANTIC_RESPONSE_RECORD_LIMIT

    output: dict[str, list[dict[str, Any]]] = {
        "semantic_evidence": [],
        "semantic_diagnostics": [],
    }
    matched_analysis_keys: set[str] = set()
    try:
        if include_evidence:
            raw_evidence = store.get_semantic_evidence(
                repository=repository, limit=bounded_limit * 4,
            )
            for item in raw_evidence:
                record = _semantic_response_record(item)
                if record is None or not _semantic_record_matches(
                    record, endpoints=endpoint_values, files=file_values,
                ):
                    continue
                output["semantic_evidence"].append(record)
                provenance = record.get("provenance")
                if isinstance(provenance, Mapping):
                    analysis_key = provenance.get("analysis_key")
                    if isinstance(analysis_key, str) and analysis_key:
                        # Diagnostics from the same bounded adapter query are
                        # part of the review context even when the tool did
                        # not attach a source location to each warning.
                        matched_analysis_keys.add(analysis_key)
                if len(output["semantic_evidence"]) >= bounded_limit:
                    break
    except Exception:
        logger.debug("Could not read optional semantic evidence", exc_info=True)
    try:
        raw_diagnostics = store.get_semantic_diagnostics(
            repository=repository, limit=bounded_limit * 4,
        )
        for item in raw_diagnostics:
            record = _semantic_response_record(item)
            if record is None:
                continue
            provenance = record.get("provenance")
            same_query = (
                isinstance(provenance, Mapping)
                and isinstance(provenance.get("analysis_key"), str)
                and provenance["analysis_key"] in matched_analysis_keys
            )
            if not same_query and not _semantic_record_matches(
                record, endpoints=endpoint_values, files=file_values, diagnostic=True,
            ):
                continue
            output["semantic_diagnostics"].append(record)
            if len(output["semantic_diagnostics"]) >= bounded_limit:
                break
    except Exception:
        logger.debug("Could not read optional semantic diagnostics", exc_info=True)
    return output


def _attach_semantic_context(
    response: dict[str, Any],
    store: GraphStore,
    root: Path,
    *,
    endpoints: Iterable[str] = (),
    files: Iterable[str] = (),
    limit: int = _SEMANTIC_RESPONSE_RECORD_LIMIT,
    include_evidence: bool = True,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach non-empty semantic context fields to an existing response."""
    payload = _read_semantic_context(
        store, root, endpoints=endpoints, files=files, limit=limit,
        include_evidence=include_evidence,
    )
    destination = target if target is not None else response
    for key, values in payload.items():
        if values:
            destination[key] = values
    return response


def _error_response(
    message: str, status: str = "error", **extra: Any,
) -> dict[str, Any]:
    """Build a standardised error response dict."""
    return {"status": status, "error": message, "summary": message, **extra}


def _read_live_git_head(root: Path) -> str | None:
    """Return the checked-out commit without making provenance mandatory.

    ``head_matches_build`` deliberately compares commits only. It does not
    claim that staged, unstaged, or untracked files are represented by the
    graph, avoiding the misleading ``is_stale=False`` contract from #458.
    """
    if not (root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(root),
            timeout=_PROVENANCE_GIT_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        logger.debug("Could not read live Git HEAD for graph provenance", exc_info=True)
        return None
    if result.returncode != 0:
        logger.debug("git rev-parse failed while reading graph provenance")
        return None
    head_sha = result.stdout.strip()
    return head_sha or None


def graph_provenance(repo_root: str | None = None) -> dict[str, Any] | None:
    """Return best-effort build metadata for one repository's graph.

    The metadata read is deliberately read-only. Missing, incomplete, or
    unreadable graph databases must never make the enclosing tool call fail.
    """
    try:
        root = _resolve_root(repo_root)
        db_path = get_db_path(root, read_only=True)
        if not db_path.exists():
            return None

        # ``as_uri`` escapes URI-significant path characters before the
        # read-only mode query is appended. It also handles Windows drives.
        database_uri = f"{db_path.resolve().as_uri()}?mode=ro"
        # Provenance is optional and reads only three local metadata rows.
        # Allow a brief commit boundary, but never inherit sqlite3's 5-second
        # default wait when a build or migration holds an exclusive lock.
        connection = sqlite3.connect(
            database_uri,
            uri=True,
            timeout=_PROVENANCE_READ_TIMEOUT_SECONDS,
        )
        try:
            rows = dict(connection.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('last_updated', 'git_branch', 'git_head_sha')"
            ).fetchall())
        finally:
            connection.close()

        provenance: dict[str, Any] = {}
        updated_at = rows.get("last_updated")
        if isinstance(updated_at, str) and updated_at:
            provenance["updated_at"] = updated_at
            try:
                built_at = datetime.fromisoformat(updated_at)
                # Match aware timestamps with an aware ``now`` in the same
                # timezone; None preserves the stored naive/local format.
                now = datetime.now(tz=built_at.tzinfo)
                provenance["age_seconds"] = max(
                    0, int((now - built_at).total_seconds()),
                )
            except (OverflowError, TypeError, ValueError):
                # A malformed timestamp only removes the derived age. The raw
                # timestamp and independently valid branch/SHA remain useful.
                pass

        head_sha = rows.get("git_head_sha")
        if isinstance(head_sha, str) and head_sha:
            provenance["built_at_sha"] = head_sha
        if provenance:
            branch = rows.get("git_branch")
            if isinstance(branch, str) and branch:
                provenance["built_on_branch"] = branch
            live_head_sha = _read_live_git_head(root)
            if live_head_sha:
                provenance["head_sha"] = live_head_sha
                if isinstance(head_sha, str) and head_sha:
                    provenance["head_matches_build"] = live_head_sha == head_sha
        return provenance or None
    except Exception:
        return None


def with_provenance(result: Any, repo_root: str | None = None) -> Any:
    """Attach a ``_graph`` envelope without changing existing fields."""
    if not isinstance(result, dict) or "_graph" in result:
        return result
    provenance = graph_provenance(repo_root)
    if provenance:
        result["_graph"] = provenance
    return result

# Common JS/TS builtin method names filtered from callers_of results.
# "Who calls .map()?" returns hundreds of hits and is never useful.
# These are kept in the graph (callees_of still shows them) but excluded
# when doing reverse call tracing to reduce noise.
_BUILTIN_CALL_NAMES: set[str] = {
    "map", "filter", "reduce", "reduceRight", "forEach", "find", "findIndex",
    "some", "every", "includes", "indexOf", "lastIndexOf",
    "push", "pop", "shift", "unshift", "splice", "slice",
    "concat", "join", "flat", "flatMap", "sort", "reverse", "fill",
    "keys", "values", "entries", "from", "isArray", "of", "at",
    "trim", "trimStart", "trimEnd", "split", "replace", "replaceAll",
    "match", "matchAll", "search", "substring", "substr",
    "toLowerCase", "toUpperCase", "startsWith", "endsWith",
    "padStart", "padEnd", "repeat", "charAt", "charCodeAt",
    "assign", "freeze", "defineProperty", "getOwnPropertyNames",
    "hasOwnProperty", "create", "is", "fromEntries",
    "log", "warn", "error", "info", "debug", "trace", "dir", "table",
    "time", "timeEnd", "assert", "clear", "count",
    "then", "catch", "finally", "resolve", "reject", "all", "allSettled", "race", "any",
    "parse", "stringify",
    "floor", "ceil", "round", "random", "max", "min", "abs", "pow", "sqrt",
    "addEventListener", "removeEventListener", "querySelector", "querySelectorAll",
    "getElementById", "createElement", "appendChild", "removeChild",
    "setAttribute", "getAttribute", "preventDefault", "stopPropagation",
    "setTimeout", "clearTimeout", "setInterval", "clearInterval",
    "toString", "valueOf", "toJSON", "toISOString",
    "getTime", "getFullYear", "now",
    "isNaN", "parseInt", "parseFloat", "toFixed",
    "encodeURIComponent", "decodeURIComponent",
    "call", "apply", "bind", "next",
    "emit", "on", "off", "once",
    "pipe", "write", "read", "end", "close", "destroy",
    "send", "status", "json", "redirect",
    "set", "get", "delete", "has",
    "findUnique", "findFirst", "findMany", "createMany",
    "update", "updateMany", "deleteMany", "upsert",
    "aggregate", "groupBy", "transaction",
    "describe", "it", "test", "expect", "beforeEach", "afterEach",
    "beforeAll", "afterAll", "mock", "spyOn",
    "require", "fetch",
}


def _validate_repo_root(path: "Path | str") -> Path:
    """Validate that a path is a plausible project root.

    Ensures the path is an existing directory that contains a ``.git``,
    ``.svn``, or ``.code-review-graph`` directory, preventing arbitrary
    file-system traversal via the ``repo_root`` parameter.
    """
    resolved = Path(path).resolve()
    if not resolved.is_dir():
        raise ValueError(
            f"repo_root is not an existing directory: {resolved}"
        )
    has_vcs = (
        (resolved / ".git").exists()
        or (resolved / ".svn").exists()
        or (resolved / ".code-review-graph").exists()
    )
    if not has_vcs:
        raise ValueError(
            f"repo_root does not look like a project root "
            f"(no .git, .svn, or .code-review-graph directory found): "
            f"{resolved}"
        )
    return resolved


def _resolve_root(repo_root: str | None = None) -> Path:
    """Resolve and validate the repository root without opening a store."""
    return _validate_repo_root(Path(repo_root)) if repo_root else find_project_root()


def _get_store(repo_root: str | None = None) -> tuple[GraphStore, Path]:
    """Resolve repo root and open the graph store.

    Callers own the returned store and must close it (try/finally or
    context manager) to avoid leaking SQLite file descriptors.
    """
    root = _resolve_root(repo_root)
    db_path = get_db_path(root)
    return GraphStore(db_path), root


def _resolve_graph_file_paths(
    store: GraphStore, root: Path, file_paths: list[str],
) -> list[str]:
    """Resolve user-facing file paths to the paths stored in the graph.

    Graphs may contain absolute paths, repo-relative paths, or cwd-relative
    paths depending on how they were built. Tool inputs are usually relative to
    repo root, so exact matching alone can miss existing graph nodes.
    """
    resolved: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        if path not in seen:
            resolved.append(path)
            seen.add(path)

    for file_path in file_paths:
        raw = file_path.replace("\\", "/")
        candidates = [raw]
        path = Path(file_path)
        if path.is_absolute():
            try:
                candidates.append(str(path.resolve().relative_to(root)).replace("\\", "/"))
            except ValueError:
                pass
        else:
            candidates.append(normalize_file_path(root / path))

        for candidate in candidates:
            if store.get_nodes_by_file(candidate):
                add(candidate)

        suffixes = []
        for candidate in candidates:
            normalized = candidate.replace("\\", "/")
            if normalized not in suffixes:
                suffixes.append(normalized)

        for suffix in suffixes:
            for matched_path in store.get_files_matching(suffix):
                add(matched_path)

    return resolved


# ---------------------------------------------------------------------------
# Result bounding (#849 follow-up)
# ---------------------------------------------------------------------------
#
# Every MCP tool response has to survive a client-side context window. #849
# found get_affected_flows returning 247k tokens inside a workflow documented
# as "5 tool calls, 800 tokens total"; PR #853 capped that one tool. These
# helpers give the remaining tools the same contract:
#
#   * ``total`` always reports the untruncated count,
#   * ``truncated`` marks that the list was cut,
#   * the summary line says how many of how many are shown.
#
# Each tool pairs a caller-facing default with a hard ceiling. The ceiling
# exists so a caller passing ``max_results=1_000_000`` still gets a response
# that fits the ~25k-token budget most MCP clients allow for one tool result.


def _validate_positive_int(value: int, name: str) -> int:
    """Validate a caller-supplied result bound.

    Mirrors the check ``query.py`` applies to ``max_results``: ``bool`` is
    rejected explicitly because ``True`` would otherwise silently mean 1.
    """
    if isinstance(value, bool) or value < 1:
        raise ValueError(f"{name} must be an integer greater than or equal to 1")
    return value


def _bounded(
    items: "list[Any]", max_results: int, hard_cap: int,
) -> tuple[list[Any], int, bool]:
    """Cap *items* at ``min(max_results, hard_cap)``.

    Returns ``(visible, total, truncated)`` where ``total`` is the
    untruncated length, so callers can always report the real count.
    """
    total = len(items)
    limit = min(max_results, hard_cap)
    return list(items[:limit]), total, total > limit


def _shown_of(shown: int, total: int) -> str:
    """Return the ``", showing N of M"`` fragment used by capped summaries."""
    return f", showing {shown} of {total}" if shown < total else ""


def compact_response(
    summary: str,
    key_entities: list[str] | None = None,
    risk: str = "unknown",
    communities: list[str] | None = None,
    flows_affected: list[str] | None = None,
    next_tool_suggestions: list[str] | None = None,
    data: dict[str, Any] | None = None,
    detail_level: str = "minimal",
) -> dict[str, Any]:
    """Standard compact response format for token efficiency."""
    resp: dict[str, Any] = {
        "status": "ok",
        "summary": summary,
    }
    if key_entities:
        resp["key_entities"] = key_entities[:10]
    if risk != "unknown":
        resp["risk"] = risk
    if communities:
        resp["communities"] = communities[:5]
    if flows_affected:
        resp["flows_affected"] = flows_affected[:5]
    if next_tool_suggestions:
        resp["next_tool_suggestions"] = next_tool_suggestions[:3]
    if detail_level != "minimal" and data:
        resp["data"] = data
    return resp
