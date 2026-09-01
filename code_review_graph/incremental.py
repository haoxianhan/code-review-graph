"""Incremental graph update logic.

Detects changed files via git diff, re-parses only changed + impacted files,
and updates the graph accordingly. Also supports CLI invocation for hooks.
"""

from __future__ import annotations

import concurrent.futures
import fnmatch
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, NamedTuple, Optional

from .graph import GraphStore
from .parser import CodeParser, normalize_file_path

_MAX_PARSE_WORKERS = int(os.environ.get("CRG_PARSE_WORKERS", str(min(os.cpu_count() or 4, 8))))

# Set only while the in-process FastMCP server is using stdio transport.
# This is deliberately separate from ``sys.stdin.isatty()``: CI, cron, and
# redirected CLI builds also have non-TTY stdin, but do not share the MCP
# transport's file-descriptor lifetime problem.
_MCP_STDIO_ACTIVE = False

# Each process-pool worker runs this module in its own process, while each
# thread-pool worker needs isolated parser state.  A thread-local cache covers
# both cases and avoids rebuilding CodeParser (including its grammar probes and
# parser caches) for every file in a parallel build.
_PARSE_WORKER_STATE = threading.local()


def _select_executor_kind() -> str:
    """Return 'process' or 'thread' for parallel parsing.

    Defaults to ``process`` (the original behavior, fastest on Linux/macOS).
    Auto-switches to ``thread`` for an active MCP stdio server on every
    platform, where ``ProcessPoolExecutor`` workers can inherit the transport
    pipe/socket and prevent EOF shutdown. The older Windows non-TTY fallback
    remains for direct integrations that predate the explicit transport flag
    (issues #46, #136, PR #615).

    Override explicitly with ``CRG_PARSE_EXECUTOR={process,thread}``.

    Tree-sitter parsing in the worker releases the GIL during native
    parsing, so the speedup loss for falling back to threads is small
    (typically <30% on the full-build path) and the trade is worth it
    to avoid the deadlock + zombie process accumulation.
    """
    explicit = os.environ.get("CRG_PARSE_EXECUTOR", "").strip().lower()
    if explicit in ("process", "thread"):
        return explicit
    if _MCP_STDIO_ACTIVE:
        return "thread"
    if sys.platform == "win32" and not sys.stdin.isatty():
        return "thread"
    return "process"


def _make_executor(max_workers: int):
    """Construct the parallel-parse executor selected by [_select_executor_kind]."""
    if _select_executor_kind() == "thread":
        return concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    return concurrent.futures.ProcessPoolExecutor(max_workers=max_workers)

logger = logging.getLogger(__name__)

CPP_IDENTITY_VERSION = "1"
_CPP_IDENTITY_METADATA_KEY = "cpp_identity_version"

# Erlang node identities changed when the Generic parser started persisting
# module/export metadata.  Keep this marker independent from the optional
# ELP/xref/Dialyzer bridge: a toolchain outage must not make a sound Generic
# graph look unmigrated forever.
ERLANG_IDENTITY_VERSION = "6"
_ERLANG_IDENTITY_METADATA_KEY = "erlang_identity_version"
_ERLANG_IDENTITY_METADATA_PREFIX = f"{_ERLANG_IDENTITY_METADATA_KEY}:"
_ERLANG_IDENTITY_DIGEST_LENGTH = 32
_ERLANG_SOURCE_SUFFIXES = (".erl", ".hrl", ".app.src")

# Lifecycle callers opt into the optional Erlang bridge explicitly or through
# CRG_ERLANG_* environment variables.  A sentinel keeps an omitted argument
# distinct from ``ErlangIntegrationConfig(enabled=False)``, which is an
# intentional cleanup request.
_ERLANG_CONFIG_UNSET = object()
_WATCH_POSTPROCESS_PENDING_METADATA_KEY = "watch_postprocess_pending"
_WATCH_PENDING_LEGACY_WILDCARD = "*"
_ERLANG_LAYOUT_BASENAMES = frozenset(
    {
        "rebar.config",
        "rebar.config.script",
        "erlang_ls.config",
        "rebar.lock",
    }
)


def _is_erlang_layout_path(path: str | Path) -> bool:
    """Return whether *path* can change Erlang semantic project layout."""
    value = str(path).replace("\\", "/")
    basename = value.rsplit("/", 1)[-1].casefold()
    return basename in _ERLANG_LAYOUT_BASENAMES or basename.endswith(".app.src")


def _is_erlang_source_path(path: str | Path) -> bool:
    """Return whether *path* participates in Generic Erlang identity."""
    value = str(path).replace("\\", "/").casefold()
    return value.endswith(_ERLANG_SOURCE_SUFFIXES)


def _is_erlang_relevant_path(path: str | Path) -> bool:
    value = str(path).replace("\\", "/").casefold()
    return _is_erlang_source_path(value) or _is_erlang_layout_path(value)


def _erlang_identity_key(repo_root: Path) -> str:
    """Return the metadata key for one canonical repository root."""
    canonical = Path(repo_root).expanduser().resolve(strict=False)
    identity = normalize_file_path(canonical)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"{_ERLANG_IDENTITY_METADATA_PREFIX}{digest[:_ERLANG_IDENTITY_DIGEST_LENGTH]}"


def _path_belongs_to_root(path: str | Path, repo_root: Path) -> bool:
    """Return whether a stored graph path can belong to *repo_root*.

    Graph paths are normally absolute and separator-normalized.  Relative
    paths are legacy rows and are interpreted in the requested checkout, but
    traversal components are rejected so a foreign ``../`` row cannot pass
    the ownership check.
    """
    value = normalize_file_path(path)
    if not value:
        return False
    root = Path(repo_root).expanduser().resolve(strict=False)
    root_value = normalize_file_path(root).rstrip("/")
    # Keep Windows drive paths comparable when the graph was produced on a
    # different host than the one reading it.
    if re.match(r"^[A-Za-z]:/", value):
        folded = value.casefold()
        expected = root_value.casefold()
        return folded == expected or folded.startswith(expected + "/")
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate.resolve(strict=False).relative_to(root)
            return True
        except (OSError, RuntimeError, ValueError):
            return False
    parts = PurePosixPath(value).parts
    return ".." not in parts


def _graph_has_foreign_roots(store: GraphStore, repo_root: Path) -> bool:
    """Return whether authoritative File markers name another checkout."""
    try:
        return any(
            not _path_belongs_to_root(path, repo_root)
            for path in store.get_file_marker_paths()
        )
    except Exception as exc:  # pragma: no cover - defensive metadata boundary
        logger.debug("Could not inspect graph repository markers: %s", exc)
        return True


def _erlang_identity_is_current(store: GraphStore, repo_root: Path) -> bool:
    """Check a scoped marker, upgrading a trustworthy legacy scalar marker."""
    if store.get_metadata(_erlang_identity_key(repo_root)) == ERLANG_IDENTITY_VERSION:
        return True
    # ``erlang_identity_version`` predates shared GraphStores.  It is safe to
    # promote only when every authoritative File marker belongs to this root;
    # otherwise another checkout may have written the same scalar value.
    if (
        store.get_metadata(_ERLANG_IDENTITY_METADATA_KEY) == ERLANG_IDENTITY_VERSION
        and not _graph_has_foreign_roots(store, repo_root)
    ):
        _set_erlang_identity_current(store, repo_root)
        return True
    return False


def _clear_erlang_identity(
    store: GraphStore,
    repo_root: Path | None = None,
) -> None:
    """Persist a pending Erlang migration marker.

    Full and incremental parsing commit file replacements independently.  A
    direct ``DELETE`` without a commit would let a later transaction restore a
    stale marker after an interrupted update, so marker cleanup is committed at
    the lifecycle boundary just like :meth:`GraphStore.set_metadata`.
    """
    if repo_root is None:
        # Compatibility for external callers that used the old helper without
        # a root.  Lifecycle code always supplies a root and therefore leaves
        # other repositories' scoped markers untouched.
        store._conn.execute(
            "DELETE FROM metadata WHERE key = ? OR key LIKE ?",
            (_ERLANG_IDENTITY_METADATA_KEY, f"{_ERLANG_IDENTITY_METADATA_PREFIX}%"),
        )
    else:
        key = _erlang_identity_key(repo_root)
        store._conn.execute(
            "DELETE FROM metadata WHERE key = ?",
            (key,),
        )
        # A scalar marker cannot express repository ownership.  Once a scoped
        # lifecycle pass touches the store, remove it so a later checkout can
        # never mistake another repository's value for its own.
        store._conn.execute(
            "DELETE FROM metadata WHERE key = ?",
            (_ERLANG_IDENTITY_METADATA_KEY,),
        )
    store._conn.commit()


def _set_erlang_identity_current(
    store: GraphStore,
    repo_root: Path | None = None,
) -> None:
    """Persist the current Generic Erlang identity version."""
    if repo_root is None:
        store.set_metadata(_ERLANG_IDENTITY_METADATA_KEY, ERLANG_IDENTITY_VERSION)
        return
    store.set_metadata(_erlang_identity_key(repo_root), ERLANG_IDENTITY_VERSION)
    # Do not write the ambiguous legacy scalar.  It remains readable for one
    # migration pass, but all new state is repository-scoped.
    store._conn.execute(
        "DELETE FROM metadata WHERE key = ?",
        (_ERLANG_IDENTITY_METADATA_KEY,),
    )
    store._conn.commit()


def _invoke_full_build(
    repo_root: Path,
    store: GraphStore,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
) -> dict[str, Any]:
    """Call :func:`full_build` while preserving legacy omitted arguments.

    The helper is used by identity migrations as well as the public build
    wrapper.  Keep the no-option path as ``full_build(root, store)`` because
    callers and tests commonly patch that shape; add optional arguments only
    when the caller explicitly supplied them.
    """
    if erlang_config is _ERLANG_CONFIG_UNSET:
        return full_build(repo_root, store)
    return full_build(repo_root, store, erlang_config=erlang_config)


def _error_is_erlang_related(error: Any) -> bool:
    """Classify a build error that invalidates Erlang identity metadata."""
    if not isinstance(error, Mapping):
        return False
    path = str(error.get("file", "")).replace("\\", "/").casefold()
    return (
        _is_erlang_source_path(path)
        or "erlang" in path
        or "relation_reconciliation" in path
    )


def _result_has_erlang_errors(result: Mapping[str, Any] | None) -> bool:
    """Return whether a full-build result contains a fatal Erlang parse error."""
    if not isinstance(result, Mapping):
        return False
    errors = result.get("errors", ())
    if not isinstance(errors, (list, tuple)):
        return False
    return any(_error_is_erlang_related(error) for error in errors)


def _identity_rebuild_result(
    rebuilt: Mapping[str, Any],
    changed_files: list[str] | tuple[str, ...] | None,
) -> dict[str, Any]:
    """Adapt a full-build result to the incremental result contract."""
    result: dict[str, Any] = {
        "files_updated": int(rebuilt.get("files_parsed", 0) or 0),
        "total_nodes": rebuilt.get("total_nodes", 0),
        "total_edges": rebuilt.get("total_edges", 0),
        "changed_files": list(changed_files or ()),
        "dependent_files": [],
        "errors": list(rebuilt.get("errors", ()) or ()),
        "identity_rebuild": True,
        "graph_changed": True,
        "relation_layout_changed": False,
    }
    for key in (
        "python_resolution",
        "rescript_resolution",
        "spring_resolution",
        "event_resolution",
        "temporal_resolution",
        "hcl_resolution",
        "scoped_resolution",
        "erlang_integration",
    ):
        if key in rebuilt:
            result[key] = rebuilt[key]
    return result


def _repo_contains_erlang_sources(repo_root: Path) -> bool:
    """Probe the authoritative parse inventory for Erlang source files.

    ``collect_all_files`` applies VCS and ignore rules used by a real full
    build.  This avoids triggering migration for an ignored or merely
    untracked ``.erl`` file while still recognizing legacy custom-language
    graph rows by their path suffix.
    """
    try:
        return any(
            _is_erlang_source_path(path)
            for path in collect_all_files(_canonical_repo_root(repo_root))
        )
    except Exception as exc:  # pragma: no cover - defensive inventory boundary
        logger.debug("Could not probe Erlang source inventory: %s", exc)
        return False


def _ensure_erlang_identity_current(
    repo_root: Path,
    store: GraphStore,
    *,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
) -> dict[str, Any] | None:
    """Rebuild a stale Erlang graph before an independent lifecycle pass.

    The marker is intentionally checked against the exact current version;
    missing, malformed, and every older value (including native v1/v4
    databases) are migration candidates.  A repository source inventory is
    required so a Python-only graph does not trigger an expensive rebuild.
    """
    root = _canonical_repo_root(repo_root)
    if _erlang_identity_is_current(store, root):
        return None
    if not store.has_nodes():
        return None
    # Do not run a Git/filesystem inventory probe for an unrelated graph.  In
    # particular, watch startup must remain independent of project VCS state
    # for Python-only repositories.  Legacy stores can still be recognized by
    # their Erlang file suffixes; only those stores need the authoritative
    # source inventory check below.
    if not store.has_nodes_for_language("erlang"):
        try:
            represented_erlang = any(
                _is_erlang_source_path(path) for path in store.get_all_files()
            )
        except Exception:  # pragma: no cover - defensive graph boundary
            represented_erlang = True
        if not represented_erlang:
            return None
    if not _repo_contains_erlang_sources(root):
        return None

    logger.info("Erlang graph identity is stale; rebuilding before postprocessing")
    # Clear before entering the file replacement loop.  If parsing or an
    # optional lifecycle callback is interrupted, the next invocation retries.
    _clear_erlang_identity(store, root)
    try:
        rebuilt = _invoke_full_build(root, store, erlang_config)
    except BaseException:
        _clear_erlang_identity(store, root)
        raise

    if _result_has_erlang_errors(rebuilt):
        _clear_erlang_identity(store, root)
    else:
        # Real full_build writes this marker itself.  Reassert it here as a
        # boundary guarantee for custom/mocked builders and future callers.
        _set_erlang_identity_current(store, root)
    return rebuilt


def _append_untracked_erlang_layout_files(
    repo_root: Path,
    changed_files: list[str],
) -> list[str]:
    """Add untracked Erlang layout files to automatic incremental changes.

    ``git diff <base>`` intentionally omits untracked paths.  A newly-created
    ``rebar.config`` or ``*.app.src`` can nevertheless change semantic
    resolution, so include those paths when the caller did not provide an
    explicit change list.  Source files keep the historical Git-diff behavior;
    watch mode and a full build remain the mechanisms for discovering them.
    """
    if detect_vcs(repo_root) != "git":
        return changed_files
    try:
        working_tree = get_staged_and_unstaged(repo_root)
    except Exception as exc:  # pragma: no cover - defensive VCS boundary
        logger.debug("Could not inspect working-tree Erlang layout: %s", exc)
        return changed_files
    seen = {str(path).replace("\\", "/") for path in changed_files}
    for path in working_tree:
        normalized = str(path).replace("\\", "/")
        if not _is_erlang_layout_path(normalized) or normalized in seen:
            continue
        changed_files.append(path)
        seen.add(normalized)
    return changed_files


def _append_mismatched_erlang_hashes(
    repo_root: Path,
    store: "GraphStore",
    changed_files: list[str],
) -> list[str]:
    """Include Erlang files whose bytes no longer match the stored graph.

    A working-tree edit can be indexed while the graph's Git anchor remains at
    the same commit. If that edit is then restored to the anchor, ``git diff``
    becomes empty even though the graph still describes the edited bytes. The
    Generic Erlang contract is hash-based, so compare stored file hashes for
    Erlang paths before accepting an automatic update as a no-op.
    """
    root = _canonical_repo_root(repo_root)
    seen = {str(path).replace("\\", "/") for path in changed_files}
    for stored_path in store.get_all_files():
        normalized = normalize_file_path(stored_path)
        if not _is_erlang_source_path(normalized) or not _path_belongs_to_root(
            normalized, root
        ):
            continue
        absolute = Path(normalized)
        if not absolute.is_absolute():
            absolute = root / absolute
        try:
            raw = absolute.read_bytes()
        except (OSError, PermissionError):
            continue
        current_hash = hashlib.sha256(raw).hexdigest()
        nodes = store.get_nodes_by_file(str(absolute))
        stored_hashes = {node.file_hash for node in nodes if node.file_hash}
        if stored_hashes and current_hash in stored_hashes:
            continue
        try:
            relative = absolute.relative_to(root).as_posix()
        except ValueError:
            continue
        if relative not in seen:
            changed_files.append(relative)
            seen.add(relative)
    return changed_files


def _run_erlang_lifecycle(
    repo_root: Path,
    store: GraphStore,
    *,
    config: Any = _ERLANG_CONFIG_UNSET,
    changed_files: list[str] | tuple[str, ...] | None = None,
    force: bool = False,
) -> dict[str, Any] | None:
    """Run one optional Erlang integration pass for a lifecycle boundary."""
    from .erlang_integration import (
        erlang_integration_requested,
        maybe_run_erlang_integration,
    )

    effective_config = None if config is _ERLANG_CONFIG_UNSET else config
    if not erlang_integration_requested(effective_config):
        return None
    paths = [str(path) for path in (changed_files or ())]
    if not force and not any(_is_erlang_relevant_path(path) for path in paths):
        # An explicit disabled setting is a cleanup request, even when the
        # current change is unrelated (or the update is otherwise a no-op).
        # Enabled settings still avoid tool discovery until a relevant Erlang
        # path is changed.
        try:
            from .erlang_integration import ErlangIntegrationConfig

            explicitly_disabled = not ErlangIntegrationConfig.from_value(
                effective_config
            ).enabled
        except Exception:
            explicitly_disabled = False
        if not explicitly_disabled:
            return None
    result = maybe_run_erlang_integration(
        repo_root,
        store,
        config=effective_config,
        changed_files=paths,
    )
    if result is None:
        return None
    payload = result.to_dict()
    if payload.get("status") == "blocked":
        diagnostics = payload.get("diagnostics", [])
        codes = [
            str(item.get("code"))
            for item in diagnostics
            if isinstance(item, Mapping) and item.get("code")
        ]
        detail = ", ".join(codes[:8]) or "required_toolchain"
        raise RuntimeError(f"Erlang strict preflight blocked operation ({detail})")
    return payload


def _erlang_result_requires_derived_refresh(result: Mapping[str, Any] | None) -> bool:
    """Return whether semantic reconciliation changed graph-derived state."""
    if not isinstance(result, Mapping):
        return False
    integration = result.get("erlang_integration")
    if not isinstance(integration, Mapping):
        return False
    counts = integration.get("counts")
    if not isinstance(counts, Mapping):
        return False
    # Query, diagnostic, and cache counters alone do not alter derived graph
    # tables. Evidence/projection reconciliation and cleanup do.
    for key in (
        "evidence",
        "persisted_evidence",
        "persisted_diagnostics",
        "persisted_runs",
        "projected_edges",
        "cleared_edges",
        "cleared_evidence",
        "cleared_diagnostics",
        "cleared_runs",
        "stale_removed",
    ):
        try:
            if int(counts.get(key, 0) or 0) > 0:
                return True
        except (TypeError, ValueError, OverflowError):
            continue
    return False


def _watch_repository_identity(repo_root: Path) -> str:
    """Return the canonical, separator-stable identity used by watch state."""
    return normalize_file_path(_canonical_repo_root(repo_root))


def _watch_pending_repositories(store: GraphStore) -> set[str]:
    """Read roots whose derived post-processing still needs a retry.

    The value is intentionally a small JSON object rather than a process-local
    flag: daemon restarts can then recover a failed callback.  Accept a plain
    string/list as a defensive migration path for early development builds.
    """
    raw = store.get_metadata(_WATCH_POSTPROCESS_PENDING_METADATA_KEY)
    if not raw:
        return set()
    try:
        payload: Any = json.loads(raw)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        payload = raw
    if isinstance(payload, Mapping):
        values = payload.get("roots", ())
    elif isinstance(payload, (list, tuple, set, frozenset)):
        values = payload
    else:
        values = (payload,)
    roots = {
        str(value).replace("\\", "/")
        for value in values
        if isinstance(value, str) and value
    }
    # Early watch builds persisted a process-independent boolean ``"1"``.
    # It had no repository identity, so treat it as a conservative wildcard
    # for the current lifecycle pass instead of silently losing the retry.
    if payload == 1 or payload is True or (isinstance(payload, str) and payload.strip() == "1"):
        roots.add(_WATCH_PENDING_LEGACY_WILDCARD)
    return roots


def _set_watch_postprocess_pending(
    store: GraphStore,
    repo_root: Path,
    pending: bool,
) -> None:
    """Mark or clear a repository's derived post-processing retry state."""
    identity = _watch_repository_identity(repo_root)
    roots = _watch_pending_repositories(store)
    if pending:
        roots.add(identity)
    else:
        roots.discard(identity)
        roots.discard(_WATCH_PENDING_LEGACY_WILDCARD)
    if roots:
        store.set_metadata(
            _WATCH_POSTPROCESS_PENDING_METADATA_KEY,
            json.dumps({"roots": sorted(roots)}, separators=(",", ":")),
        )
        return
    # Keep the metadata table free of an empty marker.  GraphStore does not
    # expose a delete_metadata method, so use its already-open transaction
    # connection for this tiny lifecycle row.
    store._conn.execute(
        "DELETE FROM metadata WHERE key = ?",
        (_WATCH_POSTPROCESS_PENDING_METADATA_KEY,),
    )
    store._conn.commit()


def _watch_postprocess_pending(store: GraphStore, repo_root: Path) -> bool:
    """Return whether *repo_root* has a callback that must be retried."""
    roots = _watch_pending_repositories(store)
    return (
        _WATCH_PENDING_LEGACY_WILDCARD in roots
        or _watch_repository_identity(repo_root) in roots
    )


def _run_python_resolver(store: GraphStore) -> Optional[dict]:
    """Run repository-wide Python import resolution without failing a build."""
    try:
        from .python_resolver import resolve_python_imports
        return resolve_python_imports(store)
    except Exception as exc:  # noqa: BLE001 - best-effort post-pass
        logger.warning("Python import resolver failed: %s", exc)
        return None


def _run_erlang_header_resolver(
    store: GraphStore,
    repo_root: Path | None = None,
) -> Optional[dict]:
    """Resolve repository-local Erlang include and record endpoints.

    The Generic parser remains intentionally syntax-only; this lightweight
    pass is run at build boundaries so direct ``full_build`` /
    ``incremental_update`` callers receive the same canonical graph as the
    higher-level post-processing tools.  Resolver failures are non-fatal and
    leave raw endpoints available for diagnostics.
    """
    try:
        from .erlang_header_resolver import resolve_erlang_header_records

        return resolve_erlang_header_records(store, repo_root)
    except Exception as exc:  # noqa: BLE001 - optional best-effort pass
        logger.warning("Erlang header/record resolver failed: %s", exc)
        return None


def _run_rescript_resolver(store: GraphStore) -> Optional[dict]:
    """Run the ReScript cross-module resolver, swallowing any failure so
    build never fails because of it. Returns stats or None on error.
    """
    try:
        from .rescript_resolver import resolve_rescript_cross_module
        return resolve_rescript_cross_module(store)
    except Exception as exc:  # noqa: BLE001 - best-effort post-pass
        logger.warning("ReScript cross-module resolver failed: %s", exc)
        return None


def _run_spring_resolver(store: GraphStore) -> Optional[dict]:
    """Run the Spring DI call resolver, swallowing any failure so
    build never fails because of it. Returns stats or None on error.
    """
    try:
        from .spring_resolver import resolve_spring_di_calls
        return resolve_spring_di_calls(store)
    except Exception as exc:  # noqa: BLE001 - best-effort post-pass
        logger.warning("Spring DI resolver failed: %s", exc)
        return None


def _run_spring_event_resolver(store: GraphStore) -> Optional[dict]:
    """Run the Spring application-event resolver without failing a build."""
    try:
        from .event_resolver import resolve_spring_events
        return resolve_spring_events(store)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Spring event resolver failed: %s", exc)
        return None


def _run_temporal_resolver(store: GraphStore) -> Optional[dict]:
    """Run the Temporal workflow/activity call resolver, swallowing any failure so
    build never fails because of it. Returns stats or None on error.
    """
    try:
        from .temporal_resolver import resolve_temporal_calls
        return resolve_temporal_calls(store)
    except Exception as exc:  # noqa: BLE001 - best-effort post-pass
        logger.warning("Temporal resolver failed: %s", exc)
        return None


def _run_hcl_resolver(store: GraphStore) -> Optional[dict]:
    """Run Terraform module-scope resolution without failing a build."""
    try:
        from .hcl_resolver import resolve_hcl_module_references
        return resolve_hcl_module_references(store)
    except Exception as exc:  # noqa: BLE001 - best-effort post-pass
        logger.warning("Terraform/HCL resolver failed: %s", exc)
        return None


def _run_scoped_resolver(store: GraphStore) -> Optional[dict]:
    """Resolve static/scoped ``Class::method`` calls without failing a build."""
    try:
        from .scoped_resolver import resolve_scoped_calls
        return resolve_scoped_calls(store)
    except Exception as exc:  # noqa: BLE001 - best-effort post-pass
        logger.warning("Scoped call resolver failed: %s", exc)
        return None


# Default ignore patterns (in addition to .gitignore).
#
# ``**/<dir>/**`` patterns are safe-anywhere directory exclusions.  A leading
# slash anchors a pattern to the repository root, which prevents ambiguous
# output names such as ``build`` and ``dist`` from hiding nested source
# directories.  See: #91 and PR #92.
DEFAULT_IGNORE_PATTERNS = [
    "**/.code-review-graph/**",
    "**/node_modules/**",
    "**/.git/**",
    "**/.svn/**",
    "**/__pycache__/**",
    "*.pyc",
    "**/.venv/**",
    "**/venv/**",
    "/dist/**",
    "/build/**",
    "/.next/**",
    "/.nuxt/**",
    "/target/**",
    "/bin/**",
    "/obj/**",
    # PHP / Laravel / Composer
    "**/vendor/**",
    "/storage/**",
    "/bootstrap/cache/**",
    "/public/build/**",
    # Ruby / Bundler
    "**/.bundle/**",
    # Java / Kotlin / Gradle
    "**/.gradle/**",
    "*.jar",
    # Dart / Flutter
    "**/.dart_tool/**",
    "**/.pub-cache/**",
    # AWS CDK
    "**/cdk.out/**",
    # General
    "/coverage/**",
    "**/.cache/**",
    "/.tmp/**",
    "/tmp/**",  # nosec B108 -- repo-relative ignore glob, not a temp-file path
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "*.db",
    "*.sqlite",
    "*.db-journal",
    "*.db-wal",
]

# Build-output directories that ``DEFAULT_IGNORE_PATTERNS`` only anchors at the
# repository root.  A nested copy is ignored as well, but only when a sibling
# manifest proves the directory is that module's build output — ``moduleA/pom.xml``
# next to ``moduleA/target/``.  Without that evidence the nested directory keeps
# being parsed and watched, so the root anchoring from #91/#92 still protects
# everyone whose nested ``build/`` or ``dist/`` holds real sources.  See: #811.
NESTED_OUTPUT_DIR_MARKERS: dict[str, frozenset[str]] = {
    "target": frozenset({"pom.xml", "Cargo.toml", "build.sbt"}),
    "build": frozenset({
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    }),
    ".next": frozenset({
        "next.config.js",
        "next.config.mjs",
        "next.config.cjs",
        "next.config.ts",
    }),
    ".nuxt": frozenset({"nuxt.config.js", "nuxt.config.mjs", "nuxt.config.ts"}),
}

# Bounds for the nested build-output scan.  The scan only lists directories
# (no file stats), stops at ``CRG_MODULE_SCAN_DEPTH`` levels, never descends
# into an already-ignored tree, and its result is cached per repository so
# incremental updates never pay for it twice inside the TTL.
_MODULE_SCAN_DEPTH = int(os.environ.get("CRG_MODULE_SCAN_DEPTH", "3"))
_MODULE_SCAN_MAX_DIRS = int(os.environ.get("CRG_MODULE_SCAN_MAX_DIRS", "2000"))
_MAX_NESTED_OUTPUT_PATTERNS = 200
_NESTED_IGNORE_TTL_SECONDS = float(os.environ.get("CRG_NESTED_IGNORE_TTL", "300"))

_nested_ignore_cache: dict[tuple[str, tuple[str, ...]], tuple[float, list[str]]] = {}
_nested_ignore_lock = threading.Lock()


def find_svn_root(start: Path | None = None) -> Optional[Path]:
    """Walk up from start to find the SVN working copy root.

    For SVN 1.7+, there is a single ``.svn`` at the WC root.
    For older SVN, every directory has ``.svn`` — we return the topmost one
    found so that the WC root is correctly identified.
    """
    current = start or Path.cwd()
    candidate: Optional[Path] = None
    while current != current.parent:
        if (current / ".svn").exists():
            candidate = current
        current = current.parent
    if (current / ".svn").exists():
        candidate = current
    return candidate


def find_repo_root(
    start: Path | None = None,
    stop_at: Path | None = None,
) -> Optional[Path]:
    """Walk up from ``start`` to find the nearest ``.git`` directory or SVN working copy root.

    Args:
        start: Starting directory.  Defaults to ``Path.cwd()``.
        stop_at: Optional boundary — if provided, the walk examines
            ``stop_at`` for a ``.git`` directory and then stops without
            crossing above it.  Useful for tests that create a synthetic
            repo under ``tmp_path`` (so the walk does not accidentally
            climb into a developer's home-directory dotfiles repo) and
            for any production caller that wants to bound the ancestor
            walk — e.g. multi-repo orchestrators, CI containers with
            bind-mounted volumes, embedded sandboxes.  See #241.

    Returns:
        The first ancestor containing ``.git`` or an SVN working copy,
        or ``None`` if no ancestor up to and including ``stop_at`` (when
        set) or the filesystem root (when ``stop_at is None``) contains one.
    """
    current = start or Path.cwd()
    while current != current.parent:
        if (current / ".git").exists():
            return current
        if stop_at is not None and current == stop_at:
            return None
        current = current.parent
    if (current / ".git").exists():
        return current
    # No Git root found — try SVN
    return find_svn_root(start)


def detect_vcs(root: Path) -> str:
    """Return ``'git'``, ``'svn'``, or ``'none'`` based on VCS markers at *root*."""
    if (root / ".git").exists():
        return "git"
    if (root / ".svn").exists():
        return "svn"
    return "none"


def find_project_root(
    start: Path | None = None,
    stop_at: Path | None = None,
) -> Path:
    """Find the project root.

    Resolution order (highest precedence first):

    1. ``CRG_REPO_ROOT`` environment variable — explicit override for
       anyone scripting the CLI from outside the repo (CI jobs, daemons,
       multi-repo orchestrators). See: #155
    2. Git repository root via :func:`find_repo_root` from ``start``,
       honoring ``stop_at`` if provided.
    3. ``start`` itself (or cwd if no start given).

    ``stop_at`` is forwarded to :func:`find_repo_root` so callers that
    want to bound the ancestor walk (typically tests; see #241) can do so
    without having to call ``find_repo_root`` directly.
    """
    env_override = os.environ.get("CRG_REPO_ROOT", "").strip()
    if env_override:
        p = Path(env_override).expanduser().resolve()
        if p.exists():
            return p
    root = find_repo_root(start, stop_at=stop_at)
    if root:
        return root
    return start or Path.cwd()


def _write_data_dir_gitignore(data_dir: Path) -> None:
    """Write .gitignore file in data directory if it doesn't exist.

    The gitignore contains a single '*' to prevent accidental commits.
    """
    inner_gitignore = data_dir / ".gitignore"
    if not inner_gitignore.exists():
        try:
            # `encoding="utf-8"` is REQUIRED — the em-dash in the header is
            # U+2014 which falls outside cp1252.  On Windows, calling
            # write_text without an encoding silently uses the system default
            # codepage, producing a file that subsequently fails to decode as
            # UTF-8 (see issue #239).
            inner_gitignore.write_text(
                "# Auto-generated by code-review-graph — do not commit database files.\n"
                "# The graph.db contains absolute paths and code structure metadata.\n"
                "*\n",
                encoding="utf-8",
            )
        except OSError:
            # Data dir might be read-only (rare); that's OK, it's a best-effort guard.
            pass


def get_data_dir(repo_root: Path, *, create: bool = True) -> Path:
    """Return the directory where this project's graph data lives.

    Resolution priority:
    1. Registry entry for this repo (set via --data-dir)
    2. CRG_DATA_DIR environment variable (global override)
    3. Default: <repo>/.code-review-graph/

    By default, ``<repo_root>/.code-review-graph``. If the
    ``CRG_DATA_DIR`` environment variable is set, it is used verbatim
    instead — letting you keep graphs outside the working tree (useful
    for ephemeral workspaces, Docker volumes, or shared caches). See: #155

    By default the directory is created if it does not already exist; an
    inner ``.gitignore`` (with ``*``) is written so any accidentally-nested
    files never get committed. Both are idempotent. Pass ``create=False``
    when resolving the path for a read-only existence check.
    """
    # Check registry first
    try:
        from .registry import Registry, default_registry_path

        # Registry construction creates its parent directory. A read-only
        # lookup must skip it entirely when no registry file exists.
        if create or default_registry_path().is_file():
            registry_data_dir = Registry().get_data_dir_for_repo(str(repo_root))
            if registry_data_dir:
                data_dir = Path(registry_data_dir).resolve()
                if create:
                    data_dir.mkdir(parents=True, exist_ok=True)
                    _write_data_dir_gitignore(data_dir)
                return data_dir
    except Exception as exc:
        # If registry lookup fails, log and fall through to other methods
        logger.debug("Registry lookup failed for %s: %s", repo_root, exc)

    # Check environment variable
    env_override = os.environ.get("CRG_DATA_DIR", "").strip()
    if env_override:
        data_dir = Path(env_override).expanduser().resolve()
    else:
        data_dir = repo_root / ".code-review-graph"

    if create:
        data_dir.mkdir(parents=True, exist_ok=True)
        _write_data_dir_gitignore(data_dir)

    return data_dir


def get_db_path(repo_root: Path, *, read_only: bool = False) -> Path:
    """Determine the database path for a repository.

    Respects ``CRG_DATA_DIR`` (see :func:`get_data_dir`). Migrates a
    legacy top-level ``.code-review-graph.db`` file into the new
    directory when it exists (WAL/SHM side-files are discarded). Pass
    ``read_only=True`` to resolve the current path without creating a data
    directory, migrating a legacy database, or deleting side-files.
    """
    crg_dir = get_data_dir(repo_root, create=not read_only)
    new_db = crg_dir / "graph.db"

    if read_only:
        return new_db

    # Migrate legacy database if present (only meaningful when the
    # legacy file sits at the repo root — if CRG_DATA_DIR is set we
    # skip the migration because there's no relationship between the
    # legacy location and the new one).
    legacy_db = repo_root / ".code-review-graph.db"
    if legacy_db.exists() and not new_db.exists():
        legacy_db.rename(new_db)
    # Discard stale WAL/SHM side-files from the old location
    for suffix in ("-wal", "-shm", "-journal"):
        side = repo_root / f".code-review-graph.db{suffix}"
        if side.exists():
            side.unlink()

    return new_db


def ensure_repo_gitignore_excludes_crg(repo_root: Path) -> str:
    """Ensure repo-level .gitignore excludes ``.code-review-graph/``.

    Returns one of:
    - ``created``: .gitignore was created with the entry
    - ``updated``: entry was appended to existing .gitignore
    - ``already-present``: no changes were needed
    """
    gitignore_path = repo_root / ".gitignore"
    existing = gitignore_path.read_text(encoding="utf-8") if gitignore_path.exists() else ""

    for raw_line in existing.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == ".code-review-graph" or line.startswith(".code-review-graph/"):
            return "already-present"

    block = "# Added by code-review-graph\n.code-review-graph/\n"
    prefix = "\n" if existing and not existing.endswith("\n") else ""
    gitignore_path.write_text(existing + prefix + block, encoding="utf-8")

    if existing:
        return "updated"
    return "created"


def _load_ignore_patterns(repo_root: Path) -> list[str]:
    """Load ignore patterns from .code-review-graphignore file.

    A line starting with ``!`` keeps a path out of the automatic nested
    build-output detection (see :data:`NESTED_OUTPUT_DIR_MARKERS`); it does not
    negate the explicit patterns, which keep their existing meaning.
    """
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    keep: list[str] = []
    ignore_file = repo_root / ".code-review-graphignore"
    if ignore_file.exists():
        for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                if line.startswith("!"):
                    keep.append(line[1:].strip().strip("/"))
                    continue
                # Directory names without a slash match at any depth, as in
                # .gitignore. A leading slash remains an explicit root anchor.
                if line.endswith("/"):
                    prefix = line[:-1]
                    if prefix.startswith("/") or "/" in prefix:
                        line = f"{prefix}/**"
                    else:
                        line = f"**/{prefix}/**"
                elif line.endswith("/**") and not line.startswith(("/", "**/")):
                    prefix = line[:-3]
                    if "/" in prefix:
                        line = f"/{line}"
                    else:
                        line = f"**/{line}"
                if line:
                    patterns.append(line)
    patterns.extend(_nested_output_ignore_patterns(repo_root, patterns, tuple(keep)))
    return patterns


def _should_ignore(path: str, patterns: list[str]) -> bool:
    """Check if a path matches any ignore pattern.

    ``**/<dir>/**`` and unanchored single-directory patterns match at any
    depth. A leading slash anchors a pattern to the repository root.
    """
    normalized = path.replace("\\", "/").lstrip("/")
    parts = PurePosixPath(normalized).parts
    for pattern in patterns:
        anchored = pattern.startswith("/")
        candidate = pattern[1:] if anchored else pattern

        if candidate.startswith("**/") and candidate.endswith("/**"):
            segment = candidate[3:-3]
            if segment and segment in parts:
                return True
            continue

        if candidate.endswith("/**"):
            prefix = tuple(part for part in candidate[:-3].split("/") if part)
            if not prefix:
                continue
            if anchored or len(prefix) > 1:
                if parts[: len(prefix)] == prefix:
                    return True
            elif prefix[0] in parts:
                return True
            continue

        if fnmatch.fnmatch(normalized, candidate):
            return True
    return False


def _child_directories(directory: Path) -> list[tuple[str, bool]]:
    """List ``directory`` once, returning ``(name, is_dir)`` for its entries.

    Symlinked directories are reported as non-directories so no walk follows
    them out of the repository.  Returns an empty list for anything that
    cannot be listed — an unreadable directory is not worth a failed watch.
    """
    try:
        with os.scandir(directory) as entries:
            listing: list[tuple[str, bool]] = []
            for entry in entries:
                try:
                    listing.append((entry.name, entry.is_dir(follow_symlinks=False)))
                except OSError:  # pragma: no cover - vanished mid-scan
                    continue
    except OSError as exc:
        logger.debug("Cannot list %s: %s", directory, exc)
        return []
    listing.sort()
    return listing


def _scan_nested_output_dirs(
    repo_root: Path,
    base_patterns: list[str],
    max_depth: int = _MODULE_SCAN_DEPTH,
    max_dirs: int = _MODULE_SCAN_MAX_DIRS,
) -> list[str]:
    """Find nested build-output directories that a sibling manifest confirms.

    Returns root-anchored ignore patterns such as ``/moduleA/target/**``.  The
    walk lists directories only, skips trees the base patterns already ignore,
    and is bounded by *max_depth* and *max_dirs*.
    """
    patterns: list[str] = []
    queue: list[tuple[Path, int]] = [(repo_root, 0)]
    visited = 0
    while queue:
        directory, depth = queue.pop()
        visited += 1
        if visited > max_dirs:
            logger.debug("Nested output scan hit the %d directory cap", max_dirs)
            break
        listing = _child_directories(directory)
        subdirectories = {name for name, is_dir in listing if is_dir}
        file_names = {name for name, is_dir in listing if not is_dir}
        flagged: set[str] = set()
        if depth > 0:
            for output_dir, markers in NESTED_OUTPUT_DIR_MARKERS.items():
                if output_dir in subdirectories and file_names & markers:
                    relative = (directory / output_dir).relative_to(repo_root).as_posix()
                    patterns.append(f"/{relative}/**")
                    flagged.add(output_dir)
                    if len(patterns) >= _MAX_NESTED_OUTPUT_PATTERNS:
                        logger.debug("Nested output scan hit the pattern cap")
                        return patterns
        if depth >= max_depth:
            continue
        for name in subdirectories:
            if name in flagged:
                continue
            child = directory / name
            if _should_ignore(child.relative_to(repo_root).as_posix(), base_patterns):
                continue
            queue.append((child, depth + 1))
    return patterns


def _nested_output_ignore_patterns(
    repo_root: Path,
    base_patterns: list[str],
    keep: tuple[str, ...] = (),
) -> list[str]:
    """Cached wrapper around :func:`_scan_nested_output_dirs`.

    The result is reused for ``_NESTED_IGNORE_TTL_SECONDS`` so a long-running
    watch pays for the scan once, not on every incremental update, while a
    module added later is still picked up without a restart.  Set
    ``CRG_NESTED_OUTPUT_SCAN=0`` to turn the whole thing off, or list
    ``!some/path`` in ``.code-review-graphignore`` to spare one directory.

    Excluding a directory removes its files from the graph, so the result is
    logged at info level: an unexpected exclusion has to be discoverable from
    a normal build, not only by diffing file counts.
    """
    if os.environ.get("CRG_NESTED_OUTPUT_SCAN", "1").strip().lower() in ("0", "false", "no"):
        return []
    key = (str(repo_root), keep)
    now = time.monotonic()
    with _nested_ignore_lock:
        cached = _nested_ignore_cache.get(key)
        if cached is not None and now - cached[0] < _NESTED_IGNORE_TTL_SECONDS:
            return list(cached[1])
    patterns = _scan_nested_output_dirs(repo_root, base_patterns)
    if keep:
        spared = {entry.replace("\\", "/").strip("/") for entry in keep}
        patterns = [
            pattern for pattern in patterns if pattern[1:-3] not in spared
        ]
    if patterns:
        logger.info(
            "Excluding %d nested build-output director%s (a sibling manifest marks "
            "them as build output; keep one with '!<path>' in "
            ".code-review-graphignore): %s",
            len(patterns),
            "y" if len(patterns) == 1 else "ies",
            ", ".join(pattern[1:-3] for pattern in patterns[:10])
            + (" …" if len(patterns) > 10 else ""),
        )
    with _nested_ignore_lock:
        _nested_ignore_cache[key] = (time.monotonic(), patterns)
    return list(patterns)


def clear_nested_ignore_cache() -> None:
    """Drop the cached nested build-output patterns (used by tests)."""
    with _nested_ignore_lock:
        _nested_ignore_cache.clear()


def _is_binary(path: Path) -> bool:
    """Quick heuristic: check if file appears to be binary."""
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


_GIT_TIMEOUT = int(os.environ.get("CRG_GIT_TIMEOUT", "30"))  # seconds, configurable

# When True, `git ls-files --recurse-submodules` is used so that files
# inside git submodules are included in the graph.  Opt-in via env var;
# can also be overridden per-call through function parameters.
_RECURSE_SUBMODULES = os.environ.get("CRG_RECURSE_SUBMODULES", "").lower() in ("1", "true", "yes")


def _git_branch_info(repo_root: Path) -> tuple[str, str]:
    """Return (branch_name, head_sha) for the current repo state."""
    branch = ""
    sha = ""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True, encoding='utf-8', errors='replace',
            cwd=str(repo_root),
            timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            branch = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, UnicodeDecodeError):
        pass
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True, encoding='utf-8', errors='replace',
            cwd=str(repo_root),
            timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            sha = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, UnicodeDecodeError):
        pass
    return branch, sha


def _svn_revision_info(repo_root: Path) -> tuple[str, str]:
    """Return (branch_path, revision_str) for the current SVN working copy."""
    branch = ""
    rev = ""
    try:
        result = subprocess.run(
            ["svn", "info", "--non-interactive"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(repo_root), timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("URL: "):
                    url = line[5:].strip()
                    # Extract trunk/branches/tags segment from SVN URL
                    for marker in ("/branches/", "/tags/", "/trunk"):
                        if marker in url:
                            idx = url.index(marker)
                            branch = url[idx:].lstrip("/")
                            break
                    if not branch and url:
                        branch = url.rstrip("/").split("/")[-1]
                elif line.startswith("Revision: "):
                    rev = line[10:].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return branch, rev


_SAFE_GIT_REF = re.compile(r"^[A-Za-z0-9_.~^/@{}\-]+$")
_SAFE_SVN_REV = re.compile(r"^r?\d+(:r?\d+|:HEAD|:BASE|:COMMITTED)?$", re.IGNORECASE)


def _decode_name_status_paths(output: bytes) -> list[str]:
    """Decode ``git diff --name-status -z`` output into a list of paths.

    Renames and copies (``R<score>``/``C<score>`` records) carry two paths —
    the old and the new one.  Both are emitted so the old path flows through
    the purge loop in :func:`incremental_update`; otherwise a rename leaves
    the old path's nodes and edges in the graph and the incremental result
    diverges from a full rebuild.
    """
    fields = [os.fsdecode(f) for f in output.split(b"\0") if f]
    paths: list[str] = []
    seen: set[str] = set()
    i = 0
    while i < len(fields):
        status = fields[i]
        takes_two = status[:1] in ("R", "C")
        entry = fields[i + 1 : i + (3 if takes_two else 2)]
        i += 3 if takes_two else 2
        for path in entry:
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _store_vcs_metadata(repo_root: Path, store: "GraphStore") -> None:
    """Persist VCS branch/revision info into the graph metadata table."""
    vcs = detect_vcs(repo_root)
    if vcs == "git":
        branch, sha = _git_branch_info(repo_root)
        if branch:
            store.set_metadata("git_branch", branch)
        if sha:
            store.set_metadata("git_head_sha", sha)
    elif vcs == "svn":
        branch, rev = _svn_revision_info(repo_root)
        if branch:
            store.set_metadata("svn_branch", branch)
        if rev:
            store.set_metadata("svn_revision", rev)


def _commit_object_exists(repo_root: Path, ref: str) -> bool:
    """Return True if *ref* resolves to a commit object present in the repo.

    This is an object-existence check, not an ancestry check: a commit that is
    only reachable from a branch we have since switched away from is still a
    valid ``git diff`` base, so we must accept it. Any git failure (missing
    binary, timeout, unknown ref) is treated as "not usable".
    """
    if not ref or ref.startswith("-") or not _SAFE_GIT_REF.fullmatch(ref):
        return False
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            capture_output=True,
            cwd=str(repo_root),
            timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def resolve_incremental_base(repo_root: Path, store: "GraphStore") -> str | None:
    """Resolve the automatic diff base for a default incremental update.

    The graph records the commit it was last built at (``git_head_sha``). Using
    that as the diff base lets a single ``update`` reconcile every change since
    the graph was last in sync, instead of only the most recent commit, which
    is what a fixed ``HEAD~1`` base does. That fixed base silently misses work
    that arrived through a multi-commit pull, rebase, or branch switch.

    Returns:
        - the stored commit SHA when it is still a usable diff base;
        - ``"HEAD~1"`` for SVN or non-git working copies, whose change
          discovery ignores or reinterprets the base anyway;
        - ``None`` for a git repo with no usable anchor (a fresh or legacy
          database, or a stored commit lost to a history rewrite or shallow
          clone), signalling the caller to do a full rebuild rather than
          diff against a wrong base.
    """
    if detect_vcs(repo_root) != "git":
        return "HEAD~1"
    stored = store.get_metadata("git_head_sha")
    if stored and _commit_object_exists(repo_root, stored):
        return stored
    return None


def get_changed_files(repo_root: Path, base: str = "HEAD~1") -> list[str]:
    """Get list of changed files via git diff or svn status.

    For SVN working copies the *base* parameter is ignored; modified/added/
    deleted files are detected from ``svn status``.  Pass an SVN revision
    range (e.g. ``"r100:HEAD"``) as *base* to compare against a specific
    revision instead.
    """
    if detect_vcs(repo_root) == "svn":
        return _get_svn_changed_files(repo_root, base if _SAFE_SVN_REV.match(base) else None)
    # Git path
    if base.startswith("-") or not _SAFE_GIT_REF.fullmatch(base):
        logger.warning("Invalid git ref rejected: %s", base)
        return []
    try:
        # --name-status (not --name-only): renames/copies must report BOTH
        # paths, or the old path never reaches the purge loop (issue #684).
        result = subprocess.run(
            ["git", "diff", "--name-status", "-z", base, "--"],
            capture_output=True,
            cwd=str(repo_root),
            timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            # Fallback: try diff against empty tree (initial commit)
            result = subprocess.run(
                ["git", "diff", "--name-status", "-z", "--cached"],
                capture_output=True,
                cwd=str(repo_root),
                timeout=_GIT_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
        if result.returncode != 0:
            logger.warning("git diff failed while discovering changed files")
            return []
        return _decode_name_status_paths(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

def _get_svn_changed_files(repo_root: Path, rev_range: str | None = None) -> list[str]:
    """Return changed files in an SVN working copy.

    When *rev_range* is given (e.g. ``"r100:HEAD"``), ``svn diff --summarize``
    is used to list files changed between those revisions.  Otherwise
    ``svn status`` reports working-copy modifications.
    """
    try:
        if rev_range:
            result = subprocess.run(
                ["svn", "diff", "--summarize", "--non-interactive", "-r", rev_range],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                cwd=str(repo_root), timeout=_GIT_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
            if result.returncode != 0:
                logger.warning("svn diff --summarize failed (rc=%d): %s",
                               result.returncode, result.stderr[:200])
                return []
            files = []
            for line in result.stdout.splitlines():
                # Format: "M       path/to/file"  (first char is status)
                if len(line) >= 2 and line[0] in ("M", "A", "D"):
                    files.append(line[1:].strip())
            return files
        else:
            result = subprocess.run(
                ["svn", "status", "--non-interactive"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                cwd=str(repo_root), timeout=_GIT_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
            files = []
            for line in result.stdout.splitlines():
                if len(line) < 2:
                    continue
                status_char = line[0]
                # M=modified, A=added, D=deleted, R=replaced, C=conflicted
                if status_char in ("M", "A", "D", "R", "C"):
                    # SVN status: 8 fixed-width columns then the path
                    path = line[8:].strip() if len(line) > 8 else line[1:].strip()
                    files.append(path)
            return files
    except (FileNotFoundError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return []

def get_staged_and_unstaged(repo_root: Path) -> list[str]:
    """Get all modified files (staged + unstaged + untracked)."""
    if detect_vcs(repo_root) == "svn":
        return _get_svn_changed_files(repo_root)
    try:
        result = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ],
            capture_output=True,
            cwd=str(repo_root),
            timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            logger.warning("git status failed while discovering working-tree files")
            return []
        files: list[str] = []
        records = result.stdout.split(b"\0")
        index = 0
        while index < len(records):
            record = records[index]
            if len(record) > 3:
                status = record[:2]
                files.append(os.fsdecode(record[3:]))
                # With porcelain -z, a rename/copy record stores the
                # destination first and its source in the following record.
                if b"R" in status or b"C" in status:
                    index += 1
            index += 1
        return files
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

def get_all_tracked_files(
    repo_root: Path,
    recurse_submodules: bool | None = None,
) -> list[str]:
    """Get all files tracked by git or svn.

    Args:
        repo_root: Repository root directory.
        recurse_submodules: If True, pass ``--recurse-submodules`` to
            ``git ls-files`` so that files inside git submodules are
            included.  When *None* (default), falls back to the
            ``CRG_RECURSE_SUBMODULES`` environment variable.
            (Ignored for SVN working copies.)
    """
    if detect_vcs(repo_root) == "svn":
        return _get_svn_all_tracked_files(repo_root)

    if recurse_submodules is None:
        recurse_submodules = _RECURSE_SUBMODULES

    cmd = ["git", "ls-files"]
    if recurse_submodules:
        cmd.append("--recurse-submodules")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True, encoding='utf-8', errors='replace',
            cwd=str(repo_root),
            timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return []

def _get_svn_all_tracked_files(repo_root: Path) -> list[str]:
    """Return SVN-versioned files by walking the working copy.

    Uses ``svn list -R`` to get the server-side file list, falling back to
    a filesystem walk (which is also the fallback in :func:`collect_all_files`).
    """
    try:
        result = subprocess.run(
            ["svn", "list", "--recursive", "--non-interactive"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(repo_root), timeout=60,  # svn list queries the server
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            # svn list returns paths relative to the WC URL; directories end with "/"
            files = [
                f.strip()
                for f in result.stdout.splitlines()
                if f.strip() and not f.strip().endswith("/")
            ]
            if files:
                return files
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Fallback: let collect_all_files do a filesystem walk
    return []


def collect_all_files(
    repo_root: Path,
    recurse_submodules: bool | None = None,
) -> list[str]:
    """Collect all parseable files in the repo, respecting ignore patterns.

    Args:
        repo_root: Repository root directory.
        recurse_submodules: If True, include files from git submodules.
            When *None*, falls back to ``CRG_RECURSE_SUBMODULES`` env var.
    """
    ignore_patterns = _load_ignore_patterns(repo_root)
    parser = CodeParser(repo_root)
    files = []

    # Prefer git ls-files for tracked files
    tracked = get_all_tracked_files(repo_root, recurse_submodules)
    if tracked:
        candidates = tracked
    else:
        # Fallback: walk directory
        candidates = [str(p.relative_to(repo_root)) for p in repo_root.rglob("*") if p.is_file()]

    for rel_path in candidates:
        if _should_ignore(rel_path, ignore_patterns):
            continue
        # Skip paths that would exceed OS filename limits (macOS: 255 bytes
        # per component, ~1024 total; Windows: 260 total).
        try:
            full_path = repo_root / rel_path
        except (OSError, ValueError):
            logger.debug("Skipping path that cannot be constructed: %s", rel_path)
            continue
        if len(str(full_path)) > 1000 or any(len(p.encode()) > 255 for p in full_path.parts):
            logger.debug("Skipping overlong path: %s", rel_path[:120])
            continue
        if not full_path.is_file():
            continue
        if full_path.is_symlink():
            continue
        if parser.detect_language(full_path) is None:
            continue
        if _is_binary(full_path):
            continue
        files.append(rel_path)

    return files


def _reconcile_stale_files(
    repo_root: Path,
    store: GraphStore,
    current_files: list[str] | None = None,
    *,
    dependent_files: set[str] | None = None,
) -> list[str]:
    """Remove current-root files absent from the parseable inventory.

    A GraphStore can intentionally be shared by more than one checkout.  In
    that case a repository-wide ``get_all_files() - current_files`` diff would
    mistake the other checkout for stale data and delete it.  File markers are
    the authoritative ownership signal: when any marker is foreign, scope
    cleanup to paths under the requested root and leave all foreign rows alone.
    With no foreign marker we retain the historical orphan purge, including
    edge-only rows whose ownership cannot be recovered.
    """
    all_stored_files = set(store.get_all_files())
    marker_paths = store.get_file_marker_paths()
    root_prefix = normalize_file_path(repo_root).rstrip("/") + "/"

    def belongs_to_root(path: str) -> bool:
        normalized = normalize_file_path(path)
        if normalized.startswith(root_prefix):
            return True
        # Relative rows occur in legacy databases and are interpreted in the
        # context of the requested checkout.  This also preserves the prior
        # Windows-path behavior where a drive-qualified spelling is normalized
        # textually rather than by the host OS Path implementation.
        if not Path(normalized).is_absolute() and ":/" not in normalized:
            return True
        return False

    foreign_markers = [path for path in marker_paths if not belongs_to_root(path)]
    stored_files = (
        {path for path in all_stored_files if belongs_to_root(path)}
        if foreign_markers
        else all_stored_files
    )
    current_paths: set[str]
    if current_files is not None:
        current_paths = {
            normalize_file_path(repo_root / file_path) for file_path in current_files
        }
    else:
        ignore_patterns = _load_ignore_patterns(repo_root)
        parser = CodeParser(repo_root)
        current_paths = set()
        for stored_file in stored_files:
            path = Path(stored_file)
            if not path.is_absolute():
                # Legacy stores may use repository-relative file markers.  The
                # marker spelling remains unchanged in ``current_paths`` so
                # reconciliation does not rewrite graph identities merely by
                # opening an older database.
                path = repo_root / path
            try:
                relative = str(path.relative_to(repo_root))
            except ValueError:
                continue
            if (
                path.is_file()
                and not path.is_symlink()
                and not _should_ignore(relative, ignore_patterns)
                and parser.detect_language(path) is not None
                and not _is_binary(path)
            ):
                current_paths.add(stored_file)
    stale_files = sorted(stored_files - current_paths)
    # Capture referrers before removing stale nodes and their incoming edges.
    # This is especially important for Erlang headers: their parser edges are
    # textual until reconciliation, and ``remove_files_permanently`` removes
    # the very evidence needed to discover consumers afterward.
    if stale_files and dependent_files is not None:
        dependent_files.update(
            _transitive_stale_dependents(
                store, stale_files, repo_root=repo_root
            )
        )
    if stale_files:
        store.remove_files_permanently(stale_files)
    return stale_files


def _assert_graph_matches_root(repo_root: Path, store: GraphStore) -> None:
    """Refuse an incremental reconciliation anchored to a different root.

    Authoritative File nodes identify the root a graph was built with. If none
    of them are under the requested root, treating every row as stale is more
    likely to destroy a usable graph than to clean up orphan rows. Orphan-only
    databases have no File markers and retain the purge behavior from #861.
    """
    file_paths = store.get_file_marker_paths()
    if not file_paths:
        return
    root = Path(repo_root).expanduser().resolve(strict=False)
    prefix = normalize_file_path(root)
    prefix = prefix if prefix.endswith("/") else prefix + "/"
    for path in file_paths:
        normalized = normalize_file_path(path)
        if normalized.startswith(prefix):
            return
        # Legacy databases may store repository-relative File markers.  They
        # have no independent origin to compare, so interpret them in the
        # explicitly requested checkout; reject traversal rows instead of
        # treating them as a foreign absolute path.
        if not Path(normalized).is_absolute() and ":/" not in normalized:
            if ".." not in PurePosixPath(normalized).parts:
                return
    sample = normalize_file_path(sorted(file_paths)[0])
    raise RuntimeError(
        f"the graph holds {len(file_paths)} file(s) such as {sample!r}, none of "
        f"them under {str(repo_root)!r}; it was built with a different "
        "repository root. Rebuild it, or retry with the root it was built "
        "with, instead of reconciling every file away."
    )


def _assert_changed_files_belong_to_root(
    repo_root: Path, changed_files: list[str] | tuple[str, ...]
) -> None:
    """Reject explicit incremental inputs outside the requested checkout."""
    foreign = [
        str(path)
        for path in changed_files
        if str(path).strip() and not _path_belongs_to_root(path, repo_root)
    ]
    if foreign:
        raise ValueError(
            f"changed_files contains a path outside repository root "
            f"{repo_root!s}: {foreign[0]!r}"
        )


_MAX_DEPENDENT_HOPS = int(os.environ.get("CRG_DEPENDENT_HOPS", "2"))
_MAX_DEPENDENT_FILES = 500


def _single_hop_dependents(store: GraphStore, file_path: str) -> set[str]:
    """Find files that directly depend on *file_path* (single hop)."""
    dependents: set[str] = set()
    edges = store.get_edges_by_target(file_path)
    for e in edges:
        if e.kind == "IMPORTS_FROM":
            dependents.add(e.file_path)

    nodes = store.get_nodes_by_file(file_path)
    for node in nodes:
        for e in store.get_edges_by_target(node.qualified_name):
            if e.kind in ("CALLS", "IMPORTS_FROM", "INHERITS", "IMPLEMENTS"):
                dependents.add(e.file_path)

    # Older graphs may still contain the textual spelling emitted by the
    # Erlang parser (for example ``sample.hrl``) instead of the canonical
    # header path.  Recover those incoming include edges only when the
    # basename identifies one header in the graph.  A duplicate basename is
    # deliberately left unresolved: selecting one sibling application's
    # header would schedule unrelated files and can corrupt later resolution.
    target_name = Path(file_path).name
    if target_name.casefold().endswith(".hrl"):
        matching_files = {
            candidate
            for candidate in store.get_all_files()
            if Path(candidate).name.casefold() == target_name.casefold()
        }
        if matching_files == {file_path}:
            rows = store._conn.execute(
                "SELECT file_path, extra FROM edges "
                "WHERE kind = 'IMPORTS_FROM' AND "
                "(lower(target_qualified) = lower(?) OR "
                "lower(target_qualified) LIKE lower(?))",
                (target_name, f"%/{target_name}"),
            ).fetchall()
            for row in rows:
                try:
                    extra = json.loads(row["extra"] or "{}")
                except (TypeError, ValueError, UnicodeError, RecursionError):
                    extra = {}
                import_kind = (
                    extra.get("erlang_import_kind")
                    if isinstance(extra, dict)
                    else None
                )
                # New parser rows identify the managed include explicitly;
                # legacy rows without metadata are accepted only when their
                # owner is an Erlang source/header, preventing another
                # language's textual include from entering this path.
                if import_kind in {"pp_include", "pp_include_lib"} or (
                    not import_kind
                    and _is_erlang_source_path(str(row["file_path"]))
                ):
                    dependents.add(row["file_path"])

    dependents.discard(file_path)
    return dependents


def _single_hop_erlang_include_dependents(
    store: GraphStore,
    file_path: str,
    repo_root: Path | None = None,
) -> set[str]:
    """Find direct consumers through managed Erlang preprocessor includes.

    This intentionally ignores ordinary ``CALLS``/inheritance edges.  It is
    used only while a stale header is still present in the graph, when an
    include chain may need to be walked before the stale rows are removed.
    """
    target = normalize_file_path(file_path)
    target_path = Path(str(file_path).replace("\\", "/"))
    if not target_path.is_absolute() and repo_root is not None:
        target_path = repo_root / target_path
    try:
        target = normalize_file_path(target_path.resolve(strict=False))
    except (OSError, RuntimeError):
        pass
    target_name = Path(target).name.casefold()
    header_candidates = {
        normalize_file_path(path if Path(path).is_absolute() else (
            repo_root / path if repo_root is not None else Path(path)
        ))
        for path in store.get_all_files()
        if str(path).replace("\\", "/").casefold().endswith(".hrl")
    }
    unique_basename = {
        path for path in header_candidates if Path(path).name.casefold() == target_name
    } == {target}

    rows = store._conn.execute(
        "SELECT file_path, target_qualified, extra FROM edges "
        "WHERE kind = 'IMPORTS_FROM' AND "
        # SQLite may reorder predicates, so a standalone json_valid() guard
        # does not protect json_extract() from malformed legacy rows.  Keep
        # the extraction inside CASE to make the fail-closed boundary
        # independent of the query planner.
        "CASE WHEN typeof(extra) = 'text' AND json_valid(extra) = 1 THEN "
        "json_extract(extra, '$.erlang_import_kind') ELSE NULL END IN "
        "('pp_include', 'pp_include_lib')"
    ).fetchall()
    dependents: set[str] = set()
    for row in rows:
        raw_extra = row["extra"]
        try:
            decoded = json.loads(raw_extra or "{}")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            decoded = {}
        raw_target = (
            decoded.get("erlang_raw_target")
            if isinstance(decoded, dict)
            else None
        )
        spellings = [str(row["target_qualified"])]
        if isinstance(raw_target, str) and raw_target:
            spellings.append(raw_target)
        matched = False
        for spelling in spellings:
            candidate = str(spelling).replace("\\", "/")
            candidate_path = Path(candidate)
            if not candidate_path.is_absolute() and repo_root is not None:
                candidate_path = repo_root / candidate_path
            try:
                normalized = normalize_file_path(candidate_path.resolve(strict=False))
            except (OSError, RuntimeError):
                normalized = normalize_file_path(candidate)
            if normalized == target:
                matched = True
                break
        if not matched and unique_basename:
            matched = any(Path(spelling.replace("\\", "/")).name.casefold() == target_name
                          for spelling in spellings)
        if matched:
            dependents.add(str(row["file_path"]))
    dependents.discard(file_path)
    return dependents


def _transitive_stale_dependents(
    store: GraphStore,
    stale_files: Iterable[str],
    *,
    repo_root: Path | None = None,
) -> set[str]:
    """Return the bounded reverse dependency closure of stale files.

    Stale rows must be inspected before they are removed.  In an Erlang
    include chain such as ``consumer -> middle.hrl -> base.hrl``, deleting
    ``base.hrl`` removes the middle header's incoming edge as part of the
    node cleanup; a one-hop lookup therefore cannot discover ``consumer``.
    Traverse through stale intermediate files while retaining only live
    consumers for reparsing.  The traversal is deterministic and shares the
    same global cap as :func:`find_dependents` so a pathological include fan
    out cannot make an incremental update unbounded.
    """
    stale_spellings = [str(path) for path in stale_files]
    # This closure exists for nested Erlang preprocessor includes.  Ordinary
    # stale files retain the established one-hop dependency behavior; walking
    # CALLS/INHERITS transitively here would unexpectedly enlarge unrelated
    # Python/Java incremental updates.
    stale_spellings = [
        path for path in stale_spellings
        if path.replace("\\", "/").casefold().endswith(".hrl")
    ]
    def _normalized(path: str) -> str:
        candidate = Path(path.replace("\\", "/"))
        if not candidate.is_absolute() and repo_root is not None:
            candidate = repo_root / candidate
        try:
            return normalize_file_path(candidate.resolve(strict=False))
        except (OSError, RuntimeError):
            return normalize_file_path(candidate)

    stale = {_normalized(path) for path in stale_spellings}
    if not stale:
        return set()

    # Keep both the exact graph spelling and its normalized spelling in the
    # visited set.  The former preserves compatibility with mixed legacy
    # stores; the latter prevents a separator-only alias from being expanded
    # repeatedly.
    visited: set[str] = set()
    frontier: set[str] = set()
    for spelling in stale_spellings:
        normalized = _normalized(spelling)
        visited.add(spelling)
        visited.add(normalized)
        frontier.add(spelling)

    live_dependents: set[str] = set()
    while frontier and len(live_dependents) < _MAX_DEPENDENT_FILES:
        next_frontier: set[str] = set()
        for file_path in sorted(frontier):
            for dependent in sorted(
                _single_hop_erlang_include_dependents(
                    store, file_path, repo_root
                )
            ):
                dependent_spelling = str(dependent)
                dependent_normalized = _normalized(dependent_spelling)
                if (
                    dependent_spelling in visited
                    or dependent_normalized in visited
                ):
                    continue
                visited.add(dependent_spelling)
                visited.add(dependent_normalized)
                # Only headers can have further preprocessor include
                # consumers.  Keeping source files out of the frontier makes
                # the closure bounded even in large call graphs.
                if dependent_spelling.replace("\\", "/").casefold().endswith(".hrl"):
                    next_frontier.add(dependent_spelling)
                # Stale intermediates are still traversed, but will be absent
                # from the parse set after reconciliation.  Their dependents
                # must remain eligible for reparsing.
                if dependent_normalized not in stale:
                    live_dependents.add(dependent_spelling)
                    if len(live_dependents) >= _MAX_DEPENDENT_FILES:
                        break
            if len(live_dependents) >= _MAX_DEPENDENT_FILES:
                break
        frontier = next_frontier

    if len(live_dependents) >= _MAX_DEPENDENT_FILES:
        logger.warning(
            "Stale dependent expansion capped at %d files",
            _MAX_DEPENDENT_FILES,
        )
    return live_dependents


class DependentList(list):
    """A ``list[str]`` with a ``.truncated`` flag.

    When :func:`find_dependents` hits ``_MAX_DEPENDENT_FILES`` it truncates
    the result and sets ``truncated = True`` so callers can distinguish a
    complete expansion from a capped one.  See issue #261.

    This is a transparent ``list`` subclass — existing callers that iterate,
    ``len()``, or slice continue to work unchanged; only callers that
    specifically check ``.truncated`` benefit from the signal.
    """

    truncated: bool

    def __init__(self, items: list, *, truncated: bool = False) -> None:
        super().__init__(items)
        self.truncated = truncated


def find_dependents(
    store: GraphStore,
    file_path: str,
    max_hops: int = _MAX_DEPENDENT_HOPS,
) -> DependentList:
    """Find files that import from or depend on the given file.

    Performs up to *max_hops* iterations of expansion (default 2).
    Stops early if the total exceeds 500 files.

    Returns a :class:`DependentList` — a regular ``list[str]`` that also
    carries a ``.truncated`` flag.  When ``truncated is True`` the
    returned list is capped at ``_MAX_DEPENDENT_FILES`` and the full
    set of dependents was not explored.  See issue #261.
    """
    all_dependents: set[str] = set()
    visited: set[str] = {file_path}
    frontier: set[str] = {file_path}
    for _hop in range(max_hops):
        next_frontier: set[str] = set()
        for fp in frontier:
            deps = _single_hop_dependents(store, fp)
            new_deps = deps - visited
            all_dependents.update(new_deps)
            next_frontier.update(new_deps)
        visited.update(next_frontier)
        frontier = next_frontier
        if not frontier:
            break
        if len(all_dependents) > _MAX_DEPENDENT_FILES:
            logger.warning(
                "Dependent expansion capped at %d files for %s",
                len(all_dependents),
                file_path,
            )
            return DependentList(
                list(all_dependents)[:_MAX_DEPENDENT_FILES],
                truncated=True,
            )
    return DependentList(list(all_dependents))


def _parse_single_file(
    args: tuple[str, str],
) -> tuple[str, list, list, str | None, str]:
    """Parse one file in a process- or thread-pool worker.

    Returns ``(rel_path, nodes, edges, error_or_none, file_hash)``.
    Must be a module-level function so ``ProcessPoolExecutor`` can
    serialise it across processes.
    """
    rel_path, repo_root_str = args
    abs_path = Path(repo_root_str) / rel_path
    try:
        raw = abs_path.read_bytes()
        fhash = hashlib.sha256(raw).hexdigest()
        parser = getattr(_PARSE_WORKER_STATE, "parser", None)
        parser_repo_root = getattr(_PARSE_WORKER_STATE, "repo_root", None)
        if parser is None or parser_repo_root != repo_root_str:
            parser = CodeParser(Path(repo_root_str))
            _PARSE_WORKER_STATE.parser = parser
            _PARSE_WORKER_STATE.repo_root = repo_root_str
        nodes, edges = parser.parse_bytes(abs_path, raw)
        return (rel_path, nodes, edges, None, fhash)
    except Exception as e:
        return (rel_path, [], [], str(e), "")


def _canonical_repo_root(repo_root: Path) -> Path:
    """Return one stable identity for a repository root.

    Graph paths are anchored to the root supplied by the caller. Resolving the
    root once prevents equivalent spellings (notably ``.`` and an absolute
    path) from looking like two different repositories during reconciliation.
    """
    return Path(repo_root).expanduser().resolve()


def full_build(
    repo_root: Path,
    store: GraphStore,
    recurse_submodules: bool | None = None,
    *,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
) -> dict:
    """Full rebuild of the entire graph.

    Args:
        repo_root: Repository root directory.
        store: Graph database store.
        recurse_submodules: If True, include files from git submodules.
            When *None*, falls back to ``CRG_RECURSE_SUBMODULES`` env var.
    """
    repo_root = _canonical_repo_root(repo_root)
    # Full builds replace files one transaction at a time.  Mark the Erlang
    # identity as pending before the first replacement so an interruption can
    # never leave a stale v5 marker attached to a partially rebuilt graph.
    _clear_erlang_identity(store, repo_root)
    parser = CodeParser(repo_root)
    files = collect_all_files(repo_root, recurse_submodules)
    stale_files = _reconcile_stale_files(repo_root, store, files)
    parse_started = time.perf_counter()

    total_nodes = 0
    total_edges = 0
    errors = []
    cpp_errors: set[str] = set()
    erlang_errors: set[str] = set()
    file_count = len(files)

    use_serial = os.environ.get("CRG_SERIAL_PARSE", "") == "1"

    if use_serial or file_count < 8:
        # Serial fallback (for debugging or tiny repos)
        for i, rel_path in enumerate(files, 1):
            full_path = repo_root / rel_path
            try:
                source = full_path.read_bytes()
                fhash = hashlib.sha256(source).hexdigest()
                nodes, edges = parser.parse_bytes(full_path, source)
                store.store_file_nodes_edges(str(full_path), nodes, edges, fhash)
                total_nodes += len(nodes)
                total_edges += len(edges)
            except (OSError, PermissionError) as e:
                errors.append({"file": rel_path, "error": str(e)})
                if parser.detect_language(full_path) == "cpp":
                    cpp_errors.add(str(rel_path))
                if _is_erlang_source_path(rel_path):
                    erlang_errors.add(str(rel_path))
            except Exception as e:
                logger.warning("Error parsing %s: %s", rel_path, e)
                errors.append({"file": rel_path, "error": str(e)})
                if parser.detect_language(full_path) == "cpp":
                    cpp_errors.add(str(rel_path))
                if _is_erlang_source_path(rel_path):
                    erlang_errors.add(str(rel_path))
            if i % 50 == 0 or i == file_count:
                logger.info("Progress: %d/%d files parsed", i, file_count)
    else:
        # Parallel parsing — store calls remain serial (SQLite single-writer).
        # Executor kind auto-selected: process for normal CLI/automation;
        # thread for MCP stdio to avoid pipe-handle inheritance deadlocks and
        # orphan workers (issues #46, #136, PR #615). Override via
        # CRG_PARSE_EXECUTOR env.
        args_list = [(rel_path, str(repo_root)) for rel_path in files]
        with _make_executor(_MAX_PARSE_WORKERS) as executor:
            for i, (rel_path, nodes, edges, error, fhash) in enumerate(
                executor.map(_parse_single_file, args_list, chunksize=20),
                1,
            ):
                if error:
                    logger.warning("Error parsing %s: %s", rel_path, error)
                    errors.append({"file": rel_path, "error": error})
                    if parser.detect_language(repo_root / rel_path) == "cpp":
                        cpp_errors.add(str(rel_path))
                    if _is_erlang_source_path(rel_path):
                        erlang_errors.add(str(rel_path))
                    continue
                full_path = repo_root / rel_path
                store.store_file_nodes_edges(
                    str(full_path),
                    nodes,
                    edges,
                    fhash,
                )
                total_nodes += len(nodes)
                total_edges += len(edges)
                if i % 200 == 0 or i == file_count:
                    logger.info("Progress: %d/%d files parsed", i, file_count)

    stage_timing = {
        "parse_s": max(0.0, round(time.perf_counter() - parse_started, 6)),
    }
    resolver_started = time.perf_counter()
    resolver_timing: dict[str, float] = {}

    def run_resolver(name: str, operation: Any) -> Any:
        started = time.perf_counter()
        try:
            return operation()
        finally:
            resolver_timing[name] = max(
                0.0, round(time.perf_counter() - started, 6)
            )

    store.set_metadata("last_updated", time.strftime("%Y-%m-%dT%H:%M:%S"))
    store.set_metadata("last_build_type", "full")
    if not cpp_errors:
        store.set_metadata(_CPP_IDENTITY_METADATA_KEY, CPP_IDENTITY_VERSION)
    _store_vcs_metadata(repo_root, store)
    store.commit()

    python_stats = run_resolver("python", lambda: _run_python_resolver(store))
    erlang_header_stats = run_resolver(
        "erlang_header", lambda: _run_erlang_header_resolver(store, repo_root)
    )
    rescript_stats = run_resolver("rescript", lambda: _run_rescript_resolver(store))
    spring_stats = run_resolver("spring", lambda: _run_spring_resolver(store))
    spring_event_stats = run_resolver(
        "spring_event", lambda: _run_spring_event_resolver(store)
    )
    temporal_stats = run_resolver("temporal", lambda: _run_temporal_resolver(store))
    hcl_stats = run_resolver("hcl", lambda: _run_hcl_resolver(store))
    scoped_stats = run_resolver("scoped", lambda: _run_scoped_resolver(store))
    stage_timing["repository_resolvers_s"] = max(
        0.0, round(time.perf_counter() - resolver_started, 6)
    )

    result = {
        "files_parsed": len(files),
        "stale_files_removed": len(stale_files),
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "errors": errors,
        "python_resolution": python_stats,
        "erlang_header_resolution": erlang_header_stats,
        "rescript_resolution": rescript_stats,
        "spring_resolution": spring_stats,
        "event_resolution": spring_event_stats,
        "temporal_resolution": temporal_stats,
        "hcl_resolution": hcl_stats,
        "scoped_resolution": scoped_stats,
        "stage_timing": stage_timing,
        "resolver_timing": resolver_timing,
    }
    try:
        erlang_started = time.perf_counter()
        erlang_result = _run_erlang_lifecycle(
            repo_root,
            store,
            config=erlang_config,
            changed_files=(),
            force=True,
        )
        stage_timing["erlang_integration_s"] = max(
            0.0, round(time.perf_counter() - erlang_started, 6)
        )
    except BaseException:
        _clear_erlang_identity(store, repo_root)
        raise
    if erlang_result is not None:
        result["erlang_integration"] = erlang_result
    if erlang_errors:
        _clear_erlang_identity(store, repo_root)
    else:
        _set_erlang_identity_current(store, repo_root)
    return result


def incremental_update(
    repo_root: Path,
    store: GraphStore,
    base: str = "HEAD~1",
    changed_files: list[str] | None = None,
    reconcile_stale: bool = True,
    *,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
) -> dict:
    """Incremental update: re-parse changed + dependent files only."""
    repo_root = _canonical_repo_root(repo_root)
    if reconcile_stale:
        _assert_graph_matches_root(repo_root, store)
    if changed_files is not None:
        _assert_changed_files_belong_to_root(repo_root, changed_files)

    # Upgrade legacy/missing Erlang identities before considering the diff.
    # This is deliberately first: a no-op diff must not allow an old graph to
    # bypass the migration gate, and a successful full build makes the rest of
    # this lifecycle exactly-once.
    rebuilt = _ensure_erlang_identity_current(
        repo_root,
        store,
        erlang_config=erlang_config,
    )
    if rebuilt is not None:
        return _identity_rebuild_result(rebuilt, changed_files)

    parser = CodeParser(repo_root)
    ignore_patterns = _load_ignore_patterns(repo_root)
    stage_timing: dict[str, float] = {}

    if (
        store.get_metadata(_CPP_IDENTITY_METADATA_KEY) != CPP_IDENTITY_VERSION
        and store.has_nodes_for_language("cpp")
    ):
        logger.info(
            "C++ identity format changed; rebuilding the graph before incremental update",
        )
        rebuilt = _invoke_full_build(repo_root, store, erlang_config)
        return _identity_rebuild_result(rebuilt, changed_files)

    # Determine changed files.  Automatic Git diffs do not include untracked
    # paths; add only Erlang layout manifests from the working tree so a new
    # rebar/app configuration still refreshes semantic evidence without
    # changing the established discovery behavior for other languages.
    if changed_files is None:
        changed_files = get_changed_files(repo_root, base)
        changed_files = _append_untracked_erlang_layout_files(repo_root, changed_files)
        changed_files = _append_mismatched_erlang_hashes(repo_root, store, changed_files)

    # Canonicalize existing Erlang include edges before stale-file cleanup and
    # dependency discovery. Header changes are compared against the previous
    # graph, so this ordering lets us retain consumers even when a deleted
    # header's incoming edge would otherwise be removed with its node.
    stage_started = time.perf_counter()
    # A clean no-op already has canonical header/record state from the last
    # build.  Avoid rescanning every Erlang import/reference edge; changed or
    # stale paths still run the pre-pass before dependency discovery.
    erlang_header_pre_stats = (
        _run_erlang_header_resolver(store, repo_root)
        if (
            changed_files
            and any(_is_erlang_relevant_path(path) for path in changed_files)
            and store.has_nodes_for_language("erlang")
        )
        else None
    )
    stage_timing["header_pre_s"] = max(
        0.0, round(time.perf_counter() - stage_started, 6)
    )
    stage_started = time.perf_counter()
    stale_dependents: set[str] = set()
    stale_files = (
        _reconcile_stale_files(
            repo_root,
            store,
            dependent_files=stale_dependents,
        )
        if reconcile_stale
        else []
    )
    stage_timing["stale_reconciliation_s"] = max(
        0.0, round(time.perf_counter() - stage_started, 6)
    )

    layout_changed = any(_is_erlang_layout_path(path) for path in changed_files)
    erlang_changed = any(
        _is_erlang_relevant_path(path)
        for path in set(changed_files) | set(stale_files)
    )
    # Clear before any file replacement.  The explicit commit is required
    # because GraphStore's replacement helpers begin their own transaction and
    # would otherwise roll back an uncommitted marker deletion.
    if erlang_changed:
        _clear_erlang_identity(store, repo_root)
    if not changed_files and not stale_files:
        result = {
            "files_updated": 0,
            "total_nodes": 0,
            "total_edges": 0,
            "changed_files": [],
            "dependent_files": [],
            "stale_files_removed": 0,
            "errors": [],
            "graph_changed": False,
            "relation_layout_changed": False,
            "erlang_header_resolution": erlang_header_pre_stats,
            "stage_timing": stage_timing,
        }
        stage_started = time.perf_counter()
        erlang_result = _run_erlang_lifecycle(
            repo_root,
            store,
            config=erlang_config,
            changed_files=changed_files,
            force=layout_changed,
        )
        stage_timing["erlang_integration_s"] = max(
            0.0, round(time.perf_counter() - stage_started, 6)
        )
        if erlang_result is not None:
            result["erlang_integration"] = erlang_result
        return result

    # Find dependent files (files that import from changed files)
    stage_started = time.perf_counter()
    dependent_files: set[str] = set()
    for dependent in stale_dependents:
        if not _path_belongs_to_root(dependent, repo_root):
            logger.warning(
                "Ignoring stale dependent outside repository root: %s",
                dependent,
            )
            continue
        try:
            dependent_files.add(str(Path(dependent).relative_to(repo_root)))
        except ValueError:
            dependent_files.add(dependent)
    for rel_path in changed_files:
        full_path = normalize_file_path(repo_root / rel_path)
        deps = find_dependents(store, full_path)
        for d in deps:
            if not _path_belongs_to_root(d, repo_root):
                logger.warning(
                    "Ignoring dependent file outside repository root: %s", d
                )
                continue
            # Convert back to relative path if needed
            try:
                dependent_files.add(str(Path(d).relative_to(repo_root)))
            except ValueError:
                dependent_files.add(d)

    # Combine changed + dependent
    all_files = set(changed_files) | dependent_files
    stage_timing["dependency_discovery_s"] = max(
        0.0, round(time.perf_counter() - stage_started, 6)
    )

    total_nodes = 0
    total_edges = 0
    errors = []
    erlang_errors: set[str] = set()
    missing_paths: set[str] = set()
    # Watch events normally address canonical absolute rows.  Keep the
    # legacy relative spellings that are still present in a shared store so a
    # deletion removes both representations of the same checkout file.
    stored_file_paths = set(store.get_all_files())

    # Separate deleted/unparseable files from files that need re-parsing
    stage_started = time.perf_counter()
    to_parse: list[str] = []
    snapshots: dict[str, tuple[bytes, str]] = {}
    for rel_path in all_files:
        if _should_ignore(rel_path, ignore_patterns):
            continue
        abs_path = repo_root / rel_path
        if not abs_path.is_file():
            absolute_marker = normalize_file_path(abs_path)
            if absolute_marker not in stale_files:
                missing_paths.add(absolute_marker)
                relative_marker = normalize_file_path(
                    abs_path.relative_to(repo_root)
                )
                if relative_marker in stored_file_paths:
                    missing_paths.add(relative_marker)
            continue
        try:
            raw = abs_path.read_bytes()
            # Language detection must use the same byte snapshot as hashing
            # and parsing.  A separate shebang probe can observe an editor's
            # truncate window and make an otherwise valid extensionless file
            # look unsupported (issue #746).
            if parser.detect_language(abs_path, raw) is None:
                continue
            fhash = hashlib.sha256(raw).hexdigest()
            # Extensionless files need the pre-read bytes again during the
            # parse stage: their language is inferred from a shebang, and a
            # second path-only probe can race an editor save.  For ordinary
            # extension-based files retain the historical parse-stage read so
            # the stored hash continues to describe the bytes actually parsed.
            if abs_path.suffix == "":
                snapshots[rel_path] = (raw, fhash)
            existing_nodes = store.get_nodes_by_file(str(abs_path))
            # Dependents must be re-parsed even when their own bytes are
            # unchanged: an included header/module may have changed the
            # syntax or resolution context of their edges.
            if (
                existing_nodes
                and existing_nodes[0].file_hash == fhash
                and rel_path not in dependent_files
            ):
                continue
        except (OSError, PermissionError):
            pass
        to_parse.append(rel_path)
    stage_timing["change_inventory_s"] = max(
        0.0, round(time.perf_counter() - stage_started, 6)
    )

    # Persist deletions before store_file_nodes_edges() opens its own
    # explicit transaction — avoids nested transaction errors.
    use_serial = os.environ.get("CRG_SERIAL_PARSE", "") == "1"
    parsed_files = 0

    stage_started = time.perf_counter()
    if use_serial or len(to_parse) < 8:
        for rel_path in to_parse:
            abs_path = repo_root / rel_path
            try:
                snapshot = snapshots.get(rel_path)
                if snapshot is None:
                    source = abs_path.read_bytes()
                    fhash = hashlib.sha256(source).hexdigest()
                else:
                    source, fhash = snapshot
                nodes, edges = parser.parse_bytes(abs_path, source)
                store.store_file_nodes_edges(str(abs_path), nodes, edges, fhash)
                parsed_files += 1
                total_nodes += len(nodes)
                total_edges += len(edges)

            except (OSError, PermissionError) as e:
                errors.append({"file": rel_path, "error": str(e)})
                if _is_erlang_source_path(rel_path):
                    erlang_errors.add(str(rel_path))
            except Exception as e:
                logger.warning("Error parsing %s: %s", rel_path, e)
                errors.append({"file": rel_path, "error": str(e)})
                if _is_erlang_source_path(rel_path):
                    erlang_errors.add(str(rel_path))
    else:
        # See full-build comment above for executor kind rationale.
        args_list = [(rel_path, str(repo_root)) for rel_path in to_parse]
        with _make_executor(_MAX_PARSE_WORKERS) as executor:
            for rel_path, nodes, edges, error, fhash in executor.map(
                _parse_single_file,
                args_list,
                chunksize=20,
            ):
                if error:
                    logger.warning("Error parsing %s: %s", rel_path, error)
                    errors.append({"file": rel_path, "error": error})
                    if _is_erlang_source_path(rel_path):
                        erlang_errors.add(str(rel_path))
                    continue
                store.store_file_nodes_edges(
                    str(repo_root / rel_path),
                    nodes,
                    edges,
                    fhash,
                )
                parsed_files += 1
                total_nodes += len(nodes)
                total_edges += len(edges)

    stage_timing["parse_s"] = max(0.0, round(time.perf_counter() - stage_started, 6))

    removed_files = store.remove_files_permanently(sorted(missing_paths)) if missing_paths else 0
    files_updated = parsed_files + len(stale_files) + removed_files
    if files_updated:
        store.set_metadata("last_updated", time.strftime("%Y-%m-%dT%H:%M:%S"))
        store.set_metadata("last_build_type", "incremental")
        store.set_metadata(_CPP_IDENTITY_METADATA_KEY, CPP_IDENTITY_VERSION)
        _store_vcs_metadata(repo_root, store)
        store.commit()

    # Only re-run language-specific resolvers when the relevant files changed.
    stage_started = time.perf_counter()
    python_changed = any(
        path.endswith(".py")
        for path in set(all_files) | set(stale_files) | missing_paths
    )
    python_stats = _run_python_resolver(store) if python_changed else None

    # Header/record endpoints are cheap to reconcile and must be canonical
    # before the next incremental cycle's dependent-file lookup.  Run this on
    # every update that still contains Erlang nodes so legacy/raw graphs also
    # converge when no Erlang source itself changed.
    erlang_header_stats = (
        _run_erlang_header_resolver(store, repo_root)
        if store.has_nodes_for_language("erlang")
        else None
    )

    rescript_changed = any(
        rp.endswith((".res", ".resi")) for rp in all_files
    )
    rescript_stats = (
        _run_rescript_resolver(store) if rescript_changed else None
    )

    # Like python_changed above, include stale/missing paths so a deletion
    # that only surfaces through reconciliation still clears derived state
    # (e.g. virtual Spring Event nodes — issue #474).
    spring_changed = any(
        path.endswith(".java")
        for path in set(all_files) | set(stale_files) | missing_paths
    )
    spring_stats = _run_spring_resolver(store) if spring_changed else None
    spring_event_stats = (
        _run_spring_event_resolver(store) if spring_changed else None
    )
    temporal_stats = _run_temporal_resolver(store) if spring_changed else None
    hcl_changed = any(rp.endswith((".tf", ".hcl")) for rp in all_files)
    hcl_stats = _run_hcl_resolver(store) if hcl_changed else None
    scoped_changed = any(rp.endswith((".php", ".rs", ".cs")) for rp in all_files)
    scoped_stats = _run_scoped_resolver(store) if scoped_changed else None
    stage_timing["repository_resolvers_s"] = max(
        0.0, round(time.perf_counter() - stage_started, 6)
    )

    result = {
        "files_updated": files_updated,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "changed_files": list(changed_files),
        "dependent_files": list(dependent_files),
        "stale_files_removed": len(stale_files),
        "errors": errors,
        "python_resolution": python_stats,
        "erlang_header_resolution": erlang_header_stats,
        "rescript_resolution": rescript_stats,
        "spring_resolution": spring_stats,
        "event_resolution": spring_event_stats,
        "temporal_resolution": temporal_stats,
        "hcl_resolution": hcl_stats,
        "scoped_resolution": scoped_stats,
        "graph_changed": bool(files_updated or layout_changed),
        "relation_layout_changed": layout_changed,
        "stage_timing": stage_timing,
    }
    try:
        stage_started = time.perf_counter()
        # A preparation command can touch generated Erlang files without
        # changing their bytes.  Watchdog still reports those writes, but
        # restarting the strict semantic chain for each one would make the
        # project's own build recursively retrigger itself.  Hash changes,
        # deletions, and layout changes remain semantic triggers.
        erlang_result = (
            _run_erlang_lifecycle(
                repo_root,
                store,
                config=erlang_config,
                changed_files=list(changed_files),
                force=layout_changed,
            )
            if files_updated > 0 or layout_changed
            else None
        )
        stage_timing["erlang_integration_s"] = max(
            0.0, round(time.perf_counter() - stage_started, 6)
        )
    except BaseException:
        if erlang_changed:
            _clear_erlang_identity(store, repo_root)
        raise
    if erlang_result is not None:
        result["erlang_integration"] = erlang_result
    if erlang_changed:
        if erlang_errors:
            _clear_erlang_identity(store, repo_root)
        else:
            _set_erlang_identity_current(store, repo_root)
    return result


# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------


_DEBOUNCE_SECONDS = 1


def _raise_watch_update_errors(result: dict, context: str) -> None:
    """Fail the watch boundary when an incremental update reports errors."""
    errors = result.get("errors") or []
    if not errors:
        return
    details = "; ".join(
        f"{error.get('file', 'unknown')}: {error.get('error', 'unknown error')}"
        for error in errors
    )
    raise RuntimeError(f"{context} reported errors: {details}")


def _raise_watch_postprocess_warnings(result: object) -> None:
    """Treat structured post-processing warnings as a failed watch update."""
    if not isinstance(result, dict):
        return
    warnings = result.get("warnings") or []
    if warnings:
        details = "; ".join(str(warning) for warning in warnings)
        raise RuntimeError(f"post-processing reported warnings: {details}")


def _watch_postprocess_required(
    repo_root: Path,
    store: GraphStore,
    result: Mapping[str, Any] | None,
) -> bool:
    """Return whether a watch batch needs its derived callback run."""
    if isinstance(result, Mapping):
        try:
            if int(result.get("files_updated", 0) or 0) > 0:
                return True
        except (TypeError, ValueError, OverflowError):
            pass
        if _erlang_result_requires_derived_refresh(result):
            return True
    return _watch_postprocess_pending(store, repo_root)


def _run_watch_postprocess(
    repo_root: Path,
    store: GraphStore,
    callback: Optional[Callable],
    result: Mapping[str, Any] | None,
) -> bool:
    """Run and durably track one watch post-processing attempt.

    The marker is written *before* invoking the callback.  A callback failure
    therefore survives a daemon restart even when the source file hash makes
    the next incremental reconciliation a no-op.
    """
    if callback is None or not _watch_postprocess_required(repo_root, store, result):
        return False
    _set_watch_postprocess_pending(store, repo_root, True)
    postprocess_result = callback(store)
    _raise_watch_postprocess_warnings(postprocess_result)
    _set_watch_postprocess_pending(store, repo_root, False)
    return True


# ---------------------------------------------------------------------------
# Watch scheduling and supervision
# ---------------------------------------------------------------------------

# A single recursive watch on the repository root makes the OS register one
# watch per directory in the tree — including every temp directory a build tool
# churns through inside ``target/`` or ``node_modules/``.  Planning the watches
# ourselves keeps ignored trees off the OS watch list entirely.  See: #811.
_WATCH_PLAN_DEPTH = int(os.environ.get("CRG_WATCH_PLAN_DEPTH", "3"))
_MAX_WATCH_SCHEDULES = int(os.environ.get("CRG_MAX_WATCH_SCHEDULES", "24"))
# Splitting a watch costs one watchdog emitter, so it has to buy more than it
# costs: an ignored tree is only worth excluding once it holds this many
# directories.  A lone ``__pycache__`` is not worth a thread; ``target/`` is.
_WATCH_SPLIT_MIN_DIRS = int(os.environ.get("CRG_WATCH_SPLIT_MIN_DIRS", "4"))
_WATCH_HEALTH_INTERVAL = float(os.environ.get("CRG_WATCH_HEALTH_INTERVAL", "10"))
_WATCH_STOP_TIMEOUT = 10.0
_WATCH_TICK_SECONDS = 1.0
_REAL_WATCH_SLEEP = time.sleep


def _watch_sleep(seconds: float) -> None:
    """Sleep between watch reconciliation ticks.

    Keep the watcher clock independent from process-wide ``time.sleep``
    monkeypatches.  Test drivers patch this narrow seam, while subprocess and
    parser timeout polling continue to use the real sleeper.
    """
    _REAL_WATCH_SLEEP(seconds)


def _watch_child_dirs(
    directory: Path,
    cache: dict[Path, list[Path]] | None = None,
) -> list[Path]:
    """Return the real (non-symlink) subdirectories of *directory*."""
    if cache is not None and directory in cache:
        return cache[directory]
    children = [directory / name for name, is_dir in _child_directories(directory) if is_dir]
    if cache is not None:
        cache[directory] = children
    return children


def _ignored_tree_weight(directory: Path, cap: int) -> int:
    """Count the directories inside an ignored tree, stopping at *cap*.

    Used to decide whether excluding the tree is worth a separate watch.  The
    count stops as soon as the cap is reached, so probing ``node_modules`` is
    barely more expensive than probing an empty ``__pycache__``.
    """
    if cap <= 0:
        return 0
    total = 1
    queue = [directory]
    while queue and total < cap:
        current = queue.pop()
        for name, is_dir in _child_directories(current):
            if not is_dir:
                continue
            total += 1
            if total >= cap:
                return total
            queue.append(current / name)
    return total


def _plan_watch_subtree(
    directory: Path,
    repo_root: Path,
    ignore_patterns: list[str],
    depth: int,
    max_depth: int,
    cache: dict[Path, list[Path]],
    split_threshold: int = _WATCH_SPLIT_MIN_DIRS,
) -> tuple[bool, list[tuple[Path, bool]]]:
    """Plan the watches covering *directory*.

    Returns ``(clean, plan)``.  ``clean`` means nothing below *directory*
    within *max_depth* is worth excluding, in which case a single recursive
    watch covers it.  Otherwise the directory is watched non-recursively and
    each surviving child is planned in turn, so the ignored subtree is never
    handed to the OS at all.
    """
    ignored_weight = 0
    kept: list[Path] = []
    for child in _watch_child_dirs(directory, cache):
        if _should_ignore(child.relative_to(repo_root).as_posix(), ignore_patterns):
            if ignored_weight < split_threshold:
                ignored_weight += _ignored_tree_weight(child, split_threshold - ignored_weight)
        else:
            kept.append(child)
    clean = ignored_weight < split_threshold
    if depth >= max_depth:
        if clean:
            return True, [(directory, True)]
        return False, [(directory, False)] + [(child, True) for child in kept]
    child_plans: list[tuple[Path, bool]] = []
    for child in kept:
        child_clean, child_plan = _plan_watch_subtree(
            child, repo_root, ignore_patterns, depth + 1, max_depth, cache, split_threshold
        )
        clean = clean and child_clean
        child_plans.extend(child_plan)
    if clean:
        return True, [(directory, True)]
    return False, [(directory, False)] + child_plans


def _plan_watch_paths(
    repo_root: Path,
    ignore_patterns: list[str],
    max_depth: int = _WATCH_PLAN_DEPTH,
    max_schedules: int = _MAX_WATCH_SCHEDULES,
    split_threshold: int = _WATCH_SPLIT_MIN_DIRS,
) -> list[tuple[Path, bool]]:
    """Return the ``(path, recursive)`` watches that cover the repo.

    Deeper plans exclude more ignored trees but cost one watchdog emitter each,
    so an over-budget plan is retried at a shallower depth before falling back
    to the single recursive root watch.
    """
    cache: dict[Path, list[Path]] = {}
    for depth in range(max(1, max_depth), 0, -1):
        _, plan = _plan_watch_subtree(
            repo_root, repo_root, ignore_patterns, 0, depth, cache, split_threshold
        )
        if len(plan) <= max(1, max_schedules):
            return plan
    logger.warning(
        "%s needs more than %d watches to skip its ignored trees; "
        "falling back to one recursive watch (raise CRG_MAX_WATCH_SCHEDULES to split it)",
        repo_root,
        max_schedules,
    )
    return [(repo_root, True)]


def _run_time_boxed(
    operation: Callable[[], Any], description: str, timeout: float = 10.0
) -> bool:
    """Run *operation* on a throwaway thread so a wedged watcher cannot hang exit.

    Watchdog's teardown joins its emitter threads, and the whole point of this
    module's health check is that one of those threads may be stuck.  Every
    watchdog thread is a daemon thread, so abandoning the join is safe.
    """

    def _call() -> None:
        try:
            operation()
        except Exception as exc:  # noqa: BLE001 - teardown must not mask the real error
            logger.debug("%s failed: %s", description, exc)

    thread = threading.Thread(target=_call, name="crg-watch-teardown", daemon=True)
    thread.start()
    thread.join(max(0.0, timeout))
    if thread.is_alive():
        logger.warning(
            "%s did not finish in %.0fs; leaving it to process exit", description, timeout
        )
        return False
    return True


def _watch_health_path(repo_root: Path) -> Path | None:
    """Where this watcher publishes its health, or None if that is unavailable."""
    try:
        from .daemon import watch_health_path

        return watch_health_path(repo_root)
    except Exception as exc:  # noqa: BLE001 - health reporting is best-effort
        logger.debug("Watcher health reporting disabled: %s", exc)
        return None


def _watch_identity(path: str | Path) -> tuple[int, int, float] | None:
    """Identify a directory by inode, not by name.

    ``rm -rf src && mkdir src`` leaves the path spelled exactly as before while
    the watch on it is dead, so a name is not an identity.  ``st_birthtime``
    joins the tuple where the platform has it (macOS, Windows), which catches
    the recreated directory that happens to reuse an inode.
    """
    try:
        status = os.stat(path)
    except OSError:
        return None
    return (status.st_dev, status.st_ino, float(getattr(status, "st_birthtime", 0.0)))


class _WatchEntry(NamedTuple):
    """One scheduled watch: the watchdog handle and the directory it covers."""

    handle: Any
    identity: tuple[int, int, float] | None


class _WatchSupervisor:
    """Owns the observer's watches and reports whether they still work.

    Three jobs, all deliberately cheap:

    * schedule only the directories that survive the ignore patterns, so the OS
      never registers a watch inside an ignored tree;
    * adopt directories created later underneath a non-recursive watch, and
      notice when a watched directory has been replaced by a new one wearing
      the same name;
    * notice a dead watchdog thread and publish watcher health, so a stalled
      watcher stops looking healthy to ``crg-daemon status``.
    """

    def __init__(
        self,
        observer: Any,
        repo_root: Path,
        ignore_patterns: list[str],
        health_path: Path | None = None,
        max_schedules: int = _MAX_WATCH_SCHEDULES,
    ) -> None:
        self._observer = observer
        # One boundary resolves the path.  ``--repo .`` stays relative all the
        # way down from the CLI, and a relative root would make every
        # ``relative_to`` on an absolute event path raise.
        self._repo_root = Path(os.path.abspath(repo_root))
        self._ignore_patterns = ignore_patterns
        self._health_path = health_path
        self._max_schedules = max(1, max_schedules)
        self._handler: Any = None
        self._watches: dict[str, _WatchEntry] = {}
        self._shallow: set[str] = set()
        # The repository root has no watched parent to discover a disappearance
        # or replacement. Remember that it needs restoration while absent; the
        # planner is rerun on reappearance so ignore and budget policy follows
        # the replacement tree.
        self._root_pending = False
        self._live_threads: dict[int, threading.Thread] = {}
        self._repaired_roots: set[str] = set()
        self._degraded = False
        self._last_health_write = 0.0
        self._last_health_state: tuple[bool, bool, tuple[str, ...]] | None = None
        self._started_at = time.time()
        self._token = f"{os.getpid()}.{uuid.uuid4().hex[:8]}"

    # -- scheduling -----------------------------------------------------

    @property
    def watched_paths(self) -> list[str]:
        return sorted(self._watches)

    @property
    def degraded(self) -> bool:
        """True once the watch budget forced a coarser, recursive watch."""
        return self._degraded

    def attach(self, observer: Any) -> None:
        """Bind the observer, once the initial build has earned one."""
        self._observer = observer

    def schedule_initial(self, handler: Any) -> None:
        """Schedule the planned watches for *handler*."""
        self._handler = handler
        plan = _plan_watch_paths(
            self._repo_root,
            self._ignore_patterns,
            max_schedules=self._max_schedules,
        )
        for path, recursive in plan:
            self._schedule(path, recursive=recursive)
        logger.info(
            "Watching %d path(s) under %s; ignored trees are never registered",
            len(self._watches),
            self._repo_root,
        )

    def _schedule(self, path: Path, *, recursive: bool) -> None:
        key = str(path)
        if key in self._watches:
            return
        try:
            handle = self._observer.schedule(self._handler, key, recursive=recursive)
        except OSError as exc:
            logger.warning("Could not watch %s: %s", key, exc)
            return
        self._watches[key] = _WatchEntry(handle, _watch_identity(key))
        if key == str(self._repo_root):
            self._root_pending = False
        if recursive:
            self._shallow.discard(key)
        else:
            self._shallow.add(key)

    def sync_watches(self) -> tuple[list[str], list[str]]:
        """Reconcile the watches under every non-recursive watch.

        Returns ``(adopted, vanished)`` as absolute paths, so the caller can
        index a directory that appeared and reconcile one that disappeared.

        Directory events cannot be used for this.  macOS drops every directory
        event for a child of a non-recursive watch (``FSEventsEmitter.
        _is_recursive_event``), so a brand-new top-level directory — or one
        recreated by ``rm -rf src && mkdir src`` — would never be noticed and
        would stay unindexed forever.  One ``scandir`` per non-recursive watch
        per tick (typically one or two) is nothing next to the thousands of
        kernel watches this planning saves, and it cannot go blind.
        """
        adopted: list[str] = []
        vanished: list[str] = []

        # A recursive fallback root has no shallow parent, so the normal child
        # scan below can never observe that the root inode was replaced. Check
        # the root itself first and rebuild the planner's current plan when
        # needed. This also handles a root that disappears for a few ticks.
        repository_root = str(self._repo_root)
        root_entry = self._watches.get(repository_root)
        if root_entry is not None:
            root_present = self._is_watchable_directory(repository_root)
            current_identity = _watch_identity(repository_root) if root_present else None
            if not root_present or current_identity != root_entry.identity:
                logger.info(
                    "Watch root %s was gone or replaced; releasing and re-adopting it",
                    repository_root,
                )
                self._release_watch_tree(repository_root)
                self._root_pending = True
                vanished.append(repository_root)
        if (
            self._root_pending
            and repository_root not in self._watches
            and self._is_watchable_directory(repository_root)
        ):
            if self._schedule_root_plan():
                self._root_pending = False
                adopted.append(repository_root)

        for parent in sorted(self._shallow):
            present = {
                name for name, is_dir in _child_directories(Path(parent)) if is_dir
            }
            for child in sorted(self._children_of(parent)):
                if os.path.basename(child) not in present:
                    self._release_directory(child)
                    vanished.append(child)
                elif self._watches[child].identity != _watch_identity(child):
                    # Same name, different directory: the watch on it died with
                    # the old inode.  Release it now so the loop below adopts
                    # the replacement, instead of mistaking it for a corpse.
                    logger.info("Directory %s was replaced; re-watching it", child)
                    self._release_directory(child)
                    vanished.append(child)
            for name in sorted(present):
                if parent not in self._shallow:
                    # A promotion replaced this parent with one recursive
                    # watch, which already covers everything below it.
                    break
                candidate = os.path.join(parent, name)
                if candidate in self._watches:
                    continue
                if self._adopt_directory(candidate):
                    adopted.append(candidate)
        return adopted, vanished

    def _children_of(self, parent: str) -> list[str]:
        """Watched paths directly underneath *parent*."""
        return [path for path in self._watches if os.path.dirname(path) == parent]

    def _descendants_of(self, parent: str) -> list[str]:
        """Watched paths anywhere underneath *parent*, at any depth."""
        prefix = parent.rstrip(os.sep) + os.sep
        return [path for path in self._watches if path.startswith(prefix)]

    def _release_watch_tree(self, path: str) -> None:
        """Release *path* and all nested watches, deepest paths first."""
        descendants = sorted(
            self._descendants_of(path),
            key=lambda candidate: candidate.count(os.sep),
            reverse=True,
        )
        for descendant in descendants:
            self._release_directory(descendant)
        self._release_directory(path)

    def _is_watchable_directory(self, path: str) -> bool:
        """Return whether *path* is a real directory we can schedule."""
        try:
            candidate = Path(path)
            return candidate.is_dir() and not candidate.is_symlink()
        except OSError:
            return False

    def _schedule_root_plan(self) -> bool:
        """Restore the root watch and its current planned children."""
        if not self._is_watchable_directory(str(self._repo_root)):
            return False
        plan = _plan_watch_paths(
            self._repo_root,
            self._ignore_patterns,
            max_schedules=self._max_schedules,
        )
        # The planner always puts the repository root first. Schedule it before
        # descendants so a partial observer failure cannot leave child watches
        # active while the root remains pending.
        root_plan = next(
            ((path, recursive) for path, recursive in plan if path == self._repo_root),
            None,
        )
        if root_plan is None:
            return False
        root, root_recursive = root_plan
        self._schedule(root, recursive=root_recursive)
        if str(self._repo_root) not in self._watches:
            return False
        for path, path_recursive in plan:
            if path == self._repo_root:
                continue
            self._schedule(path, recursive=path_recursive)
        return str(self._repo_root) in self._watches

    def _adopt_directory(self, candidate: str) -> bool:
        """Watch a directory that appeared under a non-recursive watch.

        Planned the same way startup plans the repository: a module arriving
        from a branch switch must not hand its ``node_modules`` and ``target``
        straight back to the OS, which is the exposure #811 is about.
        """
        try:
            relative = Path(candidate).relative_to(self._repo_root).as_posix()
        except ValueError:
            return False
        if not self._is_watchable_directory(candidate):
            return False
        if _should_ignore(relative, self._ignore_patterns):
            logger.debug("Not watching ignored directory %s", relative)
            return False
        plan = self._affordable_plan(Path(candidate))
        if plan is None:
            # Promoting the parent — often the repository root — hands every
            # ignored tree under it back to the OS, which is the condition
            # #811 is about.  It is the last resort, never the first.
            self._promote_to_recursive(os.path.dirname(candidate))
            return True
        for path, recursive in plan:
            self._schedule(path, recursive=recursive)
        logger.info("Watching new directory %s (%d watch(es))", relative, len(plan))
        return True

    def _affordable_plan(self, directory: Path) -> list[tuple[Path, bool]] | None:
        """The most selective plan for *directory* that fits the budget.

        Mirrors :func:`_plan_watch_paths`: try the deepest split first, then
        shallower ones, then a single recursive watch on the directory itself.
        Only when even one slot is unavailable does the caller fall back to
        promoting the parent.
        """
        cache: dict[Path, list[Path]] = {}
        available = self._max_schedules - len(self._watches)
        if available <= 0:
            return None
        for depth in range(max(1, _WATCH_PLAN_DEPTH), 0, -1):
            _, plan = _plan_watch_subtree(
                directory, self._repo_root, self._ignore_patterns, 0, depth, cache
            )
            if len(plan) <= available:
                return plan
        # One recursive watch still filters every other directory in the repo.
        return [(directory, True)]

    def _promote_to_recursive(self, parent: str) -> None:
        """Trade filtering for coverage when the watch budget runs out."""
        for path in [parent, *self._descendants_of(parent)]:
            self._release_directory(path)
        self._schedule(Path(parent), recursive=True)
        self._degraded = True
        logger.warning(
            "Watch budget of %d reached; watching %s recursively instead — ignored "
            "trees under it are watched again. Raise CRG_MAX_WATCH_SCHEDULES to "
            "keep filtering.",
            self._max_schedules,
            parent,
        )

    def _release_directory(self, path: str) -> None:
        entry = self._watches.pop(path, None)
        self._shallow.discard(path)
        self._repaired_roots.discard(path)
        if entry is None:
            return
        # unschedule() joins the emitter thread with no timeout, and a wedged
        # emitter is the very thing this class exists to survive.
        _run_time_boxed(
            lambda: self._observer.unschedule(entry.handle),
            f"unschedule {path}",
            timeout=_WATCH_STOP_TIMEOUT,
        )

    # -- liveness -------------------------------------------------------

    def _watchdog_threads(self) -> list[tuple[threading.Thread, str | None]]:
        """Every thread the observer depends on, with the root it watches.

        The dispatcher, each emitter, and any reader thread an emitter owns
        (inotify keeps its buffer thread there) can die on their own; the
        process survives all three, which is what makes the failure silent.
        """
        threads: list[tuple[threading.Thread, str | None]] = []
        observer = self._observer
        if isinstance(observer, threading.Thread):
            threads.append((observer, None))
        try:
            emitters = list(getattr(observer, "emitters", ()) or ())
        except TypeError:  # a stub or mock observer — nothing to inspect
            return threads
        for emitter in emitters:
            root = getattr(getattr(emitter, "watch", None), "path", None)
            root = root if isinstance(root, str) else None
            if isinstance(emitter, threading.Thread):
                threads.append((emitter, root))
            try:
                members = list(vars(emitter).values())
            except TypeError:
                continue
            threads.extend(
                (member, root)
                for member in members
                if isinstance(member, threading.Thread) and member is not emitter
            )
        return threads

    def check_liveness(self) -> tuple[list[str], list[str]]:
        """Return ``(dead_thread_names, repaired_roots)``.

        A thread that stopped is only a death if the watch it belonged to is
        still the live watch for a directory that is still the same directory.
        Three things are deliberately not deaths:

        * a thread never seen alive — an emitter caught between construction
          and start is not a corpse;
        * a thread whose watch we have already released, or whose root is gone.
          Both backends stop an emitter when its own root disappears, so a
          plain ``rm -rf lib/`` would otherwise exit the watcher, and the
          daemon would restart it every 30s forever;
        * a thread whose root has been replaced since we scheduled it.
          ``rm -rf src && mkdir src`` inside one tick leaves the name in place
          but kills the watch, and calling that a death both exits the process
          and loses the recreated directory's contents.

        The remaining case — the watch is current, the directory is the same
        one, and its thread died anyway — is repaired once per root by
        rescheduling it, so an inode the filesystem handed straight back does
        not cost a restart.  A second death of the same root is reported, and
        the caller exits: that is #811's crash, and it must stay loud.
        """
        dead: list[str] = []
        repaired: list[str] = []
        still_present: dict[int, threading.Thread] = {}
        for thread, root in self._watchdog_threads():
            key = id(thread)
            if thread.is_alive():
                still_present[key] = thread
                continue
            # A watchdog emitter can be inserted into ``observer.emitters``
            # immediately after ``Thread.start`` but before the thread gets a
            # scheduling slice.  In that small window the first liveness
            # sample observes ``is_alive() == False`` and the old
            # ``_live_threads``-only check forgot the thread forever.  Use the
            # thread's started marker as the lower bound for observation: an
            # unstarted thread remains explicitly ignored, while a thread that
            # was started and already exited is a real failure even if the
            # first sample raced its startup.
            started_marker = getattr(thread, "_started", None)
            thread_started = thread.ident is not None
            if started_marker is not None:
                try:
                    thread_started = thread_started or bool(started_marker.is_set())
                except AttributeError:
                    pass
            if key not in self._live_threads and not thread_started:
                continue
            if root is None:
                dead.append(thread.name)
                continue
            entry = self._watches.get(root)
            if entry is None:
                logger.debug("Watch on %s was already released; not a death", root)
                continue
            if entry.identity != _watch_identity(root):
                logger.info(
                    "Watch root %s is gone or replaced; not a death — sync_watches "
                    "releases the stale watch and adopts the replacement",
                    root,
                )
                continue
            if root in self._repaired_roots:
                dead.append(thread.name)
                continue
            logger.warning(
                "Watch on %s stopped while the directory is still there; "
                "rescheduling it once before giving up",
                root,
            )
            recursive = root not in self._shallow
            self._release_directory(root)  # also clears the repair mark
            self._schedule(Path(root), recursive=recursive)
            if root not in self._watches:
                # Rescheduling failed — ENOSPC from inotify is the very trigger
                # behind #811 — so the directory is now unwatched.  That is a
                # loss of coverage, and the one thing it must not do is pass
                # quietly as a repair.
                logger.error("Could not reschedule the watch on %s", root)
                dead.append(thread.name)
                continue
            self._repaired_roots.add(root)
            repaired.append(root)
        self._live_threads = still_present
        return dead, repaired

    # -- health reporting ------------------------------------------------

    def report_health(
        self,
        *,
        observer_alive: bool,
        last_event_at: float | None = None,
        events_seen: int = 0,
        dead_threads: tuple[str, ...] = (),
        phase: str = "watching",
        force: bool = False,
    ) -> None:
        """Publish watcher health, rate-limited to one write per interval."""
        if self._health_path is None:
            return
        now = time.time()
        state = (observer_alive, self._degraded, tuple(dead_threads))
        if (
            not force
            and state == self._last_health_state
            and now - self._last_health_write < _WATCH_HEALTH_INTERVAL
        ):
            return
        payload = {
            "repo": str(self._repo_root),
            "pid": os.getpid(),
            "started_at": self._started_at,
            "updated_at": now,
            "observer_alive": observer_alive,
            "last_event_at": last_event_at,
            "events_seen": events_seen,
            "watched_paths": len(self._watches),
            "dead_threads": list(dead_threads),
            "degraded": self._degraded,
            "phase": phase,
        }
        try:
            self._health_path.parent.mkdir(parents=True, exist_ok=True)
            # Unique per writer, not per process: two supervisors in one
            # process would otherwise race on the same temp file and hand a
            # reader a torn document.
            temporary = self._health_path.with_name(f"{self._health_path.name}.{self._token}.tmp")
            temporary.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(temporary, self._health_path)
        except OSError as exc:
            logger.debug("Could not write watcher health to %s: %s", self._health_path, exc)
            return
        self._last_health_write = now
        self._last_health_state = state

    def clear_health(self) -> None:
        """Remove the health file on a clean shutdown."""
        if self._health_path is None:
            return
        try:
            self._health_path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best-effort cleanup
            pass


def _create_watch_handler(
    repo_root: Path,
    store: GraphStore,
    on_files_updated: Optional[Callable],
    *,
    initializing: bool = False,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
):
    """Create the debounced watchdog handler for one repository."""
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.utils.event_debouncer import EventDebouncer

    ignore_patterns = _load_ignore_patterns(repo_root)
    parser = CodeParser(repo_root)
    lexical_root = Path(os.path.abspath(repo_root))
    resolved_root = lexical_root.resolve()

    class WatchBatchProcessor:
        def __init__(self) -> None:
            self.failure: BaseException | None = None
            self.last_event_at: float | None = None
            self.events_seen: int = 0
            self._state_lock = threading.Lock()
            self._work_lock = threading.Lock()
            self._initializing = initializing
            # An initialization abort is distinct from an ordinary shutdown:
            # events captured before the initial graph is ready must be
            # discarded, while events queued after a successful initialization
            # still need to be drained during a clean stop.
            self._initialization_aborted = False
            self._pending_events: list[FileSystemEvent] = []

        def _relative_path(self, path: str) -> str | None:
            candidate = Path(os.path.abspath(path))
            try:
                relative = candidate.relative_to(lexical_root)
            except ValueError:
                return None
            # The exact repository root remains an in-scope event even while
            # it is absent. This lets a root deletion remove stored descendants
            # before a later tick re-adopts a replacement directory; all other
            # missing paths still require an existing in-root ancestor to guard
            # against events from a moved-out or symlinked tree.
            if candidate != lexical_root:
                existing = candidate
                while not existing.exists() and existing != lexical_root:
                    existing = existing.parent
                try:
                    existing.resolve().relative_to(resolved_root)
                except ValueError:
                    return None
            if any(
                component.is_symlink()
                for component in [
                    lexical_root / Path(*relative.parts[:index])
                    for index in range(1, len(relative.parts) + 1)
                ]
            ):
                return None
            if _should_ignore(str(relative), ignore_patterns):
                return None
            return str(relative)

        def _stored_descendants(self, relative_directory: str) -> set[str]:
            """Return stored descendants as paths relative to the watch root.

            Current graph rows use absolute paths, while older stores may use
            repository-relative paths.  Directory delete/move events are
            delivered as relative paths, so compare path components after
            normalizing both representations instead of relying on an
            absolute string prefix.  A relative legacy row is intentionally
            interpreted in this explicitly selected checkout, matching the
            reconciliation contract; absolute rows from another checkout are
            ignored.
            """
            raw_directory = normalize_file_path(relative_directory).rstrip("/")
            if raw_directory in {"", "."}:
                directory_parts: tuple[str, ...] = ()
            else:
                directory_path = Path(raw_directory)
                if directory_path.is_absolute() or re.match(r"^[A-Za-z]:/", raw_directory):
                    directory_parts = ()
                    matched_root = False
                    for root in (lexical_root, resolved_root):
                        try:
                            directory_parts = PurePosixPath(
                                directory_path.relative_to(root).as_posix()
                            ).parts
                            matched_root = True
                            break
                        except (ValueError, OSError, RuntimeError):
                            continue
                    if not matched_root:
                        # ``Path`` on POSIX treats a Windows-qualified path as
                        # relative.  Compare that representation textually so
                        # a foreign checkout cannot be mistaken for a legacy
                        # relative directory.
                        for root in (lexical_root, resolved_root):
                            root_text = normalize_file_path(root).rstrip("/")
                            if raw_directory.casefold().startswith(
                                root_text.casefold() + "/"
                            ):
                                directory_parts = PurePosixPath(
                                    raw_directory[len(root_text) + 1 :]
                                ).parts
                                matched_root = True
                                break
                    if not matched_root:
                        return set()
                else:
                    directory_parts = PurePosixPath(raw_directory).parts
            if ".." in directory_parts:
                return set()

            descendants: set[str] = set()
            for stored_path in store.get_all_files():
                normalized = normalize_file_path(stored_path)
                if not normalized or re.match(r"^[A-Za-z]:[^/]", normalized):
                    continue
                candidate = Path(normalized)
                relative: PurePosixPath | None = None
                if candidate.is_absolute():
                    for root in (lexical_root, resolved_root):
                        try:
                            relative = PurePosixPath(
                                candidate.relative_to(root).as_posix()
                            )
                            break
                        except (ValueError, OSError, RuntimeError):
                            continue
                else:
                    relative = PurePosixPath(normalized)
                if relative is None or ".." in relative.parts:
                    continue
                if (
                    len(relative.parts) > len(directory_parts)
                    and relative.parts[: len(directory_parts)] == directory_parts
                ):
                    descendants.add(relative.as_posix())
            return descendants

        def _parseable_file(self, relative_path: str) -> bool:
            absolute_path = repo_root / relative_path
            resolved_path = absolute_path.resolve()
            try:
                resolved_path.relative_to(resolved_root)
            except ValueError:
                return False
            return (
                absolute_path.is_file()
                and not absolute_path.is_symlink()
                and parser.detect_language(absolute_path) is not None
                and not _is_binary(absolute_path)
            )

        def _relevant_file(self, relative_path: str) -> bool:
            """Include non-parseable Erlang manifests in watch batches."""
            return self._parseable_file(relative_path) or _is_erlang_layout_path(
                relative_path
            )

        def _parseable_descendants(self, relative_directory: str) -> set[str]:
            directory = repo_root / relative_directory
            if not directory.is_dir() or directory.is_symlink():
                return set()
            return {
                str(path.relative_to(repo_root))
                for path in directory.rglob("*")
                if self._relevant_file(str(path.relative_to(repo_root)))
                and not _should_ignore(str(path.relative_to(repo_root)), ignore_patterns)
            }

        def _event_paths(self, event: FileSystemEvent) -> set[str]:
            paths: set[str] = set()
            source = self._relative_path(os.fsdecode(event.src_path))
            destination_path = getattr(event, "dest_path", "")
            destination = (
                self._relative_path(os.fsdecode(destination_path))
                if destination_path
                else None
            )
            if event.is_directory:
                if source is not None and event.event_type in {"deleted", "moved"}:
                    paths.update(self._stored_descendants(source))
                if destination is not None:
                    paths.update(self._parseable_descendants(destination))
                elif source is not None and event.event_type == "created":
                    paths.update(self._parseable_descendants(source))
            else:
                if source is not None and event.event_type in {"deleted", "moved"}:
                    paths.add(source)
                elif source is not None and self._relevant_file(source):
                    paths.add(source)
                if destination is not None and self._relevant_file(destination):
                    paths.add(destination)
            return paths

        def process(self, events: list[FileSystemEvent]) -> None:
            # Recorded before the work so a stalled watcher is distinguishable
            # from a watcher whose repository is simply quiet.
            self.last_event_at = time.time()
            self.events_seen += len(events)
            with self._state_lock:
                if self._initialization_aborted:
                    return
                if self._initializing:
                    self._pending_events.extend(events)
                    return
            self._process_now(events)

        def _process_now(self, events: list[FileSystemEvent]) -> None:
            with self._work_lock:
                try:
                    changed_files = sorted(
                        {path for event in events for path in self._event_paths(event)}
                    )
                    if not changed_files:
                        return
                    result = incremental_update(
                        repo_root,
                        store,
                        changed_files=changed_files,
                        reconcile_stale=False,
                        erlang_config=erlang_config,
                    )
                    _raise_watch_update_errors(result, "incremental update")
                    _run_watch_postprocess(
                        repo_root,
                        store,
                        on_files_updated,
                        result,
                    )
                # KeyboardInterrupt/SystemExit belong to the caller's
                # lifecycle boundary.  Capturing them as an asynchronous
                # update failure turns a normal Ctrl+C during parser startup
                # into ``watch update failed`` and hides the intended stop.
                # This runs on the debouncer thread.  Letting a BaseException
                # escape would silently kill that thread (and leave the watch
                # looking healthy), so record every failure and surface it at
                # the synchronous watch boundary via ``raise_if_failed``.
                except BaseException as exc:
                    with self._state_lock:
                        if self.failure is None:
                            self.failure = exc

        def finish_initialization(self) -> None:
            """Enable live processing and drain events captured during startup."""
            if not initializing:
                return
            while True:
                with self._state_lock:
                    if self._initialization_aborted:
                        self._pending_events.clear()
                        return
                    if not self._pending_events:
                        self._initializing = False
                        return
                    # Project preparation can touch many generated Erlang
                    # files while the observer is already subscribed.  Merge
                    # the accepted startup events into one batch so strict
                    # semantic preparation runs once per drain, not once per
                    # generated file.
                    events = self._pending_events
                    self._pending_events = []
                self._process_now(events)

        def abort_initialization(self) -> None:
            with self._state_lock:
                if self._initializing:
                    self._initialization_aborted = True
                self._initializing = False
                self._pending_events.clear()

        def raise_if_failed(self) -> None:
            with self._state_lock:
                failure = self.failure
            if failure is not None:
                raise RuntimeError("watch update failed") from failure

        def record_lifecycle_failure(self, description: str, timeout: float) -> None:
            """Make a bounded teardown failure visible at the watch boundary."""
            failure = TimeoutError(
                f"watch teardown timed out during {description} "
                f"after {max(0.0, timeout):.3f}s"
            )
            with self._state_lock:
                if self.failure is None:
                    self.failure = failure

        @property
        def initialization_aborted(self) -> bool:
            with self._state_lock:
                return self._initialization_aborted

    processor = WatchBatchProcessor()

    class GraphUpdateHandler(FileSystemEventHandler):
        def __init__(self) -> None:
            super().__init__()
            self._lifecycle_condition = threading.Condition()
            self._processing_local = threading.local()
            self._stopping = False
            self._started = False
            self._finalizing = False
            self._finalized = False
            self._finalizer_ident: int | None = None
            self._callback_stop_requested = False
            self._inflight = 0
            self._dispatching = 0
            self._dispatching_local = threading.local()

        def _enter_batch(self, *, during_shutdown: bool = False) -> bool:
            """Reserve one processor batch without holding a user callback lock."""
            with self._lifecycle_condition:
                if self._stopping and not during_shutdown:
                    return False
                self._inflight += 1
                return True

        def _leave_batch(self) -> None:
            with self._lifecycle_condition:
                self._inflight -= 1
                if self._inflight == 0:
                    self._lifecycle_condition.notify_all()

        def _wait_for_dispatches(self, deadline: float) -> bool:
            # A synchronous EventDebouncer test double may invoke the callback
            # from ``dispatch`` itself.  In that case one dispatch belongs to
            # this thread and must not be counted as work to wait for.
            own_dispatches = getattr(self._dispatching_local, "depth", 0)
            with self._lifecycle_condition:
                while self._dispatching > own_dispatches:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._lifecycle_condition.wait(timeout=remaining)
            return True

        def _process_batch(
            self,
            events: list[FileSystemEvent],
            *,
            during_shutdown: bool = False,
        ) -> None:
            if not self._enter_batch(during_shutdown=during_shutdown):
                return
            try:
                processor.process(events)
            finally:
                self._leave_batch()

        def _run_batch(
            self,
            events: list[FileSystemEvent],
            *,
            during_shutdown: bool = False,
        ) -> None:
            previous = getattr(self._processing_local, "active", False)
            self._processing_local.active = True
            try:
                self._process_batch(events, during_shutdown=during_shutdown)
            finally:
                self._processing_local.active = previous

        def dispatch(self, event: FileSystemEvent) -> None:
            if event.event_type not in {"created", "modified", "deleted", "moved"}:
                return
            if event.is_directory and event.event_type == "modified":
                return
            # Once teardown starts, an observer callback racing with the
            # shutdown path must not append work after the final drain.  The
            # lifecycle lock covers the check and enqueue as one operation.
            # Reserve the enqueue under the lifecycle lock, then release it
            # before taking EventDebouncer's condition.  EventDebouncer runs
            # its callback while holding that condition; keeping a strict
            # lock order here avoids a callback/dispatch deadlock.
            with self._lifecycle_condition:
                if self._stopping:
                    return
                self._dispatching += 1
                self._dispatching_local.depth = (
                    getattr(self._dispatching_local, "depth", 0) + 1
                )
            try:
                debouncer.handle_event(event)
            finally:
                with self._lifecycle_condition:
                    self._dispatching -= 1
                    # Notify on every decrement: a re-entrant finalizer may
                    # deliberately ignore its own dispatch depth and wait
                    # for other dispatchers to leave.
                    self._lifecycle_condition.notify_all()
                self._dispatching_local.depth -= 1

        def start(self) -> None:
            with self._lifecycle_condition:
                if self._stopping or self._started:
                    return
                debouncer.start()
                self._started = True

        def begin_shutdown(self) -> None:
            """Stop accepting observer callbacks before teardown begins."""
            with self._lifecycle_condition:
                self._stopping = True
            # Clear startup work before finalization can call
            # ``finish_initialization``.  Once initialization has completed,
            # this is a no-op and live debounced events remain drainable.
            processor.abort_initialization()

        def _wait_for_batches(self, deadline: float) -> bool:
            """Wait until callbacks that won the shutdown race are finished."""
            with self._lifecycle_condition:
                while self._inflight:
                    # A callback is allowed to call ``stop``.  It cannot wait
                    # for itself, so leave finalization to the outer teardown
                    # path in that re-entrant case.
                    if getattr(self._processing_local, "active", False):
                        return True
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._lifecycle_condition.wait(timeout=remaining)
            return True

        def _drain_debouncer(self) -> list[FileSystemEvent]:
            """Take queued events without relying on watchdog thread timing.

            ``EventDebouncer`` does not expose a public flush API.  Its queue
            and condition are stable across the supported watchdog releases,
            so access them only when they have the expected concrete types;
            test doubles and future implementations safely become a no-op.
            """
            condition = getattr(debouncer, "_cond", None)
            if not isinstance(condition, threading.Condition):
                return []
            with condition:
                queued = getattr(debouncer, "_events", None)
                if not isinstance(queued, list) or not queued:
                    return []
                events = list(queued)
                queued.clear()
                return events

        def _finalize_stop(self, *, wait_for_other: bool = True) -> None:
            """Stop the debouncer and drain accepted work exactly once.

            The thread that owns a debounced batch may reach this method after
            another thread has already started finalization. That thread must
            return instead of waiting for the owner: the owner is waiting in
            ``debouncer.join()`` for this callback to return.
            """
            if getattr(self._processing_local, "active", False):
                # A callback may request stop re-entrantly.  The releasable
                # debouncer observes this flag after the callback returns;
                # joining or draining here would race the callback's store.
                debouncer.stop()
                return
            deadline = time.monotonic() + max(0.0, _WATCH_STOP_TIMEOUT)
            with self._lifecycle_condition:
                if self._finalized:
                    return
                if self._finalizing:
                    # Re-entry from the finalizer's own callback (including an
                    # initial post-process callback) must return; waiting here
                    # would make the finalizer wait on itself forever.
                    if self._finalizer_ident == threading.get_ident():
                        return
                    if not wait_for_other:
                        return
                    while not self._finalized:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            processor.record_lifecycle_failure(
                                "another teardown finalizer", _WATCH_STOP_TIMEOUT
                            )
                            return
                        self._lifecycle_condition.wait(timeout=remaining)
                    return
                self._finalizing = True
                self._finalizer_ident = threading.get_ident()
            # Stopping the debouncer first prevents its run loop from moving
            # another batch out of the private queue while we drain it.  A
            # batch already handed to the callback is tracked by _inflight.
            try:
                debouncer.stop()
                if self._started and threading.current_thread() is not debouncer:
                    remaining = max(0.0, deadline - time.monotonic())
                    if not _run_time_boxed(
                        lambda: debouncer.join(timeout=remaining),
                        "debouncer join",
                        timeout=remaining,
                    ):
                        processor.record_lifecycle_failure(
                            "debouncer join", _WATCH_STOP_TIMEOUT
                        )
                dispatches_finished = self._wait_for_dispatches(deadline)
                if not dispatches_finished:
                    processor.record_lifecycle_failure(
                        "watch event dispatch", _WATCH_STOP_TIMEOUT
                    )
                batches_finished = self._wait_for_batches(deadline)
                if not batches_finished:
                    processor.record_lifecycle_failure(
                        "watch update callback", _WATCH_STOP_TIMEOUT
                    )
                # The queue and pending startup list can lead back to the same
                # user callback.  Once either accepted-work wait times out,
                # draining them here would reintroduce the unbounded wait that
                # teardown is intended to avoid.
                if not dispatches_finished or not batches_finished:
                    return
                # Events delivered while the initial build was running live in
                # a separate pending list.  On an aborted startup they must be
                # discarded along with the debouncer queue; a clean shutdown
                # drains them before the queue so no accepted event is lost.
                if not processor.initialization_aborted:
                    processor.finish_initialization()
                events = self._drain_debouncer()
                if events and not processor.initialization_aborted:
                    self._run_batch(events, during_shutdown=True)
            finally:
                with self._lifecycle_condition:
                    self._finalized = True
                    self._finalizing = False
                    self._finalizer_ident = None
                    self._lifecycle_condition.notify_all()

        def flush(self) -> None:
            """Request shutdown and drain accepted work exactly once."""
            callback_active = bool(getattr(self._processing_local, "active", False))
            if callback_active:
                # Only a callback that explicitly requested stop may hand
                # finalization back to the debouncer thread.  An ordinary
                # outer shutdown sets ``_stopping`` while a callback is
                # unwinding; letting that callback claim finalization races
                # the outer thread's join and can deadlock teardown.
                with self._lifecycle_condition:
                    self._callback_stop_requested = True
            self.begin_shutdown()
            if callback_active:
                # The enclosing process/process_debounced call finalizes after
                # it releases the processor's work lock.  Returning here is
                # essential for callback re-entry: waiting for that same batch
                # would deadlock and an unowned background finalizer could race
                # a caller closing the GraphStore.
                return
            self._finalize_stop()

        def stop(self) -> None:
            self.flush()

        def process(self, events: list[FileSystemEvent]) -> None:
            # Synthetic repair batches enter through the same acceptance gate
            # as observer callbacks, but the potentially slow parser and user
            # callback run outside the lifecycle lock.
            self._run_batch(events)
            with self._lifecycle_condition:
                callback_stop_requested = self._callback_stop_requested
                self._callback_stop_requested = False
            if callback_stop_requested and not self._finalized:
                self._finalize_stop(wait_for_other=False)

        def process_debounced(self, events: list[FileSystemEvent]) -> None:
            # EventDebouncer has already accepted these events before stop;
            # allow the batch to complete during shutdown.
            self._run_batch(events, during_shutdown=True)
            # ``stop()`` may be called by the user callback itself.  In that
            # re-entrant case ``flush`` cannot join or drain from the
            # debouncer thread, so the callback thread must hand off to the
            # non-reentrant finalization path after its batch has returned.
            with self._lifecycle_condition:
                callback_stop_requested = self._callback_stop_requested
                self._callback_stop_requested = False
            if callback_stop_requested and not self._finalized:
                self._finalize_stop(wait_for_other=False)

        def finish_initialization(self) -> None:
            processor.finish_initialization()

        def abort_initialization(self) -> None:
            processor.abort_initialization()

        def raise_if_failed(self) -> None:
            processor.raise_if_failed()

        @property
        def last_event_at(self) -> float | None:
            return processor.last_event_at

        @property
        def events_seen(self) -> int:
            return processor.events_seen

    handler = GraphUpdateHandler()

    def _debounced_callback(events: list[FileSystemEvent]) -> None:
        handler.process_debounced(events)

    # watchdog's implementation invokes the callback while holding its
    # condition.  That makes a callback-triggered stop vulnerable to a lost
    # wake-up and self-join.  Keep the same queue/debounce contract while
    # releasing the condition before invoking user/parser work.
    if isinstance(EventDebouncer, type):
        class _ReleasableEventDebouncer(EventDebouncer):
            def run(self) -> None:
                while self.should_keep_running():
                    with self._cond:
                        if not self.should_keep_running():
                            return
                        if not self._events:
                            self._cond.wait()
                        if not self.should_keep_running():
                            return
                        if self.debounce_interval_seconds:
                            while self.should_keep_running():
                                if not self._cond.wait(
                                    timeout=self.debounce_interval_seconds
                                ):
                                    break
                        if not self.should_keep_running():
                            return
                        events = self._events
                        self._events = []
                    self.events_callback(events)

        debouncer = _ReleasableEventDebouncer(
            _DEBOUNCE_SECONDS, _debounced_callback
        )
    else:
        # Test doubles and future watchdog shims may expose a factory rather
        # than a class; preserve their injection surface.
        debouncer = EventDebouncer(_DEBOUNCE_SECONDS, _debounced_callback)
    return handler


def _sync_watch_tree(supervisor: _WatchSupervisor, handler: Any) -> None:
    """Reconcile watches, then bring the graph in line with what changed.

    A directory adopted this tick may already hold files, and one that
    vanished may still have nodes in the graph — on macOS neither produces a
    single event, so the sync has to do the bookkeeping itself.  The work goes
    through the debouncer, exactly as a real event would, so indexing a large
    new directory never blocks the loop that publishes the heartbeat.
    """
    from watchdog.events import DirCreatedEvent, DirDeletedEvent

    adopted, vanished = supervisor.sync_watches()
    for path in vanished:
        handler.dispatch(DirDeletedEvent(path))
    # A path can be both vanished and adopted in one tick when its inode was
    # replaced.  Queue the deletion first so synchronous debouncer shims (and
    # a zero-delay test configuration) cannot index the new tree and then
    # immediately remove it again from the old deletion snapshot.
    for path in adopted:
        handler.dispatch(DirCreatedEvent(path))


def _install_sigterm_interrupt() -> Callable[[], None]:
    """Make SIGTERM unwind like Ctrl+C, and return an undo callable.

    ``crg-daemon stop`` terminates its children, so without this the watcher
    dies at 143 and leaves its health file behind, which then reads as a
    stalled watcher forever.  Only the main thread may install handlers.
    """
    def _raise_interrupt(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):  # not the main thread, or no SIGTERM
        return lambda: None

    def _restore() -> None:
        try:
            signal.signal(signal.SIGTERM, previous)
        except (ValueError, OSError):  # pragma: no cover - shutdown race
            pass

    return _restore


def watch(
    repo_root: Path,
    store: GraphStore,
    on_files_updated: Optional[Callable] = None,
    stop_event: threading.Event | None = None,
    *,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
    ready_event: threading.Event | None = None,
) -> None:
    """Watch for file changes and auto-update the graph.

    Uses a one-second debounce to batch rapid-fire saves into a single update.

    Ignored trees are never handed to the OS watcher, and every tick checks
    that watchdog's own threads are still running: a dead one raises, so the
    process exits non-zero and the daemon restarts it instead of the graph
    going quietly stale.  See: #811.

    Args:
        repo_root: Repository root to watch.
        store: Graph database to update.
        on_files_updated: Optional callback invoked after each debounced
            batch of file updates completes.  Receives the store as its
            only argument.  Used by the CLI to run post-processing
            (FTS, flows, communities) after watch updates.
        stop_event: Optional event that ends the loop cleanly, for callers
            that run ``watch`` on a thread they need to shut down.
        ready_event: Optional event set after initial reconciliation and
            post-processing have completed, immediately before live watching
            begins.  This is useful for bounded lifecycle smoke tests.

    Raises:
        RuntimeError: if a watch update fails, or if the filesystem observer
            stops running.
    """
    from watchdog.events import DirCreatedEvent, DirDeletedEvent
    from watchdog.observers import Observer

    # One boundary, once: ``--repo .`` reaches here relative, and every path
    # comparison below — stored file paths, watch keys, event paths — assumes
    # they are all spelled the same way.
    repo_root = _canonical_repo_root(repo_root)
    # Refuse a clearly foreign graph before creating an observer or writing a
    # transient health record.  A valid shared store may contain mixed roots;
    # the guard only rejects the total-mismatch case.
    _assert_graph_matches_root(repo_root, store)
    supervisor = _WatchSupervisor(
        None,
        repo_root,
        _load_ignore_patterns(repo_root),
        health_path=_watch_health_path(repo_root),
    )
    # Subscribe before reconciling the graph.  A repository can change while
    # the initial update is running; the handler holds those events in a
    # pending batch and drains it after the initial state is known.
    observer = Observer()
    supervisor.attach(observer)
    handler = _create_watch_handler(
        repo_root,
        store,
        on_files_updated,
        initializing=True,
        erlang_config=erlang_config,
    )
    restore_sigterm = _install_sigterm_interrupt()
    initialization_complete = False
    completed_cleanly = False
    observer_started = False
    try:
        supervisor.schedule_initial(handler)
        handler.start()
        observer.start()
        observer_started = True
        supervisor.report_health(observer_alive=True, phase="initial-build", force=True)

        initial = incremental_update(
            repo_root,
            store,
            changed_files=[],
            erlang_config=erlang_config,
        )
        _raise_watch_update_errors(initial, "initial watch reconciliation")
        _run_watch_postprocess(repo_root, store, on_files_updated, initial)

        # Flip the gate only after the initial callback has succeeded.  Any
        # event delivered concurrently is either still pending or is handled
        # by the normal live path after the lock transition.
        handler.finish_initialization()
        handler.raise_if_failed()
        initialization_complete = True
        supervisor.report_health(observer_alive=True, phase="watching", force=True)
        if ready_event is not None:
            ready_event.set()

        logger.info("Watching %s for changes... (Ctrl+C to stop)", repo_root)
        while True:
            if stop_event is not None:
                if stop_event.wait(_WATCH_TICK_SECONDS):
                    break
            else:
                _watch_sleep(_WATCH_TICK_SECONDS)
            handler.raise_if_failed()
            _sync_watch_tree(supervisor, handler)
            dead, repaired = supervisor.check_liveness()
            for path in repaired:
                # A rescheduled watch missed whatever happened while it was
                # down, so re-read the directory rather than trust the gap.
                # Both halves are needed: the deletion contributes the stored
                # descendants, without which a file removed during the outage
                # keeps its rows, and the creation contributes what is on disk
                # now.  Watch batches run with reconcile_stale=False, so
                # nothing else would ever catch the stale side.
                # This reconciliation is correctness-critical: queueing the
                # synthetic events through the debounce thread can leave them
                # unprocessed when shutdown follows immediately after the
                # repair tick.  Process both halves as one serialized batch;
                # ordinary filesystem events remain debounced.
                handler.process([DirDeletedEvent(path), DirCreatedEvent(path)])
            if dead:
                names = ", ".join(dead)
                supervisor.report_health(
                    observer_alive=False,
                    last_event_at=handler.last_event_at,
                    events_seen=handler.events_seen,
                    dead_threads=tuple(dead),
                    force=True,
                )
                logger.error(
                    "Filesystem watcher thread(s) died (%s); %s would stop updating "
                    "silently, so this watcher is exiting for the daemon to restart it",
                    names,
                    repo_root,
                )
                raise RuntimeError(f"watch observer stopped: dead thread(s) {names}")
            supervisor.report_health(
                observer_alive=True,
                last_event_at=handler.last_event_at,
                events_seen=handler.events_seen,
            )
        supervisor.clear_health()
        completed_cleanly = True
    except KeyboardInterrupt:
        supervisor.clear_health()
        handler.abort_initialization()
    except BaseException:
        # Keep an unhealthy health record after a live watcher failure so the
        # daemon can report why it stopped.  Startup failures have no usable
        # watcher to diagnose and should remove their transient record.
        if not initialization_complete:
            supervisor.clear_health()
        handler.abort_initialization()
        raise
    finally:
        # Prevent callbacks racing observer shutdown from adding work after
        # the final drain.  ``handler.stop`` repeats the guard and is
        # idempotent for callers that own teardown themselves.
        handler.begin_shutdown()
        restore_sigterm()
        # ``Observer.start`` can fail after starting one or more emitters but
        # before its own dispatcher thread is marked started.  Always signal
        # stop, then either join a started dispatcher or explicitly release
        # unstarted/partially-started emitters.  Calling ``join`` on an
        # unstarted Thread raises and would mask the startup exception.
        _run_time_boxed(observer.stop, "observer stop")
        observer_thread_started = observer_started
        if isinstance(observer, threading.Thread):
            marker = getattr(observer, "_started", None)
            if isinstance(marker, threading.Event):
                observer_thread_started = observer_thread_started or marker.is_set()
        if observer_thread_started:
            # A backend can wedge while joining (and test doubles are free to
            # ignore the timeout argument), so keep teardown bounded just like
            # unscheduling.  Joining only after a successful start avoids the
            # ``cannot join thread before it is started`` error masking a
            # startup failure.
            _run_time_boxed(
                lambda: observer.join(timeout=_WATCH_STOP_TIMEOUT),
                "observer join",
                timeout=_WATCH_STOP_TIMEOUT,
            )
        else:
            # BaseObserver.stop only sets its stop flag; its on_thread_stop
            # cleanup runs from the dispatcher thread, which never started in
            # this branch.  Unschedule all emitters directly so a partial
            # Observer.start failure cannot leak backend resources.
            unschedule_all = getattr(observer, "unschedule_all", None)
            if callable(unschedule_all):
                _run_time_boxed(unschedule_all, "observer unschedule_all")
        handler.stop()
        if completed_cleanly:
            # A debounced batch can finish during teardown after the last
            # health tick.  Surface its failure when there is no higher-level
            # exception already being propagated; Ctrl+C/runtime failures keep
            # their original exception and are intentionally not replaced.
            handler.raise_if_failed()
    logger.info("Watch stopped.")


def start_watch_thread(
    repo_root: Path,
    store: GraphStore,
    daemon: bool = True,
    *,
    erlang_config: Any = _ERLANG_CONFIG_UNSET,
) -> threading.Thread | None:
    """Start watch mode in a background thread.

    Returns the started thread, or None if watchdog is unavailable.
    """
    try:
        import watchdog  # noqa: F401
    except ImportError:
        logger.warning("watchdog not installed; auto-watch disabled")
        return None

    def _run() -> None:
        # A thread cannot take the process down, so the one thing it must not
        # do is die quietly: the server would keep serving a frozen graph.
        try:
            watch(repo_root, store, erlang_config=erlang_config)
        except RuntimeError as exc:
            logger.error("Auto-watch for %s stopped: %s", repo_root, exc)

    thread = threading.Thread(
        target=_run,
        daemon=daemon,
        name="crg-watch",
    )
    thread.start()
    logger.info("Auto-watch started for %s", repo_root)
    return thread
