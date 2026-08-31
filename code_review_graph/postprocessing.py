"""Shared post-build processing pipeline.

After the core Tree-sitter parse (full_build or incremental_update), five
post-processing steps must run to populate derived tables:

1. Resolve evidence-backed bare edge endpoints
2. Compute node signatures
3. Rebuild FTS5 search index
4. Trace execution flows
5. Detect code communities

An embedding refresh can be added as an explicit fifth step by supplying an
exact provider and model.  It is default-off because cloud providers transmit
source-derived text and may incur API cost.

This module extracts that pipeline so every entry point — MCP tool, CLI
commands, and watch mode — produces identical results.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from .graph import GraphStore

logger = logging.getLogger(__name__)


def run_post_processing(
    store: GraphStore,
    *,
    repo_root: str | Path | None = None,
    embedding_provider: str | None = None,
    embedding_model: str | None = None,
) -> dict[str, Any]:
    """Run all post-build steps on a populated graph.

    Each step is non-fatal: failures are logged and collected as warnings
    so the primary build result is never lost.

    Args:
        store: An open GraphStore with nodes and edges already populated.

    Returns:
        Dict with keys for each step's result count and a ``warnings``
        list (only present when at least one step failed).
    """
    result: dict[str, Any] = {}
    warnings: list[str] = []

    # Keep stage timings in the result so lifecycle evaluators can identify
    # repository-wide work without relying on log parsing.  A stage is recorded
    # even when its best-effort operation raises; this is useful evidence for a
    # degraded or timed-out lifecycle run.
    timing: dict[str, float] = {}

    def run_stage(name: str, operation: Any) -> None:
        started = time.perf_counter()
        try:
            operation()
        finally:
            timing[name] = max(0.0, round(time.perf_counter() - started, 6))

    run_stage(
        "bare_endpoints_s",
        lambda: _resolve_bare_endpoints(store, result, warnings, repo_root=repo_root),
    )
    run_stage("signatures_s", lambda: _compute_signatures(store, result, warnings))
    run_stage("fts_s", lambda: _rebuild_fts_index(store, result, warnings))
    run_stage("flows_s", lambda: _trace_flows(store, result, warnings))
    run_stage("communities_s", lambda: _detect_communities(store, result, warnings))
    run_stage(
        "embeddings_s",
        lambda: _refresh_embeddings(
            store,
            result,
            warnings,
            provider=embedding_provider,
            model=embedding_model,
        ),
    )

    if warnings:
        result["warnings"] = warnings
    result["postprocess_timing"] = timing
    return result


# -- Individual steps (private) ------------------------------------------


def _resolve_bare_endpoints(
    store: GraphStore,
    result: dict[str, Any],
    warnings: list[str],
    *,
    repo_root: str | Path | None = None,
) -> None:
    """Resolve language endpoints before derived graph steps."""
    # Erlang include/record endpoints must be canonical before generic call
    # resolution and impact/FTS derivation.  The pass is deliberately
    # best-effort so a malformed optional project config cannot discard the
    # primary graph.
    try:
        from .erlang_header_resolver import resolve_erlang_header_records

        result["erlang_header_resolution"] = resolve_erlang_header_records(
            store, repo_root,
        )
    except Exception as exc:  # noqa: BLE001 - post-processing is non-fatal
        logger.warning("Erlang header/record resolution failed: %s", exc)
        warnings.append(
            "Erlang header/record resolution failed: "
            f"{type(exc).__name__}: {exc}"
        )

    try:
        resolved = store.resolve_bare_call_targets(repo_root=repo_root)
        resolved += store.resolve_bare_tested_by_sources(repo_root=repo_root)
        result["bare_edges_resolved"] = resolved
        result["cpp_scoped_edges_resolved"] = (
            store.resolve_cpp_scoped_call_targets()
        )
    except sqlite3.OperationalError as e:
        logger.warning("Call-target resolution failed: %s", e)
        warnings.append(
            f"Call-target resolution failed: {type(e).__name__}: {e}"
        )


def _compute_signatures(
    store: GraphStore,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """Compute human-readable signatures for nodes that lack one."""
    try:
        rows = store.get_nodes_without_signature()
        for row in rows:
            node_id, name, kind, params, ret = (
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
            )
            if kind in ("Function", "Test"):
                sig = f"def {name}({params or ''})"
                if ret:
                    sig += f" -> {ret}"
            elif kind == "Class":
                sig = f"class {name}"
            else:
                sig = name
            store.update_node_signature(node_id, sig[:512])
        store.commit()
        result["signatures_computed"] = len(rows)
    except (sqlite3.OperationalError, TypeError, KeyError) as e:
        logger.warning("Signature computation failed: %s", e)
        warnings.append(f"Signature computation failed: {type(e).__name__}: {e}")


def _rebuild_fts_index(
    store: GraphStore,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """Rebuild the FTS5 full-text search index."""
    try:
        from .search import rebuild_fts_index

        fts_count = rebuild_fts_index(store)
        result["fts_indexed"] = fts_count
    except (sqlite3.OperationalError, ImportError) as e:
        logger.warning("FTS index rebuild failed: %s", e)
        warnings.append(f"FTS index rebuild failed: {type(e).__name__}: {e}")


def _trace_flows(
    store: GraphStore,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """Trace execution flows from entry points."""
    try:
        from .flows import store_flows, trace_flows

        flows = trace_flows(store)
        count = store_flows(store, flows)
        result["flows_detected"] = count
    except (sqlite3.OperationalError, ImportError) as e:
        logger.warning("Flow detection failed: %s", e)
        warnings.append(f"Flow detection failed: {type(e).__name__}: {e}")


def _detect_communities(
    store: GraphStore,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """Detect code communities via Leiden algorithm or file grouping."""
    try:
        from .communities import detect_communities, store_communities

        comms = detect_communities(store)
        count = store_communities(store, comms)
        result["communities_detected"] = count
    except (sqlite3.OperationalError, ImportError) as e:
        logger.warning("Community detection failed: %s", e)
        warnings.append(f"Community detection failed: {type(e).__name__}: {e}")


def _refresh_embeddings(
    store: GraphStore,
    result: dict[str, Any],
    warnings: list[str],
    *,
    provider: str | None,
    model: str | None,
) -> None:
    """Run an explicitly requested embedding refresh without failing a build."""
    if provider is None and model is None:
        return
    if not provider or not model:
        warning = "Embedding refresh requires both an explicit provider and model."
        logger.warning(warning)
        warnings.append(warning)
        return

    try:
        from .embeddings import refresh_embeddings

        refreshed = refresh_embeddings(store, provider=provider, model=model)
        if refreshed is not None:
            result["embeddings_refreshed"] = refreshed["embedded"]
            result["embeddings_purged"] = refreshed["purged"]
    except Exception as exc:
        logger.warning("Embedding refresh failed: %s", exc)
        warnings.append(
            f"Embedding refresh failed: {type(exc).__name__}: {exc}",
        )
