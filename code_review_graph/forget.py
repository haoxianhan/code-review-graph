"""Forget parsed files from the graph while keeping every derived layer sane.

Dropping a file's own nodes and edges is not enough to match the graph a full
rebuild without that file would produce:

* surviving files that referenced it keep dangling, still-qualified edges
  (a call resolved to ``other.py::helper`` stays pointing at a node that no
  longer exists instead of falling back to the bare ``helper``);
* the derived layers — execution flows, communities, the FTS index, and
  embeddings — continue to reference the deleted nodes.

``forget_files`` therefore removes the files, re-parses the surviving referrers
so their cross-file edges are re-derived exactly as a build would, re-runs the
repository-wide Python import resolver and shared post-processing pipeline
(which fully recomputes flows, communities, signatures, and FTS and re-resolves
bare endpoints), and purges embedding vectors whose node is gone. The result is
equivalent to building the graph without the forgotten files.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from .graph import GraphStore

logger = logging.getLogger(__name__)

# Keep IN-clause windows comfortably under SQLite's default 999-variable limit.
_SQL_PARAM_CHUNK = 400
_NON_SOURCE_LAYOUT_BASENAMES = frozenset({"erlang_ls.config"})


def _canonical_path(value: str | Path) -> Path:
    """Return a stable path for repository ownership comparisons."""
    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return Path(value).expanduser().absolute()


def _assert_graph_matches_root(repo_root: Path, store: GraphStore) -> None:
    """Reject a total repository-root mismatch before mutating the graph.

    A shared GraphStore may legitimately contain files from multiple
    checkouts.  We therefore allow mixed roots and only fail when authoritative
    ``File`` markers exist but none can be placed under the requested root.
    Graphs without markers (including legacy/orphan-only stores) retain the
    historical forget behavior.
    """
    expected_root = _canonical_path(repo_root)
    markers = store.get_file_marker_paths()
    if not markers:
        return

    def belongs_to_root(value: str) -> bool:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            # Older graphs sometimes persisted repository-relative File paths.
            candidate = expected_root / candidate
        try:
            candidate.resolve(strict=False).relative_to(expected_root)
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    if any(belongs_to_root(path) for path in markers):
        return
    sample = _canonical_path(markers[0])
    raise RuntimeError(
        f"the graph holds {len(markers)} File marker(s) such as {sample!s}, "
        f"none under {expected_root!s}; it was built with a different "
        "repository root. Rebuild it, or retry with the root it was built "
        "with, instead of forgetting files from another checkout."
    )


def _assert_targets_belong_to_root(repo_root: Path, targets: list[str]) -> None:
    """Reject forget targets that resolve outside the requested checkout."""
    expected_root = _canonical_path(repo_root)
    foreign: list[str] = []
    for raw in targets:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = expected_root / candidate
        try:
            candidate.resolve(strict=False).relative_to(expected_root)
        except (OSError, RuntimeError, ValueError):
            foreign.append(str(raw))
    if foreign:
        sample = foreign[0]
        raise ValueError(
            f"forget target {sample!r} is outside repository root "
            f"{expected_root!s}; refusing to mutate a foreign checkout"
        )


def _referrer_files(
    store: GraphStore,
    deleted_qualified_names: set[str],
    forgotten: set[str],
    *,
    repo_root: Path | None = None,
) -> list[str]:
    """Return surviving files whose edges point at any forgotten node.

    Those edges are precisely the ones a rebuild would re-derive (usually
    dropping back to a bare endpoint), so the files owning them must be
    re-parsed for parity.
    """
    if not deleted_qualified_names:
        return []
    conn = store._conn
    referrers: set[str] = set()
    names = list(deleted_qualified_names)
    for start in range(0, len(names), _SQL_PARAM_CHUNK):
        window = names[start:start + _SQL_PARAM_CHUNK]
        placeholders = ",".join("?" for _ in window)
        rows = conn.execute(
            f"SELECT DISTINCT file_path FROM edges "
            f"WHERE target_qualified IN ({placeholders}) "
            f"OR source_qualified IN ({placeholders})",
            window + window,
        ).fetchall()
        referrers.update(row["file_path"] for row in rows)

    # Erlang's Generic parser intentionally leaves unresolved remote calls as
    # bare MFAs (``worker:run/0``) and local calls as ``run/0``.  The node
    # qualified name being removed is path-qualified (for example
    # ``/repo/src/worker.erl::worker.run/0``), so the exact-name query above
    # cannot discover those callers.  Derive the stable aliases from the
    # deleted node metadata and match them before the node rows disappear.
    # Bare local aliases are later restricted to consumers that explicitly
    # import the deleted module: a common ``run/0`` helper in another module is
    # not evidence that it references this one.
    node_rows: list[Any] = []
    for start in range(0, len(names), _SQL_PARAM_CHUNK):
        window = names[start:start + _SQL_PARAM_CHUNK]
        placeholders = ",".join("?" for _ in window)
        node_rows.extend(
            conn.execute(
                f"SELECT qualified_name, file_path, kind, name, parent_name, extra, "
                f"language FROM nodes WHERE qualified_name IN ({placeholders})",
                window,
            ).fetchall()
        )
    module_aliases: dict[str, set[str]] = {}
    module_names: set[str] = set()
    for row in node_rows:
        # Bare MFA/module aliases are an Erlang parser convention.  A custom
        # parser in the same shared database may use the same node kinds and
        # arity metadata, but its symbols must never drive Erlang referrer
        # discovery.
        if str(row["language"] or "").casefold() != "erlang":
            continue
        kind = str(row["kind"] or "")
        name = str(row["name"] or "").strip()
        parent = str(row["parent_name"] or "").strip()
        extra: dict[str, Any] = {}
        raw_extra = row["extra"]
        if isinstance(raw_extra, str):
            try:
                decoded = json.loads(raw_extra)
                if isinstance(decoded, dict):
                    extra = decoded
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        arity: int | None = None
        raw_arity = extra.get("arity")
        if raw_arity is not None:
            try:
                arity = int(raw_arity)
            except (TypeError, ValueError, OverflowError):
                arity = None
        if arity is None:
            suffix = str(row["qualified_name"] or "").rsplit("::", 1)[-1]
            tail = suffix.rsplit(".", 1)[-1]
            if "/" in tail:
                raw_tail = tail.rsplit("/", 1)[-1]
                if raw_tail.isdigit():
                    arity = int(raw_tail)
        is_callable = kind in {"Function", "Test", "Type"} and bool(name)
        if is_callable and arity is not None:
            identity = f"{name}/{arity}"
            if parent:
                module_names.add(parent)
                module_aliases.setdefault(parent, set()).add(identity)
        elif kind == "Class" and name and extra.get("erlang_kind") == "module":
            # Module-level behaviour/import edges use the bare module atom.
            module_names.add(name)

    remote_aliases = {
        f"{module}:{identity}"
        for module, identities in module_aliases.items()
        for identity in identities
    } | module_names

    erlang_edge_source = (
        "EXISTS (SELECT 1 FROM nodes AS source_file "
        "WHERE source_file.kind = 'File' "
        "AND source_file.file_path = edges.file_path "
        "AND lower(source_file.language) = 'erlang')"
    )

    if remote_aliases:
        aliases = list(remote_aliases)
        for start in range(0, len(aliases), _SQL_PARAM_CHUNK):
            window = aliases[start:start + _SQL_PARAM_CHUNK]
            placeholders = ",".join("?" for _ in window)
            rows = conn.execute(
                f"SELECT DISTINCT file_path FROM edges "
                f"WHERE target_qualified IN ({placeholders}) "
                f"AND {erlang_edge_source}",
                window,
            ).fetchall()
            referrers.update(row["file_path"] for row in rows)
    # A bare local MFA can refer to a deleted module only when the consumer
    # explicitly imports that module.  Resolve that relation first, then
    # restrict the MFA lookup to those consumer files; otherwise a common
    # ``run/0`` helper in an unrelated module would be falsely re-parsed.
    for module, aliases in module_aliases.items():
        imported_rows = conn.execute(
            "SELECT DISTINCT file_path FROM edges "
            "WHERE kind = 'IMPORTS_FROM' AND "
            "(target_qualified = ? OR lower(target_qualified) = lower(?)) "
            "AND " + erlang_edge_source,
            (module, module),
        ).fetchall()
        consumer_files = {
            row["file_path"] for row in imported_rows if row["file_path"] not in forgotten
        }
        if not consumer_files:
            continue
        values = list(aliases)
        for start in range(0, len(values), _SQL_PARAM_CHUNK):
            window = values[start:start + _SQL_PARAM_CHUNK]
            placeholders = ",".join("?" for _ in window)
            file_placeholders = ",".join("?" for _ in consumer_files)
            rows = conn.execute(
                f"SELECT DISTINCT file_path FROM edges "
                f"WHERE file_path IN ({file_placeholders}) "
                f"AND target_qualified IN ({placeholders}) "
                f"AND {erlang_edge_source}",
                [*sorted(consumer_files), *window],
            ).fetchall()
            referrers.update(row["file_path"] for row in rows)

    # Erlang preprocessor includes are intentionally stored as their source
    # spelling (for example ``sample.hrl``), so they do not point at the
    # included file's node qualified name. Re-parse matching referrers when a
    # forgotten target is an Erlang header, just as incremental updates do.
    for forgotten_file in forgotten:
        header_name = Path(forgotten_file).name
        if not header_name.lower().endswith(".hrl"):
            continue
        rows = conn.execute(
            "SELECT DISTINCT file_path FROM edges "
            "WHERE kind = 'IMPORTS_FROM' AND "
            "(lower(target_qualified) = lower(?) OR "
            "lower(target_qualified) LIKE lower(?)) AND "
            + erlang_edge_source,
            (header_name, f"%/{header_name}"),
        ).fetchall()
        referrers.update(row["file_path"] for row in rows)
    # ``erlang_ls.config`` participates in toolchain discovery but is not an
    # Erlang source unit.  Older/custom graphs may nevertheless contain a
    # File/edge row for it; never ask the parser to re-process that layout
    # manifest as a referrer during forget.
    surviving = {
        path
        for path in (referrers - forgotten)
        if Path(path).name.casefold() not in _NON_SOURCE_LAYOUT_BASENAMES
    }
    if repo_root is not None:
        try:
            expected_root = Path(repo_root).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            expected_root = Path(repo_root).expanduser().absolute()

        def belongs_to_root(path: str) -> bool:
            try:
                candidate = Path(path).expanduser()
                if not candidate.is_absolute():
                    candidate = expected_root / candidate
                candidate.resolve(strict=False).relative_to(expected_root)
                return True
            except (OSError, RuntimeError, ValueError):
                return False

        surviving = {path for path in surviving if belongs_to_root(path)}
    return sorted(surviving)


def _purge_orphan_embeddings(store: GraphStore) -> int:
    """Delete embedding vectors whose graph node no longer exists.

    Mirrors :meth:`embeddings.EmbeddingStore.purge_orphans` but runs on the
    graph's own connection so we never open a second writer. A graph without
    an embeddings table is a no-op.
    """
    conn = store._conn
    has_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'embeddings'"
    ).fetchone()
    if has_table is None:
        return 0
    cursor = conn.execute(
        "DELETE FROM embeddings WHERE NOT EXISTS ("
        "SELECT 1 FROM nodes WHERE nodes.qualified_name = embeddings.qualified_name"
        ")"
    )
    return max(cursor.rowcount, 0)


def forget_files(
    store: GraphStore,
    repo_root: Path,
    targets: list[str],
    *,
    erlang_config: Any = None,
) -> dict[str, Any]:
    """Remove ``targets`` from the graph and repair every derived layer.

    Args:
        store: An open graph store.
        repo_root: Repository root, used to re-parse surviving referrers.
        targets: Absolute file paths (as stored in the graph) to forget.
        erlang_config: Optional Erlang integration configuration. ``None``
            leaves bridge activation to ``CRG_ERLANG_*`` environment settings.

    Returns:
        A summary dict with the forgotten files, the referrer files that were
        re-parsed, and the number of orphaned embedding vectors purged.
    """
    from .incremental import _ERLANG_CONFIG_UNSET, _run_erlang_lifecycle
    from .parser import CodeParser
    from .postprocessing import run_post_processing
    from .python_resolver import resolve_python_imports

    # Fail closed before taking a shared database mutation when it is clearly
    # anchored to another checkout. Empty/legacy stores without File markers
    # intentionally keep the historical behavior.
    _assert_graph_matches_root(Path(repo_root), store)
    _assert_targets_belong_to_root(Path(repo_root), targets)

    forgotten = set(targets)

    # 1. Snapshot the qualified names about to disappear so we can find the
    #    surviving files that reference them (before we delete anything).
    deleted_qualified_names: set[str] = set()
    for file_path in targets:
        for node in store.get_nodes_by_file(file_path):
            deleted_qualified_names.add(node.qualified_name)

    referrers = _referrer_files(
        store,
        deleted_qualified_names,
        forgotten,
        repo_root=repo_root,
    )

    # 2. Drop the forgotten files' own nodes and edges.
    for file_path in targets:
        store.remove_file_data(file_path)
    # Persist deletions before store_file_nodes_edges() opens its own
    # explicit transaction (BEGIN IMMEDIATE) during the re-parse below.
    store.commit()

    # 3. Re-parse the surviving referrers so their cross-file edges are
    #    re-derived exactly as a build would: edges that had resolved into a
    #    forgotten file fall back to bare and are re-resolved against the
    #    smaller graph, while edges into other survivors are preserved. The
    #    forgotten files are hidden from import resolution so a still-on-disk
    #    file is not silently re-resolved (forget removes it from the graph,
    #    not from the working tree).
    parser = CodeParser(repo_root)
    parser.exclude_files(forgotten)
    reparsed: list[str] = []
    for file_path in referrers:
        abs_path = Path(file_path)
        if not abs_path.is_file():
            # Referrer is gone from disk; nothing to re-parse. Its stale edges
            # are cleaned up by post-processing's bare re-resolution below.
            continue
        if parser.detect_language(abs_path) is None:
            continue
        try:
            source = abs_path.read_bytes()
            fhash = hashlib.sha256(source).hexdigest()
            nodes, edges = parser.parse_bytes(abs_path, source)
            store.store_file_nodes_edges(str(abs_path), nodes, edges, fhash)
            reparsed.append(file_path)
        except (OSError, PermissionError) as exc:
            logger.warning("Could not re-parse referrer %s: %s", file_path, exc)
        except Exception as exc:  # noqa: BLE001 - a parser failure is non-fatal
            logger.warning("Error re-parsing referrer %s: %s", file_path, exc)

    # 4. Re-run repository-wide Python import resolution. A forgotten file can
    #    turn an ambiguous module suffix into a unique survivor even when the
    #    import edge did not directly target the forgotten node, so referrer
    #    re-parsing alone cannot discover this transition.
    try:
        resolve_python_imports(store)
    except Exception as exc:  # noqa: BLE001 - resolver failure is non-fatal
        logger.warning("Python import resolver failed after forget: %s", exc)

    # 5. Reconcile optional Erlang evidence before derived graph layers are
    # rebuilt. The lifecycle helper is called once here so a forget operation
    # cannot accidentally run the bridge twice through a wrapper callback.
    # Include surviving referrers in the changed set: their targets are the
    # useful ELP enrichment inputs after an included module/header disappears.
    lifecycle_config = (
        _ERLANG_CONFIG_UNSET if erlang_config is None else erlang_config
    )
    erlang_result = _run_erlang_lifecycle(
        Path(repo_root),
        store,
        config=lifecycle_config,
        changed_files=sorted(forgotten | set(reparsed)),
        force=True,
    )

    # 6. Re-run the shared post-processing pipeline. store_flows and
    #    store_communities clear their tables first, so flows and communities
    #    are fully recomputed; signatures and FTS are rebuilt; and any edge
    #    left bare by the re-parse is re-resolved.
    # A caller may keep the graph database outside the checkout (shared stores
    # and evaluator fixtures do this routinely), so never let the Erlang
    # resolver infer its scope from the database parent.
    run_post_processing(store, repo_root=Path(repo_root))

    # 7. Drop embedding vectors that now reference a deleted node.
    purged = _purge_orphan_embeddings(store)

    summary = {
        "forgotten": sorted(forgotten),
        "reparsed": reparsed,
        "embeddings_purged": purged,
    }
    if erlang_result is not None:
        summary["erlang_integration"] = erlang_result
    return summary
