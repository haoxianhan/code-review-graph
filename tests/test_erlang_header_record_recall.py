"""Regression coverage for Erlang header and record review recall.

The Generic Erlang parser emits source spellings for preprocessor includes and
record references.  Review-facing queries must resolve those spellings only
when repository path evidence is sufficient, while keeping duplicate headers
in separate applications isolated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from code_review_graph.erlang_header_resolver import resolve_erlang_header_records
from code_review_graph.graph import GraphStore
from code_review_graph.incremental import full_build, get_db_path
from code_review_graph.parser import EdgeInfo, NodeInfo
from code_review_graph.tools.build import build_or_update_graph
from code_review_graph.tools.query import get_impact_radius, query_graph
from code_review_graph.tools.review import get_review_context


def _write(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _app(root: Path, name: str, *, record_value: str = "value") -> tuple[Path, Path]:
    """Create a small OTP application and return its header/source paths."""
    app_root = root / "apps" / name
    header = app_root / "include" / "shared.hrl"
    source = app_root / "src" / f"{name}.erl"
    _write(
        app_root / "src" / f"{name}.app.src",
        f"{{application, {name}, [{{modules, [{name}]}}]}}.\n",
    )
    _write(header, f"-record(shared, {{{record_value}}}).\n")
    _write(source, f"-module({name}).\nrun() -> ok.\n")
    return header, source


def _build(root: Path) -> None:
    (root / ".code-review-graph").mkdir(parents=True, exist_ok=True)
    result = build_or_update_graph(
        full_rebuild=True,
        repo_root=str(root),
        postprocess="minimal",
    )
    assert result["errors"] == []


def _edges_for_source(store: GraphStore, source: Path, kind: str) -> list:
    source_name = source.as_posix()
    return [
        edge
        for edge in store.get_all_edges()
        if edge.file_path == source_name
        and edge.kind == kind
        and edge.source_qualified == source_name
    ]


def test_unique_include_lib_resolves_header_record_queries_and_review_impact(
    tmp_path: Path,
) -> None:
    """A unique include_lib path reaches importers, record users, and impact."""
    root = tmp_path / "repo"
    provider_header, _provider_source = _app(root, "provider")
    consumer_header, consumer_source = _app(root, "consumer")
    # Keep a same-named header in the consumer application.  The explicit
    # include_lib spelling must still select the provider header.
    assert consumer_header.name == provider_header.name
    _write(
        consumer_source,
        "-module(consumer).\n"
        '-include_lib("provider/include/shared.hrl").\n'
        "-export([run/0]).\n"
        "run() -> #shared{value = ok}.\n",
    )

    _build(root)
    provider_header_name = provider_header.as_posix()
    consumer_source_name = consumer_source.as_posix()
    provider_record_name = f"{provider_header_name}::#shared{{}}"

    with GraphStore(get_db_path(root)) as store:
        includes = _edges_for_source(store, consumer_source, "IMPORTS_FROM")
        records = [
            edge
            for edge in store.get_all_edges()
            if edge.file_path == consumer_source_name
            and edge.kind == "REFERENCES"
            and edge.extra.get("erlang_reference_kind") == "record"
        ]
        assert len(includes) == 1
        assert includes[0].target_qualified == provider_header_name
        assert includes[0].extra.get("erlang_raw_target") == (
            "provider/include/shared.hrl"
        )
        assert len(records) == 1
        assert records[0].target_qualified == provider_record_name
        assert records[0].extra["erlang_raw_target"] == "shared"

    importers = query_graph(
        "importers_of",
        "apps/provider/include/shared.hrl",
        repo_root=str(root),
    )
    assert importers["status"] == "ok"
    assert {
        item["file"] for item in importers["results"]
    } == {consumer_source_name}

    consumers = query_graph(
        "references_to",
        provider_record_name,
        repo_root=str(root),
    )
    assert consumers["status"] == "ok"
    assert {
        item["qualified_name"] for item in consumers["results"]
    } == {f"{consumer_source_name}::consumer.run/0"}

    impact = get_impact_radius(
        ["apps/provider/include/shared.hrl"],
        repo_root=str(root),
        max_depth=3,
    )
    assert impact["status"] == "ok"
    assert consumer_source_name in impact["impacted_files"]
    assert any(
        node["qualified_name"] == f"{consumer_source_name}::consumer.run/0"
        for node in impact["impacted_nodes"]
    )

    review = get_review_context(
        changed_files=["apps/provider/include/shared.hrl"],
        repo_root=str(root),
        max_depth=3,
        include_source=False,
    )
    assert review["status"] == "ok"
    assert consumer_source_name in review["context"]["impacted_files"]


def test_include_lib_duplicate_application_name_stays_unresolved_when_one_header_is_missing(
    tmp_path: Path,
) -> None:
    """A missing file in a duplicate app must not erase app-name ambiguity."""
    root = tmp_path / "repo"
    provider_a, _source_a = _app(root, "provider")
    provider_b, _source_b = _app(root / "other", "provider")
    provider_b.unlink()
    consumer = root / "src" / "consumer.erl"
    _write(
        consumer,
        "-module(consumer).\n"
        '-include_lib("provider/include/shared.hrl").\n'
        "run() -> #shared{}.\n",
    )

    _build(root)

    with GraphStore(get_db_path(root)) as store:
        include = _edges_for_source(store, consumer, "IMPORTS_FROM")
        assert len(include) == 1
        assert include[0].target_qualified == "provider/include/shared.hrl"
        assert include[0].extra["ambiguous_target_count"] >= 2
        assert provider_a.as_posix() in include[0].extra["ambiguous_targets"]


def test_plain_include_keeps_duplicate_application_headers_isolated(
    tmp_path: Path,
) -> None:
    """A basename match must never make one application's record look shared."""
    root = tmp_path / "repo"
    header_a, source_a = _app(root, "app_a", record_value="from_a")
    header_b, source_b = _app(root, "app_b", record_value="from_b")
    _write(
        source_a,
        "-module(app_a).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{from_a = true}.\n",
    )
    _write(
        source_b,
        "-module(app_b).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{from_b = true}.\n",
    )

    _build(root)
    header_a_name = header_a.as_posix()
    header_b_name = header_b.as_posix()
    source_a_name = source_a.as_posix()
    source_b_name = source_b.as_posix()
    record_a_name = f"{header_a_name}::#shared{{}}"
    record_b_name = f"{header_b_name}::#shared{{}}"

    with GraphStore(get_db_path(root)) as store:
        include_targets = {
            source_a_name: _edges_for_source(store, source_a, "IMPORTS_FROM"),
            source_b_name: _edges_for_source(store, source_b, "IMPORTS_FROM"),
        }
        assert [edge.target_qualified for edge in include_targets[source_a_name]] == [
            header_a_name
        ]
        assert [edge.target_qualified for edge in include_targets[source_b_name]] == [
            header_b_name
        ]
        assert header_b_name not in {
            edge.target_qualified for edge in include_targets[source_a_name]
        }
        assert header_a_name not in {
            edge.target_qualified for edge in include_targets[source_b_name]
        }

        record_targets = {
            source_a_name: {
                edge.target_qualified
                for edge in store.get_all_edges()
                if edge.file_path == source_a_name
                and edge.kind == "REFERENCES"
                and edge.extra.get("erlang_reference_kind") == "record"
            },
            source_b_name: {
                edge.target_qualified
                for edge in store.get_all_edges()
                if edge.file_path == source_b_name
                and edge.kind == "REFERENCES"
                and edge.extra.get("erlang_reference_kind") == "record"
            },
        }
        assert record_targets == {
            source_a_name: {record_a_name},
            source_b_name: {record_b_name},
        }

    importers_a = query_graph(
        "importers_of", "apps/app_a/include/shared.hrl", repo_root=str(root)
    )
    importers_b = query_graph(
        "importers_of", "apps/app_b/include/shared.hrl", repo_root=str(root)
    )
    assert {item["file"] for item in importers_a["results"]} == {source_a_name}
    assert {item["file"] for item in importers_b["results"]} == {source_b_name}

    refs_a = query_graph("references_to", record_a_name, repo_root=str(root))
    refs_b = query_graph("references_to", record_b_name, repo_root=str(root))
    assert {
        item["file_path"] for item in refs_a["results"]
    } == {source_a_name}
    assert {
        item["file_path"] for item in refs_b["results"]
    } == {source_b_name}

    impact_a = get_impact_radius(
        ["apps/app_a/include/shared.hrl"], repo_root=str(root), max_depth=3
    )
    assert source_a_name in impact_a["impacted_files"]
    assert source_b_name not in impact_a["impacted_files"]


def test_plain_include_does_not_cross_into_a_sibling_application(
    tmp_path: Path,
) -> None:
    """An unresolved basename must not attach to a sibling app's header."""
    root = tmp_path / "repo"
    header_a, source_a = _app(root, "app_a")
    header_b, _source_b = _app(root, "app_b", record_value="from_b")
    # There is no app_a/include/shared.hrl.  A repository-wide basename scan
    # would incorrectly bind app_a's include and record use to app_b's header.
    header_a.unlink()
    _write(
        source_a,
        "-module(app_a).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )

    _build(root)
    source_a_name = source_a.as_posix()
    header_b_name = header_b.as_posix()
    record_b_name = f"{header_b_name}::#shared{{}}"

    with GraphStore(get_db_path(root)) as store:
        include = _edges_for_source(store, source_a, "IMPORTS_FROM")
        record = [
            edge
            for edge in store.get_all_edges()
            if edge.file_path == source_a_name
            and edge.kind == "REFERENCES"
            and edge.extra.get("erlang_reference_kind") == "record"
        ]
        assert len(include) == 1
        assert include[0].target_qualified == "shared.hrl"
        assert include[0].extra.get("erlang_raw_target") == "shared.hrl"
        assert len(record) == 1
        assert record[0].target_qualified == "shared"
        assert record[0].extra.get("erlang_raw_target") == "shared"

    importers_b = query_graph(
        "importers_of", "apps/app_b/include/shared.hrl", repo_root=str(root)
    )
    assert importers_b["status"] == "ok"
    assert importers_b["results"] == []

    refs_b = query_graph("references_to", record_b_name, repo_root=str(root))
    assert refs_b["status"] == "ok"
    assert refs_b["results"] == []

    impact_b = get_impact_radius(
        ["apps/app_b/include/shared.hrl"], repo_root=str(root), max_depth=3
    )
    assert source_a_name not in impact_b["impacted_files"]


def test_nested_rebar_include_scope_does_not_cross_into_sibling_application(
    tmp_path: Path,
) -> None:
    """A nested app's ``{i, ...}`` path remains scoped to that app."""
    root = tmp_path / "repo"
    header_a, source_a = _app(root, "app_a")
    header_b, _source_b = _app(root, "app_b", record_value="from_b")
    header_a.unlink()
    # The config is intentionally nested under app_b.  Its relative include
    # path is valid for app_b, but must not make app_b's header visible to
    # app_a's otherwise unresolved plain include.
    _write(
        root / "apps" / "app_b" / "rebar.config",
        "{erl_opts, [{i, \"include\"}]}.\n",
    )
    _write(
        source_a,
        "-module(app_a).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )

    _build(root)
    source_a_name = source_a.as_posix()
    header_b_name = header_b.as_posix()
    record_b_name = f"{header_b_name}::#shared{{}}"

    with GraphStore(get_db_path(root)) as store:
        include = _edges_for_source(store, source_a, "IMPORTS_FROM")
        record = [
            edge
            for edge in store.get_all_edges()
            if edge.file_path == source_a_name
            and edge.kind == "REFERENCES"
            and edge.extra.get("erlang_reference_kind") == "record"
        ]
        assert len(include) == 1
        assert include[0].target_qualified == "shared.hrl"
        assert len(record) == 1
        assert record[0].target_qualified == "shared"

    refs_b = query_graph("references_to", record_b_name, repo_root=str(root))
    assert refs_b["status"] == "ok"
    assert refs_b["results"] == []


def test_sibling_scoped_include_does_not_hide_root_include_fallback(
    tmp_path: Path,
) -> None:
    """An unrelated app config must not suppress a root-level header lookup."""
    root = tmp_path / "repo"
    header = root / "include" / "shared.hrl"
    source = root / "src" / "main.erl"
    _write(header, "-record(shared, {}).\n")
    _write(
        source,
        "-module(main).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )
    # This path resolves to the same physical root/include directory, but its
    # rebar scope belongs only to the sibling application.
    _write(
        root / "apps" / "sibling" / "rebar.config",
        "{erl_opts, [{i, \"../../include\"}]} .\n",
    )

    _build(root)

    with GraphStore(get_db_path(root)) as store:
        includes = _edges_for_source(store, source, "IMPORTS_FROM")
        records = [
            edge
            for edge in store.get_all_edges()
            if edge.file_path == source.as_posix()
            and edge.kind == "REFERENCES"
            and edge.extra.get("erlang_reference_kind") == "record"
        ]
        assert len(includes) == 1
        assert includes[0].target_qualified == header.as_posix()
        assert len(records) == 1
        assert records[0].target_qualified.endswith("::#shared{}")


def test_shared_graph_resolver_keeps_foreign_repository_edges_unchanged(
    tmp_path: Path, monkeypatch
) -> None:
    """Resolving one checkout must not rebind rows from another checkout."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    root_a = tmp_path / "repo_a"
    root_b = tmp_path / "repo_b"
    for root, module in ((root_a, "repo_a"), (root_b, "repo_b")):
        _write(root / "include" / "shared.hrl", "-record(shared, {}).\n")
        _write(
            root / "src" / f"{module}.erl",
            f'-module({module}).\n'
            '-include("shared.hrl").\n'
            "run() -> #shared{}.\n",
        )

    # A shared store is supported by incremental reconciliation.  Each build
    # must retain the other checkout's rows and keep their local endpoints.
    store = GraphStore(tmp_path / "shared.db")
    try:
        # Use the direct lifecycle entry point with the same open store so the
        # test exercises resolver scoping rather than separate databases.
        assert full_build(root_a, store)["errors"] == []
        assert full_build(root_b, store)["errors"] == []

        targets_before = {
            edge.file_path: edge.target_qualified
            for edge in store.get_all_edges()
            if edge.kind == "IMPORTS_FROM"
        }
        assert targets_before == {
            (root_a / "src" / "repo_a.erl").as_posix(): (
                root_a / "include" / "shared.hrl"
            ).as_posix(),
            (root_b / "src" / "repo_b.erl").as_posix(): (
                root_b / "include" / "shared.hrl"
            ).as_posix(),
        }

        resolve_erlang_header_records(store, root_a)
        targets_after = {
            edge.file_path: edge.target_qualified
            for edge in store.get_all_edges()
            if edge.kind == "IMPORTS_FROM"
        }
        assert targets_after == targets_before
    finally:
        store.close()


def test_shared_graph_resolver_without_root_fails_closed(
    tmp_path: Path,
) -> None:
    """An ambiguous inferred scope must not rewrite any checkout's edges."""
    roots = (tmp_path / "repo_a", tmp_path / "repo_b")
    for root, module in zip(roots, ("repo_a", "repo_b")):
        _write(root / "include" / "shared.hrl", "-record(shared, {}).\n")
        _write(
            root / "src" / f"{module}.erl",
            f"-module({module}).\n"
            '-include("shared.hrl").\n'
            "run() -> #shared{}.\n",
        )

    store = GraphStore(tmp_path / "shared.db")
    try:
        for root in roots:
            assert full_build(root, store)["errors"] == []

        before = {
            (edge.kind, edge.file_path, edge.source_qualified): (
                edge.target_qualified,
                edge.extra,
            )
            for edge in store.get_all_edges()
            if edge.kind in {"IMPORTS_FROM", "REFERENCES"}
        }
        result = resolve_erlang_header_records(store)
        after = {
            (edge.kind, edge.file_path, edge.source_qualified): (
                edge.target_qualified,
                edge.extra,
            )
            for edge in store.get_all_edges()
            if edge.kind in {"IMPORTS_FROM", "REFERENCES"}
        }

        assert result["files_indexed"] == 0
        assert before == after
    finally:
        store.close()


def test_shared_graph_resolver_does_not_trust_apps_parent_as_repo_root(
    tmp_path: Path,
) -> None:
    """A directory named ``apps`` is not repository identity by itself."""
    parent = tmp_path / "apps"
    roots = (parent / "checkout_a", parent / "checkout_b")
    for root, module in zip(roots, ("checkout_a", "checkout_b")):
        _write(root / "include" / "shared.hrl", "-record(shared, {}).\n")
        _write(
            root / "src" / f"{module}.erl",
            f"-module({module}).\n"
            '-include("shared.hrl").\n'
            "run() -> #shared{}.\n",
        )

    store = GraphStore(tmp_path / "shared.db")
    try:
        for root in roots:
            assert full_build(root, store)["errors"] == []
        before = {
            (edge.kind, edge.file_path, edge.source_qualified): edge.target_qualified
            for edge in store.get_all_edges()
            if edge.kind in {"IMPORTS_FROM", "REFERENCES"}
        }

        result = resolve_erlang_header_records(store)

        after = {
            (edge.kind, edge.file_path, edge.source_qualified): edge.target_qualified
            for edge in store.get_all_edges()
            if edge.kind in {"IMPORTS_FROM", "REFERENCES"}
        }
        assert result["files_indexed"] == 0
        assert before == after
    finally:
        store.close()


def test_header_resolver_skips_deep_malformed_edge_metadata(tmp_path: Path) -> None:
    """A deeply nested optional payload must not abort include resolution."""
    root = tmp_path / "repo"
    header = root / "include" / "shared.hrl"
    good_source = root / "src" / "good.erl"
    bad_source = root / "src" / "bad.erl"
    for path in (header, good_source, bad_source):
        path.parent.mkdir(parents=True, exist_ok=True)

    with GraphStore(tmp_path / "malformed-header.db") as store:
        for path in (header, good_source, bad_source):
            store.upsert_node(NodeInfo(
                kind="File",
                name=path.as_posix(),
                file_path=path.as_posix(),
                line_start=1,
                line_end=1,
                language="erlang",
            ))
        good_id = store.upsert_edge(EdgeInfo(
            kind="IMPORTS_FROM",
            source=good_source.as_posix(),
            target="shared.hrl",
            file_path=good_source.as_posix(),
            line=1,
            extra={"erlang_import_kind": "pp_include"},
        ))
        bad_id = store.upsert_edge(EdgeInfo(
            kind="IMPORTS_FROM",
            source=bad_source.as_posix(),
            target="shared.hrl",
            file_path=bad_source.as_posix(),
            line=1,
            extra={"erlang_import_kind": "pp_include"},
        ))
        # This depth reliably crosses CPython's JSON decoder recursion guard,
        # while remaining a small (~20 KiB) legacy metadata fixture.
        deep_extra = "[" * 10_000 + "0" + "]" * 10_000
        store._conn.execute(
            "UPDATE edges SET extra = ? WHERE id = ?",
            (deep_extra, bad_id),
        )
        store.commit()

        result = resolve_erlang_header_records(store, root)
        assert result["imports_resolved"] == 1
        good = store._conn.execute(
            "SELECT target_qualified FROM edges WHERE id = ?", (good_id,)
        ).fetchone()
        bad = store._conn.execute(
            "SELECT target_qualified FROM edges WHERE id = ?", (bad_id,)
        ).fetchone()
        assert good["target_qualified"] == header.as_posix()
        assert bad["target_qualified"] == "shared.hrl"


def test_header_resolver_infers_checkout_for_external_graph_database(
    tmp_path: Path,
) -> None:
    """A resolver call without ``repo_root`` still handles an external DB."""
    root = tmp_path / "repo"
    header = root / "include" / "shared.hrl"
    source = root / "src" / "worker.erl"
    _write(header, "-record(shared, {}).\n")
    _write(
        source,
        "-module(worker).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )

    # This layout mirrors ``CRG_DATA_DIR``/registry-backed storage: the graph
    # database is a sibling of the checkout, not below its ``.code-review-graph``
    # directory.  The raw endpoint mutation models a pre-resolver graph.
    db_path = tmp_path / "graph-cache" / "graph.db"
    with GraphStore(db_path) as store:
        assert full_build(root, store)["errors"] == []
        store._conn.execute(
            "UPDATE edges SET target_qualified = 'shared.hrl' "
            "WHERE kind = 'IMPORTS_FROM'"
        )
        store._conn.execute(
            "UPDATE edges SET target_qualified = 'shared' "
            "WHERE kind = 'REFERENCES' AND extra LIKE '%record%'"
        )
        store.commit()

        result = resolve_erlang_header_records(store)

        assert result["files_indexed"] == 2
        assert result["imports_resolved"] == 1
        assert result["records_resolved"] == 1
        assert store._conn.execute(
            "SELECT target_qualified FROM edges WHERE kind = 'IMPORTS_FROM'"
        ).fetchone()["target_qualified"] == header.as_posix()


@pytest.mark.parametrize(
    "config_text",
    (
        "include_dirs: headers\n",
        "include_dirs: [headers]\n",
        "include_dirs:\n  - headers\n",
    ),
)
def test_erlang_ls_unquoted_include_dirs_are_honored(
    tmp_path: Path,
    config_text: str,
) -> None:
    """The lightweight YAML reader accepts common unquoted forms."""
    root = tmp_path / "repo"
    header = root / "headers" / "shared.hrl"
    source = root / "src" / "worker.erl"
    _write(header, "-record(shared, {}).\n")
    _write(
        source,
        "-module(worker).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )
    _write(root / "erlang_ls.config", config_text)

    _build(root)

    with GraphStore(get_db_path(root)) as store:
        include = _edges_for_source(store, source, "IMPORTS_FROM")
        assert len(include) == 1
        assert include[0].target_qualified == header.as_posix()


def test_rebar_comment_does_not_enable_an_include_root(tmp_path: Path) -> None:
    """A commented ``{i, ...}`` term must remain inactive."""
    root = tmp_path / "repo"
    header = root / "commented" / "shared.hrl"
    source = root / "src" / "worker.erl"
    _write(header, "-record(shared, {}).\n")
    _write(
        source,
        "-module(worker).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )
    _write(
        root / "rebar.config",
        '% {erl_opts, [{i, "commented"}]}.\n',
    )

    _build(root)

    with GraphStore(get_db_path(root)) as store:
        include = _edges_for_source(store, source, "IMPORTS_FROM")
        assert len(include) == 1
        assert include[0].target_qualified == "shared.hrl"


def test_header_resolution_preserves_case_sensitive_erlang_spelling(
    tmp_path: Path,
) -> None:
    """A case-only mismatch must not become a resolved include on Linux."""
    root = tmp_path / "repo"
    header = root / "include" / "SHARED.HRL"
    source = root / "src" / "worker.erl"
    _write(header, "-record(shared, {}).\n")
    _write(
        source,
        "-module(worker).\n"
        '-include("shared.hrl").\n'
        "run() -> #shared{}.\n",
    )
    # On a case-insensitive checkout these names refer to one physical file,
    # so the distinction cannot be tested meaningfully.
    if (root / "include" / "shared.hrl").exists():
        pytest.skip("filesystem is case-insensitive")

    _build(root)

    with GraphStore(get_db_path(root)) as store:
        include = _edges_for_source(store, source, "IMPORTS_FROM")
        assert len(include) == 1
        assert include[0].target_qualified == "shared.hrl"
