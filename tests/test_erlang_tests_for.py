"""Regression coverage for Erlang helper-chain test discovery."""

from __future__ import annotations

from pathlib import Path

from code_review_graph.graph import GraphStore
from code_review_graph.parser import CodeParser, EdgeInfo, NodeInfo


def _erlang_function(
    file_path: Path,
    module: str,
    name: str,
    arity: int = 0,
    *,
    is_test: bool = False,
) -> NodeInfo:
    """Build a parser-shaped Erlang function node with a stable MFA identity."""
    return NodeInfo(
        kind="Test" if is_test else "Function",
        name=name,
        identity_name=f"{name}/{arity}",
        file_path=file_path.as_posix(),
        parent_name=module,
        line_start=1,
        line_end=1,
        language="erlang",
        is_test=is_test,
        extra={"erlang_kind": "function", "arity": arity},
    )


def _qn(file_path: Path, module: str, name: str, arity: int = 0) -> str:
    return f"{file_path.as_posix()}::{module}.{name}/{arity}"


def test_erlang_tests_for_reaches_two_level_helper_chain(tmp_path: Path) -> None:
    """A test mirrored on the outer helper still covers the production MFA.

    The CALLS endpoints are deliberately canonical and every endpoint has a
    stored node.  Remote MFA spelling/resolution is a separate concern; this
    test isolates the reverse traversal contract that was previously missing.
    """
    production_file = tmp_path / "src" / "production.erl"
    helper_one_file = tmp_path / "src" / "helper_one.erl"
    helper_two_file = tmp_path / "src" / "helper_two.erl"
    unrelated_file = tmp_path / "src" / "unrelated.erl"
    suite_file = tmp_path / "test" / "production_SUITE.erl"
    for file_path in (
        production_file,
        helper_one_file,
        helper_two_file,
        unrelated_file,
        suite_file,
    ):
        file_path.parent.mkdir(parents=True, exist_ok=True)

    production = _erlang_function(production_file, "production", "run")
    helper_one = _erlang_function(helper_one_file, "helper_one", "entry")
    helper_two = _erlang_function(helper_two_file, "helper_two", "setup")
    unrelated = _erlang_function(unrelated_file, "unrelated", "entry")
    test_case = _erlang_function(
        suite_file, "production_SUITE", "case_run", 1, is_test=True,
    )
    unrelated_test = _erlang_function(
        suite_file, "production_SUITE", "case_unrelated", 1, is_test=True,
    )
    production_qn = _qn(production_file, "production", "run")
    helper_one_qn = _qn(helper_one_file, "helper_one", "entry")
    helper_two_qn = _qn(helper_two_file, "helper_two", "setup")
    unrelated_qn = _qn(unrelated_file, "unrelated", "entry")
    test_qn = _qn(suite_file, "production_SUITE", "case_run", 1)
    unrelated_test_qn = _qn(
        suite_file, "production_SUITE", "case_unrelated", 1,
    )

    with GraphStore(tmp_path / "graph.db") as store:
        for node in (
            production, helper_one, helper_two, unrelated,
            test_case, unrelated_test,
        ):
            store.upsert_node(node)

        # The test reaches production through two helper modules:
        # production <- helper_one <- helper_two <- test_case.
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=helper_one_qn,
            target=production_qn,
            file_path=helper_one_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "production:run/0",
                "erlang_resolution": "canonical",
                "arity": 0,
            },
        ))
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=helper_two_qn,
            target=helper_one_qn,
            file_path=helper_two_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "helper_one:entry/0",
                "erlang_resolution": "canonical",
                "arity": 0,
            },
        ))
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=test_qn,
            target=helper_two_qn,
            file_path=suite_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "helper_two:setup/0",
                "erlang_resolution": "canonical",
                "arity": 0,
            },
        ))
        # Parser TESTED_BY mirrors the test's CALLS target, so the direct
        # coverage edge belongs to helper_two rather than production.
        store.upsert_edge(EdgeInfo(
            kind="TESTED_BY",
            source=helper_two_qn,
            target=test_qn,
            file_path=suite_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "helper_two:setup/0",
                "erlang_resolution": "canonical",
                "arity": 0,
            },
        ))
        # A syntactically valid but unresolved remote MFA with no repository
        # node must not bridge into the canonical production node or leak its
        # unrelated test.
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=unrelated_qn,
            target="ghost:run/0",
            file_path=unrelated_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "ghost:run/0",
                "erlang_resolution": "syntactic",
                "arity": 0,
            },
        ))
        store.upsert_edge(EdgeInfo(
            kind="TESTED_BY",
            source="ghost:run/0",
            target=unrelated_test_qn,
            file_path=suite_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "ghost:run/0",
                "erlang_resolution": "syntactic",
                "arity": 0,
            },
        ))
        store.commit()

        results = store.get_transitive_tests(production_qn, max_depth=2)

    matches = [item for item in results if item["qualified_name"] == test_qn]
    assert len(matches) == 1
    assert matches[0]["indirect"] is True
    assert all(item["qualified_name"] != unrelated_test_qn for item in results)


def test_parser_remote_mfa_chain_is_canonicalized_before_tests_for(
    tmp_path: Path,
) -> None:
    """The parser-shaped remote chain resolves and reaches its Common Test."""
    files = {
        "src/production.erl": (
            "-module(production).\n"
            "-export([run/0]).\n"
            "run() -> ok.\n"
        ),
        "src/helper_one.erl": (
            "-module(helper_one).\n"
            "-export([entry/0]).\n"
            "entry() -> production:run().\n"
        ),
        "src/helper_two.erl": (
            "-module(helper_two).\n"
            "-export([setup/0]).\n"
            "setup() -> helper_one:entry().\n"
        ),
        "test/production_SUITE.erl": (
            "-module(production_SUITE).\n"
            "-export([all/0, case_run/1]).\n"
            "all() -> [case_run].\n"
            "case_run(_Config) -> helper_two:setup().\n"
        ),
    }
    parser = CodeParser(tmp_path)
    parsed_nodes: list[NodeInfo] = []
    parsed_edges: list[EdgeInfo] = []
    for relative, source in files.items():
        file_path = tmp_path / relative
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(source, encoding="utf-8")
        nodes, edges = parser.parse_file(file_path)
        parsed_nodes.extend(nodes)
        parsed_edges.extend(edges)

    production_file = tmp_path / "src" / "production.erl"
    helper_one_file = tmp_path / "src" / "helper_one.erl"
    helper_two_file = tmp_path / "src" / "helper_two.erl"
    suite_file = tmp_path / "test" / "production_SUITE.erl"
    production_qn = _qn(production_file, "production", "run")
    helper_one_qn = _qn(helper_one_file, "helper_one", "entry")
    helper_two_qn = _qn(helper_two_file, "helper_two", "setup")
    test_qn = _qn(suite_file, "production_SUITE", "case_run", 1)

    with GraphStore(tmp_path / "graph.db") as store:
        for node in parsed_nodes:
            store.upsert_node(node)
        for edge in parsed_edges:
            store.upsert_edge(edge)
        store.commit()

        # Prove the fixture exercises the unresolved parser path before the
        # post-build resolver runs.
        raw_calls = {
            edge.target_qualified
            for edge in store.get_edges_by_source(helper_one_qn)
            if edge.kind == "CALLS"
        }
        assert raw_calls == {"production:run/0"}

        resolved = store.resolve_bare_call_targets()
        assert resolved == 3

        calls = {
            edge.source_qualified: edge.target_qualified
            for edge in store.get_all_edges()
            if edge.kind == "CALLS"
        }
        assert calls[helper_one_qn] == production_qn
        assert calls[helper_two_qn] == helper_one_qn
        assert calls[test_qn] == helper_two_qn

        mirrors = [
            edge
            for edge in store.get_all_edges()
            if edge.kind == "TESTED_BY" and edge.target_qualified == test_qn
        ]
        assert [edge.source_qualified for edge in mirrors] == [helper_two_qn]

        results = store.get_transitive_tests(production_qn, max_depth=2)

    assert [item["qualified_name"] for item in results] == [test_qn]
    assert results[0]["indirect"] is True
