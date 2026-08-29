"""Focused regression coverage for the built-in Generic Erlang parser."""

from pathlib import Path

from code_review_graph.parser import CodeParser, normalize_erlang_atom, parse_erlang_mfa


def _parse(name: str, source: str):
    return CodeParser().parse_bytes(Path(name), source.encode())


def test_erlang_extensions_and_app_src_detection():
    parser = CodeParser()

    assert parser.detect_language(Path("sample.erl")) == "erlang"
    assert parser.detect_language(Path("sample.ERL")) == "erlang"
    assert parser.detect_language(Path("sample.hrl")) == "erlang"
    assert parser.detect_language(Path("sample.app.src")) == "erlang"
    assert parser.detect_language(Path("sample.src")) is None


def test_erlang_module_records_types_and_multiclause_functions():
    nodes, edges = _parse(
        "src/sample.erl",
        """\
-module(sample).
-record(state, {value :: integer()}).
-type alias() :: integer().
-opaque secret() :: atom().
value(0) -> 0;
value(N) -> helper(N).
helper(N) -> N.
""",
    )

    by_kind = {(node.kind, node.name): node for node in nodes}
    assert by_kind[("File", "src/sample.erl")].extra["erlang_module"] == "sample"
    assert by_kind[("Class", "sample")].extra["erlang_kind"] == "module"
    assert by_kind[("Type", "state")].parent_name == "sample"
    assert by_kind[("Type", "state")].identity_name == "#state{}"
    assert by_kind[("Type", "alias")].extra["erlang_kind"] == "type_alias"
    assert by_kind[("Type", "alias")].identity_name == "alias/0"
    assert by_kind[("Type", "secret")].extra["erlang_kind"] == "opaque"
    assert by_kind[("Type", "secret")].identity_name == "secret/0"

    function = by_kind[("Function", "value")]
    assert function.identity_name == "value/1"
    assert function.extra["clause_count"] == 2
    assert function.extra["arity"] == 1
    assert any(
        edge.kind == "CONTAINS"
        and edge.target == "src/sample.erl::sample.value/1"
        for edge in edges
    )


def test_erlang_quoted_atoms_are_normalized_in_symbol_names():
    nodes, _edges = _parse(
        "quoted.erl",
        """\
-module('quoted-mod').
-record('state-name', {}).
-type 'foo-bar'() :: atom().
'run-now'() -> ok.
""",
    )

    assert {node.name for node in nodes if node.kind == "Class"} == {"quoted-mod"}
    assert {node.name for node in nodes if node.kind == "Type"} == {
        "state-name", "foo-bar",
    }
    function = next(node for node in nodes if node.kind == "Function")
    assert function.name == "run-now"
    assert function.identity_name == "run-now/0"


def test_erlang_mfa_parser_handles_quoted_delimiters_and_escapes():
    assert normalize_erlang_atom(r"'mod\:ule'") == "mod:ule"
    assert normalize_erlang_atom(r"'fun\/ction'") == "fun/ction"
    assert normalize_erlang_atom(r"'line\x{3a}oct\072'") == "line:oct:"
    assert normalize_erlang_atom(r"'control\^?'") == "control\x7f"
    assert parse_erlang_mfa(
        r"'mod\:ule':'fun\/ction'/2", require_module=True,
    ) == ("mod:ule", "fun/ction", 2)
    assert parse_erlang_mfa("local/1", require_module=True) is None
    assert parse_erlang_mfa("Upper:run/0", require_module=True) is None


def test_erlang_mfa_parser_rejects_malformed_or_out_of_range_targets():
    assert parse_erlang_mfa("worker:run/256", require_module=True) is None
    assert parse_erlang_mfa("worker:run/not-an-arity", require_module=True) is None
    assert parse_erlang_mfa("worker module:run/0", require_module=True) is None
    assert parse_erlang_mfa("worker:run/" + ("0" * 4000), require_module=True) == (
        "worker", "run", 0,
    )
    assert normalize_erlang_atom("'" + r"\x{" + ("0" * 4096) + "}'") == "\x00"


def test_erlang_local_nested_and_remote_calls_preserve_arity():
    nodes, edges = _parse(
        "src/sample.erl",
        """\
-module(sample).
run(X) -> lists:map(fun(Y) -> helper(Y) end, X), remote:work(X).
helper(X) -> X.
""",
    )

    run = next(node for node in nodes if node.name == "run")
    calls = [edge for edge in edges if edge.kind == "CALLS" and edge.source.endswith("run/1")]
    assert {
        edge.target for edge in calls
    } == {
        "src/sample.erl::sample.helper/1",
        "lists:map/2",
        "remote:work/1",
    }
    assert run.extra["arity"] == 1
    assert all(edge.extra["arity"] in {1, 2} for edge in calls)
    assert any(edge.extra["erlang_resolution"] == "same_file" for edge in calls)


def test_erlang_deep_expression_walk_does_not_overflow():
    """Deep but legal Erlang expressions remain parseable without recursion."""
    depth = 1_500
    source = (
        b"-module(deep).\n"
        + b"run() -> "
        + b"(" * depth
        + b"helper()"
        + b")" * depth
        + b".\n"
        + b"helper() -> ok.\n"
    )

    nodes, edges = CodeParser().parse_bytes(Path("deep.erl"), source)

    assert {node.name for node in nodes if node.kind == "Function"} == {
        "run", "helper",
    }
    assert any(
        edge.kind == "CALLS"
        and edge.source.endswith("run/0")
        and edge.target.endswith("helper/0")
        for edge in edges
    )


def test_erlang_import_include_and_behaviour_edges():
    _nodes, edges = _parse(
        "src/sample.erl",
        """\
-module(sample).
-import(lists, [map/2]).
-include("sample.hrl").
-include_lib("kernel/include/file.hrl").
-behaviour(gen_server).
run() -> ok.
""",
    )

    assert {
        (edge.kind, edge.target, edge.extra["erlang_import_kind"])
        for edge in edges
        if edge.kind == "IMPORTS_FROM"
    } == {
        ("IMPORTS_FROM", "lists", "import"),
        ("IMPORTS_FROM", "sample.hrl", "pp_include"),
        ("IMPORTS_FROM", "kernel/include/file.hrl", "pp_include_lib"),
    }
    behaviour = next(edge for edge in edges if edge.kind == "IMPLEMENTS")
    assert behaviour.target == "gen_server"
    assert behaviour.extra["erlang_reference_kind"] == "behaviour"


def test_erlang_export_spec_callback_metadata_and_test_conventions():
    nodes, edges = _parse(
        "test/sample_test.ERL",
        """\
-module(sample_test).
-export([run/0]).
-spec run() -> ok.
-callback handle(term()) -> ok.
run_test() -> ok.
property_test_() -> [].
""",
    )

    file_node = next(node for node in nodes if node.kind == "File")
    assert file_node.is_test is True
    assert file_node.extra["erlang_exports"] == ["run/0"]
    assert file_node.extra["erlang_specs"] == ["run/0"]
    assert file_node.extra["erlang_callbacks"] == ["handle/1"]
    assert any(
        node.identity_name == "$callback.handle/1"
        and node.extra["erlang_kind"] == "callback"
        for node in nodes
    )
    assert {
        node.name for node in nodes if node.kind == "Test"
    } == {"property_test_", "run_test"}
    assert not [edge for edge in edges if edge.kind == "CALLS"]


def test_erlang_test_calls_create_tested_by_edges():
    _nodes, edges = _parse(
        "test/sample_test.erl",
        """\
-module(sample_test).
run_test() -> helper().
helper() -> ok.
""",
    )

    assert any(
        edge.kind == "TESTED_BY"
        and edge.source.endswith("helper/0")
        and edge.target.endswith("run_test/0")
        for edge in edges
    )


def test_erlang_app_src_metadata_is_kept_on_file_node():
    nodes, edges = _parse(
        "sample.app.src",
        '{application, sample, [{modules, [sample, sample_sup]}, '
        '{mod, {sample_sup, []}}]}.\n',
    )

    assert len(nodes) == 1
    file_node = nodes[0]
    assert file_node.extra == {
        "erlang_application": "sample",
        "erlang_application_modules": ["sample", "sample_sup"],
        "erlang_application_module": "sample_sup",
    }
    assert [(edge.kind, edge.target) for edge in edges] == [
        ("REFERENCES", "sample"),
    ]


def test_erlang_type_and_record_references_are_not_runtime_calls():
    nodes, edges = _parse(
        "src/sample.erl",
        """\
-module(sample).
-record(state, {value :: integer()}).
-type result() :: {ok, state()}.
-spec run() -> result().
run() -> #state{value = 1}.
""",
    )

    assert any(
        edge.kind == "REFERENCES"
        and edge.extra.get("erlang_reference_kind") == "record"
        and edge.target == "state"
        for edge in edges
    )
    assert any(
        edge.kind == "REFERENCES"
        and edge.extra.get("erlang_reference_kind") == "type"
        and edge.target == "result/0"
        for edge in edges
    )
    assert not any(
        edge.kind == "CALLS" and edge.target.startswith("integer/")
        for edge in edges
    )


def test_erlang_app_src_captures_dependencies():
    _nodes, edges = _parse(
        "apps/demo/src/demo.app.src",
        "{application, demo, [{applications, [kernel, stdlib]}, {modules, [demo]}]}.\n",
    )
    assert {
        edge.target for edge in edges
        if edge.kind == "DEPENDS_ON"
    } == {"kernel", "stdlib"}
