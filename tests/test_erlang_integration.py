"""Focused contracts for the opt-in Erlang lifecycle integration."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from code_review_graph.erlang_integration import (
    ErlangIntegrationConfig,
    run_erlang_integration,
)
from code_review_graph.erlang_semantic import (
    CommandResult,
    ToolchainIdentity,
    compute_plt_identity,
)
from code_review_graph.graph import GraphStore
from code_review_graph.incremental import full_build


def _toolchain(repo: Path, *, revision: str = "rev-1", elp: str | None = "/opt/elp"):
    return ToolchainIdentity(
        repository=repo.resolve().as_posix(),
        source_revision=revision,
        generated_data_revision="generated-1",
        configuration_digest="config-1",
        otp_version="27",
        elp_executable=elp,
        elp_version="0.12.0" if elp else None,
        rebar3_executable="/opt/rebar3",
        rebar3_version="3.25.0",
        xref_command=("/opt/rebar3", "xref"),
        dialyzer_command=("/opt/rebar3", "dialyzer"),
    )


def _fixture(repo: Path) -> None:
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "caller.erl").write_text(
        "-module(caller).\n"
        "-export([run/0]).\n"
        "run() -> worker:run().\n",
        encoding="utf-8",
    )
    (repo / "src" / "worker.erl").write_text(
        "-module(worker).\n"
        "-export([run/0]).\n"
        "run() -> ok.\n",
        encoding="utf-8",
    )


def _store_and_build(repo: Path, monkeypatch) -> GraphStore:
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    store = GraphStore(repo / "graph.db")
    result = full_build(repo, store)
    assert result["errors"] == []
    return store


def _elp_runner(payload: object, calls: list[tuple[str, ...]]):
    encoded = json.dumps(payload)

    def run(command, *, cwd, env, timeout):
        calls.append(tuple(command))
        return CommandResult(0, encoded)

    return run


def _evidence_payload(
    *,
    kind: str = "CALLS",
    source: str = "src/caller.erl::caller.run/0",
    target: str = "worker:run/0",
) -> dict:
    return {
        "evidence": [
            {
                "kind": kind,
                "source": source,
                "target": target,
                "file": "src/caller.erl",
                "line": 3,
            }
        ]
    }


def test_disabled_integration_never_discovers_or_runs_tools(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = GraphStore(repo / "graph.db")
    calls: list[tuple[str, ...]] = []

    def should_not_run(*args, **kwargs):
        raise AssertionError("disabled integration invoked a subprocess")

    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(enabled=False),
            runner=should_not_run,
        )
        assert result.status == "disabled"
        assert result.counts["queries"] == 0
        assert calls == []
        assert store.get_metadata("erlang_integration_status") is None
    finally:
        store.close()


def test_unavailable_tool_keeps_generic_graph_and_persists_status(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    try:
        before = len(store.get_all_nodes(exclude_files=False))
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                queries={"callers_of": "worker:run/0"},
            ),
            toolchain=_toolchain(repo, elp=None),
        )
        assert result.status == "degraded"
        assert any(item.code == "elp_unavailable" for item in result.diagnostics)
        assert result.counts["projected_edges"] == 0
        assert len(store.get_all_nodes(exclude_files=False)) == before
        snapshot = store.get_semantic_snapshot(repository=repo.resolve().as_posix())
        assert snapshot["runs"][0]["status"] == "unavailable"
    finally:
        store.close()


def test_empty_generic_graph_skips_enabled_integration_without_running_tools(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = GraphStore(repo / "graph.db")
    calls: list[tuple[str, ...]] = []

    def should_not_run(command, **kwargs):
        calls.append(tuple(command))
        raise AssertionError("an empty Generic graph must not invoke ELP")

    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                queries={"callers_of": "worker:run/0"},
            ),
            toolchain=_toolchain(repo),
            runner=should_not_run,
        )
        assert result.status == "skipped"
        assert result.counts["queries"] == 0
        assert calls == []
    finally:
        store.close()


def test_changed_erlang_file_gets_default_targeted_enrichment_query(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    calls: list[tuple[str, ...]] = []
    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                cache_dir=tmp_path / "cache",
            ),
            changed_files=["src/caller.erl"],
            toolchain=_toolchain(repo),
            runner=_elp_runner({"evidence": []}, calls),
        )
        assert result.status == "ok"
        assert result.to_dict()["adapters"]["elp"]["status"] == "ok"
        assert result.counts["queries"] == 1
        assert calls == [
            (
                "/opt/elp",
                "query",
                "--format",
                "json",
                "enrichment",
                f"{repo.resolve().as_posix()}/src/caller.erl::caller.run/0",
            )
        ]
    finally:
        store.close()


def test_success_projects_unique_explicit_endpoint_and_is_idempotent(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    calls: list[tuple[str, ...]] = []
    config = ErlangIntegrationConfig(
        enabled=True,
        queries={"callers_of": "worker:run/0"},
        cache_dir=tmp_path / "cache",
    )
    try:
        first = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=_elp_runner(_evidence_payload(), calls),
        )
        assert first.status == "ok"
        assert first.counts["projected_edges"] == 1
        row = store._conn.execute(
            "SELECT target_qualified, confidence_tier, extra FROM edges "
            "WHERE kind = 'CALLS' AND extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()
        assert row is not None
        assert row["target_qualified"].endswith("src/worker.erl::worker.run/0")
        assert row["confidence_tier"] == "INFERRED"
        assert json.loads(row["extra"])["semantic_tool"] == "elp"

        second = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=_elp_runner(_evidence_payload(), calls),
        )
        assert second.counts["cache_hits"] == 1
        assert second.counts["projected_edges"] == 1
        marked = store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0]
        assert marked == 1
        assert len(calls) == 1
    finally:
        store.close()


def test_timeout_retains_previous_valid_evidence_and_projection(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    config = ErlangIntegrationConfig(
        enabled=True,
        queries={"callers_of": "worker:run/0"},
        cache_dir=tmp_path / "cache",
    )
    try:
        first = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=_elp_runner(_evidence_payload(), []),
        )
        assert first.counts["projected_edges"] == 1
        for path in (tmp_path / "cache").glob("*.json"):
            path.unlink()

        def timed_out(command, *, cwd, env, timeout):
            return CommandResult(124, stderr="timeout")

        second = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=timed_out,
        )
        assert second.status == "degraded"
        assert second.counts["projected_edges"] == 1
        assert any(item.code == "elp_timeout" for item in second.diagnostics)
        assert len(second.evidence) == 1
        row = store._conn.execute(
            "SELECT target_qualified FROM edges WHERE kind = 'CALLS' "
            "AND extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()
        assert row is not None
        assert row["target_qualified"].endswith("worker.erl::worker.run/0")
    finally:
        store.close()


def test_revision_change_purges_old_snapshot_and_keeps_module_xref_granularity(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    try:
        config = ErlangIntegrationConfig(
            enabled=True,
            queries={"callers_of": "worker:run/0"},
            include_xref=True,
            cache_dir=tmp_path / "cache",
        )

        def first_runner(command, *, cwd, env, timeout):
            if tuple(command) == ("/opt/rebar3", "xref"):
                return CommandResult(0, "caller -> worker\n")
            return CommandResult(0, json.dumps(_evidence_payload()))

        first = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo, revision="rev-1"),
            runner=first_runner,
        )
        assert first.status == "ok"
        assert any(item.kind == "DEPENDS_ON" for item in first.evidence)
        assert first.counts["projected_edges"] == 2
        module_edge = store._conn.execute(
            "SELECT source_qualified, target_qualified FROM edges "
            "WHERE kind = 'DEPENDS_ON' AND extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()
        assert module_edge is not None
        assert module_edge["source_qualified"].endswith("src/caller.erl::caller")
        assert module_edge["target_qualified"].endswith("src/worker.erl::worker")
        assert not any(
            item.kind == "CALLS" and item.provenance.tool == "xref"
            for item in first.evidence
        )

        # A new source revision must not retain rev-1 records.  Use a fresh
        # cache directory to force the adapter path instead of a cache hit.
        config2 = ErlangIntegrationConfig(
            enabled=True,
            queries={"callers_of": "worker:run/0"},
            cache_dir=tmp_path / "cache-rev-2",
        )
        second = run_erlang_integration(
            repo,
            store,
            config=config2,
            toolchain=_toolchain(repo, revision="rev-2"),
            runner=_elp_runner(_evidence_payload(), []),
        )
        assert second.status == "ok"
        rows = store._conn.execute(
            "SELECT DISTINCT source_revision FROM semantic_evidence"
        ).fetchall()
        assert [row["source_revision"] for row in rows] == ["rev-2"]
    finally:
        store.close()


def test_plt_change_removes_previous_dialyzer_diagnostics(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    plt = tmp_path / "dialyzer.plt"
    plt.write_bytes(b"plt-revision-1")
    first_identity = compute_plt_identity(plt)
    assert first_identity is not None
    config = ErlangIntegrationConfig(
        enabled=True,
        include_dialyzer=True,
        cache_dir=tmp_path / "cache-1",
        plt_path=plt,
    )
    try:
        first = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=ToolchainIdentity(
                **{
                    **_toolchain(repo).__dict__,
                    "plt_identity": first_identity,
                }
            ),
            runner=lambda command, **kwargs: CommandResult(
                0, "src/caller.erl:3: warning: first PLT result\n"
            ),
        )
        assert first.status == "ok"
        assert first.diagnostic_count == 1

        plt.write_bytes(b"plt-revision-2")
        second_identity = compute_plt_identity(plt)
        assert second_identity is not None
        second = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                include_dialyzer=True,
                cache_dir=tmp_path / "cache-2",
                plt_path=plt,
            ),
            toolchain=ToolchainIdentity(
                **{
                    **_toolchain(repo).__dict__,
                    "plt_identity": second_identity,
                }
            ),
            runner=lambda command, **kwargs: CommandResult(
                0, "src/caller.erl:3: warning: second PLT result\n"
            ),
        )
        assert second.status == "ok"
        messages = [
            row["message"]
            for row in store._conn.execute(
                "SELECT message FROM semantic_diagnostics ORDER BY message"
            ).fetchall()
        ]
        assert messages == ["second PLT result"]
    finally:
        store.close()


def test_malformed_adapter_output_is_fail_soft(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                queries={"impact": "worker:run/0"},
                cache_dir=tmp_path / "cache",
            ),
            toolchain=_toolchain(repo),
            runner=lambda command, **kwargs: CommandResult(0, "not-json"),
        )
        assert result.status == "degraded"
        assert any(item.code == "elp_malformed_output" for item in result.diagnostics)
        assert result.evidence == ()
        assert store.get_all_nodes(exclude_files=False)
    finally:
        store.close()


def test_disabling_integration_removes_projection_and_restores_generic_edge(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    config = ErlangIntegrationConfig(
        enabled=True,
        queries={"callers_of": "worker:run/0"},
        cache_dir=tmp_path / "cache",
    )
    try:
        run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=_elp_runner(_evidence_payload(), []),
        )
        marked = store._conn.execute(
            "SELECT target_qualified FROM edges "
            "WHERE kind = 'CALLS' AND extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()
        assert marked is not None

        disabled = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(enabled=False),
            # A disabled run must not inspect or execute the toolchain.
            runner=lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("disabled integration invoked a tool")
            ),
        )
        assert disabled.status == "disabled"
        assert disabled.counts["cleared_edges"] == 1
        assert store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0] == 0
        generic = store._conn.execute(
            "SELECT target_qualified, extra, confidence_tier FROM edges "
            "WHERE kind = 'CALLS'"
        ).fetchone()
        assert generic is not None
        assert generic["target_qualified"] == "worker:run/0"
        assert "_crg_erlang_semantic" not in generic["extra"]
        assert generic["confidence_tier"] == "EXTRACTED"
        assert store._conn.execute("SELECT COUNT(*) FROM semantic_evidence").fetchone()[0] == 0
        assert store.get_metadata("erlang_integration_status") == "disabled"
    finally:
        store.close()


def test_same_revision_targeted_queries_coexist_without_cross_target_purge(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    try:
        cases = (
            ("worker:run/0", "src/caller.erl::caller.run/0"),
            ("caller:run/0", "src/worker.erl::worker.run/0"),
        )
        for target, source in cases:
            result = run_erlang_integration(
                repo,
                store,
                config=ErlangIntegrationConfig(
                    enabled=True,
                    queries={"callers_of": target},
                    cache_dir=tmp_path / f"cache-{target.replace(':', '-')}",
                ),
                toolchain=_toolchain(repo),
                runner=_elp_runner(
                    _evidence_payload(source=source, target=target), []
                ),
            )
            assert result.status == "ok"
        rows = store._conn.execute(
            "SELECT target_qualified FROM edges "
            "WHERE kind = 'CALLS' AND extra LIKE '%_crg_erlang_semantic%' "
            "ORDER BY target_qualified"
        ).fetchall()
        assert len(rows) == 2
        evidence_rows = store._conn.execute(
            "SELECT COUNT(*) FROM semantic_evidence"
        ).fetchone()[0]
        assert evidence_rows == 2
    finally:
        store.close()


def test_toolchain_for_another_repository_is_rejected_before_running_tools(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    other = tmp_path / "other"
    repo.mkdir()
    other.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    calls: list[tuple[str, ...]] = []
    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                queries={"callers_of": "worker:run/0"},
            ),
            toolchain=_toolchain(other),
            runner=lambda command, **kwargs: calls.append(tuple(command)),
        )
        assert result.status == "mismatch"
        assert any(item.code == "erlang_repository_mismatch" for item in result.diagnostics)
        assert result.counts["repository_mismatches"] == 1
        assert calls == []
        assert store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0] == 0
        assert store._conn.execute("SELECT COUNT(*) FROM semantic_evidence").fetchone()[0] == 0
    finally:
        store.close()


def test_strict_profile_blocks_missing_required_tool_before_adapter_execution(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    calls: list[tuple[str, ...]] = []
    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                strict=True,
                queries={"callers_of": "worker:run/0"},
                include_xref=True,
                include_dialyzer=True,
            ),
            toolchain=ToolchainIdentity(
                **{
                    **_toolchain(repo).__dict__,
                    "elp_executable": None,
                    "elp_version": None,
                    "dialyzer_executable": "/opt/dialyzer",
                    "dialyzer_version": "5.3.1.1",
                }
            ),
            runner=_elp_runner({}, calls),
        )
        assert result.status == "blocked"
        assert any(item.code == "required_tool_unavailable" for item in result.diagnostics)
        assert calls == []
    finally:
        store.close()


def test_strict_profile_requires_matching_plt_and_adapter_set(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    plt = tmp_path / "dialyzer.plt"
    plt.write_bytes(b"strict-plt")
    plt_identity = compute_plt_identity(plt)
    assert plt_identity is not None
    toolchain = ToolchainIdentity(
        **{
            **_toolchain(repo).__dict__,
            "otp_executable": "/opt/erl",
            "otp_version": "27.3.4.16",
            "elp_version": "1.1.0+build-2026-01-15",
            "rebar3_version": "3.27.0",
            "dialyzer_executable": "/opt/dialyzer",
            "dialyzer_version": "5.3.1.1",
            "plt_identity": plt_identity,
        }
    )
    calls: list[tuple[str, ...]] = []

    def runner(command, *, cwd, env, timeout):
        calls.append(tuple(command))
        if tuple(command) == toolchain.xref_command:
            return CommandResult(0, "caller -> worker\n")
        if tuple(command) == toolchain.dialyzer_command:
            return CommandResult(0, "")
        return CommandResult(0, json.dumps(_evidence_payload()))

    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                strict=True,
                queries={"callers_of": "worker:run/0"},
                include_xref=True,
                include_dialyzer=True,
                plt_path=plt,
            ),
            toolchain=toolchain,
            runner=runner,
        )
        assert result.status == "ok"
        assert tuple(toolchain.xref_command) in calls
        assert tuple(toolchain.dialyzer_command) in calls
    finally:
        store.close()


def test_strict_project_profile_requires_authoritative_entrypoints(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    calls: list[tuple[str, ...]] = []
    toolchain = ToolchainIdentity(
        **{
            **_toolchain(repo).__dict__,
            "otp_executable": "/opt/erl",
            "otp_version": "27.3.4.16",
            "elp_version": "1.1.0+build-2026-01-15",
            "rebar3_version": "3.27.0",
            "dialyzer_executable": "/opt/dialyzer",
            "dialyzer_version": "5.3.1.1",
        }
    )
    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                strict=True,
                queries={"callers_of": "worker:run/0"},
                include_xref=True,
                include_dialyzer=True,
                project_compile_command=("./xserver.sh", "compile"),
                project_dialyzer_command=("./xserver.sh", "dialyzer"),
                require_project_entrypoints=True,
            ),
            toolchain=toolchain,
            runner=lambda command, **kwargs: calls.append(tuple(command)),
        )
        assert result.status == "blocked"
        assert any(
            item.code == "project_compile_entrypoint_mismatch"
            for item in result.diagnostics
        )
        assert any(
            item.code == "project_dialyzer_entrypoint_mismatch"
            for item in result.diagnostics
        )
        assert calls == []
    finally:
        store.close()


def test_strict_project_profile_runs_compile_before_semantic_adapters(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    (repo / "xserver.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    store = _store_and_build(repo, monkeypatch)
    calls: list[tuple[str, ...]] = []
    plt = tmp_path / "dialyzer.plt"
    plt.write_bytes(b"strict-plt")
    plt_identity = compute_plt_identity(plt)
    assert plt_identity is not None
    toolchain = ToolchainIdentity(
        **{
            **_toolchain(repo).__dict__,
            "otp_executable": "/opt/erl",
            "otp_version": "27.3.4.16",
            "elp_version": "1.1.0+build-2026-01-15",
            "rebar3_version": "3.27.0",
            "dialyzer_executable": "/opt/dialyzer",
            "dialyzer_version": "5.3.1.1",
            "plt_identity": plt_identity,
            "project_compile_command": ("./xserver.sh", "compile"),
            "project_dialyzer_command": ("./xserver.sh", "dialyzer"),
            "dialyzer_command": ("./xserver.sh", "dialyzer"),
        }
    )

    def runner(command, **kwargs):
        calls.append(tuple(command))
        if tuple(command) == toolchain.project_compile_command:
            return CommandResult(0, "compiled")
        if tuple(command) == toolchain.xref_command:
            return CommandResult(0, "caller -> worker\n")
        if tuple(command) == toolchain.project_dialyzer_command:
            return CommandResult(0, "")
        return CommandResult(0, json.dumps(_evidence_payload()))

    try:
        result = run_erlang_integration(
            repo,
            store,
            config=ErlangIntegrationConfig(
                enabled=True,
                strict=True,
                queries={"callers_of": "worker:run/0"},
                include_xref=True,
                include_dialyzer=True,
                plt_path=plt,
                project_compile_command=("./xserver.sh", "compile"),
                project_dialyzer_command=("./xserver.sh", "dialyzer"),
                require_project_entrypoints=True,
            ),
            toolchain=toolchain,
            runner=runner,
        )
        assert result.status == "ok"
        assert calls[0] == ("./xserver.sh", "compile")
    finally:
        store.close()


def test_snapshot_and_persistence_storage_errors_are_fail_soft(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _fixture(repo)
    store = _store_and_build(repo, monkeypatch)
    config = ErlangIntegrationConfig(
        enabled=True,
        queries={"callers_of": "worker:run/0"},
        cache_dir=tmp_path / "cache",
    )
    try:
        first = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=_elp_runner(_evidence_payload(), []),
        )
        assert first.status == "ok"
        before = store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0]
        assert before == 1

        original_snapshot = store.get_semantic_snapshot

        def broken_snapshot(*args, **kwargs):
            raise sqlite3.OperationalError("snapshot is locked")

        monkeypatch.setattr(store, "get_semantic_snapshot", broken_snapshot)
        calls: list[tuple[str, ...]] = []
        snapshot_failure = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=lambda command, **kwargs: calls.append(tuple(command)),
        )
        assert snapshot_failure.status == "degraded"
        assert any(
            item.code == "erlang_snapshot_read_failed"
            for item in snapshot_failure.diagnostics
        )
        assert calls == []
        assert store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0] == before

        monkeypatch.setattr(store, "get_semantic_snapshot", original_snapshot)

        def broken_persistence(*args, **kwargs):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(store, "store_semantic_snapshot", broken_persistence)
        persisted_failure = run_erlang_integration(
            repo,
            store,
            config=config,
            toolchain=_toolchain(repo),
            runner=_elp_runner(_evidence_payload(), []),
        )
        assert persisted_failure.status == "degraded"
        assert any(
            item.code == "erlang_snapshot_persistence_failed"
            for item in persisted_failure.diagnostics
        )
        # Projection remains best effort even if persistence is unavailable.
        assert persisted_failure.counts["projected_edges"] == 1
    finally:
        store.close()
