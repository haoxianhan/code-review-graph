"""Lifecycle contracts for optional Erlang work during ``forget``."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import code_review_graph.incremental as incremental_module
from code_review_graph.erlang_integration import (
    ErlangIntegrationConfig,
    _scoped_metadata_key,
    run_erlang_integration,
)
from code_review_graph.erlang_semantic import CommandResult, ToolchainIdentity
from code_review_graph.forget import forget_files
from code_review_graph.graph import GraphStore
from code_review_graph.incremental import collect_all_files, full_build
from code_review_graph.parser import CodeParser, EdgeInfo, NodeInfo


def _write_fixture(
    repo: Path, *, caller_module: str = "caller", worker_module: str = "worker"
) -> None:
    (repo / "src").mkdir()
    (repo / "src" / f"{caller_module}.erl").write_text(
        f"-module({caller_module}).\n"
        "-export([run/0]).\n"
        f"run() -> {worker_module}:run().\n",
        encoding="utf-8",
    )
    (repo / "src" / f"{worker_module}.erl").write_text(
        f"-module({worker_module}).\n"
        "-export([run/0]).\n"
        "run() -> ok.\n",
        encoding="utf-8",
    )


def _toolchain(repo: Path) -> ToolchainIdentity:
    return ToolchainIdentity(
        repository=repo.resolve().as_posix(),
        source_revision="rev-1",
        generated_data_revision="generated-1",
        configuration_digest="config-1",
        otp_version="27",
        elp_executable="/opt/elp",
        elp_version="0.12.0",
        rebar3_executable="/opt/rebar3",
        rebar3_version="3.25.0",
        xref_command=("/opt/rebar3", "xref"),
        dialyzer_command=("/opt/rebar3", "dialyzer"),
    )


def _evidence_runner_for(
    caller_module: str = "caller", worker_module: str = "worker"
):
    def runner(command: Any, **_kwargs: Any) -> CommandResult:
        return CommandResult(
            0,
            json.dumps(
                {
                    "evidence": [
                        {
                            "kind": "CALLS",
                            "source": f"src/{caller_module}.erl::{caller_module}.run/0",
                            "target": f"{worker_module}:run/0",
                            "file": f"src/{caller_module}.erl",
                            "line": 3,
                        }
                    ]
                }
            ),
        )

    return runner


def _evidence_runner(command: Any, **_kwargs: Any) -> CommandResult:
    """Default fixture runner kept as a named helper for focused tests."""
    return _evidence_runner_for()(command, **_kwargs)


def _populate_shared_store(repo: Path, store: GraphStore) -> None:
    """Parse one checkout into a shared store without cross-root stale purge."""
    parser = CodeParser(repo)
    for relative in collect_all_files(repo):
        path = repo / relative
        source = path.read_bytes()
        nodes, edges = parser.parse_bytes(path, source)
        store.store_file_nodes_edges(
            str(path), nodes, edges, hashlib.sha256(source).hexdigest()
        )


def test_forget_calls_erlang_owner_once_with_reparsed_scope(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    store = GraphStore(repo / "graph.db")
    calls: list[dict[str, Any]] = []
    config = {"enabled": False}

    def fake_lifecycle(repo_root, lifecycle_store, **kwargs):
        calls.append(
            {
                "repo_root": repo_root,
                "store": lifecycle_store,
                **kwargs,
            }
        )
        return {"status": "disabled", "counts": {"cleared_edges": 0}}

    try:
        full_build(repo, store)
        forgotten = str(repo / "src" / "worker.erl")
        monkeypatch.setattr(incremental_module, "_run_erlang_lifecycle", fake_lifecycle)
        summary = forget_files(
            store,
            repo,
            [forgotten],
            erlang_config=config,
        )

        assert len(calls) == 1
        call = calls[0]
        assert call["repo_root"] == repo.resolve()
        assert call["store"] is store
        assert call["config"] is config
        assert call["force"] is True
        assert forgotten in call["changed_files"]
        assert str(repo / "src" / "caller.erl") in call["changed_files"]
        assert str(repo / "src" / "caller.erl") in summary["reparsed"]
        edge = store._conn.execute(
            "SELECT target_qualified FROM edges WHERE kind = 'CALLS'"
        ).fetchone()
        assert edge is not None
        assert edge["target_qualified"] == "worker:run/0"
        assert summary["erlang_integration"] == {
            "status": "disabled",
            "counts": {"cleared_edges": 0},
        }
    finally:
        store.close()


def test_forget_explicitly_disables_and_clears_existing_erlang_projection(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    unrelated = repo / "notes.py"
    unrelated.write_text("value = 1\n", encoding="utf-8")
    store = GraphStore(repo / "graph.db")
    try:
        full_build(repo, store)
        enabled = ErlangIntegrationConfig(
            enabled=True,
            queries={"callers_of": "worker:run/0"},
            cache_dir=tmp_path / "cache",
        )
        projected = run_erlang_integration(
            repo,
            store,
            config=enabled,
            toolchain=_toolchain(repo),
            runner=_evidence_runner,
        )
        assert projected.counts["projected_edges"] == 1
        assert store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0] == 1

        summary = forget_files(
            store,
            repo,
            [str(unrelated)],
            erlang_config=ErlangIntegrationConfig(enabled=False),
        )

        assert summary["erlang_integration"]["status"] == "disabled"
        assert store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchone()[0] == 0
        assert store._conn.execute("SELECT COUNT(*) FROM semantic_evidence").fetchone()[0] == 0
        assert store._conn.execute("SELECT COUNT(*) FROM semantic_diagnostics").fetchone()[0] == 0
        assert store.get_metadata("erlang_integration_status") == "disabled"
    finally:
        store.close()


def test_disabling_one_repository_keeps_shared_store_state_for_another(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    _write_fixture(repo_a)
    _write_fixture(repo_b, caller_module="caller_b", worker_module="worker_b")
    notes_a = repo_a / "notes.py"
    notes_a.write_text("value = 1\n", encoding="utf-8")
    store = GraphStore(tmp_path / "shared.db")
    try:
        _populate_shared_store(repo_a, store)
        _populate_shared_store(repo_b, store)
        for repo, worker in ((repo_a, "worker"), (repo_b, "worker_b")):
            config = ErlangIntegrationConfig(
                enabled=True,
                queries={"callers_of": f"{worker}:run/0"},
                cache_dir=tmp_path / f"cache-{worker}",
            )
            result = run_erlang_integration(
                repo,
                store,
                config=config,
                toolchain=_toolchain(repo),
                runner=_evidence_runner_for(
                    caller_module="caller" if worker == "worker" else "caller_b",
                    worker_module=worker,
                ),
            )
            assert result.counts["projected_edges"] == 1

        marked = store._conn.execute(
            "SELECT file_path FROM edges "
            "WHERE extra LIKE '%_crg_erlang_semantic%' ORDER BY file_path"
        ).fetchall()
        assert [row["file_path"] for row in marked] == [
            str(repo_a / "src" / "caller.erl"),
            str(repo_b / "src" / "caller_b.erl"),
        ]

        disabled_summary = forget_files(
            store,
            repo_a,
            [str(notes_a)],
            erlang_config=ErlangIntegrationConfig(enabled=False),
        )
        assert disabled_summary["erlang_integration"]["status"] == "disabled"
        remaining = store._conn.execute(
            "SELECT file_path FROM edges "
            "WHERE extra LIKE '%_crg_erlang_semantic%'"
        ).fetchall()
        assert [row["file_path"] for row in remaining] == [
            str(repo_b / "src" / "caller_b.erl")
        ]
        repositories = store._conn.execute(
            "SELECT DISTINCT repository FROM semantic_evidence ORDER BY repository"
        ).fetchall()
        assert [row["repository"] for row in repositories] == [repo_b.resolve().as_posix()]
        assert store.get_metadata("erlang_integration_status") is None
        assert store.get_metadata(
            _scoped_metadata_key("erlang_integration_status", repo_a)
        ) == "disabled"
        assert store.get_metadata(
            _scoped_metadata_key("erlang_integration_status", repo_b)
        ) == "ok"
    finally:
        store.close()


def test_same_named_mfa_projection_is_scoped_to_requested_checkout(
    tmp_path: Path, monkeypatch
) -> None:
    """Bare MFA resolution must ignore same-named nodes in another root."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    _write_fixture(repo_a)
    _write_fixture(repo_b)
    store = GraphStore(tmp_path / "shared.db")
    config = ErlangIntegrationConfig(
        enabled=True,
        queries={"callers_of": "worker:run/0"},
        cache_dir=tmp_path / "cache",
    )
    try:
        _populate_shared_store(repo_a, store)
        _populate_shared_store(repo_b, store)

        first = run_erlang_integration(
            repo_a,
            store,
            config=config,
            toolchain=_toolchain(repo_a),
            runner=_evidence_runner,
        )
        second = run_erlang_integration(
            repo_b,
            store,
            config=config,
            toolchain=_toolchain(repo_b),
            runner=_evidence_runner,
        )

        assert first.counts["projected_edges"] == 1
        assert second.counts["projected_edges"] == 1
        rows = store._conn.execute(
            "SELECT file_path, target_qualified FROM edges "
            "WHERE extra LIKE '%_crg_erlang_semantic%' ORDER BY file_path"
        ).fetchall()
        assert [row["file_path"] for row in rows] == [
            str(repo_a / "src" / "caller.erl"),
            str(repo_b / "src" / "caller.erl"),
        ]
        assert rows[0]["target_qualified"].startswith(str(repo_a))
        assert rows[1]["target_qualified"].startswith(str(repo_b))
    finally:
        store.close()


def test_forget_does_not_reparse_same_named_mfa_in_other_repository(
    tmp_path: Path, monkeypatch
) -> None:
    """Bare MFA matching must remain scoped when a GraphStore is shared."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    _write_fixture(repo_a)
    _write_fixture(repo_b)
    store = GraphStore(tmp_path / "shared.db")
    calls: list[dict[str, Any]] = []

    def fake_lifecycle(repo_root, lifecycle_store, **kwargs):
        calls.append({"repo_root": repo_root, "store": lifecycle_store, **kwargs})
        return None

    monkeypatch.setattr(incremental_module, "_run_erlang_lifecycle", fake_lifecycle)
    try:
        _populate_shared_store(repo_a, store)
        _populate_shared_store(repo_b, store)
        forgotten = str(repo_a / "src" / "worker.erl")
        summary = forget_files(store, repo_a, [forgotten])

        assert summary["reparsed"] == [str(repo_a / "src" / "caller.erl")]
        assert calls and calls[0]["repo_root"] == repo_a.resolve()
        assert store.get_nodes_by_file(str(repo_b / "src" / "worker.erl"))
        assert store.get_nodes_by_file(str(repo_b / "src" / "caller.erl"))
    finally:
        store.close()


def test_forget_ignores_non_erlang_mfa_alias_collisions(
    tmp_path: Path, monkeypatch
) -> None:
    """A same-shaped node from another language cannot drive Erlang repair."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    foreign = repo / "foreign.py"
    foreign.write_text("value = 1\n", encoding="utf-8")
    store = GraphStore(repo / "graph.db")
    monkeypatch.setattr(incremental_module, "_run_erlang_lifecycle", lambda *a, **k: None)
    try:
        _populate_shared_store(repo, store)
        # Simulate a Python parser that happens to expose the same parent/name
        # and arity shape as an Erlang MFA. The language marker is the
        # discriminator that prevents a false cross-language referrer match.
        store.upsert_node(
            NodeInfo(
                kind="Function",
                name="run",
                identity_name="run/0",
                file_path=str(foreign),
                line_start=1,
                line_end=1,
                language="python",
                parent_name="worker",
                extra={"arity": 0},
            )
        )
        store.commit()

        summary = forget_files(store, repo, [str(foreign)])

        assert str(repo / "src" / "caller.erl") not in summary["reparsed"]
        assert store._conn.execute(
            "SELECT target_qualified FROM edges WHERE kind = 'CALLS' "
            "AND file_path = ?",
            (str(repo / "src" / "caller.erl"),),
        ).fetchone()["target_qualified"] == "worker:run/0"
    finally:
        store.close()


def test_forget_refuses_a_shared_store_from_another_repository(
    tmp_path: Path, monkeypatch
) -> None:
    """A total root mismatch must fail before deleting another checkout."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    _write_fixture(repo_a)
    _write_fixture(repo_b)
    store = GraphStore(tmp_path / "shared.db")
    try:
        _populate_shared_store(repo_a, store)
        before = store.get_all_files()
        target = str(repo_a / "src" / "worker.erl")

        with pytest.raises(RuntimeError, match="different repository root"):
            forget_files(store, repo_b, [target])

        assert store.get_all_files() == before
        assert store.get_nodes_by_file(target)
    finally:
        store.close()


def test_forget_refuses_a_foreign_target_in_a_mixed_store(
    tmp_path: Path, monkeypatch
) -> None:
    """A valid mixed store must still reject a target from another root."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    _write_fixture(repo_a)
    _write_fixture(repo_b)
    store = GraphStore(tmp_path / "shared.db")
    try:
        _populate_shared_store(repo_a, store)
        _populate_shared_store(repo_b, store)
        before = store.get_all_files()

        with pytest.raises(ValueError, match="outside repository root"):
            forget_files(store, repo_a, [str(repo_b / "src" / "worker.erl")])

        assert store.get_all_files() == before
        assert store.get_nodes_by_file(str(repo_b / "src" / "worker.erl"))
    finally:
        store.close()


def test_legacy_projection_cleanup_requires_all_paths_to_be_local(
    tmp_path: Path,
) -> None:
    """Malformed legacy projection rows are left untouched during cleanup."""
    from code_review_graph.erlang_integration import _clear_projection

    repo = tmp_path / "repo"
    repo.mkdir()
    store = GraphStore(tmp_path / "graph.db")
    try:
        source = str(repo / "src" / "caller.erl")
        store._conn.execute(
            "INSERT INTO edges "
            "(kind, source_qualified, target_qualified, file_path, line, extra, "
            "confidence, confidence_tier, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "CALLS",
                source + "::caller.run/0",
                "worker:run/0",
                source,
                1,
                json.dumps({"_crg_erlang_semantic": True}),
                0.9,
                "INFERRED",
                0.0,
            ),
        )
        row = store._conn.execute("SELECT id FROM edges").fetchone()
        assert row is not None
        store._conn.execute(
            "UPDATE edges SET source_qualified = ?, extra = ? WHERE id = ?",
            (
                str(tmp_path / "foreign" / "caller.erl") + "::caller.run/0",
                json.dumps({"_crg_erlang_semantic": True}),
                row["id"],
            ),
        )
        store.commit()

        assert _clear_projection(store, repo) == 0
        assert store._conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 1
    finally:
        store.close()


def test_projection_cleanup_rejects_conflicting_repository_markers(
    tmp_path: Path,
) -> None:
    """Conflicting explicit ownership markers must fail closed."""
    from code_review_graph.erlang_integration import _clear_projection

    repo = tmp_path / "repo"
    foreign = tmp_path / "foreign"
    repo.mkdir()
    foreign.mkdir()
    store = GraphStore(tmp_path / "graph.db")
    try:
        source = str(repo / "caller.erl")
        store._conn.execute(
            "INSERT INTO edges "
            "(kind, source_qualified, target_qualified, file_path, line, extra, "
            "confidence, confidence_tier, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "CALLS",
                source + "::caller.run/0",
                "worker:run/0",
                source,
                1,
                json.dumps(
                    {
                        "_crg_erlang_semantic": True,
                        "_crg_erlang_repository": str(repo),
                        "semantic_provenance": {"repository": str(foreign)},
                    }
                ),
                0.9,
                "INFERRED",
                0.0,
            ),
        )
        store.commit()

        assert _clear_projection(store, repo) == 0
        assert store._conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 1
    finally:
        store.close()


def test_forget_does_not_treat_erlang_ls_config_as_a_referrer(
    tmp_path: Path, monkeypatch
) -> None:
    """Toolchain layout manifests are never included in the reparse scope."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    config_path = repo / "erlang_ls.config"
    config_path.write_text("{config, []}.\n", encoding="utf-8")
    store = GraphStore(repo / "graph.db")
    monkeypatch.setattr(incremental_module, "_run_erlang_lifecycle", lambda *a, **k: None)
    try:
        _populate_shared_store(repo, store)
        worker_qname = store._conn.execute(
            "SELECT qualified_name FROM nodes WHERE file_path = ? "
            "AND kind = 'Function' AND name = 'run'",
            (str(repo / "src" / "worker.erl"),),
        ).fetchone()["qualified_name"]
        store.store_file_nodes_edges(
            str(config_path),
            [
                NodeInfo(
                    kind="File",
                    name=str(config_path),
                    file_path=str(config_path),
                    line_start=1,
                    line_end=1,
                    language="toml",
                )
            ],
            [
                EdgeInfo(
                    kind="REFERENCES",
                    source=str(config_path),
                    target=worker_qname,
                    file_path=str(config_path),
                )
            ],
        )

        summary = forget_files(store, repo, [str(repo / "src" / "worker.erl")])

        assert str(config_path) not in summary["reparsed"]
        assert summary["reparsed"] == [str(repo / "src" / "caller.erl")]
    finally:
        store.close()


def test_forget_reparses_erlang_import_and_module_alias_referrers(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    worker = repo / "src" / "worker.erl"
    consumer = repo / "src" / "consumer.erl"
    worker.write_text(
        "-module(worker).\n-export([run/0]).\nrun() -> ok.\n",
        encoding="utf-8",
    )
    consumer.write_text(
        "-module(consumer).\n"
        "-import(worker, [run/0]).\n"
        "-behaviour(worker).\n"
        "-export([call/0]).\n"
        "call() -> run().\n",
        encoding="utf-8",
    )
    store = GraphStore(repo / "graph.db")
    monkeypatch.setattr(incremental_module, "_run_erlang_lifecycle", lambda *a, **k: None)
    try:
        full_build(repo, store)
        summary = forget_files(store, repo, [str(worker)])
        assert summary["reparsed"] == [str(consumer)]
    finally:
        store.close()
