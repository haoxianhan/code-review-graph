"""Focused persistence contracts for optional Erlang semantic evidence."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from code_review_graph.erlang_semantic import (
    STATUS_UNAVAILABLE,
    AnalysisKey,
    Diagnostic,
    EvidenceRecord,
    Provenance,
    ToolchainIdentity,
)
from code_review_graph.graph import GraphStore
from code_review_graph.migrations import MIGRATIONS, get_schema_version, run_migrations


def _toolchain(tmp_path: Path, *, source_revision: str = "source-1") -> ToolchainIdentity:
    return ToolchainIdentity(
        repository=tmp_path.as_posix(),
        source_revision=source_revision,
        generated_data_revision="generated-1",
        configuration_digest="config-1",
        otp_version="27",
        elp_executable="/opt/elp",
        elp_version="0.12.0",
    )


def _key(tmp_path: Path, *, source_revision: str = "source-1", query_kind: str = "callers_of"):
    return AnalysisKey.from_toolchain(
        _toolchain(tmp_path, source_revision=source_revision),
        "elp",
        query_kind,
        "worker.run/1",
    )


def _evidence(key: AnalysisKey, *, target: str = "worker.run/1") -> EvidenceRecord:
    return EvidenceRecord(
        kind="CALLS",
        source="caller.run/0",
        target=target,
        file_path="src/caller.erl",
        line=9,
        provenance=Provenance.from_key(key),
        metadata={"confidence": "explicit"},
    )


def _diagnostic(key: AnalysisKey, *, message: str = "warning") -> Diagnostic:
    return Diagnostic(
        code="elp_note",
        message=message,
        severity="info",
        file_path="src/caller.erl",
        line=9,
        provenance=Provenance.from_key(key),
    )


@pytest.fixture
def store(tmp_path: Path):
    graph_store = GraphStore(tmp_path / "graph.db")
    try:
        yield graph_store
    finally:
        graph_store.close()


def test_typed_snapshot_round_trip_preserves_provenance(store: GraphStore, tmp_path: Path):
    key = _key(tmp_path)
    evidence = _evidence(key)
    diagnostic = _diagnostic(key)

    counts = store.store_semantic_snapshot(
        {"status": "ok", "evidence": [evidence], "diagnostics": [diagnostic]},
        analysis_key=key,
    )

    snapshot = store.get_semantic_snapshot(analysis_key=key)
    assert counts == {
        "runs": 1,
        "evidence": 1,
        "diagnostics": 1,
        "stale_removed": 0,
        "mismatched": 0,
    }
    assert snapshot["runs"][0]["status"] == "ok"
    assert snapshot["evidence"][0].evidence_id == evidence.evidence_id
    assert snapshot["evidence"][0].provenance.analysis_key == key.cache_key
    assert snapshot["diagnostics"][0].diagnostic_id == diagnostic.diagnostic_id
    assert snapshot["diagnostics"][0].provenance.source_revision == "source-1"


def test_same_evidence_id_can_exist_under_multiple_revisions(
    store: GraphStore, tmp_path: Path
):
    first_key = _key(tmp_path, source_revision="source-1")
    second_key = _key(tmp_path, source_revision="source-2")
    first = _evidence(first_key)
    second = _evidence(second_key)
    assert first.evidence_id == second.evidence_id

    store.store_semantic_snapshot({"evidence": [first]}, purge_stale=False)
    store.store_semantic_snapshot({"evidence": [second]}, purge_stale=False)

    rows = store._conn.execute(
        "SELECT analysis_key, evidence_id FROM semantic_evidence "
        "ORDER BY source_revision"
    ).fetchall()
    assert [(row["analysis_key"], row["evidence_id"]) for row in rows] == [
        (first_key.cache_key, first.evidence_id),
        (second_key.cache_key, second.evidence_id),
    ]


def test_replace_removes_only_records_for_the_same_analysis_key(
    store: GraphStore, tmp_path: Path
):
    key = _key(tmp_path)
    other_key = _key(tmp_path, query_kind="references")
    old = _evidence(key, target="old/0")
    replacement = _evidence(key, target="new/0")
    other = _evidence(other_key, target="other/0")

    store.store_semantic_snapshot({"evidence": [old]}, purge_stale=False)
    store.store_semantic_snapshot({"evidence": [other]}, purge_stale=False)
    store.store_semantic_snapshot({"evidence": [replacement]}, analysis_key=key)

    assert [item.target for item in store.get_semantic_evidence(analysis_key=key)] == [
        "new/0"
    ]
    assert [item.target for item in store.get_semantic_evidence(analysis_key=other_key)] == [
        "other/0"
    ]


def test_stale_purge_is_limited_to_repository_tool_and_query_scope(
    store: GraphStore, tmp_path: Path
):
    old_key = _key(tmp_path, source_revision="source-1")
    current_key = _key(tmp_path, source_revision="source-2")
    different_query = _key(tmp_path, source_revision="source-1", query_kind="references")
    different_repo = replace(current_key, repository="/other/repository")

    store.store_semantic_snapshot(
        {"evidence": [_evidence(old_key)], "diagnostics": [_diagnostic(old_key)]},
        purge_stale=False,
    )
    store.store_semantic_snapshot(
        {"evidence": [_evidence(different_query)]}, purge_stale=False
    )
    store.store_semantic_snapshot(
        {"evidence": [_evidence(different_repo)]}, purge_stale=False
    )

    removed = store.purge_stale_semantic_evidence(current_key)

    assert removed == 3  # old evidence, diagnostic, and run envelope
    assert store.get_semantic_evidence(analysis_key=old_key) == []
    assert store.get_semantic_diagnostics(analysis_key=old_key) == []
    assert store.get_semantic_evidence(analysis_key=different_query)
    assert store.get_semantic_evidence(analysis_key=different_repo)


def test_unavailable_snapshot_without_records_keeps_run_status(store: GraphStore, tmp_path: Path):
    key = _key(tmp_path)
    provenance = Provenance.from_key(key, status=STATUS_UNAVAILABLE)

    counts = store.store_semantic_snapshot(
        {"status": STATUS_UNAVAILABLE, "provenance": provenance.to_dict()},
        analysis_key=key,
    )
    snapshot = store.get_semantic_snapshot(analysis_key=key)

    assert counts["runs"] == 1
    assert counts["evidence"] == counts["diagnostics"] == 0
    assert snapshot["runs"] == [
        {
            "analysis_key": key.cache_key,
            "status": STATUS_UNAVAILABLE,
            "provenance": provenance.to_dict(),
            "evidence_count": 0,
            "diagnostic_count": 0,
            "updated_at": snapshot["runs"][0]["updated_at"],
        }
    ]


def test_malformed_json_and_limits_do_not_break_snapshot_reads(
    store: GraphStore, tmp_path: Path
):
    key = _key(tmp_path)
    store.store_semantic_snapshot(
        {"evidence": [_evidence(key)], "diagnostics": [_diagnostic(key)]}
    )
    store._conn.execute(
        "UPDATE semantic_runs SET provenance_json = ? WHERE analysis_key = ?",
        ("{malformed", key.cache_key),
    )
    store._conn.execute(
        "UPDATE semantic_evidence SET record_json = ? WHERE analysis_key = ?",
        ("[malformed", key.cache_key),
    )

    snapshot = store.get_semantic_snapshot(analysis_key=key, limit=0)

    assert snapshot["runs"][0]["provenance"] == {}
    assert snapshot["evidence"] == []
    assert len(snapshot["diagnostics"]) == 1
    assert store.get_semantic_evidence(analysis_key=key, limit=10**100) == []
    assert len(store.get_semantic_diagnostics(analysis_key=key, limit="invalid")) == 1


def test_oversized_metadata_is_bounded_before_storage(store: GraphStore, tmp_path: Path):
    key = _key(tmp_path)
    oversized = EvidenceRecord(
        kind="CALLS",
        source="caller.run/0",
        target="worker.run/1",
        provenance=Provenance.from_key(key),
        metadata={"payload": "x" * 500_000},
    )

    store.store_semantic_snapshot({"evidence": [oversized]})
    row = store._conn.execute(
        "SELECT record_json FROM semantic_evidence WHERE analysis_key = ?",
        (key.cache_key,),
    ).fetchone()

    assert row is not None
    assert len(row["record_json"]) <= 128_000
    assert len(store.get_semantic_evidence(analysis_key=key)[0].metadata["payload"]) <= 4_096


def test_explicit_key_does_not_accept_mismatched_record_provenance(
    store: GraphStore, tmp_path: Path
):
    expected_key = _key(tmp_path, source_revision="source-1")
    actual_key = _key(tmp_path, source_revision="source-2")

    counts = store.store_semantic_snapshot(
        {"evidence": [_evidence(actual_key)]},
        analysis_key=expected_key,
        purge_stale=False,
    )

    assert counts["mismatched"] == 1
    assert counts["runs"] == counts["evidence"] == 0
    assert store.get_semantic_snapshot(analysis_key=expected_key) == {
        "runs": [],
        "evidence": [],
        "diagnostics": [],
    }


def test_migration_rolls_back_python_exceptions(monkeypatch: pytest.MonkeyPatch):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO metadata(key, value) VALUES ('schema_version', '9')")
    conn.commit()

    def fail(_conn: sqlite3.Connection) -> None:
        _conn.execute("CREATE TABLE should_rollback (id INTEGER)")
        raise RuntimeError("injected migration failure")

    monkeypatch.setitem(MIGRATIONS, 10, fail)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        run_migrations(conn)

    assert get_schema_version(conn) == 9
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name = 'should_rollback'"
    ).fetchone() is None
    conn.close()
