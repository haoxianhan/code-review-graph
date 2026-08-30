"""Focused contracts for Erlang-aware graph query projections."""

from __future__ import annotations

from pathlib import Path

from code_review_graph.erlang_semantic import (
    AnalysisKey,
    Diagnostic,
    EvidenceRecord,
    Provenance,
    ToolchainIdentity,
)
from code_review_graph.graph import GraphEdge, GraphStore, edge_to_dict
from code_review_graph.parser import EdgeInfo, NodeInfo
from code_review_graph.tools.query import _erlang_mfa_parts, query_graph


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".code-review-graph").mkdir(parents=True)
    return root


def _seed_erlang(root: Path) -> tuple[str, str]:
    caller_file = (root / "src" / "caller.erl").as_posix()
    worker_file = (root / "src" / "worker.erl").as_posix()
    (root / "src").mkdir()
    with GraphStore(root / ".code-review-graph" / "graph.db") as store:
        store.upsert_node(NodeInfo(
            kind="Class", name="caller", file_path=caller_file,
            line_start=1, line_end=5, language="erlang",
            extra={"erlang_kind": "module"},
        ))
        store.upsert_node(NodeInfo(
            kind="Function", name="run", identity_name="run/0",
            file_path=caller_file, parent_name="caller",
            line_start=3, line_end=3, language="erlang",
            extra={"erlang_kind": "function", "arity": 0},
        ))
        store.upsert_node(NodeInfo(
            kind="Class", name="worker", file_path=worker_file,
            line_start=1, line_end=5, language="erlang",
            extra={"erlang_kind": "module"},
        ))
        store.upsert_node(NodeInfo(
            kind="Function", name="run", identity_name="run/0",
            file_path=worker_file, parent_name="worker",
            line_start=3, line_end=3, language="erlang",
            extra={"erlang_kind": "function", "arity": 0},
        ))
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=f"{caller_file}::caller.run/0",
            target="worker:run/0",
            file_path=caller_file,
            line=3,
            extra={"erlang_raw_target": "worker:run/0"},
        ))
        store.commit()
    return caller_file, worker_file


def _semantic_records(
    root: Path, caller_file: str,
) -> tuple[AnalysisKey, EvidenceRecord, Diagnostic]:
    toolchain = ToolchainIdentity(
        repository=root.as_posix(),
        source_revision="revision-1",
        otp_version="27",
        elp_executable="/opt/elp",
        elp_version="0.12.0",
    )
    key = AnalysisKey.from_toolchain(toolchain, "elp", "callers_of", "worker:run/0")
    provenance = Provenance.from_key(key)
    evidence = EvidenceRecord(
        kind="CALLS",
        source=f"{caller_file}::caller.run/0",
        target="worker:run/0",
        file_path="src/caller.erl",
        line=3,
        provenance=provenance,
    )
    diagnostic = Diagnostic(
        code="elp_note",
        message="targeted warning",
        provenance=provenance,
    )
    return key, evidence, diagnostic


def test_mfa_alias_resolves_without_generic_broad_fallback(tmp_path: Path):
    root = _repo(tmp_path)
    _caller_file, worker_file = _seed_erlang(root)

    result = query_graph("callers_of", "worker:run/0", repo_root=str(root))

    assert result["status"] == "ok"
    assert result["target"] == f"{worker_file}::worker.run/0"
    # The Generic baseline keeps an unresolved remote target. It must not be
    # mistaken for a resolved caller merely because the MFA alias matched.
    assert result["results"] == []


def test_quoted_mfa_alias_resolves_canonical_delimiters(tmp_path: Path):
    root = _repo(tmp_path)
    (root / "src").mkdir()
    worker_file = (root / "src" / "worker.erl").as_posix()
    with GraphStore(root / ".code-review-graph" / "graph.db") as store:
        store.upsert_node(NodeInfo(
            kind="Class", name="mod:ule", file_path=worker_file,
            line_start=1, line_end=3, language="erlang",
            extra={"erlang_kind": "module"},
        ))
        store.upsert_node(NodeInfo(
            kind="Function", name="fun/ction", identity_name="fun/ction/2",
            file_path=worker_file, parent_name="mod:ule",
            line_start=2, line_end=2, language="erlang",
            extra={"erlang_kind": "function", "arity": 2},
        ))
        store.commit()

    assert _erlang_mfa_parts(r"'mod\:ule':'fun\/ction'/2") == (
        "mod:ule", "fun/ction", 2,
    )
    result = query_graph(
        "callers_of", r"'mod\:ule':'fun\/ction'/2", repo_root=str(root),
    )
    assert result["status"] == "ok"
    assert result["target"] == f"{worker_file}::mod:ule.fun/ction/2"


def test_invalid_mfa_is_bounded_and_does_not_search_by_fragment(tmp_path: Path):
    root = _repo(tmp_path)
    _seed_erlang(root)
    huge_arity = "9" * 5_000

    result = query_graph("callers_of", f"worker:run/{huge_arity}", repo_root=str(root))

    assert result["status"] == "not_found"
    assert len(result["summary"]) < 400
    assert huge_arity not in result["summary"]


def test_query_max_results_is_bounded_before_sqlite(tmp_path: Path):
    root = _repo(tmp_path)
    _seed_erlang(root)

    result = query_graph(
        "callers_of", "worker:run/0", repo_root=str(root), max_results=10**5_000,
    )

    assert result["status"] == "ok"


def test_semantic_evidence_round_trip_is_visible_for_mfa_query(tmp_path: Path):
    root = _repo(tmp_path)
    caller_file, _worker_file = _seed_erlang(root)
    key, evidence, diagnostic = _semantic_records(root, caller_file)
    with GraphStore(root / ".code-review-graph" / "graph.db") as store:
        store.store_semantic_snapshot(
            {"evidence": [evidence], "diagnostics": [diagnostic]},
            analysis_key=key,
        )

    result = query_graph("callers_of", "worker:run/0", repo_root=str(root))

    assert result["semantic_evidence"][0]["evidence_id"] == evidence.evidence_id
    assert result["semantic_evidence"][0]["target"] == "worker:run/0"
    assert result["semantic_diagnostics"][0]["code"] == "elp_note"


def test_semantic_query_discards_evidence_from_stale_source_revision(tmp_path: Path):
    root = _repo(tmp_path)
    caller_file, _worker_file = _seed_erlang(root)
    old_key, old_evidence, old_diagnostic = _semantic_records(root, caller_file)
    current_toolchain = ToolchainIdentity(
        repository=root.as_posix(),
        source_revision="revision-2",
        otp_version="27",
        elp_executable="/opt/elp",
        elp_version="0.12.0",
    )
    current_key = AnalysisKey.from_toolchain(
        current_toolchain, "elp", "callers_of", "worker:run/0"
    )
    current_provenance = Provenance.from_key(current_key)
    current_evidence = EvidenceRecord(
        kind="CALLS",
        source=old_evidence.source,
        target=old_evidence.target,
        file_path=old_evidence.file_path,
        line=old_evidence.line,
        provenance=current_provenance,
    )
    current_diagnostic = Diagnostic(
        code="elp_current", message="current warning", provenance=current_provenance
    )
    with GraphStore(root / ".code-review-graph" / "graph.db") as store:
        store.set_metadata("git_head_sha", "revision-2")
        store.store_semantic_snapshot(
            {"evidence": [old_evidence], "diagnostics": [old_diagnostic]},
            analysis_key=old_key,
            purge_stale=False,
        )
        store.store_semantic_snapshot(
            {"evidence": [current_evidence], "diagnostics": [current_diagnostic]},
            analysis_key=current_key,
            purge_stale=False,
        )

    result = query_graph("callers_of", "worker:run/0", repo_root=str(root))

    assert [item["provenance"]["source_revision"] for item in result["semantic_evidence"]] == [
        "revision-2"
    ]
    assert [item["code"] for item in result["semantic_diagnostics"]] == ["elp_current"]


def test_unrelated_targetless_diagnostic_is_not_leaked_into_scoped_query(
    tmp_path: Path,
):
    root = _repo(tmp_path)
    caller_file, _worker_file = _seed_erlang(root)
    key, evidence, diagnostic = _semantic_records(root, caller_file)
    unrelated = Diagnostic(
        code="other_warning",
        message="unrelated",
        provenance=Provenance.from_key(
            AnalysisKey.from_toolchain(
                ToolchainIdentity(
                    repository=root.as_posix(),
                    source_revision="revision-1",
                    otp_version="27",
                    elp_executable="/opt/elp",
                    elp_version="0.12.0",
                ),
                "elp",
                "callers_of",
                "other:run/0",
            )
        ),
    )
    with GraphStore(root / ".code-review-graph" / "graph.db") as store:
        store.store_semantic_snapshot(
            {"evidence": [evidence], "diagnostics": [diagnostic]},
            analysis_key=key,
            purge_stale=False,
        )
        store.store_semantic_snapshot(
            {"diagnostics": [unrelated]}, purge_stale=False,
        )

    result = query_graph("callers_of", "worker:run/0", repo_root=str(root))

    assert [item["code"] for item in result["semantic_diagnostics"]] == ["elp_note"]


def test_malformed_semantic_row_does_not_break_generic_query(tmp_path: Path):
    root = _repo(tmp_path)
    caller_file, _worker_file = _seed_erlang(root)
    key, evidence, _diagnostic = _semantic_records(root, caller_file)
    with GraphStore(root / ".code-review-graph" / "graph.db") as store:
        store.store_semantic_snapshot({"evidence": [evidence]}, analysis_key=key)
        store._conn.execute(
            "UPDATE semantic_evidence SET record_json = ? WHERE analysis_key = ?",
            ("{malformed", key.cache_key),
        )

    result = query_graph("callers_of", "worker:run/0", repo_root=str(root))

    assert result["status"] == "ok"
    assert "semantic_evidence" not in result


def test_projected_edge_exposes_bounded_semantic_metadata_only_when_marked():
    ordinary = GraphEdge(
        id=1,
        kind="CALLS",
        source_qualified="caller",
        target_qualified="worker",
        file_path="caller.erl",
        line=3,
        extra={"semantic_evidence_id": "should-not-leak"},
    )
    assert "evidence_id" not in edge_to_dict(ordinary)

    projected = GraphEdge(
        id=2,
        kind="CALLS",
        source_qualified="caller",
        target_qualified="worker",
        file_path="caller.erl",
        line=3,
        extra={
            "_crg_erlang_semantic": True,
            "semantic_evidence_id": "evidence-1",
            "semantic_evidence_ids": ["evidence-1", "evidence-2"],
            "semantic_tool": "elp",
            "semantic_query_kind": "callers_of",
            "semantic_provenance": {"status": "ok", "nested": {"value": "x"}},
        },
    )
    result = edge_to_dict(projected)
    assert result["evidence_id"] == "evidence-1"
    assert result["evidence_ids"] == ["evidence-1", "evidence-2"]
    assert result["semantic_tool"] == "elp"
    assert result["semantic_query_kind"] == "callers_of"
