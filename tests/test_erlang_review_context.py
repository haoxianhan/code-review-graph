"""Regression coverage for Erlang evidence in normal review workflows."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from code_review_graph.erlang_semantic import (
    AnalysisKey,
    Diagnostic,
    EvidenceRecord,
    Provenance,
    ToolchainIdentity,
)
from code_review_graph.graph import GraphStore
from code_review_graph.parser import CodeParser
from code_review_graph.tools.review import detect_changes_func, get_review_context


def _seed(root: Path) -> tuple[str, AnalysisKey]:
    source = root / "src" / "caller.erl"
    source.parent.mkdir(parents=True)
    source.write_text(
        "-module(caller).\n-run() -> worker:run().\n", encoding="utf-8"
    )
    nodes, edges = CodeParser().parse_file(source)
    db_path = root / ".code-review-graph" / "graph.db"
    db_path.parent.mkdir(parents=True)
    with GraphStore(db_path) as store:
        for node in nodes:
            store.upsert_node(node)
        for edge in edges:
            store.upsert_edge(edge)
        toolchain = ToolchainIdentity(
            repository=root.as_posix(),
            source_revision="revision-1",
            otp_version="27",
            elp_executable="/opt/elp",
            elp_version="0.12.0",
        )
        key = AnalysisKey.from_toolchain(
            toolchain, "elp", "callers_of", "worker:run/0"
        )
        provenance = Provenance.from_key(key)
        evidence = EvidenceRecord(
            kind="CALLS",
            source=f"{source.as_posix()}::caller.run/0",
            target="worker:run/0",
            file_path=source.as_posix(),
            line=2,
            provenance=provenance,
        )
        diagnostic = Diagnostic(
            code="elp_note", message="targeted warning", provenance=provenance
        )
        store.store_semantic_snapshot(
            {"evidence": [evidence], "diagnostics": [diagnostic]}, analysis_key=key
        )
    return source.as_posix(), key


def test_get_review_context_includes_scoped_erlang_evidence(tmp_path: Path):
    source, _key = _seed(tmp_path)

    result = get_review_context(
        changed_files=["src/caller.erl"],
        repo_root=str(tmp_path),
        include_source=False,
    )

    assert result["status"] == "ok"
    assert result["semantic_evidence"][0]["kind"] == "CALLS"
    assert result["semantic_diagnostics"][0]["code"] == "elp_note"
    assert result["semantic_evidence"][0]["file_path"] == source


def test_detect_changes_includes_scoped_erlang_evidence(tmp_path: Path):
    _seed(tmp_path)

    with patch(
        "code_review_graph.tools.review.parse_diff_ranges", return_value={}
    ):
        result = detect_changes_func(
            changed_files=["src/caller.erl"], repo_root=str(tmp_path)
        )

    assert result["status"] == "ok"
    assert result["semantic_evidence"][0]["kind"] == "CALLS"
    assert result["semantic_diagnostics"][0]["code"] == "elp_note"
