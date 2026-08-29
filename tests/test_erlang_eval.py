"""Contracts for the checked-in Erlang evaluation artifacts."""

from __future__ import annotations

from code_review_graph.eval.erlang import (
    CASE_CATEGORIES,
    DEFAULT_CORPUS,
    DEFAULT_MANIFEST,
    execute_corpus,
    load_corpus,
    load_manifest,
)


def test_server_flexible_artifacts_load_and_cover_planned_categories():
    manifest = load_manifest(DEFAULT_MANIFEST)
    corpus = load_corpus(DEFAULT_CORPUS)

    assert manifest["target"]["name"] == "server_flexible"
    assert manifest["revision"]["requested"] == manifest["revision"]["observed"]
    assert manifest["toolchain"]["configuration"]["execute_during_discovery"] is False
    assert {case["category"] for case in corpus["cases"]} == CASE_CATEGORIES


def test_corpus_anchors_are_repository_relative():
    corpus = load_corpus(DEFAULT_CORPUS)

    for case in corpus["cases"]:
        target = case["query"]["target"]
        if isinstance(target, dict) and "file" in target:
            assert not target["file"].startswith("/")
            assert "\\" not in target["file"]


def test_corpus_execution_is_observable_without_running_project_code(tmp_path):
    manifest = load_manifest(DEFAULT_MANIFEST)
    corpus = load_corpus(DEFAULT_CORPUS)

    result = execute_corpus(
        manifest, corpus, target_root=tmp_path / "missing-target", dry_run=True
    )

    assert result["status"] == "blocked"
    assert result["metrics"]["adoption_pass"] is False
    assert all(item["status"] == "blocked" for item in result["case_results"])
    assert all(item["status"] == "not_run" for item in result["lifecycle"].values())
