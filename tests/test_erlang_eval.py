"""Contracts for the checked-in Erlang evaluation artifacts."""

from __future__ import annotations

from code_review_graph.eval.erlang import (
    CASE_CATEGORIES,
    DEFAULT_CORPUS,
    DEFAULT_MANIFEST,
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
