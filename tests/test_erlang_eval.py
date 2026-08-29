"""Contracts for the checked-in Erlang evaluation artifacts."""

from __future__ import annotations

import copy

import pytest

from code_review_graph.eval.erlang import (
    CASE_CATEGORIES,
    DEFAULT_CORPUS,
    DEFAULT_MANIFEST,
    discover_environment,
    execute_corpus,
    load_corpus,
    load_manifest,
    validate_artifact_pair,
)


def _path_validation_fixtures(tmp_path):
    manifest = copy.deepcopy(load_manifest(DEFAULT_MANIFEST, load_adapters=False))
    corpus = copy.deepcopy(load_corpus(DEFAULT_CORPUS))
    manifest["target"]["path"] = str(tmp_path / "target")
    return manifest, corpus


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


@pytest.mark.parametrize(
    ("artifact", "mutator"),
    [
        (
            "manifest",
            lambda manifest, corpus: manifest["dependencies"]["lockfiles"][0].update(
                path="../outside.lock"
            ),
        ),
        (
            "manifest",
            lambda manifest, corpus: manifest["generated_data"].update(
                paths=["../outside-generated"]
            ),
        ),
        (
            "manifest",
            lambda manifest, corpus: manifest["analysis"].update(
                cache_paths=["../outside-cache"]
            ),
        ),
        (
            "corpus",
            lambda manifest, corpus: corpus["cases"][0]["query"]["target"].update(
                file="../outside.erl"
            ),
        ),
    ],
)
def test_discover_environment_rejects_lexical_artifact_traversal(
    tmp_path, artifact, mutator
):
    manifest, corpus = _path_validation_fixtures(tmp_path)
    mutator(manifest, corpus)

    with pytest.raises(ValueError, match="must not escape"):
        discover_environment(manifest, corpus, target_root=tmp_path / "target")


@pytest.mark.parametrize(
    ("artifact", "mutator"),
    [
        (
            "manifest",
            lambda manifest, corpus: manifest["dependencies"]["lockfiles"][0].update(
                path="link/outside.lock"
            ),
        ),
        (
            "manifest",
            lambda manifest, corpus: manifest["generated_data"].update(
                paths=["link/outside-generated"]
            ),
        ),
        (
            "manifest",
            lambda manifest, corpus: manifest["analysis"].update(
                cache_paths=["link/outside-cache"]
            ),
        ),
        (
            "corpus",
            lambda manifest, corpus: corpus["cases"][0]["query"]["target"].update(
                file="link/outside.erl"
            ),
        ),
    ],
)
def test_discover_environment_rejects_symlink_artifact_traversal(
    tmp_path, artifact, mutator
):
    manifest, corpus = _path_validation_fixtures(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (target / "link").symlink_to(outside, target_is_directory=True)
    mutator(manifest, corpus)

    with pytest.raises(ValueError, match="escapes the target checkout"):
        discover_environment(manifest, corpus, target_root=target)


def test_execute_corpus_rejects_symlinked_anchor_before_read(tmp_path):
    manifest, corpus = _path_validation_fixtures(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "anchor.erl").write_text("outside", encoding="utf-8")
    (target / "link").symlink_to(outside, target_is_directory=True)
    corpus["cases"][0]["query"]["target"]["file"] = "link/anchor.erl"

    with pytest.raises(ValueError, match="escapes the target checkout"):
        execute_corpus(manifest, corpus, target_root=target, dry_run=True)


def test_manifest_and_corpus_artifacts_must_match(tmp_path):
    manifest, corpus = _path_validation_fixtures(tmp_path)
    manifest_path = tmp_path / "server_flexible.manifest.json"
    corpus_path = tmp_path / "corpus.json"
    corpus["manifest"] = "other.manifest.json"

    with pytest.raises(ValueError, match="does not reference the supplied manifest"):
        validate_artifact_pair(
            manifest,
            corpus,
            manifest_path=manifest_path,
            corpus_path=corpus_path,
        )
