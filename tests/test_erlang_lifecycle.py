"""Lifecycle coverage for the built-in Generic Erlang parser."""

from __future__ import annotations

from pathlib import Path

from code_review_graph.eval.erlang_adoption import graph_fingerprint
from code_review_graph.forget import forget_files
from code_review_graph.graph import GraphStore
from code_review_graph.incremental import (
    ERLANG_IDENTITY_VERSION,
    _erlang_identity_key,
    collect_all_files,
    full_build,
    incremental_update,
)
from code_review_graph.postprocessing import run_post_processing
from code_review_graph.tools.build import build_or_update_graph, run_postprocess


def _git(repo: Path, *args: str) -> str:
    import subprocess

    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _write_fixture(repo: Path) -> None:
    (repo / "include").mkdir()
    (repo / "src").mkdir()
    (repo / "include" / "sample.hrl").write_text(
        "-record(sample, {value :: integer()}).\n", encoding="utf-8"
    )
    (repo / "src" / "sample.erl").write_text(
        "-module(sample).\n"
        "-include(\"sample.hrl\").\n"
        "-export([run/0]).\n"
        "run() -> #sample{value = 1}.\n",
        encoding="utf-8",
    )
    (repo / "sample.app.src").write_text(
        "{application, sample, [{modules, [sample]}]}.\n",
        encoding="utf-8",
    )


def test_erlang_extensions_work_through_build_update_postprocess_and_forget(
    tmp_path: Path, monkeypatch
) -> None:
    """All normal graph lifecycle entry points retain Erlang files."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    db_path = repo / ".code-review-graph" / "graph.db"
    db_path.parent.mkdir()
    store = GraphStore(db_path)
    try:
        discovered = set(collect_all_files(repo))
        assert discovered == {"include/sample.hrl", "src/sample.erl", "sample.app.src"}

        built = full_build(repo, store)
        assert built["files_parsed"] == 3
        assert built["errors"] == []
        stored = {
            Path(path).relative_to(repo).as_posix()
            for path in store.get_all_files()
        }
        assert stored == discovered

        # Standalone postprocess must be safe on the same Generic-only graph.
        postprocessed = run_post_processing(store)
        assert "warnings" not in postprocessed
        store.close()
        standalone = run_postprocess(
            flows=False, communities=False, fts=True, repo_root=str(repo)
        )
        assert standalone["status"] == "ok"
        store = GraphStore(db_path)

        source = repo / "src" / "sample.erl"
        source.write_text(
            source.read_text(encoding="utf-8") + "\nhelper() -> ok.\n",
            encoding="utf-8",
        )
        updated = incremental_update(repo, store, changed_files=["src/sample.erl"])
        assert updated["files_updated"] == 1
        assert updated["errors"] == []
        assert store.get_nodes_by_file(str(source))

        header = repo / "include" / "sample.hrl"
        header.write_text(
            header.read_text(encoding="utf-8") + "-type value() :: integer().\n",
            encoding="utf-8",
        )
        header_update = incremental_update(
            repo, store, changed_files=["include/sample.hrl"]
        )
        assert "src/sample.erl" in header_update["dependent_files"]
        assert header_update["files_updated"] == 2

        forgotten = str(repo / "include" / "sample.hrl")
        summary = forget_files(store, repo, [forgotten])
        assert summary["forgotten"] == [forgotten]
        assert str(source) in summary["reparsed"]
        assert forgotten not in store.get_all_files()
        assert str(source) in store.get_all_files()
    finally:
        store.close()


def test_uppercase_erlang_header_change_reparses_include_dependents(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "include").mkdir()
    (repo / "src").mkdir()
    header = repo / "include" / "SAMPLE.HRL"
    source = repo / "src" / "sample.erl"
    header.write_text("-record(sample, {}).\n", encoding="utf-8")
    source.write_text(
        "-module(sample).\n-include(\"sample.hrl\").\nrun() -> #sample{}.\n",
        encoding="utf-8",
    )
    store = GraphStore(repo / "graph.db")
    try:
        full_build(repo, store)
        header.write_text(
            "-record(sample, {value :: integer()}).\n", encoding="utf-8"
        )
        result = incremental_update(
            repo, store, changed_files=["include/SAMPLE.HRL"]
        )
        assert "src/sample.erl" in result["dependent_files"]
        assert result["files_updated"] == 2
    finally:
        store.close()


def test_automatic_update_reconciles_dirty_edit_restore_and_noop(
    tmp_path: Path, monkeypatch
) -> None:
    """Restoring a previously indexed dirty Erlang file must not be a no-op."""
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    repo = tmp_path / "git-repo"
    repo.mkdir()
    (repo / "src").mkdir()
    source = repo / "src" / "worker.erl"
    original = "-module(worker).\n-export([run/0]).\nrun() -> ok.\n"
    source.write_text(original, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "initial Erlang source")

    initial = build_or_update_graph(
        full_rebuild=True, repo_root=str(repo), postprocess="none"
    )
    assert initial["errors"] == []
    db_path = repo / ".code-review-graph" / "graph.db"
    with GraphStore(db_path) as store:
        clean_fingerprint = graph_fingerprint(store, repo)
        identity_key = _erlang_identity_key(repo)
        assert store.get_metadata(identity_key) == ERLANG_IDENTITY_VERSION

    source.write_text(original + "helper() -> ok.\n", encoding="utf-8")
    dirty = build_or_update_graph(
        full_rebuild=False, repo_root=str(repo), base=None, postprocess="none"
    )
    assert dirty["files_updated"] == 1
    with GraphStore(db_path) as store:
        assert graph_fingerprint(store, repo) != clean_fingerprint
        assert store.get_metadata(identity_key) == ERLANG_IDENTITY_VERSION

    # Restore the exact committed bytes. Git now reports no diff, so the
    # hash reconciliation must be what schedules this file for re-parsing.
    source.write_text(original, encoding="utf-8")
    restored = build_or_update_graph(
        full_rebuild=False, repo_root=str(repo), base=None, postprocess="none"
    )
    assert restored["changed_files"] == ["src/worker.erl"]
    assert restored["files_updated"] == 1
    with GraphStore(db_path) as store:
        assert graph_fingerprint(store, repo) == clean_fingerprint
        assert store.get_metadata(identity_key) == ERLANG_IDENTITY_VERSION

    no_op = build_or_update_graph(
        full_rebuild=False, repo_root=str(repo), base=None, postprocess="none"
    )
    assert no_op["files_updated"] == 0
    assert no_op["changed_files"] == []
    with GraphStore(db_path) as store:
        assert graph_fingerprint(store, repo) == clean_fingerprint
        assert store.get_metadata(identity_key) == ERLANG_IDENTITY_VERSION

    # Compare against an independent clean rebuild, not only the initial
    # fingerprint, so the parity assertion covers the production path.
    clean_store = GraphStore(tmp_path / "clean-rebuild.db")
    try:
        rebuilt = full_build(repo, clean_store)
        assert rebuilt["errors"] == []
        assert graph_fingerprint(clean_store, repo) == clean_fingerprint
    finally:
        clean_store.close()
