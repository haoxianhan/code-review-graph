"""Repository-root identity regressions for graph reconciliation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, patch

import pytest

from code_review_graph import cli
from code_review_graph.graph import GraphStore
from code_review_graph.incremental import (
    ERLANG_IDENTITY_VERSION,
    _ensure_erlang_identity_current,
    _erlang_identity_key,
    _reconcile_stale_files,
    collect_all_files,
    full_build,
    incremental_update,
)
from code_review_graph.parser import CodeParser


def test_incremental_update_survives_mixed_repo_root_spellings(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "app.py").write_text("def main() -> None:\n    pass\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    store = GraphStore(repo / ".code-review-graph" / "graph.db")
    try:
        full_build(repo.resolve(), store)
        before = store.get_all_files()

        result = incremental_update(Path("."), store, changed_files=[])

        assert result["stale_files_removed"] == 0
        assert store.get_all_files() == before
    finally:
        store.close()


def test_incremental_update_refuses_total_root_mismatch_without_purging(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "app.py").write_text("def main() -> None:\n    pass\n", encoding="utf-8")
    wrong_root = tmp_path / "wrong-root"
    wrong_root.mkdir()
    store = GraphStore(repo / ".code-review-graph" / "graph.db")
    try:
        full_build(repo, store)
        before = store.get_all_files()

        with pytest.raises(RuntimeError, match="different repository root"):
            incremental_update(wrong_root, store, changed_files=[])

        assert store.get_all_files() == before
    finally:
        store.close()


def test_mixed_root_reconciliation_does_not_delete_foreign_checkout(
    tmp_path: Path,
) -> None:
    """Stale cleanup is scoped when a shared GraphStore has two roots."""
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    for repo, name in ((repo_a, "a.py"), (repo_b, "b.py")):
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / name).write_text("def live():\n    pass\n", encoding="utf-8")

    store = GraphStore(tmp_path / "shared.db")
    try:
        for repo in (repo_a, repo_b):
            parser = CodeParser(repo)
            for relative in collect_all_files(repo):
                path = repo / relative
                source = path.read_bytes()
                nodes, edges = parser.parse_bytes(path, source)
                store.store_file_nodes_edges(
                    str(path), nodes, edges, hashlib.sha256(source).hexdigest()
                )
        store.commit()

        stale = _reconcile_stale_files(repo_a, store, ["a.py"])

        assert stale == []
        assert store.get_nodes_by_file(str(repo_b / "b.py"))
    finally:
        store.close()


def test_erlang_identity_marker_is_scoped_and_legacy_scalar_cannot_skip_foreign_root(
    tmp_path: Path, monkeypatch
) -> None:
    """A shared GraphStore must not let one checkout bypass migration."""
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    for repo, name in ((repo_a, "a"), (repo_b, "b")):
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / f"{name}.erl").write_text(
            f"-module({name}).\n-export([run/0]).\nrun() -> ok.\n",
            encoding="utf-8",
        )

    store = GraphStore(tmp_path / "shared.db")
    try:
        monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
        full_build(repo_a, store)
        full_build(repo_b, store)

        assert store.get_metadata(_erlang_identity_key(repo_a)) == ERLANG_IDENTITY_VERSION
        assert store.get_metadata(_erlang_identity_key(repo_b)) == ERLANG_IDENTITY_VERSION
        # New writes do not rely on the ambiguous scalar marker in a mixed store.
        assert store.get_metadata("erlang_identity_version") is None

        # Simulate an old database that only has the scalar marker.  The
        # foreign File marker must force a rebuild for repo_b.
        store._conn.execute(
            "DELETE FROM metadata WHERE key LIKE 'erlang_identity_version:%'"
        )
        store.set_metadata("erlang_identity_version", ERLANG_IDENTITY_VERSION)
        calls: list[Path] = []

        def fake_rebuild(root, _store, _config):
            calls.append(root)
            return {"files_parsed": 1, "total_nodes": 1, "total_edges": 0, "errors": []}

        monkeypatch.setattr(
            "code_review_graph.incremental._invoke_full_build", fake_rebuild
        )
        rebuilt = _ensure_erlang_identity_current(repo_b, store)
        assert rebuilt is not None
        assert calls == [repo_b.resolve()]
        assert store.get_metadata(_erlang_identity_key(repo_b)) == ERLANG_IDENTITY_VERSION
    finally:
        store.close()


def test_erlang_identity_legacy_scalar_upgrades_for_single_root(
    tmp_path: Path, monkeypatch
) -> None:
    """A legacy single-root marker is migrated without an unnecessary rebuild."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "sample.erl").write_text(
        "-module(sample).\n-export([run/0]).\nrun() -> ok.\n",
        encoding="utf-8",
    )
    store = GraphStore(repo / "graph.db")
    try:
        monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
        full_build(repo, store)
        store._conn.execute(
            "DELETE FROM metadata WHERE key LIKE 'erlang_identity_version:%'"
        )
        store.set_metadata("erlang_identity_version", ERLANG_IDENTITY_VERSION)
        monkeypatch.setattr(
            "code_review_graph.incremental._invoke_full_build",
            lambda *_args, **_kwargs: pytest.fail("legacy marker should be upgraded"),
        )

        assert _ensure_erlang_identity_current(repo, store) is None
        assert store.get_metadata(_erlang_identity_key(repo)) == ERLANG_IDENTITY_VERSION
    finally:
        store.close()


def test_incremental_update_rejects_foreign_explicit_changed_file(
    tmp_path: Path,
) -> None:
    """Explicit changed-file inputs cannot escape the requested root."""
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    for repo, name in ((repo_a, "a.py"), (repo_b, "b.py")):
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / name).write_text("def live():\n    pass\n", encoding="utf-8")

    store = GraphStore(tmp_path / "shared.db")
    try:
        for repo in (repo_a, repo_b):
            parser = CodeParser(repo)
            for relative in collect_all_files(repo):
                path = repo / relative
                source = path.read_bytes()
                nodes, edges = parser.parse_bytes(path, source)
                store.store_file_nodes_edges(
                    str(path), nodes, edges, hashlib.sha256(source).hexdigest()
                )
        store.commit()
        before = store.get_all_files()

        with pytest.raises(ValueError, match="outside repository root"):
            incremental_update(
                repo_a,
                store,
                changed_files=[str(repo_b / "b.py")],
            )

        assert store.get_all_files() == before
    finally:
        store.close()


@pytest.mark.parametrize(
    "command",
    sorted(cli._PATH_REPO_COMMANDS),
)
def test_path_repo_commands_use_one_absolute_root_spelling(
    command: str, tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    args = SimpleNamespace(command=command, repo=".")

    cli._canonicalize_repo_argument(args)

    assert args.repo == str(repo.resolve())


@pytest.mark.parametrize("command", ["eval", "daemon"])
def test_name_valued_repo_arguments_are_not_treated_as_paths(
    command: str,
) -> None:
    args = SimpleNamespace(command=command, repo="repo-config-name")

    cli._canonicalize_repo_argument(args)

    assert args.repo == "repo-config-name"


@pytest.mark.parametrize("command", ["build", "update"])
def test_build_and_update_cli_pass_a_canonical_root(
    command: str, tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    monkeypatch.chdir(repo)
    result = {
        "files_parsed": 1,
        "files_updated": 0,
        "total_nodes": 2,
        "total_edges": 1,
        "errors": [],
    }

    with patch.object(cli.sys, "argv", ["code-review-graph", command, "--repo", ".", "--quiet"]):
        with patch("code_review_graph.graph.GraphStore", return_value=MagicMock()):
            with patch(
                "code_review_graph.incremental.get_db_path",
                return_value=MagicMock(),
            ):
                with patch(
                    "code_review_graph.tools.build.build_or_update_graph",
                    return_value=result,
                ) as build_or_update:
                    cli.main()

    assert build_or_update.call_args.kwargs["repo_root"] == str(repo.resolve())


def test_watch_cli_passes_a_canonical_root(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    monkeypatch.chdir(repo)
    store = MagicMock()

    with patch.object(cli.sys, "argv", ["code-review-graph", "watch", "--repo", "."]):
        with patch("code_review_graph.graph.GraphStore", return_value=store):
            with patch(
                "code_review_graph.incremental.get_db_path",
                return_value=MagicMock(),
            ):
                with patch("code_review_graph.incremental.watch") as watch:
                    cli.main()

    watch.assert_called_once_with(repo.resolve(), store, on_files_updated=ANY)
