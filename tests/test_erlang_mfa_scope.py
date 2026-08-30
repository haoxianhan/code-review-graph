"""Repository-boundary regressions for Erlang MFA lookup helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_review_graph.eval.erlang_adoption import (
    _query_edges,
    _target_mfa_ambiguous,
)
from code_review_graph.graph import GraphStore, _graph_path_belongs_to_root
from code_review_graph.parser import EdgeInfo, NodeInfo
from code_review_graph.tools import query as query_module

_GENERIC_PROVENANCE_FIELDS = frozenset({
    "source",
    "tool",
    "tool_version",
    "otp_version",
    "repository",
    "source_revision",
    "generated_data_revision",
    "configuration_digest",
    "query_kind",
    "query_targets",
    "status",
    "analysis_key",
    "command",
    "duration_seconds",
    "cache_state",
})


def _assert_mfa_provenance(
    extra: dict,
    *,
    repo: Path,
    raw_target: str,
    source_revision: str | None = None,
    generated_data_revision: str | None = None,
) -> None:
    provenance = extra["provenance"]
    assert _GENERIC_PROVENANCE_FIELDS <= provenance.keys()
    assert provenance == {
        "source": "generic",
        "tool": "code-review-graph",
        "tool_version": None,
        "otp_version": None,
        "repository": repo.resolve(strict=False).as_posix(),
        "source_revision": source_revision,
        "generated_data_revision": generated_data_revision,
        "configuration_digest": None,
        "query_kind": "mfa_resolution",
        "query_targets": [raw_target],
        "status": "ok",
        "analysis_key": None,
        "command": [],
        "duration_seconds": None,
        "cache_state": None,
    }


def _function_node(
    file_path: Path,
    *,
    module: str = "worker",
    suffix: str = "",
) -> NodeInfo:
    return NodeInfo(
        kind="Function",
        name="run",
        identity_name="run/0",
        file_path=file_path.as_posix(),
        line_start=1,
        line_end=1,
        language="erlang",
        parent_name=module,
        extra={"erlang_kind": "function", "arity": 0, "suffix": suffix},
    )


def _caller_node(file_path: Path, *, name: str = "caller") -> NodeInfo:
    return NodeInfo(
        kind="Function",
        name=name,
        identity_name=f"{name}/0",
        file_path=file_path.as_posix(),
        line_start=1,
        line_end=1,
        language="erlang",
        parent_name="caller",
        extra={"erlang_kind": "function", "arity": 0},
    )


def test_erlang_mfa_find_and_count_are_scoped_for_shared_store(tmp_path: Path) -> None:
    root_a = tmp_path / "repo-a"
    root_b = tmp_path / "repo-b"
    file_a = root_a / "src" / "worker.erl"
    file_b = root_b / "src" / "worker.erl"

    with GraphStore(tmp_path / "shared.db") as store:
        store.upsert_node(_function_node(file_a, suffix="a"))
        store.upsert_node(_function_node(file_b, suffix="b"))
        store.commit()

        assert store.count_erlang_mfa("worker", "run", 0) == 2
        assert store.count_erlang_mfa(
            "worker", "run", 0, repo_root=root_a,
        ) == 1
        assert store.count_erlang_mfa(
            "worker", "run", 0, repo_root=root_b,
        ) == 1
        assert [
            node.file_path
            for node in store.find_erlang_mfa(
                "worker", "run", 0, limit=2, repo_root=root_a,
            )
        ] == [file_a.as_posix()]


def test_graph_path_scope_rejects_windows_drive_relative_rows() -> None:
    """Drive-relative Windows paths must not bypass an explicit root."""
    assert not _graph_path_belongs_to_root(
        "C:outside.erl", "C:/repo", allow_relative=True,
    )
    assert not _graph_path_belongs_to_root(
        "C:", "C:/repo", allow_relative=True,
    )
    assert _graph_path_belongs_to_root(
        "C:/repo/src/worker.erl", "C:/repo",
    )


def test_scoped_erlang_mfa_rejects_untrusted_relative_traversal_and_symlink_rows(
    tmp_path: Path,
) -> None:
    """Scoped MFA lookup must require a path that resolves inside the checkout."""
    root = tmp_path / "repo"
    foreign = tmp_path / "foreign"
    (root / "src").mkdir(parents=True)
    (foreign / "src").mkdir(parents=True)

    local = root / "src" / "worker_local.erl"
    relative = Path("src/worker_relative.erl")
    lexical_foreign = root / ".." / foreign.name / "src" / "worker_lexical.erl"
    linked_dir = root / "linked"
    try:
        linked_dir.symlink_to(foreign, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    symlink_foreign = linked_dir / "src" / "worker_symlink.erl"
    caller = root / "src" / "caller.erl"

    caller_node = _caller_node(caller)
    caller_qn = f"{caller.as_posix()}::caller.caller/0"
    call = EdgeInfo(
        kind="CALLS",
        source=caller_qn,
        target="worker:run/0",
        file_path=caller.as_posix(),
        line=1,
        extra={
            "erlang_raw_target": "worker:run/0",
            "erlang_resolution": "syntactic",
            "arity": 0,
        },
    )

    with GraphStore(tmp_path / "shared.db") as store:
        for path, suffix in (
            (local, "local"),
            (relative, "relative"),
            (lexical_foreign, "lexical"),
            (symlink_foreign, "symlink"),
        ):
            store.upsert_node(_function_node(path, suffix=suffix))
        store.upsert_node(caller_node)
        store.upsert_edge(call)
        store.commit()

        # The unscoped form exposes all legacy rows, including relative rows.
        assert store.count_erlang_mfa("worker", "run", 0) == 4

        # A scoped lookup must fail closed for rows without trustworthy
        # repository provenance, while retaining the real local definition.
        assert store.count_erlang_mfa(
            "worker", "run", 0, repo_root=root,
        ) == 1
        matches = store.find_erlang_mfa(
            "worker", "run", 0, limit=10, repo_root=root,
        )
        assert [node.file_path for node in matches] == [local.as_posix()]

        # The production resolver uses the same scoped candidate set and must
        # canonicalize to the local endpoint rather than a foreign row.
        assert store.resolve_erlang_remote_call_targets(repo_root=root) == 1
        edge = store._conn.execute(
            "SELECT target_qualified FROM edges WHERE kind = 'CALLS'"
        ).fetchone()
        assert edge["target_qualified"] == f"{local.as_posix()}::worker.run/0"


def test_query_and_adoption_mfa_ambiguity_ignore_foreign_checkout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root_a = tmp_path / "repo-a"
    root_b = tmp_path / "repo-b"
    local_one = root_a / "src" / "worker_one.erl"
    local_two = root_a / "src" / "worker_two.erl"
    foreign = root_b / "src" / "worker.erl"
    local_solo = root_a / "src" / "solo.erl"
    foreign_solo = root_b / "src" / "solo.erl"
    caller = root_a / "src" / "caller.erl"

    store = GraphStore(tmp_path / "shared.db")
    for path, suffix in (
        (local_one, "one"),
        (local_two, "two"),
        (foreign, "foreign"),
    ):
        store.upsert_node(_function_node(path, suffix=suffix))
    store.upsert_node(_function_node(local_solo, module="solo", suffix="solo"))
    store.upsert_node(
        _function_node(foreign_solo, module="solo", suffix="foreign-solo")
    )
    store.upsert_node(_caller_node(caller))
    caller_qn = f"{caller.as_posix()}::caller.caller/0"
    store.upsert_edge(EdgeInfo(
        kind="CALLS",
        source=caller_qn,
        target="solo:run/0",
        file_path=caller.as_posix(),
        line=1,
    ))
    store.commit()

    try:
        # There are two local definitions, but the foreign checkout must not
        # turn the adoption query into a three-way ambiguity.
        assert _target_mfa_ambiguous(
            "worker:run/0", store, repo_root=root_a,
        ) is True
        assert _target_mfa_ambiguous("worker:run/0", store) is True

        # The adoption matcher must likewise accept a local unique MFA even
        # when a sibling checkout contains a definition with the same alias.
        assert _target_mfa_ambiguous(
            "solo:run/0", store, repo_root=root_a,
        ) is False
        assert _target_mfa_ambiguous("solo:run/0", store) is True
        matched, _ = _query_edges(
            store,
            root_a,
            {"kind": "callers_of", "target": "solo:run/0"},
        )
        assert len(matched) == 1
        assert matched[0].source_qualified == caller_qn

        monkeypatch.setattr(
            query_module,
            "_get_store",
            lambda _repo_root=None: (store, root_a),
        )
        result = query_module.query_graph(
            "callers_of", "worker:run/0", repo_root=str(root_a),
        )
        assert result["status"] == "ambiguous"
        assert result["candidate_count"] == 2
        assert result["candidates_truncated"] is False
    finally:
        # query_graph owns and closes the monkeypatched store on success;
        # closing again is harmless only when the query returned early.
        try:
            store.close()
        except Exception:
            pass


def test_erlang_mfa_resolver_reports_exact_ambiguity_count_beyond_preview_cap(
    tmp_path: Path,
) -> None:
    """Ambiguous MFA metadata keeps a bounded preview and exact total count."""
    repo = tmp_path / "repo"
    caller_file = repo / "src" / "caller.erl"
    caller = _caller_node(caller_file)
    caller_qn = f"{caller_file.as_posix()}::caller.caller/0"

    with GraphStore(tmp_path / "shared.db") as store:
        store.upsert_node(caller)
        for index in range(25):
            store.upsert_node(
                _function_node(
                    repo / "src" / f"worker_{index:02d}.erl",
                    suffix=str(index),
                )
            )
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=caller_qn,
            target="worker:run/0",
            file_path=caller_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "worker:run/0",
                "erlang_resolution": "syntactic",
                "arity": 0,
            },
        ))
        store.upsert_edge(EdgeInfo(
            kind="TESTED_BY",
            source="worker:run/0",
            target=caller_qn,
            file_path=caller_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "worker:run/0",
                "erlang_resolution": "syntactic",
                "arity": 0,
            },
        ))
        store.commit()

        assert store.resolve_erlang_remote_call_targets(repo_root=repo) == 0
        call = store._conn.execute(
            "SELECT target_qualified, extra FROM edges WHERE kind = 'CALLS'"
        ).fetchone()
        mirror = store._conn.execute(
            "SELECT source_qualified, extra FROM edges WHERE kind = 'TESTED_BY'"
        ).fetchone()

        call_extra = json.loads(call["extra"])
        mirror_extra = json.loads(mirror["extra"])
        assert call["target_qualified"] == "worker:run/0"
        assert call_extra["erlang_resolution"] == "ambiguous"
        assert call_extra["ambiguous_target_count"] == 25
        assert len(call_extra["ambiguous_targets"]) == 20
        assert call_extra["ambiguous_targets_truncated"] is True
        assert mirror["source_qualified"] == "worker:run/0"
        assert mirror_extra["ambiguous_target_count"] == 25
        assert len(mirror_extra["ambiguous_targets"]) == 20
        assert mirror_extra["ambiguous_targets_truncated"] is True
        _assert_mfa_provenance(
            call_extra, repo=repo, raw_target="worker:run/0",
        )
        _assert_mfa_provenance(
            mirror_extra, repo=repo, raw_target="worker:run/0",
        )
        assert call_extra["provenance"] == mirror_extra["provenance"]


def test_erlang_mfa_resolver_rebinds_stale_canonical_endpoint_and_mirror(
    tmp_path: Path,
) -> None:
    """A changed unique definition is canonicalized in the same pass."""
    repo = tmp_path / "repo"
    caller_file = repo / "src" / "caller.erl"
    old_file = repo / "src" / "worker_old.erl"
    new_file = repo / "src" / "worker_new.erl"
    caller = _caller_node(caller_file)
    caller_qn = f"{caller_file.as_posix()}::caller.caller/0"
    old_qn = f"{old_file.as_posix()}::worker.run/0"
    new_qn = f"{new_file.as_posix()}::worker.run/0"

    with GraphStore(tmp_path / "shared.db") as store:
        store.upsert_node(caller)
        store.upsert_node(_function_node(old_file, suffix="old"))
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=caller_qn,
            target=old_qn,
            file_path=caller_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "worker:run/0",
                "erlang_resolution": "mfa_index",
                "arity": 0,
            },
        ))
        store.upsert_edge(EdgeInfo(
            kind="TESTED_BY",
            source=old_qn,
            target=caller_qn,
            file_path=caller_file.as_posix(),
            line=1,
            extra={
                "erlang_raw_target": "worker:run/0",
                "erlang_resolution": "mfa_index",
                "arity": 0,
            },
        ))
        store.commit()

        # Leave the canonical edge in place while replacing its indexed node.
        store._conn.execute(
            "DELETE FROM nodes WHERE file_path = ?", (old_file.as_posix(),)
        )
        store.upsert_node(_function_node(new_file, suffix="new"))
        store.set_metadata("git_head_sha", "source-revision")
        store.set_metadata(
            "generated_data_revision", "generated-data-revision",
        )
        store.commit()

        assert store.resolve_erlang_remote_call_targets(repo_root=repo) == 1
        call = store._conn.execute(
            "SELECT target_qualified, extra FROM edges WHERE kind = 'CALLS'"
        ).fetchone()
        mirror = store._conn.execute(
            "SELECT source_qualified, extra FROM edges WHERE kind = 'TESTED_BY'"
        ).fetchone()

        assert call["target_qualified"] == new_qn
        call_extra = json.loads(call["extra"])
        mirror_extra = json.loads(mirror["extra"])
        assert call_extra["erlang_resolution"] == "mfa_index"
        assert mirror["source_qualified"] == new_qn
        assert mirror_extra["erlang_resolution"] == "mfa_index"
        _assert_mfa_provenance(
            call_extra,
            repo=repo,
            raw_target="worker:run/0",
            source_revision="source-revision",
            generated_data_revision="generated-data-revision",
        )
        _assert_mfa_provenance(
            mirror_extra,
            repo=repo,
            raw_target="worker:run/0",
            source_revision="source-revision",
            generated_data_revision="generated-data-revision",
        )
        assert call_extra["provenance"] == mirror_extra["provenance"]


def test_erlang_mfa_resolver_keeps_zero_and_multiple_candidates_unresolved(
    tmp_path: Path,
) -> None:
    """Missing or duplicate MFAs never retain a stale canonical endpoint."""
    repo = tmp_path / "repo"
    caller_zero_file = repo / "src" / "caller_zero.erl"
    caller_many_file = repo / "src" / "caller_many.erl"
    old_zero = repo / "src" / "missing_old.erl"
    old_many = repo / "src" / "worker_old.erl"

    def add_stale_edge(
        store: GraphStore,
        caller_file: Path,
        caller_name: str,
        old_target: str,
        raw_target: str,
        line: int,
    ) -> str:
        caller = _caller_node(caller_file, name=caller_name)
        caller_qn = f"{caller_file.as_posix()}::caller.{caller_name}/0"
        store.upsert_node(caller)
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=caller_qn,
            target=old_target,
            file_path=caller_file.as_posix(),
            line=line,
            extra={
                "erlang_raw_target": raw_target,
                "erlang_resolution": "mfa_index",
                "arity": 0,
            },
        ))
        store.upsert_edge(EdgeInfo(
            kind="TESTED_BY",
            source=old_target,
            target=caller_qn,
            file_path=caller_file.as_posix(),
            line=line,
            extra={
                "erlang_raw_target": raw_target,
                "erlang_resolution": "mfa_index",
                "arity": 0,
            },
        ))
        return caller_qn

    old_zero_qn = f"{old_zero.as_posix()}::missing.run/0"
    old_many_qn = f"{old_many.as_posix()}::worker.run/0"
    with GraphStore(tmp_path / "shared.db") as store:
        zero_caller_qn = add_stale_edge(
            store, caller_zero_file, "zero", old_zero_qn, "missing:run/0", 1,
        )
        many_caller_qn = add_stale_edge(
            store, caller_many_file, "many", old_many_qn, "worker:run/0", 2,
        )
        store.upsert_node(_function_node(repo / "src" / "worker_a.erl"))
        store.upsert_node(_function_node(repo / "src" / "worker_b.erl"))
        store.commit()

        assert store.resolve_erlang_remote_call_targets(repo_root=repo) == 2
        rows = store._conn.execute(
            "SELECT source_qualified, target_qualified, extra FROM edges "
            "WHERE kind = 'CALLS' ORDER BY line"
        ).fetchall()
        assert rows[0]["source_qualified"] == zero_caller_qn
        assert rows[0]["target_qualified"] == "missing:run/0"
        zero_extra = json.loads(rows[0]["extra"])
        assert zero_extra["erlang_resolution"] == "unresolved"
        assert zero_extra["unresolved_target_count"] == 0
        assert rows[1]["source_qualified"] == many_caller_qn
        assert rows[1]["target_qualified"] == "worker:run/0"
        many_extra = json.loads(rows[1]["extra"])
        assert many_extra["erlang_resolution"] == "ambiguous"
        assert many_extra["ambiguous_target_count"] == 2

        mirrors = store._conn.execute(
            "SELECT source_qualified, extra FROM edges WHERE kind = 'TESTED_BY' "
            "ORDER BY line"
        ).fetchall()
        assert mirrors[0]["source_qualified"] == "missing:run/0"
        assert mirrors[1]["source_qualified"] == "worker:run/0"
        zero_mirror_extra = json.loads(mirrors[0]["extra"])
        many_mirror_extra = json.loads(mirrors[1]["extra"])
        _assert_mfa_provenance(
            zero_extra, repo=repo, raw_target="missing:run/0",
        )
        _assert_mfa_provenance(
            zero_mirror_extra, repo=repo, raw_target="missing:run/0",
        )
        _assert_mfa_provenance(
            many_extra, repo=repo, raw_target="worker:run/0",
        )
        _assert_mfa_provenance(
            many_mirror_extra, repo=repo, raw_target="worker:run/0",
        )
        assert zero_extra["provenance"] == zero_mirror_extra["provenance"]
        assert many_extra["provenance"] == many_mirror_extra["provenance"]


def test_erlang_mfa_resolver_survives_malformed_candidate_node_extra(
    tmp_path: Path,
) -> None:
    """Corrupt optional node metadata must not abort MFA resolution."""
    repo = tmp_path / "repo"
    caller_file = repo / "src" / "caller.erl"
    worker_file = repo / "src" / "worker.erl"
    caller = _caller_node(caller_file)
    caller_qn = f"{caller_file.as_posix()}::caller.caller/0"
    worker_qn = f"{worker_file.as_posix()}::worker.run/0"

    with GraphStore(tmp_path / "shared.db") as store:
        store.upsert_node(caller)
        store.upsert_node(_function_node(worker_file))
        store._conn.execute(
            "UPDATE nodes SET extra = ? WHERE qualified_name = ?",
            ("{malformed", worker_qn),
        )
        store.upsert_edge(EdgeInfo(
            kind="CALLS",
            source=caller_qn,
            target="worker:run/0",
            file_path=caller_file.as_posix(),
            line=1,
            extra={"erlang_raw_target": "worker:run/0"},
        ))
        store.commit()

        assert store.resolve_erlang_remote_call_targets(repo_root=repo) == 0
        edge = store._conn.execute(
            "SELECT target_qualified, extra FROM edges WHERE kind = 'CALLS'"
        ).fetchone()
        assert edge["target_qualified"] == "worker:run/0"
        extra = json.loads(edge["extra"])
        assert extra["erlang_resolution"] == "unresolved"
        assert extra["unresolved_target_count"] == 0
