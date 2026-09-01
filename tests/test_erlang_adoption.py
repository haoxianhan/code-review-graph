"""Focused tests for the executable Erlang adoption runner."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

from code_review_graph.eval.erlang import DEFAULT_MANIFEST, load_manifest
from code_review_graph.eval.erlang_adoption import (
    RESULT_KIND,
    _adoption_gates,
    _aggregate_metrics,
    _available_semantic_tools,
    _case_tool_reason,
    _checked_lifecycle_result,
    _checkout_snapshot,
    _lifecycle_parity_from_evidence,
    _manifest_erlang_config,
    _materialize_forget_mirror,
    _portable_graph_fingerprint,
    _portable_graph_value,
    _relation_matches,
    _repository_gates,
    _run_case,
    _run_isolated_watch_smoke,
    _run_lifecycle,
    _semantic_execution_state,
    _top_level_diagnostics_gate,
    render_adoption_report,
    run_adoption_evaluation,
    score_case,
    validate_evaluation_result,
    write_adoption_report,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _fixture(tmp_path: Path) -> tuple[Path, dict, dict]:
    repo = tmp_path / "server_flexible"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "worker.erl").write_text(
        "-module(worker).\n-export([run/0]).\nrun() -> ok.\n",
        encoding="utf-8",
    )
    (repo / "src" / "caller.erl").write_text(
        "-module(caller).\n-export([run/0]).\nrun() -> worker:run().\n",
        encoding="utf-8",
    )
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    revision = _git(repo, "rev-parse", "HEAD")

    manifest = load_manifest(DEFAULT_MANIFEST, load_adapters=False)
    manifest = copy.deepcopy(manifest)
    manifest["target"]["path"] = str(repo)
    manifest["revision"] = {
        "requested": revision,
        "observed": revision,
        "working_tree_clean": True,
        "baseline_status": "clean",
        "dirty_paths": [],
    }
    manifest["dependencies"] = {"lockfiles": [], "submodules": []}
    manifest["generated_data"] = {
        "revision": "fixture",
        "config_version": "fixture",
        "paths": [],
    }
    manifest.pop("adapters", None)
    corpus = {
        "schema_version": 1,
        "kind": "erlang_evaluation_corpus",
        "manifest": "fixture.manifest.json",
        "cases": [
            {
                "id": "worker-callers",
                "category": "local_callers",
                "description": "Find a caller of worker:run/0.",
                "query": {
                    "kind": "callers_of",
                    "target": {
                        "file": "src/worker.erl",
                        "symbol": "run",
                        "arity": 0,
                    },
                },
                "expected": {
                    "positive": [
                        {
                            "relation": "CALLS",
                            "source": {
                                "file": "src/caller.erl",
                                "symbol": "run",
                                "arity": 0,
                            },
                            # Generic cross-file calls remain bare until a
                            # semantic resolver proves the target file.
                            "target": "worker:run/0",
                        }
                    ],
                    "negative": [],
                    "unresolved": [],
                },
                "review": {"status": "fixture", "reviewer": "test"},
            }
        ],
        "metrics": {"status": "not_run"},
    }
    return repo, manifest, corpus


def test_clean_fixture_executes_graph_lifecycle_and_scores_query(tmp_path: Path, monkeypatch):
    repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    target_snapshot = _checkout_snapshot(repo)

    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    assert result["kind"] == RESULT_KIND
    assert result["adoption"]["verdict"] == "auxiliary"
    assert result["adoption"]["pass"] is False
    assert result["cases"][0]["status"] == "executed"
    assert result["cases"][0]["true_positive"] == 1
    assert result["cases"][0]["precision"] == 1.0
    assert result["cases"][0]["recall"] == 1.0
    assert result["metrics"]["latency"]["by_operation"]["targeted_query"]["p95_ms"] is not None
    assert result["lifecycle"]["full_build"]["status"] == "executed"
    assert result["lifecycle"]["incremental_update"]["status"] == "executed"
    assert result["lifecycle"]["incremental_update"]["parity"] is True
    assert result["lifecycle"]["incremental_update"]["temporary_source_mutation"] is True
    assert result["lifecycle"]["incremental_update"]["source_restored"] is True
    assert (repo / "src" / "worker.erl").read_bytes() == (
        b"-module(worker).\n-export([run/0]).\nrun() -> ok.\n"
    )
    assert _checkout_snapshot(repo) == target_snapshot
    assert result["lifecycle"]["standalone_postprocess"]["status"] == "executed"
    assert result["lifecycle"]["forget"]["status"] == "executed"
    assert result["lifecycle"]["watch"]["status"] == "not_run"
    assert not (repo / ".code-review-graph").exists()
    validate_evaluation_result(result)


def test_forget_mirror_has_independent_git_metadata(tmp_path: Path):
    repo, _manifest, _corpus = _fixture(tmp_path)
    (repo / ".self_key").write_text("P4PASSWD=should-not-be-copied\n", encoding="utf-8")
    mirror = tmp_path / "forget-mirror"

    _materialize_forget_mirror(repo, mirror)

    assert _git(mirror, "rev-parse", "--show-toplevel") == str(mirror)
    assert _git(mirror, "rev-parse", "HEAD") == _git(repo, "rev-parse", "HEAD")
    assert (mirror / ".git").is_dir()
    assert not (mirror / ".self_key").exists()


def test_project_mirror_uses_external_runtime_key_without_copying_it(tmp_path: Path):
    repo, _manifest, _corpus = _fixture(tmp_path)
    runtime_key = tmp_path / "runtime.self_key"
    runtime_key.write_text("P4PASSWD=secret\n", encoding="utf-8")
    mirror = tmp_path / "project-mirror"

    _materialize_forget_mirror(
        repo,
        mirror,
        include_runtime_key=True,
        runtime_key=runtime_key,
    )

    assert (mirror / ".self_key").is_symlink()
    assert (mirror / ".self_key").resolve() == runtime_key.resolve()
    assert (mirror / ".self_key").read_bytes() == runtime_key.read_bytes()


def test_portable_fingerprint_ignores_checkout_scoped_semantic_ids(tmp_path: Path):
    """Equivalent semantic projections from temporary mirrors hash equally."""
    from code_review_graph.graph import GraphStore
    from code_review_graph.parser import EdgeInfo

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()

    def add_projection(store_path: Path, root: Path, evidence_id: str, analysis_key: str):
        store = GraphStore(store_path)
        source = root / "src" / "caller.erl"
        target = root / "src" / "worker.erl"
        store.upsert_edge(
            EdgeInfo(
                kind="CALLS",
                source=f"{source}::caller.run/0",
                target=f"{target}::worker.run/0",
                file_path=str(source),
                line=3,
                extra={
                    "_crg_erlang_semantic": True,
                    "_crg_erlang_projection_owned": True,
                    "_crg_erlang_repository": str(root),
                    "semantic_evidence_id": evidence_id,
                    "semantic_evidence_ids": [evidence_id],
                    "semantic_provenance": {
                        "repository": str(root),
                        "analysis_key": analysis_key,
                        "source_revision": "same-revision",
                        "tool": "elp",
                        "tool_version": "same-version",
                    },
                },
            )
        )
        store.commit()
        return store

    first = add_projection(tmp_path / "first.db", first_root, "evidence-a", "analysis-a")
    second = add_projection(tmp_path / "second.db", second_root, "evidence-b", "analysis-b")
    try:
        assert _portable_graph_fingerprint(first, first_root) == _portable_graph_fingerprint(
            second, second_root
        )
        assert _portable_graph_value(
            {"semantic_evidence_ids": ["a", "b"]}, first_root
        ) == {"semantic_evidence_ids": ["<stable-evidence-identity>"] * 2}
    finally:
        first.close()
        second.close()


def test_manifest_can_raise_bounded_semantic_timeout(tmp_path: Path):
    manifest = load_manifest(DEFAULT_MANIFEST, load_adapters=False)
    manifest["evaluation"] = {"semantic_timeout_seconds": 900}

    config = _manifest_erlang_config(manifest)

    assert config is not None
    assert config.timeout == 900.0


def test_manifest_profile_adds_corpus_probe_for_required_elp(tmp_path: Path):
    manifest = load_manifest(DEFAULT_MANIFEST, load_adapters=False)
    corpus = {
        "cases": [
            {
                "query": {
                    "target": {
                        "file": "apps/demo/src/demo.erl",
                        "symbol": "run",
                        "arity": 0,
                    }
                }
            }
        ]
    }

    config = _manifest_erlang_config(manifest, corpus=corpus)

    assert config is not None
    assert config.queries[0].tool == "elp"
    assert config.queries[0].targets == (
        "apps/demo/src/demo.erl::demo.run/0",
    )


def test_clause_children_do_not_make_function_anchor_ambiguous(
    tmp_path: Path, monkeypatch,
):
    """Clause navigation nodes must not be treated as callable endpoints."""
    _repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")

    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    case = result["cases"][0]
    assert case["status"] == "executed"
    assert case["true_positive"] == 1
    assert case["precision"] == 1.0
    assert case["recall"] == 1.0


def test_dirty_target_is_fail_closed_and_does_not_build(tmp_path: Path, monkeypatch):
    repo, manifest, corpus = _fixture(tmp_path)
    (repo / "src" / "caller.erl").write_text(
        (repo / "src" / "caller.erl").read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    called = False

    def fail_build(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("dirty target must not be built")

    result = run_adoption_evaluation(
        manifest,
        corpus,
        probe_root=tmp_path,
        graph_runner=fail_build,
    )

    assert called is False
    assert result["adoption"]["verdict"] == "auxiliary"
    assert result["adoption"]["pass"] is False
    assert result["cases"][0]["status"] == "not_run"
    assert result["cases"][0]["reason"] == "target_worktree_dirty"
    assert result["metrics"]["status"] == "not_run"
    assert result["metrics"]["precision"] is None


@pytest.mark.parametrize("mode", ["missing", "revision"])
def test_missing_or_mismatched_target_is_blocked(tmp_path: Path, mode: str):
    repo, manifest, corpus = _fixture(tmp_path)
    if mode == "missing":
        manifest["target"]["path"] = str(tmp_path / "does-not-exist")
    else:
        manifest["revision"]["requested"] = "0" * 40

    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    assert result["adoption"]["verdict"] == "blocked"
    assert result["adoption"]["pass"] is False
    assert all(case["status"] == "not_run" for case in result["cases"])
    assert result["metrics"]["precision"] is None


def test_dry_run_and_report_writer_are_deterministic_and_safe(tmp_path: Path):
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path, dry_run=True)

    assert result["metrics"]["status"] == "not_run"
    assert result["metrics"]["precision"] is None
    assert result["lifecycle"]["full_build"]["status"] == "not_run"
    report_dir = tmp_path / "reports"
    paths = write_adoption_report(result, report_dir)
    assert paths["json"].is_file()
    assert paths["markdown"].is_file()
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["kind"] == RESULT_KIND
    assert render_adoption_report(result).endswith("\n")
    with pytest.raises(ValueError, match="outside"):
        write_adoption_report(result, Path(manifest["target"]["path"]))


def test_recall_at_10_uses_ranked_hit_count(tmp_path: Path):
    """The aggregate Recall@10 must not reuse full-list true positives."""
    case_results = [
        {
            "status": "executed",
            "category": "local_callers",
            "predicted_count": 2,
            "expected_positive_count": 2,
            "true_positive": 2,
            "ranked_true_positive": 1,
            "forbidden_matches": 0,
            "precision": 1.0,
            "measurement_complete": True,
        }
    ]

    metrics = _aggregate_metrics(case_results, {}, {}, None, tmp_path)

    assert metrics["recall_at_10"]["function"] == 0.5
    assert metrics["recall_at_10"]["module"] is None


def test_unresolved_expectation_requires_an_explicit_unresolved_candidate(tmp_path: Path):
    from code_review_graph.graph import GraphStore

    store = GraphStore(tmp_path / "graph.db")
    case = {
        "id": "dynamic",
        "expected": {
            "positive": [],
            "negative": [],
            "unresolved": [{"relation": "CALLS", "target": "dynamic:run/0"}],
        },
    }
    try:
        missing = score_case(case, [], root=tmp_path, store=store)
        assert missing["unresolved_satisfied"] is False
        assert missing["measurement_complete"] is False

        candidate = score_case(
            case,
            [
                {
                    "relation": "CALLS",
                    "source": "src/caller.erl::caller.run/0",
                    "target": "dynamic:run/0",
                    "extra": {"unresolved_targets": ["dynamic:run/0"]},
                }
            ],
            root=tmp_path,
            store=store,
        )
        assert candidate["unresolved_satisfied"] is True
        assert candidate["precision"] is None
        assert candidate["predicted_count"] == 0
        assert candidate["unresolved_prediction_count"] == 1

        resolved = score_case(
            case,
            [
                {
                    "relation": "CALLS",
                    "source": "src/caller.erl::caller.run/0",
                    "target": "src/dynamic.erl::dynamic.run/0",
                    "extra": {},
                }
            ],
            root=tmp_path,
            store=store,
        )
        assert resolved["unresolved_satisfied"] is False
    finally:
        store.close()


def test_result_validator_recomputes_recall_and_top_level_diagnostics(tmp_path: Path):
    """Derived adoption gates must follow measured cases and diagnostics."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged_recall = copy.deepcopy(result)
    forged_recall["metrics"]["recall_at_10"] = {"function": 1.0, "module": 1.0}
    forged_recall["adoption"]["gates"]["recall_at_10"] = True
    with pytest.raises(ValueError, match="recall_at_10"):
        validate_evaluation_result(forged_recall)

    forged_diagnostics = copy.deepcopy(result)
    forged_diagnostics["environment"]["diagnostics_contract"] = {
        "required": ["diagnostic_that_was_not_observed"]
    }
    # Keep the producer's green gate unchanged; the validator must recompute it
    # from the observed top-level diagnostic codes and the declared contract.
    with pytest.raises(ValueError, match="top_level_diagnostics"):
        validate_evaluation_result(forged_diagnostics)


def test_result_validator_recomputes_impact_entries(tmp_path: Path):
    """Impact summaries must be derived from non-empty, self-consistent entries."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)
    result["metrics"]["impact"] = {
        "status": "executed",
        "expected": ["src/worker.erl"],
        "predicted": ["src/worker.erl"],
        "covered": ["src/worker.erl"],
        "coverage": 1.0,
        "all_entries_covered": True,
        "false_positive_count": 0,
        "disallowed_false_positive_count": 0,
        "false_positive_allowed": False,
        "entries": [
            {
                "expected": ["src/worker.erl"],
                "predicted": ["src/worker.erl"],
                "covered": ["src/worker.erl"],
                "coverage": 1.0,
                "false_positive_count": 0,
                "false_positive_allowed": False,
            }
        ],
    }
    result["adoption"]["gates"]["impact_coverage"] = True
    validate_evaluation_result(result)

    empty_entries = copy.deepcopy(result)
    empty_entries["metrics"]["impact"]["entries"] = []
    with pytest.raises(ValueError, match="impact.entries"):
        validate_evaluation_result(empty_entries)

    inconsistent_entries = copy.deepcopy(result)
    inconsistent_entries["metrics"]["impact"]["entries"][0]["covered"] = []
    with pytest.raises(ValueError, match="impact.entries.*coverage"):
        validate_evaluation_result(inconsistent_entries)

    inconsistent_summary = copy.deepcopy(result)
    inconsistent_summary["metrics"]["impact"]["predicted"] = [
        "src/other.erl",
        "src/worker.erl",
    ]
    with pytest.raises(ValueError, match="impact.predicted"):
        validate_evaluation_result(inconsistent_summary)


def test_impact_expected_paths_cannot_escape_target(tmp_path: Path):
    """The legacy impact ``expected`` spelling remains repository-scoped."""
    _repo, manifest, corpus = _fixture(tmp_path)
    corpus["impact"] = [
        {
            "changed_files": ["src/worker.erl"],
            "expected": ["../outside.erl"],
        }
    ]

    with pytest.raises(ValueError, match=r"corpus\.impact\[0\]\.expected"):
        run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)


def test_empty_diagnostics_requirement_is_satisfied() -> None:
    assert _top_level_diagnostics_gate(set(), {"required": []}) is True
    assert _top_level_diagnostics_gate(set(), {"required": ["missing"]}) is False


def test_result_validator_requires_anchor_evidence_fields(tmp_path: Path):
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    missing_field = copy.deepcopy(result)
    missing_field["cases"][0].pop("missing_anchors")
    with pytest.raises(ValueError, match="missing_anchors.*missing field"):
        validate_evaluation_result(missing_field)

    unrelated_anchor = copy.deepcopy(result)
    unrelated_anchor["cases"][0]["missing_anchors"] = ["src/not-an-anchor.erl"]
    with pytest.raises(ValueError, match="not a subset"):
        validate_evaluation_result(unrelated_anchor)


def test_result_validator_rejects_remote_mismatch_and_non_blocked_verdict(tmp_path: Path):
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    forged["gates"]["remote_mismatch"] = True
    with pytest.raises(ValueError, match="remote_mismatch"):
        validate_evaluation_result(forged)

    forged = copy.deepcopy(result)
    forged["environment"]["repository"]["remote"] = "ssh://wrong.example/repo"
    forged["gates"]["remote_identity"] = False
    forged["gates"]["remote_mismatch"] = True
    forged["adoption"]["gates"]["remote_identity"] = False
    # All other fields remain unchanged, including the auxiliary verdict. A
    # consistent remote mismatch is a hard failure and must be blocked.
    with pytest.raises(ValueError, match="adoption.verdict"):
        validate_evaluation_result(forged)


def test_result_validator_derives_optional_semantic_requirements_from_policy(tmp_path: Path):
    """Optional adapters are not required, but a lifecycle envelope is."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)
    policy = {
        "manifests": ["generic", "elp", "xref", "dialyzer"],
        "runtime_policy_enforced": True,
        "manifest_activation": {
            "generic": {"mode": "always", "required": True},
            "elp": {"mode": "explicit_opt_in", "required": False},
            "xref": {"mode": "explicit_opt_in", "required": False},
            "dialyzer": {"mode": "explicit_opt_in", "required": False},
        },
    }
    result["environment"]["adapter_policy"] = policy
    successful_integration = {
        "status": "ok",
        "adapters": {"elp": {"status": "ok"}},
    }
    for phase_name in ("full_build", "incremental_update"):
        result["lifecycle"][phase_name]["result"][
            "erlang_integration"
        ] = successful_integration
    expected = _semantic_execution_state(result["environment"], result["lifecycle"])
    result["adoption"]["semantic"]["execution"] = expected
    result["adoption"]["gates"]["semantic_tools"] = expected["valid"]
    result["adoption"]["gates"]["semantic_adapters_executed"] = expected["valid"]
    result["adoption"]["gates"]["runtime_policy_enforced"] = expected["policy_enforced"]
    validate_evaluation_result(result)

    forged_required = copy.deepcopy(result)
    forged_required["adoption"]["semantic"]["execution"]["required"] = ["elp"]
    with pytest.raises(ValueError, match="required"):
        validate_evaluation_result(forged_required)

    forged_lifecycle = copy.deepcopy(result)
    forged_lifecycle["lifecycle"]["full_build"]["result"]["erlang_integration"][
        "adapters"
    ]["elp"]["status"] = "failed"
    with pytest.raises(ValueError, match="semantic.execution"):
        validate_evaluation_result(forged_lifecycle)


def test_result_validator_recomputes_runtime_policy_gate(tmp_path: Path):
    """A stale runtime-policy gate cannot be used to promote a report."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    forged["adoption"]["gates"]["runtime_policy_enforced"] = False
    with pytest.raises(ValueError, match="runtime_policy_enforced"):
        validate_evaluation_result(forged)


def test_result_validator_blocks_generated_data_mismatch(tmp_path: Path):
    """A declared generated-data case with unavailable markers is hard-blocked."""
    _repo, manifest, corpus = _fixture(tmp_path)
    corpus["cases"][0]["category"] = "generated_data"
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)
    assert result["adoption"]["verdict"] == "blocked"

    forged = copy.deepcopy(result)
    forged["adoption"]["gates"]["generated_data_consistent"] = True
    # The validator must derive the failed gate from observed markers rather
    # than trusting a producer-supplied boolean.
    with pytest.raises(ValueError, match="generated_data_consistent"):
        validate_evaluation_result(forged)


def test_checked_lifecycle_result_rejects_phase_and_status_mismatch():
    payload = {
        "files_parsed": 1,
        "errors": [],
        "total_nodes": 1,
        "total_edges": 0,
    }
    with pytest.raises(ValueError, match="phase"):
        _checked_lifecycle_result({**payload, "phase": "watch"}, "full_build")
    with pytest.raises(TypeError, match="status"):
        _checked_lifecycle_result({**payload, "status": 1}, "full_build")
    with pytest.raises(ValueError, match="incomplete envelope"):
        _checked_lifecycle_result(
            {"files_parsed": 1, "errors": [], "total_nodes": 1},
            "full_build",
        )


def test_lifecycle_watch_requires_activity_evidence(tmp_path: Path):
    """A zero-event smoke envelope cannot claim that watch was exercised."""
    root = tmp_path / "repo"
    root.mkdir()

    def runner(phase, *_args, **_kwargs):
        if phase == "full_build":
            return {
                "files_parsed": 0,
                "errors": [],
                "total_nodes": 0,
                "total_edges": 0,
            }
        if phase == "incremental_update":
            return {
                "files_updated": 1,
                "errors": [],
                "changed_files": ["src/worker.erl"],
                "graph_changed": False,
            }
        if phase == "standalone_postprocess":
            return {
                "bare_edges_resolved": 0,
                "fts_indexed": 0,
                "signatures_computed": 0,
                "full_build_reference_fingerprint": "0" * 64,
            }
        if phase == "watch":
            return {
                "events": 0,
                "updates": 0,
                "graph_changed": False,
                "notifications": 0,
            }
        raise AssertionError(phase)

    store, lifecycle, _timings, diagnostics = _run_lifecycle(
        root,
        tmp_path / "work",
        lifecycle_runner=runner,
        watch_smoke=True,
    )
    try:
        assert lifecycle["watch"]["status"] == "executed"
        assert lifecycle["watch"]["activity_evidence"] is False
        assert lifecycle["watch"]["parity"] is False
        assert any(item["code"] == "watch_activity_unverified" for item in diagnostics)
        assert lifecycle["standalone_postprocess"]["parity"] is False
    finally:
        store.close()


def test_default_watch_smoke_uses_mirror_and_cleans_up(tmp_path: Path, monkeypatch):
    """The opt-in default smoke never writes the evaluated checkout."""
    repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    before = (repo / "src" / "worker.erl").read_bytes()

    result = run_adoption_evaluation(
        manifest,
        corpus,
        probe_root=tmp_path,
        watch_smoke=True,
        timeout=5.0,
    )

    assert result["lifecycle"]["watch"]["status"] == "executed"
    assert result["lifecycle"]["watch"]["activity_evidence"] is True
    assert result["lifecycle"]["watch"]["parity"] is True
    assert result["lifecycle"]["watch"]["result"]["events"] > 0
    assert (repo / "src" / "worker.erl").read_bytes() == before
    assert not (repo / ".code-review-graph").exists()
    assert not list(tmp_path.glob("crg-watch-smoke-*"))


def test_isolated_watch_smoke_timeout_is_bounded_and_cleans_up(tmp_path: Path, monkeypatch):
    """A watcher that never reaches readiness cannot satisfy the smoke gate."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "worker.erl").write_text(
        "-module(worker).\n-export([run/0]).\nrun() -> ok.\n",
        encoding="utf-8",
    )

    def stalled_watch(*_args, **_kwargs):
        _kwargs["stop_event"].wait(1.0)

    monkeypatch.setattr("code_review_graph.eval.erlang_adoption.watch", stalled_watch)
    with pytest.raises(TimeoutError, match="live phase"):
        _run_isolated_watch_smoke(root, tmp_path, timeout=0.1)
    assert not list(tmp_path.glob("crg-watch-smoke-*"))


@pytest.mark.parametrize("field", ["events", "updates", "notifications"])
def test_checked_watch_rejects_opaque_activity_arrays(field: str):
    """Watch counters cannot be forged with arbitrary non-empty arrays."""
    payload = {
        "events": 1,
        "updates": 1,
        "graph_changed": True,
        "notifications": 1,
    }
    payload[field] = [{}]
    with pytest.raises(TypeError, match=rf"watch runner returned invalid {field}"):
        _checked_lifecycle_result(payload, "watch")


def test_validator_rejects_opaque_watch_activity_array(tmp_path: Path, monkeypatch):
    """A report cannot promote an arbitrary watch array to activity evidence."""
    _repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    forged["lifecycle"]["watch"] = {
        "status": "executed",
        "parity": False,
        "activity_evidence": False,
        "reference_match": False,
        "reference_fingerprint": None,
        "observed_fingerprint": "0" * 64,
        "result": {
            "events": [{}],
            "updates": 1,
            "graph_changed": True,
            "notifications": 1,
        },
    }
    with pytest.raises(ValueError, match=r"result\.lifecycle\.watch\.result"):
        validate_evaluation_result(forged)


def test_lifecycle_parity_is_derived_from_phase_evidence(tmp_path: Path, monkeypatch):
    """Changing only lifecycle summaries cannot manufacture a green parity."""
    _repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    mutations = {
        "full_build": lambda item: item["result"]["errors"].append(
            {"message": "forged build error"}
        ),
            "incremental_update": lambda item: item.update({"source_restored": False}),
        "standalone_postprocess": lambda item: item.update(
            {"observed_fingerprint": "f" * 64}
        ),
        "forget": lambda item: item.update({"target_absent": False}),
        "watch": lambda item: item.update({"parity": True}),
    }

    for phase, mutate in mutations.items():
        forged = copy.deepcopy(result)
        mutate(forged["lifecycle"][phase])
        with pytest.raises(ValueError, match=rf"result\.lifecycle\.{phase}"):
            validate_evaluation_result(forged)


def test_validator_rejects_inconsistent_incremental_evidence(tmp_path: Path, monkeypatch):
    """Incremental evidence fields must describe the same observed update."""
    _repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    incremental = forged["lifecycle"]["incremental_update"]
    # A zero-file update cannot claim that update evidence was observed.
    incremental["result"]["files_updated"] = 0
    incremental["update_evidence"] = True
    incremental["parity"] = False
    with pytest.raises(ValueError, match="incremental_update.update_evidence"):
        validate_evaluation_result(forged)

    forged = copy.deepcopy(result)
    incremental = forged["lifecycle"]["incremental_update"]
    incremental["result"]["files_updated"] = 1
    incremental["update_evidence"] = True
    incremental["result"]["changed_files"] = []
    incremental["result"]["graph_changed"] = True
    # Keep the reported parity aligned with the reducer so this assertion
    # reaches the positive-update evidence contract itself.
    incremental["parity"] = False
    with pytest.raises(ValueError, match="positive update evidence"):
        validate_evaluation_result(forged)


def test_validator_rejects_inconsistent_forget_target_evidence(tmp_path: Path, monkeypatch):
    """The forget wrapper target must be present in its runner summary."""
    _repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    forget = forged["lifecycle"]["forget"]
    forget["parity"] = False
    forget["result"]["forgotten"] = []
    with pytest.raises(ValueError, match=r"result\.lifecycle\.forget\.forgotten"):
        validate_evaluation_result(forged)


@pytest.mark.parametrize("payload_status", ["failed", "blocked", "not_run", "dry_run"])
def test_validator_rejects_failed_inner_lifecycle_status(
    tmp_path: Path, monkeypatch, payload_status: str
):
    """An inner failure status cannot be hidden by an executed outer phase."""
    _repo, manifest, corpus = _fixture(tmp_path)
    monkeypatch.setenv("CRG_SERIAL_PARSE", "1")
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    forged["lifecycle"]["full_build"]["result"]["status"] = payload_status
    with pytest.raises(
        ValueError,
        match=r"result\.lifecycle\.full_build\.result\.status",
    ):
        validate_evaluation_result(forged)


def test_watch_parity_requires_a_reference_and_activity_evidence():
    """The pure reducer rejects a forged watch envelope without graph access."""
    item = {
        "status": "executed",
        "parity": True,
        "activity_evidence": True,
        "reference_match": True,
        "reference_fingerprint": "0" * 64,
        "observed_fingerprint": "0" * 64,
        "result": {
            "events": 1,
            "updates": 1,
            "graph_changed": False,
            "notifications": 1,
        },
    }
    assert _lifecycle_parity_from_evidence("watch", item) is True
    item["reference_fingerprint"] = None
    item["reference_match"] = False
    assert _lifecycle_parity_from_evidence("watch", item) is False


def test_semantic_execution_rejects_generic_only_envelope():
    """Generic baseline indexing must not satisfy semantic execution."""
    environment = {
        "adapter_policy": {
            "manifests": ["generic"],
            "manifest_activation": {
                "generic": {"mode": "always", "required": True},
            },
        }
    }
    lifecycle = {
        "full_build": {
            "status": "executed",
            "result": {
                "erlang_integration": {
                    "status": "ok",
                    "adapters": {"generic": {"status": "ok"}},
                }
            },
        }
    }

    execution = _semantic_execution_state(environment, lifecycle)

    assert execution["valid"] is False
    assert execution["status"] == "not_run"


def test_unresolved_expectation_keeps_source_constraint(tmp_path: Path):
    from code_review_graph.graph import GraphStore

    store = GraphStore(tmp_path / "graph.db")
    case = {
        "expected": {
            "positive": [],
            "negative": [],
            "unresolved": [
                {
                    "relation": "CALLS",
                    "source": {"file": "src/expected.erl", "symbol": "run", "arity": 0},
                    "target": "dynamic:function/0",
                }
            ],
        }
    }
    predicted = {
        "relation": "CALLS",
        "source": "src/other.erl::other.run/0",
        "target": "dynamic:function/0",
        "extra": {"resolution": "unresolved"},
    }
    try:
        scored = score_case(case, [predicted], root=tmp_path, store=store)
        assert scored["unresolved_satisfied"] is False
        assert scored["measurement_complete"] is False
    finally:
        store.close()


def test_tests_for_follows_production_to_test_edge_direction(tmp_path: Path):
    from code_review_graph.eval.erlang_adoption import _query_edges
    from code_review_graph.graph import GraphStore
    from code_review_graph.parser import EdgeInfo, NodeInfo

    root = tmp_path / "repo"
    production = root / "src" / "worker.erl"
    suite = root / "test" / "worker_SUITE.erl"
    production.parent.mkdir(parents=True)
    suite.parent.mkdir(parents=True)
    production.write_text("-module(worker).\nrun() -> ok.\n", encoding="utf-8")
    suite.write_text("-module(worker_SUITE).\nrun_test() -> worker:run().\n", encoding="utf-8")
    store = GraphStore(tmp_path / "graph.db")
    production_path = production.as_posix()
    suite_path = suite.as_posix()
    production_qn = f"{production_path}::worker.run/0"
    suite_qn = f"{suite_path}::worker_SUITE.run_test/0"
    try:
        store.upsert_node(
            NodeInfo(
                kind="Function",
                name="run",
                identity_name="run/0",
                file_path=production_path,
                parent_name="worker",
                line_start=2,
                line_end=2,
                language="erlang",
                extra={"arity": 0},
            )
        )
        store.upsert_node(
            NodeInfo(
                kind="Test",
                name="run_test",
                identity_name="run_test/0",
                file_path=suite_path,
                parent_name="worker_SUITE",
                line_start=2,
                line_end=2,
                language="erlang",
                is_test=True,
                extra={"arity": 0},
            )
        )
        store.upsert_edge(
            EdgeInfo(
                kind="TESTED_BY",
                source=production_qn,
                target=suite_qn,
                file_path=suite_path,
                line=2,
            )
        )
        store.commit()

        function_edges, _ = _query_edges(
            store,
            root,
            {
                "kind": "tests_for",
                "target": {"file": "src/worker.erl", "symbol": "run", "arity": 0},
            },
        )
        file_edges, _ = _query_edges(
            store,
            root,
            {"kind": "tests_for", "target": {"file": "test/worker_SUITE.erl"}},
        )
        assert [edge.target_qualified for edge in function_edges] == [suite_qn]
        assert [edge.source_qualified for edge in file_edges] == [production_qn]
    finally:
        store.close()


def test_lifecycle_error_is_blocked_not_auxiliary():
    lifecycle = {
        name: {"status": "executed", "parity": True, "target_absent": True}
        for name in (
            "full_build",
            "incremental_update",
            "watch",
            "forget",
            "standalone_postprocess",
        )
    }
    lifecycle["incremental_update"]["status"] = "error"
    gates = {
        "target_exists": True,
        "standalone_git": True,
        "pinned_revision": True,
        "clean_baseline": True,
        "working_tree_state_known": True,
        "remote_identity": True,
        "dependencies_consistent": True,
    }
    environment = {
        "toolchain": {"tools": {}},
        "diagnostics": [{"code": "elp_unavailable"}],
        "evaluation": {"latency_budget_ms": {}},
        "adapter_policy": {"manifests": []},
    }
    metrics = {
        "precision": None,
        "cases_scored": 0,
        "forbidden_matches": 0,
        "recall_at_10": {"function": None, "module": None},
        "latency": {"status": "not_run"},
        "impact": {"status": "not_run"},
    }
    adoption = _adoption_gates(gates, environment, [], lifecycle, metrics, {})
    assert adoption["verdict"] == "blocked"
    assert adoption["gates"]["lifecycle_errors"] is False


def _repository_gate_fixture(root: Path) -> tuple[dict, dict]:
    revision = "a" * 40
    manifest = {
        "revision": {"requested": revision, "observed": revision},
        "target": {"remote": "origin"},
        "dependencies": {"submodules": []},
    }
    environment = {
        "repository": {
            "exists": True,
            "top_level": str(root),
            "revision": revision,
            "remote": "origin",
            "working_tree_clean": True,
            "submodules": [],
        },
        "diagnostics": [],
    }
    return manifest, environment


def test_repository_gate_rejects_malformed_observed_submodule(tmp_path: Path):
    manifest, environment = _repository_gate_fixture(tmp_path)
    environment["repository"]["submodules"] = [{"path": "lib"}, None]

    gates, diagnostics, can_build = _repository_gates(
        manifest, environment, tmp_path, allow_dirty=False
    )

    assert gates["dependencies_consistent"] is False
    assert can_build is False
    malformed = next(
        item for item in diagnostics if item["code"] == "submodule_observation_malformed"
    )
    assert malformed["details"]["paths"] == [
        "repository.submodules[1]",
    ]


def test_repository_gate_requires_manifest_revision_observed_to_match_requested(tmp_path: Path):
    manifest, environment = _repository_gate_fixture(tmp_path)
    manifest["revision"]["observed"] = "b" * 40

    gates, diagnostics, can_build = _repository_gates(
        manifest, environment, tmp_path, allow_dirty=False
    )

    assert gates["pinned_revision"] is False
    assert can_build is False
    mismatch = next(item for item in diagnostics if item["code"] == "pinned_revision_mismatch")
    assert mismatch["details"]["manifest_observed"] == "b" * 40


def test_postprocess_warnings_fail_lifecycle_gate(tmp_path: Path):
    from code_review_graph.eval import erlang_adoption

    _repo, manifest, corpus = _fixture(tmp_path)
    original = erlang_adoption.run_post_processing

    def warning_postprocess(_store):
        return {
            "bare_edges_resolved": 0,
            "fts_indexed": 0,
            "signatures_computed": 0,
            "warnings": ["synthetic postprocess failure"],
        }

    erlang_adoption.run_post_processing = warning_postprocess
    try:
        result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)
    finally:
        erlang_adoption.run_post_processing = original

    assert result["lifecycle"]["standalone_postprocess"]["status"] == "error"
    assert result["adoption"]["gates"]["lifecycle_errors"] is False
    assert any(
        item["code"] == "standalone_postprocess_failed"
        for item in result["diagnostics"]
    )


def test_result_validator_rejects_missing_schema_sections(tmp_path: Path):
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)
    for field in ("status", "lifecycle", "diagnostics"):
        malformed = copy.deepcopy(result)
        malformed.pop(field)
        with pytest.raises(ValueError, match="missing keys"):
            validate_evaluation_result(malformed)


def test_result_validator_rejects_forged_available_semantic_tools(tmp_path: Path):
    """The advertised tools must be derived from observed toolchain status."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    forged = copy.deepcopy(result)
    forged_tools = ["made_up_tool"]
    forged["environment"]["available_semantic_tools"] = forged_tools
    forged["adoption"]["semantic"]["available"] = forged_tools

    with pytest.raises(ValueError, match="available_semantic_tools.*toolchain"):
        validate_evaluation_result(forged)

    stale_status = copy.deepcopy(result)
    elp = stale_status["environment"]["toolchain"]["tools"]["elp"]
    elp["status"] = (
        "unavailable"
        if elp["status"] in {"available", "available_via_rebar3"}
        else "available"
    )
    with pytest.raises(ValueError, match="available_semantic_tools.*toolchain"):
        validate_evaluation_result(stale_status)


def test_result_validator_rejects_malformed_toolchain_tools(tmp_path: Path):
    """Tool status evidence must remain a structured mapping."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    mutations = []

    def sync_advertised_tools(report: dict) -> None:
        expected = sorted(_available_semantic_tools(report["environment"]))
        report["environment"]["available_semantic_tools"] = expected
        report["adoption"]["semantic"]["available"] = expected

    def non_mapping_tools(report: dict) -> None:
        report["environment"]["toolchain"]["tools"] = []
        report["environment"]["available_semantic_tools"] = []
        report["adoption"]["semantic"]["available"] = []

    mutations.append(non_mapping_tools)

    def empty_tools(report: dict) -> None:
        report["environment"]["toolchain"]["tools"] = {}
        report["environment"]["available_semantic_tools"] = []
        report["adoption"]["semantic"]["available"] = []

    mutations.append(empty_tools)

    def non_mapping_tool(report: dict) -> None:
        report["environment"]["toolchain"]["tools"]["elp"] = []
        sync_advertised_tools(report)

    mutations.append(non_mapping_tool)

    def missing_status(report: dict) -> None:
        report["environment"]["toolchain"]["tools"]["elp"].pop("status")
        sync_advertised_tools(report)

    mutations.append(missing_status)

    def unsupported_status(report: dict) -> None:
        report["environment"]["toolchain"]["tools"]["elp"]["status"] = "installed"
        sync_advertised_tools(report)

    mutations.append(unsupported_status)

    for mutate in mutations:
        malformed = copy.deepcopy(result)
        mutate(malformed)
        with pytest.raises(ValueError, match=r"toolchain\.tools"):
            validate_evaluation_result(malformed)


def test_result_validator_rejects_inconsistent_measured_surfaces(tmp_path: Path):
    """A report mutation must not leave a stale adoption result accepted."""
    _repo, manifest, corpus = _fixture(tmp_path)
    result = run_adoption_evaluation(manifest, corpus, probe_root=tmp_path)

    mutations = []

    def stale_gate(report: dict) -> None:
        report["adoption"]["gates"]["precision_100"] = not report["adoption"]["gates"][
            "precision_100"
        ]

    mutations.append(stale_gate)

    def wrong_case_count(report: dict) -> None:
        report["metrics"]["cases_scored"] += 1

    mutations.append(wrong_case_count)

    def invalid_latency(report: dict) -> None:
        report["metrics"]["latency"]["p95_ms"] = -1

    mutations.append(invalid_latency)

    def malformed_prediction(report: dict) -> None:
        report["cases"][0]["predictions"][0]["extra"] = []

    mutations.append(malformed_prediction)

    def foreign_prediction_target(report: dict) -> None:
        # Keep the shape and all reported counts intact while changing only
        # the endpoint.  The embedded corpus contract must reject this as a
        # false relation rather than trusting the producer's true_positive.
        report["cases"][0]["predictions"][0]["target"] = "foreign:run/0"

    mutations.append(foreign_prediction_target)

    def inconsistent_impact(report: dict) -> None:
        # The fixture has no impact ground truth, so coverage must remain null.
        report["metrics"]["impact"]["coverage"] = 0.5

    mutations.append(inconsistent_impact)

    for mutate in mutations:
        malformed = copy.deepcopy(result)
        mutate(malformed)
        with pytest.raises(ValueError):
            validate_evaluation_result(malformed)


def test_file_qualified_endpoint_does_not_match_same_symbol_in_other_file(tmp_path: Path):
    from code_review_graph.graph import GraphStore

    store = GraphStore(tmp_path / "graph.db")
    predicted = {
        "relation": "CALLS",
        "source": "src/caller.erl::caller.run/0",
        "target": "src/other.erl::other.run/0",
    }
    expected = {
        "relation": "CALLS",
        "source": {"file": "src/caller.erl", "symbol": "run", "arity": 0},
        "target": {"file": "src/worker.erl", "symbol": "run", "arity": 0},
    }
    try:
        assert _relation_matches(predicted, expected, tmp_path, store) is False
    finally:
        store.close()


def test_absolute_in_root_qualified_edges_match_but_outside_edges_do_not(tmp_path: Path):
    """Internal graph identities may be absolute, while checkout escapes fail closed."""
    from code_review_graph.graph import GraphStore

    root = tmp_path / "repo"
    caller = root / "src" / "caller.erl"
    worker = root / "src" / "worker.erl"
    caller.parent.mkdir(parents=True)
    caller.write_text("", encoding="utf-8")
    worker.write_text("", encoding="utf-8")
    store = GraphStore(tmp_path / "graph.db")
    expected = {
        "relation": "CALLS",
        "source": {"file": "src/caller.erl", "symbol": "run", "arity": 0},
        "target": {"file": "src/worker.erl", "symbol": "run", "arity": 0},
    }
    predicted = {
        "relation": "CALLS",
        "source": f"{caller}::caller.run/0",
        "target": f"{worker}::worker.run/0",
    }
    try:
        assert _relation_matches(predicted, expected, root, store) is True
        outside = dict(predicted)
        outside["target"] = f"{tmp_path / 'outside.erl'}::worker.run/0"
        assert _relation_matches(outside, expected, root, store) is False
    finally:
        store.close()


def test_special_mfa_uses_only_explicit_supervises_evidence(tmp_path: Path):
    from code_review_graph.erlang_semantic import (
        AnalysisKey,
        EvidenceRecord,
        Provenance,
        ToolchainIdentity,
    )
    from code_review_graph.graph import GraphStore
    from code_review_graph.parser import EdgeInfo

    root = tmp_path / "repo"
    source = root / "src" / "supervisor.erl"
    source.parent.mkdir(parents=True)
    source.write_text("", encoding="utf-8")
    store = GraphStore(tmp_path / "graph.db")
    query = {
        "kind": "mfa",
        "target": {"symbol": "start_link/0", "arity": 0},
    }
    case = {
        "id": "supervisor-mfa",
        "category": "supervisor_mfa",
        "query": query,
        "expected": {
            "positive": [
                {
                    "relation": "SUPERVISES",
                    "target": {"symbol": "start_link/0", "arity": 0},
                }
            ],
            "negative": [],
            "unresolved": [],
        },
    }
    try:
        # A regular call edge is not supervisor evidence and must not be
        # promoted by the special handler.
        store.upsert_edge(
            EdgeInfo(
                kind="CALLS",
                source=f"{source}::supervisor.init/1",
                target="worker:start_link/0",
                file_path=source.as_posix(),
                line=1,
            )
        )
        store.commit()
        result, _duration = _run_case(case, store, root)
        assert result["status"] == "not_run"
        assert result["reason"] == "semantic_evidence_unavailable"

        toolchain = ToolchainIdentity(repository=root.as_posix(), source_revision="revision-1")
        key = AnalysisKey.from_toolchain(toolchain, "elp", "mfa", "start_link/0")
        evidence = EvidenceRecord(
            kind="SUPERVISES",
            source=f"{source}::supervisor.init/1",
            target="worker:start_link/0",
            line=1,
            provenance=Provenance.from_key(key),
        )
        store.store_semantic_snapshot({"evidence": [evidence]}, analysis_key=key)
        result, _duration = _run_case(case, store, root)
        assert result["status"] == "executed"
        assert result["true_positive"] == 1
        assert result["predictions"][0]["relation"] == "SUPERVISES"
    finally:
        store.close()


def test_special_diagnostics_and_cache_queries_report_unresolved_state(tmp_path: Path):
    from code_review_graph.graph import GraphStore

    root = tmp_path / "repo"
    root.mkdir()
    store = GraphStore(tmp_path / "graph.db")
    diagnostics_case = {
        "id": "fallback-unavailable",
        "category": "fallback_unavailable",
        "query": {"kind": "diagnostics", "target": {"symbol": "elp"}},
        "expected": {
            "positive": [],
            "negative": [],
            "unresolved": [{"relation": "TOOL_UNAVAILABLE", "target": "elp"}],
        },
    }
    cache_case = {
        "id": "stale-cache",
        "category": "stale_cache",
        "query": {"kind": "cache", "target": {"symbol": "revision-1"}},
        "expected": {
            "positive": [],
            "negative": [],
            "unresolved": [{"relation": "CACHE_REJECTED", "target": "revision-1"}],
        },
    }
    environment = {
        "toolchain": {"tools": {"elp": {"status": "unavailable", "command": ["elp"]}}},
        "diagnostics": [],
        "cache": {
            "paths": [
                {
                    "path": ".code-review-graph",
                    "present": True,
                    "status": "unkeyed",
                    "revision_key": None,
                }
            ]
        },
    }
    try:
        diagnostics, _duration = _run_case(diagnostics_case, store, root, environment)
        assert diagnostics["status"] == "executed"
        assert diagnostics["unresolved_satisfied"] is True
        assert diagnostics["predictions"][0]["relation"] == "TOOL_UNAVAILABLE"

        cache, _duration = _run_case(cache_case, store, root, environment)
        assert cache["status"] == "executed"
        assert cache["unresolved_satisfied"] is True
        assert cache["predictions"][0]["relation"] == "CACHE_REJECTED"

        assert _case_tool_reason(diagnostics_case, set()) is None
        assert _case_tool_reason(cache_case, set()) is None
    finally:
        store.close()
