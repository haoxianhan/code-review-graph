"""Focused contracts for optional Erlang semantic evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from code_review_graph.erlang_semantic import (
    STATUS_MALFORMED,
    STATUS_MISMATCH,
    STATUS_OK,
    STATUS_STALE,
    STATUS_TIMEOUT,
    AnalysisKey,
    CommandResult,
    DialyzerAdapter,
    ELPAdapter,
    EnrichmentQuery,
    EvidenceCache,
    EvidenceReconciler,
    EvidenceRecord,
    Provenance,
    ToolchainIdentity,
    XrefAdapter,
    compute_generated_data_revision,
    compute_plt_identity,
    discover_toolchain,
    run_erlang_enrichment,
)


def _toolchain(
    tmp_path: Path,
    *,
    source_revision: str | None = "source-1",
    generated_data_revision: str | None = "generated-1",
    elp_executable: str | None = "/opt/elp",
    elp_version: str | None = "0.12.0",
    elp_otp_version: str | None = None,
    plt_identity: str | None = None,
) -> ToolchainIdentity:
    return ToolchainIdentity(
        repository=tmp_path.as_posix(),
        source_revision=source_revision,
        generated_data_revision=generated_data_revision,
        configuration_digest="config-1",
        otp_version="27",
        elp_executable=elp_executable,
        elp_version=elp_version,
        elp_otp_version=elp_otp_version,
        rebar3_executable="/opt/rebar3",
        rebar3_version="3.25.0",
        xref_command=("/opt/rebar3", "xref"),
        dialyzer_command=("/opt/rebar3", "dialyzer"),
        plt_identity=plt_identity,
    )


def _runner(result: CommandResult):
    calls: list[tuple[str, ...]] = []

    def run(command, *, cwd, env, timeout):
        calls.append(tuple(command))
        return result

    run.calls = calls  # type: ignore[attr-defined]
    return run


def _record(key: AnalysisKey, target: str, *, source: str = "caller") -> EvidenceRecord:
    provenance = Provenance.from_key(key)
    return EvidenceRecord(
        kind="CALLS",
        source=source,
        target=target,
        provenance=provenance,
    )


def test_analysis_key_is_revision_and_target_order_stable(tmp_path: Path):
    toolchain = _toolchain(tmp_path)
    first = AnalysisKey.from_toolchain(toolchain, "elp", "callers_of", ["b", "a", "a"])
    second = AnalysisKey.from_toolchain(toolchain, "ELP", "CALLERS_OF", ["a", "b"])

    assert first == second
    assert first.cache_key == second.cache_key
    assert first.to_dict()["query_targets"] == ["a", "b"]


def test_elp_parses_explicit_json_and_keeps_provenance(tmp_path: Path):
    toolchain = _toolchain(tmp_path)
    payload = json.dumps({
        "evidence": [{
            "kind": "CALLS",
            "source": "caller",
            "target": "worker.run/1",
            "file": "src/caller.erl",
            "line": 9,
        }],
        "diagnostics": [{"code": "elp_note", "message": "indexed"}],
    })
    adapter = ELPAdapter(
        toolchain,
        runner=_runner(CommandResult(0, payload)),
    )

    result = adapter.query(tmp_path, "callers_of", "worker.run/1")

    assert result.status == STATUS_OK
    assert len(result.evidence) == 1
    assert result.evidence[0].target == "worker.run/1"
    assert result.evidence[0].provenance.tool == "elp"
    assert result.evidence[0].provenance.source_revision == "source-1"
    assert result.diagnostics[0].code == "elp_note"


def test_elp_unavailable_and_otp_mismatch_are_non_throwing(tmp_path: Path):
    unavailable = ELPAdapter(
        _toolchain(tmp_path, elp_executable=None, elp_version=None)
    )
    result = unavailable.query(tmp_path, "callers_of", "worker.run/1")
    assert result.status == "unavailable"
    assert result.diagnostics[0].code == "elp_unavailable"

    mismatch = ELPAdapter(
        _toolchain(tmp_path, elp_otp_version="26"),
        runner=_runner(CommandResult(0, "{}")),
    )
    result = mismatch.query(tmp_path, "callers_of", "worker.run/1")
    assert result.status == STATUS_MISMATCH
    assert result.diagnostics[0].code == "elp_otp_mismatch"


def test_elp_timeout_and_malformed_output_are_observable(tmp_path: Path):
    timeout = ELPAdapter(
        _toolchain(tmp_path),
        runner=_runner(CommandResult(124, stderr="timed out")),
    )
    result = timeout.query(tmp_path, "impact", "worker")
    assert result.status == STATUS_TIMEOUT
    assert result.diagnostics[0].code == "elp_timeout"

    malformed = ELPAdapter(
        _toolchain(tmp_path),
        runner=_runner(CommandResult(0, "not-json")),
    )
    result = malformed.query(tmp_path, "impact", "worker")
    assert result.status == STATUS_MALFORMED
    assert result.diagnostics[0].code == "elp_malformed_output"


def test_xref_stays_at_module_granularity_and_preserves_undefined_diagnostics(tmp_path: Path):
    output = "alpha -> beta\nCall to undefined function missing:run/0\n"
    adapter = XrefAdapter(
        _toolchain(tmp_path),
        runner=_runner(CommandResult(0, output)),
    )

    result = adapter.collect(tmp_path)

    assert result.status == STATUS_OK
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.kind == "DEPENDS_ON"
    assert evidence.metadata["module_level"] is True
    assert not any(item.kind == "CALLS" for item in result.evidence)
    assert any(item.code == "xref_undefined_call" for item in result.diagnostics)


def test_dialyzer_rejects_stale_plt_before_running_command(tmp_path: Path):
    plt = tmp_path / "dialyzer.plt"
    plt.write_bytes(b"current")
    adapter = DialyzerAdapter(
        _toolchain(tmp_path, plt_identity="old"),
        plt_path=plt,
        runner=_runner(CommandResult(0, "src/a.erl:4: warning: no local return")),
    )

    result = adapter.collect(tmp_path)

    assert result.status == STATUS_STALE
    assert result.diagnostics[0].code == "dialyzer_plt_stale"


def test_dialyzer_ingests_location_and_kind(tmp_path: Path):
    adapter = DialyzerAdapter(
        _toolchain(tmp_path),
        runner=_runner(CommandResult(0, "src/a.erl:4:7: Warning: no local return\n")),
    )

    result = adapter.collect(tmp_path)

    assert result.status == STATUS_OK
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "dialyzer_warning"
    assert diagnostic.file_path == "src/a.erl"
    assert diagnostic.line == 4
    assert diagnostic.column == 7
    assert diagnostic.metadata["warning_kind"] == "unknown"


def test_dialyzer_preserves_structured_warning_kind(tmp_path: Path):
    adapter = DialyzerAdapter(
        _toolchain(tmp_path),
        runner=_runner(
            CommandResult(
                0,
                "src/a.erl:4:7: Warning: [warn_return_no_exit] no local return\n",
            )
        ),
    )

    result = adapter.collect(tmp_path)

    assert result.status == STATUS_OK
    assert result.diagnostics[0].metadata["warning_kind"] == "warn_return_no_exit"


def test_reconciler_merges_duplicates_and_marks_conflicts():
    toolchain = ToolchainIdentity(
        repository="/repo",
        source_revision="r1",
        otp_version="27",
        elp_version="1",
        elp_executable="elp",
    )
    key = AnalysisKey.from_toolchain(toolchain, "elp", "callers_of", "target")
    first = _record(key, "target")
    duplicate = replace_provenance(first, source="other-adapter")
    conflict = _record(key, "other-target")

    result = EvidenceReconciler().reconcile(
        [first, duplicate, conflict],
        analysis_key=key,
        replace_queries=["callers_of"],
    )

    assert len(result.evidence) == 2
    merged = next(item for item in result.evidence if item.target == "target")
    assert len(merged.provenance_chain) == 1
    assert len(result.conflicts) == 1
    assert all("conflict_group" in item.metadata for item in result.evidence)


def test_reconciler_drops_stale_and_retains_matching_on_unavailable():
    toolchain = ToolchainIdentity(
        repository="/repo",
        source_revision="r1",
        otp_version="27",
        elp_version="1",
        elp_executable="elp",
    )
    key = AnalysisKey.from_toolchain(toolchain, "elp", "callers_of", "target")
    old = _record(key, "old")
    new_key = AnalysisKey.from_toolchain(
        replace(toolchain, source_revision="r2"),
        "elp",
        "callers_of",
        "target",
    )
    result = EvidenceReconciler().reconcile(
        [],
        analysis_key=new_key,
        previous=[old],
        unavailable_queries=["callers_of"],
    )
    assert result.evidence == ()
    assert len(result.stale_evidence) == 1
    assert any(item.code == "evidence_stale" for item in result.diagnostics)


def test_cache_round_trip_and_key_mismatch(tmp_path: Path):
    toolchain = _toolchain(tmp_path)
    key = AnalysisKey.from_toolchain(toolchain, "elp", "impact", "worker")
    record = _record(key, "worker.run/1")
    cache = EvidenceCache(tmp_path / "cache")
    path = cache.save(key, [record])
    loaded = cache.load(key)
    assert path.is_file()
    assert loaded.status == "hit"
    assert loaded.evidence[0].evidence_id == record.evidence_id

    mismatch = AnalysisKey.from_toolchain(
        _toolchain(tmp_path, source_revision="source-2"), "elp", "impact", "worker"
    )
    stale = cache.load(mismatch)
    assert stale.status == "miss"
    assert stale.stale is True
    assert "mismatch" in (stale.message or "") or "older" in (stale.message or "")


def test_generated_and_plt_revisions_are_content_based(tmp_path: Path):
    generated = tmp_path / "generated"
    generated.mkdir()
    output = generated / "schema.hrl"
    output.write_text("-record(state, {}).\n", encoding="utf-8")
    first = compute_generated_data_revision(tmp_path, [generated])
    output.write_text("-record(state, {value}).\n", encoding="utf-8")
    second = compute_generated_data_revision(tmp_path, [generated])
    assert first and second and first != second

    plt = tmp_path / "x.plt"
    plt.write_bytes(b"plt")
    expected = hashlib.sha256(b"plt").hexdigest()
    assert compute_plt_identity(plt) == expected


def replace_provenance(record: EvidenceRecord, *, source: str) -> EvidenceRecord:
    provenance = replace(record.provenance, source=source)
    return EvidenceRecord(
        kind=record.kind,
        source=record.source,
        target=record.target,
        provenance=provenance,
        file_path=record.file_path,
        line=record.line,
        column=record.column,
        metadata=record.metadata,
    )


def test_enrichment_query_normalization_accepts_single_tuple_and_mapping():
    assert EnrichmentQuery.from_value(("elp", "callers_of", ["b", "a"])).to_dict() == {
        "tool": "elp",
        "query_kind": "callers_of",
        "query_targets": ["a", "b"],
    }


def test_enrichment_keeps_previous_evidence_when_targeted_adapter_times_out(tmp_path: Path):
    toolchain = _toolchain(tmp_path)
    success = _runner(
        CommandResult(
            0,
            json.dumps(
                {
                    "evidence": [
                        {"kind": "CALLS", "source": "caller", "target": "worker.run/1"}
                    ]
                }
            ),
        )
    )
    first = run_erlang_enrichment(
        tmp_path,
        toolchain=toolchain,
        queries={"callers_of": "worker.run/1"},
        runner=success,
    )
    assert first.ok
    assert len(first.evidence) == 1

    timeout = _runner(CommandResult(124, stderr="timed out"))
    second = run_erlang_enrichment(
        tmp_path,
        toolchain=toolchain,
        queries={"callers_of": "worker.run/1"},
        previous=first.evidence,
        runner=timeout,
    )
    assert second.status == "degraded"
    assert second.evidence == first.evidence
    assert any(item.code == "elp_timeout" for item in second.diagnostics)


def test_enrichment_aggregates_xref_and_dialyzer_without_graph_store(tmp_path: Path):
    toolchain = _toolchain(tmp_path)

    def run(command, *, cwd, env, timeout):
        if tuple(command) == toolchain.xref_command:
            return CommandResult(0, "alpha -> beta\n")
        if tuple(command) == toolchain.dialyzer_command:
            return CommandResult(0, "src/a.erl:4: warning: no local return\n")
        return CommandResult(0, "{}")

    result = run_erlang_enrichment(
        tmp_path,
        toolchain=toolchain,
        runner=run,
        include_xref=True,
        include_dialyzer=True,
    )
    assert result.ok
    assert any(item.kind == "DEPENDS_ON" for item in result.evidence)
    assert any(item.code == "dialyzer_warning" for item in result.diagnostics)
    assert result.cache_state["xref:module_dependencies:"] == "miss"


def test_discovery_records_elp_otp_hint_and_timeout(monkeypatch, tmp_path: Path):
    executable_paths = {
        "erl": "/usr/bin/erl",
        "elp": "/usr/bin/elp",
        "rebar3": "/usr/bin/rebar3",
    }

    def which(name):
        return executable_paths.get(name)

    monkeypatch.setattr("code_review_graph.erlang_semantic.shutil.which", which)
    calls = []

    def run(command, *, cwd, env, timeout):
        calls.append(tuple(command))
        if command[0] == "/usr/bin/erl":
            return CommandResult(124, stderr="timeout")
        if command[0] == "/usr/bin/elp":
            return CommandResult(0, "elp 0.12.0")
        if command[0] == "/usr/bin/rebar3":
            return CommandResult(0, "rebar 3.25.0")
        if command[0] == "git":
            return CommandResult(0, "revision\n")
        return CommandResult(127)

    identity = discover_toolchain(
        tmp_path,
        runner=run,
        environment={"ELP_OTP_VERSION": "27", "SECRET_TOKEN": "redact-me"},
    )
    assert identity.elp_otp_version == "27"
    assert ("ELP_OTP_VERSION", "27") in identity.environment
    assert all(key != "SECRET_TOKEN" for key, _ in identity.environment)
    assert any(item.startswith("otp_timeout:") for item in identity.diagnostics)
    assert any(command[0] == "/usr/bin/elp" for command in calls)
