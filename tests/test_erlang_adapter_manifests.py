"""Contracts for the checked-in Erlang adapter execution policies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_review_graph.eval.erlang import (
    DEFAULT_ADAPTER_MANIFEST_DIR,
    DEFAULT_MANIFEST,
    ERLANG_ADAPTERS,
    inspect_adapter_manifests,
    load_adapter_manifests,
    load_manifest,
    validate_adapter_manifest,
)


def test_server_manifest_loads_all_adapter_policies():
    manifest = load_manifest(DEFAULT_MANIFEST)
    adapters = manifest["_adapter_manifests"]

    assert set(adapters) == set(ERLANG_ADAPTERS)
    assert manifest["adapters"]["runtime_policy"] == "mixed"
    for name, adapter in adapters.items():
        assert adapter["adapter"] == name
        assert adapter["invocation"]["shell"] is False
        assert adapter["provenance"]["command_recorded"] is True
        assert adapter["cache"]["stale_policy"].startswith("reject_")


def test_adapter_manifests_capture_distinct_execution_contracts():
    manifests = load_adapter_manifests(DEFAULT_ADAPTER_MANIFEST_DIR)

    assert manifests["generic"]["invocation"]["mode"] == "in_process"
    assert manifests["generic"]["enforcement"]["status"] == "intrinsic"
    for name in ("elp", "xref", "dialyzer"):
        manifest = manifests[name]
        assert manifest["invocation"]["mode"] == "argv"
        assert manifest["invocation"]["cwd"] == "repository_root"
        assert manifest["sandbox"]["network"] in {"deny", "controlled"}
        assert manifest["enforcement"]["runtime_policy_enforced"] is False
        assert manifest["enforcement"]["status"] == "described_only"
        assert manifest["enforcement"]["diagnostic_code"]
    assert "plt_identity" in manifests["dialyzer"]["cache"]["key_fields"]


def test_policy_inspection_reports_descriptive_runtime_boundary():
    result = inspect_adapter_manifests(DEFAULT_ADAPTER_MANIFEST_DIR)

    assert result["status"] == "degraded"
    assert result["runtime_policy_enforced"] is False
    assert result["manifests"] == sorted(ERLANG_ADAPTERS)
    assert result["diagnostics"][0]["code"] == "adapter_manifest_policy_not_enforced"
    assert set(result["diagnostics"][0]["details"]["adapters"]) == {
        "elp",
        "xref",
        "dialyzer",
    }


def test_missing_or_invalid_policy_is_observable(tmp_path: Path):
    missing = inspect_adapter_manifests(tmp_path)
    assert missing["status"] == "unavailable"
    assert missing["diagnostics"][0]["code"] == "adapter_manifest_unavailable"

    source = DEFAULT_ADAPTER_MANIFEST_DIR / "elp.manifest.json"
    broken = json.loads(source.read_text(encoding="utf-8"))
    broken["invocation"]["shell"] = True
    with pytest.raises(ValueError, match="shell execution is forbidden"):
        validate_adapter_manifest(broken, "elp.manifest.json")


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("sandbox", "read_paths", ["../outside"], "must not escape"),
        ("cache", "key_fields", ["repository"], "missing fields"),
        ("timeout", "max_seconds", 301, "must bound"),
    ],
)
def test_policy_validator_rejects_unsafe_or_incomplete_contracts(
    section: str, field: str, value: object, message: str
):
    source = DEFAULT_ADAPTER_MANIFEST_DIR / "elp.manifest.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    manifest[section][field] = value

    with pytest.raises(ValueError, match=message):
        validate_adapter_manifest(manifest, "elp.manifest.json")
