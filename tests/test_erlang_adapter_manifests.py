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
    assert manifest["adapters"]["runtime_policy"] == "enforced"
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
        assert manifest["enforcement"]["runtime_policy_enforced"] is True
        assert manifest["enforcement"]["status"] == "enforced"
    assert "plt_identity" in manifests["dialyzer"]["cache"]["key_fields"]


def test_policy_inspection_reports_enforced_runtime_boundary():
    result = inspect_adapter_manifests(DEFAULT_ADAPTER_MANIFEST_DIR)

    assert result["status"] == "ok"
    assert result["runtime_policy_enforced"] is True
    assert result["manifests"] == sorted(ERLANG_ADAPTERS)
    assert result["diagnostics"] == []


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
    ("mutator", "message"),
    [
        (
            lambda manifest: manifest["invocation"].update(argv=["other", "query"]),
            "must match invocation.executable",
        ),
        (
            lambda manifest: manifest["invocation"].update(argv=["elp", "other"]),
            "subcommand is not in",
        ),
        (
            lambda manifest: manifest["invocation"].update(
                argv=["elp", "query", "--unsafe", "{query_kind}", "{query_targets}"]
            ),
            "approved flag",
        ),
        (
            lambda manifest: manifest["invocation"].update(
                argv=["elp", "query", "{unknown}", "{query_kind}", "{query_targets}"]
            ),
            "unsupported template placeholder",
        ),
        *[
            (
                lambda manifest, character=character: manifest["invocation"].update(
                    argv=[
                        "elp",
                        "query",
                        f"--format{character}evil",
                        "json",
                        "{query_kind}",
                        "{query_targets}",
                    ]
                ),
                "shell metacharacters",
            )
            for character in (";", "|", "&", "$", "`", "<", ">", "\n")
        ],
        (
            lambda manifest: manifest["invocation"].update(
                argv=[
                    "elp",
                    "query",
                    "--format",
                    "json value",
                    "{query_kind}",
                    "{query_targets}",
                ]
            ),
            "single argv token",
        ),
    ],
)
def test_policy_validator_rejects_unsafe_command_templates(mutator, message):
    source = DEFAULT_ADAPTER_MANIFEST_DIR / "elp.manifest.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    mutator(manifest)

    with pytest.raises(ValueError, match=message):
        validate_adapter_manifest(manifest, "elp.manifest.json")


def test_policy_validator_rejects_command_allowlist_shape_changes():
    source = DEFAULT_ADAPTER_MANIFEST_DIR / "elp.manifest.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))

    manifest["invocation"]["command_allowlist"]["unexpected"] = []
    with pytest.raises(ValueError, match="unknown keys"):
        validate_adapter_manifest(manifest, "elp.manifest.json")

    manifest = json.loads(source.read_text(encoding="utf-8"))
    del manifest["invocation"]["command_allowlist"]["flags"]
    with pytest.raises(ValueError, match="missing keys"):
        validate_adapter_manifest(manifest, "elp.manifest.json")


def _write_manifest_fixture(root: Path) -> Path:
    root.mkdir()
    adapter_dir = root / "adapters"
    adapter_dir.mkdir()
    manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    manifest_path = root / "server.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for name in ERLANG_ADAPTERS:
        source = DEFAULT_ADAPTER_MANIFEST_DIR / f"{name}.manifest.json"
        target = adapter_dir / source.name
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return manifest_path


@pytest.mark.parametrize("directory", ["../outside", "sub/../../outside"])
def test_parent_manifest_rejects_lexical_adapter_traversal(tmp_path: Path, directory: str):
    manifest_path = _write_manifest_fixture(tmp_path / "bundle")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["adapters"]["directory"] = directory
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="must not escape"):
        load_manifest(manifest_path)


def test_parent_manifest_rejects_symlinked_adapter_directory(tmp_path: Path):
    manifest_path = _write_manifest_fixture(tmp_path / "bundle")
    outside = tmp_path / "outside"
    outside.mkdir()
    for name in ERLANG_ADAPTERS:
        source = DEFAULT_ADAPTER_MANIFEST_DIR / f"{name}.manifest.json"
        (outside / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    adapter_dir = manifest_path.parent / "adapters"
    for child in adapter_dir.iterdir():
        child.unlink()
    adapter_dir.rmdir()
    adapter_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="escapes the manifest directory"):
        load_manifest(manifest_path)


def test_parent_manifest_rejects_symlinked_adapter_file(tmp_path: Path):
    manifest_path = _write_manifest_fixture(tmp_path / "bundle")
    outside = tmp_path / "outside"
    outside.mkdir()
    source = DEFAULT_ADAPTER_MANIFEST_DIR / "elp.manifest.json"
    outside_file = outside / source.name
    outside_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    local_file = manifest_path.parent / "adapters" / source.name
    local_file.unlink()
    local_file.symlink_to(outside_file)

    with pytest.raises(ValueError, match="escapes the manifest directory"):
        load_manifest(manifest_path)


@pytest.mark.parametrize("child", ["../elp.manifest.json", "sub/../../elp.manifest.json"])
def test_parent_manifest_rejects_child_traversal(tmp_path: Path, child: str):
    manifest_path = _write_manifest_fixture(tmp_path / "bundle")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["adapters"]["files"]["elp"] = child
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="must not escape"):
        load_manifest(manifest_path)


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("sandbox", "read_paths", ["../outside"], "must not escape"),
        ("cache", "key_fields", ["repository"], "missing fields"),
        ("timeout", "max_seconds", 301, "must bound"),
        ("timeout", "default_seconds", float("nan"), "finite"),
        ("timeout", "max_seconds", float("inf"), "finite"),
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


def test_policy_validator_rejects_probe_timeout_above_hard_limit():
    source = DEFAULT_ADAPTER_MANIFEST_DIR / "elp.manifest.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    manifest["timeout"]["version_probe_seconds"] = 301

    with pytest.raises(ValueError, match="must not exceed max_seconds"):
        validate_adapter_manifest(manifest, "elp.manifest.json")


def test_loader_allows_contained_absolute_programmatic_paths(tmp_path: Path):
    adapter_dir = tmp_path / "adapters"
    adapter_dir.mkdir()
    paths = {}
    for name in ERLANG_ADAPTERS:
        source = DEFAULT_ADAPTER_MANIFEST_DIR / f"{name}.manifest.json"
        target = adapter_dir / source.name
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        paths[name] = target

    manifests = load_adapter_manifests(adapter_dir, paths=paths)
    assert set(manifests) == set(ERLANG_ADAPTERS)
