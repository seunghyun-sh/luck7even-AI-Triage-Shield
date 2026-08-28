"""Tests for the trusted target registry boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestration.target_registry import (
    TargetRegistryError,
    list_registered_targets,
    load_registered_target,
)


def _write_registry(tmp_path: Path, *, base_url: str, manifest: str) -> Path:
    registry = tmp_path / "target-registry.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "targets": [
                    {
                        "target_set_id": "local-lab-v1",
                        "manifest": manifest,
                        "allowed_base_url": base_url,
                    }
                ],
            }
        )
    )
    return registry


def test_default_registry_resolves_authorized_manifest() -> None:
    targets = list_registered_targets()

    assert [target.target_set_id for target in targets] == [
        "local-lab-v1",
        "lumi-market-1",
        "novastream-2",
    ]
    for target in targets:
        assert load_registered_target(target.target_set_id) == target.manifest


def test_registry_rejects_manifest_outside_config_directory(tmp_path: Path) -> None:
    registry = _write_registry(
        tmp_path,
        base_url="http://127.0.0.1:5000",
        manifest="../targets.json",
    )

    with pytest.raises(TargetRegistryError, match="unsafe"):
        list_registered_targets(registry)


def test_registry_revalidates_allowed_base_url(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "configs" / "targets.example.json"
    (tmp_path / "targets.json").write_text(source.read_text())
    registry = _write_registry(
        tmp_path,
        base_url="https://unregistered.example",
        manifest="targets.json",
    )

    with pytest.raises(TargetRegistryError, match="allowlist"):
        list_registered_targets(registry)
