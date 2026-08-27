"""Focused validation tests for scanner input and raw-result contracts."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from orchestration.data_loader import (
    ContractLoadError,
    load_raw_data,
    load_target_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
TARGETS_FIXTURE = ROOT / "configs" / "targets.example.json"
RAW_FIXTURE = ROOT / "configs" / "raw-findings.example.json"


def _targets_payload() -> dict[str, object]:
    return json.loads(TARGETS_FIXTURE.read_text(encoding="utf-8"))


def _raw_payload() -> dict[str, object]:
    return json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))


def test_canonical_fixtures_load_and_preserve_all_cases() -> None:
    manifest = load_target_manifest(TARGETS_FIXTURE)
    raw_payload = _raw_payload()
    run = load_raw_data(json.dumps(raw_payload).encode())

    assert len(manifest.targets) == 7
    assert len(run.findings) == 7
    assert run.model_dump(mode="json")["findings"] == raw_payload["findings"]


@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://127.0.0.1:5000",
        "http://user:password@127.0.0.1:5000",
        "http://127.0.0.1:5000/?next=/case",
        "http://127.0.0.1:5000/#fragment",
    ],
)
def test_target_manifest_rejects_unsafe_base_url(base_url: str) -> None:
    payload = _targets_payload()
    payload["base_url"] = base_url

    with pytest.raises(ContractLoadError, match="base_url"):
        load_target_manifest(json.dumps(payload).encode())


@pytest.mark.parametrize("path", ["http://outside.example/case", "/case/../admin"])
def test_target_manifest_rejects_unsafe_target_path(path: str) -> None:
    payload = _targets_payload()
    payload["targets"][0]["path"] = path

    with pytest.raises(ContractLoadError, match="path"):
        load_target_manifest(json.dumps(payload).encode())


def test_target_manifest_enforces_auth_and_attack_parameter() -> None:
    auth_payload = _targets_payload()
    auth_payload["targets"][0]["auth_profile"] = "lab-user"

    with pytest.raises(ContractLoadError, match="without pre-auth"):
        load_target_manifest(json.dumps(auth_payload).encode())

    missing_auth_payload = _targets_payload()
    missing_auth_payload["targets"][0]["requires_pre_auth"] = True

    with pytest.raises(ContractLoadError, match="requires an auth_profile"):
        load_target_manifest(json.dumps(missing_auth_payload).encode())

    parameter_payload = _targets_payload()
    parameter_payload["targets"][0]["input"]["attack_parameter"] = "missing"

    with pytest.raises(ContractLoadError, match="attack_parameter"):
        load_target_manifest(json.dumps(parameter_payload).encode())


def test_target_manifest_rejects_duplicate_case_ids() -> None:
    payload = _targets_payload()
    payload["targets"][1]["case_id"] = payload["targets"][0]["case_id"]

    with pytest.raises(ContractLoadError, match="case_id values must be unique"):
        load_target_manifest(json.dumps(payload).encode())


def test_raw_run_rejects_duplicate_ids_and_invalid_status() -> None:
    duplicate_id_payload = _raw_payload()
    duplicate_id_payload["findings"][1]["finding_id"] = duplicate_id_payload[
        "findings"
    ][0]["finding_id"]

    with pytest.raises(ContractLoadError, match="finding_id values must be unique"):
        load_raw_data(json.dumps(duplicate_id_payload).encode())

    status_payload = _raw_payload()
    status_payload["status"] = "COMPLETED"

    with pytest.raises(ContractLoadError, match="completed run must not contain scan failures"):
        load_raw_data(json.dumps(status_payload).encode())


def test_raw_run_requires_sqli_baseline_and_aware_timestamps() -> None:
    baseline_payload = _raw_payload()
    baseline_payload["findings"][3]["scan"]["response"]["baseline_elapsed_ms"] = None

    with pytest.raises(ContractLoadError, match="completed SQLI scan requires"):
        load_raw_data(json.dumps(baseline_payload).encode())

    timestamp_payload = _raw_payload()
    timestamp_payload["started_at"] = "2026-08-27T09:30:00"

    with pytest.raises(ContractLoadError, match="timezone offset"):
        load_raw_data(json.dumps(timestamp_payload).encode())


def test_raw_finding_enforces_failed_scan_invariants() -> None:
    payload = _raw_payload()
    failed_scan = payload["findings"][5]["scan"]
    failed_scan["error"] = None

    with pytest.raises(ContractLoadError, match="failed scan requires an error"):
        load_raw_data(json.dumps(payload).encode())


def test_loaders_normalize_closed_stream_errors() -> None:
    target_source = io.StringIO("{}")
    target_source.close()
    raw_source = io.BytesIO(b"{}")
    raw_source.close()

    with pytest.raises(ContractLoadError, match="Unable to read target manifest"):
        load_target_manifest(target_source)
    with pytest.raises(ContractLoadError, match="Unable to read raw findings data"):
        load_raw_data(raw_source)
