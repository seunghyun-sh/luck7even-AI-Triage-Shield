"""Focused contract tests for dashboard input artifacts."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from analysis.models import GroundTruthSet, ProcessedRun
from dashboard.data_loader import (
    DataLoadError,
    findings_to_dataframe,
    load_ground_truth,
    load_processed_data,
)

ROOT = Path(__file__).resolve().parents[1]
PROCESSED_FIXTURE = ROOT / "configs" / "triaged-results.example.json"
GROUND_TRUTH_FIXTURE = ROOT / "configs" / "ground-truth.example.json"


def _processed_payload() -> dict[str, object]:
    return json.loads(PROCESSED_FIXTURE.read_text(encoding="utf-8"))


def test_contract_fixtures_load_and_preserve_findings() -> None:
    run = load_processed_data(PROCESSED_FIXTURE)
    ground_truth = load_ground_truth(GROUND_TRUTH_FIXTURE.read_bytes())

    assert len(run.findings) == 7
    assert len(ground_truth.cases) == 4
    assert list(findings_to_dataframe(run)["finding_id"]) == [
        "XSS-001",
        "XSS-002",
        "XSS-003",
        "SQLI-001",
        "SQLI-002",
        "SQLI-003",
        "SQLI-004",
    ]


def test_processed_run_rejects_duplicate_ids() -> None:
    payload = _processed_payload()
    findings = payload["findings"]
    assert isinstance(findings, list)
    duplicate = copy.deepcopy(findings[0])
    duplicate["case_id"] = "xss-new-case"
    findings.append(duplicate)

    with pytest.raises(ValidationError, match="finding_id values must be unique"):
        ProcessedRun.model_validate(payload)

    duplicate_case_payload = _processed_payload()
    duplicate_case_payload["findings"][1]["case_id"] = duplicate_case_payload[
        "findings"
    ][0]["case_id"]
    with pytest.raises(ValidationError, match="case_id values must be unique"):
        ProcessedRun.model_validate(duplicate_case_payload)


def test_ground_truth_rejects_duplicate_case_ids() -> None:
    payload = json.loads(GROUND_TRUTH_FIXTURE.read_text(encoding="utf-8"))
    cases = payload["cases"]
    assert isinstance(cases, list)
    cases.append(copy.deepcopy(cases[0]))

    with pytest.raises(
        ValidationError, match="ground-truth case_id values must be unique"
    ):
        GroundTruthSet.model_validate(payload)


def test_ai_status_invariants_reject_generated_data_or_labels() -> None:
    failed_payload = _processed_payload()
    failed_ai = failed_payload["findings"][6]["ai"]
    failed_ai["label"] = "SAFE"

    with pytest.raises(
        ValidationError, match="failed AI result must not include a label"
    ):
        ProcessedRun.model_validate(failed_payload)

    not_requested_payload = _processed_payload()
    not_requested_ai = not_requested_payload["findings"][4]["ai"]
    not_requested_ai["recommendation"] = "Do not generate this text."

    with pytest.raises(
        ValidationError, match="not-requested AI result must not include"
    ):
        ProcessedRun.model_validate(not_requested_payload)


def test_scan_rejects_unsafe_html_path() -> None:
    payload = _processed_payload()
    payload["findings"][0]["scan"]["response"]["html_path"] = "../outside.html"

    with pytest.raises(ValidationError, match="html_path must be a safe relative path"):
        ProcessedRun.model_validate(payload)


def test_cross_status_and_run_status_invariants() -> None:
    failed_scan_payload = _processed_payload()
    failed_scan_payload["findings"][5]["ai"]["needs_human_review"] = False
    with pytest.raises(ValidationError, match="failed scan requires NOT_REQUESTED"):
        ProcessedRun.model_validate(failed_scan_payload)

    rule_payload = _processed_payload()
    rule_payload["findings"][4]["scan"]["rule"]["label"] = "SUSPECTED"
    with pytest.raises(ValidationError, match="RULE_NOT_SUSPECTED requires"):
        ProcessedRun.model_validate(rule_payload)

    partial_without_usable = _processed_payload()
    partial_without_usable["findings"] = partial_without_usable["findings"][5:6]
    with pytest.raises(ValidationError, match="partial run requires failures"):
        ProcessedRun.model_validate(partial_without_usable)

    failed_with_completed_scan = _processed_payload()
    failed_with_completed_scan["status"] = "FAILED"
    with pytest.raises(ValidationError, match="failed run must not contain"):
        ProcessedRun.model_validate(failed_with_completed_scan)

    completed_without_finished_at = _processed_payload()
    completed_without_finished_at["findings"] = completed_without_finished_at["findings"][
        :5
    ]
    completed_without_finished_at["status"] = "COMPLETED"
    completed_without_finished_at["completed_at"] = None
    with pytest.raises(ValidationError, match="require completed_at"):
        ProcessedRun.model_validate(completed_without_finished_at)


def test_contract_rejects_coerced_confidence_and_numeric_timestamps() -> None:
    confidence_payload = _processed_payload()
    confidence_payload["findings"][0]["ai"]["confidence"] = "0.98"
    with pytest.raises(ValidationError):
        ProcessedRun.model_validate(confidence_payload)

    boolean_confidence_payload = _processed_payload()
    boolean_confidence_payload["findings"][0]["ai"]["confidence"] = True
    with pytest.raises(ValidationError):
        ProcessedRun.model_validate(boolean_confidence_payload)

    timestamp_payload = _processed_payload()
    timestamp_payload["findings"][0]["scanned_at"] = 1_788_000_000
    with pytest.raises(ValidationError, match="ISO 8601"):
        ProcessedRun.model_validate(timestamp_payload)


def test_loader_normalizes_closed_stream_value_errors() -> None:
    source = io.StringIO("{}")
    source.close()

    with pytest.raises(DataLoadError, match="Unable to read processed results data"):
        load_processed_data(source)
