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
    payload = json.loads(PROCESSED_FIXTURE.read_text(encoding="utf-8"))
    for finding in payload["findings"]:
        ai = finding["ai"]
        if ai["grounding_status"] == "GROUNDED" and ai["confidence"] is None:
            ai["confidence"] = 0.5
    return payload


def _legacy_processed_payload() -> dict[str, object]:
    payload = _processed_payload()
    payload["schema_version"] = "1.0"
    findings = payload["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, dict)
        ai = finding["ai"]
        assert isinstance(ai, dict)
        for field in ("role", "grounding_status", "claims", "references", "provenance"):
            ai.pop(field)
        if ai["status"] == "COMPLETED":
            ai.update(
                {
                    "status_reason": None,
                    "label": "INCONCLUSIVE",
                    "confidence": 0.5,
                    "needs_human_review": True,
                    "source_evidence": ai["source_evidence"]
                    or "스캔 근거를 검토했습니다.",
                    "impact": ai["impact"] or "영향을 수동으로 검토합니다.",
                    "recommendation": ai["recommendation"]
                    or "안전한 구현을 유지합니다.",
                    "manual_check": ai["manual_check"] or "브라우저에서 확인합니다.",
                    "report_paragraph": ai["report_paragraph"]
                    or "추가 검토가 필요합니다.",
                }
            )

    completed_ai = findings[0]["ai"]
    assert isinstance(completed_ai, dict)
    completed_ai.update(
        {
            "label": "VULNERABLE",
            "confidence": 0.98,
            "needs_human_review": False,
        }
    )
    insufficient_ai = findings[1]["ai"]
    assert isinstance(insufficient_ai, dict)
    insufficient_ai.update(
        {
            "status_reason": None,
            "label": "SAFE",
            "confidence": 0.96,
            "needs_human_review": False,
            "source_evidence": "응답에는 인코딩된 문자열만 존재합니다.",
            "impact": "현재 증거에서 실행 가능성이 확인되지 않았습니다.",
            "recommendation": "출력 인코딩을 유지합니다.",
            "manual_check": "브라우저 DOM을 확인합니다.",
            "report_paragraph": "추가 실행 가능성이 확인되지 않았습니다.",
        }
    )
    return payload


def test_contract_fixtures_load_and_preserve_findings() -> None:
    run = ProcessedRun.model_validate(_processed_payload())
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


def test_legacy_1_0_processed_run_remains_valid() -> None:
    run = ProcessedRun.model_validate(_legacy_processed_payload())

    assert run.schema_version == "1.0"
    assert run.findings[0].ai.role is None


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
    completed_without_finished_at["findings"] = completed_without_finished_at[
        "findings"
    ][:5]
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


def test_evidence_grounded_statuses_are_valid_in_schema_1_1_fixture() -> None:
    run = ProcessedRun.model_validate(_processed_payload())

    assert [finding.ai.grounding_status.value for finding in run.findings] == [
        "GROUNDED",
        "INSUFFICIENT",
        "GROUNDED",
        "GROUNDED",
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
    ]
    grounded = [
        finding.ai
        for finding in run.findings
        if finding.ai.grounding_status.value == "GROUNDED"
    ]
    assert {ai.label.value for ai in grounded} == {"VULNERABLE", "SAFE"}
    assert all(ai.confidence is not None for ai in grounded)
    assert all(
        claim.evidence_ids and not claim.reference_ids
        if claim.claim_type.value == "OBSERVATION"
        else claim.reference_ids and not claim.evidence_ids
        for ai in grounded
        for claim in ai.claims
    )
    assert {ai.provenance.prompt_version for ai in grounded if ai.provenance} == {
        "triage-report-v5"
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_evidence", "unverified draft evidence"),
        (
            "claims",
            [
                {
                    "claim_id": "C1",
                    "claim_type": "OBSERVATION",
                    "text": "unverified claim",
                    "evidence_ids": ["E1"],
                    "reference_ids": [],
                }
            ],
        ),
    ],
)
def test_insufficient_evidence_rejects_draft_content(field: str, value: object) -> None:
    payload = _processed_payload()
    payload["findings"][1]["ai"][field] = value

    with pytest.raises(ValidationError, match="insufficient evidence"):
        ProcessedRun.model_validate(payload)


def test_evidence_claims_reject_orphan_references_and_invalid_evidence_ids() -> None:
    orphan_reference_payload = _processed_payload()
    orphan_reference_payload["findings"][0]["ai"]["claims"][0]["reference_ids"] = [
        "R404"
    ]
    with pytest.raises(ValidationError, match="claim reference_ids must exist"):
        ProcessedRun.model_validate(orphan_reference_payload)

    invalid_evidence_payload = _processed_payload()
    invalid_evidence_payload["findings"][0]["ai"]["claims"][0]["evidence_ids"] = ["e0"]
    with pytest.raises(ValidationError, match="positive integer"):
        ProcessedRun.model_validate(invalid_evidence_payload)


def test_evidence_claim_and_reference_ids_must_be_unique() -> None:
    duplicate_claim_payload = _processed_payload()
    duplicate_claim_payload["findings"][0]["ai"]["claims"][1]["claim_id"] = "C1"
    with pytest.raises(ValidationError, match="claim_id values must be unique"):
        ProcessedRun.model_validate(duplicate_claim_payload)

    duplicate_reference_payload = _processed_payload()
    reference = copy.deepcopy(
        duplicate_reference_payload["findings"][0]["ai"]["references"][0]
    )
    duplicate_reference_payload["findings"][0]["ai"]["references"].append(reference)
    with pytest.raises(ValidationError, match="reference_id values must be unique"):
        ProcessedRun.model_validate(duplicate_reference_payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "canonical_url",
            "https://example.com/reference",
            "allowlisted OWASP or KISA",
        ),
        ("document_sha256", "A" * 64, "string_pattern_mismatch"),
    ],
)
def test_references_reject_invalid_domain_and_hash(
    field: str, value: str, message: str
) -> None:
    payload = _processed_payload()
    payload["findings"][0]["ai"]["references"][0][field] = value

    with pytest.raises(ValidationError, match=message):
        ProcessedRun.model_validate(payload)


def test_provenance_rejects_timezone_less_timestamp() -> None:
    payload = _processed_payload()
    payload["findings"][0]["ai"]["provenance"]["generated_at"] = "2026-08-27T09:30:11"

    with pytest.raises(ValidationError, match="generated_at must include a timezone"):
        ProcessedRun.model_validate(payload)


@pytest.mark.parametrize(
    "retrieval_mode",
    [
        "REVIEWED_PACK",
        "REVIEWED_PACK_PLUS_VERIFIED_CACHE",
        "REVIEWED_PACK_PLUS_LOCAL_SEARCH",
    ],
)
def test_provenance_accepts_complete_grounding_bundle(
    retrieval_mode: str,
) -> None:
    payload = _processed_payload()
    provenance = payload["findings"][0]["ai"]["provenance"]
    provenance.update(
        {
            "retrieval_mode": retrieval_mode,
            "grounding_bundle_digest": "a" * 64,
            "grounding_pack_version": "reviewed-pack-v1",
        }
    )

    run = ProcessedRun.model_validate(payload)

    assert run.findings[0].ai.provenance.retrieval_mode == retrieval_mode


@pytest.mark.parametrize(
    "field",
    [
        "retrieval_mode",
        "grounding_bundle_digest",
        "grounding_pack_version",
    ],
)
def test_provenance_rejects_partial_grounding_bundle(field: str) -> None:
    payload = _processed_payload()
    provenance = payload["findings"][0]["ai"]["provenance"]
    provenance.update(
        {
            "retrieval_mode": "REVIEWED_PACK",
            "grounding_bundle_digest": "a" * 64,
            "grounding_pack_version": "reviewed-pack-v1",
        }
    )
    provenance.pop(field)

    with pytest.raises(ValidationError, match="must be all present or all absent"):
        ProcessedRun.model_validate(payload)


def test_provenance_rejects_invalid_grounding_bundle_digest() -> None:
    payload = _processed_payload()
    provenance = payload["findings"][0]["ai"]["provenance"]
    provenance.update(
        {
            "retrieval_mode": "REVIEWED_PACK",
            "grounding_bundle_digest": "A" * 64,
            "grounding_pack_version": "reviewed-pack-v1",
        }
    )

    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        ProcessedRun.model_validate(payload)


def test_provenance_accepts_legacy_absence_of_grounding_bundle() -> None:
    payload = _processed_payload()
    provenance = payload["findings"][0]["ai"]["provenance"]
    for field in (
        "retrieval_mode",
        "grounding_bundle_digest",
        "grounding_pack_version",
    ):
        provenance.pop(field, None)

    run = ProcessedRun.model_validate(payload)

    assert run.findings[0].ai.provenance.retrieval_mode is None


def test_processed_run_rejects_schema_version_and_ai_role_mixing() -> None:
    legacy_with_role = _processed_payload()
    legacy_with_role["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match="1.0 findings must not include"):
        ProcessedRun.model_validate(legacy_with_role)

    evidence_without_role = _processed_payload()
    evidence_ai = evidence_without_role["findings"][0]["ai"]
    evidence_ai.update(
        {
            "role": None,
            "grounding_status": None,
            "claims": [],
            "references": [],
            "provenance": None,
            "label": "SAFE",
            "confidence": 0.9,
            "needs_human_review": False,
        }
    )
    with pytest.raises(ValidationError, match="1.1 findings require"):
        ProcessedRun.model_validate(evidence_without_role)


def test_loader_normalizes_closed_stream_value_errors() -> None:
    source = io.StringIO("{}")
    source.close()

    with pytest.raises(DataLoadError, match="Unable to read processed results data"):
        load_processed_data(source)
