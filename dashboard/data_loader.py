"""Validated readers and DataFrame adapter for dashboard contract data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import BinaryIO, TextIO, TypeAlias

import pandas as pd
from pydantic import ValidationError

from analysis.models import ErrorDetail, GroundTruthSet, ProcessedRun

DataSource: TypeAlias = Path | bytes | BinaryIO | TextIO


class DataLoadError(ValueError):
    """A safe, screen-displayable contract-data loading error."""


def _read_source(source: DataSource, artifact_name: str) -> bytes | str:
    try:
        if isinstance(source, Path):
            return source.read_bytes()
        if isinstance(source, bytes):
            return source
        content = source.read()
    except (OSError, UnicodeError, AttributeError, ValueError):
        raise DataLoadError(f"Unable to read {artifact_name}.") from None

    if not isinstance(content, (bytes, str)):
        raise DataLoadError(f"Unable to read {artifact_name}.")
    return content


def _validation_message(artifact_name: str, error: ValidationError) -> str:
    first_error = error.errors(include_input=False)[0]
    location = ".".join(str(part) for part in first_error["loc"])
    detail = first_error["msg"]
    if location:
        return f"Invalid {artifact_name}: {location}: {detail}"
    return f"Invalid {artifact_name}: {detail}"


def load_processed_data(source: DataSource) -> ProcessedRun:
    """Load and validate a processed-results JSON artifact without exposing its path."""

    content = _read_source(source, "processed results data")
    try:
        return ProcessedRun.model_validate_json(content)
    except ValidationError as error:
        raise DataLoadError(
            _validation_message("processed results data", error)
        ) from None


def load_ground_truth(source: DataSource) -> GroundTruthSet:
    """Load and validate a ground-truth JSON artifact without exposing its path."""

    content = _read_source(source, "ground-truth data")
    try:
        return GroundTruthSet.model_validate_json(content)
    except ValidationError as error:
        raise DataLoadError(_validation_message("ground-truth data", error)) from None


def _display_error(error: ErrorDetail | None) -> str | None:
    if error is None:
        return None
    return f"{error.code}: {error.message}"


def findings_to_dataframe(run: ProcessedRun) -> pd.DataFrame:
    """Flatten validated findings into the dashboard's non-canonical UI representation."""

    def json_value(value: object) -> str:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )

    rows = [
        {
            "schema_version": run.schema_version,
            "scan_run_id": run.scan_run_id,
            "target_set_id": run.target_set_id,
            "case_id": finding.case_id,
            "finding_id": finding.finding_id,
            "scanned_at": finding.scanned_at,
            "vuln_type": finding.vuln_type.value,
            "url": finding.scan.request.url,
            "method": finding.scan.request.method,
            "input_location": finding.scan.request.input_location,
            "parameter": finding.scan.request.parameter,
            "payload": finding.scan.request.payload,
            "scan_status": finding.scan.status.value,
            "http_status": finding.scan.response.http_status,
            "elapsed_ms": finding.scan.response.elapsed_ms,
            "baseline_elapsed_ms": finding.scan.response.baseline_elapsed_ms,
            "rule_label": finding.scan.rule.label.value
            if finding.scan.rule.label
            else None,
            "rule_reason": finding.scan.rule.reason,
            "scan_evidence": finding.scan.response.evidence_summary,
            "scan_error": _display_error(finding.scan.error),
            "ai_status": finding.ai.status.value,
            "ai_status_reason": finding.ai.status_reason.value
            if finding.ai.status_reason
            else None,
            "ai_label": finding.ai.label.value if finding.ai.label else None,
            "confidence": finding.ai.confidence,
            "needs_human_review": finding.ai.needs_human_review,
            "assessment_summary": finding.ai.assessment_summary,
            "source_evidence": finding.ai.source_evidence,
            "impact": finding.ai.impact,
            "recommendation": finding.ai.recommendation,
            "manual_check": finding.ai.manual_check,
            "report_paragraph": finding.ai.report_paragraph,
            "ai_error": _display_error(finding.ai.error),
            "ai_role": finding.ai.role.value if finding.ai.role else None,
            "grounding_status": (
                finding.ai.grounding_status.value
                if finding.ai.grounding_status
                else None
            ),
            "claim_count": len(finding.ai.claims),
            "reference_count": len(finding.ai.references),
            "claims_json": json_value(
                [claim.model_dump(mode="json") for claim in finding.ai.claims]
            ),
            "references_json": json_value(
                [
                    reference.model_dump(mode="json")
                    for reference in finding.ai.references
                ]
            ),
            "provenance_model": (
                finding.ai.provenance.model if finding.ai.provenance else None
            ),
            "provenance_prompt_version": (
                finding.ai.provenance.prompt_version if finding.ai.provenance else None
            ),
            "provenance_knowledge_base_version": (
                finding.ai.provenance.knowledge_base_version
                if finding.ai.provenance
                else None
            ),
            "provenance_output_schema_version": (
                finding.ai.provenance.output_schema_version
                if finding.ai.provenance
                else None
            ),
            "provenance_retrieval_policy_version": (
                finding.ai.provenance.retrieval_policy_version
                if finding.ai.provenance
                else None
            ),
            "provenance_retrieval_mode": (
                finding.ai.provenance.retrieval_mode if finding.ai.provenance else None
            ),
            "provenance_grounding_pack_version": (
                finding.ai.provenance.grounding_pack_version
                if finding.ai.provenance
                else None
            ),
            "provenance_grounding_bundle_digest": (
                finding.ai.provenance.grounding_bundle_digest
                if finding.ai.provenance
                else None
            ),
            "provenance_generated_at": (
                finding.ai.provenance.generated_at.isoformat()
                if finding.ai.provenance
                else None
            ),
            "provenance_vector_store_ids_json": json_value(
                finding.ai.provenance.vector_store_ids if finding.ai.provenance else []
            ),
            "provenance_retrieved_file_ids_json": json_value(
                finding.ai.provenance.retrieved_file_ids
                if finding.ai.provenance
                else []
            ),
        }
        for finding in run.findings
    ]
    columns = [
        "schema_version",
        "scan_run_id",
        "target_set_id",
        "case_id",
        "finding_id",
        "scanned_at",
        "vuln_type",
        "url",
        "method",
        "input_location",
        "parameter",
        "payload",
        "scan_status",
        "http_status",
        "elapsed_ms",
        "baseline_elapsed_ms",
        "rule_label",
        "rule_reason",
        "scan_evidence",
        "scan_error",
        "ai_status",
        "ai_status_reason",
        "ai_label",
        "confidence",
        "needs_human_review",
        "assessment_summary",
        "source_evidence",
        "impact",
        "recommendation",
        "manual_check",
        "report_paragraph",
        "ai_error",
        "ai_role",
        "grounding_status",
        "claim_count",
        "reference_count",
        "claims_json",
        "references_json",
        "provenance_model",
        "provenance_prompt_version",
        "provenance_knowledge_base_version",
        "provenance_output_schema_version",
        "provenance_retrieval_policy_version",
        "provenance_retrieval_mode",
        "provenance_grounding_pack_version",
        "provenance_grounding_bundle_digest",
        "provenance_generated_at",
        "provenance_vector_store_ids_json",
        "provenance_retrieved_file_ids_json",
    ]
    return pd.DataFrame(rows, columns=columns)
