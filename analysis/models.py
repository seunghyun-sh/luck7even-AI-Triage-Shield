"""Pydantic models for the canonical processed-results and ground-truth contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import PurePath, PureWindowsPath
from typing import Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError


class ContractModel(BaseModel):
    """Base model that rejects fields outside data-contracts-v1."""

    model_config = ConfigDict(extra="forbid")


class VulnType(str, Enum):
    XSS = "XSS"
    SQLI = "SQLI"


class RunStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ScanStatus(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RuleLabel(str, Enum):
    SUSPECTED = "SUSPECTED"
    SAFE = "SAFE"


class AiStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AiLabel(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    INCONCLUSIVE = "INCONCLUSIVE"


class AiRole(str, Enum):
    EVIDENCE_GROUNDED_REPORTING = "EVIDENCE_GROUNDED_REPORTING"


class GroundingStatus(str, Enum):
    GROUNDED = "GROUNDED"
    INSUFFICIENT = "INSUFFICIENT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AiClaimType(str, Enum):
    OBSERVATION = "OBSERVATION"
    IMPACT = "IMPACT"
    RECOMMENDATION = "RECOMMENDATION"
    MANUAL_CHECK = "MANUAL_CHECK"


class AiStatusReason(str, Enum):
    RULE_NOT_SUSPECTED = "RULE_NOT_SUSPECTED"
    SCAN_FAILED = "SCAN_FAILED"
    POLICY_EXCLUDED = "POLICY_EXCLUDED"


class GroundTruthLabel(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"


class ErrorDetail(ContractModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    retryable: StrictBool


class RequestPolicy(ContractModel):
    timeout_seconds: StrictInt = Field(gt=0)
    follow_redirects: StrictBool


class TargetInput(ContractModel):
    location: Literal["query", "form", "json"]
    parameters: dict[StrictStr, StrictStr | StrictInt | StrictFloat | StrictBool | None]
    attack_parameter: StrictStr = Field(min_length=1)

    @model_validator(mode="after")
    def validate_attack_parameter(self) -> Self:
        if self.attack_parameter not in self.parameters:
            raise ValueError("attack_parameter must exist in parameters")
        return self


class TargetCase(ContractModel):
    case_id: StrictStr = Field(min_length=1)
    vuln_type: VulnType
    path: StrictStr = Field(min_length=1)
    method: Literal["GET", "POST"]
    input: TargetInput
    requires_pre_auth: StrictBool
    auth_profile: StrictStr | None
    payload_profile: StrictStr = Field(min_length=1)
    manual_verification_profile: StrictStr = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        decoded = unquote(value)
        path = PurePath(decoded)
        windows_path = PureWindowsPath(decoded)
        if (
            not value.startswith("/")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "\\" in value
            or ".." in path.parts
            or ".." in windows_path.parts
        ):
            raise ValueError("path must be a safe relative path rooted at /")
        return value

    @model_validator(mode="after")
    def validate_auth_profile(self) -> Self:
        if self.requires_pre_auth and not self.auth_profile:
            raise ValueError("pre-auth target requires an auth_profile")
        if not self.requires_pre_auth and self.auth_profile is not None:
            raise ValueError("target without pre-auth must not include an auth_profile")
        return self


class TargetManifest(ContractModel):
    schema_version: Literal["1.0"]
    target_set_id: StrictStr = Field(min_length=1)
    base_url: StrictStr = Field(min_length=1)
    request_policy: RequestPolicy
    targets: list[TargetCase] = Field(min_length=1)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("base_url must have a valid port") from error
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or port is not None
            and not 0 <= port <= 65535
        ):
            raise ValueError(
                "base_url must be an http or https origin without userinfo"
            )
        return value

    @model_validator(mode="after")
    def validate_case_ids(self) -> Self:
        case_ids = [target.case_id for target in self.targets]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case_id values must be unique within a target manifest")
        return self


class ScanRequest(ContractModel):
    url: str = Field(min_length=1)
    method: str = Field(min_length=1)
    input_location: str = Field(min_length=1)
    parameter: str = Field(min_length=1)
    payload: str = Field(min_length=1)


class ScanResponse(ContractModel):
    http_status: StrictInt | None
    elapsed_ms: StrictInt | None
    baseline_elapsed_ms: StrictInt | None
    evidence_summary: str | None
    html_path: str | None

    @field_validator("http_status")
    @classmethod
    def validate_http_status(cls, value: int | None) -> int | None:
        if value is not None and not 100 <= value <= 599:
            raise ValueError("http_status must be between 100 and 599")
        return value

    @field_validator("elapsed_ms", "baseline_elapsed_ms")
    @classmethod
    def validate_elapsed_ms(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("elapsed_ms values must be non-negative")
        return value

    @field_validator("html_path")
    @classmethod
    def validate_html_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = PurePath(value)
        windows_path = PureWindowsPath(value)
        if (
            not value
            or path.is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or ".." in path.parts
            or ".." in windows_path.parts
        ):
            raise ValueError(
                "html_path must be a safe relative path within the run directory"
            )
        return value


class ScanRule(ContractModel):
    label: RuleLabel | None
    reason: str | None


class ScanResult(ContractModel):
    status: ScanStatus
    request: ScanRequest
    response: ScanResponse
    rule: ScanRule
    error: ErrorDetail | None

    @model_validator(mode="after")
    def validate_status_fields(self) -> Self:
        if self.status is ScanStatus.COMPLETED:
            if self.error is not None:
                raise ValueError("completed scan must not include an error")
            if (
                self.response.http_status is None
                or self.response.elapsed_ms is None
                or self.response.evidence_summary is None
            ):
                raise ValueError(
                    "completed scan requires http_status, elapsed_ms, and evidence_summary"
                )
            if self.rule.label is None or self.rule.reason is None:
                raise ValueError("completed scan requires a rule label and reason")
        else:
            if self.error is None:
                raise ValueError("failed scan requires an error")
            if self.rule.label is not None or self.rule.reason is not None:
                raise ValueError("failed scan must not include a rule label or reason")
            if any(
                value is not None
                for value in (
                    self.response.http_status,
                    self.response.elapsed_ms,
                    self.response.baseline_elapsed_ms,
                    self.response.evidence_summary,
                    self.response.html_path,
                )
            ):
                raise ValueError("failed scan response fields must all be null")
        return self


class AiClaim(ContractModel):
    claim_id: str = Field(min_length=1)
    claim_type: AiClaimType
    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    reference_ids: list[str] = Field(default_factory=list)


class AiReference(ContractModel):
    reference_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    publisher: str = Field(min_length=1)
    title: str = Field(min_length=1)
    version: str = Field(min_length=1)
    section: str = Field(min_length=1)
    canonical_url: str = Field(min_length=1)
    file_id: str = Field(min_length=1)
    document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("canonical_url")
    @classmethod
    def validate_canonical_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not (
                hostname in {"owasp.org", "kisa.or.kr"}
                or hostname.endswith((".owasp.org", ".kisa.or.kr"))
            )
        ):
            raise ValueError(
                "canonical_url must be an allowlisted OWASP or KISA https URL without credentials, query, or fragment"
            )
        return value


class AiProvenance(ContractModel):
    model: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    knowledge_base_version: str = Field(min_length=1)
    output_schema_version: Literal["1.1"]
    retrieval_policy_version: str = Field(min_length=1)
    vector_store_ids: list[str] = Field(default_factory=list)
    retrieved_file_ids: list[str] = Field(default_factory=list)
    generated_at: datetime

    @field_validator("vector_store_ids", "retrieved_file_ids")
    @classmethod
    def validate_unique_ids(cls, value: list[str]) -> list[str]:
        if any(not identifier for identifier in value) or len(value) != len(set(value)):
            raise ValueError("provenance identifiers must be nonblank and unique")
        return value

    @field_validator("generated_at", mode="before")
    @classmethod
    def reject_numeric_generated_at(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "generated_at must be an ISO 8601 timestamp string"
            )
        return value

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must include a timezone offset")
        return value


class AiResult(ContractModel):
    status: AiStatus
    status_reason: AiStatusReason | None
    label: AiLabel | None
    confidence: float | None
    needs_human_review: StrictBool
    assessment_summary: str | None
    source_evidence: str | None
    impact: str | None
    recommendation: str | None
    manual_check: str | None
    report_paragraph: str | None
    error: ErrorDetail | None
    role: AiRole | None = None
    grounding_status: GroundingStatus | None = None
    claims: list[AiClaim] = Field(default_factory=list)
    references: list[AiReference] = Field(default_factory=list)
    provenance: AiProvenance | None = None

    @field_validator("confidence", mode="before")
    @classmethod
    def reject_non_numeric_confidence(cls, value: object) -> object:
        if isinstance(value, (str, bool)):
            raise PydanticCustomError("numeric_type", "confidence must be numeric")
        return value

    @model_validator(mode="after")
    def validate_status_fields(self) -> Self:
        generated_fields = (
            self.assessment_summary,
            self.source_evidence,
            self.impact,
            self.recommendation,
            self.manual_check,
            self.report_paragraph,
        )
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("claim_id values must be unique within an AI result")
        reference_ids = [reference.reference_id for reference in self.references]
        if len(reference_ids) != len(set(reference_ids)):
            raise ValueError("reference_id values must be unique within an AI result")

        if self.role is AiRole.EVIDENCE_GROUNDED_REPORTING:
            return self.validate_evidence_grounded_fields(generated_fields)

        if self.status is AiStatus.COMPLETED:
            if self.status_reason is not None or self.error is not None:
                raise ValueError(
                    "completed AI result must not include status_reason or error"
                )
            if self.label is None or self.confidence is None:
                raise ValueError("completed AI result requires label and confidence")
            if any(value is None or not value.strip() for value in generated_fields):
                raise ValueError(
                    "completed AI result requires all generated text fields"
                )
            if self.label is AiLabel.INCONCLUSIVE and not self.needs_human_review:
                raise ValueError("inconclusive AI result requires human review")
        elif self.status is AiStatus.NOT_REQUESTED:
            if self.status_reason is None:
                raise ValueError("not-requested AI result requires status_reason")
            if (
                self.label is not None
                or self.confidence is not None
                or any(value is not None for value in generated_fields)
            ):
                raise ValueError(
                    "not-requested AI result must not include a label, confidence, or generated text"
                )
            if self.error is not None:
                raise ValueError("not-requested AI result must not include an error")
        else:
            if self.status_reason is not None:
                raise ValueError("failed AI result must not include status_reason")
            if (
                self.label is not None
                or self.confidence is not None
                or any(value is not None for value in generated_fields)
            ):
                raise ValueError(
                    "failed AI result must not include a label, confidence, or generated text"
                )
            if not self.needs_human_review:
                raise ValueError("failed AI result requires human review")
            if self.error is None:
                raise ValueError("failed AI result requires an error")
        return self

    def validate_evidence_grounded_fields(
        self, generated_fields: tuple[str | None, ...]
    ) -> Self:
        reference_ids = [reference.reference_id for reference in self.references]

        if self.status is AiStatus.COMPLETED:
            if self.grounding_status is GroundingStatus.GROUNDED:
                if (
                    self.label is not AiLabel.INCONCLUSIVE
                    or self.confidence is not None
                    or not self.needs_human_review
                    or self.status_reason is not None
                    or self.error is not None
                ):
                    raise ValueError(
                        "grounded evidence AI result requires inconclusive label, null confidence, human review, and no status_reason or error"
                    )
                if any(
                    value is None or not value.strip() for value in generated_fields
                ):
                    raise ValueError(
                        "grounded evidence AI result requires all generated text fields"
                    )
                if not self.claims or not self.references:
                    raise ValueError(
                        "grounded evidence AI result requires claims and references"
                    )
                claim_types = {claim.claim_type for claim in self.claims}
                required_types = set(AiClaimType)
                if not required_types.issubset(claim_types):
                    raise ValueError(
                        "grounded evidence AI result requires every claim type"
                    )
                if any(
                    not evidence_id.startswith("E")
                    or not evidence_id[1:].isdigit()
                    or int(evidence_id[1:]) <= 0
                    for claim in self.claims
                    for evidence_id in claim.evidence_ids
                ):
                    raise ValueError(
                        "claim evidence_ids must be E followed by a positive integer"
                    )
                if any(
                    len(claim.evidence_ids) != len(set(claim.evidence_ids))
                    or len(claim.reference_ids) != len(set(claim.reference_ids))
                    for claim in self.claims
                ):
                    raise ValueError(
                        "claim evidence_ids and reference_ids must be unique"
                    )
                if any(
                    not claim.evidence_ids
                    for claim in self.claims
                    if claim.claim_type is AiClaimType.OBSERVATION
                ):
                    raise ValueError("observation claims require local evidence IDs")
                if any(
                    not claim.reference_ids
                    for claim in self.claims
                    if claim.claim_type is not AiClaimType.OBSERVATION
                ):
                    raise ValueError(
                        "impact, recommendation, and manual-check claims require references"
                    )
                reference_id_set = set(reference_ids)
                if any(
                    reference_id not in reference_id_set
                    for claim in self.claims
                    for reference_id in claim.reference_ids
                ):
                    raise ValueError("claim reference_ids must exist in references")
                if self.provenance is None:
                    raise ValueError("evidence AI result requires provenance")
                if (
                    not self.provenance.vector_store_ids
                    or not self.provenance.retrieved_file_ids
                    or any(
                        reference.file_id not in set(self.provenance.retrieved_file_ids)
                        for reference in self.references
                    )
                ):
                    raise ValueError(
                        "grounded references must come from retrieved provenance files"
                    )
            elif self.grounding_status is GroundingStatus.INSUFFICIENT:
                if (
                    self.label is not AiLabel.INCONCLUSIVE
                    or self.confidence is not None
                    or not self.needs_human_review
                    or self.status_reason is not AiStatusReason.POLICY_EXCLUDED
                    or self.error is not None
                    or self.assessment_summary is None
                    or not self.assessment_summary.strip()
                    or any(
                        value is not None
                        for value in (
                            self.source_evidence,
                            self.impact,
                            self.recommendation,
                            self.manual_check,
                            self.report_paragraph,
                        )
                    )
                    or self.claims
                    or self.references
                    or self.provenance is None
                ):
                    raise ValueError(
                        "insufficient evidence AI result violates its contract"
                    )
            else:
                raise ValueError(
                    "completed evidence AI result requires GROUNDED or INSUFFICIENT grounding_status"
                )
        elif self.status is AiStatus.NOT_REQUESTED:
            if self.grounding_status is not GroundingStatus.NOT_APPLICABLE:
                raise ValueError(
                    "not-requested evidence AI result requires NOT_APPLICABLE grounding_status"
                )
            if self.claims or self.references or self.provenance is not None:
                raise ValueError(
                    "not-requested evidence AI result must not include claims, references, or provenance"
                )
            self.validate_legacy_status_fields(generated_fields)
        else:
            if self.grounding_status is not GroundingStatus.NOT_APPLICABLE:
                raise ValueError(
                    "failed evidence AI result requires NOT_APPLICABLE grounding_status"
                )
            if self.claims or self.references:
                raise ValueError(
                    "failed evidence AI result must not include claims or references"
                )
            self.validate_legacy_status_fields(generated_fields)
        return self

    def validate_legacy_status_fields(
        self, generated_fields: tuple[str | None, ...]
    ) -> None:
        if self.status is AiStatus.NOT_REQUESTED:
            if self.status_reason is None:
                raise ValueError("not-requested AI result requires status_reason")
            if (
                self.label is not None
                or self.confidence is not None
                or any(value is not None for value in generated_fields)
            ):
                raise ValueError(
                    "not-requested AI result must not include a label, confidence, or generated text"
                )
            if self.error is not None:
                raise ValueError("not-requested AI result must not include an error")
        else:
            if self.status_reason is not None:
                raise ValueError("failed AI result must not include status_reason")
            if (
                self.label is not None
                or self.confidence is not None
                or any(value is not None for value in generated_fields)
            ):
                raise ValueError(
                    "failed AI result must not include a label, confidence, or generated text"
                )
            if not self.needs_human_review:
                raise ValueError("failed AI result requires human review")
            if self.error is None:
                raise ValueError("failed AI result requires an error")


class ProcessedFinding(ContractModel):
    case_id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    scanned_at: datetime
    vuln_type: VulnType
    scan: ScanResult
    ai: AiResult

    @field_validator("scanned_at", mode="before")
    @classmethod
    def reject_numeric_scanned_at(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "scanned_at must be an ISO 8601 timestamp string"
            )
        return value

    @field_validator("scanned_at")
    @classmethod
    def validate_scanned_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scanned_at must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_cross_status_fields(self) -> Self:
        if (
            self.scan.status is ScanStatus.COMPLETED
            and self.vuln_type is VulnType.SQLI
            and self.scan.response.baseline_elapsed_ms is None
        ):
            raise ValueError("completed SQLI scan requires baseline_elapsed_ms")
        if self.scan.status is ScanStatus.FAILED and (
            self.ai.status is not AiStatus.NOT_REQUESTED
            or self.ai.status_reason is not AiStatusReason.SCAN_FAILED
            or not self.ai.needs_human_review
        ):
            raise ValueError(
                "failed scan requires NOT_REQUESTED AI with SCAN_FAILED and human review"
            )
        if (
            self.ai.status is AiStatus.NOT_REQUESTED
            and self.ai.status_reason is AiStatusReason.SCAN_FAILED
            and self.scan.status is not ScanStatus.FAILED
        ):
            raise ValueError("SCAN_FAILED AI status_reason requires a failed scan")
        if (
            self.ai.status is AiStatus.NOT_REQUESTED
            and self.ai.status_reason is AiStatusReason.RULE_NOT_SUSPECTED
            and (
                self.scan.status is not ScanStatus.COMPLETED
                or self.scan.rule.label is not RuleLabel.SAFE
            )
        ):
            raise ValueError(
                "RULE_NOT_SUSPECTED requires a completed scan with a SAFE rule"
            )
        return self


class ProcessedRun(ContractModel):
    schema_version: Literal["1.0", "1.1"]
    scan_run_id: str = Field(min_length=1)
    target_set_id: str = Field(min_length=1)
    started_at: datetime
    completed_at: datetime | None
    status: RunStatus
    findings: list[ProcessedFinding]

    @field_validator("started_at", "completed_at", mode="before")
    @classmethod
    def reject_numeric_timestamps(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "timestamps must be ISO 8601 timestamp strings"
            )
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamps must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_run(self) -> Self:
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique within a scan run")
        case_ids = [finding.case_id for finding in self.findings]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case_id values must be unique within a scan run")
        if self.schema_version == "1.0" and any(
            finding.ai.role is not None for finding in self.findings
        ):
            raise ValueError("1.0 findings must not include an AI role")
        if self.schema_version == "1.1" and any(
            finding.ai.role is not AiRole.EVIDENCE_GROUNDED_REPORTING
            for finding in self.findings
        ):
            raise ValueError("1.1 findings require EVIDENCE_GROUNDED_REPORTING AI role")

        has_failure = any(
            finding.scan.status is ScanStatus.FAILED
            or finding.ai.status is AiStatus.FAILED
            for finding in self.findings
        )
        has_usable_completed_scan = any(
            finding.scan.status is ScanStatus.COMPLETED for finding in self.findings
        )
        if (
            self.status in {RunStatus.COMPLETED, RunStatus.PARTIAL}
            and self.completed_at is None
        ):
            raise ValueError("completed and partial runs require completed_at")
        if self.status is RunStatus.COMPLETED:
            if has_failure:
                raise ValueError("completed run must not contain scan or AI failures")
        elif self.status is RunStatus.PARTIAL:
            if not has_failure or not has_usable_completed_scan:
                raise ValueError(
                    "partial run requires failures and a usable completed scan"
                )
        elif has_usable_completed_scan:
            raise ValueError("failed run must not contain a usable completed scan")
        return self


class RawFinding(ContractModel):
    case_id: StrictStr = Field(min_length=1)
    finding_id: StrictStr = Field(min_length=1)
    scanned_at: datetime
    vuln_type: VulnType
    scan: ScanResult

    @field_validator("scanned_at", mode="before")
    @classmethod
    def reject_numeric_scanned_at(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "scanned_at must be an ISO 8601 timestamp string"
            )
        return value

    @field_validator("scanned_at")
    @classmethod
    def validate_scanned_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scanned_at must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_sqli_baseline(self) -> Self:
        if (
            self.scan.status is ScanStatus.COMPLETED
            and self.vuln_type is VulnType.SQLI
            and self.scan.response.baseline_elapsed_ms is None
        ):
            raise ValueError("completed SQLI scan requires baseline_elapsed_ms")
        return self


class RawRun(ContractModel):
    schema_version: Literal["1.0"]
    scan_run_id: StrictStr = Field(min_length=1)
    target_set_id: StrictStr = Field(min_length=1)
    started_at: datetime
    completed_at: datetime | None
    status: RunStatus
    findings: list[RawFinding]

    @field_validator("started_at", "completed_at", mode="before")
    @classmethod
    def reject_numeric_timestamps(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "timestamps must be ISO 8601 timestamp strings"
            )
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamps must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_run(self) -> Self:
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique within a scan run")
        case_ids = [finding.case_id for finding in self.findings]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case_id values must be unique within a scan run")

        has_failed_scan = any(
            finding.scan.status is ScanStatus.FAILED for finding in self.findings
        )
        has_usable_completed_scan = any(
            finding.scan.status is ScanStatus.COMPLETED for finding in self.findings
        )
        if (
            self.status in {RunStatus.COMPLETED, RunStatus.PARTIAL}
            and self.completed_at is None
        ):
            raise ValueError("completed and partial runs require completed_at")
        if self.status is RunStatus.COMPLETED:
            if has_failed_scan:
                raise ValueError("completed run must not contain scan failures")
        elif self.status is RunStatus.PARTIAL:
            if not has_failed_scan or not has_usable_completed_scan:
                raise ValueError(
                    "partial run requires scan failures and a usable completed scan"
                )
        elif has_usable_completed_scan:
            raise ValueError("failed run must not contain a usable completed scan")
        return self


class GroundTruthCase(ContractModel):
    case_id: str = Field(min_length=1)
    vuln_type: VulnType
    label: GroundTruthLabel
    evidence_summary: str = Field(min_length=1)
    assessed_at: datetime

    @field_validator("assessed_at", mode="before")
    @classmethod
    def reject_numeric_assessed_at(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "assessed_at must be an ISO 8601 timestamp string"
            )
        return value

    @field_validator("assessed_at")
    @classmethod
    def validate_assessed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("assessed_at must include a timezone offset")
        return value


class GroundTruthSet(ContractModel):
    schema_version: Literal["1.0"]
    assessment_set_id: str = Field(min_length=1)
    target_set_id: str = Field(min_length=1)
    assessor_tool: str = Field(min_length=1)
    created_at: datetime
    cases: list[GroundTruthCase]

    @field_validator("created_at", mode="before")
    @classmethod
    def reject_numeric_created_at(cls, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            raise PydanticCustomError(
                "datetime_type", "created_at must be an ISO 8601 timestamp string"
            )
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_case_ids(self) -> Self:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError(
                "ground-truth case_id values must be unique within a target_set_id"
            )
        return self
