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
            or port is not None and not 0 <= port <= 65535
        ):
            raise ValueError("base_url must be an http or https origin without userinfo")
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
    schema_version: Literal["1.0"]
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

# RAG 기반 AI 분석용 스키마
from typing import Literal, List
from pydantic import Field

class AIClaim(BaseModel):
    claim_type: Literal["OBSERVATION", "IMPACT", "RECOMMENDATION", "MANUAL_CHECK"]
    text: str
    evidence_keys: List[str] = Field(default_factory=list)
    retrieved_result_ids: List[str] = Field(default_factory=list)

class AIAnalysisResult(BaseModel):
    claims: List[AIClaim]