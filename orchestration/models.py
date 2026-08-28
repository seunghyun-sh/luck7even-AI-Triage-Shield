"""Pydantic models for the execution contract."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

SCHEMA_VERSION = "1.0"
RUN_ID_PATTERN = re.compile(r"run-\d{8}-\d{6}-[0-9a-f]{6}\Z")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class ExecutionStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ExecutionStage(str, Enum):
    VALIDATING_TARGET = "VALIDATING_TARGET"
    SCANNING_XSS = "SCANNING_XSS"
    SCANNING_SQLI = "SCANNING_SQLI"
    PUBLISHING_RAW = "PUBLISHING_RAW"
    AI_TRIAGE = "AI_TRIAGE"
    PUBLISHING_RESULT = "PUBLISHING_RESULT"


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


def _validate_run_id(value: str) -> str:
    if not isinstance(value, str):
        raise PydanticCustomError("string_type", "scan_run_id has an invalid format")
    if not RUN_ID_PATTERN.fullmatch(value):
        raise ValueError("scan_run_id has an invalid format")
    return value


def _validate_artifact_path(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("artifact path must be a non-empty relative path")

    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part in {"", ".", ".."} for part in posix_path.parts)
        or any(part in {"", ".", ".."} for part in windows_path.parts)
    ):
        raise ValueError("artifact path must be a safe relative path")

    # PurePath catches platform-specific absolute paths on the running host.
    if PurePath(value).is_absolute():
        raise ValueError("artifact path must be a safe relative path")
    return value


def _validate_identifier(value: str, field_name: str) -> str:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must contain only letters, numbers, dots, underscores, and hyphens"
        )
    return value


class RunRequest(_ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    target_set_id: str = Field(min_length=1)
    deployment_id: str = Field(min_length=1)
    vuln_types: list[Literal["XSS", "SQLI"]] = Field(min_length=1)

    @field_validator("target_set_id", "deployment_id")
    @classmethod
    def request_identifiers_must_be_valid(cls, value: str, info: Any) -> str:
        return _validate_identifier(value, info.field_name)

    @field_validator("vuln_types")
    @classmethod
    def vuln_types_must_be_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("vuln_types must not contain duplicates")
        return value


class Progress(_ContractModel):
    completed: StrictInt = Field(ge=0)
    total: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def completed_must_not_exceed_known_total(self) -> Progress:
        if self.total > 0 and self.completed > self.total:
            raise ValueError("progress.completed cannot exceed progress.total")
        return self


class RunError(_ContractModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    retryable: StrictBool


class RunStatusDocument(_ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    scan_run_id: str
    target_set_id: str = Field(min_length=1)
    deployment_id: str = Field(min_length=1)
    requested_vuln_types: list[Literal["XSS", "SQLI"]] = Field(min_length=1)
    status: ExecutionStatus
    stage: ExecutionStage | None
    progress: Progress
    started_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    raw_result_path: str | None
    processed_result_path: str | None
    error: RunError | None

    @field_validator("scan_run_id")
    @classmethod
    def scan_run_id_must_be_valid(cls, value: str) -> str:
        return _validate_run_id(value)

    @field_validator("target_set_id", "deployment_id")
    @classmethod
    def status_identifiers_must_be_valid(cls, value: str, info: Any) -> str:
        return _validate_identifier(value, info.field_name)

    @field_validator("requested_vuln_types")
    @classmethod
    def requested_vuln_types_must_be_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("requested_vuln_types must not contain duplicates")
        return value

    @field_validator("started_at", "updated_at", "completed_at", mode="before")
    @classmethod
    def timestamps_must_not_be_numeric(cls, value: Any) -> Any:
        if isinstance(value, (int, float)):
            raise PydanticCustomError(
                "datetime_type",
                "timestamps must be ISO 8601 values with a timezone offset",
            )
        return value

    @field_validator("started_at", "updated_at", "completed_at")
    @classmethod
    def timestamps_must_be_timezone_aware(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamps must include a timezone offset")
        return value

    @field_validator("raw_result_path", "processed_result_path")
    @classmethod
    def artifact_paths_must_be_safe(cls, value: str | None) -> str | None:
        return None if value is None else _validate_artifact_path(value)

    @model_validator(mode="after")
    def status_fields_must_be_consistent(self) -> RunStatusDocument:
        terminal = {
            ExecutionStatus.COMPLETED,
            ExecutionStatus.PARTIAL,
            ExecutionStatus.FAILED,
        }
        if self.updated_at < self.started_at:
            raise ValueError("updated_at cannot precede started_at")
        if self.completed_at is not None and self.completed_at < self.updated_at:
            raise ValueError("completed_at cannot precede updated_at")

        if self.status in terminal:
            if self.stage is not None:
                raise ValueError("terminal statuses require stage to be null")
            if self.completed_at is None:
                raise ValueError("terminal statuses require completed_at")
        else:
            if self.completed_at is not None:
                raise ValueError(
                    "non-terminal statuses require completed_at to be null"
                )

        if self.status is ExecutionStatus.QUEUED and self.stage is not None:
            raise ValueError("QUEUED status requires stage to be null")
        if self.status is ExecutionStatus.RUNNING and self.stage is None:
            raise ValueError("RUNNING status requires a stage")
        if (
            self.status in {ExecutionStatus.COMPLETED, ExecutionStatus.PARTIAL}
            and self.processed_result_path is None
        ):
            raise ValueError(
                "COMPLETED and PARTIAL statuses require processed_result_path"
            )
        if (
            self.status in {ExecutionStatus.COMPLETED, ExecutionStatus.PARTIAL}
            and self.raw_result_path is None
        ):
            raise ValueError("COMPLETED and PARTIAL statuses require raw_result_path")
        if self.status is ExecutionStatus.FAILED:
            if self.processed_result_path is not None:
                raise ValueError("FAILED status cannot publish processed_result_path")
            if self.error is None:
                raise ValueError("FAILED status requires an execution error")
        elif self.error is not None:
            raise ValueError("Only FAILED status may contain an execution error")
        return self
