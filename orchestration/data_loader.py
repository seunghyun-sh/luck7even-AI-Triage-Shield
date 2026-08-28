"""Validated readers for scanner execution contracts."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, TextIO, TypeAlias

from pydantic import ValidationError

from analysis.models import RawRun, TargetManifest

DataSource: TypeAlias = Path | bytes | BinaryIO | TextIO


class ContractLoadError(ValueError):
    """A safe error raised when a contract artifact cannot be loaded."""


def _read_source(source: DataSource, artifact_name: str) -> bytes | str:
    try:
        if isinstance(source, Path):
            return source.read_bytes()
        if isinstance(source, bytes):
            return source
        content = source.read()
    except (OSError, UnicodeError, AttributeError, TypeError, ValueError):
        raise ContractLoadError(f"Unable to read {artifact_name}.") from None

    if not isinstance(content, (bytes, str)):
        raise ContractLoadError(f"Unable to read {artifact_name}.")
    return content


def _validation_message(artifact_name: str, error: ValidationError) -> str:
    first_error = error.errors(include_input=False)[0]
    location = ".".join(str(part) for part in first_error["loc"])
    detail = first_error["msg"]
    if location:
        return f"Invalid {artifact_name}: {location}: {detail}"
    return f"Invalid {artifact_name}: {detail}"


def load_target_manifest(source: DataSource) -> TargetManifest:
    """Load and validate the sole authorized scanner target input."""

    content = _read_source(source, "target manifest")
    try:
        return TargetManifest.model_validate_json(content)
    except ValidationError as error:
        raise ContractLoadError(_validation_message("target manifest", error)) from None


def load_raw_data(source: DataSource) -> RawRun:
    """Load and validate a canonical raw scanner-results artifact."""

    content = _read_source(source, "raw findings data")
    try:
        return RawRun.model_validate_json(content)
    except ValidationError as error:
        raise ContractLoadError(_validation_message("raw findings data", error)) from None
