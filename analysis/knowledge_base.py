"""Private knowledge-base manifest validation for AI reference grounding."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

DEFAULT_KNOWLEDGE_BASE_PATH = Path("configs/knowledge-base.local.json")

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class KnowledgeBaseError(Exception):
    """A safe, stable error raised while loading a private manifest."""


class KnowledgeBaseModel(BaseModel):
    """Strict base model for private knowledge-base metadata."""

    model_config = ConfigDict(extra="forbid", strict=True)


class KnowledgeSource(KnowledgeBaseModel):
    file_id: StrictStr = Field(min_length=1)
    source_id: StrictStr = Field(min_length=1)
    publisher: Literal["OWASP", "KISA"]
    title: StrictStr = Field(min_length=1)
    version: StrictStr = Field(min_length=1)
    section: StrictStr = Field(min_length=1)
    canonical_url: StrictStr = Field(min_length=1)
    document_sha256: StrictStr = Field(min_length=1)
    vuln_types: list[Literal["XSS", "SQLI"]]
    language: Literal["ko", "en"]

    @field_validator("canonical_url")
    @classmethod
    def validate_canonical_url(cls, value: str, info: ValidationInfo) -> str:
        parsed = urlsplit(value)
        publisher = info.data.get("publisher")

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or "@" in parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise PydanticCustomError(
                "invalid_canonical_url",
                "canonical_url must be an official HTTPS URL without userinfo, query, or fragment",
            )

        hostname = parsed.hostname.lower()
        is_owasp_domain = hostname == "owasp.org" or hostname.endswith(".owasp.org")
        is_kisa_domain = hostname == "www.kisa.or.kr"
        if (publisher == "OWASP" and not is_owasp_domain) or (
            publisher == "KISA" and not is_kisa_domain
        ):
            raise PydanticCustomError(
                "untrusted_canonical_url",
                "canonical_url must use an official publisher domain",
            )
        return value

    @field_validator("document_sha256")
    @classmethod
    def validate_document_sha256(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise PydanticCustomError(
                "invalid_document_sha256",
                "document_sha256 must be a 64-character lowercase hexadecimal SHA-256 digest",
            )
        return value

    @field_validator("vuln_types")
    @classmethod
    def validate_vuln_types(
        cls, value: list[Literal["XSS", "SQLI"]]
    ) -> list[Literal["XSS", "SQLI"]]:
        if not value or len(value) != len(set(value)):
            raise PydanticCustomError(
                "invalid_vuln_types",
                "vuln_types must be nonempty and unique",
            )
        return value


class KnowledgeBaseManifest(KnowledgeBaseModel):
    schema_version: Literal["1.0"]
    knowledge_base_version: StrictStr = Field(min_length=1)
    vector_store_ids: list[StrictStr]
    files: list[KnowledgeSource]

    @field_validator("knowledge_base_version")
    @classmethod
    def validate_knowledge_base_version(cls, value: str) -> str:
        if not _IDENTIFIER_PATTERN.fullmatch(value):
            raise PydanticCustomError(
                "invalid_knowledge_base_version",
                "knowledge_base_version must be an identifier",
            )
        return value

    @field_validator("vector_store_ids")
    @classmethod
    def validate_vector_store_ids(cls, value: list[str]) -> list[str]:
        if (
            not value
            or any(not identifier for identifier in value)
            or len(value) != len(set(value))
        ):
            raise PydanticCustomError(
                "invalid_vector_store_ids",
                "vector_store_ids must be nonempty and unique",
            )
        return value

    @model_validator(mode="after")
    def validate_files(self) -> Self:
        if not self.files:
            raise PydanticCustomError("empty_files", "files must be nonempty")

        file_ids = [source.file_id for source in self.files]
        source_ids = [source.source_id for source in self.files]
        if len(file_ids) != len(set(file_ids)):
            raise PydanticCustomError(
                "duplicate_file_id", "files must have unique file_id values"
            )
        if len(source_ids) != len(set(source_ids)):
            raise PydanticCustomError(
                "duplicate_source_id",
                "files must have unique source_id values",
            )
        return self


def load_knowledge_base(
    path: str | Path = DEFAULT_KNOWLEDGE_BASE_PATH,
) -> KnowledgeBaseManifest:
    """Load a local private manifest without exposing its path or contents in errors."""

    manifest_path = Path(path)
    try:
        if manifest_path.is_symlink():
            raise KnowledgeBaseError(
                "Knowledge base manifest must not be a symbolic link."
            )
        with manifest_path.open("r", encoding="utf-8") as manifest_file:
            raw_manifest = json.load(manifest_file)
    except KnowledgeBaseError:
        raise
    except FileNotFoundError:
        raise KnowledgeBaseError("Knowledge base manifest is unavailable.") from None
    except (OSError, UnicodeDecodeError):
        raise KnowledgeBaseError("Knowledge base manifest could not be read.") from None
    except json.JSONDecodeError:
        raise KnowledgeBaseError("Knowledge base manifest is malformed.") from None

    try:
        return KnowledgeBaseManifest.model_validate(raw_manifest)
    except ValidationError:
        raise KnowledgeBaseError("Knowledge base manifest is invalid.") from None


def source_map_by_file_id(
    manifest: KnowledgeBaseManifest,
) -> dict[str, KnowledgeSource]:
    """Return the trusted source metadata keyed by OpenAI File Search file ID."""

    return {source.file_id: source for source in manifest.files}
