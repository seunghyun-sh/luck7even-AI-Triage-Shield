"""Canonical evidence-grounded AI triage callable."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    OpenAI,
    OpenAIError,
    RateLimitError,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from analysis.grounding import (
    GroundingBundle,
    GroundingUnavailableError,
    resolve_grounding,
)
from analysis.knowledge_base import (
    KnowledgeBaseError,
    KnowledgeBaseManifest,
    load_knowledge_base,
    source_map_by_file_id,
)
from analysis.models import (
    AiClaim,
    AiClaimType,
    AiLabel,
    AiProvenance,
    AiReference,
    AiResult,
    AiRole,
    AiStatus,
    AiStatusReason,
    ErrorDetail,
    GroundingStatus,
    ProcessedFinding,
    ProcessedRun,
    RawFinding,
    RawRun,
    RuleLabel,
    RunStatus,
    ScanStatus,
)
from analysis.prompts import (
    PROMPT_VERSION,
    batch_triage_input,
    triage_instructions,
)

OUTPUT_SCHEMA_VERSION = "1.1"
RETRIEVAL_POLICY_VERSION = "hybrid-reviewed-v1"
_PROVIDER_TIMEOUT_SECONDS = 30.0
_RETRY_BUDGET_SECONDS = 70.0
_CACHE_TIMEOUT_SECONDS = 5
_LEASE_SECONDS = 90
_TRUNCATION_MARKER = "[TRUNCATED]"
_FIELD_JSON_BYTE_CAPS = {"E1": 384, "E2": 512, "E3": 256, "E4": 768}
_BATCH_SIZE = 16
_SYNTHESIS_CONCURRENCY = 3
ProgressCallback = Callable[[int, int, str | None], None]
_REDACTIONS = (
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL_REDACTED]"),
    (
        re.compile(r"(?:\+?\d{1,3}[-. ]?)?(?:\d{2,4}[-. ]?){2,3}\d{3,4}"),
        "[PHONE_REDACTED]",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "[JWT_REDACTED]",
    ),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[CARD_REDACTED]"),
    (
        re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,&;]+"),
        "[PASSWORD_REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(?:set-cookie|cookie)\s*[:=]\s*[^\r\n;]+"),
        "[COOKIE_REDACTED]",
    ),
    (
        re.compile(r"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+[^\s,;]+"),
        "[AUTHORIZATION_REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(?:csrf(?:[_-]?token)?|session(?:[_-]?(?:id|key|token))?|access[_-]?token|api[_-]?key|auth[_-]?token|token)\s*[:=]\s*[^\s,&;]+"
        ),
        "[TOKEN_REDACTED]",
    ),
)


class ProviderObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)


class CompactFindingAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str = Field(min_length=1)
    label: AiLabel
    confidence: float = Field(ge=0.0, le=1.0)
    observation: ProviderObservation
    guidance_ids: list[str] = Field(min_length=1, max_length=3)


class CompactBatchAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    findings: list[CompactFindingAnalysis] = Field(min_length=1, max_length=_BATCH_SIZE)


@dataclass(frozen=True)
class GroupGrounding:
    vuln_type: str
    bundle: GroundingBundle


class ProviderSchemaError(ValueError):
    """Provider output violated the requested structured schema."""


class ReferenceMismatchError(ValueError):
    """Provider references did not match retrieved trusted files."""


class ProviderToolError(RuntimeError):
    """Provider tool execution failed without a retryable transport error."""


class ProviderDeadlineError(TimeoutError):
    """The application-owned provider retry budget was exhausted."""


def _load_environment() -> None:
    load_dotenv(
        dotenv_path=Path(__file__).resolve().parents[1] / ".env",
        override=False,
    )


def _configured_model() -> str:
    _load_environment()
    model = os.environ.get("AI_TRIAGE_MODEL")
    if model is None or not model.strip():
        raise ProviderToolError
    return model


def _truncate_utf8(value: str, cap: int) -> str:
    raw = value.encode("utf-8")
    if len(raw) <= cap:
        return value
    marker = _TRUNCATION_MARKER.encode("utf-8")
    limit = max(0, cap - len(marker))
    prefix = raw[:limit]
    while prefix:
        try:
            return prefix.decode("utf-8") + _TRUNCATION_MARKER
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    return _TRUNCATION_MARKER[:cap]


def _truncate_json_string(value: str, cap: int) -> str:
    """Bound JSON-serialized string bytes, including escaped controls."""

    def encoded(text: str) -> int:
        return len(
            json.dumps(text, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )

    if encoded(value) <= cap:
        return value
    marker = _TRUNCATION_MARKER
    lower, upper = 0, len(value)
    while lower < upper:
        middle = (lower + upper + 1) // 2
        if encoded(value[:middle] + marker) <= cap:
            lower = middle
        else:
            upper = middle - 1
    prefix = value[:lower]
    return prefix + marker if encoded(prefix + marker) <= cap else marker[:cap]


def _redact(value: str | None) -> str:
    text = value or ""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "[INVALID_URL]"
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme}://{parsed.hostname}{port}{parsed.path or '/'}"


def _evidence(finding: RawFinding) -> dict[str, str]:
    request, response = finding.scan.request, finding.scan.response
    baseline = (
        "none"
        if response.baseline_elapsed_ms is None
        else str(response.baseline_elapsed_ms)
    )
    first_stage_observation = (
        f"The first-stage {finding.vuln_type.value} rule selected this finding "
        "for independent second-stage review."
    )
    values = {
        "E1": first_stage_observation,
        "E2": _redact(response.evidence_summary),
        "E3": f"HTTP {response.http_status}; elapsed_ms={response.elapsed_ms}; baseline_elapsed_ms={baseline}",
        "E4": _redact(
            f"method={request.method}; url={_safe_url(request.url)}; parameter={request.parameter}; input_location={request.input_location}; payload={request.payload}"
        ),
    }
    return {
        key: _truncate_json_string(values[key], _FIELD_JSON_BYTE_CAPS[key])
        for key in sorted(values)
    }


def check_readiness() -> None:
    _load_environment()
    if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("AI_TRIAGE_MODEL"):
        raise RuntimeError("AI triage configuration is unavailable.")
    try:
        manifest = load_knowledge_base()
        resolve_grounding("XSS", manifest)
        resolve_grounding("SQLI", manifest)
    except (GroundingUnavailableError, KnowledgeBaseError):
        raise RuntimeError("AI triage knowledge base is unavailable.") from None


def _cache_root() -> Path:
    return (Path.cwd() / "data" / "cache").resolve()


class SQLiteCache:
    def __init__(self, path: str | Path | None = None) -> None:
        supplied = Path(path or "data/cache/ai-triage.sqlite3")
        if supplied.is_absolute():
            raise RuntimeError("AI triage cache is unavailable.")
        raw_candidate = Path.cwd() / supplied
        cursor = raw_candidate
        while cursor != Path.cwd().parent:
            if cursor.exists() and cursor.is_symlink():
                raise RuntimeError("AI triage cache is unavailable.")
            cursor = cursor.parent
        root = _cache_root()
        candidate = (Path.cwd() / supplied).resolve(strict=False)
        if candidate != root and root not in candidate.parents:
            raise RuntimeError("AI triage cache is unavailable.")
        for ancestor in (Path.cwd(), *candidate.parents):
            if ancestor == Path.cwd().parent:
                break
            if ancestor.exists() and ancestor.is_symlink():
                raise RuntimeError("AI triage cache is unavailable.")
            if ancestor == root:
                break
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        self.path = candidate
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS ai_triage_cache (cache_key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS ai_triage_leases (cache_key TEXT PRIMARY KEY, owner TEXT NOT NULL, expires_at REAL NOT NULL)"
            )
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=_CACHE_TIMEOUT_SECONDS)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def get(self, key: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM ai_triage_cache WHERE cache_key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
            if isinstance(value, dict):
                return value
            self.delete(key)
            return None
        except (TypeError, json.JSONDecodeError):
            self.delete(key)
            return None

    def set(self, key: str, value: dict[str, Any]) -> None:
        serialized = json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=str
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO ai_triage_cache(cache_key, value) VALUES (?, ?)",
                (key, serialized),
            )

    def delete(self, key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM ai_triage_cache WHERE cache_key = ?", (key,)
            )

    def acquire(self, key: str, owner: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM ai_triage_leases WHERE expires_at <= ?", (current,)
            )
            try:
                connection.execute(
                    "INSERT INTO ai_triage_leases(cache_key, owner, expires_at) VALUES (?, ?, ?)",
                    (key, owner, current + _LEASE_SECONDS),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def release(self, key: str, owner: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM ai_triage_leases WHERE cache_key = ? AND owner = ?",
                (key, owner),
            )


def _cache_get(cache: Any, key: str) -> Any:
    try:
        return cache.get(key) if hasattr(cache, "get") else None
    except (OSError, RuntimeError, sqlite3.Error, TypeError):
        return None


def _cache_set(cache: Any, key: str, value: dict[str, Any]) -> None:
    try:
        if hasattr(cache, "set"):
            cache.set(key, value)
        elif hasattr(cache, "__setitem__"):
            cache[key] = value
    except (OSError, RuntimeError, sqlite3.Error, TypeError):
        pass


def _cache_delete(cache: Any, key: str) -> None:
    try:
        if hasattr(cache, "delete"):
            cache.delete(key)
        elif hasattr(cache, "pop"):
            cache.pop(key, None)
    except (OSError, RuntimeError, sqlite3.Error, TypeError):
        pass


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def _manifest_digest(manifest: KnowledgeBaseManifest) -> str:
    return _canonical_digest(manifest.model_dump(mode="json"))


def _cache_bindings(
    evidence: dict[str, str],
    model: str,
    manifest: KnowledgeBaseManifest,
    vuln_type: str,
    bundle: GroundingBundle,
) -> dict[str, Any]:
    return {
        "model": model,
        "prompt_version": PROMPT_VERSION,
        "knowledge_base_version": manifest.knowledge_base_version,
        "manifest_digest": _manifest_digest(manifest),
        "output_schema_version": OUTPUT_SCHEMA_VERSION,
        "retrieval_policy_version": RETRIEVAL_POLICY_VERSION,
        "vuln_type": vuln_type,
        "evidence_hash": _canonical_digest(evidence),
        "retrieval_mode": bundle.mode.value,
        "grounding_bundle_digest": bundle.bundle_digest,
        "grounding_pack_version": bundle.pack_version,
    }


def _cache_key(
    finding: RawFinding,
    evidence: dict[str, str],
    model: str,
    manifest: KnowledgeBaseManifest,
    bundle: GroundingBundle,
) -> str:
    return _canonical_digest(
        {
            "finding": finding.model_dump(mode="json"),
            **_cache_bindings(
                evidence, model, manifest, finding.vuln_type.value, bundle
            ),
        }
    )


def _not_requested(reason: AiStatusReason, *, needs_human_review: bool) -> AiResult:
    return AiResult(
        status=AiStatus.NOT_REQUESTED,
        status_reason=reason,
        label=None,
        confidence=None,
        needs_human_review=needs_human_review,
        assessment_summary=None,
        source_evidence=None,
        impact=None,
        recommendation=None,
        manual_check=None,
        report_paragraph=None,
        error=None,
        role=AiRole.EVIDENCE_GROUNDED_REPORTING,
        grounding_status=GroundingStatus.NOT_APPLICABLE,
    )


def _failed(code: str, retryable: bool) -> AiResult:
    return AiResult(
        status=AiStatus.FAILED,
        status_reason=None,
        label=None,
        confidence=None,
        needs_human_review=True,
        assessment_summary=None,
        source_evidence=None,
        impact=None,
        recommendation=None,
        manual_check=None,
        report_paragraph=None,
        error=ErrorDetail(
            code=code, message="AI triage could not be completed.", retryable=retryable
        ),
        role=AiRole.EVIDENCE_GROUNDED_REPORTING,
        grounding_status=GroundingStatus.NOT_APPLICABLE,
    )


def _provenance(
    model: str, manifest: KnowledgeBaseManifest, bundle: GroundingBundle, now: Any
) -> AiProvenance:
    timestamp = now() if callable(now) else now
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ProviderSchemaError
    return AiProvenance(
        model=model,
        prompt_version=PROMPT_VERSION,
        knowledge_base_version=manifest.knowledge_base_version,
        output_schema_version=OUTPUT_SCHEMA_VERSION,
        retrieval_policy_version=RETRIEVAL_POLICY_VERSION,
        vector_store_ids=[],
        retrieved_file_ids=list(bundle.retrieved_file_ids),
        retrieval_mode=bundle.mode.value,
        grounding_bundle_digest=bundle.bundle_digest,
        grounding_pack_version=bundle.pack_version,
        generated_at=timestamp,
    )


def _insufficient(
    model: str, manifest: KnowledgeBaseManifest, bundle: GroundingBundle, now: Any
) -> AiResult:
    return AiResult(
        status=AiStatus.COMPLETED,
        status_reason=AiStatusReason.POLICY_EXCLUDED,
        label=AiLabel.INCONCLUSIVE,
        confidence=None,
        needs_human_review=True,
        assessment_summary="Insufficient trusted official evidence was retrieved.",
        source_evidence=None,
        impact=None,
        recommendation=None,
        manual_check=None,
        report_paragraph=None,
        error=None,
        role=AiRole.EVIDENCE_GROUNDED_REPORTING,
        grounding_status=GroundingStatus.INSUFFICIENT,
        provenance=_provenance(model, manifest, bundle, now),
    )


def _get(value: Any, name: str, default: Any = None) -> Any:
    return getattr(
        value, name, value.get(name, default) if isinstance(value, dict) else default
    )


def _status_retryable(error: APIStatusError) -> bool:
    return error.status_code in {408, 409, 429} or error.status_code >= 500


def _retry_after(error: Exception) -> float | None:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", {}) if response is not None else {}
    try:
        value = float(headers.get("retry-after"))
        return min(10.0, max(0.0, value))
    except (AttributeError, TypeError, ValueError):
        return None


def _grounded(
    parsed: CompactFindingAnalysis,
    bundle: GroundingBundle,
    evidence: dict[str, str],
    vuln_type: str,
    model: str,
    manifest: KnowledgeBaseManifest,
    now: Any,
) -> AiResult:
    sources = source_map_by_file_id(manifest)
    if len(parsed.guidance_ids) != len(set(parsed.guidance_ids)) or any(
        guidance_id not in bundle.guidance for guidance_id in parsed.guidance_ids
    ):
        raise ProviderSchemaError
    prefix = f"{parsed.finding_id}:"
    if any(
        not evidence_id.startswith(prefix)
        or evidence_id.removeprefix(prefix) not in evidence
        for evidence_id in parsed.observation.evidence_ids
    ):
        raise ProviderSchemaError
    if len(parsed.observation.evidence_ids) != len(
        set(parsed.observation.evidence_ids)
    ):
        raise ProviderSchemaError
    refs, ref_ids = [], {}
    selected = [bundle.guidance[key] for key in parsed.guidance_ids]
    if any(guide.family != vuln_type for guide in selected):
        raise ProviderSchemaError
    source_ids = {source_id for guide in selected for source_id in guide.source_ids}
    for index, fid in enumerate(
        sorted(
            fid
            for fid, source in sources.items()
            if (
                source.source_id in source_ids
                and fid in bundle.retrieved_file_ids
                and vuln_type in source.vuln_types
            )
        ),
        1,
    ):
        source, ref_id = sources[fid], f"R{index}"
        ref_ids[fid] = ref_id
        refs.append(
            AiReference(
                reference_id=ref_id,
                source_id=source.source_id,
                publisher=source.publisher,
                title=source.title,
                version=source.version,
                section=source.section,
                canonical_url=source.canonical_url,
                file_id=fid,
                document_sha256=source.document_sha256,
            )
        )
    if not refs or {sources[fid].source_id for fid in ref_ids} != source_ids:
        raise ReferenceMismatchError
    claims = [
        AiClaim(
            claim_id="C1",
            claim_type=AiClaimType.OBSERVATION,
            text=_redact(parsed.observation.text),
            evidence_ids=[
                evidence_id.removeprefix(prefix)
                for evidence_id in parsed.observation.evidence_ids
            ],
            reference_ids=[],
        )
    ]
    for claim_id, claim_type, field in (
        ("C2", AiClaimType.IMPACT, "impact"),
        ("C3", AiClaimType.RECOMMENDATION, "recommendation"),
        ("C4", AiClaimType.MANUAL_CHECK, "manual_check"),
    ):
        texts = [_redact(getattr(guide, field)) for guide in selected]
        ids = {source_id for guide in selected for source_id in guide.source_ids}
        claims.append(
            AiClaim(
                claim_id=claim_id,
                claim_type=claim_type,
                text=" ".join(texts),
                evidence_ids=[],
                reference_ids=[
                    ref_id
                    for fid, ref_id in ref_ids.items()
                    if sources[fid].source_id in ids
                ],
            )
        )

    def text(kind: AiClaimType) -> str:
        return " ".join(
            f"{claim.text} {' '.join(f'[{item}]' for item in claim.evidence_ids + claim.reference_ids)}".strip()
            for claim in claims
            if claim.claim_type is kind
        )

    observation, impact, recommendation, manual = (text(kind) for kind in AiClaimType)
    return AiResult(
        status=AiStatus.COMPLETED,
        status_reason=None,
        label=parsed.label,
        confidence=parsed.confidence,
        needs_human_review=True,
        assessment_summary=observation,
        source_evidence="; ".join(f"{key}: {value}" for key, value in evidence.items()),
        impact=impact,
        recommendation=recommendation,
        manual_check=manual,
        report_paragraph=f"{observation} {impact} {recommendation} {manual}",
        error=None,
        role=AiRole.EVIDENCE_GROUNDED_REPORTING,
        grounding_status=GroundingStatus.GROUNDED,
        claims=claims,
        references=refs,
        provenance=_provenance(model, manifest, bundle, now),
    )


def _batch_parse(
    client: Any,
    model: str,
    group: GroupGrounding,
    items: list[tuple[RawFinding, dict[str, str]]],
    *,
    timeout: float,
) -> CompactBatchAnalysis:
    payload = [
        {
            "finding_id": finding.finding_id,
            "evidence": {
                f"{finding.finding_id}:{key}": value for key, value in evidence.items()
            },
        }
        for finding, evidence in items
    ]
    try:
        provider_input = batch_triage_input(
            group.vuln_type,
            payload,
            {
                "passages": [
                    item.model_dump(mode="json") for item in group.bundle.passages
                ],
                "guidance": {
                    key: {
                        "description": (
                            f"impact: {value.impact}; recommendation: "
                            f"{value.recommendation}; manual_check: {value.manual_check}"
                        )
                    }
                    for key, value in sorted(group.bundle.guidance.items())
                },
            },
        )
    except ValueError as error:
        raise ProviderSchemaError from error
    response = client.responses.parse(
        model=model,
        instructions=triage_instructions(group.vuln_type),
        input=provider_input,
        text_format=CompactBatchAnalysis,
        max_output_tokens=6000,
        timeout=timeout,
    )
    if _get(response, "status") != "completed":
        raise ProviderToolError
    parsed = _get(response, "output_parsed")
    if not isinstance(parsed, CompactBatchAnalysis):
        parsed = CompactBatchAnalysis.model_validate(parsed)
    expected = {finding.finding_id for finding, _ in items}
    actual = [item.finding_id for item in parsed.findings]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ProviderSchemaError
    return parsed


def _error_result(error: Exception) -> AiResult:
    if isinstance(error, ReferenceMismatchError):
        return _failed("AI_REFERENCE_MISMATCH", False)
    if isinstance(error, (ProviderSchemaError, ValidationError)):
        return _failed("AI_SCHEMA_INVALID", False)
    if isinstance(error, (ProviderDeadlineError, APITimeoutError)):
        return _failed("AI_TIMEOUT", True)
    if isinstance(error, (RateLimitError, APIConnectionError)):
        return _failed("AI_PROVIDER_UNAVAILABLE", True)
    if isinstance(error, APIStatusError):
        return _failed(
            "AI_PROVIDER_UNAVAILABLE" if _status_retryable(error) else "AI_TOOL_FAILED",
            _status_retryable(error),
        )
    return _failed("AI_TOOL_FAILED", False)


def _cache_envelope(ai: AiResult, bindings: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "ai-triage-cache-v1",
        "bindings": bindings,
        "trusted_file_ids": ai.provenance.retrieved_file_ids if ai.provenance else [],
        "result": ai.model_dump(mode="json"),
    }


def _cached_result(
    row: dict[str, Any], bindings: dict[str, Any], manifest: KnowledgeBaseManifest
) -> AiResult | None:
    try:
        if row.get("schema") != "ai-triage-cache-v1" or row.get("bindings") != bindings:
            return None
        ai = AiResult.model_validate(row["result"])
        if (
            ai.status is not AiStatus.COMPLETED
            or ai.role is not AiRole.EVIDENCE_GROUNDED_REPORTING
            or ai.grounding_status
            not in {GroundingStatus.GROUNDED, GroundingStatus.INSUFFICIENT}
            or not ai.provenance
        ):
            return None
        provenance = ai.provenance
        for key in (
            "model",
            "prompt_version",
            "knowledge_base_version",
            "output_schema_version",
            "retrieval_policy_version",
            "retrieval_mode",
            "grounding_bundle_digest",
            "grounding_pack_version",
        ):
            if getattr(provenance, key) != bindings[key]:
                return None
        if (
            provenance.vector_store_ids != []
            or row.get("trusted_file_ids") != provenance.retrieved_file_ids
        ):
            return None
        sources = source_map_by_file_id(manifest)
        if any(
            fid not in sources or bindings["vuln_type"] not in sources[fid].vuln_types
            for fid in provenance.retrieved_file_ids
        ):
            return None
        expected = {ref.file_id: sources.get(ref.file_id) for ref in ai.references}
        if any(
            source is None
            or ref.model_dump(mode="json", exclude={"reference_id"})
            != AiReference(
                reference_id=ref.reference_id,
                source_id=source.source_id,
                publisher=source.publisher,
                title=source.title,
                version=source.version,
                section=source.section,
                canonical_url=source.canonical_url,
                file_id=source.file_id,
                document_sha256=source.document_sha256,
            ).model_dump(mode="json", exclude={"reference_id"})
            for ref, source in ((ref, expected[ref.file_id]) for ref in ai.references)
        ):
            return None
        claim_refs = {rid for claim in ai.claims for rid in claim.reference_ids}
        if claim_refs != {ref.reference_id for ref in ai.references}:
            return None
        return ai
    except (AttributeError, KeyError, TypeError, ValidationError, ValueError):
        return None


def triage(
    raw_run: RawRun,
    on_progress: ProgressCallback | None = None,
    *,
    client: Any = None,
    knowledge_base: KnowledgeBaseManifest | None = None,
    cache: Any = None,
    sleeper: Any = time.sleep,
    now: Any = lambda: datetime.now(timezone.utc),
    monotonic: Any = time.monotonic,
    jitter: Any = lambda: 0.0,
    retry_budget: float = _RETRY_BUDGET_SECONDS,
) -> ProcessedRun:
    on_progress = on_progress or (lambda _completed, _total, _detail: None)
    manifest, default_cache = knowledge_base, None
    terminal: dict[str, AiResult] = {}
    candidates = [
        finding
        for finding in raw_run.findings
        if finding.scan.status is not ScanStatus.FAILED
        and finding.scan.rule.label is RuleLabel.SUSPECTED
    ]
    total, completed = len(candidates), 0
    on_progress(0, total, "AI 후보 준비 중" if total else "AI 후보 없음")

    for finding in raw_run.findings:
        if finding.scan.status is ScanStatus.FAILED:
            terminal[finding.finding_id] = _not_requested(
                AiStatusReason.SCAN_FAILED, needs_human_review=True
            )
        elif finding.scan.rule.label is RuleLabel.SAFE:
            terminal[finding.finding_id] = _not_requested(
                AiStatusReason.RULE_NOT_SUSPECTED, needs_human_review=False
            )

    pending: dict[str, tuple[RawFinding, dict[str, str], str, dict[str, Any], Any]] = {}
    bundles: dict[str, GroundingBundle] = {}
    if candidates:
        try:
            _load_environment()
            if manifest is None:
                manifest = load_knowledge_base()
            model = _configured_model()
            for vuln_type in {finding.vuln_type.value for finding in candidates}:
                try:
                    on_progress(completed, total, f"판단 기준 문서 준비 · {vuln_type}")
                    bundles[vuln_type] = resolve_grounding(vuln_type, manifest)
                except GroundingUnavailableError:
                    for finding in candidates:
                        if finding.vuln_type.value == vuln_type:
                            terminal[finding.finding_id] = _failed(
                                "AI_GROUNDING_UNAVAILABLE", False
                            )
                            completed += 1
            active_cache = cache
            if active_cache is None:
                try:
                    default_cache = SQLiteCache()
                    active_cache = default_cache
                except (OSError, RuntimeError, sqlite3.Error):
                    active_cache = None
            for finding in candidates:
                if finding.finding_id in terminal:
                    continue
                evidence = _evidence(finding)
                bundle = bundles[finding.vuln_type.value]
                key = _cache_key(finding, evidence, model, manifest, bundle)
                bindings = _cache_bindings(
                    evidence, model, manifest, finding.vuln_type.value, bundle
                )
                row = (
                    _cache_get(active_cache, key) if active_cache is not None else None
                )
                cached = _cached_result(row, bindings, manifest) if row else None
                if row is not None and cached is None:
                    _cache_delete(active_cache, key)
                if cached is not None:
                    terminal[finding.finding_id] = cached
                    completed += 1
                else:
                    pending[finding.finding_id] = (
                        finding,
                        evidence,
                        key,
                        bindings,
                        active_cache,
                    )
            if completed:
                on_progress(completed, total, f"캐시 결과 재사용 · {completed}/{total}")
        except (
            KnowledgeBaseError,
            OSError,
            RuntimeError,
            sqlite3.Error,
            ProviderToolError,
            ValidationError,
            ValueError,
            TypeError,
        ) as error:
            for finding in candidates:
                if finding.finding_id not in terminal:
                    terminal[finding.finding_id] = _error_result(error)
                    completed += 1
            on_progress(completed, total, f"AI 처리 완료 · {completed}/{total}")
            pending.clear()

    groups: dict[str, list[tuple[RawFinding, dict[str, str]]]] = {}
    for finding, evidence, *_ in pending.values():
        groups.setdefault(finding.vuln_type.value, []).append((finding, evidence))
    if pending and client is None:
        client = OpenAI(max_retries=0, timeout=_PROVIDER_TIMEOUT_SECONDS)

    breaker_lock, breaker = Lock(), {"consecutive": 0, "open": False}

    def synthesize(
        group: GroupGrounding, items: list[tuple[RawFinding, dict[str, str]]]
    ) -> dict[str, AiResult]:
        with breaker_lock:
            if breaker["open"]:
                return {
                    finding.finding_id: _failed("AI_PROVIDER_UNAVAILABLE", True)
                    for finding, _ in items
                }
        deadline = monotonic() + retry_budget
        batch_data = [pending[finding.finding_id] for finding, _ in items]
        lease_cache = batch_data[0][4] if batch_data else None
        acquire = getattr(lease_cache, "acquire", None)
        release = getattr(lease_cache, "release", None)
        lease_owner: str | None = None
        lease_key: str | None = None

        if callable(acquire) and callable(release):
            lease_key = _canonical_digest(
                {
                    "cache_keys": sorted(data[2] for data in batch_data),
                    "model": model,
                    "bundle_digest": group.bundle.bundle_digest,
                }
            )
            owner = uuid.uuid4().hex
            while monotonic() < deadline:
                try:
                    if acquire(lease_key, owner):
                        lease_owner = owner
                        cached_results: dict[str, AiResult] = {}
                        for data in batch_data:
                            row = _cache_get(data[4], data[2])
                            cached = (
                                _cached_result(row, data[3], manifest)
                                if row is not None
                                else None
                            )
                            if cached is None:
                                cached_results = {}
                                break
                            cached_results[data[0].finding_id] = cached
                        if cached_results:
                            try:
                                release(lease_key, owner)
                            except (
                                OSError,
                                RuntimeError,
                                sqlite3.Error,
                                TypeError,
                            ):
                                pass
                            lease_owner = None
                            return cached_results
                        break
                except (OSError, RuntimeError, sqlite3.Error, TypeError):
                    # A cache fault must not prevent a valid provider response.
                    lease_key = None
                    break

                cached_results: dict[str, AiResult] = {}
                for data in batch_data:
                    row = _cache_get(data[4], data[2])
                    cached = (
                        _cached_result(row, data[3], manifest)
                        if row is not None
                        else None
                    )
                    if row is not None and cached is None:
                        _cache_delete(data[4], data[2])
                    if cached is None:
                        cached_results = {}
                        break
                    cached_results[data[0].finding_id] = cached
                if cached_results:
                    return cached_results

                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                sleeper(min(0.1, remaining))

            if lease_key is not None and lease_owner is None:
                return {
                    finding.finding_id: _failed("AI_PROVIDER_UNAVAILABLE", True)
                    for finding, _ in items
                }

        try:
            for attempt in range(3):
                try:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise ProviderDeadlineError
                    parsed = _batch_parse(
                        client,
                        model,
                        group,
                        items,
                        timeout=min(_PROVIDER_TIMEOUT_SECONDS, remaining),
                    )
                    with breaker_lock:
                        breaker["consecutive"] = 0
                    by_id = {item.finding_id: item for item in parsed.findings}
                    results = {}
                    for finding, evidence in items:
                        try:
                            results[finding.finding_id] = _grounded(
                                by_id[finding.finding_id],
                                group.bundle,
                                evidence,
                                group.vuln_type,
                                model,
                                manifest,
                                now,
                            )
                        except (
                            ProviderSchemaError,
                            ReferenceMismatchError,
                            ValidationError,
                        ) as error:
                            results[finding.finding_id] = _error_result(error)
                    if lease_owner is not None:
                        for finding_id, ai in results.items():
                            data = pending[finding_id]
                            if (
                                ai.status is AiStatus.COMPLETED
                                and ai.grounding_status
                                in {
                                    GroundingStatus.GROUNDED,
                                    GroundingStatus.INSUFFICIENT,
                                }
                            ):
                                _cache_set(
                                    data[4], data[2], _cache_envelope(ai, data[3])
                                )
                    return results
                except (
                    ProviderSchemaError,
                    ReferenceMismatchError,
                    ValidationError,
                ) as error:
                    return {
                        finding.finding_id: _error_result(error) for finding, _ in items
                    }
                except (
                    APITimeoutError,
                    RateLimitError,
                    APIConnectionError,
                    APIStatusError,
                    ProviderDeadlineError,
                ) as error:
                    transient = not isinstance(
                        error, APIStatusError
                    ) or _status_retryable(error)
                    if not transient:
                        return {
                            finding.finding_id: _error_result(error)
                            for finding, _ in items
                        }
                    if attempt < 2:
                        delay = _retry_after(error) or min(
                            10.0, 2**attempt + max(0.0, float(jitter()))
                        )
                        if monotonic() + delay > deadline:
                            error = ProviderDeadlineError()
                            attempt = 2
                        else:
                            sleeper(delay)
                            continue
                    with breaker_lock:
                        breaker["consecutive"] += 1
                        if breaker["consecutive"] >= 3:
                            breaker["open"] = True
                    return {
                        finding.finding_id: _error_result(error) for finding, _ in items
                    }
                except (
                    ProviderToolError,
                    OpenAIError,
                    AttributeError,
                    KeyError,
                    TypeError,
                    ValueError,
                ) as error:
                    return {
                        finding.finding_id: _error_result(error) for finding, _ in items
                    }
            raise AssertionError("unreachable")
        finally:
            if lease_owner is not None and lease_key is not None:
                try:
                    release(lease_key, lease_owner)
                except (OSError, RuntimeError, sqlite3.Error, TypeError):
                    pass

    futures = []
    with ThreadPoolExecutor(max_workers=_SYNTHESIS_CONCURRENCY) as executor:
        for vuln_type, items in groups.items():
            group = GroupGrounding(vuln_type, bundles[vuln_type])
            for start in range(0, len(items), _BATCH_SIZE):
                futures.append(
                    executor.submit(
                        synthesize, group, items[start : start + _BATCH_SIZE]
                    )
                )
        for future in as_completed(futures):
            batch_results = future.result()
            for finding_id, ai in batch_results.items():
                terminal[finding_id] = ai
                data = pending[finding_id]
                if ai.status is AiStatus.COMPLETED and ai.grounding_status in {
                    GroundingStatus.GROUNDED,
                    GroundingStatus.INSUFFICIENT,
                }:
                    _cache_set(data[4], data[2], _cache_envelope(ai, data[3]))
            completed += len(batch_results)
            on_progress(completed, total, f"AI 배치 처리 · {completed}/{total}")

    results = [
        ProcessedFinding(
            case_id=finding.case_id,
            finding_id=finding.finding_id,
            scanned_at=finding.scanned_at,
            vuln_type=finding.vuln_type,
            scan=finding.scan.model_copy(deep=True),
            ai=terminal.get(
                finding.finding_id, _failed("AI_PROVIDER_UNAVAILABLE", True)
            ),
        )
        for finding in raw_run.findings
    ]
    has_failure = any(
        item.scan.status is ScanStatus.FAILED or item.ai.status is AiStatus.FAILED
        for item in results
    )
    has_completed = any(item.scan.status is ScanStatus.COMPLETED for item in results)
    all_scans_failed = not results or all(
        item.scan.status is ScanStatus.FAILED for item in results
    )
    status = (
        RunStatus.PARTIAL
        if has_failure and has_completed
        else (RunStatus.FAILED if all_scans_failed else RunStatus.COMPLETED)
    )
    return ProcessedRun(
        schema_version="1.1",
        scan_run_id=raw_run.scan_run_id,
        target_set_id=raw_run.target_set_id,
        started_at=raw_run.started_at,
        completed_at=now(),
        status=status,
        findings=results,
    )
