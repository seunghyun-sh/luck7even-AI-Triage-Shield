"""Canonical evidence-grounded AI triage callable."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
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
    retrieval_instructions,
    triage_input,
    triage_instructions,
)

OUTPUT_SCHEMA_VERSION = "1.1"
RETRIEVAL_POLICY_VERSION = "retrieval-v1"
_PROVIDER_TIMEOUT_SECONDS = 30.0
_RETRY_BUDGET_SECONDS = 70.0
_CACHE_TIMEOUT_SECONDS = 5
_LEASE_SECONDS = 90
_TRUNCATION_MARKER = "[TRUNCATED]"
_FIELD_BYTE_CAPS = {"E1": 2048, "E2": 2048, "E3": 512, "E4": 2048}
_RETRIEVED_TEXT_FILE_BYTE_CAP = 768
_RETRIEVED_TEXT_TOTAL_BYTE_CAP = 1024
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


class ProviderClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    claim_type: AiClaimType
    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    reference_file_ids: list[str] = Field(default_factory=list)


class ProviderAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    claims: list[ProviderClaim] = Field(default_factory=list)


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
    values = {
        "E1": _redact(finding.scan.rule.reason),
        "E2": _redact(response.evidence_summary),
        "E3": f"HTTP {response.http_status}; elapsed_ms={response.elapsed_ms}; baseline_elapsed_ms={baseline}",
        "E4": _redact(
            f"method={request.method}; url={_safe_url(request.url)}; parameter={request.parameter}; input_location={request.input_location}; payload={request.payload}"
        ),
    }
    return {
        key: _truncate_utf8(values[key], _FIELD_BYTE_CAPS[key])
        for key in sorted(values)
    }


def check_readiness() -> None:
    _load_environment()
    if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("AI_TRIAGE_MODEL"):
        raise RuntimeError("AI triage configuration is unavailable.")
    try:
        load_knowledge_base()
    except KnowledgeBaseError:
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
    }


def _cache_key(
    finding: RawFinding,
    evidence: dict[str, str],
    model: str,
    manifest: KnowledgeBaseManifest,
) -> str:
    return _canonical_digest(
        {
            "finding": finding.model_dump(mode="json"),
            **_cache_bindings(evidence, model, manifest, finding.vuln_type.value),
        }
    )


def _not_requested(reason: AiStatusReason) -> AiResult:
    return AiResult(
        status=AiStatus.NOT_REQUESTED,
        status_reason=reason,
        label=None,
        confidence=None,
        needs_human_review=True,
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
    model: str, manifest: KnowledgeBaseManifest, retrieved: list[str], now: Any
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
        vector_store_ids=manifest.vector_store_ids,
        retrieved_file_ids=retrieved,
        generated_at=timestamp,
    )


def _insufficient(
    model: str, manifest: KnowledgeBaseManifest, retrieved: list[str], now: Any
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
        provenance=_provenance(model, manifest, retrieved, now),
    )


def _get(value: Any, name: str, default: Any = None) -> Any:
    return getattr(
        value, name, value.get(name, default) if isinstance(value, dict) else default
    )


def _extract_retrieval(response: Any) -> tuple[list[dict[str, object]], set[str]]:
    retrieved, cited = [], set()
    outputs = _get(response, "output", []) or []
    calls = [item for item in outputs if _get(item, "type") == "file_search_call"]
    if (
        _get(response, "status") != "completed"
        or len(calls) != 1
        or _get(calls[0], "status") != "completed"
    ):
        raise ProviderToolError
    for result in _get(calls[0], "results", []) or []:
        file_id = _get(result, "file_id")
        text, filename, score = (
            _get(result, "text"),
            _get(result, "filename"),
            _get(result, "score"),
        )
        if (
            not isinstance(file_id, str)
            or not file_id
            or not isinstance(text, str)
            or not text
            or not isinstance(filename, str)
            or not filename
            or not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not math.isfinite(score)
        ):
            raise ProviderToolError

    def annotations(items: Any) -> None:
        for annotation in items or []:
            citation = _get(annotation, "file_citation")
            file_id = _get(citation, "file_id") or _get(annotation, "file_id")
            if file_id:
                cited.add(file_id)

    for output in outputs:
        if _get(output, "type") == "message":
            for content in _get(output, "content", []) or []:
                if _get(content, "type") == "output_text":
                    annotations(_get(content, "annotations", []))
    results = _get(calls[0], "results", []) or []
    if not results:
        return [], cited
    if not cited:
        raise ProviderToolError
    remaining = _RETRIEVED_TEXT_TOTAL_BYTE_CAP
    for result in results:
        if remaining <= 0:
            break
        if _get(result, "file_id") not in cited:
            continue
        text = _truncate_utf8(
            _get(result, "text"), min(_RETRIEVED_TEXT_FILE_BYTE_CAP, remaining)
        )
        encoded = len(text.encode("utf-8"))
        if not text:
            continue
        retrieved.append(
            {
                "file_id": _get(result, "file_id"),
                "filename": _get(result, "filename"),
                "score": _get(result, "score"),
                "text": text,
            }
        )
        remaining -= encoded
    if not retrieved:
        raise ProviderToolError
    return retrieved, cited


def _synthesis_input(
    vuln_type: str, evidence: dict[str, str], contexts: list[dict[str, object]]
) -> tuple[str, list[dict[str, object]]]:
    selected: list[dict[str, object]] = []
    encoded = ""
    for context in contexts:
        try:
            candidate = triage_input(vuln_type, evidence, [*selected, context])
        except ValueError:
            continue
        selected.append(context)
        encoded = candidate
    if not selected:
        raise ProviderToolError
    return encoded, selected


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


def _provider(
    client: Any,
    finding: RawFinding,
    evidence: dict[str, str],
    manifest: KnowledgeBaseManifest,
    sleeper: Any,
    *,
    monotonic: Any = time.monotonic,
    jitter: Any = lambda: 0.0,
    retry_budget: float = _RETRY_BUDGET_SECONDS,
) -> tuple[ProviderAnalysis, set[str], set[str]]:
    model, deadline = _configured_model(), monotonic() + retry_budget
    for attempt in range(3):
        try:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise ProviderDeadlineError
            retrieval = client.responses.create(
                model=model,
                instructions=retrieval_instructions(finding.vuln_type.value),
                input=triage_input(finding.vuln_type.value, evidence),
                tools=[
                    {
                        "type": "file_search",
                        "vector_store_ids": manifest.vector_store_ids,
                        "max_num_results": 5,
                    }
                ],
                tool_choice="required",
                include=["file_search_call.results"],
                max_output_tokens=1200,
                max_tool_calls=1,
                timeout=min(_PROVIDER_TIMEOUT_SECONDS, remaining),
            )
            contexts, cited = _extract_retrieval(retrieval)
            if not contexts:
                return ProviderAnalysis(), set(), cited
            sources = source_map_by_file_id(manifest)
            context_file_ids = {item["file_id"] for item in contexts}
            if cited - context_file_ids or any(
                file_id not in sources
                or finding.vuln_type.value not in sources[file_id].vuln_types
                for file_id in context_file_ids
            ):
                raise ReferenceMismatchError
            synthesis_input, contexts = _synthesis_input(
                finding.vuln_type.value, evidence, contexts
            )
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise ProviderDeadlineError
            response = client.responses.parse(
                model=model,
                instructions=triage_instructions(finding.vuln_type.value),
                input=synthesis_input,
                text_format=ProviderAnalysis,
                max_output_tokens=1200,
                timeout=min(_PROVIDER_TIMEOUT_SECONDS, remaining),
            )
            if _get(response, "status") != "completed":
                raise ProviderToolError
            parsed = _get(response, "output_parsed")
            if not isinstance(parsed, ProviderAnalysis):
                parsed = ProviderAnalysis.model_validate(parsed)
            return parsed, {item["file_id"] for item in contexts}, cited
        except ValidationError:
            raise ProviderSchemaError from None
        except ReferenceMismatchError:
            raise
        except (
            APITimeoutError,
            RateLimitError,
            APIConnectionError,
            APIStatusError,
        ) as error:
            retryable = not isinstance(error, APIStatusError) or _status_retryable(
                error
            )
            if not retryable or attempt == 2:
                raise
            delay = _retry_after(error)
            if delay is None:
                delay = min(10.0, 2**attempt + max(0.0, float(jitter())))
            if monotonic() + delay > deadline:
                raise
            sleeper(delay)
        except OpenAIError as error:
            raise ProviderToolError from error
        except (
            AttributeError,
            IndexError,
            KeyError,
            LookupError,
            TypeError,
            ValueError,
        ) as error:
            raise ProviderToolError from error
    raise AssertionError("unreachable")


def _grounded(
    parsed: ProviderAnalysis,
    retrieved: set[str],
    cited: set[str],
    evidence: dict[str, str],
    vuln_type: str,
    model: str,
    manifest: KnowledgeBaseManifest,
    now: Any,
) -> AiResult:
    trusted = retrieved & cited
    claimed = {fid for claim in parsed.claims for fid in claim.reference_file_ids}
    sources = source_map_by_file_id(manifest)
    if any(
        fid not in sources or vuln_type not in sources[fid].vuln_types
        for fid in retrieved
    ):
        raise ReferenceMismatchError
    if not retrieved:
        return _insufficient(model, manifest, [], now)
    if not parsed.claims:
        return _insufficient(model, manifest, sorted(retrieved), now)
    if claimed - trusted:
        raise ReferenceMismatchError
    if not trusted:
        return _insufficient(model, manifest, sorted(retrieved), now)
    if any(
        set(claim.evidence_ids) - set(evidence) for claim in parsed.claims
    ) or not set(AiClaimType).issubset({claim.claim_type for claim in parsed.claims}):
        raise ProviderSchemaError
    if any(
        not claim.evidence_ids
        for claim in parsed.claims
        if claim.claim_type is AiClaimType.OBSERVATION
    ) or any(
        not claim.reference_file_ids
        for claim in parsed.claims
        if claim.claim_type is not AiClaimType.OBSERVATION
    ):
        raise ProviderSchemaError
    refs, ref_ids = [], {}
    for index, fid in enumerate(sorted(claimed), 1):
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
    claims = [
        AiClaim(
            claim_id=f"C{index}",
            claim_type=claim.claim_type,
            text=_redact(claim.text),
            evidence_ids=claim.evidence_ids,
            reference_ids=[ref_ids[fid] for fid in claim.reference_file_ids],
        )
        for index, claim in enumerate(parsed.claims, 1)
    ]

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
        label=AiLabel.INCONCLUSIVE,
        confidence=None,
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
        provenance=_provenance(model, manifest, sorted(retrieved), now),
    )


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
        ):
            if getattr(provenance, key) != bindings[key]:
                return None
        if (
            provenance.vector_store_ids != manifest.vector_store_ids
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
    manifest, default_cache, results = knowledge_base, None, []
    for finding in raw_run.findings:
        if finding.scan.status is ScanStatus.FAILED:
            ai = _not_requested(AiStatusReason.SCAN_FAILED)
        elif finding.scan.rule.label is RuleLabel.SAFE:
            ai = _not_requested(AiStatusReason.RULE_NOT_SUSPECTED)
        else:
            try:
                _load_environment()
                if manifest is None:
                    check_readiness()
                    manifest = load_knowledge_base()
                model, evidence = _configured_model(), _evidence(finding)
                key, bindings = (
                    _cache_key(finding, evidence, model, manifest),
                    _cache_bindings(evidence, model, manifest, finding.vuln_type.value),
                )
                active_cache = cache
                if active_cache is None:
                    default_cache = default_cache or SQLiteCache()
                    active_cache = default_cache
                row = _cache_get(active_cache, key)
                cached = (
                    _cached_result(row, bindings, manifest) if row is not None else None
                )
                if row is not None and cached is None:
                    _cache_delete(active_cache, key)
                if cached is not None:
                    ai = cached
                else:
                    owner = uuid.uuid4().hex
                    leased: bool | None = None
                    if isinstance(active_cache, SQLiteCache):
                        try:
                            leased = active_cache.acquire(key, owner, time.monotonic())
                        except (OSError, RuntimeError, sqlite3.Error):
                            # A cache outage must not discard a valid provider result.
                            leased = None
                    try:
                        if leased is False:
                            wait_deadline = time.monotonic() + retry_budget
                            while time.monotonic() < wait_deadline:
                                waited = _cached_result(
                                    _cache_get(active_cache, key), bindings, manifest
                                )
                                if waited is not None:
                                    ai = waited
                                    break
                                time.sleep(0.02)
                            else:
                                raise ProviderToolError
                        if leased is not False:
                            if client is None:
                                client = OpenAI(
                                    max_retries=0, timeout=_PROVIDER_TIMEOUT_SECONDS
                                )
                            parsed, retrieved, cited = _provider(
                                client,
                                finding,
                                evidence,
                                manifest,
                                sleeper,
                                monotonic=monotonic,
                                jitter=jitter,
                                retry_budget=retry_budget,
                            )
                            ai = _grounded(
                                parsed,
                                retrieved,
                                cited,
                                evidence,
                                finding.vuln_type.value,
                                model,
                                manifest,
                                now,
                            )
                            if ai.grounding_status in {
                                GroundingStatus.GROUNDED,
                                GroundingStatus.INSUFFICIENT,
                            }:
                                _cache_set(
                                    active_cache, key, _cache_envelope(ai, bindings)
                                )
                    finally:
                        if leased:
                            try:
                                active_cache.release(key, owner)
                            except (OSError, RuntimeError, sqlite3.Error):
                                pass
            except ReferenceMismatchError:
                ai = _failed("AI_REFERENCE_MISMATCH", False)
            except ProviderSchemaError:
                ai = _failed("AI_SCHEMA_INVALID", False)
            except ValidationError:
                ai = _failed("AI_SCHEMA_INVALID", False)
            except ProviderDeadlineError:
                ai = _failed("AI_TIMEOUT", True)
            except APITimeoutError:
                ai = _failed("AI_TIMEOUT", True)
            except (RateLimitError, APIConnectionError):
                ai = _failed("AI_PROVIDER_UNAVAILABLE", True)
            except APIStatusError as error:
                ai = _failed(
                    "AI_PROVIDER_UNAVAILABLE"
                    if _status_retryable(error)
                    else "AI_TOOL_FAILED",
                    _status_retryable(error),
                )
            except (
                ProviderToolError,
                OpenAIError,
                AttributeError,
                OSError,
                RuntimeError,
                sqlite3.Error,
                TypeError,
            ):
                ai = _failed("AI_TOOL_FAILED", False)
        results.append(
            ProcessedFinding(
                case_id=finding.case_id,
                finding_id=finding.finding_id,
                scanned_at=finding.scanned_at,
                vuln_type=finding.vuln_type,
                scan=finding.scan.model_copy(deep=True),
                ai=ai,
            )
        )
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
        completed_at=raw_run.completed_at or now(),
        status=status,
        findings=results,
    )
