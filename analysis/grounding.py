"""Deterministic, locally verified grounding bundle resolution."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
)

from analysis.knowledge_base import KnowledgeBaseManifest, KnowledgeSource

DEFAULT_REVIEWED_PACK_PATH = Path("data/cache/grounding-packs.json")
DEFAULT_RETRIEVAL_CACHE_PATH = Path("data/cache/grounding-retrieval-cache.json")
DEFAULT_SOURCE_ROOT = Path("data/cache/knowledge-base-sources")
PACK_SCHEMA_VERSION = "1.0"
RETRIEVAL_POLICY_VERSION = "local-html-v1"
MAX_PASSAGES = 6
MAX_PASSAGE_CHARS = 1600
MAX_GUIDANCE_CHARS = 1200
MAX_BUNDLE_BYTES = 8 * 1024
MAX_CACHE_AGE = timedelta(days=30)

# These names are deliberately not derived from manifest data: a manifest must not
# choose arbitrary paths beneath the private source directory.
LOCAL_SOURCE_FILENAMES = {
    "owasp-xss-prevention": "owasp-xss-prevention.html",
    "owasp-sqli-prevention": "owasp-sqli-prevention.html",
    "owasp-wstg-reflected-xss": "owasp-wstg-reflected-xss.html",
    "owasp-wstg-sqli": "owasp-wstg-sqli.html",
    "kisa-secure-coding-2021": "kisa-secure-coding-2021.pdf",
}

_FAMILY_KEYWORDS = {
    "XSS": (
        "cross site scripting",
        "xss",
        "output encoding",
        "html encoding",
        "untrusted data",
    ),
    "SQLI": (
        "sql injection",
        "sqli",
        "parameterized",
        "prepared statement",
        "database query",
    ),
}


class GroundingUnavailableError(Exception):
    """Raised when the mandatory reviewed grounding pack cannot be trusted."""


class RetrievalMode(str, Enum):
    REVIEWED_PACK = "REVIEWED_PACK"
    REVIEWED_PACK_PLUS_VERIFIED_CACHE = "REVIEWED_PACK_PLUS_VERIFIED_CACHE"
    REVIEWED_PACK_PLUS_LOCAL_SEARCH = "REVIEWED_PACK_PLUS_LOCAL_SEARCH"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class GroundingPassage(_StrictModel):
    passage_id: StrictStr = Field(min_length=1)
    source_id: StrictStr = Field(min_length=1)
    file_id: StrictStr = Field(min_length=1)
    section: StrictStr = Field(min_length=1)
    text: StrictStr = Field(min_length=1, max_length=MAX_PASSAGE_CHARS)
    passage_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class GuidanceTemplate(_StrictModel):
    guidance_id: StrictStr = Field(min_length=1)
    family: Literal["XSS", "SQLI"]
    source_ids: tuple[StrictStr, ...] = Field(min_length=1)
    impact: StrictStr = Field(min_length=1, max_length=MAX_GUIDANCE_CHARS)
    recommendation: StrictStr = Field(min_length=1, max_length=MAX_GUIDANCE_CHARS)
    manual_check: StrictStr = Field(min_length=1, max_length=MAX_GUIDANCE_CHARS)

    @field_validator("impact", "recommendation", "manual_check")
    @classmethod
    def no_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("guidance text must not be blank")
        return value


class GroundingBundle(_StrictModel):
    family: Literal["XSS", "SQLI"]
    mode: RetrievalMode
    pack_version: StrictStr = Field(min_length=1)
    kb_version: StrictStr = Field(min_length=1)
    manifest_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    passages: tuple[GroundingPassage, ...] = Field(
        min_length=1, max_length=MAX_PASSAGES
    )
    guidance: Mapping[StrictStr, GuidanceTemplate]
    bundle_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    retrieved_file_ids: tuple[StrictStr, ...]


class _RawPassage(_StrictModel):
    passage_id: StrictStr = Field(min_length=1)
    source_id: StrictStr = Field(min_length=1)
    file_id: StrictStr = Field(min_length=1)
    document_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    section: StrictStr = Field(min_length=1)
    text: StrictStr = Field(min_length=1, max_length=MAX_PASSAGE_CHARS)
    passage_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class _RawGuidance(_StrictModel):
    guidance_id: StrictStr = Field(min_length=1)
    source_ids: list[StrictStr] = Field(min_length=1)
    impact: StrictStr = Field(min_length=1, max_length=MAX_GUIDANCE_CHARS)
    recommendation: StrictStr = Field(min_length=1, max_length=MAX_GUIDANCE_CHARS)
    manual_check: StrictStr = Field(min_length=1, max_length=MAX_GUIDANCE_CHARS)

    @field_validator("impact", "recommendation", "manual_check")
    @classmethod
    def no_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("guidance text must not be blank")
        return value


class _PackFamily(_StrictModel):
    passages: list[_RawPassage] = Field(min_length=1)
    guidance: list[_RawGuidance] = Field(min_length=1)


class _ReviewedPack(_StrictModel):
    schema_version: Literal[PACK_SCHEMA_VERSION]
    pack_version: StrictStr = Field(min_length=1)
    knowledge_base_version: StrictStr = Field(min_length=1)
    manifest_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    families: Mapping[Literal["XSS", "SQLI"], _PackFamily]


class _RetrievalCache(_StrictModel):
    schema_version: Literal[PACK_SCHEMA_VERSION]
    retrieval_policy_version: Literal[RETRIEVAL_POLICY_VERSION]
    created_at: StrictStr = Field(min_length=1)
    pack_version: StrictStr = Field(min_length=1)
    knowledge_base_version: StrictStr = Field(min_length=1)
    manifest_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    families: Mapping[Literal["XSS", "SQLI"], list[_RawPassage]]

    @field_validator("created_at")
    @classmethod
    def valid_created_at(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("created_at must be ISO-8601") from None
        if parsed.tzinfo is None:
            raise ValueError("created_at must include a timezone")
        return value


class _ParagraphParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self.paragraphs: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"p", "li", "h1", "h2", "h3", "h4"}:
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"p", "li", "h1", "h2", "h3", "h4"} and self._depth:
            self._depth -= 1
            if not self._depth:
                text = " ".join("".join(self._parts).split())
                self._parts.clear()
                if text:
                    self.paragraphs.append(text)

    def handle_data(self, data: str) -> None:
        if self._depth:
            self._parts.append(data)


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _manifest_digest(manifest: KnowledgeBaseManifest) -> str:
    return _canonical_digest(manifest.model_dump(mode="json"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_default_path(path: Path, default: Path) -> bool:
    return path == default


def _safe_regular_path(path: Path, *, default: Path | None = None) -> Path | None:
    """Reject traversal and symbolic links in a file path and its ancestors."""
    try:
        if ".." in path.parts:
            return None
        if default is not None and _is_default_path(path, default):
            root = Path.cwd() / "data" / "cache"
            candidate = Path.cwd() / path
            if candidate != root and root not in candidate.parents:
                return None
        candidate = path if path.is_absolute() else Path.cwd() / path
        relative = candidate.relative_to(candidate.anchor)
        current = Path(candidate.anchor)
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return None
        if not candidate.is_file():
            return None
        return candidate
    except OSError:
        return None


def _safe_directory(path: Path) -> Path | None:
    if ".." in path.parts:
        return None
    directory = path if path.is_absolute() else Path.cwd() / path
    try:
        relative = directory.relative_to(directory.anchor)
        current = Path(directory.anchor)
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return None
        return directory if directory.is_dir() else None
    except OSError:
        return None


def _read_regular_bytes(path: Path, *, default: Path | None = None) -> bytes | None:
    safe = _safe_regular_path(path, default=default)
    if safe is None:
        return None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(safe, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return None
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 64 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError:
        return None


def _load_json(
    path: Path, *, default: Path | None = None
) -> tuple[object, bytes] | None:
    content = _read_regular_bytes(path, default=default)
    if content is None:
        return None
    try:
        return json.loads(content.decode("utf-8")), content
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _trusted_pack_digest(value: str | None) -> str | None:
    digest = value if value is not None else os.environ.get("AI_GROUNDING_PACK_SHA256")
    if digest is None or len(digest) != 64:
        return None
    try:
        int(digest, 16)
    except ValueError:
        return None
    return digest if digest == digest.lower() else None


def _validated_passages(
    raw_passages: Sequence[_RawPassage],
    *,
    family: str,
    sources: Mapping[str, KnowledgeSource],
) -> tuple[GroundingPassage, ...] | None:
    validated: list[GroundingPassage] = []
    ids: set[str] = set()
    for raw in raw_passages:
        source = sources.get(raw.source_id)
        if (
            source is None
            or source.file_id != raw.file_id
            or source.document_sha256 != raw.document_sha256
            or family not in source.vuln_types
            or _sha256(raw.text.encode("utf-8")) != raw.passage_sha256
            or raw.passage_id in ids
        ):
            return None
        ids.add(raw.passage_id)
        try:
            validated.append(
                GroundingPassage(
                    passage_id=raw.passage_id,
                    source_id=source.source_id,
                    file_id=source.file_id,
                    section=source.section,
                    text=raw.text,
                    passage_sha256=raw.passage_sha256,
                )
            )
        except ValidationError:
            return None
    return tuple(validated)


def _validated_guidance(
    raw_guidance: Sequence[_RawGuidance],
    *,
    family: Literal["XSS", "SQLI"],
    sources: Mapping[str, KnowledgeSource],
) -> Mapping[str, GuidanceTemplate] | None:
    guidance: dict[str, GuidanceTemplate] = {}
    for raw in raw_guidance:
        if raw.guidance_id in guidance or any(
            source_id not in sources or family not in sources[source_id].vuln_types
            for source_id in raw.source_ids
        ):
            return None
        try:
            guidance[raw.guidance_id] = GuidanceTemplate(
                guidance_id=raw.guidance_id,
                family=family,
                source_ids=tuple(raw.source_ids),
                impact=raw.impact,
                recommendation=raw.recommendation,
                manual_check=raw.manual_check,
            )
        except ValidationError:
            return None
    return guidance


def _read_reviewed_pack(
    path: Path,
    manifest: KnowledgeBaseManifest,
    digest: str,
    family: Literal["XSS", "SQLI"],
    trusted_digest: str | None,
) -> tuple[_ReviewedPack, tuple[GroundingPassage, ...], Mapping[str, GuidanceTemplate]]:
    loaded = _load_json(path, default=DEFAULT_REVIEWED_PACK_PATH)
    if loaded is None or trusted_digest is None or _sha256(loaded[1]) != trusted_digest:
        raise GroundingUnavailableError("Reviewed grounding pack is unavailable.")
    raw, _ = loaded
    try:
        pack = _ReviewedPack.model_validate(raw)
    except ValidationError:
        raise GroundingUnavailableError(
            "Reviewed grounding pack is unavailable."
        ) from None
    if (
        pack.knowledge_base_version != manifest.knowledge_base_version
        or pack.manifest_digest != digest
        or family not in pack.families
    ):
        raise GroundingUnavailableError("Reviewed grounding pack is unavailable.")
    sources = {source.source_id: source for source in manifest.files}
    entry = pack.families[family]
    passages = _validated_passages(entry.passages, family=family, sources=sources)
    guidance = _validated_guidance(entry.guidance, family=family, sources=sources)
    if not passages or guidance is None:
        raise GroundingUnavailableError("Reviewed grounding pack is unavailable.")
    return pack, passages, guidance


def _read_cache(
    path: Path,
    manifest: KnowledgeBaseManifest,
    digest: str,
    pack: _ReviewedPack,
    family: Literal["XSS", "SQLI"],
    source_root: Path,
    now: datetime,
) -> tuple[GroundingPassage, ...] | None:
    loaded = _load_json(path, default=DEFAULT_RETRIEVAL_CACHE_PATH)
    if loaded is None:
        return None
    raw, _ = loaded
    try:
        cache = _RetrievalCache.model_validate(raw)
    except ValidationError:
        return None
    if (
        cache.pack_version != pack.pack_version
        or cache.knowledge_base_version != manifest.knowledge_base_version
        or cache.manifest_digest != digest
        or family not in cache.families
    ):
        return None
    created_at = datetime.fromisoformat(cache.created_at.replace("Z", "+00:00"))
    if now - created_at > MAX_CACHE_AGE or created_at > now:
        return None
    passages = _validated_passages(
        cache.families[family],
        family=family,
        sources={source.source_id: source for source in manifest.files},
    )
    if passages is None:
        return None
    source_paragraphs = _verified_source_paragraphs(
        source_root, manifest, {passage.source_id for passage in passages}
    )
    if source_paragraphs is None:
        return None
    if any(
        passage.text not in source_paragraphs.get(passage.source_id, ())
        for passage in passages
    ):
        return None
    return passages


def _verified_source_paragraphs(
    source_root: Path,
    manifest: KnowledgeBaseManifest,
    required_source_ids: set[str],
) -> Mapping[str, tuple[str, ...]] | None:
    root = _safe_directory(source_root)
    if root is None:
        return None
    if _is_default_path(source_root, DEFAULT_SOURCE_ROOT):
        cache = Path.cwd() / "data" / "cache"
        if root != cache and cache not in root.parents:
            return None
    paragraphs: dict[str, tuple[str, ...]] = {}
    for source in manifest.files:
        filename = LOCAL_SOURCE_FILENAMES.get(source.source_id)
        if source.source_id not in required_source_ids:
            continue
        if filename is None or not filename.endswith(".html"):
            return None
        content = _read_regular_bytes(root / filename)
        if content is None or _sha256(content) != source.document_sha256:
            return None
        try:
            parser = _ParagraphParser()
            parser.feed(content.decode("utf-8"))
            parser.close()
        except (UnicodeDecodeError, ValueError):
            return None
        paragraphs[source.source_id] = tuple(parser.paragraphs)
    return paragraphs


def _local_passages(
    source_root: Path, manifest: KnowledgeBaseManifest, family: Literal["XSS", "SQLI"]
) -> tuple[GroundingPassage, ...]:
    # A source-root injection is for isolated tests; the default root is cache-bound.
    root = _safe_directory(source_root)
    if root is None:
        return ()
    if _is_default_path(source_root, DEFAULT_SOURCE_ROOT):
        cache = Path.cwd() / "data" / "cache"
        if root != cache and cache not in root.parents:
            return ()
    candidates: list[tuple[int, str, KnowledgeSource, str]] = []
    keywords = _FAMILY_KEYWORDS[family]
    for source in manifest.files:
        filename = LOCAL_SOURCE_FILENAMES.get(source.source_id)
        if (
            family not in source.vuln_types
            or filename is None
            or not filename.endswith(".html")
        ):
            continue
        content = _read_regular_bytes(root / filename)
        if content is None:
            continue
        if _sha256(content) != source.document_sha256:
            continue
        try:
            parser = _ParagraphParser()
            parser.feed(content.decode("utf-8"))
            parser.close()
        except (UnicodeDecodeError, ValueError):
            continue
        for index, text in enumerate(parser.paragraphs):
            text = text[:MAX_PASSAGE_CHARS]
            lowered = text.lower()
            score = sum(keyword in lowered for keyword in keywords)
            if score:
                candidates.append(
                    (-score, source.source_id, source, f"{index:04d}:{text}")
                )
    candidates.sort(key=lambda item: (item[0], item[1], item[3]))
    passages: list[GroundingPassage] = []
    for _, _, source, indexed_text in candidates[:2]:
        index, text = indexed_text.split(":", 1)
        text_hash = _sha256(text.encode("utf-8"))
        passages.append(
            GroundingPassage(
                passage_id=f"local-{source.source_id}-{index}-{text_hash[:12]}",
                source_id=source.source_id,
                file_id=source.file_id,
                section=source.section,
                text=text,
                passage_sha256=text_hash,
            )
        )
    return tuple(passages)


def _merge(
    primary: tuple[GroundingPassage, ...], supplement: tuple[GroundingPassage, ...]
) -> tuple[GroundingPassage, ...]:
    merged: list[GroundingPassage] = []
    seen: set[tuple[str, str]] = set()
    encoded = 0
    for passage in (*primary, *supplement):
        key = (passage.source_id, passage.passage_sha256)
        passage_bytes = len(passage.text.encode("utf-8"))
        if (
            key in seen
            or len(merged) >= MAX_PASSAGES
            or encoded + passage_bytes > MAX_BUNDLE_BYTES
        ):
            continue
        seen.add(key)
        encoded += passage_bytes
        merged.append(passage)
    return tuple(merged)


def resolve_grounding(
    family: str,
    manifest: KnowledgeBaseManifest,
    *,
    reviewed_pack_path: str | Path = DEFAULT_REVIEWED_PACK_PATH,
    reviewed_pack_sha256: str | None = None,
    retrieval_cache_path: str | Path = DEFAULT_RETRIEVAL_CACHE_PATH,
    source_root: str | Path = DEFAULT_SOURCE_ROOT,
    now: datetime | None = None,
) -> GroundingBundle:
    """Resolve a reviewed pack and optionally verified deterministic supplements."""
    if family not in {"XSS", "SQLI"}:
        raise GroundingUnavailableError("Grounding family is unsupported.")
    current_time = now if now is not None else datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise GroundingUnavailableError("Grounding time must include a timezone.")
    typed_family: Literal["XSS", "SQLI"] = family  # type: ignore[assignment]
    digest = _manifest_digest(manifest)
    pack, reviewed, guidance = _read_reviewed_pack(
        Path(reviewed_pack_path),
        manifest,
        digest,
        typed_family,
        _trusted_pack_digest(reviewed_pack_sha256),
    )
    cache = _read_cache(
        Path(retrieval_cache_path),
        manifest,
        digest,
        pack,
        typed_family,
        Path(source_root),
        current_time,
    )
    mode = RetrievalMode.REVIEWED_PACK
    supplement: tuple[GroundingPassage, ...] = ()
    if cache:
        supplement = cache
        mode = RetrievalMode.REVIEWED_PACK_PLUS_VERIFIED_CACHE
    else:
        local = _local_passages(Path(source_root), manifest, typed_family)
        if local:
            supplement = local
            mode = RetrievalMode.REVIEWED_PACK_PLUS_LOCAL_SEARCH
    passages = _merge(reviewed, supplement)
    retrieved_file_ids = tuple(dict.fromkeys(passage.file_id for passage in passages))
    digest_payload = {
        "family": typed_family,
        "mode": mode.value,
        "pack_version": pack.pack_version,
        "kb_version": manifest.knowledge_base_version,
        "manifest_digest": digest,
        "passages": [passage.model_dump(mode="json") for passage in passages],
        "guidance": {
            key: value.model_dump(mode="json")
            for key, value in sorted(guidance.items())
        },
        "retrieved_file_ids": retrieved_file_ids,
    }
    return GroundingBundle(
        family=typed_family,
        mode=mode,
        pack_version=pack.pack_version,
        kb_version=manifest.knowledge_base_version,
        manifest_digest=digest,
        passages=passages,
        guidance=guidance,
        bundle_digest=_canonical_digest(digest_payload),
        retrieved_file_ids=retrieved_file_ids,
    )
