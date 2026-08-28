from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from analysis.grounding import (
    LOCAL_SOURCE_FILENAMES,
    GroundingUnavailableError,
    RetrievalMode,
    _manifest_digest,
    resolve_grounding,
)
from analysis.knowledge_base import KnowledgeBaseManifest


def _sha(value: bytes | str) -> str:
    return hashlib.sha256(
        value.encode() if isinstance(value, str) else value
    ).hexdigest()


def _manifest() -> KnowledgeBaseManifest:
    return KnowledgeBaseManifest.model_validate(
        {
            "schema_version": "1.0",
            "knowledge_base_version": "kb-v1",
            "vector_store_ids": ["vs_1"],
            "files": [
                {
                    "file_id": "file-xss",
                    "source_id": "owasp-xss-prevention",
                    "publisher": "OWASP",
                    "title": "XSS",
                    "version": "1",
                    "section": "XSS",
                    "canonical_url": "https://owasp.org/xss",
                    "document_sha256": "a" * 64,
                    "vuln_types": ["XSS"],
                    "language": "en",
                },
                {
                    "file_id": "file-sqli",
                    "source_id": "owasp-sqli-prevention",
                    "publisher": "OWASP",
                    "title": "SQLi",
                    "version": "1",
                    "section": "SQLi",
                    "canonical_url": "https://owasp.org/sqli",
                    "document_sha256": "b" * 64,
                    "vuln_types": ["SQLI"],
                    "language": "en",
                },
            ],
        }
    )


def _passage(source: dict[str, str], passage_id: str, text: str) -> dict[str, str]:
    return {
        "passage_id": passage_id,
        "source_id": source["source_id"],
        "file_id": source["file_id"],
        "document_sha256": source["document_sha256"],
        "section": source["section"],
        "text": text,
        "passage_sha256": _sha(text),
    }


def _pack(
    manifest: KnowledgeBaseManifest, *, xss_text: str = "XSS output encoding"
) -> dict:
    sources = [source.model_dump() for source in manifest.files]
    digest = _manifest_digest(manifest)
    return {
        "schema_version": "1.0",
        "pack_version": "pack-v1",
        "knowledge_base_version": "kb-v1",
        "manifest_digest": digest,
        "families": {
            "XSS": {
                "passages": [_passage(sources[0], "p-xss", xss_text)],
                "guidance": [
                    {
                        "guidance_id": "g-xss",
                        "source_ids": [sources[0]["source_id"]],
                        "impact": "Impact",
                        "recommendation": "Recommend",
                        "manual_check": "Check",
                    }
                ],
            },
            "SQLI": {
                "passages": [
                    _passage(
                        sources[1], "p-sqli", "SQL injection parameterized queries"
                    )
                ],
                "guidance": [
                    {
                        "guidance_id": "g-sqli",
                        "source_ids": [sources[1]["source_id"]],
                        "impact": "Impact",
                        "recommendation": "Recommend",
                        "manual_check": "Check",
                    }
                ],
            },
        },
    }


NOW = datetime(2026, 1, 15, tzinfo=timezone.utc)


def _write(path: Path, value: object) -> str:
    path.write_text(json.dumps(value), encoding="utf-8")
    return _sha(path.read_bytes())


def _resolve(
    family: str,
    manifest: KnowledgeBaseManifest,
    pack: Path,
    digest: str,
    **kwargs: object,
):
    return resolve_grounding(
        family,
        manifest,
        reviewed_pack_path=pack,
        reviewed_pack_sha256=digest,
        now=NOW,
        **kwargs,
    )


def test_valid_pack_cache_mode_and_deterministic_digest(tmp_path: Path) -> None:
    manifest = _manifest()
    pack = tmp_path / "pack.json"
    cache = tmp_path / "cache.json"
    html = b"<p>Cross site scripting needs output encoding</p>"
    manifest.files[0].document_sha256 = _sha(html)
    pack_digest = _write(pack, _pack(manifest))
    source = manifest.files[0].model_dump()
    cached = _passage(source, "cache-1", "Cross site scripting needs output encoding")
    root = tmp_path / "sources"
    root.mkdir()
    (root / LOCAL_SOURCE_FILENAMES[manifest.files[0].source_id]).write_bytes(html)
    _write(
        cache,
        {
            "schema_version": "1.0",
            "retrieval_policy_version": "local-html-v1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "pack_version": "pack-v1",
            "knowledge_base_version": "kb-v1",
            "manifest_digest": _manifest_digest(manifest),
            "families": {"XSS": [cached]},
        },
    )
    first = _resolve(
        "XSS",
        manifest,
        pack,
        pack_digest,
        retrieval_cache_path=cache,
        source_root=root,
    )
    second = _resolve(
        "XSS",
        manifest,
        pack,
        pack_digest,
        retrieval_cache_path=cache,
        source_root=root,
    )
    assert first.mode is RetrievalMode.REVIEWED_PACK_PLUS_VERIFIED_CACHE
    assert len(first.passages) == 2
    assert first.bundle_digest == second.bundle_digest


def test_pack_requires_external_digest_and_detects_guidance_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest()
    pack = tmp_path / "pack.json"
    digest = _write(pack, _pack(manifest))
    monkeypatch.delenv("AI_GROUNDING_PACK_SHA256", raising=False)
    with pytest.raises(GroundingUnavailableError):
        resolve_grounding(
            "XSS", manifest, reviewed_pack_path=pack, source_root=tmp_path
        )
    with pytest.raises(GroundingUnavailableError):
        _resolve("XSS", manifest, pack, "0" * 64, source_root=tmp_path)
    mutated = _pack(manifest)
    mutated["families"]["XSS"]["guidance"][0]["impact"] = "Changed"
    _write(pack, mutated)
    with pytest.raises(GroundingUnavailableError):
        _resolve("XSS", manifest, pack, digest, source_root=tmp_path)


def test_stale_or_non_source_cache_falls_back_to_local_search(tmp_path: Path) -> None:
    manifest = _manifest()
    html = b"<p>Cross site scripting requires output encoding for untrusted data.</p>"
    manifest.files[0].document_sha256 = _sha(html)
    pack = tmp_path / "pack.json"
    digest = _write(pack, _pack(manifest))
    root = tmp_path / "sources"
    root.mkdir()
    (root / LOCAL_SOURCE_FILENAMES["owasp-xss-prevention"]).write_bytes(html)
    source = manifest.files[0].model_dump()
    cache = tmp_path / "cache.json"
    for created_at, text in (
        (
            "2025-12-01T00:00:00+00:00",
            "Cross site scripting requires output encoding for untrusted data.",
        ),
        ("2026-01-01T00:00:00+00:00", "self-hashed but not source text"),
    ):
        _write(
            cache,
            {
                "schema_version": "1.0",
                "retrieval_policy_version": "local-html-v1",
                "created_at": created_at,
                "pack_version": "pack-v1",
                "knowledge_base_version": "kb-v1",
                "manifest_digest": _manifest_digest(manifest),
                "families": {"XSS": [_passage(source, "cached", text)]},
            },
        )
        bundle = _resolve(
            "XSS",
            manifest,
            pack,
            digest,
            retrieval_cache_path=cache,
            source_root=root,
        )
        assert bundle.mode is RetrievalMode.REVIEWED_PACK_PLUS_LOCAL_SEARCH


def test_source_sha_mismatch_rejects_cache_and_local_search(tmp_path: Path) -> None:
    manifest = _manifest()
    html = b"<p>Cross site scripting requires output encoding</p>"
    manifest.files[0].document_sha256 = _sha(html)
    pack = tmp_path / "pack.json"
    digest = _write(pack, _pack(manifest))
    root = tmp_path / "sources"
    root.mkdir()
    source_path = root / LOCAL_SOURCE_FILENAMES["owasp-xss-prevention"]
    source_path.write_bytes(b"<p>tampered source</p>")
    source = manifest.files[0].model_dump()
    cache = tmp_path / "cache.json"
    _write(
        cache,
        {
            "schema_version": "1.0",
            "retrieval_policy_version": "local-html-v1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "pack_version": "pack-v1",
            "knowledge_base_version": "kb-v1",
            "manifest_digest": _manifest_digest(manifest),
            "families": {
                "XSS": [
                    _passage(
                        source,
                        "cached",
                        "Cross site scripting requires output encoding",
                    )
                ]
            },
        },
    )
    bundle = _resolve(
        "XSS", manifest, pack, digest, retrieval_cache_path=cache, source_root=root
    )
    assert bundle.mode is RetrievalMode.REVIEWED_PACK


def test_corrupt_cache_falls_back_to_verified_local_html(tmp_path: Path) -> None:
    manifest = _manifest()
    html = b"<p>Cross site scripting requires output encoding for untrusted data.</p>"
    manifest.files[0].document_sha256 = _sha(
        html
    )  # Pydantic models are not used as immutable manifests.
    pack = tmp_path / "pack.json"
    pack_digest = _write(pack, _pack(manifest))
    cache = tmp_path / "cache.json"
    cache.write_text("not json", encoding="utf-8")
    root = tmp_path / "sources"
    root.mkdir()
    (root / LOCAL_SOURCE_FILENAMES[manifest.files[0].source_id]).write_bytes(html)
    bundle = _resolve(
        "XSS",
        manifest,
        pack,
        pack_digest,
        retrieval_cache_path=cache,
        source_root=root,
    )
    assert bundle.mode is RetrievalMode.REVIEWED_PACK_PLUS_LOCAL_SEARCH
    assert len(bundle.passages) == 2


def test_sha_mismatch_rejects_local_but_keeps_pack(tmp_path: Path) -> None:
    manifest = _manifest()
    pack = tmp_path / "pack.json"
    pack_digest = _write(pack, _pack(manifest))
    root = tmp_path / "sources"
    root.mkdir()
    (root / LOCAL_SOURCE_FILENAMES[manifest.files[0].source_id]).write_text(
        "<p>XSS output encoding</p>", encoding="utf-8"
    )
    bundle = _resolve(
        "XSS",
        manifest,
        pack,
        pack_digest,
        retrieval_cache_path=tmp_path / "missing",
        source_root=root,
    )
    assert bundle.mode is RetrievalMode.REVIEWED_PACK


@pytest.mark.parametrize("mutate", ["manifest_digest", "source_id", "passage_sha256"])
def test_bad_pack_binding_raises(tmp_path: Path, mutate: str) -> None:
    manifest = _manifest()
    value = _pack(manifest)
    if mutate == "manifest_digest":
        value[mutate] = "0" * 64
    elif mutate == "source_id":
        value["families"]["XSS"]["passages"][0][mutate] = "unknown"
    else:
        value["families"]["XSS"]["passages"][0][mutate] = "0" * 64
    path = tmp_path / "pack.json"
    digest = _write(path, value)
    with pytest.raises(GroundingUnavailableError):
        _resolve("XSS", manifest, path, digest, source_root=tmp_path)


def test_symlink_pack_and_path_escape_are_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    target = tmp_path / "target.json"
    digest = _write(target, _pack(manifest))
    link = tmp_path / "pack.json"
    link.symlink_to(target)
    with pytest.raises(GroundingUnavailableError):
        _resolve("XSS", manifest, link, digest, source_root=tmp_path)
    with pytest.raises(GroundingUnavailableError):
        _resolve(
            "XSS",
            manifest,
            tmp_path / "subdir" / ".." / "target.json",
            digest,
            source_root=tmp_path,
        )
    parent = tmp_path / "parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(GroundingUnavailableError):
        _resolve("XSS", manifest, parent / "target.json", digest, source_root=tmp_path)


def test_dedupe_caps_order_family_separation_and_unknown_family(tmp_path: Path) -> None:
    manifest = _manifest()
    value = _pack(manifest)
    source = manifest.files[0].model_dump()
    value["families"]["XSS"]["passages"] = [
        _passage(source, f"p-{number}", f"XSS output encoding {number}")
        for number in range(6)
    ]
    cache = {
        "schema_version": "1.0",
        "retrieval_policy_version": "local-html-v1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "pack_version": "pack-v1",
        "knowledge_base_version": "kb-v1",
        "manifest_digest": _manifest_digest(manifest),
        "families": {"XSS": [_passage(source, "duplicate", "XSS output encoding 0")]},
    }
    pack_path, cache_path = tmp_path / "pack.json", tmp_path / "cache.json"
    digest = _write(pack_path, value)
    _write(cache_path, cache)
    xss = _resolve(
        "XSS",
        manifest,
        pack_path,
        digest,
        retrieval_cache_path=cache_path,
        source_root=tmp_path,
    )
    sqli = _resolve("SQLI", manifest, pack_path, digest, source_root=tmp_path)
    assert len(xss.passages) == 6
    assert [passage.passage_id for passage in xss.passages] == [
        f"p-{number}" for number in range(6)
    ]
    assert all(
        passage.source_id != sqli.passages[0].source_id for passage in xss.passages
    )
    with pytest.raises(GroundingUnavailableError):
        _resolve("RCE", manifest, pack_path, digest, source_root=tmp_path)
