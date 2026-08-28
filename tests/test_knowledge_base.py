import json
from pathlib import Path

import pytest

from analysis.knowledge_base import (
    KnowledgeBaseError,
    KnowledgeBaseManifest,
    load_knowledge_base,
    source_map_by_file_id,
)


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "knowledge_base_version": "owasp-top-10-2021",
        "vector_store_ids": ["vs_private_1"],
        "files": [
            {
                "file_id": "file_private_1",
                "source_id": "owasp-a03-injection",
                "publisher": "OWASP",
                "title": "OWASP Top 10:2021",
                "version": "2021",
                "section": "A03",
                "canonical_url": "https://owasp.org/Top10/A03_2021-Injection/",
                "document_sha256": "a" * 64,
                "vuln_types": ["XSS", "SQLI"],
                "language": "en",
            }
        ],
    }


def write_manifest(path: Path, content: object) -> None:
    path.write_text(json.dumps(content), encoding="utf-8")


def test_loads_valid_manifest(tmp_path: Path) -> None:
    path = tmp_path / "knowledge-base.local.json"
    write_manifest(path, valid_manifest())

    manifest = load_knowledge_base(path)

    assert manifest.files[0].file_id == "file_private_1"


def test_missing_manifest_has_safe_stable_error(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.json"

    with pytest.raises(
        KnowledgeBaseError, match="^Knowledge base manifest is unavailable\\.$"
    ):
        load_knowledge_base(missing_path)


def test_malformed_manifest_has_safe_stable_error(tmp_path: Path) -> None:
    path = tmp_path / "knowledge-base.local.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(
        KnowledgeBaseError, match="^Knowledge base manifest is malformed\\.$"
    ):
        load_knowledge_base(path)


def test_rejects_duplicate_file_and_source_ids() -> None:
    content = valid_manifest()
    duplicate = dict(content["files"][0])  # type: ignore[index]
    content["files"] = [content["files"][0], duplicate]  # type: ignore[index]

    with pytest.raises(ValueError):
        KnowledgeBaseManifest.model_validate(content)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canonical_url", "http://owasp.org/Top10/"),
        ("canonical_url", "https://example.com/Top10/"),
        ("document_sha256", "A" * 64),
    ],
)
def test_rejects_untrusted_url_and_invalid_hash(field: str, value: str) -> None:
    content = valid_manifest()
    content["files"][0][field] = value  # type: ignore[index]

    with pytest.raises(ValueError):
        KnowledgeBaseManifest.model_validate(content)


def test_rejects_symlink_manifest(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    link = tmp_path / "knowledge-base.local.json"
    write_manifest(target, valid_manifest())
    link.symlink_to(target)

    with pytest.raises(
        KnowledgeBaseError,
        match="^Knowledge base manifest must not be a symbolic link\\.$",
    ):
        load_knowledge_base(link)


def test_source_map_by_file_id() -> None:
    manifest = KnowledgeBaseManifest.model_validate(valid_manifest())

    source_map = source_map_by_file_id(manifest)

    assert source_map == {"file_private_1": manifest.files[0]}
