"""File-backed cache for AI-generated scanner payloads.

Generating payloads through an LLM costs time and money on every run, so a
successful batch is written under `data/raw/` (already git-ignored) and
reused by later scans until someone explicitly asks for a refresh.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PayloadCache:
    payloads: list[str]
    source: str
    generated_at: str
    model: str | None = None


def load(cache_path: Path) -> PayloadCache | None:
    """Return the cached payload batch, or None if missing/unreadable."""
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        return PayloadCache(**data)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def save(cache_path: Path, payloads: list[str], source: str, model: str | None = None) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = PayloadCache(
        payloads=payloads,
        source=source,
        generated_at=datetime.now(timezone.utc).isoformat(),
        model=model,
    )
    cache_path.write_text(json.dumps(asdict(cache), ensure_ascii=False, indent=2), encoding="utf-8")
