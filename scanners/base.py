"""Shared scanner interfaces and HTTP evidence helpers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

import requests


def safe_header_value(value: str) -> str:
    """Make a value safe to send as a raw HTTP header.

    HTTP headers must be Latin-1 encodable; AI-generated payloads can contain
    Korean text, emoji, etc. that raise UnicodeEncodeError deep inside
    `http.client` and crash the whole scan. Percent-encode anything that
    isn't Latin-1 safe instead of sending it as-is -- a real header could
    never carry that text unescaped either.
    """
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        return quote(value, safe="")


class LabSession:
    """Authenticated `requests.Session` wrapper for an isolated lab target."""

    def __init__(self, host: str, timeout: float = 5.0) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()

    def login(self, login_path: str, credentials: dict, success_markers: Iterable[str]) -> bool:
        """POST credentials to `login_path` and report whether login looked successful."""
        response = self._session.post(f"{self.host}{login_path}", data=credentials, timeout=self.timeout)
        return any(marker in response.url or marker in response.text for marker in success_markers)

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self._session.post(url, **kwargs)


def write_csv(path: str | Path, rows: list[dict], fieldnames: list[str]) -> None:
    """Write scan result rows as CSV, creating parent directories as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: str | Path, rows: list[dict]) -> None:
    """Write scan result rows as JSON Lines, creating parent directories as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False))
            f.write("\n")
