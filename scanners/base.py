"""Shared scanner interfaces and HTTP evidence helpers."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

import requests


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
