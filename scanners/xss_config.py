"""Configuration for the bWAPP XSS scanner.

Lab-specific values (host, credentials, target list) are kept out of code so
the public repository never carries a real lab address or session
credentials -- they come from `.env` and a target-list JSON file instead.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

LOGIN_PATH = "/bWAPP/login.php"
DEFAULT_TARGETS_FILE = Path("configs/xss_lab_targets.example.json")
DEFAULT_HOST = "http://127.0.0.1"
DEFAULT_LOGIN = "bee"
DEFAULT_PASSWORD = "bug"

# Parameter and header names commonly accepted (and reflected) by the bWAPP
# XSS cases, used for a broad, single-shot injection per request.
INJECTABLE_PARAMS = (
    "firstname",
    "lastname",
    "title",
    "entry",
    "blog",
    "login",
    "password",
    "date",
)
INJECTABLE_HEADERS = ("User-Agent", "Referer", "bWAPP")


@dataclass(frozen=True)
class XSSScanConfig:
    host: str
    login: str
    password: str
    target_paths: tuple[str, ...]
    request_timeout: float = 5.0

    @property
    def login_url(self) -> str:
        return f"{self.host}{LOGIN_PATH}"

    @property
    def target_urls(self) -> tuple[str, ...]:
        return tuple(f"{self.host}{path}" for path in self.target_paths)


def load_target_paths(targets_file: Path) -> tuple[str, ...]:
    with targets_file.open(encoding="utf-8") as f:
        return tuple(json.load(f))


def load_config(targets_file: Path | None = None) -> XSSScanConfig:
    """Build a scan config from environment variables and a target list file.

    Call `dotenv.load_dotenv()` before this so `.env` values are visible.
    """
    return XSSScanConfig(
        host=os.getenv("XSS_LAB_HOST", DEFAULT_HOST).rstrip("/"),
        login=os.getenv("XSS_LAB_LOGIN", DEFAULT_LOGIN),
        password=os.getenv("XSS_LAB_PASSWORD", DEFAULT_PASSWORD),
        target_paths=load_target_paths(targets_file or DEFAULT_TARGETS_FILE),
    )
