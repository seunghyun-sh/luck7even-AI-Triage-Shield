"""Shared input and output models for scanner and AI results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ReflectionFinding:
    """One payload x target result from a reflection-based scan (e.g. XSS)."""

    target_url: str
    payload: str
    is_reflected: bool
    response_snippet: str

    def to_row(self) -> dict:
        return {
            "target_url": self.target_url,
            "payload": self.payload,
            "is_reflected": self.is_reflected,
            "response_snippet": self.response_snippet,
        }

    @staticmethod
    def fieldnames() -> list[str]:
        return ["target_url", "payload", "is_reflected", "response_snippet"]
