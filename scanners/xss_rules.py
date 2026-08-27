"""Rule-based reflection classifier: the scanner's first-pass (`rule_label`) verdict.

Three states instead of a plain yes/no so the AI triage stage later has a
head start: a payload that comes back HTML-escaped is very likely *not*
exploitable, even though it technically "reflected".
"""

from __future__ import annotations

import html

from analysis.models import NOT_REFLECTED, REFLECTED_ESCAPED, REFLECTED_UNSANITIZED

_SEVERITY = {NOT_REFLECTED: 0, REFLECTED_ESCAPED: 1, REFLECTED_UNSANITIZED: 2}


def classify_reflection(payload: str, response_body: str) -> str:
    """Classify how (or whether) a payload came back in a response body."""
    if payload and payload in response_body:
        return REFLECTED_UNSANITIZED
    escaped = html.escape(payload)
    if escaped and escaped != payload and escaped in response_body:
        return REFLECTED_ESCAPED
    return NOT_REFLECTED


def most_severe(*results: tuple[str, str]) -> tuple[str, str]:
    """Given multiple (label, body) results for the same test, keep the worst one."""
    return max(results, key=lambda pair: _SEVERITY[pair[0]])
