"""Shared input and output models for scanner and AI results."""

from __future__ import annotations

from dataclasses import dataclass

# Rule-based first-pass verdict labels (`rule_label`), ordered by severity.
NOT_REFLECTED = "NOT_REFLECTED"
REFLECTED_ESCAPED = "REFLECTED_ESCAPED"
REFLECTED_UNSANITIZED = "REFLECTED_UNSANITIZED"


@dataclass
class Finding:
    """One rule-verdict record produced by a scanner, ready for `data/raw/`."""

    finding_id: str
    vuln_type: str
    url: str
    parameter: str
    payload: str
    rule_label: str
    response_body: str

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "rule_label": self.rule_label,
            "response_body": self.response_body,
        }
