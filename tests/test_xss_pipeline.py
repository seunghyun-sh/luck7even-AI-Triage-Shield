from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
import requests

from analysis.models import RequestPolicy, ScanStatus, TargetCase, TargetInput, VulnType
from scanners import base, xss_report
from scanners.pipeline import xss


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.elapsed = timedelta(milliseconds=7)

    @property
    def is_redirect(self):
        return 300 <= self.status_code < 400 and "Location" in self.headers


class FakeSession:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _target(*, stored=False, pre_auth=False, method="GET"):
    return TargetCase(
        case_id="stored-case" if stored else "reflected-case",
        vuln_type=VulnType.XSS,
        path="/reviews" if stored else "/search",
        method=method,
        input=TargetInput(
            location="form" if method == "POST" else "query",
            parameters={"content" if method == "POST" else "q": ""},
            attack_parameter="content" if method == "POST" else "q",
        ),
        requires_pre_auth=pre_auth,
        auth_profile="lab-auth" if pre_auth else None,
        payload_profile="profile",
        manual_verification_profile="xss-stored" if stored else "none",
    )


def _context(tmp_path, *, follow_redirects=True):
    return SimpleNamespace(
        base_url="http://authorized.test:5001",
        request_policy=RequestPolicy(
            timeout_seconds=2, follow_redirects=follow_redirects
        ),
        responses_dir=tmp_path / "responses",
        resolve_auth_profile=lambda _: {"Authorization": "Bearer exact-secret"},
    )


def _scan_one(session, context, target, payload="<script>alert(1)</script>"):
    return xss._scan_one(session, context, target, "payload-1", payload, "XSS-000001")


@pytest.mark.parametrize(
    "location",
    [
        "https://outside.test/steal",
        "http://authorized.test:5000/other-port",
        "https://authorized.test:5001/scheme-downgrade",
        "http://authorized.test:not-a-port/invalid",
        "http://[invalid-ipv6/redirect",
    ],
)
def test_redirect_to_other_origin_fails_without_forwarding_auth(tmp_path, location):
    session = FakeSession([FakeResponse(302, headers={"Location": location})])

    finding = _scan_one(session, _context(tmp_path), _target(pre_auth=True))

    assert finding.scan.status is ScanStatus.FAILED
    assert finding.scan.error.code == "SCAN_REDIRECT_BLOCKED"
    assert len(session.calls) == 1
    assert session.calls[0][1] == "http://authorized.test:5001/search"
    assert session.calls[0][2]["headers"] == {"Authorization": "Bearer exact-secret"}


@pytest.mark.parametrize("status", [307, 308])
def test_safe_request_preserves_method_and_body_for_307_and_308(status):
    session = FakeSession(
        [
            FakeResponse(status, headers={"Location": "/next"}),
            FakeResponse(200, "ok"),
        ]
    )

    response = base.safe_request(
        session,
        "POST",
        "http://authorized.test:5001/start",
        timeout=2,
        data={"content": "payload"},
        headers={"Authorization": "Bearer exact-secret"},
    )

    assert response.status_code == 200
    assert [(method, url) for method, url, _ in session.calls] == [
        ("POST", "http://authorized.test:5001/start"),
        ("POST", "http://authorized.test:5001/next"),
    ]
    assert session.calls[1][2]["data"] == {"content": "payload"}
    assert session.calls[1][2]["headers"] == {"Authorization": "Bearer exact-secret"}


def test_stored_xss_requires_new_unsanitized_verify_occurrence(tmp_path):
    payload = "<script>alert(1)</script>"
    session = FakeSession(
        [
            FakeResponse(200, "old reviews"),
            FakeResponse(201, "saved"),
            FakeResponse(200, f"old reviews {payload}"),
        ]
    )

    finding = _scan_one(
        session, _context(tmp_path), _target(stored=True, method="POST"), payload
    )

    assert finding.scan.status is ScanStatus.COMPLETED
    assert finding.scan.rule.label.value == "SUSPECTED"
    assert "저장형 XSS" in finding.scan.rule.reason
    assert [call[0] for call in session.calls] == ["GET", "POST", "GET"]
    assert session.calls[1][2]["data"]["content"] == payload


@pytest.mark.parametrize(
    ("outcomes", "code"),
    [
        (
            [
                FakeResponse(200, "baseline"),
                FakeResponse(201),
                requests.Timeout("hidden detail"),
            ],
            "SCAN_TIMEOUT",
        ),
        ([FakeResponse(404)], "SCAN_VERIFY_BASELINE_FAILED"),
        (
            [
                FakeResponse(200, "stale <script>x</script>"),
                FakeResponse(201),
                FakeResponse(200, "stale <script>x</script>"),
            ],
            "SCAN_VERIFY_STALE_EVIDENCE",
        ),
    ],
)
def test_stored_verify_failures_are_failed_findings(tmp_path, outcomes, code):
    finding = _scan_one(
        FakeSession(outcomes),
        _context(tmp_path),
        _target(stored=True, method="POST"),
        "<script>x</script>",
    )

    assert finding.scan.status is ScanStatus.FAILED
    assert finding.scan.error.code == code
    assert finding.scan.rule.label is None


def test_scan_emits_unique_findings_and_progress_for_reflected_cases(
    tmp_path, monkeypatch
):
    sessions = []

    def make_session():
        session = FakeSession(
            [FakeResponse(200, "<script>a</script>"), FakeResponse(200, "clean")]
        )
        sessions.append(session)
        return session

    monkeypatch.setattr(xss.requests, "Session", make_session)
    monkeypatch.setattr(
        xss.payload_profiles,
        "load_payload_profile",
        lambda _: [("a", "<script>a</script>"), ("b", "b")],
    )
    progress = []

    findings = xss.scan(
        [_target()],
        _context(tmp_path),
        lambda completed, total: progress.append((completed, total)),
    )

    assert [finding.case_id for finding in findings] == [
        "reflected-case::a",
        "reflected-case::b",
    ]
    assert [finding.finding_id for finding in findings] == ["XSS-000001", "XSS-000002"]
    assert [finding.scan.status for finding in findings] == [
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED,
    ]
    assert progress == [(1, 2), (2, 2)]
    assert len(sessions[0].calls) == 2


def test_sidecar_redacts_exact_auth_secrets_pii_and_bounds_utf8_size(tmp_path):
    exact_secret = "resolver-secret-value"
    body = (
        f"{exact_secret} jane@example.test 010-1234-5678 "
        "Authorization: Basic dXNlcjpwYXNz "
        "api_key=api-secret session_id=session-secret csrf_token=csrf-secret "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature "
        + "가"
        * (xss_report.MAX_SIDECAR_BYTES // 3 + 100)
    )

    path = xss_report.write_sidecar_html(
        tmp_path / "responses", "XSS-000001", body, secret_values=[exact_secret]
    )
    saved = (tmp_path / path).read_text(encoding="utf-8")

    assert path == "responses/XSS-000001.html"
    for secret in (
        exact_secret,
        "jane@example.test",
        "010-1234-5678",
        "dXNlcjpwYXNz",
        "api-secret",
        "session-secret",
        "csrf-secret",
    ):
        assert secret not in saved
    assert "[REDACTED]" in saved
    assert saved.endswith(xss_report.TRUNCATION_MARKER)
    assert len(saved.encode("utf-8")) <= xss_report.MAX_SIDECAR_BYTES


def test_sidecar_size_limit_preserves_evidence_near_response_end(tmp_path):
    payload = "<svg onload=alert(1)>"
    body = "가" * xss_report.MAX_SIDECAR_BYTES + payload

    path = xss_report.write_sidecar_html(
        tmp_path / "responses",
        "XSS-000002",
        body,
        evidence_token=payload,
    )
    saved = (tmp_path / path).read_text(encoding="utf-8")

    assert payload in saved
    assert saved.startswith(xss_report.LEADING_TRUNCATION_MARKER)
    assert saved.endswith(xss_report.TRUNCATION_MARKER)
    assert len(saved.encode("utf-8")) <= xss_report.MAX_SIDECAR_BYTES
