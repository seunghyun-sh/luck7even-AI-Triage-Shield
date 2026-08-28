"""scanners/sqli 패키지의 판정 로직을 실제 서버 없이 검증하는 자동 테스트."""

import requests

from analysis.models import TargetCase, TargetInput
from scanners.sqli import detectors


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def _make_target(case_id: str = "sqli-search-a") -> TargetCase:
    return TargetCase(
        case_id=case_id,
        vuln_type="SQLI",
        path="/case/sqli-a",
        method="GET",
        input=TargetInput(location="query", parameters={"id": "1"}, attack_parameter="id"),
        requires_pre_auth=False,
        auth_profile=None,
        payload_profile="sqli-default",
        manual_verification_profile="sqli-response-difference",
    )


def test_evaluate_single_payload_flags_db_error(monkeypatch, tmp_path):
    target = _make_target()

    def fake_get(url, params=None, timeout=None, allow_redirects=None):
        payload = params.get("id", "")
        if "union" in payload.lower():
            return FakeResponse("Error: you have an error in your sql syntax", 500)
        return FakeResponse("검색 결과가 없습니다", 200)

    monkeypatch.setattr(requests, "get", fake_get)

    finding = detectors.evaluate_single_payload(
        target, "attack-union-2col", "' UNION SELECT NULL,NULL--",
        base_url="http://fake", timeout_seconds=10, follow_redirects=False,
        responses_dir=tmp_path,
    )

    assert finding.case_id == "sqli-search-a::attack-union-2col"
    assert finding.scan.rule.label.value == "SUSPECTED"
    assert "DB 오류" in finding.scan.rule.reason


def test_evaluate_single_payload_flags_normal_value_as_safe(monkeypatch, tmp_path):
    target = _make_target()

    def fake_get(url, params=None, timeout=None, allow_redirects=None):
        return FakeResponse("검색 결과가 없습니다", 200)

    monkeypatch.setattr(requests, "get", fake_get)

    finding = detectors.evaluate_single_payload(
        target, "normal-laptop", "laptop",
        base_url="http://fake", timeout_seconds=10, follow_redirects=False,
        responses_dir=tmp_path,
    )

    assert finding.scan.rule.label.value == "SAFE"


def test_evaluate_boolean_pair_detects_difference(monkeypatch, tmp_path):
    target = _make_target()

    def fake_get(url, params=None, timeout=None, allow_redirects=None):
        payload = params.get("id", "")
        if "1=1" in payload:
            return FakeResponse("검색 결과 3건: laptop, phone, keyboard", 200)
        return FakeResponse("검색 결과 0건", 200)

    monkeypatch.setattr(requests, "get", fake_get)

    finding = detectors.evaluate_boolean_pair_payload(
        target, "boolean-pair-1", "1 AND 1=1", "1 AND 1=2",
        base_url="http://fake", timeout_seconds=10, follow_redirects=False,
        responses_dir=tmp_path,
    )

    assert finding.scan.rule.label.value == "SUSPECTED"

def test_evaluate_boolean_pair_detects_short_json_content_mismatch(monkeypatch, tmp_path):
    """/products/stock처럼 길이 차이는 작지만 내용이 다른 JSON 응답도 잡아야 한다."""
    target = _make_target()

    def fake_get(url, params=None, timeout=None, allow_redirects=None):
        payload = params.get("id", "")
        if "1=1" in payload:
            return FakeResponse('{"available":true,"status":"in_stock"}', 200)
        return FakeResponse('{"available":false,"status":"unavailable"}', 200)

    monkeypatch.setattr(requests, "get", fake_get)

    finding = detectors.evaluate_boolean_pair_payload(
        target, "boolean-pair-1", "1 AND 1=1", "1 AND 1=2",
        base_url="http://fake", timeout_seconds=10, follow_redirects=False,
        responses_dir=tmp_path,
    )

    assert finding.scan.rule.label.value == "SUSPECTED"