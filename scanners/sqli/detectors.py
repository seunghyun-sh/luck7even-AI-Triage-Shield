"""Internal SQL injection detection logic (implementation details).

Other modules should not import from this file directly.
Use `scanners.sqli.scan` instead.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests

from analysis.models import (
    ErrorDetail,
    RawFinding,
    RuleLabel,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanRule,
    ScanStatus,
    TargetCase,
    VulnType,
)
from scanners import base

DB_ERROR_KEYWORDS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unknown column",
    "sql syntax",
    "mysqli_sql_exception",
    "mysql.connector.errors",
    "pymysql.err",
    "sqlite3.operationalerror",
    "sqlite3.programmingerror",
    "sqlite3.integrityerror",
    "unrecognized token",
    "no such table",
    "no such column",
    "you can only execute one statement at a time",
    "sqlalchemy.exc.",
    "sqlalche.me/e/",
]

RESPONSE_DIFF_THRESHOLD = 0.5
BOOLEAN_DIFF_THRESHOLD = 0.2
SHORT_JSON_RESPONSE_LIMIT = 4096
TIME_DELAY_MARGIN_MS = 3000


def _looks_like_db_error(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in DB_ERROR_KEYWORDS)


def _response_diff_ratio(text_a: str, text_b: str) -> float:
    len_a, len_b = len(text_a), len(text_b)
    longer = max(len_a, len_b, 1)
    return abs(len_a - len_b) / longer


def _short_json_content_differs(text_a: str, text_b: str) -> bool:
    """Detect semantic differences in small JSON responses without flagging HTML noise."""

    if max(len(text_a.encode("utf-8")), len(text_b.encode("utf-8"))) > (
        SHORT_JSON_RESPONSE_LIMIT
    ):
        return False
    try:
        return json.loads(text_a) != json.loads(text_b)
    except (json.JSONDecodeError, TypeError):
        return False


def _now() -> datetime:
    return datetime.now().astimezone()


def _new_finding_id() -> str:
    return f"SQLI-{uuid.uuid4().hex[:12]}"


def _save_response_html(responses_dir: Path, finding_id: str, html_text: str) -> str:
    """Atomically save response HTML and return the run-relative path."""
    responses_dir.mkdir(parents=True, exist_ok=True)
    final_path = responses_dir / f"{finding_id}.html"
    tmp_path = responses_dir / f"{finding_id}.html.tmp"
    tmp_path.write_text(html_text, encoding="utf-8")
    tmp_path.replace(final_path)
    return f"responses/{finding_id}.html"


def _baseline_value(target: TargetCase) -> str:
    value = target.input.parameters.get(target.input.attack_parameter, "")
    return "" if value is None else str(value)


def _build_fields(target: TargetCase, attack_value: str) -> dict:
    fields = dict(target.input.parameters)
    fields[target.input.attack_parameter] = attack_value
    return fields


def _send(
    client,
    method: str,
    url: str,
    location: str,
    fields: dict,
    timeout_seconds: int,
    follow_redirects: bool,
):
    kwargs = {}
    if location == "json":
        kwargs["json"] = fields
    elif location == "form":
        kwargs["data"] = fields
    else:
        kwargs["params"] = fields
    if follow_redirects:
        return base.safe_request(
            client,
            method,
            url,
            timeout=timeout_seconds,
            **kwargs,
        )
    request_method = client.post if method == "POST" else client.get
    return request_method(
        url,
        timeout=timeout_seconds,
        allow_redirects=False,
        **kwargs,
    )


def load_payload_profile(profile_id: str, payloads_dir: Path) -> list[dict]:
    """Load a fixed, version-controlled payload list by its stable profile id."""
    path = (payloads_dir / f"{profile_id}.json").resolve()
    if payloads_dir.resolve() not in path.parents:
        raise ValueError("payload profile id resolved outside the payloads directory")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["payloads"]


def _failed_finding(
    case_id: str, request: ScanRequest, code: str, message: str, retryable: bool = True
) -> RawFinding:
    return RawFinding(
        case_id=case_id,
        finding_id=_new_finding_id(),
        scanned_at=_now(),
        vuln_type=VulnType.SQLI,
        scan=ScanResult(
            status=ScanStatus.FAILED,
            request=request,
            response=ScanResponse(
                http_status=None,
                elapsed_ms=None,
                baseline_elapsed_ms=None,
                evidence_summary=None,
                html_path=None,
            ),
            rule=ScanRule(label=None, reason=None),
            error=ErrorDetail(code=code, message=message, retryable=retryable),
        ),
    )


def evaluate_single_payload(
    target: TargetCase,
    payload_case_id: str,
    payload_value: str,
    *,
    base_url: str,
    timeout_seconds: int,
    follow_redirects: bool,
    responses_dir: Path,
    session: requests.Session | None = None,
) -> RawFinding:
    """신호 ①DB오류 ②응답차이 ④시간지연을 한 번에 확인한다."""
    case_id = f"{target.case_id}::{payload_case_id}"
    client = session or requests
    url = urljoin(base_url, target.path)
    baseline_value = _baseline_value(target)

    request = ScanRequest(
        url=url,
        method=target.method,
        input_location=target.input.location,
        parameter=target.input.attack_parameter,
        payload=payload_value,
    )

    try:
        baseline_started = time.monotonic()
        baseline_resp = _send(
            client,
            target.method,
            url,
            target.input.location,
            _build_fields(target, baseline_value),
            timeout_seconds,
            follow_redirects,
        )
        baseline_elapsed_ms = int((time.monotonic() - baseline_started) * 1000)

        started = time.monotonic()
        resp = _send(
            client,
            target.method,
            url,
            target.input.location,
            _build_fields(target, payload_value),
            timeout_seconds,
            follow_redirects,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
    except requests.exceptions.Timeout:
        return _failed_finding(
            case_id, request, "SCAN_TIMEOUT", "대상 요청 시간이 초과되었습니다."
        )
    except requests.exceptions.RequestException:
        return _failed_finding(
            case_id, request, "SCAN_REQUEST_FAILED", "대상 요청을 완료하지 못했습니다."
        )

    db_error = _looks_like_db_error(resp.text)
    time_delay = elapsed_ms > baseline_elapsed_ms + TIME_DELAY_MARGIN_MS
    diff_ratio = _response_diff_ratio(resp.text, baseline_resp.text)
    response_diff = diff_ratio > RESPONSE_DIFF_THRESHOLD

    if db_error:
        label, reason = RuleLabel.SUSPECTED, "DB 오류 메시지가 응답에 노출됨"
    elif time_delay:
        label, reason = (
            RuleLabel.SUSPECTED,
            "정상 요청보다 응답이 3초 이상 지연됨(시간 지연 의심)",
        )
    elif response_diff:
        label, reason = (
            RuleLabel.SUSPECTED,
            f"정상 요청과 응답 길이가 {diff_ratio:.0%} 차이남(응답 차이 의심)",
        )
    else:
        label, reason = (
            RuleLabel.SAFE,
            "DB 오류·시간 지연·응답 차이 신호가 관찰되지 않음",
        )

    finding_id = _new_finding_id()
    html_path = _save_response_html(responses_dir, finding_id, resp.text)

    return RawFinding(
        case_id=case_id,
        finding_id=finding_id,
        scanned_at=_now(),
        vuln_type=VulnType.SQLI,
        scan=ScanResult(
            status=ScanStatus.COMPLETED,
            request=request,
            response=ScanResponse(
                http_status=resp.status_code,
                elapsed_ms=elapsed_ms,
                baseline_elapsed_ms=baseline_elapsed_ms,
                evidence_summary=reason,
                html_path=html_path,
            ),
            rule=ScanRule(label=label, reason=reason),
            error=None,
        ),
    )


def evaluate_boolean_pair_payload(
    target: TargetCase,
    payload_case_id: str,
    true_value: str,
    false_value: str,
    *,
    base_url: str,
    timeout_seconds: int,
    follow_redirects: bool,
    responses_dir: Path,
    session: requests.Session | None = None,
) -> RawFinding:
    """신호 ③ 참/거짓 쌍: 두 응답을 서로 직접 비교한다."""
    case_id = f"{target.case_id}::{payload_case_id}"
    client = session or requests
    url = urljoin(base_url, target.path)
    combined_payload = f"{true_value} | {false_value}"

    request = ScanRequest(
        url=url,
        method=target.method,
        input_location=target.input.location,
        parameter=target.input.attack_parameter,
        payload=combined_payload,
    )

    try:
        started = time.monotonic()
        true_resp = _send(
            client,
            target.method,
            url,
            target.input.location,
            _build_fields(target, true_value),
            timeout_seconds,
            follow_redirects,
        )
        false_resp = _send(
            client,
            target.method,
            url,
            target.input.location,
            _build_fields(target, false_value),
            timeout_seconds,
            follow_redirects,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
    except requests.exceptions.Timeout:
        return _failed_finding(
            case_id, request, "SCAN_TIMEOUT", "대상 요청 시간이 초과되었습니다."
        )
    except requests.exceptions.RequestException:
        return _failed_finding(
            case_id, request, "SCAN_REQUEST_FAILED", "대상 요청을 완료하지 못했습니다."
        )

    diff_ratio = _response_diff_ratio(true_resp.text, false_resp.text)
    json_content_differs = _short_json_content_differs(true_resp.text, false_resp.text)
    if diff_ratio > BOOLEAN_DIFF_THRESHOLD or json_content_differs:
        label = RuleLabel.SUSPECTED
        signal = (
            "JSON 내용이 다름"
            if json_content_differs
            else f"길이가 {diff_ratio:.0%} 다름"
        )
        reason = f"참/거짓 페이로드 응답의 {signal}(Boolean-based 의심)"
    else:
        label = RuleLabel.SAFE
        reason = f"참/거짓 페이로드 응답이 비슷함(Boolean-based 신호 없음, 차이 {diff_ratio:.1%})"

    finding_id = _new_finding_id()
    html_path = _save_response_html(responses_dir, finding_id, true_resp.text)

    return RawFinding(
        case_id=case_id,
        finding_id=finding_id,
        scanned_at=_now(),
        vuln_type=VulnType.SQLI,
        scan=ScanResult(
            status=ScanStatus.COMPLETED,
            request=request,
            response=ScanResponse(
                http_status=true_resp.status_code,
                elapsed_ms=elapsed_ms,
                baseline_elapsed_ms=elapsed_ms,
                evidence_summary=reason,
                html_path=html_path,
            ),
            rule=ScanRule(label=label, reason=reason),
            error=None,
        ),
    )
