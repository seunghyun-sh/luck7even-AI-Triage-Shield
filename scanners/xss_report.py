"""스캔 결과를 팀 공통 데이터 계약 Contract B(raw findings) 형식으로 조립한다.

scanners/xss_rules.py가 내는 세분화된 내부 판정(REFLECTED_UNSANITIZED 등)을
docs/data-contracts-v1.md가 정한 rule.label(SUSPECTED/SAFE/null)로 압축하고,
잃어버리는 세부 내용은 evidence_summary/reason 텍스트로 옮긴다. 또한 응답
본문 전체를 JSON에 직접 넣지 않고 run 디렉터리 아래 sidecar HTML 파일로 저장한
뒤, 그 상대 경로만 JSON에 남긴다(계약 4.5, "HTML 원문은 Git에 등록하지 않는다").

주의(계약과의 차이점): 계약의 input_location enum은 "query"/"form"/"json" 세
값만 정의한다. 이 스캐너는 bWAPP의 User-Agent/Referer/커스텀 헤더 반사형
XSS도 탐지하는데, 이건 계약에 없는 값이라 편의상 "header"를 추가로 사용한다.
이는 아직 팀 합의를 거치지 않은 확장이므로, 이 값을 소비하는 쪽(OpenAI·데이터
처리 담당)이 생기면 계약 문서에 반영하고 버전을 올리는 절차(계약 8장)를
따라야 한다.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import requests

from analysis.models import (
    NOT_REFLECTED,
    REFLECTED_ESCAPED,
    REFLECTED_UNSANITIZED,
    RULE_LABEL_SAFE,
    RULE_LABEL_SUSPECTED,
    STORED_XSS_CONFIRMED,
    RawFinding,
    RunEnvelope,
    ScanError,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanRule,
)

VULN_TYPE = "XSS"

# 내부 판정 라벨 -> (계약 rule.label, evidence_summary, reason) 매핑.
# evidence_summary는 "응답에서 무엇을 관찰했는가"(객관적 사실), reason은
# "그래서 왜 이 라벨을 붙였는가"(판정 근거)로 문장의 성격을 구분한다.
_VERDICT_TEXT = {
    NOT_REFLECTED: (
        RULE_LABEL_SAFE,
        "응답에서 페이로드가 발견되지 않았습니다.",
        "필터링되었거나 애초에 응답에 포함되지 않았습니다.",
    ),
    REFLECTED_ESCAPED: (
        RULE_LABEL_SUSPECTED,
        "입력값의 특수문자가 HTML entity로 변환되어 반사되었습니다.",
        "페이로드 문자열이 이스케이프된 형태로 응답에 존재하여 후보로 수집했습니다.",
    ),
    REFLECTED_UNSANITIZED: (
        RULE_LABEL_SUSPECTED,
        "입력값이 인코딩 없이 응답에 그대로 반사되었습니다.",
        "페이로드가 실행 가능한 형태로 응답에 반사되었습니다.",
    ),
    STORED_XSS_CONFIRMED: (
        RULE_LABEL_SUSPECTED,
        "별도 조회 요청에서도 입력값이 인코딩 없이 그대로 남아있었습니다.",
        "페이로드가 주입 이후 별도 조회 요청에서도 유지되어 저장형 XSS로 확인되었습니다.",
    ),
}


def verdict_for(internal_label: str) -> tuple[str, str, str]:
    """내부 판정 라벨 하나를 (rule.label, evidence_summary, reason)으로 변환한다."""
    return _VERDICT_TEXT[internal_label]


def slugify(text: str) -> str:
    """URL 경로나 파라미터명을 case_id에 쓸 수 있는 소문자 하이픈 문자열로 바꾼다."""
    text = text.strip("/").lower()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-") or "root"


def make_case_id(path: str, parameter: str, method: str) -> str:
    """(대상 경로, 파라미터, 메서드)로부터 실행 간 안정적인 case_id를 만든다.

    현재 이 스캐너는 환경 구축팀이 배포하는 공식 Contract A 타겟 매니페스트가
    아니라 자체 xss_lab_targets 목록을 입력으로 쓰기 때문에, 외부에서 부여된
    case_id가 없다. 대신 (경로, 파라미터, 메서드) 조합이 바뀌지 않는 한 항상
    같은 문자열이 나오도록 결정적으로 생성해서 "실행 간 안정적"이라는 계약
    요구사항(2.1)을 충족한다.
    """
    return f"xss-{slugify(path)}-{slugify(parameter)}-{method.lower()}"


def make_finding_id(sequence_no: int) -> str:
    """실행 안에서만 유일하면 되는 finding_id를 순번으로 만든다. 예: XSS-000001."""
    return f"XSS-{sequence_no:06d}"


def now_iso() -> str:
    """timezone offset을 포함한 ISO 8601 문자열(계약 2.2)을 로컬 시간대로 반환한다."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


_ERROR_MAP = {
    requests.Timeout: ("SCAN_TIMEOUT", "대상 요청 시간이 초과되었습니다.", True),
    requests.ConnectionError: ("SCAN_CONNECTION_ERROR", "대상 서버에 연결할 수 없습니다.", True),
}


def build_scan_error(exc: Exception) -> ScanError:
    """예외 하나를 계약이 정한 {code, message, retryable} 구조로 변환한다."""
    for exc_type, (code, message, retryable) in _ERROR_MAP.items():
        if isinstance(exc, exc_type):
            return ScanError(code=code, message=f"{message} ({exc})", retryable=retryable)

    if isinstance(exc, requests.RequestException):
        return ScanError(code="SCAN_REQUEST_ERROR", message=str(exc), retryable=True)

    # UnicodeError 등 인코딩 관련 예외. 페이로드/환경 자체의 문제라 재시도해도
    # 결과가 달라지지 않으므로 retryable=False로 표시한다.
    return ScanError(code="SCAN_ENCODING_ERROR", message=str(exc), retryable=False)


def build_completed_scan(
    request: ScanRequest,
    http_status: int,
    elapsed_ms: int,
    internal_label: str,
    html_path: str,
) -> ScanResult:
    """정상적으로 응답을 받은 경우의 scan 객체를 만든다."""
    rule_label, evidence_summary, reason = verdict_for(internal_label)
    return ScanResult(
        status="COMPLETED",
        request=request,
        response=ScanResponse(
            http_status=http_status,
            elapsed_ms=elapsed_ms,
            baseline_elapsed_ms=None,  # XSS는 null 허용(계약 4.4)
            evidence_summary=evidence_summary,
            html_path=html_path,
        ),
        rule=ScanRule(label=rule_label, reason=reason),
        error=None,
    )


def build_failed_scan(request: ScanRequest, exc: Exception) -> ScanResult:
    """요청 자체가 실패한 경우의 scan 객체를 만든다. response/rule은 모두 null."""
    return ScanResult(
        status="FAILED",
        request=request,
        response=ScanResponse(
            http_status=None,
            elapsed_ms=None,
            baseline_elapsed_ms=None,
            evidence_summary=None,
            html_path=None,
        ),
        rule=ScanRule(label=None, reason=None),
        error=build_scan_error(exc),
    )


def make_finding(case_id: str, finding_id: str, scan: ScanResult) -> RawFinding:
    return RawFinding(
        case_id=case_id,
        finding_id=finding_id,
        scanned_at=now_iso(),
        vuln_type=VULN_TYPE,
        scan=scan,
    )


def compute_run_status(findings: list[RawFinding]) -> str:
    """findings 목록을 보고 run 전체의 status(COMPLETED/PARTIAL/FAILED)를 계산한다(계약 5.5)."""
    if not findings:
        return "FAILED"
    failed = sum(1 for f in findings if f.scan.status == "FAILED")
    if failed == 0:
        return "COMPLETED"
    if failed < len(findings):
        return "PARTIAL"
    return "FAILED"


def write_sidecar_html(run_dir: Path, finding_id: str, html: str) -> str:
    """응답 본문 전체를 run 디렉터리 아래 responses/<finding_id>.html로 저장한다.

    반환값은 findings.json에 기록할, run 디렉터리 기준 상대 경로다(계약 4.5).
    """
    responses_dir = run_dir / "responses"
    responses_dir.mkdir(parents=True, exist_ok=True)
    file_path = responses_dir / f"{finding_id}.html"
    file_path.write_text(html, encoding="utf-8")
    return f"responses/{finding_id}.html"


def write_run_envelope(run_dir: Path, envelope: RunEnvelope) -> Path:
    """RunEnvelope 전체를 <run_dir>/findings.json으로 저장한다."""
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.json"
    findings_path.write_text(
        json.dumps(asdict(envelope), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return findings_path
