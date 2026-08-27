"""스캔 결과를 팀 공통 데이터 계약(canonical analysis.models) 형식으로 조립한다.

scanners/xss_rules.py가 내는 세분화된 내부 판정(REFLECTED_UNSANITIZED 등)을
공통 계약이 정한 RuleLabel(SUSPECTED/SAFE)로 압축하고, 잃어버리는 세부 내용은
evidence_summary/reason 텍스트로 옮긴다. 또한 응답 본문 전체를 JSON에 직접
넣지 않고 run의 sidecar HTML 파일로 저장한 뒤, 그 상대 경로만 JSON에 남긴다.

scanners/pipeline/xss.py(실제 실습 환경을 대상으로 하는 계약 준수 스캐너)가
이 모듈의 판정·조립 로직을 그대로 가져다 쓴다.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

import requests

from analysis.models import (
    ErrorDetail,
    RawFinding,
    RawRun,
    RuleLabel,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanRule,
    ScanStatus,
    VulnType,
)
from scanners.xss_rules import (
    NOT_REFLECTED,
    REFLECTED_ESCAPED,
    REFLECTED_UNSANITIZED,
    STORED_XSS_CONFIRMED,
)

# 내부 판정 라벨 -> (계약 rule.label, evidence_summary, reason) 매핑.
# evidence_summary는 "응답에서 무엇을 관찰했는가"(객관적 사실), reason은
# "그래서 왜 이 라벨을 붙였는가"(판정 근거)로 문장의 성격을 구분한다.
_VERDICT_TEXT = {
    NOT_REFLECTED: (
        RuleLabel.SAFE,
        "응답에서 페이로드가 발견되지 않았습니다.",
        "필터링되었거나 애초에 응답에 포함되지 않았습니다.",
    ),
    REFLECTED_ESCAPED: (
        RuleLabel.SUSPECTED,
        "입력값의 특수문자가 HTML entity로 변환되어 반사되었습니다.",
        "페이로드 문자열이 이스케이프된 형태로 응답에 존재하여 후보로 수집했습니다.",
    ),
    REFLECTED_UNSANITIZED: (
        RuleLabel.SUSPECTED,
        "입력값이 인코딩 없이 응답에 그대로 반사되었습니다.",
        "페이로드가 실행 가능한 형태로 응답에 반사되었습니다.",
    ),
    STORED_XSS_CONFIRMED: (
        RuleLabel.SUSPECTED,
        "별도 조회 요청에서도 입력값이 인코딩 없이 그대로 남아있었습니다.",
        "페이로드가 주입 이후 별도 조회 요청에서도 유지되어 저장형 XSS로 확인되었습니다.",
    ),
}


def verdict_for(internal_label: str) -> tuple[RuleLabel, str, str]:
    """내부 판정 라벨 하나를 (rule.label, evidence_summary, reason)으로 변환한다."""
    return _VERDICT_TEXT[internal_label]


def make_finding_id(sequence_no: int) -> str:
    """실행 안에서만 유일하면 되는 finding_id를 순번으로 만든다. 예: XSS-000001."""
    return f"XSS-{sequence_no:06d}"


def now_iso() -> str:
    """timezone offset을 포함한 ISO 8601 문자열을 로컬 시간대로 반환한다."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


_ERROR_MAP = {
    requests.Timeout: ("SCAN_TIMEOUT", "대상 요청 시간이 초과되었습니다.", True),
    requests.ConnectionError: ("SCAN_CONNECTION_ERROR", "대상 서버에 연결할 수 없습니다.", True),
}


def build_scan_error(exc: Exception) -> ErrorDetail:
    """예외 하나를 계약이 정한 {code, message, retryable} 구조로 변환한다."""
    for exc_type, (code, message, retryable) in _ERROR_MAP.items():
        if isinstance(exc, exc_type):
            return ErrorDetail(code=code, message=f"{message} ({exc})", retryable=retryable)

    if isinstance(exc, requests.RequestException):
        return ErrorDetail(code="SCAN_REQUEST_ERROR", message=str(exc), retryable=True)

    # UnicodeError 등 인코딩 관련 예외. 페이로드/환경 자체의 문제라 재시도해도
    # 결과가 달라지지 않으므로 retryable=False로 표시한다.
    return ErrorDetail(code="SCAN_ENCODING_ERROR", message=str(exc), retryable=False)


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
        status=ScanStatus.COMPLETED,
        request=request,
        response=ScanResponse(
            http_status=http_status,
            elapsed_ms=elapsed_ms,
            baseline_elapsed_ms=None,  # XSS는 null 허용
            evidence_summary=evidence_summary,
            html_path=html_path,
        ),
        rule=ScanRule(label=rule_label, reason=reason),
        error=None,
    )


def _build_failed_scan(request: ScanRequest, error: ErrorDetail) -> ScanResult:
    """실패 scan 객체(response/rule 전부 null + error)를 만든다.

    계약상 FAILED scan은 response의 모든 필드가 null이어야 한다(ScanResult
    검증기). 그래서 실제로 응답을 받았더라도(예: 404) 그 상태 코드는 구조화된
    필드가 아니라 error.message에만 남긴다.
    """
    return ScanResult(
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
        error=error,
    )


def build_failed_scan(request: ScanRequest, exc: Exception) -> ScanResult:
    """요청 자체가 예외로 실패한 경우의 scan 객체를 만든다. response/rule은 모두 null."""
    return _build_failed_scan(request, build_scan_error(exc))


def build_not_found_scan(request: ScanRequest) -> ScanResult:
    """대상 경로가 404를 반환한 경우의 scan 객체를 만든다.

    스캐너 통합 계약 변경 안내(8·9장): 404는 "안전(SAFE)"이 아니라 실패
    Finding으로 보존해야 한다. 404는 주입 지점 자체가 존재하지 않는다는 뜻이라,
    그 응답을 근거로 SAFE라고 판정하면 실제로는 테스트가 수행되지 않았는데도
    안전하다고 오판(거짓 음성)하게 된다. 같은 경로를 다시 요청해도 404가 바뀌지
    않으므로 retryable=False로 둔다.
    """
    return _build_failed_scan(
        request,
        ErrorDetail(
            code="SCAN_TARGET_NOT_FOUND",
            message="대상 경로가 404 Not Found를 반환하여 주입 지점을 확인할 수 없습니다.",
            retryable=False,
        ),
    )


def make_finding(case_id: str, finding_id: str, scan: ScanResult) -> RawFinding:
    return RawFinding(
        case_id=case_id,
        finding_id=finding_id,
        scanned_at=now_iso(),
        vuln_type=VulnType.XSS,
        scan=scan,
    )


def compute_run_status(findings: list[RawFinding]) -> str:
    """findings 목록을 보고 run 전체의 status(COMPLETED/PARTIAL/FAILED)를 계산한다.

    이 계산은 analysis.models.RawRun의 검증 규칙과 일치해야 한다: COMPLETED는
    실패가 전혀 없어야 하고, PARTIAL은 성공·실패가 모두 있어야 하고, 그 외
    (전부 실패했거나 findings가 비어있음)에만 FAILED를 쓸 수 있다.
    """
    if not findings:
        return "FAILED"
    failed = sum(1 for f in findings if f.scan.status is ScanStatus.FAILED)
    if failed == 0:
        return "COMPLETED"
    if failed < len(findings):
        return "PARTIAL"
    return "FAILED"


# 저장 전 응답 본문에서 지워야 하는 민감정보 패턴(계약 11.4: "쿠키, 인증 헤더와
# 불필요한 개인정보를 제거"). 우리 스캐너가 다루는 대상은 대부분 인증이 필요
# 없는 페이지라 실제로 걸릴 일은 드물지만, 페이로드나 응답에 우연히 이런 패턴이
# 섞여 들어올 가능성에 대비해 최소한의 방어선으로 둔다.
_SECRET_PATTERNS = [
    re.compile(r"(?im)^set-cookie:.*$"),
    re.compile(r"(?i)authorization:\s*bearer\s+\S+"),
    re.compile(r"(?i)\bpassword\s*=\s*[^&\s\"'<>]+"),
]


def _redact_secrets(html_body: str) -> str:
    """응답 본문에서 쿠키/인증 헤더/비밀번호로 보이는 패턴을 마스킹한다."""
    redacted = html_body
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _write_atomic(path: Path, content: str) -> None:
    """임시 파일에 쓰고 flush한 뒤 rename하는 원자적 쓰기.

    실행 계약(11.4) 요구사항: "응답 파일은 임시 파일에 쓴 뒤 rename한다" --
    쓰는 도중에 프로세스가 죽거나 다른 프로세스가 같은 파일을 읽어도 항상
    완전한 내용이거나 이전 내용만 보이게 하기 위함이다(부분적으로 쓰인 파일이
    보이는 경우를 없앤다).
    """
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    tmp_path.replace(path)


def write_sidecar_html(responses_dir: Path, finding_id: str, html_body: str) -> str:
    """응답 본문 전체를 responses_dir/<finding_id>.html로 저장한다.

    `responses_dir`는 호출자가 넘겨준 run 전용 증거 저장 경로(예:
    ScanContext.responses_dir)여야 하며, 이 함수가 임의로 다른 경로를
    계산해서는 안 된다. 반환값은 findings.json에 기록할, run 디렉터리
    기준 상대 경로다.
    """
    responses_dir.mkdir(parents=True, exist_ok=True)
    file_path = responses_dir / f"{finding_id}.html"
    _write_atomic(file_path, _redact_secrets(html_body))
    return f"responses/{finding_id}.html"


def write_run_envelope(run_dir: Path, raw_run: RawRun) -> Path:
    """RawRun 전체를 <run_dir>/findings.json으로 저장한다.

    주의: 이건 main.py 통합 전 우리 자신의 로컬 테스트용 헬퍼다. 실제
    파이프라인에서는 스캐너가 findings.json을 직접 게시하지 않고
    orchestration.RunStore가 XSS·SQLi 결과를 합쳐서 게시한다.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.json"
    _write_atomic(findings_path, json.dumps(raw_run.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return findings_path
