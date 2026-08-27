"""Shared input and output models for scanner and AI results.

이 모듈의 "Contract B" 관련 데이터클래스들은 docs/data-contracts-v1.md
(4. Contract B: raw findings)에서 정의한 팀 공통 규격을 그대로 코드로 옮긴 것이다.
XSS 스캐너(우리 팀)가 이 규격의 "생산자"이고, OpenAI·데이터 처리 담당 팀이
"소비자"다. 필드명, 자료형, enum 값을 계약 문서와 반드시 일치시켜야 하며,
임의로 필드를 추가/삭제/이름 변경하면 소비자 쪽 파싱이 깨진다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ============================================================
# 내부 판정 라벨 (scanners/xss_rules.py 전용, 계약에는 직접 노출되지 않음)
# ============================================================
# 아래 네 값은 우리 스캐너 내부에서만 쓰는 "세분화된" 판정이다. 데이터 계약
# (Contract B)의 rule.label은 SUSPECTED/SAFE/null 세 가지만 허용하므로, 이
# 세분화된 값들은 scanners/xss_report.py가 SUSPECTED/SAFE로 압축하고, 대신
# 원래의 세부 내용은 rule.reason과 response.evidence_summary 텍스트로 남긴다.
# 아래로 갈수록 "더 위험함"을 의미하며, xss_rules.most_severe()가 이 순서로
# 우선순위를 매긴다.
NOT_REFLECTED = "NOT_REFLECTED"  # 페이로드가 응답에 전혀 나타나지 않음 (필터링됨/무관)
REFLECTED_ESCAPED = "REFLECTED_ESCAPED"  # HTML 이스케이프된 형태로만 반사됨 (대체로 안전)
REFLECTED_UNSANITIZED = "REFLECTED_UNSANITIZED"  # 입력 그대로 반사됨 (취약 가능성 높음)
# Reflected XSS는 "요청 -> 응답" 한 번으로 판정할 수 있지만, Stored XSS는 그렇지 않다.
# 글을 쓸 때(POST)는 정상적으로 저장됐다는 메시지만 보일 수도 있고, 실제로 다른 사람이
# 그 글을 읽을 때(GET, 별도 요청) 비로소 스크립트가 실행된다. 그래서 이 라벨은
# xss_rules.classify_reflection()이 직접 매기지 않고, 스캐너(xss.py)가 "주입 요청"과
# "조회 요청" 두 단계를 모두 수행해서 조회 응답에서도 페이로드가 그대로 남아있는 것을
# 확인했을 때만 부여한다. REFLECTED_UNSANITIZED보다 심각도를 더 높게 두는 이유는,
# 공격자 자신의 요청/응답에만 국한되지 않고 이후 방문자 전원에게 영향을 주기 때문이다.
STORED_XSS_CONFIRMED = "STORED_XSS_CONFIRMED"

# ============================================================
# Contract B가 실제로 허용하는 rule.label 값 (data-contracts-v1.md 2.4)
# ============================================================
RULE_LABEL_SUSPECTED = "SUSPECTED"
RULE_LABEL_SAFE = "SAFE"

# run status enum (data-contracts-v1.md 2.4, 4.2)
RUN_STATUS_COMPLETED = "COMPLETED"
RUN_STATUS_PARTIAL = "PARTIAL"
RUN_STATUS_FAILED = "FAILED"

# scan status enum (data-contracts-v1.md 2.4, 4.4)
SCAN_STATUS_COMPLETED = "COMPLETED"
SCAN_STATUS_FAILED = "FAILED"

SCHEMA_VERSION = "1.0"


@dataclass
class ScanRequest:
    """scan.request -- 실제로 보낸 요청 하나를 그대로 기록한다.

    Contract B는 "요청 1번 = Finding 1건"을 전제로 한다. 즉 GET과 POST를 모두
    시도했다면 각각 별도의 RawFinding으로 남아야 하며, 두 결과를 하나로 합쳐서는
    안 된다.
    """

    url: str
    method: str  # "GET" | "POST"
    input_location: str  # "query" | "form" | "json" (계약 enum). "header"는 아래 참고.
    parameter: str
    payload: str


@dataclass
class ScanResponse:
    """scan.response -- 응답에서 얻은 정보. scan.status=FAILED면 전부 None(=JSON null)."""

    http_status: int | None
    elapsed_ms: int | None
    baseline_elapsed_ms: int | None  # XSS는 null 허용(SQLi만 필수)
    evidence_summary: str | None
    html_path: str | None  # run 디렉터리 기준 상대경로. 예: "responses/XSS-000001.html"


@dataclass
class ScanRule:
    """scan.rule -- 규칙 기반 1차 판정. label은 SUSPECTED/SAFE만 허용(FAILED면 둘 다 null)."""

    label: str | None
    reason: str | None


@dataclass
class ScanError:
    """scan.error -- scan.status=FAILED일 때만 값이 있고, 그 외엔 None(=JSON null)."""

    code: str
    message: str
    retryable: bool


@dataclass
class ScanResult:
    """RawFinding.scan 전체."""

    status: str  # "COMPLETED" | "FAILED"
    request: ScanRequest
    response: ScanResponse
    rule: ScanRule
    error: ScanError | None


@dataclass
class RawFinding:
    """Contract B의 RawFinding 1건.

    case_id는 (대상, 파라미터, 테스트 케이스)에 대해 실행마다 바뀌지 않는
    안정적인 값이어야 한다(향후 ground truth와 결합하는 키). finding_id는 이번
    실행(scan_run_id) 안에서만 유일하면 된다.
    """

    case_id: str
    finding_id: str
    scanned_at: str  # ISO 8601, timezone offset 포함
    vuln_type: str  # 항상 "XSS"
    scan: ScanResult


@dataclass
class RunEnvelope:
    """Contract B 최상위 envelope. data/raw/<scan_run_id>/findings.json에 그대로 저장된다."""

    scan_run_id: str
    target_set_id: str
    started_at: str
    completed_at: str | None
    status: str  # run status enum
    findings: list[RawFinding] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION


# ============================================================
# Contract A: target manifest (docs/data-contracts-v1.md 3장)
# ============================================================
# 생산자는 환경 구축팀, 소비자는 우리(XSS·SQLi 스캐너)다. scanners/pipeline/xss.py가
# 이 타입으로 매니페스트 JSON을 읽어들인다.


@dataclass
class TargetCase:
    """Contract A의 target 항목 1개.

    계약이 정의하지 않은 필드도 하나 들어있다: verification_mode(아래 참고).
    """

    case_id: str
    vuln_type: str
    path: str  # "/"로 시작하는 상대 경로
    method: str  # "GET" | "POST"
    input_location: str  # "query" | "form" | "json"
    input_parameters: dict[str, str]  # 정상 기준값(비밀값 아님)
    attack_parameter: str  # input_parameters에 존재해야 함
    requires_pre_auth: bool
    auth_profile: str | None
    payload_profile: str
    manual_verification_profile: str
    # 계약에 없는 확장 필드: "reflected"(기본) | "stored". Stored XSS는 주입 후
    # 별도 조회 요청으로 저장 여부까지 확인해야 하는데, Contract A에는 이걸 표현할
    # 필드가 없어서 우리가 임시로 추가했다. 통합 담당과 추후 확인 필요.
    verification_mode: str = "reflected"
