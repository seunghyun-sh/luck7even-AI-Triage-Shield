"""Shared input and output models for scanner and AI results."""

from __future__ import annotations

from dataclasses import dataclass

# 규칙 기반 1차 판정 라벨(rule_label). 아래로 갈수록 "더 위험함"을 의미하며,
# scanners/xss_rules.py의 most_severe()가 이 순서로 우선순위를 매긴다.
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


@dataclass
class Finding:
    """스캐너가 만들어내는 결과 1건(취약점 후보 1개)을 표현하는 데이터 모델.

    이 값들이 그대로 data/raw/*.jsonl 한 줄에 저장되고, 이후 analysis/ai_triage.py
    단계에서 OpenAI에게 2차 판정을 요청할 때 입력으로 재사용될 예정이다.
    """

    finding_id: str  # 발견된 취약점(테스트 1건)의 고유 ID. xss.py에서 uuid4로 생성.
    vuln_type: str  # 취약점 종류. XSS 스캐너에서는 항상 "XSS".
    url: str  # 공격을 시도한 대상 URL.
    parameter: str  # 실제로 페이로드를 주입한 파라미터명(또는 헤더명) 단 하나.
    payload: str  # 그 요청에 실제로 주입한 페이로드 원문.
    rule_label: str  # 위 상수 중 하나(1차 규칙 기반 판정 결과).
    response_body: str  # 공격 요청에 대한 응답 본문 전체(원문 그대로, 자르지 않음).

    def to_dict(self) -> dict:
        """JSON Lines로 저장하기 위해 일반 dict로 변환한다."""
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "rule_label": self.rule_label,
            "response_body": self.response_body,
        }
