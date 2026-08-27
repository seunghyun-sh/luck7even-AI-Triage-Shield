"""Shared input and output models for scanner and AI results."""

from __future__ import annotations

from dataclasses import dataclass

# 규칙 기반 1차 판정 라벨(rule_label). 아래로 갈수록 "더 위험함"을 의미하며,
# scanners/xss_rules.py의 most_severe()가 이 순서로 우선순위를 매긴다.
NOT_REFLECTED = "NOT_REFLECTED"  # 페이로드가 응답에 전혀 나타나지 않음 (필터링됨/무관)
REFLECTED_ESCAPED = "REFLECTED_ESCAPED"  # HTML 이스케이프된 형태로만 반사됨 (대체로 안전)
REFLECTED_UNSANITIZED = "REFLECTED_UNSANITIZED"  # 입력 그대로 반사됨 (취약 가능성 높음)


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
