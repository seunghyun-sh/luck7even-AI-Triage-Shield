"""반사(reflection) 여부를 판정하는 규칙 기반 로직 -- 스캐너의 1차 판정(rule_label).

단순 Yes/No 2단계가 아니라 3단계로 나누는 이유: 페이로드가 HTML 이스케이프된 채로
돌아온 경우(예: <script> -> &lt;script&gt;)는 "반사는 됐지만" 브라우저에서 스크립트로
실행되지 않으므로 실제로는 안전한 경우가 대부분이다. 이렇게 미리 구분해두면 이후
AI 2차 판정(analysis/ai_triage.py) 단계에서 오탐을 줄이는 데 도움이 된다.
"""

from __future__ import annotations

import html

from analysis.models import NOT_REFLECTED, REFLECTED_ESCAPED, REFLECTED_UNSANITIZED

# 판정 라벨별 심각도 점수. 숫자가 클수록 더 위험하다고 간주한다.
# GET/POST 두 응답 중 더 심각한 쪽을 최종 결과로 채택할 때 사용됨(most_severe 참고).
_SEVERITY = {NOT_REFLECTED: 0, REFLECTED_ESCAPED: 1, REFLECTED_UNSANITIZED: 2}


def classify_reflection(payload: str, response_body: str) -> str:
    """페이로드 하나가 응답 본문에 어떤 형태로 반사됐는지 판정한다.

    판정 순서(우선순위):
    1) 페이로드 원문이 응답에 그대로 들어있으면 -> REFLECTED_UNSANITIZED (취약 가능성 높음)
    2) 원문은 없지만 HTML 이스케이프된 형태(&lt;, &gt; 등)로 들어있으면 -> REFLECTED_ESCAPED
    3) 둘 다 아니면 -> NOT_REFLECTED (필터링되었거나 애초에 반사되지 않음)
    """
    if payload and payload in response_body:
        return REFLECTED_UNSANITIZED

    escaped = html.escape(payload)
    # escaped == payload인 경우(특수문자가 없는 순수 텍스트 페이로드)는 이스케이프 여부를
    # 구분할 의미가 없으므로 제외한다. 이미 위 조건에서 원문 매칭으로 처리됐을 것이다.
    if escaped and escaped != payload and escaped in response_body:
        return REFLECTED_ESCAPED

    return NOT_REFLECTED


def most_severe(*results: tuple[str, str]) -> tuple[str, str]:
    """같은 테스트에 대한 (판정 라벨, 응답 본문) 결과 여러 개 중 가장 심각한 것 하나를 고른다.

    예: GET 응답에서는 필터링됐지만 POST 응답에서는 그대로 반사된 경우,
    더 위험한 POST 쪽 결과를 최종 finding으로 남기기 위해 사용한다.
    """
    return max(results, key=lambda pair: _SEVERITY[pair[0]])
