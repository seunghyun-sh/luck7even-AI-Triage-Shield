"""반사(reflection) 여부를 판정하는 규칙 기반 로직 -- 스캐너의 1차 판정(rule_label).

단순 Yes/No 2단계가 아니라 3단계로 나누는 이유: 페이로드가 HTML 이스케이프된 채로
돌아온 경우(예: <script> -> &lt;script&gt;)는 "반사는 됐지만" 브라우저에서 스크립트로
실행되지 않으므로 실제로는 안전한 경우가 대부분이다. 이렇게 미리 구분해두면 이후
AI 2차 판정 단계에서 오탐을 줄이는 데 도움이 된다.

여기서 쓰는 라벨(NOT_REFLECTED 등)은 팀 공통 데이터 계약(analysis/models.py)에는
없는, 이 모듈 내부 전용 값이다. 공통 계약의 canonical 모델은 extra="forbid"로
임의 필드/값 추가를 막기 때문에, 이런 세분화된 내부 판정을 그 안에 넣을 수 없다.
대신 scanners/xss_report.py가 이 내부 라벨을 계약이 허용하는 RuleLabel(SUSPECTED/
SAFE)로 압축해서 내보낸다.
"""

from __future__ import annotations

import html

# 판정 라벨별 심각도 점수. 숫자가 클수록 더 위험하다고 간주한다.
# GET/POST 두 응답 중 더 심각한 쪽을 최종 결과로 채택할 때, 그리고 저장형 XSS의
# "주입 응답"과 "조회 응답" 판정을 합칠 때 모두 이 우선순위로 비교한다(most_severe 참고).
NOT_REFLECTED = "NOT_REFLECTED"  # 페이로드가 응답에 전혀 나타나지 않음 (필터링됨/무관)
REFLECTED_ESCAPED = "REFLECTED_ESCAPED"  # HTML 이스케이프된 형태로만 반사됨 (대체로 안전)
REFLECTED_UNSANITIZED = "REFLECTED_UNSANITIZED"  # 입력 그대로 반사됨 (취약 가능성 높음)
# Reflected XSS는 "요청 -> 응답" 한 번으로 판정할 수 있지만, Stored XSS는 그렇지 않다.
# 글을 쓸 때(POST)는 정상적으로 저장됐다는 메시지만 보일 수도 있고, 실제로 다른 사람이
# 그 글을 읽을 때(GET, 별도 요청) 비로소 스크립트가 실행된다. 그래서 이 라벨은
# classify_reflection()이 직접 매기지 않고, 스캐너가 "주입 요청"과 "조회 요청" 두
# 단계를 모두 수행해서 조회 응답에서도 페이로드가 그대로 남아있는 것을 확인했을 때만
# 부여한다. REFLECTED_UNSANITIZED보다 심각도를 더 높게 두는 이유는, 공격자 자신의
# 요청/응답에만 국한되지 않고 이후 방문자 전원에게 영향을 주기 때문이다.
STORED_XSS_CONFIRMED = "STORED_XSS_CONFIRMED"

_SEVERITY = {
    NOT_REFLECTED: 0,
    REFLECTED_ESCAPED: 1,
    REFLECTED_UNSANITIZED: 2,
    STORED_XSS_CONFIRMED: 3,
}


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
