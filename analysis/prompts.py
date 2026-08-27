def get_triage_prompt(url, parameter, payload, html_content):
    return f"""
    너는 최고 수준의 웹 보안 분석가다. 아래의 1차 탐지 결과와 실제 HTML 응답을 분석하라.

    [탐지 정보]
    - URL: {url}
    - 공격 파라미터: {parameter}
    - 주입한 페이로드: {payload}

    [응답 HTML 원문]
    {html_content}

    [핵심 지시사항]
    1. 주입한 페이로드가 필터링(인코딩) 없이 그대로 실행 가능한 상태인지, 아니면 안전하게 방어되었는지 판단해라.
    2. 판단 결과에 따라 라벨을 'VULNERABLE'(취약), 'SAFE'(양호), 'INCONCLUSIVE'(판단 불가/사람 확인 필요) 중 하나로 선택해라.
    3. XSS 진단 시: 응답 HTML에 페이로드가 존재하더라도 꺾쇠 기호(`<`, `>`)가 HTML Entity(`&lt;`, `&gt;`)로 치환되었다면 반드시 'SAFE'로 판정해라.
    4. 모든 분석 결과와 설명은 100% 한국어로 작성해라.
    """