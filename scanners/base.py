"""여러 스캐너(XSS, SQLi 등)가 공통으로 쓰는 HTTP 헬퍼 모음."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import requests


def safe_request(
    session: requests.Session, method: str, url: str, *, timeout: float, max_redirects: int = 5, **kwargs
) -> requests.Response:
    """리다이렉트를 자동으로 따라가되, 같은 호스트 밖으로 나가면 멈춘다.

    실행 계약(11.5) 요구사항: "스캐너가 임의 외부 URL로 redirect된 요청을 계속하지
    않는다." `requests`의 기본 동작(allow_redirects=True)은 리다이렉트 대상이
    어디든 그냥 따라가므로, 타겟이 공격받거나 오설정되어 외부 호스트로 리다이렉트를
    돌려주면 우리가 모르는 사이에 그 외부 서버로 요청(쿠키 포함)을 계속 보내게 될
    위험이 있다. 그래서 리다이렉트 전마다 호스트가 원래 요청과 같은지 확인하고,
    다르면 그 시점의 응답(3xx)을 그대로 반환하고 멈춘다.
    """
    origin = urlsplit(url).netloc
    current_url = url
    current_method = method
    follow_kwargs = dict(kwargs)

    for _ in range(max_redirects + 1):
        response = session.request(current_method, current_url, timeout=timeout, allow_redirects=False, **follow_kwargs)
        if not response.is_redirect:
            return response

        location = response.headers.get("Location", "")
        next_url = urljoin(current_url, location)
        if urlsplit(next_url).netloc != origin:
            # 외부 호스트로 튀는 리다이렉트: 따라가지 않고 이 3xx 응답 자체를 반환한다.
            return response

        current_url = next_url
        # 대부분의 3xx는 다음 요청을 GET으로 바꾸는 것이 표준 브라우저 동작과
        # 가장 가깝다(307/308처럼 메서드를 유지해야 하는 경우는 이 실습 대상들에서
        # 쓰이지 않으므로 단순화한다).
        current_method = "GET"
        follow_kwargs.pop("data", None)
        follow_kwargs.pop("json", None)

    return response
