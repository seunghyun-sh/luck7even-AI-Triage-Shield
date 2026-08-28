"""여러 스캐너(XSS, SQLi 등)가 공통으로 쓰는 HTTP 헬퍼 모음."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import requests


class RedirectBlockedError(requests.RequestException):
    """Raised before a redirect can leave the authorized request origin."""


def _origin(url: str) -> tuple[str, str, int | None]:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme == "http":
            default_port = 80
        elif scheme == "https":
            default_port = 443
        else:
            default_port = None
        return scheme, (parsed.hostname or "").lower(), parsed.port or default_port
    except ValueError as error:
        raise RedirectBlockedError("Redirect target URL is invalid.") from error


def safe_request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: float,
    max_redirects: int = 5,
    **kwargs,
) -> requests.Response:
    """Follow redirects only while they remain on the authorized origin.

    Scheme, hostname, and effective port must all remain identical. A blocked
    redirect raises before credentials or payload data can be sent elsewhere.
    """
    authorized_origin = _origin(url)
    current_url = url
    current_method = method
    follow_kwargs = dict(kwargs)

    for _ in range(max_redirects + 1):
        response = session.request(
            current_method,
            current_url,
            timeout=timeout,
            allow_redirects=False,
            **follow_kwargs,
        )
        if not response.is_redirect:
            return response

        location = response.headers.get("Location", "")
        try:
            next_url = urljoin(current_url, location)
        except ValueError as error:
            raise RedirectBlockedError("Redirect target URL is invalid.") from error
        if _origin(next_url) != authorized_origin:
            raise RedirectBlockedError(
                "Redirect target is outside the authorized origin."
            )

        current_url = next_url
        if response.status_code not in {307, 308}:
            current_method = "GET"
            follow_kwargs.pop("data", None)
            follow_kwargs.pop("json", None)

    raise requests.TooManyRedirects("Redirect limit exceeded.")
