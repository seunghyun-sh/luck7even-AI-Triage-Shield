"""여러 스캐너(XSS, SQLi 등)가 공통으로 쓰는 HTTP 세션/저장 헬퍼 모음."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

import requests


def safe_header_value(value: str) -> str:
    """임의의 문자열을 HTTP 헤더 값으로 안전하게 보낼 수 있는 형태로 변환한다.

    HTTP 헤더는 Latin-1(ISO-8859-1)로만 인코딩할 수 있다. 그런데 AI가 생성한
    페이로드에는 한글, 이모지처럼 Latin-1로 표현할 수 없는 문자가 섞여 있을 수
    있고, 이를 그대로 User-Agent 같은 헤더에 넣으면 requests/http.client 내부에서
    UnicodeEncodeError가 발생해 스캔 전체가 죽어버린다.

    그래서 Latin-1로 인코딩 가능한 값은 그대로 두고, 그렇지 않은 값만
    percent-encoding(URL 인코딩)으로 바꿔서 보낸다. 어차피 실제 HTTP 헤더도
    그런 문자를 이스케이프 없이 담을 수 없으므로, 이 변환이 원래 취약점 테스트의
    의미를 크게 훼손하지는 않는다.
    """
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        return quote(value, safe="")


class LabSession:
    """격리된 실습 대상(bWAPP 등)에 인증된 상태로 요청을 보내기 위한 래퍼.

    내부적으로 requests.Session을 하나 유지해서 로그인 시 발급된 세션 쿠키가
    이후 모든 GET/POST 요청에 자동으로 실려 나가도록 한다.
    """

    def __init__(self, host: str, timeout: float = 5.0) -> None:
        self.host = host.rstrip("/")  # 끝에 슬래시가 있어도 없어도 동작하도록 정규화
        self.timeout = timeout
        self._session = requests.Session()

    def login(self, login_path: str, credentials: dict, success_markers: Iterable[str]) -> bool:
        """login_path로 자격 증명을 POST하고, 로그인 성공으로 보이는지 판단한다.

        success_markers에 담긴 문자열 중 하나라도 응답 URL이나 응답 본문에
        포함되어 있으면 로그인 성공으로 간주한다(예: "portal.php", "Welcome").
        이는 서버가 별도의 로그인 성공 API를 제공하지 않는 실습 환경 특성상
        휴리스틱으로 판단하는 것이며, 100% 정확하지는 않을 수 있다.
        """
        response = self._session.post(f"{self.host}{login_path}", data=credentials, timeout=self.timeout)
        return any(marker in response.url or marker in response.text for marker in success_markers)

    def get(self, url: str, **kwargs) -> requests.Response:
        """GET 요청. timeout을 지정하지 않으면 인스턴스 기본값을 사용한다."""
        kwargs.setdefault("timeout", self.timeout)
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """POST 요청. timeout을 지정하지 않으면 인스턴스 기본값을 사용한다."""
        kwargs.setdefault("timeout", self.timeout)
        return self._session.post(url, **kwargs)


def write_csv(path: str | Path, rows: list[dict], fieldnames: list[str]) -> None:
    """스캔 결과를 CSV 파일로 저장한다. 상위 디렉터리가 없으면 자동 생성한다.

    (참고: XSS 스캐너는 현재 CSV 대신 write_jsonl을 사용하지만, 다른 스캐너나
    용도에서 재사용할 수 있도록 CSV 저장 함수도 함께 남겨둔다.)
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: str | Path, rows: list[dict]) -> None:
    """스캔 결과를 JSON Lines(한 줄에 객체 하나)로 저장한다.

    JSON Lines를 쓰는 이유: finding 하나하나가 완결된 JSON 객체이므로, 이후
    AI 2차 판정 단계에서 파일을 한 줄씩 읽어 처리하기 쉽고, 응답 본문처럼
    긴 문자열이 섞여 있어도 CSV처럼 줄바꿈/쉼표 이스케이프를 신경 쓸 필요가 없다.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            # ensure_ascii=False: response_body에 담긴 한글 등이 유니코드 이스케이프
            # 없이 그대로 저장되도록 함(가독성 + 파일 크기 절약).
            f.write(json.dumps(row, ensure_ascii=False))
            f.write("\n")
