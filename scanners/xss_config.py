"""bWAPP XSS 스캐너 설정 모듈.

실습 서버 주소, 로그인 계정, 공격 대상 목록처럼 "환경마다 달라지는 값"은
코드에 하드코딩하지 않는다. 이렇게 해야 공개 저장소에 실제 실습 서버 주소나
세션 계정 정보가 커밋되는 사고를 막을 수 있다. 대신 이 값들은 `.env` 파일과
타겟 목록 JSON 파일에서 읽어온다.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# bWAPP 로그인 페이지 경로. 호스트는 환경마다 다르지만 이 경로 자체는 고정이므로 상수로 둔다.
LOGIN_PATH = "/bWAPP/login.php"
# --targets 옵션을 안 주면 사용할 기본 타겟 목록 파일(저장소에 커밋된 예시 파일).
DEFAULT_TARGETS_FILE = Path("configs/xss_lab_targets.example.json")

# 환경 변수가 하나도 설정 안 되어 있을 때 쓰는 기본값들(로컬 개발 편의용).
DEFAULT_HOST = "http://127.0.0.1"
DEFAULT_LOGIN = "bee"
DEFAULT_PASSWORD = "bug"

# bWAPP XSS 실습 페이지들이 공통으로 받아들이고(그리고 종종 그대로 반사하는)
# 파라미터 이름들. xss.py에서 이 각각을 한 번에 하나씩 개별 공격한다.
INJECTABLE_PARAMS = (
    "firstname",
    "lastname",
    "title",
    "entry",
    "blog",
    "login",
    "password",
    "date",
)
# 파라미터뿐 아니라 HTTP 헤더 값도 반사되는 취약점(User-Agent, Referer, 커스텀
# 헤더 등)이 있으므로 별도의 공격 벡터로 취급한다.
INJECTABLE_HEADERS = ("User-Agent", "Referer", "bWAPP")


@dataclass(frozen=True)
class XSSScanConfig:
    """한 번의 스캔 실행에 필요한 설정값을 모아둔 불변 객체."""

    host: str  # 예: "http://192.168.199.130" (끝에 슬래시 없음)
    login: str  # bWAPP 로그인 계정
    password: str  # bWAPP 로그인 비밀번호
    target_paths: tuple[str, ...]  # host 뒤에 붙일 상대 경로들(예: "/bWAPP/xss_get.php")
    request_timeout: float = 5.0  # 각 HTTP 요청의 타임아웃(초)

    @property
    def login_url(self) -> str:
        """로그인 페이지의 전체 URL(호스트 + 경로)."""
        return f"{self.host}{LOGIN_PATH}"

    @property
    def target_urls(self) -> tuple[str, ...]:
        """공격 대상 경로들을 실제 호출 가능한 전체 URL로 변환한 목록."""
        return tuple(f"{self.host}{path}" for path in self.target_paths)


def load_target_paths(targets_file: Path) -> tuple[str, ...]:
    """타겟 목록 JSON 파일(문자열 배열)을 읽어서 튜플로 반환한다."""
    with targets_file.open(encoding="utf-8") as f:
        return tuple(json.load(f))


def load_config(targets_file: Path | None = None) -> XSSScanConfig:
    """환경 변수와 타겟 목록 파일로부터 스캔 설정을 만든다.

    이 함수를 호출하기 전에 `dotenv.load_dotenv()`를 먼저 실행해서
    `.env` 파일 내용이 os.environ에 반영되어 있어야 한다(xss.py의 main()에서 처리).
    targets_file을 안 주면 DEFAULT_TARGETS_FILE(예시 파일)을 사용한다.
    """
    return XSSScanConfig(
        host=os.getenv("XSS_LAB_HOST", DEFAULT_HOST).rstrip("/"),
        login=os.getenv("XSS_LAB_LOGIN", DEFAULT_LOGIN),
        password=os.getenv("XSS_LAB_PASSWORD", DEFAULT_PASSWORD),
        target_paths=load_target_paths(targets_file or DEFAULT_TARGETS_FILE),
    )
