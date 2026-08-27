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

# 타겟의 검증 방식. "reflected"(기본값)는 요청 1번의 응답만 보고 즉시 판정하고,
# "stored"는 페이로드를 주입(POST)한 뒤 별도의 조회(GET) 요청으로 실제로 저장되어
# 남아있는지까지 2단계로 확인한다. bWAPP의 xss_stored_*.php 같은 게시판/방명록형
# 페이지가 여기 해당한다.
MODE_REFLECTED = "reflected"
MODE_STORED = "stored"


@dataclass(frozen=True)
class XSSTarget:
    """공격 대상 페이지 1개에 대한 정보.

    타겟 목록 JSON 파일의 각 항목은 다음 두 형태 중 하나일 수 있다.
    1) 단순 문자열: "/bWAPP/xss_get.php" -> mode는 자동으로 "reflected"가 된다.
    2) 객체: {"path": "/bWAPP/xss_stored_1.php", "mode": "stored"} 처럼
       Stored XSS 2단계 검증이 필요한 대상을 명시적으로 표시할 수 있다.
       조회 페이지가 주입 페이지와 다르면 "verify_path"로 별도 지정 가능하며,
       생략하면 path와 동일한 페이지를 다시 조회한다.
    """

    path: str
    mode: str = MODE_REFLECTED
    verify_path: str | None = None

    @property
    def effective_verify_path(self) -> str:
        """Stored 모드에서 실제로 재조회할 경로. 지정 안 했으면 주입 경로와 동일."""
        return self.verify_path or self.path


@dataclass(frozen=True)
class XSSScanConfig:
    """한 번의 스캔 실행에 필요한 설정값을 모아둔 불변 객체."""

    host: str  # 예: "http://192.168.199.130" (끝에 슬래시 없음)
    login: str  # bWAPP 로그인 계정
    password: str  # bWAPP 로그인 비밀번호
    targets: tuple[XSSTarget, ...]  # 공격 대상 페이지 목록(경로 + 검증 방식)
    request_timeout: float = 5.0  # 각 HTTP 요청의 타임아웃(초)

    @property
    def login_url(self) -> str:
        """로그인 페이지의 전체 URL(호스트 + 경로)."""
        return f"{self.host}{LOGIN_PATH}"

    @property
    def target_urls(self) -> tuple[str, ...]:
        """공격 대상 경로들을 실제 호출 가능한 전체 URL로 변환한 목록."""
        return tuple(f"{self.host}{t.path}" for t in self.targets)


def load_targets(targets_file: Path) -> tuple[XSSTarget, ...]:
    """타겟 목록 JSON 파일을 읽어서 XSSTarget 튜플로 변환한다.

    문자열 항목과 객체 항목이 섞여 있어도 된다(위 XSSTarget 설명 참고).
    """
    with targets_file.open(encoding="utf-8") as f:
        raw_targets = json.load(f)

    targets = []
    for entry in raw_targets:
        if isinstance(entry, str):
            targets.append(XSSTarget(path=entry))
        else:
            targets.append(
                XSSTarget(
                    path=entry["path"],
                    mode=entry.get("mode", MODE_REFLECTED),
                    verify_path=entry.get("verify_path"),
                )
            )
    return tuple(targets)


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
        targets=load_targets(targets_file or DEFAULT_TARGETS_FILE),
    )
