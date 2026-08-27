"""AI가 생성한 스캐너 페이로드를 파일로 캐싱하는 범용 유틸리티.

이 모듈 자체는 순수 파일 입출력만 담당하고 OpenAI를 호출하지 않는다.
`scanners/tools/generate_xss_payload_profile.py`(사람이 직접 실행하는 오프라인
도구)가 이 모듈로 캐시를 저장하고, `scanners/payload_profiles.py`(런타임
스캐너)가 이 모듈로 캐시를 읽어온다. 캐시 파일은 data/raw/ 아래에 저장되어
(.gitignore에 이미 등록되어 있어 커밋되지 않음), 한 번 생성한 배치를 이후
스캔에서 계속 재사용한다.

캐시 파일 하나가 Contract A의 `payload_profile` 하나에 대응한다. 여러 실습
환경(Lumi Market, NovaStream 등)의 매니페스트가 같은 payload_profile 이름을
쓰면, 이 캐시를 공유해서 재사용하고 AI를 중복 호출하지 않는다.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CACHE_ROOT = Path("data/raw/payload_profiles")


@dataclass
class PayloadItem:
    """페이로드 1개 + Contract A(11.3)가 요구하는 안정적인 payload_case_id."""

    payload_case_id: str
    payload: str


@dataclass
class PayloadCache:
    profile: str  # Contract A의 payload_profile 값(예: "xss-v1")
    items: list[PayloadItem]
    source: str  # 이 배치가 어디서 왔는지("openai" 등)
    generated_at: str  # 생성 시각(UTC, ISO 8601 문자열)
    model: str | None = None  # 생성에 사용한 OpenAI 모델명(있는 경우)


def cache_path_for(profile: str, root: Path = DEFAULT_CACHE_ROOT) -> Path:
    """payload_profile 이름으로부터 캐시 파일 경로를 만든다."""
    return root / f"{profile}.json"


def load(cache_path: Path) -> PayloadCache | None:
    """캐시 파일을 읽어온다. 파일이 없거나 형식이 깨졌으면 None을 반환한다.

    None을 반환하는 경우 호출자(scanners.payload_profiles.load_payload_profile)는
    "캐시 없음"으로 간주하고 PayloadProfileMissingError를 던진다(런타임
    스캐너는 여기서 AI를 호출하지 않는다 -- scanners/tools/ 참고).
    """
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        items = [PayloadItem(**item) for item in data["items"]]
        return PayloadCache(
            profile=data["profile"],
            items=items,
            source=data["source"],
            generated_at=data["generated_at"],
            model=data.get("model"),
        )
    except (json.JSONDecodeError, TypeError, KeyError):
        # 파일이 손상됐거나 스키마가 안 맞는 경우 -> 캐시가 없는 것처럼 취급하고
        # 새로 생성하도록 조용히 넘어간다(에러를 던지지 않음).
        return None


def save(cache_path: Path, profile: str, payloads: list[str], source: str, model: str | None = None) -> PayloadCache:
    """페이로드 배치를 메타데이터와 함께 JSON 파일로 저장한다.

    각 페이로드에는 순번 기반의 payload_case_id(예: "ai-001")를 부여한다.
    같은 캐시 파일을 재사용하는 한 이 ID는 바뀌지 않는다.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    items = [PayloadItem(payload_case_id=f"ai-{i:03d}", payload=p) for i, p in enumerate(payloads, 1)]
    cache = PayloadCache(
        profile=profile,
        items=items,
        source=source,
        generated_at=datetime.now(timezone.utc).isoformat(),
        model=model,
    )
    # ensure_ascii=False: 한글/이모지 페이로드가 \uXXXX로 이스케이프되지 않고
    # 사람이 읽기 좋은 형태로 그대로 저장되도록 함.
    cache_path.write_text(json.dumps(asdict(cache), ensure_ascii=False, indent=2), encoding="utf-8")
    return cache
