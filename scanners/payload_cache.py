"""AI가 생성한 스캐너 페이로드를 파일로 캐싱하는 범용 유틸리티.

LLM을 호출해서 페이로드를 생성하는 작업은 실행할 때마다 시간과 비용(API 요금)이
든다. 그래서 한 번 성공적으로 생성한 배치는 data/raw/ 아래 파일로 저장해두고
(.gitignore에 이미 등록되어 있어 커밋되지 않음), 이후 스캔에서는 별도로
"다시 생성해줘"라고 요청하지 않는 한 이 캐시를 그대로 재사용한다.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PayloadCache:
    """캐시 파일 하나에 저장되는 내용을 표현하는 데이터 모델."""

    payloads: list[str]  # 실제 페이로드 문자열 목록
    source: str  # 이 배치가 어디서 왔는지("openai" 등)
    generated_at: str  # 생성 시각(UTC, ISO 8601 문자열)
    model: str | None = None  # 생성에 사용한 OpenAI 모델명(있는 경우)


def load(cache_path: Path) -> PayloadCache | None:
    """캐시 파일을 읽어온다. 파일이 없거나 형식이 깨졌으면 None을 반환한다.

    None을 반환하는 경우 호출자(xss_payloads.get_payloads)는 "캐시 없음"으로
    간주하고 AI를 새로 호출하게 된다.
    """
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        return PayloadCache(**data)
    except (json.JSONDecodeError, TypeError, KeyError):
        # 파일이 손상됐거나 스키마가 안 맞는 경우 -> 캐시가 없는 것처럼 취급하고
        # 새로 생성하도록 조용히 넘어간다(에러를 던지지 않음).
        return None


def save(cache_path: Path, payloads: list[str], source: str, model: str | None = None) -> None:
    """페이로드 배치를 메타데이터와 함께 JSON 파일로 저장한다.

    상위 디렉터리(data/raw 등)가 없으면 자동으로 생성한다.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = PayloadCache(
        payloads=payloads,
        source=source,
        generated_at=datetime.now(timezone.utc).isoformat(),
        model=model,
    )
    # ensure_ascii=False: 한글/이모지 페이로드가 \uXXXX로 이스케이프되지 않고
    # 사람이 읽기 좋은 형태로 그대로 저장되도록 함.
    cache_path.write_text(json.dumps(asdict(cache), ensure_ascii=False, indent=2), encoding="utf-8")
