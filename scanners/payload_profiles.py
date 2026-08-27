"""런타임 스캐너가 payload_profile을 읽어오는 곳.

중요: 이 모듈은 OpenAI(또는 어떤 AI API도)를 호출하지 않는다. 팀 실행 계약은
"런타임 스캐너는 OpenAI API를 호출하지 않는다"고 명시하며, payload profile은
아래 순서로 미리 만들어져 있어야 한다.

  별도 사전 생성 도구(scanners/tools/generate_xss_payload_profile.py)
  -> 사람이 후보 검토
  -> 안정적인 payload_case_id 부여(생성 도구가 자동으로 붙임)
  -> 버전이 고정된 payload profile 저장(data/raw/payload_profiles/<profile>.json)
  -> 런타임 스캐너(scan())는 이 모듈로 고정 목록만 로드

캐시가 없거나 손상된 경우 AI를 대신 호출하거나 임의 fallback으로 조용히
계속 실행하지 않는다. 원인을 숨기지 않고 PayloadProfileMissingError를 던져서
실행 준비 실패로 처리한다.
"""

from __future__ import annotations

from pathlib import Path

from scanners import payload_cache


class PayloadProfileMissingError(RuntimeError):
    """요청한 payload_profile의 고정 목록이 없거나 읽을 수 없을 때 발생시키는 예외."""


def load_payload_profile(
    profile: str, cache_root: Path = payload_cache.DEFAULT_CACHE_ROOT
) -> list[tuple[str, str]]:
    """저장된 payload_profile을 (payload_case_id, payload) 목록으로 반환한다.

    profile이 여러 실습 환경(Lumi Market, NovaStream 등)의 매니페스트에서
    공유될 수 있으므로, 한 번 생성해두면 그 profile을 참조하는 모든 대상이
    같은 캐시 파일을 재사용한다.
    """
    cache_path = payload_cache.cache_path_for(profile, cache_root)
    cached = payload_cache.load(cache_path)
    if not cached or not cached.items:
        raise PayloadProfileMissingError(
            f"payload_profile '{profile}'에 대한 고정 목록이 없습니다: {cache_path}\n"
            "먼저 'python -m scanners.tools.generate_xss_payload_profile "
            f"--profile {profile}'로 생성한 뒤 검토하세요."
        )
    return [(item.payload_case_id, item.payload) for item in cached.items]
