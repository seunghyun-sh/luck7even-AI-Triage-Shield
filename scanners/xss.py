"""팀 실행 계약이 요구하는 공개 진입점: `scanners.xss.scan`.

main.py와 사전점검은 이 정확한 경로(`scanners.xss.scan`)를 찾는다(스캐너 통합
계약 변경 안내 3장). 실제 구현은 `scanners/pipeline/xss.py`에 두고, 여기서는
그대로 재수출만 한다 -- 구현을 다른 취약점 스캐너(예: 앞으로 추가될 XSS 변종)와
분리해서 관리하기 위함이며, 재수출한다고 해서 시그니처나 동작이 계약과
달라지지는 않는다.
"""

from __future__ import annotations

from scanners.pipeline.xss import scan

__all__ = ["scan"]
