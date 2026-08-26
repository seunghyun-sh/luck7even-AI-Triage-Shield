"""AI-assisted XSS payload generation.

Isolated from the scan/request logic in `xss.py` so the AI call is a single,
swappable step: `get_payloads()` reuses the cached batch in `data/raw/` and
only calls OpenAI when no cache exists or a refresh is explicitly requested.
"""

from __future__ import annotations

import os
from pathlib import Path

from scanners import payload_cache

DEFAULT_CACHE_PATH = Path("data/raw/xss_ai_payloads.json")
DEFAULT_MODEL = "gpt-4o"
FALLBACK_PAYLOADS = ["<script>alert(1)</script>", "<b>정상코드</b>"]

SYSTEM_PROMPT = (
    "너는 웹 취약점 진단 도구 및 AI 오탐(False Positive) 판독기를 "
    "테스트하기 위한 데이터 생성기야."
)


class PayloadGenerationError(RuntimeError):
    """Raised when the AI payload call is unavailable or fails."""


def _build_prompt(count: int) -> str:
    return f"""
bWAPP XSS 실습 환경에 입력할 테스트 페이로드 {count}개를 만들어줘.
아래 두 가지 유형을 절반씩 무작위로 섞어서 작성해:

[유형 1: 실제 악의적인 XSS 공격 페이로드]
- <script>, <iframe>, <svg>, onerror, javascript: 등을 활용한 실제 실행 가능한 스크립트.

[유형 2: 오탐(False Positive)을 유발하는 무해한 정상 코드 및 텍스트]
- 특수문자(<, >, ', ")가 포함되어 있어 스캐너는 의심할 수 있지만, 실제 악성 스크립트는 아닌 것.
- 예: <b>단순 강조 텍스트</b>, 5 < 10 (수식), "인용구", 하트 이모티콘 <3, 단순 텍스트 등.

절대 부가 설명이나 번호 매기기를 하지 말고, 오직 페이로드만 한 줄에 하나씩 순수 텍스트로 출력해.
"""


def generate_ai_payloads(count: int = 100, model: str | None = None) -> list[str]:
    """Call OpenAI for a fresh batch of XSS test payloads.

    Raises PayloadGenerationError instead of silently falling back, so the
    caller decides whether/when a failure should be cached.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise PayloadGenerationError("OPENAI_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요.")

    from openai import OpenAI  # lazy import: only needed once we're actually calling the API

    model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
    client = OpenAI(api_key=api_key)

    print(f"[AI] {count}개의 테스트 페이로드(진짜 공격 + 오탐 유도용) 생성을 요청 중... (model={model})")
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_prompt(count)},
            ],
            temperature=0.8,
            max_tokens=2500,  # count개가 잘리지 않도록 여유 있게 설정
        )
    except Exception as e:  # openai.* exceptions, network errors, etc.
        raise PayloadGenerationError(f"OpenAI 호출 에러: {e}") from e

    raw_text = (response.choices[0].message.content or "").strip()
    payloads = [p.strip() for p in raw_text.split("\n") if p.strip()]
    if not payloads:
        raise PayloadGenerationError("AI가 빈 응답을 반환했습니다.")

    print(f"[AI] 페이로드 생성 완료! (총 {len(payloads)}개 추출됨)")
    return payloads


def get_payloads(
    count: int = 100,
    cache_path: Path = DEFAULT_CACHE_PATH,
    force_refresh: bool = False,
) -> list[str]:
    """Return a payload batch, generating via AI only when needed.

    - If `cache_path` already holds a saved batch and `force_refresh` is
      False, that batch is reused (no API call).
    - Otherwise the AI is called; a successful result is saved to
      `cache_path` for next time. A failed call falls back to a tiny static
      payload set *without* caching it, so the next run retries the AI
      instead of being stuck on the fallback.
    """
    if not force_refresh:
        cached = payload_cache.load(cache_path)
        if cached and cached.payloads:
            print(
                f"[AI] 캐시된 페이로드 사용: {cache_path} "
                f"({len(cached.payloads)}개, generated_at={cached.generated_at})"
            )
            return cached.payloads

    model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
    try:
        payloads = generate_ai_payloads(count, model=model)
    except PayloadGenerationError as e:
        print(f"[AI] {e}")
        print("[AI] 기본 페이로드로 대체합니다. (캐시에는 저장하지 않음)")
        return list(FALLBACK_PAYLOADS)

    payload_cache.save(cache_path, payloads, source="openai", model=model)
    return payloads
