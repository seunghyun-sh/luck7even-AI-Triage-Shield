"""AI를 이용한 XSS 페이로드 생성 모듈.

xss.py의 스캔/요청 로직과 완전히 분리되어 있다. 이렇게 나눠 둔 이유는 AI 호출
부분을 하나의 독립된 단계로 만들어서, 나중에 다른 생성 방식으로 교체하거나
테스트하기 쉽게 하기 위함이다.

핵심 동작: get_payloads()는 매번 AI를 호출하지 않는다. data/raw/ 아래에 저장된
캐시 파일이 있으면 그것을 그대로 재사용하고, 캐시가 없거나 --refresh-payloads
옵션으로 강제 갱신을 요청했을 때만 실제로 OpenAI API를 호출한다.
"""

from __future__ import annotations

import os
from pathlib import Path

from scanners import payload_cache

DEFAULT_CACHE_PATH = Path("data/raw/xss_ai_payloads.json")
DEFAULT_MODEL = "gpt-4o"
# OpenAI 호출이 완전히 실패했을 때(키 없음, 네트워크 오류 등) 사용할 최소한의
# 대체 페이로드. 이 값은 캐시 파일에 저장되지 않으므로, 다음 실행 때는 다시
# AI 호출을 시도하게 된다(문제가 해결됐을 수 있으므로).
FALLBACK_PAYLOADS = ["<script>alert(1)</script>", "<b>정상코드</b>"]

# OpenAI에게 역할을 부여하는 시스템 프롬프트.
SYSTEM_PROMPT = (
    "너는 웹 취약점 진단 도구 및 AI 오탐(False Positive) 판독기를 "
    "테스트하기 위한 데이터 생성기야."
)


class PayloadGenerationError(RuntimeError):
    """AI 페이로드 생성 호출을 사용할 수 없거나 실패했을 때 발생시키는 예외.

    generate_ai_payloads()는 실패 시 조용히 기본값을 반환하지 않고 이 예외를
    던진다. 그래야 호출하는 쪽(get_payloads)이 "이 실패를 캐시에 남길지 말지"를
    직접 결정할 수 있다.
    """


def _build_prompt(count: int) -> str:
    """OpenAI에게 보낼 사용자 프롬프트를 만든다.

    실제 공격 가능한 XSS 페이로드와, 특수문자는 있지만 무해한 오탐 유도용
    텍스트를 절반씩 섞어서 요청한다. 이렇게 하면 스캐너/AI 판정기가
    "특수문자만 보고 무조건 취약하다고 판단하는 오탐"을 만들어내는지도
    함께 테스트할 수 있다.
    """
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
    """OpenAI를 호출해서 새 XSS 테스트 페이로드 배치를 생성한다.

    실패하면 대체 페이로드를 조용히 반환하는 대신 PayloadGenerationError를
    던진다(위 클래스 설명 참고).
    """
    # openai 패키지를 상단이 아니라 여기서 지연 임포트(lazy import)하는 이유:
    # 캐시 히트 경로(get_payloads가 캐시를 그대로 반환하는 경우)에서는 이 함수
    # 자체가 호출되지 않으므로, openai 패키지나 API 키가 아예 없어도 스캔이 돌아가야
    # 하기 때문이다. 단, API 키 검사는 임포트보다 먼저 해서 불필요한 임포트 자체도
    # 건너뛴다.
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise PayloadGenerationError("OPENAI_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요.")

    from openai import OpenAI  # 실제로 API를 호출해야 할 때만 임포트

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
            temperature=0.8,  # 페이로드 종류가 다양하게 나오도록 약간 높은 값 사용
            max_tokens=2500,  # count개가 잘리지 않도록 여유 있게 설정
        )
    except Exception as e:  # openai 라이브러리 예외, 네트워크 오류 등 전부 포함
        raise PayloadGenerationError(f"OpenAI 호출 에러: {e}") from e

    raw_text = (response.choices[0].message.content or "").strip()
    # 프롬프트에서 "한 줄에 하나씩, 번호 매기지 말고"라고 요청했으므로
    # 줄바꿈 기준으로 나누고 빈 줄만 제거하면 된다.
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
    """페이로드 배치를 반환한다. 필요할 때만 AI를 호출한다.

    동작 순서:
    - force_refresh가 False이고 cache_path에 이미 저장된 배치가 있다면
      그것을 그대로 재사용한다(API 호출 없음).
    - 그렇지 않으면 AI를 호출한다. 성공하면 결과를 cache_path에 저장해서
      다음 실행부터는 캐시를 쓰게 만든다.
    - AI 호출이 실패하면 아주 작은 고정 페이로드 집합으로 대체하되,
      *캐시에는 저장하지 않는다*. 그래야 다음 실행이 실패한 대체값에
      계속 묶여있지 않고 AI 호출을 다시 시도하게 된다.
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
