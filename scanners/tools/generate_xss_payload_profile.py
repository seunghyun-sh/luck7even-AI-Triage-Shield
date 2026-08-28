"""XSS payload profile을 AI로 생성하는 오프라인 도구 (사람이 직접 실행).

실행 계약은 "런타임 스캐너는 OpenAI API를 호출하지 않는다"고 명시한다. 그래서
AI 페이로드 생성은 스캔 경로(scanners/pipeline/xss.py, scanners/payload_profiles.py)
밖으로 완전히 분리했다. 이 스크립트를 사람이 직접 실행해서 후보를 만들고,
`data/raw/payload_profiles/<profile>.json`에 저장된 결과를 검토한 뒤(필요하면
직접 편집해서) 그 상태로 커밋/공유해서 쓴다. 런타임 스캐너는 이 파일이
있으면 그대로 읽고, 없으면 실행 준비 실패로 처리할 뿐 절대 이 스크립트를
대신 호출하지 않는다.

사용 예:
    python -m scanners.tools.generate_xss_payload_profile --profile xss-v1 --count 100
"""

from __future__ import annotations

import argparse
import os

from scanners import payload_cache

DEFAULT_MODEL = "gpt-4o"
DEFAULT_COUNT = 100

# OpenAI에게 역할을 부여하는 시스템 프롬프트.
SYSTEM_PROMPT = (
    "너는 웹 취약점 진단 도구 및 AI 오탐(False Positive) 판독기를 "
    "테스트하기 위한 데이터 생성기야."
)


class PayloadGenerationError(RuntimeError):
    """AI 페이로드 생성 호출이 실패했을 때 발생시키는 예외."""


def _build_prompt(count: int) -> str:
    """OpenAI에게 보낼 사용자 프롬프트를 만든다.

    실제 공격 가능한 XSS 페이로드와, 특수문자는 있지만 무해한 오탐 유도용
    텍스트를 절반씩 섞어서 요청한다. 이렇게 하면 스캐너/AI 판정기가
    "특수문자만 보고 무조건 취약하다고 판단하는 오탐"을 만들어내는지도
    함께 테스트할 수 있다.
    """
    return f"""
웹 애플리케이션의 XSS 취약점 스캐너에 입력할 테스트 페이로드 {count}개를 만들어줘.
아래 두 가지 유형을 절반씩 무작위로 섞어서 작성해:

[유형 1: 실제 악의적인 XSS 공격 페이로드]
- <script>, <iframe>, <svg>, onerror, javascript: 등을 활용한 실제 실행 가능한 스크립트.

[유형 2: 오탐(False Positive)을 유발하는 무해한 정상 코드 및 텍스트]
- 특수문자(<, >, ', ")가 포함되어 있어 스캐너는 의심할 수 있지만, 실제 악성 스크립트는 아닌 것.
- 예: <b>단순 강조 텍스트</b>, 5 < 10 (수식), "인용구", 하트 이모티콘 <3, 단순 텍스트 등.

절대 부가 설명이나 번호 매기기를 하지 말고, 오직 페이로드만 한 줄에 하나씩 순수 텍스트로 출력해.
"""


def generate_ai_payloads(
    count: int = DEFAULT_COUNT, model: str | None = None
) -> list[str]:
    """OpenAI를 호출해서 새 XSS 테스트 페이로드 배치를 생성한다."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise PayloadGenerationError(
            "OPENAI_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요."
        )

    from openai import OpenAI

    model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
    client = OpenAI(api_key=api_key)

    print(
        f"[AI] {count}개의 XSS 테스트 페이로드(진짜 공격 + 오탐 유도용) 생성을 요청 중... (model={model})"
    )
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
    payloads = [p.strip() for p in raw_text.split("\n") if p.strip()]
    if not payloads:
        raise PayloadGenerationError("AI가 빈 응답을 반환했습니다.")

    print(f"[AI] 페이로드 생성 완료! (총 {len(payloads)}개 추출됨)")
    return payloads


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()

    parser = argparse.ArgumentParser(
        description="XSS payload profile을 AI로 생성해 data/raw/payload_profiles/에 저장한다."
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="예: xss-v1 (매니페스트의 payload_profile 값과 일치해야 함)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
        help=f"생성할 페이로드 개수 (기본 {DEFAULT_COUNT})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="이미 저장된 profile 파일이 있어도 덮어쓴다(기본은 실수 방지를 위해 거부).",
    )
    args = parser.parse_args()

    cache_path = payload_cache.cache_path_for(args.profile)
    if cache_path.exists() and not args.force:
        raise SystemExit(
            f"이미 '{cache_path}'가 있습니다. 덮어쓰려면 --force를 붙이세요 "
            "(사람이 검토한 기존 목록을 실수로 지우지 않기 위한 안전장치)."
        )

    model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
    payloads = generate_ai_payloads(args.count, model=model)
    cache = payload_cache.save(
        cache_path, args.profile, payloads, source="openai", model=model
    )

    print(f"\n저장 완료: {cache_path} ({len(cache.items)}개)")
    print(
        "계속 진행하기 전에 이 파일을 열어 후보를 검토하세요. 필요하면 항목을 직접 수정/삭제해도 됩니다."
    )


if __name__ == "__main__":
    main()
