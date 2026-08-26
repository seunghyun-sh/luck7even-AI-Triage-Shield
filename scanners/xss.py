"""bWAPP XSS reflection scanner.

Logs into the lab app, replays each AI-assisted payload against every
configured target (as both GET and POST, plus commonly-injectable headers),
and records whether the payload was reflected verbatim in the response.

Run as a script (`python scanners/xss.py`) or as a module
(`python -m scanners.xss`); both work thanks to the path bootstrap below.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:  # `python scanners/xss.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from dotenv import load_dotenv

from analysis.models import ReflectionFinding
from scanners import base, xss_payloads
from scanners.xss_config import INJECTABLE_HEADERS, INJECTABLE_PARAMS, LOGIN_PATH, load_config

DEFAULT_OUTPUT = Path("data/raw/raw-findings-xss-multi.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the bWAPP XSS reflection scan.")
    parser.add_argument("--targets", type=Path, help="JSON file listing target paths.")
    parser.add_argument("--count", type=int, default=100, help="Number of AI payloads to request.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="CSV output path.")
    parser.add_argument(
        "--refresh-payloads",
        action="store_true",
        help="Ignore the cached AI payload file and call the AI again.",
    )
    parser.add_argument(
        "--payload-cache",
        type=Path,
        default=xss_payloads.DEFAULT_CACHE_PATH,
        help="Path to the cached AI payload file.",
    )
    return parser.parse_args()


def run_scan(session: base.LabSession, target_urls: list[str], payloads: list[str]) -> list[ReflectionFinding]:
    findings: list[ReflectionFinding] = []
    skipped = 0

    for url_idx, url in enumerate(target_urls, 1):
        print(f"\n[{url_idx}/{len(target_urls)}] 타겟 스캔 중: {url}")

        for i, payload in enumerate(payloads, 1):
            # [범용 인젝션] GET, POST, Stored 등에 자주 쓰이는 파라미터 이름을 모두 포함
            attack_params = {name: payload for name in INJECTABLE_PARAMS}
            attack_params.update({"action": "add", "form": "submit"})
            # [헤더 인젝션] User-Agent, Referer, Custom Header 취약점을 노리기 위한 헤더 조작
            attack_headers = {name: payload for name in INJECTABLE_HEADERS}

            try:
                res_get = session.get(url, params=attack_params, headers=attack_headers)
                res_post = session.post(url, data=attack_params, headers=attack_headers)
            except requests.RequestException:
                skipped += 1
                continue

            reflected_in_get = payload in res_get.text
            is_reflected = reflected_in_get or payload in res_post.text
            snippet = (res_get.text if reflected_in_get else res_post.text)[:200]

            # 터미널 출력은 너무 길어지지 않게 10번 단위 또는 반사 발생 시에만 출력
            if i % 10 == 0 or is_reflected:
                status = "Yes" if is_reflected else "No (Filtered)"
                print(f"   ㄴ [Test {i}/{len(payloads)}] 반사 여부: {status} (페이로드: {payload[:20]}...)")

            findings.append(
                ReflectionFinding(
                    target_url=url,
                    payload=payload,
                    is_reflected=is_reflected,
                    response_snippet=snippet,
                )
            )

    if skipped:
        print(f"\n[Info] 요청 실패(타임아웃 등)로 스킵된 테스트: {skipped}건")

    return findings


def main() -> None:
    load_dotenv()
    args = parse_args()
    config = load_config(args.targets)

    print("=" * 50)
    print("[다중 URL] 지능형 XSS 스캐너 작동 시작")
    print("=" * 50)

    print(f"\n[1단계] 로그인 시도 중... (URL: {config.login_url})")
    session = base.LabSession(config.host, timeout=config.request_timeout)
    try:
        logged_in = session.login(
            LOGIN_PATH,
            {"login": config.login, "password": config.password, "security_level": "0", "form": "submit"},
            success_markers=("portal.php", "Welcome"),
        )
    except requests.RequestException as e:
        print(f"에러: {e}")
        raise SystemExit(1) from e
    print("로그인 성공!" if logged_in else "로그인 실패 가능성 있음.")

    payloads = xss_payloads.get_payloads(
        count=args.count,
        cache_path=args.payload_cache,
        force_refresh=args.refresh_payloads,
    )

    print(f"\n[2단계] 다중 URL 공격 스캔 시작... (타겟: {len(config.target_urls)}개, 페이로드: {len(payloads)}개)")
    findings = run_scan(session, list(config.target_urls), payloads)

    base.write_csv(args.output, [f.to_row() for f in findings], ReflectionFinding.fieldnames())
    print(f"\n[Info] CSV 저장 완료: '{args.output}'")


if __name__ == "__main__":
    main()
