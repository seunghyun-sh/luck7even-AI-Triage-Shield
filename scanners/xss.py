"""bWAPP XSS reflection scanner.

Logs into the lab app, then replays each AI-assisted payload against every
configured target through one attack vector at a time -- one of
INJECTABLE_PARAMS or INJECTABLE_HEADERS -- so each finding can be attributed
to the single parameter/header that carried the payload. Every finding gets
a rule-based verdict (`rule_label`) from `xss_rules.classify_reflection` and
is written to `data/raw/` as JSON Lines.

Run as a script (`python scanners/xss.py`) or as a module
(`python -m scanners.xss`); both work thanks to the path bootstrap below.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

if __name__ == "__main__" and __package__ is None:  # `python scanners/xss.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from dotenv import load_dotenv

from analysis.models import Finding
from scanners import base, xss_payloads, xss_rules
from scanners.xss_config import INJECTABLE_HEADERS, INJECTABLE_PARAMS, LOGIN_PATH, load_config

VULN_TYPE = "XSS"
DEFAULT_OUTPUT = Path("data/raw/raw-findings-xss.jsonl")
# Baseline fields most bWAPP XSS cases need present to actually process the
# request, independent of which single field carries the test payload.
FORM_TRIGGERS = {"action": "add", "form": "submit"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the bWAPP XSS reflection scan.")
    parser.add_argument("--targets", type=Path, help="JSON file listing target paths.")
    parser.add_argument("--count", type=int, default=100, help="Number of AI payloads to request.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON Lines output path.")
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


def _attack_vectors() -> list[tuple[str, str]]:
    """Every (name, kind) vector to test in isolation, one per request."""
    return [(name, "param") for name in INJECTABLE_PARAMS] + [(name, "header") for name in INJECTABLE_HEADERS]


def _probe(session: base.LabSession, url: str, vector_name: str, vector_kind: str, payload: str) -> tuple[str, str]:
    """Send one isolated GET+POST probe and return the worst-case (label, body)."""
    attack_params = dict(FORM_TRIGGERS)
    attack_headers: dict[str, str] = {}
    if vector_kind == "param":
        attack_params[vector_name] = payload
    else:
        attack_headers[vector_name] = base.safe_header_value(payload)

    res_get = session.get(url, params=attack_params, headers=attack_headers)
    res_post = session.post(url, data=attack_params, headers=attack_headers)

    label_get = xss_rules.classify_reflection(payload, res_get.text)
    label_post = xss_rules.classify_reflection(payload, res_post.text)
    return xss_rules.most_severe((label_get, res_get.text), (label_post, res_post.text))


def run_scan(session: base.LabSession, target_urls: list[str], payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    skipped = 0
    vectors = _attack_vectors()
    tests_per_url = len(payloads) * len(vectors)

    for url_idx, url in enumerate(target_urls, 1):
        print(f"\n[{url_idx}/{len(target_urls)}] 타겟 스캔 중: {url} (테스트 {tests_per_url}건)")
        test_no = 0

        for payload in payloads:
            for vector_name, vector_kind in vectors:
                test_no += 1

                try:
                    rule_label, response_body = _probe(session, url, vector_name, vector_kind, payload)
                except (requests.RequestException, UnicodeError):
                    skipped += 1
                    continue

                if rule_label != xss_rules.NOT_REFLECTED:
                    print(f"   ㄴ [{vector_name}] {rule_label} (페이로드: {payload[:20]}...)")
                elif test_no % 50 == 0:
                    print(f"   ㄴ [Test {test_no}/{tests_per_url}] 진행 중...")

                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        vuln_type=VULN_TYPE,
                        url=url,
                        parameter=vector_name,
                        payload=payload,
                        rule_label=rule_label,
                        response_body=response_body,
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

    vector_count = len(_attack_vectors())
    print(
        f"\n[2단계] 파라미터별 개별 공격 스캔 시작... "
        f"(타겟: {len(config.target_urls)}개, 페이로드: {len(payloads)}개, 공격 벡터: {vector_count}개)"
    )
    findings = run_scan(session, list(config.target_urls), payloads)

    base.write_jsonl(args.output, [f.to_dict() for f in findings])
    print(f"\n[Info] JSON Lines 저장 완료: '{args.output}' ({len(findings)}건)")


if __name__ == "__main__":
    main()
