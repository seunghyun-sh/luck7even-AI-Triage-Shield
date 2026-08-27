"""bWAPP XSS 반사(reflection) 스캐너 -- 전체 스캔을 조립하는 진입점.

동작 순서:
1) 실습 앱에 로그인한다(LabSession 사용).
2) AI 페이로드 배치를 준비한다(캐시가 있으면 재사용, 없으면 새로 생성 -- xss_payloads 모듈 담당).
3) 설정된 모든 타겟 URL x 모든 페이로드 x 모든 공격 벡터(파라미터/헤더) 조합에 대해
   "한 번에 하나의 벡터만" 공격해서, 어떤 파라미터/헤더가 실제로 반사를 일으켰는지
   정확히 특정할 수 있게 한다.
4) 각 시도 결과를 규칙 기반으로 판정(xss_rules 모듈 담당)하고 Finding으로 만든다.
5) 모든 Finding을 data/raw/ 아래 JSON Lines 파일로 저장한다.

실행 방법은 두 가지 다 지원한다.
- 스크립트로 직접 실행: `python scanners/xss.py`
- 모듈로 실행: `python -m scanners.xss`
아래의 sys.path 보정 코드 덕분에 둘 다 정상 동작한다(스크립트로 직접 실행하면
파이썬이 scanners/ 디렉터리만 sys.path에 넣어서, "scanners 패키지"를 못 찾는
문제가 생기기 때문).
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

# `python scanners/xss.py`처럼 스크립트로 직접 실행된 경우에만 저장소 루트를
# sys.path에 추가한다. `python -m scanners.xss`로 실행하면 __package__가
# "scanners"로 채워지므로 이 블록은 건너뛰고, 파이썬이 알아서 패키지를 찾는다.
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from dotenv import load_dotenv

from analysis.models import Finding
from scanners import base, xss_payloads, xss_rules
from scanners.xss_config import INJECTABLE_HEADERS, INJECTABLE_PARAMS, LOGIN_PATH, load_config

VULN_TYPE = "XSS"
DEFAULT_OUTPUT = Path("data/raw/raw-findings-xss.jsonl")
# 어떤 파라미터를 테스트하는지와 무관하게, bWAPP의 XSS 페이지 대부분이 요청을
# 실제로 처리하기 위해 항상 함께 보내야 하는 "고정 필드"들이다. 예를 들어
# action/form 값이 없으면 서버가 폼 제출로 인식하지 못해 애초에 반사가 일어나지
# 않을 수 있으므로, 테스트 대상 파라미터와 별개로 항상 포함시킨다.
FORM_TRIGGERS = {"action": "add", "form": "submit"}


def parse_args() -> argparse.Namespace:
    """커맨드라인 옵션을 정의하고 파싱한다."""
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
    """이번 스캔에서 개별적으로(하나씩) 테스트할 모든 공격 벡터 목록을 만든다.

    반환값은 (이름, 종류) 튜플의 리스트다. 종류는 "param"(요청 파라미터) 또는
    "header"(HTTP 헤더) 둘 중 하나이며, 아래 _probe()에서 이 정보를 보고
    페이로드를 파라미터에 넣을지 헤더에 넣을지 결정한다.
    """
    return [(name, "param") for name in INJECTABLE_PARAMS] + [(name, "header") for name in INJECTABLE_HEADERS]


def _probe(session: base.LabSession, url: str, vector_name: str, vector_kind: str, payload: str) -> tuple[str, str]:
    """공격 벡터 하나 + 페이로드 하나로 GET/POST 요청을 각각 한 번씩 보내고,
    두 응답 중 더 심각한 판정 결과 (rule_label, response_body)를 반환한다.

    핵심 설계: 이 함수는 vector_name 딱 하나에만 payload를 넣는다. 나머지
    INJECTABLE_PARAMS/INJECTABLE_HEADERS는 이번 요청에 포함시키지 않는다(단,
    FORM_TRIGGERS는 항상 포함). 이렇게 "한 번에 하나씩"만 공격해야 나중에
    Finding.parameter 필드에 "실제로 반사를 일으킨 그 파라미터명"을 정확히
    기록할 수 있다. 예전 버전처럼 모든 파라미터에 동시에 같은 페이로드를 넣으면,
    반사가 확인돼도 어떤 파라미터 때문인지 알 수 없었다.
    """
    attack_params = dict(FORM_TRIGGERS)
    attack_headers: dict[str, str] = {}
    if vector_kind == "param":
        attack_params[vector_name] = payload
    else:
        # 헤더 값은 Latin-1만 허용되므로, 한글/이모지가 섞인 AI 페이로드가
        # 크래시를 일으키지 않도록 안전하게 인코딩한다.
        attack_headers[vector_name] = base.safe_header_value(payload)

    # GET과 POST 두 방식 모두 시도한다. bWAPP 페이지마다 어느 방식으로 값을
    # 받는지 다르기 때문에(예: xss_get.php는 GET, xss_post.php는 POST 위주),
    # 둘 다 보내서 취약점을 놓치지 않는다.
    res_get = session.get(url, params=attack_params, headers=attack_headers)
    res_post = session.post(url, data=attack_params, headers=attack_headers)

    label_get = xss_rules.classify_reflection(payload, res_get.text)
    label_post = xss_rules.classify_reflection(payload, res_post.text)
    # 둘 중 더 위험한(심각도가 높은) 쪽을 이번 테스트의 최종 결과로 채택한다.
    return xss_rules.most_severe((label_get, res_get.text), (label_post, res_post.text))


def run_scan(session: base.LabSession, target_urls: list[str], payloads: list[str]) -> list[Finding]:
    """모든 (타겟 URL x 페이로드 x 공격 벡터) 조합을 순회하며 스캔을 수행한다.

    조합 개수 = len(target_urls) * len(payloads) * len(vectors)이며, 파라미터별로
    개별 공격하기 때문에(vectors가 11개: 파라미터 8개 + 헤더 3개) 예전의
    "한 번에 다 넣기" 방식보다 요청 수가 훨씬 많아진다. 그 대신 각 finding의
    parameter 필드가 정확해진다는 장점이 있다.
    """
    findings: list[Finding] = []
    skipped = 0  # 요청 실패(타임아웃 등)로 건너뛴 테스트 개수
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
                    # requests.RequestException: 타임아웃, 연결 끊김 등 네트워크 문제.
                    # UnicodeError: safe_header_value로도 못 거른 예외적인 인코딩 문제에
                    # 대한 최후 방어선(defense in depth). 둘 다 이 테스트 1건만 건너뛰고
                    # 전체 스캔은 계속 진행한다.
                    skipped += 1
                    continue

                # 취약 가능성이 있는 경우(NOT_REFLECTED가 아님)는 바로바로 출력해서
                # 실시간으로 눈에 띄게 하고, 그렇지 않은 평범한 진행 상황은
                # 터미널이 너무 길어지지 않도록 50건마다 한 번만 출력한다.
                if rule_label != xss_rules.NOT_REFLECTED:
                    print(f"   ㄴ [{vector_name}] {rule_label} (페이로드: {payload[:20]}...)")
                elif test_no % 50 == 0:
                    print(f"   ㄴ [Test {test_no}/{tests_per_url}] 진행 중...")

                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),  # finding마다 전역적으로 고유한 ID 부여
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
    # .env 파일의 값들(OPENAI_API_KEY, XSS_LAB_HOST 등)을 os.environ에 반영한다.
    # 이후 load_config()와 xss_payloads 모듈이 이 값을 읽어간다.
    load_dotenv()
    args = parse_args()
    config = load_config(args.targets)

    print("=" * 50)
    print("[다중 URL] 지능형 XSS 스캐너 작동 시작")
    print("=" * 50)

    # 1단계: 로그인
    print(f"\n[1단계] 로그인 시도 중... (URL: {config.login_url})")
    session = base.LabSession(config.host, timeout=config.request_timeout)
    try:
        logged_in = session.login(
            LOGIN_PATH,
            {"login": config.login, "password": config.password, "security_level": "0", "form": "submit"},
            success_markers=("portal.php", "Welcome"),
        )
    except requests.RequestException as e:
        # 로그인 요청 자체가 실패하면(서버 다운, 잘못된 호스트 등) 스캔을
        # 계속할 이유가 없으므로 여기서 프로그램을 종료한다.
        print(f"에러: {e}")
        raise SystemExit(1) from e
    print("로그인 성공!" if logged_in else "로그인 실패 가능성 있음.")

    # 2단계: 이번 스캔에 쓸 페이로드 배치를 확보한다(캐시 우선, 없으면 AI 호출).
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

    # 3단계: 결과를 JSON Lines 파일로 저장(한 줄 = Finding 1건).
    base.write_jsonl(args.output, [f.to_dict() for f in findings])
    print(f"\n[Info] JSON Lines 저장 완료: '{args.output}' ({len(findings)}건)")


if __name__ == "__main__":
    main()
