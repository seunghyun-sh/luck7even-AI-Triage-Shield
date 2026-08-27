"""bWAPP XSS 반사(reflection) 스캐너 -- 전체 스캔을 조립하는 진입점.

동작 순서:
1) 실습 앱에 로그인한다(LabSession 사용).
2) AI 페이로드 배치를 준비한다(캐시가 있으면 재사용, 없으면 새로 생성 -- xss_payloads 모듈 담당).
3) 설정된 모든 타겟 x 모든 페이로드 x 모든 공격 벡터(파라미터/헤더) x 메서드(GET/POST)
   조합에 대해 "요청 1번 = Finding 1건" 원칙으로 개별 요청을 보낸다. Stored 모드
   타겟은 주입 요청 직후 별도의 조회 요청으로 저장 여부까지 확인한다(아래
   "Stored XSS 검증 범위" 참고).
4) 각 결과를 scanners/xss_rules.py로 1차 판정하고, scanners/xss_report.py로
   팀 공통 데이터 계약 Contract B(raw findings, docs/data-contracts-v1.md) 형식의
   RawFinding으로 변환한다.
5) 응답 본문 전체는 JSON에 넣지 않고 data/raw/<scan_run_id>/responses/ 아래
   sidecar HTML 파일로 저장하고, findings.json에는 상대 경로와 요약만 남긴다.
6) 전체 결과를 data/raw/<scan_run_id>/findings.json에 하나의 envelope로 저장한다.

실행 방법은 두 가지 다 지원한다.
- 스크립트로 직접 실행: `python scanners/xss.py`
- 모듈로 실행: `python -m scanners.xss`
아래의 sys.path 보정 코드 덕분에 둘 다 정상 동작한다(스크립트로 직접 실행하면
파이썬이 scanners/ 디렉터리만 sys.path에 넣어서, "scanners 패키지"를 못 찾는
문제가 생기기 때문).

Stored XSS 검증 범위:
    Reflected XSS는 요청 1번 -> 응답 1번만 보면 판정할 수 있지만, Stored XSS는
    "글을 쓸 때(POST) 주입하고, 그 글을 읽을 때(GET, 보통 별도 요청) 실행된다"는
    특성 때문에 단일 응답만으로는 정확히 판별할 수 없다. 이 스캐너는 타겟 목록
    JSON에서 `"mode": "stored"`로 명시된 대상에 한해서만 주입 후 별도 조회
    요청으로 2단계 검증을 수행한다(XSSTarget.mode, xss_config.load_targets 참고).
    그 외 모든 대상은 여전히 "단일 응답 기반 Reflected 판정"에 집중한다.

데이터 계약과의 차이점:
    이 스캐너는 bWAPP의 User-Agent/Referer/커스텀 헤더 반사형 XSS도 탐지하는데,
    Contract B의 input_location enum(query/form/json)에는 헤더 항목이 없다.
    편의상 "header"를 추가로 사용하며, 이는 아직 팀 합의를 거치지 않은 확장이다
    (자세한 내용은 scanners/xss_report.py 모듈 docstring 참고).
"""

from __future__ import annotations

import argparse
import itertools
import sys
from datetime import datetime
from pathlib import Path

# `python scanners/xss.py`처럼 스크립트로 직접 실행된 경우에만 저장소 루트를
# sys.path에 추가한다. `python -m scanners.xss`로 실행하면 __package__가
# "scanners"로 채워지므로 이 블록은 건너뛰고, 파이썬이 알아서 패키지를 찾는다.
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from dotenv import load_dotenv

from analysis.models import RawFinding, RunEnvelope, ScanRequest
from scanners import base, xss_payloads, xss_report, xss_rules
from scanners.xss_config import (
    INJECTABLE_HEADERS,
    INJECTABLE_PARAMS,
    LOGIN_PATH,
    MODE_STORED,
    load_config,
)

DEFAULT_OUTPUT_DIR = Path("data/raw")
DEFAULT_TARGET_SET_ID = "bwapp-xss-lab-v1"
# 어떤 파라미터를 테스트하는지와 무관하게, bWAPP의 XSS 페이지 대부분이 요청을
# 실제로 처리하기 위해 항상 함께 보내야 하는 "고정 필드"들이다. 예를 들어
# action/form 값이 없으면 서버가 폼 제출로 인식하지 못해 애초에 반사가 일어나지
# 않을 수 있으므로, 테스트 대상 파라미터와 별개로 항상 포함시킨다. Finding의
# parameter 필드에는 기록되지 않는다(실제 공격 대상이 아니라 보조 값이므로).
FORM_TRIGGERS = {"action": "add", "form": "submit"}


def parse_args() -> argparse.Namespace:
    """커맨드라인 옵션을 정의하고 파싱한다."""
    parser = argparse.ArgumentParser(description="Run the bWAPP XSS reflection scan.")
    parser.add_argument("--targets", type=Path, help="JSON file listing target paths.")
    parser.add_argument("--count", type=int, default=100, help="Number of AI payloads to request.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="결과를 저장할 상위 디렉터리. 실제로는 이 아래 <scan_run_id>/findings.json에 기록된다.",
    )
    parser.add_argument(
        "--target-set-id",
        default=DEFAULT_TARGET_SET_ID,
        help="이번 스캔에 사용한 타겟 목록을 식별하는 ID(데이터 계약의 target_set_id).",
    )
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
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="각 HTTP 요청 사이에 대기할 시간(초). 타겟 서버 부하를 줄이고 싶을 때 사용 (예: 0.5).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="각 HTTP 요청의 타임아웃(초). 응답이 이 시간 안에 안 오면 포기하고 다음 테스트로 넘어간다.",
    )
    return parser.parse_args()


def _attack_vectors() -> list[tuple[str, str]]:
    """이번 스캔에서 개별적으로(하나씩) 테스트할 모든 공격 벡터 목록을 만든다.

    반환값은 (이름, 종류) 튜플의 리스트다. 종류는 "param"(요청 파라미터) 또는
    "header"(HTTP 헤더) 둘 중 하나이다.
    """
    return [(name, "param") for name in INJECTABLE_PARAMS] + [(name, "header") for name in INJECTABLE_HEADERS]


def _send_probe(
    session: base.LabSession, url: str, method: str, vector_name: str, vector_kind: str, payload: str
) -> requests.Response:
    """공격 벡터 하나 + 페이로드 하나로 요청을 한 번 보낸다(GET 또는 POST 둘 중 하나)."""
    attack_params = dict(FORM_TRIGGERS)
    attack_headers: dict[str, str] = {}
    if vector_kind == "param":
        attack_params[vector_name] = payload
    else:
        # 헤더 값은 Latin-1만 허용되므로, 한글/이모지가 섞인 AI 페이로드가
        # 크래시를 일으키지 않도록 안전하게 인코딩한다.
        attack_headers[vector_name] = base.safe_header_value(payload)

    if method == "GET":
        return session.get(url, params=attack_params, headers=attack_headers)
    return session.post(url, data=attack_params, headers=attack_headers)


def _input_location(method: str, vector_kind: str) -> str:
    if vector_kind == "header":
        return "header"  # 계약 미포함 확장값. 모듈 docstring 참고.
    return "query" if method == "GET" else "form"


def _run_one(
    session: base.LabSession,
    finding_id: str,
    url: str,
    path: str,
    mode: str,
    verify_url: str,
    method: str,
    vector_name: str,
    vector_kind: str,
    payload: str,
) -> tuple[RawFinding, str | None]:
    """공격 벡터 하나 + 메서드 하나 + 페이로드 하나에 대한 요청을 실행하고
    Contract B RawFinding 1건으로 조립한다.

    "요청 1번 = Finding 1건" 원칙에 따라 GET/POST를 합치지 않고 각각 별도로
    처리한다. Stored 모드 타겟이면 이 요청이 성공했을 때만 추가로 조회
    요청을 보내 저장 여부를 확인한다.

    반환값은 (finding, sidecar로 저장할 응답 본문)이다. 요청 자체가 실패하면
    저장할 응답이 없으므로 두 번째 값은 None이다(html_path도 null로 유지됨).
    """
    case_id = xss_report.make_case_id(path, vector_name, method)
    scan_request = ScanRequest(
        url=url,
        method=method,
        input_location=_input_location(method, vector_kind),
        parameter=vector_name,
        payload=payload,
    )

    try:
        response = _send_probe(session, url, method, vector_name, vector_kind, payload)
    except (requests.RequestException, UnicodeError) as e:
        scan = xss_report.build_failed_scan(scan_request, e)
        return xss_report.make_finding(case_id, finding_id, scan), None

    internal_label = xss_rules.classify_reflection(payload, response.text)
    response_body = response.text

    if mode == MODE_STORED:
        # 주입 응답만으로는 판단할 수 없으므로, 별도 조회 요청으로 실제 저장
        # 여부까지 한 번 더 확인한다. 조회 요청이 실패해도 주입 단계의 결과는
        # 그대로 유지한다(판정을 낮추지 않음).
        try:
            verify_res = session.get(verify_url)
        except (requests.RequestException, UnicodeError):
            pass
        else:
            verify_label = xss_rules.classify_reflection(payload, verify_res.text)
            if verify_label == xss_rules.REFLECTED_UNSANITIZED:
                verify_label = xss_rules.STORED_XSS_CONFIRMED
            internal_label, response_body = xss_rules.most_severe(
                (internal_label, response_body), (verify_label, verify_res.text)
            )

    scan = xss_report.build_completed_scan(
        request=scan_request,
        http_status=response.status_code,
        elapsed_ms=int(response.elapsed.total_seconds() * 1000),
        internal_label=internal_label,
        html_path="",  # run_scan()이 write_sidecar_html() 호출 후 실제 경로로 덮어씀
    )
    return xss_report.make_finding(case_id, finding_id, scan), response_body


def run_scan(
    session: base.LabSession,
    targets: list[tuple[str, str, str, str]],
    payloads: list[str],
    run_dir: Path,
    findings: list[RawFinding],
) -> None:
    """모든 (타겟 x 페이로드 x 공격 벡터 x 메서드) 조합을 순회하며 스캔을 수행한다.

    targets는 (path, url, mode, verify_url) 튜플의 리스트다. 결과는 새로 만들어
    반환하는 대신 호출자가 넘겨준 findings 리스트에 바로 append한다 -- 그래야
    도중에 예외가 나거나 중단돼도 호출자가 그때까지의 부분 결과를 그대로 볼 수 있다.
    """
    vectors = _attack_vectors()
    tests_per_url = len(payloads) * len(vectors) * 2  # GET, POST
    counter = itertools.count(1)

    for url_idx, (path, url, mode, verify_url) in enumerate(targets, 1):
        mode_label = " [stored]" if mode == MODE_STORED else ""
        print(f"\n[{url_idx}/{len(targets)}] 타겟 스캔 중: {url}{mode_label} (테스트 {tests_per_url}건)")
        test_no = 0

        for payload in payloads:
            for vector_name, vector_kind in vectors:
                for method in ("GET", "POST"):
                    test_no += 1
                    finding_id = xss_report.make_finding_id(next(counter))

                    finding, response_body = _run_one(
                        session, finding_id, url, path, mode, verify_url, method, vector_name, vector_kind, payload
                    )
                    if response_body is not None:
                        finding.scan.response.html_path = xss_report.write_sidecar_html(
                            run_dir, finding_id, response_body
                        )

                    rule_label = finding.scan.rule.label
                    if rule_label == "SUSPECTED":
                        print(f"   ㄴ [{vector_name}/{method}] SUSPECTED (페이로드: {payload[:20]}...)")
                    elif finding.scan.status == "FAILED":
                        print(f"   ㄴ [{vector_name}/{method}] FAILED: {finding.scan.error.code}")
                    elif test_no % 100 == 0:
                        print(f"   ㄴ [Test {test_no}/{tests_per_url}] 진행 중...")

                    findings.append(finding)


def main() -> None:
    # .env 파일의 값들(OPENAI_API_KEY, XSS_LAB_HOST 등)을 os.environ에 반영한다.
    # 이후 load_config()와 xss_payloads 모듈이 이 값을 읽어간다.
    load_dotenv()
    args = parse_args()
    config = load_config(args.targets)

    scan_run_id = f"run-xss-{datetime.now():%Y%m%d-%H%M%S}"
    run_dir = args.output_dir / scan_run_id
    started_at = xss_report.now_iso()

    print("=" * 50)
    print("[다중 URL] 지능형 XSS 스캐너 작동 시작")
    print("=" * 50)
    print(f"[설정] timeout={args.timeout}s, delay={args.delay}s, scan_run_id={scan_run_id}")

    # 1단계: 로그인
    print(f"\n[1단계] 로그인 시도 중... (URL: {config.login_url})")
    session = base.LabSession(config.host, timeout=args.timeout, request_delay=args.delay)
    try:
        logged_in = session.login(
            LOGIN_PATH,
            {"login": config.login, "password": config.password, "security_level": "0", "form": "submit"},
            success_markers=("portal.php", "Welcome"),
        )
    except requests.RequestException as e:
        # 로그인 요청 자체가 실패하면(서버 다운, 잘못된 호스트 등) 시도한 것이
        # 아무것도 없으므로, 계약이 정의한 "FAILED" 상태의 빈 envelope를 남긴다
        # (결과가 하나도 없다고 조용히 사라지는 대신, 실행이 실패했다는 사실 자체를
        # 기록으로 남기기 위함).
        print(f"에러: {e}")
        envelope = RunEnvelope(
            scan_run_id=scan_run_id,
            target_set_id=args.target_set_id,
            started_at=started_at,
            completed_at=xss_report.now_iso(),
            status="FAILED",
            findings=[],
        )
        xss_report.write_run_envelope(run_dir, envelope)
        raise SystemExit(1) from e
    print("로그인 성공!" if logged_in else "로그인 실패 가능성 있음.")

    # 2단계: 이번 스캔에 쓸 페이로드 배치를 확보한다(캐시 우선, 없으면 AI 호출).
    payloads = xss_payloads.get_payloads(
        count=args.count,
        cache_path=args.payload_cache,
        force_refresh=args.refresh_payloads,
    )

    targets = [
        (t.path, f"{config.host}{t.path}", t.mode, f"{config.host}{t.effective_verify_path}")
        for t in config.targets
    ]
    stored_count = sum(1 for _, _, mode, _ in targets if mode == MODE_STORED)

    vector_count = len(_attack_vectors())
    print(
        f"\n[2단계] 요청 1건당 Finding 1건 방식으로 스캔 시작... "
        f"(타겟: {len(targets)}개[stored {stored_count}개], 페이로드: {len(payloads)}개, "
        f"공격 벡터: {vector_count}개, 메서드: GET/POST)"
    )

    # 스캔 도중 예외가 나거나 사용자가 중단해도, 그때까지 모은 결과는 버리지
    # 않고 PARTIAL 상태로 저장한다(장시간 스캔이 중간에 끊겨도 이전 결과를
    # 잃지 않기 위함).
    findings: list[RawFinding] = []
    try:
        run_scan(session, targets, payloads, run_dir, findings)
    finally:
        status = xss_report.compute_run_status(findings)
        envelope = RunEnvelope(
            scan_run_id=scan_run_id,
            target_set_id=args.target_set_id,
            started_at=started_at,
            completed_at=xss_report.now_iso(),
            status=status,
            findings=findings,
        )
        findings_path = xss_report.write_run_envelope(run_dir, envelope)
        print(f"\n[Info] 저장 완료: '{findings_path}' (status={status}, {len(findings)}건)")


if __name__ == "__main__":
    main()
