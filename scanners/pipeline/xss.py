"""팀 실행 계약이 정의한 `scan(targets, scan_run_id, on_progress) -> list[RawFinding]`
인터페이스를 구현하는 XSS 스캐너.

이전에 bWAPP 가상머신을 대상으로 하던 샷건 스캐너는 정식 실습 환경이 갖춰지면서
더 이상 쓰지 않는다. 이 모듈은 실제로 main.py가 호출할 것을 전제로 Contract
A(target manifest) 입력과 Contract B(raw findings) 출력을 계약대로 맞춘다.

대상 실습 환경 (모두 Flask, 각자 XSS 취약점이 있는 것으로 확인된 페이지만 다룬다):

- 1번 환경: `lab_app/`(Lumi Market) -- feature/vulnerable-lab 브랜치,
  docs/vulnerable-lab-1.md. 매니페스트: configs/lumi_market_1_xss_targets.example.json
  - Reflected: GET /search, query 파라미터 q
  - Stored: POST /reviews(작성) -> GET /reviews(같은 페이지에서 확인), form 파라미터 content
- 2번 환경: `lab_app_2/`(NovaStream) -- feature/vulnerable-lab-2 브랜치,
  lab_app_2/README.md. 매니페스트: configs/novastream_2_xss_targets.example.json
  - Reflected: GET /discover, query 파라미터 q
  - Stored: POST /titles/<id>/reviews(작성) -> GET /admin/reviews(다른 페이지에서 확인),
    form 파라미터 body

두 환경 모두 지금은 로컬(127.0.0.1)에서 실행하지만, 이후 서버에 배포될 예정이다.
그래서 `base_url`을 코드에 고정하지 않고 항상 호출 시점에 인자로 받는다 --
로컬이든 배포된 서버든 URL만 바꿔서 그대로 재사용할 수 있다.

계약에 명시되지 않아 우리가 실용적으로 채운 부분 (통합 담당과 추후 확인 필요):

- `base_url`: Contract A 매니페스트 최상위에는 base_url이 있지만, 실행 계약의
  `scan()` 시그니처 자체에는 이를 전달할 방법이 안 나와 있다. 일단 키워드
  인자로 받는다.
- `TargetCase.verification_mode`("reflected"/"stored")와 `verify_path`: Stored
  XSS는 주입 후 별도 조회 요청으로 저장 여부까지 확인해야 하는데, Contract A의
  정식 필드 중에는 이걸 표현할 곳이 없다(`manual_verification_profile`은 자유
  문자열이라 자동화 분기에 쓰기엔 애매함). 그래서 매니페스트 JSON에 이 두 필드를
  추가로 넣고 우리 로더가 읽어들인다. `verify_path`는 작성 페이지와 확인 페이지가
  다를 때만 쓰고(NovaStream의 관리자 리뷰 페이지처럼), 같으면 생략해도 된다
  (생략 시 path를 그대로 재사용).
- `auth_profile`/`requires_pre_auth=true` 처리: 아직 설계되지 않았다. 지금까지
  확인된 XSS 케이스는 모두 인증이 필요 없어서(`requires_pre_auth: false`) 당장은
  문제가 안 되지만, pre-auth 케이스가 추가되면 다시 논의해야 한다
  (`_run_one`에서 이 경우 NotImplementedError를 던지도록 명시적으로 막아둠).
- `payload_profile`: 각 타겟에 적힌 `payload_profile` 이름(예: `"xss-v1"`)마다
  `scanners/xss_payloads.get_payloads()`를 호출해 (payload_case_id, payload)
  목록을 얻는다. 캐시(`data/raw/payload_profiles/<profile>.json`)가 있으면
  재사용하고, 없을 때만 AI(OpenAI)를 호출해 새로 생성한 뒤 캐시에 저장한다.
  같은 payload_profile을 여러 실습 환경(Lumi Market, NovaStream)이 함께 쓰면
  캐시도 함께 재사용되어 AI를 중복 호출하지 않는다. 이 모듈이 스캐너 실행
  경로 안에서 OpenAI를 호출한다는 점은 실행 계약(11.5)과 긴장 관계가 있다 --
  자세한 내용은 scanners/xss_payloads.py 모듈 docstring 참고.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests

from analysis.models import RawFinding, ScanRequest, TargetCase
from scanners import base, xss_payloads, xss_report, xss_rules

ProgressCallback = Callable[[int, int], None]

DEFAULT_TIMEOUT = 5.0

# 테스트/수동 실행 시 AI 호출 없이 빠르게 확인하고 싶을 때 scan(payloads=...)에
# 직접 넘길 수 있는 소규모 고정 목록. 기본 동작(payloads=None)에서는 쓰이지
# 않고, 대신 각 타겟의 payload_profile을 통해 xss_payloads.get_payloads()가
# 페이로드를 채운다.
SAMPLE_PAYLOADS: list[tuple[str, str]] = [
    ("script-basic", "<script>alert(1)</script>"),
    ("img-onerror", "<img src=x onerror=alert(1)>"),
    ("plain-text", "그냥 평범한 후기 텍스트입니다"),
]


def load_targets(manifest_path: Path) -> list[TargetCase]:
    """Contract A 모양의 타겟 매니페스트 JSON을 읽어 TargetCase 목록으로 만든다."""
    raw_targets = json.loads(manifest_path.read_text(encoding="utf-8"))
    targets = []
    for entry in raw_targets:
        input_spec = entry["input"]
        targets.append(
            TargetCase(
                case_id=entry["case_id"],
                vuln_type=entry["vuln_type"],
                path=entry["path"],
                method=entry["method"],
                input_location=input_spec["location"],
                input_parameters=dict(input_spec["parameters"]),
                attack_parameter=input_spec["attack_parameter"],
                requires_pre_auth=entry["requires_pre_auth"],
                auth_profile=entry.get("auth_profile"),
                payload_profile=entry["payload_profile"],
                manual_verification_profile=entry["manual_verification_profile"],
                verification_mode=entry.get("verification_mode", "reflected"),
                verify_path=entry.get("verify_path"),
            )
        )
    return targets


def _build_request_kwargs(target: TargetCase, payload: str) -> dict:
    """target.input_parameters에 attack_parameter만 payload로 덮어써서 요청 인자를 만든다."""
    params = dict(target.input_parameters)
    params[target.attack_parameter] = payload
    if target.input_location == "query":
        return {"params": params}
    if target.input_location == "form":
        return {"data": params}
    if target.input_location == "json":
        return {"json": params}
    raise ValueError(f"지원하지 않는 input_location: {target.input_location!r}")


def _scan_one(
    session: requests.Session,
    base_url: str,
    target: TargetCase,
    payload_case_id: str,
    payload: str,
    finding_id: str,
    run_dir: Path,
    timeout: float,
) -> RawFinding:
    """타겟 1개 x 페이로드 1개에 대한 요청을 실행하고 RawFinding 1건으로 조립한다.

    "요청 1번 = Finding 1건" 원칙(계약 11.3)에 따라, target이 이미 method/
    input_location/attack_parameter를 하나씩만 지정하고 있으므로(Contract A
    모델), 여기서는 별도의 벡터 fan-out 없이 그 하나를 그대로 실행한다.
    """
    if target.requires_pre_auth:
        raise NotImplementedError(
            f"{target.case_id}: requires_pre_auth=true 케이스의 인증 흐름은 아직 설계되지 않았습니다."
        )

    case_id = f"{target.case_id}::{payload_case_id}"
    url = urljoin(base_url, target.path)
    request_kwargs = _build_request_kwargs(target, payload)

    scan_request = ScanRequest(
        url=url,
        method=target.method,
        input_location=target.input_location,
        parameter=target.attack_parameter,
        payload=payload,
    )

    try:
        response = base.safe_request(session, target.method, url, timeout=timeout, **request_kwargs)
    except (requests.RequestException, UnicodeError) as e:
        scan = xss_report.build_failed_scan(scan_request, e)
        return xss_report.make_finding(case_id, finding_id, scan)

    internal_label = xss_rules.classify_reflection(payload, response.text)
    response_body = response.text

    if target.verification_mode == "stored":
        # 주입 응답만으로는 판단할 수 없으므로, 별도 조회 요청으로 실제 저장
        # 여부까지 한 번 더 확인한다. 조회 요청이 실패해도 주입 단계 결과를
        # 그대로 유지한다(판정을 낮추지 않음). 작성 페이지와 확인 페이지가
        # 다른 경우(verify_path)도 지원한다 -- 예: NovaStream은 리뷰를
        # /titles/<id>/reviews에 쓰고 /admin/reviews에서 이스케이프 없이 보여준다.
        verify_url = urljoin(base_url, target.verify_path) if target.verify_path else url
        try:
            verify_res = base.safe_request(session, "GET", verify_url, timeout=timeout)
        except (requests.RequestException, UnicodeError):
            pass
        else:
            verify_label = xss_rules.classify_reflection(payload, verify_res.text)
            if verify_label == xss_rules.REFLECTED_UNSANITIZED:
                verify_label = xss_rules.STORED_XSS_CONFIRMED
            internal_label, response_body = xss_rules.most_severe(
                (internal_label, response_body), (verify_label, verify_res.text)
            )

    html_path = xss_report.write_sidecar_html(run_dir, finding_id, response_body)
    scan = xss_report.build_completed_scan(
        request=scan_request,
        http_status=response.status_code,
        elapsed_ms=int(response.elapsed.total_seconds() * 1000),
        internal_label=internal_label,
        html_path=html_path,
    )
    return xss_report.make_finding(case_id, finding_id, scan)


def _resolve_payloads_by_profile(
    targets: list[TargetCase],
    payloads: list[tuple[str, str]] | None,
    payload_count: int,
    refresh_payloads: bool,
) -> dict[str, list[tuple[str, str]]]:
    """타겟들이 쓰는 payload_profile마다 페이로드 목록을 한 번씩만 준비한다.

    `payloads`를 명시적으로 넘기면(테스트/수동 실행) 모든 타겟에 그대로
    적용하고 AI는 전혀 호출하지 않는다. 넘기지 않으면 각 타겟의
    `payload_profile`로 xss_payloads.get_payloads()를 호출한다 -- 같은
    profile을 여러 타겟(또는 여러 실습 환경)이 공유하면 한 번만 조회/생성한다.
    """
    if payloads is not None:
        return {target.payload_profile: payloads for target in targets}

    resolved: dict[str, list[tuple[str, str]]] = {}
    for target in targets:
        if target.payload_profile not in resolved:
            resolved[target.payload_profile] = xss_payloads.get_payloads(
                target.payload_profile, count=payload_count, force_refresh=refresh_payloads
            )
    return resolved


def scan(
    targets: list[TargetCase],
    scan_run_id: str,
    on_progress: ProgressCallback,
    *,
    base_url: str,
    payloads: list[tuple[str, str]] | None = None,
    payload_count: int = xss_payloads.DEFAULT_COUNT,
    refresh_payloads: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[RawFinding]:
    """모든 (타겟 x 페이로드) 조합을 실행하고 RawFinding 목록을 메모리로 반환한다.

    이 함수는 findings.json을 게시하지 않는다(계약 12.1: main.py가 XSS·SQLi
    결과를 하나의 envelope로 합쳐서 게시함). 다만 응답 본문 sidecar HTML은
    이 함수가 직접 저장한다(계약 11.4는 이걸 스캐너의 책임으로 명시함).

    `payloads`를 지정하지 않으면(기본값) 각 타겟의 payload_profile로 AI
    페이로드 캐시를 조회/생성한다(캐시가 없을 때만 실제로 AI를 호출함).
    """
    payloads_by_profile = _resolve_payloads_by_profile(targets, payloads, payload_count, refresh_payloads)
    run_dir = Path("data/raw") / scan_run_id
    total = sum(len(payloads_by_profile[target.payload_profile]) for target in targets)
    completed = 0

    findings: list[RawFinding] = []
    session = requests.Session()
    counter = itertools.count(1)

    for target in targets:
        for payload_case_id, payload in payloads_by_profile[target.payload_profile]:
            finding_id = xss_report.make_finding_id(next(counter))
            finding = _scan_one(session, base_url, target, payload_case_id, payload, finding_id, run_dir, timeout)
            findings.append(finding)
            completed += 1
            on_progress(completed, total)

    return findings


# ---------------------------------------------------------------------------
# 아래는 main.py 통합 전, 우리가 직접 동작을 확인하기 위한 로컬 실행용 코드다.
# 실제 파이프라인은 위 scan()/load_targets()만 가져다 쓰고, 아래 부분은 쓰지
# 않는다(scan_run_id 발급, findings.json 게시, 잠금 등은 main.py의 책임).
# ---------------------------------------------------------------------------
def _local_scan_run_id() -> str:
    return f"run-{datetime.now():%Y%m%d-%H%M%S}-000000"


def _main() -> None:
    import argparse

    from dotenv import load_dotenv

    from analysis.models import RunEnvelope

    load_dotenv()  # OPENAI_API_KEY 등을 .env에서 읽어온다(xss_payloads가 사용).

    parser = argparse.ArgumentParser(description="실습 환경 XSS 계약 스캐너 로컬 실행")
    parser.add_argument(
        "--targets",
        type=Path,
        required=True,
        help="예: configs/lumi_market_1_xss_targets.example.json 또는 configs/novastream_2_xss_targets.example.json",
    )
    parser.add_argument("--base-url", required=True, help="예: http://127.0.0.1:5001 (배포 후에는 실제 서버 주소)")
    parser.add_argument("--target-set-id", required=True, help="예: lumi-market-1, novastream-2")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--count", type=int, default=xss_payloads.DEFAULT_COUNT, help="캐시가 없을 때 AI에게 요청할 페이로드 개수 (기본 100)"
    )
    parser.add_argument("--refresh-payloads", action="store_true", help="캐시를 무시하고 AI 페이로드를 새로 생성")
    args = parser.parse_args()

    scan_run_id = _local_scan_run_id()
    targets = load_targets(args.targets)

    def on_progress(completed: int, total: int) -> None:
        print(f"[진행] {completed}/{total}")

    started_at = xss_report.now_iso()
    findings = scan(
        targets,
        scan_run_id,
        on_progress,
        base_url=args.base_url,
        timeout=args.timeout,
        payload_count=args.count,
        refresh_payloads=args.refresh_payloads,
    )

    envelope = RunEnvelope(
        scan_run_id=scan_run_id,
        target_set_id=args.target_set_id,
        started_at=started_at,
        completed_at=xss_report.now_iso(),
        status=xss_report.compute_run_status(findings),
        findings=findings,
    )
    run_dir = Path("data/raw") / scan_run_id
    findings_path = xss_report.write_run_envelope(run_dir, envelope)
    print(f"\n로컬 테스트 결과 저장: {findings_path} (status={envelope.status}, {len(findings)}건)")


if __name__ == "__main__":
    _main()
