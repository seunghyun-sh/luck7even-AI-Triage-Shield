"""팀 실행 계약이 정의한 `scan(targets, context, on_progress) -> list[RawFinding]`
인터페이스를 구현하는 XSS 스캐너.

이전에 bWAPP 가상머신을 대상으로 하던 샷건 스캐너는 정식 실습 환경이 갖춰지면서
더 이상 쓰지 않는다. 이 모듈은 main.py가 호출할 것을 전제로 canonical
analysis.models(Contract A/B)와 orchestration.ScanContext를 그대로 따른다.

`scanners/xss.py`가 이 모듈의 `scan`을 그대로 재수출해서 main.py가 찾는
`scanners.xss.scan` 진입점을 제공한다(스캐너 통합 계약 변경 안내 3장).

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

계약을 따르며 실용적으로 채운 부분 (통합 담당과 추후 확인 필요):

- Stored XSS 2단계 검증 여부는 `target.manual_verification_profile == "xss-stored"`
  네이밍 규칙으로 판단한다. TargetCase에는 이를 위한 전용 필드가 없고(계약에 없는
  필드를 추가할 수 없음), manual_verification_profile은 원래 자유 문자열이라
  이 값을 규칙으로 재사용한다.
- 작성 페이지와 조회 페이지가 다른 경우(NovaStream)의 조회 경로는 이 모듈이
  직접 관리하는 `KNOWN_VERIFY_PATHS`(case_id -> 조회 경로) 조회 표로 해결한다.
  마찬가지로 TargetCase 확장 없이 스캐너 쪽에서만 아는 정보로 처리한다.
- `resolve_auth_profile()`이 반환하는 값은 HTTP 헤더로 간주해 요청에 그대로
  병합한다. 계약 문서가 정확한 반환 형태를 명시하지 않아서 가장 보편적인
  해석(헤더 dict)을 취했다. 현재 모든 타겟이 `requires_pre_auth: false`라
  실제로 이 경로를 타는 경우는 아직 없다.
- payload_profile은 `scanners/payload_profiles.py`로 로드한다. 이 모듈은
  OpenAI를 호출하지 않으며(런타임 스캐너 금지 사항), 캐시가 없으면 예외를
  던진다. 페이로드는 `scanners/tools/generate_xss_payload_profile.py`를 사람이
  직접 실행해서 미리 만들어둬야 한다.
"""

from __future__ import annotations

import itertools
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import requests

from analysis.models import RawFinding, ScanRequest, TargetCase
from scanners import base, payload_profiles, xss_report, xss_rules

if TYPE_CHECKING:
    # orchestration은 통합 담당(main.py)이 소유하는 별도 패키지다. 실제 실행
    # 환경(두 브랜치가 합쳐진 뒤)에서는 임포트되지만, 이 브랜치 단독으로는
    # 없을 수 있으므로 타입 힌트 용도로만 지연 임포트한다(런타임 의존 없음).
    from orchestration import ScanContext

ProgressCallback = Callable[[int, int], None]

# manual_verification_profile 값 중 "저장 후 별도 조회로 확인해야 한다"는
# 의미로 취급할 값들. Contract A에는 이를 위한 전용 필드가 없어서, 이미 있는
# 자유 문자열 필드를 네이밍 규칙으로 재사용한다.
STORED_VERIFICATION_PROFILES = frozenset({"xss-stored"})

# 작성 페이지와 확인 페이지가 다른 케이스만 여기 등록한다(case_id -> 조회 경로).
# 등록되지 않은 case_id는 자기 자신의 path를 그대로 재조회한다.
KNOWN_VERIFY_PATHS: dict[str, str] = {
    # NovaStream: 리뷰는 /titles/<id>/reviews에 쓰지만, 이스케이프 없이 그대로
    # 보여주는 실행 지점은 /admin/reviews다(lab_app_2/README.md).
    "nova-reviews-stored": "/admin/reviews",
}


def _build_request_kwargs(target: TargetCase, payload: str) -> dict:
    """target.input.parameters에 attack_parameter만 payload로 덮어써서 요청 인자를 만든다."""
    params = dict(target.input.parameters)
    params[target.input.attack_parameter] = payload
    if target.input.location == "query":
        return {"params": params}
    if target.input.location == "form":
        return {"data": params}
    return {"json": params}  # target.input.location == "json"


def _resolve_auth_headers(target: TargetCase, context: "ScanContext") -> dict[str, str]:
    """requires_pre_auth 타겟이면 context에서 인증정보를 받아와 헤더로 취급한다."""
    if not target.requires_pre_auth:
        return {}
    # resolve_auth_profile은 Mapping[str, str]을 반환한다(계약 문서 2장). 정확한
    # 용도(헤더/쿠키)는 명시되어 있지 않아 헤더로 병합하는 것을 기본 해석으로 삼는다.
    return dict(context.resolve_auth_profile(target.auth_profile))


def _send(
    session: requests.Session, method: str, url: str, *, timeout: int, follow_redirects: bool, **kwargs
) -> requests.Response:
    """context.request_policy를 반영해서 요청 1개를 보낸다.

    follow_redirects=True면 같은 호스트로만 리다이렉트를 추적하고(base.safe_request),
    False면 리다이렉트를 전혀 따라가지 않고 3xx 응답 자체를 그대로 반환한다.
    """
    if follow_redirects:
        return base.safe_request(session, method, url, timeout=timeout, **kwargs)
    return session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)


def _scan_one(
    session: requests.Session,
    context: "ScanContext",
    target: TargetCase,
    payload_case_id: str,
    payload: str,
    finding_id: str,
) -> RawFinding:
    """타겟 1개 x 페이로드 1개에 대한 요청을 실행하고 RawFinding 1건으로 조립한다.

    "요청 1번 = Finding 1건" 원칙에 따라, target이 이미 method/input.location/
    attack_parameter를 하나씩만 지정하고 있으므로(Contract A 모델), 여기서는
    별도의 벡터 fan-out 없이 그 하나를 그대로 실행한다.
    """
    case_id = f"{target.case_id}::{payload_case_id}"
    url = urljoin(context.base_url, target.path)
    request_kwargs = _build_request_kwargs(target, payload)
    timeout = context.request_policy.timeout_seconds
    follow_redirects = context.request_policy.follow_redirects
    auth_headers = _resolve_auth_headers(target, context)

    scan_request = ScanRequest(
        url=url,
        method=target.method,
        input_location=target.input.location,
        parameter=target.input.attack_parameter,
        payload=payload,
    )

    try:
        response = _send(
            session, target.method, url, timeout=timeout, follow_redirects=follow_redirects,
            headers=auth_headers, **request_kwargs,
        )
    except (requests.RequestException, UnicodeError) as e:
        scan = xss_report.build_failed_scan(scan_request, e)
        return xss_report.make_finding(case_id, finding_id, scan)

    internal_label = xss_rules.classify_reflection(payload, response.text)
    response_body = response.text

    if target.manual_verification_profile in STORED_VERIFICATION_PROFILES:
        # 주입 응답만으로는 판단할 수 없으므로, 별도 조회 요청으로 실제 저장
        # 여부까지 한 번 더 확인한다. 조회 요청이 실패해도 주입 단계 결과를
        # 그대로 유지한다(판정을 낮추지 않음).
        verify_path = KNOWN_VERIFY_PATHS.get(target.case_id, target.path)
        verify_url = urljoin(context.base_url, verify_path)
        try:
            verify_res = _send(
                session, "GET", verify_url, timeout=timeout, follow_redirects=follow_redirects,
                headers=auth_headers,
            )
        except (requests.RequestException, UnicodeError):
            pass
        else:
            verify_label = xss_rules.classify_reflection(payload, verify_res.text)
            if verify_label == xss_rules.REFLECTED_UNSANITIZED:
                verify_label = xss_rules.STORED_XSS_CONFIRMED
            internal_label, response_body = xss_rules.most_severe(
                (internal_label, response_body), (verify_label, verify_res.text)
            )

    html_path = xss_report.write_sidecar_html(context.responses_dir, finding_id, response_body)
    scan = xss_report.build_completed_scan(
        request=scan_request,
        http_status=response.status_code,
        elapsed_ms=int(response.elapsed.total_seconds() * 1000),
        internal_label=internal_label,
        html_path=html_path,
    )
    return xss_report.make_finding(case_id, finding_id, scan)


def _resolve_payloads_by_profile(targets: list[TargetCase]) -> dict[str, list[tuple[str, str]]]:
    """타겟들이 쓰는 payload_profile마다 고정 목록을 한 번씩만 로드한다.

    캐시가 없으면 payload_profiles.load_payload_profile()이
    PayloadProfileMissingError를 던진다 -- 이 함수는 그 예외를 삼키지 않고
    그대로 전파한다("원인을 숨기지 말고 실행 준비 실패로 처리").
    """
    resolved: dict[str, list[tuple[str, str]]] = {}
    for target in targets:
        if target.payload_profile not in resolved:
            resolved[target.payload_profile] = payload_profiles.load_payload_profile(target.payload_profile)
    return resolved


def scan(
    targets: list[TargetCase],
    context: "ScanContext",
    on_progress: ProgressCallback,
) -> list[RawFinding]:
    """모든 (타겟 x 페이로드) 조합을 실행하고 RawFinding 목록을 메모리로 반환한다.

    이 함수는 findings.json이나 status.json을 게시/수정하지 않는다 --
    orchestration.RunStore가 XSS·SQLi 결과를 하나의 envelope로 합쳐서 게시한다.
    응답 본문 sidecar HTML만 context.responses_dir 아래에 이 함수가 직접 저장한다.
    """
    payloads_by_profile = _resolve_payloads_by_profile(targets)
    total = sum(len(payloads_by_profile[target.payload_profile]) for target in targets)
    completed = 0

    findings: list[RawFinding] = []
    session = requests.Session()
    counter = itertools.count(1)

    for target in targets:
        for payload_case_id, payload in payloads_by_profile[target.payload_profile]:
            finding_id = xss_report.make_finding_id(next(counter))
            finding = _scan_one(session, context, target, payload_case_id, payload, finding_id)
            findings.append(finding)
            completed += 1
            on_progress(completed, total)

    return findings


# ---------------------------------------------------------------------------
# 아래는 main.py/orchestration 통합 전, 우리가 직접 동작을 확인하기 위한 로컬
# 실행용 코드다. orchestration 패키지에 대한 실제 의존성 없이 같은 모양의
# 컨텍스트를 직접 만들어 scan()을 호출한다. 실제 파이프라인은 이 CLI를 쓰지
# 않고 위 scan()만 가져다 쓴다(scan_run_id 발급, 잠금, 게시는 orchestration의 책임).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _LocalScanContext:
    """로컬 CLI 전용 ScanContext 대역. orchestration.ScanContext와 필드 이름을 맞췄다."""

    scan_run_id: str
    base_url: str
    request_policy: object  # analysis.models.RequestPolicy
    responses_dir: Path
    resolve_auth_profile: Callable[[str], dict]


def _unconfigured_auth_profile(profile_id: str) -> dict:
    raise KeyError(f"Auth profile is not configured: {profile_id}")


def _local_scan_run_id() -> str:
    return f"run-{datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


def _main() -> None:
    import argparse
    import json

    from dotenv import load_dotenv

    from analysis.models import RunStatus, TargetManifest

    load_dotenv()

    parser = argparse.ArgumentParser(description="실습 환경 XSS 계약 스캐너 로컬 실행")
    parser.add_argument(
        "--targets",
        type=Path,
        required=True,
        help="예: configs/lumi_market_1_xss_targets.example.json 또는 configs/novastream_2_xss_targets.example.json",
    )
    parser.add_argument("--base-url", help="지정하지 않으면 매니페스트 자체의 base_url을 사용한다.")
    args = parser.parse_args()

    manifest = TargetManifest.model_validate(json.loads(args.targets.read_text(encoding="utf-8")))
    scan_run_id = _local_scan_run_id()
    run_dir = Path("data/raw") / scan_run_id
    context = _LocalScanContext(
        scan_run_id=scan_run_id,
        base_url=args.base_url or manifest.base_url,
        request_policy=manifest.request_policy,
        responses_dir=run_dir / "responses",
        resolve_auth_profile=_unconfigured_auth_profile,
    )

    def on_progress(completed: int, total: int) -> None:
        print(f"[진행] {completed}/{total}")

    started_at = xss_report.now_iso()
    findings = scan(manifest.targets, context, on_progress)

    from analysis.models import RawRun

    status = xss_report.compute_run_status(findings)
    raw_run = RawRun(
        schema_version="1.0",
        scan_run_id=scan_run_id,
        target_set_id=manifest.target_set_id,
        started_at=started_at,
        completed_at=xss_report.now_iso(),
        status=RunStatus(status),
        findings=findings,
    )
    findings_path = xss_report.write_run_envelope(run_dir, raw_run)
    print(f"\n로컬 테스트 결과 저장: {findings_path} (status={status}, {len(findings)}건)")


if __name__ == "__main__":
    _main()
