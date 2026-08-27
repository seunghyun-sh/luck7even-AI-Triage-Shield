"""SQL injection scanner pipeline entry point.

다른 팀은 이 모듈의 `scan()`만 사용하면 됩니다. 내부 판정 로직은
`scanners.sqli.detectors`에 있으며 외부에서 직접 import하지 않습니다.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from analysis.models import RawFinding, TargetCase
from orchestration import ScanContext

from . import detectors

ProgressCallback = Callable[[int, int], None]

PAYLOADS_DIR = Path(__file__).resolve().parents[2] / "payloads"


def scan(
    targets: list[TargetCase],
    context: ScanContext,
    on_progress: ProgressCallback,
) -> list[RawFinding]:
    """전달받은 모든 SQLi 대상을 진단하고, 모든 시도 결과를 RawFinding으로 반환한다."""

    work_items: list[tuple[TargetCase, dict]] = []
    for target in targets:
        payload_entries = detectors.load_payload_profile(target.payload_profile, PAYLOADS_DIR)
        for entry in payload_entries:
            work_items.append((target, entry))

    total = len(work_items)
    completed = 0
    on_progress(completed, total)

    findings: list[RawFinding] = []
    for target, entry in work_items:
        # 현재 등록된 SQLi 대상은 모두 requires_pre_auth=false 입니다.
        # 사전 로그인이 필요한 대상이 추가되면, context.resolve_auth_profile로
        # 얻은 인증 정보로 세션을 만들어 아래 evaluate_* 함수에 session=으로 전달합니다.
        common_kwargs = {
            "base_url": context.base_url,
            "timeout_seconds": context.request_policy.timeout_seconds,
            "follow_redirects": context.request_policy.follow_redirects,
            "responses_dir": context.responses_dir,
        }

        if entry["type"] == "boolean_pair":
            finding = detectors.evaluate_boolean_pair_payload(
                target,
                entry["payload_case_id"],
                entry["true_value"],
                entry["false_value"],
                **common_kwargs,
            )
        else:
            finding = detectors.evaluate_single_payload(
                target,
                entry["payload_case_id"],
                entry["value"],
                **common_kwargs,
            )

        findings.append(finding)
        completed += 1
        on_progress(completed, total)

    return findings