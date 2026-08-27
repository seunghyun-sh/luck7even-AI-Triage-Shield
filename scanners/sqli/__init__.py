"""SQL injection scanner pipeline entry point.

다른 팀은 이 모듈의 `scan()`만 사용하면 됩니다. 내부 판정 로직은
`scanners.sqli.detectors`에 있으며 외부에서 직접 import하지 않습니다.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import requests

from analysis.models import RawFinding, TargetCase
from orchestration import ScanContext

from . import detectors

ProgressCallback = Callable[[int, int], None]

PAYLOADS_DIR = Path(__file__).resolve().parents[2] / "payloads"


def _build_session(context: ScanContext, target: TargetCase) -> requests.Session | None:
    """사전 로그인이 필요한 대상이면 인증된 세션을 만들어 돌려준다.

    주의: auth_profile이 정확히 어떤 형태(쿠키/토큰 등)로 오는지는 아직
    팀 전체가 확정하지 않았다. 여기서는 쿠키 형태(dict)로 온다고 가정한
    최소 구현이며, 실제 로그인 방식이 확정되면 이 함수만 고치면 된다.
    """
    if not target.requires_pre_auth:
        return None
    session = requests.Session()
    profile = context.resolve_auth_profile(target.auth_profile)
    cookies = profile.get("cookies") if isinstance(profile, dict) else None
    if cookies:
        session.cookies.update(cookies)
    return session


def scan(
    targets: list[TargetCase],
    context: ScanContext,
    on_progress: ProgressCallback,
) -> list[RawFinding]:
    """전달받은 모든 SQLi 대상을 진단하고, 모든 시도 결과를 RawFinding으로 반환한다."""

    per_target_entries: list[tuple[TargetCase, list[dict]]] = []
    total = 0
    for target in targets:
        entries = detectors.load_payload_profile(target.payload_profile, PAYLOADS_DIR)
        per_target_entries.append((target, entries))
        total += len(entries)

    completed = 0
    on_progress(completed, total)

    findings: list[RawFinding] = []
    for target, entries in per_target_entries:
        session = _build_session(context, target)
        common_kwargs = {
            "base_url": context.base_url,
            "timeout_seconds": context.request_policy.timeout_seconds,
            "follow_redirects": context.request_policy.follow_redirects,
            "responses_dir": context.responses_dir,
            "session": session,
        }

        for entry in entries:
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