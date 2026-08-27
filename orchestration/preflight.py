"""Read-only readiness checks required before a diagnostic launch."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

import httpx

from analysis.models import TargetManifest

from .run_store import RunStore

HEALTH_TIMEOUT_SECONDS = 1.0
_SCANNER_MODULES = {"XSS": "scanners.xss", "SQLI": "scanners.sqli"}


class Readiness(str, Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class PreflightCheck:
    """A safe, user-presentable readiness result."""

    name: str
    readiness: Readiness
    code: str
    message: str


@dataclass(frozen=True)
class PreflightResult:
    """Aggregate read-only readiness results."""

    checks: tuple[PreflightCheck, ...]

    @property
    def readiness(self) -> Readiness:
        return (
            Readiness.READY
            if all(check.readiness is Readiness.READY for check in self.checks)
            else Readiness.BLOCKED
        )

    @property
    def ready(self) -> bool:
        return self.readiness is Readiness.READY


class HttpRequester(Protocol):
    def __call__(
        self,
        url: str,
        *,
        timeout: float,
        follow_redirects: bool,
        headers: dict[str, str],
    ) -> Any: ...


ModuleImporter = Callable[[str], Any]


def _check(
    name: str,
    ready: bool,
    ready_code: str,
    blocked_code: str,
    ready_message: str,
    blocked_message: str,
) -> PreflightCheck:
    return PreflightCheck(
        name=name,
        readiness=Readiness.READY if ready else Readiness.BLOCKED,
        code=ready_code if ready else blocked_code,
        message=ready_message if ready else blocked_message,
    )


def _manifest_types(manifest: TargetManifest) -> set[str]:
    return {target.vuln_type.value for target in manifest.targets}


def _health_url(manifest: TargetManifest) -> str:
    return f"{manifest.base_url.rstrip('/')}/health"


def _component_available(
    importer: ModuleImporter, module_name: str, attribute: str
) -> bool:
    try:
        module = importer(module_name)
    except Exception:  # noqa: BLE001 - plugin boundary must normalize init failures
        return False
    try:
        return callable(getattr(module, attribute, None))
    except Exception:  # noqa: BLE001 - descriptors may execute plugin code
        return False


def _data_root_writable(data_root: Path) -> bool:
    return data_root.is_dir() and os.access(data_root, os.W_OK | os.X_OK)


def run_preflight(
    manifest: TargetManifest,
    selected_types: list[str],
    data_root: Path | str,
    *,
    http_requester: HttpRequester = httpx.get,
    module_importer: ModuleImporter = importlib.import_module,
) -> PreflightResult:
    """Check launch prerequisites without invoking scanners or sending payloads."""

    manifest_types = _manifest_types(manifest)
    requested_types = tuple(dict.fromkeys(selected_types))
    checks: list[PreflightCheck] = []

    if not requested_types:
        checks.append(
            _check(
                "진단 유형",
                False,
                "VULN_TYPES_READY",
                "NO_VULN_TYPES",
                "선택된 진단 유형 정상",
                "진단 유형을 하나 이상 선택하세요.",
            )
        )
    else:
        for vuln_type in requested_types:
            target_type_ready = vuln_type in manifest_types
            checks.append(
                _check(
                    f"{vuln_type} 대상",
                    target_type_ready,
                    "VULN_TYPE_READY",
                    "VULN_TYPE_NOT_IN_MANIFEST",
                    f"{vuln_type} 대상 정상",
                    f"{vuln_type} 유형이 대상 manifest에 없습니다.",
                )
            )
            module_name = _SCANNER_MODULES.get(vuln_type)
            scanner_ready = (
                target_type_ready
                and module_name is not None
                and _component_available(module_importer, module_name, "scan")
            )
            checks.append(
                _check(
                    f"{vuln_type} 스캐너",
                    scanner_ready,
                    "SCANNER_READY",
                    "SCANNER_UNAVAILABLE",
                    f"{vuln_type} 스캐너 정상",
                    f"{vuln_type} 스캐너를 사용할 수 없습니다.",
                )
            )

    ai_ready = _component_available(module_importer, "analysis.ai_triage", "triage")
    checks.append(
        _check(
            "AI triage",
            ai_ready,
            "AI_TRIAGE_READY",
            "AI_TRIAGE_UNAVAILABLE",
            "AI triage 정상",
            "AI triage를 사용할 수 없습니다.",
        )
    )

    try:
        response = http_requester(
            _health_url(manifest),
            timeout=HEALTH_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={},
        )
        target_ready = response.status_code == 200
    except (httpx.HTTPError, OSError, RuntimeError):
        target_ready = False
    checks.append(
        _check(
            "대상 서버",
            target_ready,
            "TARGET_HEALTHY",
            "TARGET_UNAVAILABLE",
            "대상 서버 정상",
            "대상 서버 응답 없음",
        )
    )

    try:
        lock_active = RunStore(data_root).pipeline_lock_active()
    except (OSError, ValueError):
        lock_active = True
    checks.append(
        _check(
            "전역 실행 잠금",
            not lock_active,
            "PIPELINE_LOCK_CLEAR",
            "PIPELINE_LOCK_ACTIVE",
            "전역 실행 잠금 해제됨",
            "다른 진단 실행이 진행 중입니다.",
        )
    )
    checks.append(
        _check(
            "저장소",
            _data_root_writable(Path(data_root)),
            "DATA_ROOT_WRITABLE",
            "DATA_ROOT_UNWRITABLE",
            "저장소 쓰기 가능",
            "저장소에 쓸 수 없습니다.",
        )
    )
    return PreflightResult(checks=tuple(checks))
