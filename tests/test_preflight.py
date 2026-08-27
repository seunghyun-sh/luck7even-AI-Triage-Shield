"""Focused tests for read-only diagnostic launch preflight checks."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from analysis.models import TargetCase, TargetInput, TargetManifest, VulnType
from orchestration.preflight import Readiness, run_preflight


def _manifest() -> TargetManifest:
    return TargetManifest(
        schema_version="1.0",
        target_set_id="local-lab-v1",
        base_url="http://127.0.0.1:5000",
        request_policy={"timeout_seconds": 10, "follow_redirects": False},
        targets=[
            TargetCase(
                case_id="xss-case",
                vuln_type=VulnType.XSS,
                path="/case/xss",
                method="GET",
                input=TargetInput(
                    location="query",
                    parameters={"name": "baseline"},
                    attack_parameter="name",
                ),
                requires_pre_auth=False,
                auth_profile=None,
                payload_profile="xss-v1",
                manual_verification_profile="xss-reflection",
            )
        ],
    )


def _importer(name: str) -> SimpleNamespace:
    assert name in {"scanners.xss", "analysis.ai_triage"}
    return SimpleNamespace(scan=lambda: None, triage=lambda: None)


def _codes(result) -> set[str]:
    return {check.code for check in result.checks}


def test_preflight_ready_uses_only_manifest_health_url(tmp_path: Path) -> None:
    requested: dict[str, object] = {}

    def requester(url: str, **kwargs: object) -> SimpleNamespace:
        requested["url"] = url
        requested.update(kwargs)
        return SimpleNamespace(status_code=200, text="untrusted body")

    result = run_preflight(
        _manifest(),
        ["XSS"],
        tmp_path,
        http_requester=requester,
        module_importer=_importer,
    )

    assert result.readiness is Readiness.READY
    assert requested == {
        "url": "http://127.0.0.1:5000/health",
        "timeout": 1.0,
        "follow_redirects": False,
        "headers": {},
    }


def test_preflight_blocks_server_down_without_exception_details(tmp_path: Path) -> None:
    def unavailable(*args: object, **kwargs: object) -> None:
        raise RuntimeError("credential=secret /private/absolute/path")

    result = run_preflight(
        _manifest(),
        ["XSS"],
        tmp_path,
        http_requester=unavailable,
        module_importer=_importer,
    )

    target = next(check for check in result.checks if check.name == "대상 서버")
    assert target.code == "TARGET_UNAVAILABLE"
    assert target.message == "대상 서버 응답 없음"
    assert "secret" not in target.message


def test_preflight_blocks_missing_components(tmp_path: Path) -> None:
    def missing_importer(name: str) -> object:
        raise ImportError(name)

    result = run_preflight(
        _manifest(),
        ["XSS"],
        tmp_path,
        http_requester=lambda *args, **kwargs: SimpleNamespace(status_code=200),
        module_importer=missing_importer,
    )

    assert {"SCANNER_UNAVAILABLE", "AI_TRIAGE_UNAVAILABLE"} <= _codes(result)


def test_preflight_blocks_active_lock(tmp_path: Path) -> None:
    lock_path = tmp_path / "runs" / ".pipeline.lock"
    lock_path.parent.mkdir()
    lock_path.write_text("active")

    result = run_preflight(
        _manifest(),
        ["XSS"],
        tmp_path,
        http_requester=lambda *args, **kwargs: SimpleNamespace(status_code=200),
        module_importer=_importer,
    )

    assert "PIPELINE_LOCK_ACTIVE" in _codes(result)


def test_preflight_blocks_missing_manifest_type(tmp_path: Path) -> None:
    result = run_preflight(
        _manifest(),
        ["SQLI"],
        tmp_path,
        http_requester=lambda *args, **kwargs: SimpleNamespace(status_code=200),
        module_importer=_importer,
    )

    assert "VULN_TYPE_NOT_IN_MANIFEST" in _codes(result)


def test_preflight_blocks_empty_type_selection(tmp_path: Path) -> None:
    result = run_preflight(
        _manifest(),
        [],
        tmp_path,
        http_requester=lambda *args, **kwargs: SimpleNamespace(status_code=200),
        module_importer=_importer,
    )

    assert "NO_VULN_TYPES" in _codes(result)


def test_preflight_blocks_unwritable_data_root(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("orchestration.preflight.os.access", lambda *args: False)

    result = run_preflight(
        _manifest(),
        ["XSS"],
        tmp_path,
        http_requester=lambda *args, **kwargs: SimpleNamespace(status_code=200),
        module_importer=_importer,
    )

    assert "DATA_ROOT_UNWRITABLE" in _codes(result)
