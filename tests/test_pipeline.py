"""Focused tests for the blocking execution orchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import main as cli
from analysis.models import (
    AiResult,
    AiStatus,
    AiStatusReason,
    ProcessedFinding,
    ProcessedRun,
    RawFinding,
    RawRun,
    RuleLabel,
    RunStatus,
    ScanResponse,
    ScanResult,
    ScanRule,
    ScanStatus,
    TargetCase,
    TargetInput,
    TargetManifest,
)
from orchestration.models import ExecutionStatus, RunRequest
from orchestration.pipeline import PipelineOrchestrator, TargetValidationError
from orchestration.run_store import RunAlreadyActiveError, RunStore


def _manifest() -> TargetManifest:
    return TargetManifest(
        schema_version="1.0",
        target_set_id="local-lab-v1",
        base_url="http://localhost:8000",
        request_policy={"timeout_seconds": 5, "follow_redirects": False},
        targets=[
            TargetCase(
                case_id="xss-case",
                vuln_type="XSS",
                path="/search",
                method="GET",
                input=TargetInput(
                    location="query", parameters={"q": "test"}, attack_parameter="q"
                ),
                requires_pre_auth=False,
                auth_profile=None,
                payload_profile="xss-default",
                manual_verification_profile="xss-manual",
            ),
            TargetCase(
                case_id="sqli-case",
                vuln_type="SQLI",
                path="/search",
                method="GET",
                input=TargetInput(
                    location="query", parameters={"id": "1"}, attack_parameter="id"
                ),
                requires_pre_auth=False,
                auth_profile=None,
                payload_profile="sqli-default",
                manual_verification_profile="sqli-manual",
            ),
        ],
    )


def _finding(vuln_type: str, finding_id: str, *, failed: bool = False) -> RawFinding:
    now = datetime.now(timezone.utc)
    request = {
        "url": "http://localhost:8000/search",
        "method": "GET",
        "input_location": "query",
        "parameter": "q" if vuln_type == "XSS" else "id",
        "payload": "probe",
    }
    if failed:
        scan = ScanResult(
            status=ScanStatus.FAILED,
            request=request,
            response=ScanResponse(
                http_status=None,
                elapsed_ms=None,
                baseline_elapsed_ms=None,
                evidence_summary=None,
                html_path=None,
            ),
            rule=ScanRule(label=None, reason=None),
            error={"code": "REQUEST_FAILED", "message": "Request failed.", "retryable": True},
        )
    else:
        scan = ScanResult(
            status=ScanStatus.COMPLETED,
            request=request,
            response=ScanResponse(
                http_status=200,
                elapsed_ms=10,
                baseline_elapsed_ms=5 if vuln_type == "SQLI" else None,
                evidence_summary="Response inspected.",
                html_path=None,
            ),
            rule=ScanRule(label=RuleLabel.SAFE, reason="No signal."),
            error=None,
        )
    return RawFinding(
        case_id=f"{vuln_type.lower()}-case",
        finding_id=finding_id,
        scanned_at=now,
        vuln_type=vuln_type,
        scan=scan,
    )


def _triage(raw: RawRun) -> ProcessedRun:
    findings: list[ProcessedFinding] = []
    for raw_finding in raw.findings:
        if raw_finding.scan.status is ScanStatus.FAILED:
            ai = AiResult(
                status=AiStatus.NOT_REQUESTED,
                status_reason=AiStatusReason.SCAN_FAILED,
                label=None,
                confidence=None,
                needs_human_review=True,
                assessment_summary=None,
                source_evidence=None,
                impact=None,
                recommendation=None,
                manual_check=None,
                report_paragraph=None,
                error=None,
            )
        else:
            ai = AiResult(
                status=AiStatus.COMPLETED,
                status_reason=None,
                label="SAFE",
                confidence=0.9,
                needs_human_review=False,
                assessment_summary="No vulnerability found.",
                source_evidence="No signal.",
                impact="No impact.",
                recommendation="Continue monitoring.",
                manual_check="No manual check required.",
                report_paragraph="The endpoint was safe.",
                error=None,
            )
        findings.append(
            ProcessedFinding(
                case_id=raw_finding.case_id,
                finding_id=raw_finding.finding_id,
                scanned_at=raw_finding.scanned_at,
                vuln_type=raw_finding.vuln_type,
                scan=raw_finding.scan,
                ai=ai,
            )
        )
    status = RunStatus.PARTIAL if any(
        finding.scan.status is ScanStatus.FAILED for finding in findings
    ) else RunStatus.COMPLETED
    return ProcessedRun(
        schema_version="1.0",
        scan_run_id=raw.scan_run_id,
        target_set_id=raw.target_set_id,
        started_at=raw.started_at,
        completed_at=datetime.now(timezone.utc),
        status=status,
        findings=findings,
    )


def _orchestrator(
    tmp_path: Path,
    xss,
    sqli,
    triage=_triage,
    *,
    manifest: TargetManifest | None = None,
) -> PipelineOrchestrator:
    registered = manifest or _manifest()
    return PipelineOrchestrator(
        RunStore(tmp_path / "data"),
        xss_scanner=xss,
        sqli_scanner=sqli,
        triage=triage,
        manifest_resolver=lambda target_set_id: registered,
    )


def test_happy_path_publishes_one_to_one_artifacts(tmp_path: Path) -> None:
    def xss(targets, context, progress):
        progress(1, 1)
        assert context.base_url == "http://localhost:8000"
        assert context.request_policy.timeout_seconds == 5
        assert context.responses_dir.is_dir()
        return [_finding("XSS", "xss-1")]

    def sqli(targets, context, progress):
        progress(1, 1)
        return [_finding("SQLI", "sqli-1")]

    created: list[str] = []
    result = _orchestrator(tmp_path, xss, sqli).run(
        "local-lab-v1", ["XSS", "SQLI"], on_run_created=created.append
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert created == [result.scan_run_id]
    assert (tmp_path / "data" / result.raw_result_path).is_file()
    assert (tmp_path / "data" / result.processed_result_path).is_file()


def test_xss_only_filters_targets_and_skips_sqli(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def xss(targets, context, progress):
        calls.append([target.case_id for target in targets])
        return [_finding("XSS", "xss-1")]

    def sqli(targets, context, progress):
        raise AssertionError("SQLI scanner must not be called")

    result = _orchestrator(tmp_path, xss, sqli).run("local-lab-v1", ["XSS"])
    assert result.status is ExecutionStatus.COMPLETED
    assert calls == [["xss-case"]]


def test_requested_type_must_exist_in_authorized_manifest(tmp_path: Path) -> None:
    manifest = _manifest().model_copy(
        update={
            "targets": [
                target for target in _manifest().targets if target.vuln_type.value == "XSS"
            ]
        }
    )

    with pytest.raises(TargetValidationError, match="does not contain"):
        _orchestrator(
            tmp_path,
            lambda targets, context, progress: [],
            lambda targets, context, progress: [],
            manifest=manifest,
        ).run("local-lab-v1", ["SQLI"])


def test_unregistered_target_set_is_rejected_before_run_creation(tmp_path: Path) -> None:
    def missing(target_set_id: str) -> TargetManifest:
        raise ValueError("not registered")

    orchestrator = PipelineOrchestrator(
        RunStore(tmp_path / "data"),
        xss_scanner=lambda targets, context, progress: [],
        sqli_scanner=lambda targets, context, progress: [],
        triage=_triage,
        manifest_resolver=missing,
    )

    with pytest.raises(TargetValidationError):
        orchestrator.run("unregistered", ["XSS"])
    assert not (tmp_path / "data" / "runs").exists()


def test_cli_rejects_arbitrary_manifest_path() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(
            ["run", "--targets", "configs/targets.example.json", "--types", "XSS"]
        )


def test_run_id_handshake_occurs_only_after_lock_acquisition(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    active = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    created: list[str] = []
    orchestrator = PipelineOrchestrator(
        store,
        xss_scanner=lambda targets, context, progress: [_finding("XSS", "xss-1")],
        sqli_scanner=lambda targets, context, progress: [],
        triage=_triage,
        manifest_resolver=lambda target_set_id: _manifest(),
    )

    with (
        store.pipeline_lock(active.scan_run_id),
        pytest.raises(RunAlreadyActiveError),
    ):
        orchestrator.run("local-lab-v1", ["XSS"], on_run_created=created.append)

    assert created == []
    failed_run_ids = [
        run_dir.name
        for run_dir in store.runs_dir.iterdir()
        if run_dir.is_dir() and run_dir.name != active.scan_run_id
    ]
    assert len(failed_run_ids) == 1
    failed = store.load_status(failed_run_ids[0])
    assert failed.status is ExecutionStatus.FAILED
    assert failed.error is not None
    assert failed.error.code == "RUN_ALREADY_ACTIVE"


def test_run_reconciles_old_orphan_after_owning_lock_then_completes(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "data")
    orphan = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    observed_owner_statuses: list[ExecutionStatus] = []

    def xss(targets, context, progress):
        observed_owner_statuses.append(store.load_status(context.scan_run_id).status)
        assert store.load_status(orphan.scan_run_id).status is ExecutionStatus.FAILED
        return [_finding("XSS", "xss-1")]

    orchestrator = PipelineOrchestrator(
        store,
        xss_scanner=xss,
        sqli_scanner=lambda targets, context, progress: [],
        triage=_triage,
        manifest_resolver=lambda target_set_id: _manifest(),
    )

    result = orchestrator.run("local-lab-v1", ["XSS"])

    assert observed_owner_statuses == [ExecutionStatus.RUNNING]
    assert result.status is ExecutionStatus.COMPLETED
    assert store.load_status(orphan.scan_run_id).status is ExecutionStatus.FAILED
    assert store.load_status(result.scan_run_id).status is ExecutionStatus.COMPLETED


def test_cli_component_loading_skips_unrequested_scanner(monkeypatch) -> None:
    loaded: list[tuple[str, str]] = []

    def component(module_name: str, attribute: str):
        loaded.append((module_name, attribute))
        return lambda *args, **kwargs: None

    monkeypatch.setattr(cli, "_component_callable", component)

    _, unrequested_sqli, _ = cli._load_components(["XSS"])

    assert loaded == [
        ("scanners.xss", "scan"),
        ("analysis.ai_triage", "triage"),
    ]
    with pytest.raises(RuntimeError, match="unrequested scanner"):
        unrequested_sqli([], object(), lambda completed, total: None)


def test_mixed_scan_results_are_partial(tmp_path: Path) -> None:
    result = _orchestrator(
        tmp_path,
        lambda targets, context, progress: [_finding("XSS", "xss-1")],
        lambda targets, context, progress: [_finding("SQLI", "sqli-1", failed=True)],
    ).run("local-lab-v1", ["XSS", "SQLI"])
    assert result.status is ExecutionStatus.PARTIAL
    assert result.processed_result_path is not None


def test_scanner_must_cover_every_requested_target(tmp_path: Path) -> None:
    result = _orchestrator(
        tmp_path,
        lambda targets, context, progress: [],
        lambda targets, context, progress: [_finding("SQLI", "sqli-1")],
    ).run("local-lab-v1", ["XSS", "SQLI"])

    assert result.status is ExecutionStatus.FAILED
    assert result.error is not None
    assert result.error.code == "SCANNER_CONTRACT_FAILED"
    assert result.processed_result_path is None


def test_scanner_rejects_finding_for_unknown_target(tmp_path: Path) -> None:
    unknown = _finding("XSS", "xss-1").model_copy(update={"case_id": "other"})
    result = _orchestrator(
        tmp_path,
        lambda targets, context, progress: [unknown],
        lambda targets, context, progress: [],
    ).run("local-lab-v1", ["XSS"])

    assert result.status is ExecutionStatus.FAILED
    assert result.error is not None
    assert result.error.code == "SCANNER_CONTRACT_FAILED"


def test_all_failed_scans_publish_raw_without_calling_triage(tmp_path: Path) -> None:
    def no_triage(raw):
        raise AssertionError("Triage must not run when every scan failed")

    result = _orchestrator(
        tmp_path,
        lambda targets, context, progress: [_finding("XSS", "xss-1", failed=True)],
        lambda targets, context, progress: [_finding("SQLI", "sqli-1", failed=True)],
        no_triage,
    ).run("local-lab-v1", ["XSS", "SQLI"])
    assert result.status is ExecutionStatus.FAILED
    assert result.raw_result_path is not None
    assert result.processed_result_path is None


def test_scanner_crash_records_safe_failure_and_releases_lock(tmp_path: Path) -> None:
    def crash(targets, context, progress):
        raise RuntimeError(f"secret payload at {tmp_path}")

    result = _orchestrator(tmp_path, crash, crash).run("local-lab-v1", ["XSS"])
    assert result.status is ExecutionStatus.FAILED
    assert result.error is not None
    assert result.error.message == "Pipeline execution failed."
    assert not RunStore(tmp_path / "data").pipeline_lock_active()


def test_lineage_mismatch_does_not_publish_processed(tmp_path: Path) -> None:
    def wrong_lineage(raw: RawRun) -> ProcessedRun:
        processed = _triage(raw)
        changed = processed.findings[0].model_copy(update={"case_id": "other-case"})
        return processed.model_copy(update={"findings": [changed]})

    result = _orchestrator(
        tmp_path,
        lambda targets, context, progress: [_finding("XSS", "xss-1")],
        lambda targets, context, progress: [],
        wrong_lineage,
    ).run("local-lab-v1", ["XSS"])
    assert result.status is ExecutionStatus.FAILED
    assert not list((tmp_path / "data" / "processed").rglob("results.json"))


def test_artifact_publication_is_atomic(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    run = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
    raw = RawRun(
        schema_version="1.0",
        scan_run_id=run.scan_run_id,
        target_set_id="local-lab-v1",
        started_at=run.started_at,
        completed_at=datetime.now(timezone.utc),
        status=RunStatus.COMPLETED,
        findings=[_finding("XSS", "xss-1")],
    )
    relative_path = store.publish_raw(raw)
    artifact = tmp_path / "data" / relative_path
    assert json.loads(artifact.read_text(encoding="utf-8"))["scan_run_id"] == run.scan_run_id
    assert not list(artifact.parent.glob("*.tmp"))


def test_artifact_publication_rejects_unsafe_or_mismatched_identity(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "data")
    run = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    raw = RawRun(
        schema_version="1.0",
        scan_run_id=run.scan_run_id,
        target_set_id="local-lab-v1",
        started_at=run.started_at,
        completed_at=datetime.now(timezone.utc),
        status=RunStatus.COMPLETED,
        findings=[_finding("XSS", "xss-1")],
    )

    with pytest.raises(ValueError):
        store.publish_raw(raw.model_copy(update={"scan_run_id": "/tmp/escaped"}))
    with pytest.raises(ValueError, match="identity"):
        store.publish_raw(raw.model_copy(update={"target_set_id": "other-target"}))


def test_invalid_progress_records_failure_and_releases_lock(tmp_path: Path) -> None:
    def invalid_progress(targets, context, progress):
        progress(2, 1)
        return [_finding("XSS", "xss-1")]

    result = _orchestrator(
        tmp_path, invalid_progress, lambda targets, context, progress: []
    ).run("local-lab-v1", ["XSS"])
    assert result.status is ExecutionStatus.FAILED
    assert not RunStore(tmp_path / "data").pipeline_lock_active()


def test_component_import_exception_is_normalized_without_details(monkeypatch) -> None:
    def fail(name: str) -> object:
        raise RuntimeError("secret=/private/path")

    monkeypatch.setattr(cli.importlib, "import_module", fail)

    with pytest.raises(cli.ComponentUnavailableError) as error:
        cli._component_callable("analysis.ai_triage", "triage")
    assert "secret" not in str(error.value)
