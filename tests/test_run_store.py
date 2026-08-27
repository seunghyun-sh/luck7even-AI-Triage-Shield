"""Focused tests for execution-state persistence and pipeline locking."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from orchestration.models import (
    ExecutionStage,
    ExecutionStatus,
    Progress,
    RunError,
    RunRequest,
    RunStatusDocument,
)
from orchestration.run_store import RunAlreadyActiveError, RunStore


def _status(
    *,
    status: ExecutionStatus = ExecutionStatus.RUNNING,
    stage: ExecutionStage | None = ExecutionStage.VALIDATING_TARGET,
    completed_at: datetime | None = None,
    raw_result_path: str | None = None,
    processed_result_path: str | None = None,
    error: RunError | None = None,
) -> RunStatusDocument:
    now = datetime.now(timezone.utc)
    return RunStatusDocument(
        scan_run_id="run-20260827-111500-a1b2c3",
        target_set_id="local-lab-v1",
        requested_vuln_types=["XSS", "SQLI"],
        status=status,
        stage=stage,
        progress=Progress(completed=0, total=0),
        started_at=now,
        updated_at=now,
        completed_at=completed_at,
        raw_result_path=raw_result_path,
        processed_result_path=processed_result_path,
        error=error,
    )


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/results.json",
        "../results.json",
        r"C:\results.json",
        r"raw\..\results.json",
    ],
)
def test_status_rejects_unsafe_artifact_paths(path: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _status(processed_result_path=path)
    assert path not in str(exc_info.value)


def test_models_reject_duplicate_vulnerability_types_and_invalid_run_id() -> None:
    with pytest.raises(ValidationError):
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS", "XSS"])

    payload = _status().model_dump(mode="json")
    payload["scan_run_id"] = "../not-a-run"
    with pytest.raises(ValidationError):
        RunStatusDocument.model_validate(payload)


def test_models_enforce_progress_and_terminal_invariants() -> None:
    with pytest.raises(ValidationError):
        Progress(completed=2, total=1)

    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        _status(
            status=ExecutionStatus.COMPLETED,
            stage=None,
            completed_at=now + timedelta(seconds=1),
            raw_result_path="raw/run-20260827-111500-a1b2c3/findings.json",
        )

    with pytest.raises(ValidationError):
        _status(
            status=ExecutionStatus.RUNNING,
            stage=None,
            completed_at=None,
            processed_result_path="processed/run-20260827-111500-a1b2c3/results.json",
        )

    with pytest.raises(ValidationError):
        _status(
            status=ExecutionStatus.FAILED,
            stage=None,
            completed_at=now + timedelta(seconds=1),
        )


def test_run_store_creates_and_atomically_round_trips_status(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    created = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS", "SQLI"])
    )

    run_dir = tmp_path / "data" / "runs" / created.scan_run_id
    assert json.loads((run_dir / "request.json").read_text(encoding="utf-8")) == {
        "schema_version": "1.0",
        "target_set_id": "local-lab-v1",
        "vuln_types": ["XSS", "SQLI"],
    }
    assert store.load_status(created.scan_run_id) == created

    running_time = created.updated_at + timedelta(seconds=1)
    running = created.model_copy(
        update={
            "status": ExecutionStatus.RUNNING,
            "stage": ExecutionStage.VALIDATING_TARGET,
            "updated_at": running_time,
        }
    )
    store.save_status(running)

    terminal_time = running_time + timedelta(seconds=1)
    completed = running.model_copy(
        update={
            "status": ExecutionStatus.COMPLETED,
            "stage": None,
            "updated_at": terminal_time,
            "completed_at": terminal_time,
            "raw_result_path": f"raw/{created.scan_run_id}/findings.json",
            "processed_result_path": f"processed/{created.scan_run_id}/results.json",
        }
    )
    store.save_status(completed)
    assert store.load_status(created.scan_run_id) == completed
    assert not list(run_dir.glob("*.tmp"))


def test_run_store_rejects_invalid_stage_and_terminal_mutation(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    queued = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )

    invalid_start = queued.model_copy(
        update={
            "status": ExecutionStatus.RUNNING,
            "stage": ExecutionStage.SCANNING_XSS,
            "updated_at": queued.updated_at + timedelta(seconds=1),
        }
    )
    with pytest.raises(ValueError, match="target validation"):
        store.save_status(invalid_start)

    running = queued.model_copy(
        update={
            "status": ExecutionStatus.RUNNING,
            "stage": ExecutionStage.VALIDATING_TARGET,
            "updated_at": queued.updated_at + timedelta(seconds=1),
        }
    )
    store.save_status(running)
    invalid_type_stage = running.model_copy(
        update={
            "stage": ExecutionStage.SCANNING_SQLI,
            "updated_at": running.updated_at + timedelta(seconds=1),
        }
    )
    with pytest.raises(ValueError, match="not requested"):
        store.save_status(invalid_type_stage)

    terminal_time = running.updated_at + timedelta(seconds=2)
    failed = running.model_copy(
        update={
            "status": ExecutionStatus.FAILED,
            "stage": None,
            "updated_at": terminal_time,
            "completed_at": terminal_time,
            "error": RunError(
                code="PIPELINE_CRASHED",
                message="Pipeline failed.",
                retryable=True,
            ),
        }
    )
    store.save_status(failed)
    changed_terminal = failed.model_copy(update={"progress": Progress(completed=0, total=1)})
    with pytest.raises(ValueError, match="cannot be modified"):
        store.save_status(changed_terminal)


def test_pipeline_lock_rejects_duplicate_and_releases_owned_lock(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    run_id = "run-20260827-111500-a1b2c3"
    lock_path = tmp_path / "data" / "runs" / ".pipeline.lock"

    with store.pipeline_lock(run_id):
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
        assert payload["scan_run_id"] == run_id
        assert payload["pid"] > 0
        assert datetime.fromisoformat(payload["created_at"]).tzinfo is not None
        with (
            pytest.raises(RunAlreadyActiveError) as exc_info,
            store.pipeline_lock("run-20260827-111501-b2c3d4"),
        ):
            pass
        assert exc_info.value.scan_run_id == run_id
        assert str(tmp_path) not in str(exc_info.value)

    assert not lock_path.exists()


def test_dead_owner_lock_marks_run_failed_and_recovers(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    status = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    lock_path = store.runs_dir / ".pipeline.lock"
    lock_path.write_text(
        json.dumps(
            {
                "pid": 2_147_483_647,
                "scan_run_id": status.scan_run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    )

    assert not store.pipeline_lock_active()
    recovered = store.load_status(status.scan_run_id)
    assert recovered.status is ExecutionStatus.FAILED
    assert recovered.error is not None
    assert recovered.error.code == "STALE_RUN_RECOVERED"
    assert not lock_path.exists()


def test_live_owner_lock_is_never_recovered(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    status = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    lock_path = store.runs_dir / ".pipeline.lock"
    lock_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "scan_run_id": status.scan_run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    )

    assert store.pipeline_lock_active()
    assert store.load_status(status.scan_run_id).status is ExecutionStatus.QUEUED
    assert lock_path.exists()
