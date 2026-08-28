"""Focused tests for execution-state persistence and pipeline locking."""

from __future__ import annotations

import json
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

SAMPLE_PROCESSED_PATH = (
    Path(__file__).resolve().parents[1] / "configs" / "triaged-results.example.json"
)


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


def _publish_reviewable_partial(store: RunStore) -> tuple[RunStatusDocument, Path]:
    initial = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    running_time = initial.updated_at + timedelta(seconds=1)
    running = initial.model_copy(
        update={
            "status": ExecutionStatus.RUNNING,
            "stage": ExecutionStage.VALIDATING_TARGET,
            "updated_at": running_time,
        }
    )
    store.save_status(running)
    completed_at = running_time + timedelta(seconds=1)
    terminal = running.model_copy(
        update={
            "status": ExecutionStatus.PARTIAL,
            "stage": None,
            "updated_at": completed_at,
            "completed_at": completed_at,
            "raw_result_path": f"raw/{initial.scan_run_id}/findings.json",
            "processed_result_path": f"processed/{initial.scan_run_id}/results.json",
        }
    )
    store.save_status(terminal)
    payload = json.loads(SAMPLE_PROCESSED_PATH.read_text(encoding="utf-8"))
    payload.update(
        {
            "scan_run_id": initial.scan_run_id,
            "target_set_id": initial.target_set_id,
            "status": "PARTIAL",
        }
    )
    path = store.data_root / "processed" / initial.scan_run_id / "results.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return terminal, path


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

    lock = store.pipeline_lock(run_id)
    assert lock.scan_run_id == run_id
    assert not lock.held
    assert lock.owns_data_root(store.data_root)
    with lock:
        assert lock.held
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

    assert lock_path.exists()
    assert not lock.held
    assert not store.pipeline_lock_active()


def test_stale_lock_metadata_is_not_an_active_lock_or_mutated(tmp_path: Path) -> None:
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
    original = lock_path.read_bytes()

    assert not store.pipeline_lock_active()
    assert store.load_status(status.scan_run_id) == status
    assert lock_path.read_bytes() == original


def test_active_run_status_requires_live_lock_and_nonterminal_owner(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    status = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )

    assert store.active_run_status() is None
    with store.pipeline_lock(status.scan_run_id):
        assert store.active_run_status() == status


def test_active_run_status_rejects_malformed_or_terminal_owner(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    status = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    lock_path = store.runs_dir / ".pipeline.lock"

    with store.pipeline_lock(status.scan_run_id):
        lock_path.write_text("{malformed", encoding="utf-8")
        assert store.pipeline_lock_active()
        assert store.active_run_status() is None

    with store.pipeline_lock(status.scan_run_id):
        terminal_time = status.updated_at + timedelta(seconds=1)
        failed = status.model_copy(
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
        assert store.active_run_status() is None


def test_active_run_status_rejects_owner_status_identity_mismatch(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "data")
    status = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    mismatched_id = "run-20260827-111501-b2c3d4"
    payload = status.model_dump(mode="json")
    payload["scan_run_id"] = mismatched_id

    with store.pipeline_lock(status.scan_run_id):
        (store.runs_dir / status.scan_run_id / "status.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        assert store.active_run_status() is None


def test_reviewable_processed_run_requires_coupled_terminal_artifacts(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "data")
    status, _ = _publish_reviewable_partial(store)

    reviewed = store.load_reviewable_processed_run(status.scan_run_id)

    assert reviewed.scan_run_id == status.scan_run_id
    assert reviewed.target_set_id == status.target_set_id
    assert reviewed.status.value == status.status.value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scan_run_id", "run-20260827-111500-a1b2c3"),
        ("target_set_id", "other-target-set"),
        ("status", "COMPLETED"),
    ],
)
def test_reviewable_processed_run_rejects_mismatched_envelope(
    tmp_path: Path, field: str, value: str
) -> None:
    store = RunStore(tmp_path / "data")
    status, path = _publish_reviewable_partial(store)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        store.load_reviewable_processed_run(status.scan_run_id)

    assert str(store.data_root.resolve()) not in str(exc_info.value)
    assert "{" not in str(exc_info.value)


def test_reviewable_processed_run_rejects_malformed_and_symlink_artifacts(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "data")
    status, path = _publish_reviewable_partial(store)
    path.write_text("{malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="not available"):
        store.load_reviewable_processed_run(status.scan_run_id)

    symlink_status, path = _publish_reviewable_partial(store)
    outside = tmp_path / "outside-results.json"
    outside.write_text(SAMPLE_PROCESSED_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    path.unlink()
    path.symlink_to(outside)

    with pytest.raises(ValueError, match="not available"):
        store.load_reviewable_processed_run(symlink_status.scan_run_id)


def test_reconcile_orphaned_runs_requires_held_local_lock(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "data")
    status = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    lock = store.pipeline_lock(status.scan_run_id)

    with pytest.raises(TypeError):
        store.reconcile_orphaned_runs()  # type: ignore[call-arg]

    with pytest.raises(ValueError, match="held pipeline lock"):
        store.reconcile_orphaned_runs(lock)

    with lock:
        pass

    with pytest.raises(ValueError, match="held pipeline lock"):
        store.reconcile_orphaned_runs(lock)

    foreign_store = RunStore(tmp_path / "foreign-data")
    with (
        foreign_store.pipeline_lock(status.scan_run_id) as foreign_lock,
        pytest.raises(ValueError, match="held pipeline lock"),
    ):
        store.reconcile_orphaned_runs(foreign_lock)


def test_reconcile_orphaned_runs_fails_old_nonterminal_runs_but_not_owner(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "data")
    orphan = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )
    owner = store.create_run(
        RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"])
    )

    with store.pipeline_lock(owner.scan_run_id) as lock:
        reconciled = store.reconcile_orphaned_runs(lock)

    assert [status.scan_run_id for status in reconciled] == [orphan.scan_run_id]
    for recovered in reconciled:
        assert recovered.status is ExecutionStatus.FAILED
        assert recovered.error is not None
        assert recovered.error.code == "ORPHANED_RUN"
    assert store.load_status(owner.scan_run_id) == owner
