"""Atomic persistence and advisory global pipeline locking for execution runs."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Self

from analysis.models import ProcessedRun, RawRun

from .models import (
    ExecutionStage,
    ExecutionStatus,
    Progress,
    RunError,
    RunRequest,
    RunStatusDocument,
    _validate_run_id,
)


class RunAlreadyActiveError(RuntimeError):
    """Raised when the MVP global pipeline lock is already held."""

    def __init__(self, active_lock: dict[str, Any] | None = None) -> None:
        self.active_lock = active_lock or {}
        self.code = "RUN_ALREADY_ACTIVE"
        self.retryable = True
        self.pid = self.active_lock.get("pid")
        self.scan_run_id = self.active_lock.get("scan_run_id")
        self.created_at = self.active_lock.get("created_at")
        super().__init__("A pipeline run is already active.")


class PipelineLock:
    """An advisory lock whose descriptor remains open for its owner lifetime."""

    def __init__(self, data_root: Path | str, scan_run_id: str) -> None:
        self._data_root = Path(data_root)
        self._scan_run_id = _validate_run_id(scan_run_id)
        self._path = self._data_root / "runs" / ".pipeline.lock"
        self._descriptor: int | None = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        self.release()
        return False

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise RuntimeError("Pipeline lock is already held by this instance.")

        self._path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(descriptor)
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise RunAlreadyActiveError(self._read_existing_lock()) from exc
            raise
        record = {
            "pid": os.getpid(),
            "scan_run_id": self._scan_run_id,
            "created_at": datetime.now().astimezone().isoformat(),
        }
        contents = (
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        try:
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            remaining = memoryview(contents)
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise OSError("Unable to write pipeline lock metadata.")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except BaseException:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def release(self) -> None:
        if self._descriptor is None:
            return
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self._descriptor)
            self._descriptor = None

    def _read_existing_lock(self) -> dict[str, Any] | None:
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(loaded, dict):
            return None
        pid = loaded.get("pid")
        scan_run_id = loaded.get("scan_run_id")
        created_at = loaded.get("created_at")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not isinstance(created_at, str)
        ):
            return None
        try:
            created_at_value = datetime.fromisoformat(created_at)
            if (
                created_at_value.tzinfo is None
                or created_at_value.utcoffset() is None
            ):
                return None
            return {
                "pid": pid,
                "scan_run_id": _validate_run_id(scan_run_id),
                "created_at": created_at_value.isoformat(),
            }
        except (TypeError, ValueError):
            return None


class RunStore:
    """File store for validated run requests and status documents."""

    def __init__(self, data_root: Path | str = "data") -> None:
        self.data_root = Path(data_root)

    @property
    def runs_dir(self) -> Path:
        return self.data_root / "runs"

    def new_run_id(self) -> str:
        while True:
            timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
            scan_run_id = f"run-{timestamp}-{secrets.token_hex(3)}"
            if not (self.runs_dir / scan_run_id).exists():
                return scan_run_id

    def create_run(self, request: RunRequest) -> RunStatusDocument:
        request = RunRequest.model_validate(request.model_dump(mode="json"))
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        while True:
            scan_run_id = self.new_run_id()
            try:
                self._run_dir(scan_run_id).mkdir()
            except FileExistsError:
                continue
            break

        now = datetime.now().astimezone()
        status = RunStatusDocument(
            scan_run_id=scan_run_id,
            target_set_id=request.target_set_id,
            requested_vuln_types=request.vuln_types,
            status=ExecutionStatus.QUEUED,
            stage=None,
            progress=Progress(completed=0, total=0),
            started_at=now,
            updated_at=now,
            completed_at=None,
            raw_result_path=None,
            processed_result_path=None,
            error=None,
        )
        try:
            self._atomic_write_json(
                self._request_path(scan_run_id), request.model_dump(mode="json")
            )
            self.save_status(status)
        except BaseException:
            for artifact_name in ("status.json", "request.json"):
                try:
                    (self._run_dir(scan_run_id) / artifact_name).unlink()
                except FileNotFoundError:
                    pass
            try:
                self._run_dir(scan_run_id).rmdir()
            except OSError:
                pass
            raise
        return status

    def load_status(self, scan_run_id: str) -> RunStatusDocument:
        path = self._status_path(scan_run_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise FileNotFoundError("Run status does not exist.") from None
        except json.JSONDecodeError as exc:
            raise ValueError("Run status is not valid JSON.") from exc
        return RunStatusDocument.model_validate(payload)

    def load_request(self, scan_run_id: str) -> RunRequest:
        path = self._request_path(scan_run_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise FileNotFoundError("Run request does not exist.") from None
        except json.JSONDecodeError as exc:
            raise ValueError("Run request is not valid JSON.") from exc
        return RunRequest.model_validate(payload)

    def save_status(self, status: RunStatusDocument) -> None:
        status = RunStatusDocument.model_validate(status.model_dump(mode="json"))
        scan_run_id = _validate_run_id(status.scan_run_id)
        run_dir = self._run_dir(scan_run_id)
        if not run_dir.is_dir():
            raise FileNotFoundError("Run directory does not exist.")
        request = self.load_request(scan_run_id)
        if (
            status.target_set_id != request.target_set_id
            or status.requested_vuln_types != request.vuln_types
        ):
            raise ValueError("Run status does not match its request.")
        try:
            previous = self.load_status(scan_run_id)
        except FileNotFoundError:
            previous = None
        if previous is not None:
            self._validate_status_transition(previous, status)
        self._atomic_write_json(
            self._status_path(scan_run_id),
            status.model_dump(mode="json"),
        )

    def pipeline_lock(self, scan_run_id: str) -> PipelineLock:
        return PipelineLock(self.data_root, scan_run_id)

    def pipeline_lock_active(self) -> bool:
        """Return whether an advisory lock is currently held without mutating state."""

        return self._pipeline_lock_is_held()

    def active_run_status(self) -> RunStatusDocument | None:
        """Return the nonterminal status of the current live lock owner, if valid."""

        if not self._pipeline_lock_is_held():
            return None
        owner = self._read_pipeline_lock_owner()
        if owner is None:
            return None
        try:
            status = self.load_status(owner["scan_run_id"])
        except (OSError, ValueError):
            return None
        if status.status not in {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING}:
            return None
        return status

    def reconcile_orphaned_runs(self) -> list[RunStatusDocument]:
        """Fail nonterminal runs only when no pipeline owner holds the lock."""

        if self._pipeline_lock_is_held() or not self.runs_dir.is_dir():
            return []
        reconciled: list[RunStatusDocument] = []
        for run_dir in self.runs_dir.iterdir():
            if not run_dir.is_dir():
                continue
            try:
                scan_run_id = _validate_run_id(run_dir.name)
                status = self.load_status(scan_run_id)
            except (OSError, ValueError):
                continue
            if status.status not in {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING}:
                continue
            now = max(datetime.now().astimezone(), status.updated_at)
            failed = status.model_copy(
                update={
                    "status": ExecutionStatus.FAILED,
                    "stage": None,
                    "updated_at": now,
                    "completed_at": now,
                    "processed_result_path": None,
                    "error": RunError(
                        code="ORPHANED_RUN",
                        message="The run has no active pipeline owner.",
                        retryable=True,
                    ),
                }
            )
            self.save_status(failed)
            reconciled.append(failed)
        return reconciled

    def _pipeline_lock_is_held(self) -> bool:
        lock_path = self.runs_dir / ".pipeline.lock"
        try:
            descriptor = os.open(lock_path, os.O_RDWR)
        except FileNotFoundError:
            return False
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    return True
                raise
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return False
        finally:
            os.close(descriptor)

    def _read_pipeline_lock_owner(self) -> dict[str, str | int] | None:
        try:
            payload = json.loads(
                (self.runs_dir / ".pipeline.lock").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        pid = payload.get("pid")
        scan_run_id = payload.get("scan_run_id")
        created_at = payload.get("created_at")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not isinstance(created_at, str)
        ):
            return None
        try:
            created_at_value = datetime.fromisoformat(created_at)
            if (
                created_at_value.tzinfo is None
                or created_at_value.utcoffset() is None
            ):
                return None
            return {
                "pid": pid,
                "scan_run_id": _validate_run_id(scan_run_id),
                "created_at": created_at_value.isoformat(),
            }
        except (TypeError, ValueError):
            return None

    def responses_dir(self, scan_run_id: str) -> Path:
        """Return the contained evidence directory for an existing run."""

        scan_run_id = _validate_run_id(scan_run_id)
        self.load_request(scan_run_id)
        path = self._contained_artifact_path("raw", scan_run_id, "responses")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def publish_raw(self, raw_run: RawRun) -> str:
        """Validate and atomically publish a canonical raw artifact."""

        raw_run = RawRun.model_validate(raw_run.model_dump(mode="json"))
        scan_run_id = self._validate_artifact_identity(
            raw_run.scan_run_id, raw_run.target_set_id
        )
        path = self._contained_artifact_path("raw", scan_run_id, "findings.json")
        self._atomic_write_json(path, raw_run.model_dump(mode="json"))
        return f"raw/{scan_run_id}/findings.json"

    def publish_processed(self, processed_run: ProcessedRun) -> str:
        """Validate and atomically publish a canonical processed artifact."""

        processed_run = ProcessedRun.model_validate(
            processed_run.model_dump(mode="json")
        )
        scan_run_id = self._validate_artifact_identity(
            processed_run.scan_run_id, processed_run.target_set_id
        )
        path = self._contained_artifact_path(
            "processed", scan_run_id, "results.json"
        )
        self._atomic_write_json(path, processed_run.model_dump(mode="json"))
        return f"processed/{scan_run_id}/results.json"

    def _validate_artifact_identity(
        self, scan_run_id: str, target_set_id: str
    ) -> str:
        scan_run_id = _validate_run_id(scan_run_id)
        request = self.load_request(scan_run_id)
        if request.target_set_id != target_set_id:
            raise ValueError("Artifact target identity does not match its run request.")
        return scan_run_id

    def _contained_artifact_path(
        self, artifact_type: str, scan_run_id: str, name: str
    ) -> Path:
        root = self.data_root.resolve()
        path = (root / artifact_type / scan_run_id / name).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError("Artifact path escapes the data root.") from error
        return path

    def _run_dir(self, scan_run_id: str) -> Path:
        return self.runs_dir / _validate_run_id(scan_run_id)

    def _request_path(self, scan_run_id: str) -> Path:
        return self._run_dir(scan_run_id) / "request.json"

    def _status_path(self, scan_run_id: str) -> Path:
        return self._run_dir(scan_run_id) / "status.json"

    @staticmethod
    def _validate_status_transition(
        previous: RunStatusDocument, current: RunStatusDocument
    ) -> None:
        terminal_statuses = {
            ExecutionStatus.COMPLETED,
            ExecutionStatus.PARTIAL,
            ExecutionStatus.FAILED,
        }
        if previous.status in terminal_statuses:
            if current != previous:
                raise ValueError("Terminal run status cannot be modified.")
            return
        if current.scan_run_id != previous.scan_run_id:
            raise ValueError("Run status cannot change scan_run_id.")
        if current.started_at != previous.started_at:
            raise ValueError("Run status cannot change started_at.")
        if current.updated_at < previous.updated_at:
            raise ValueError("Run status updated_at cannot move backwards.")

        allowed = {
            ExecutionStatus.QUEUED: {
                ExecutionStatus.QUEUED,
                ExecutionStatus.RUNNING,
                ExecutionStatus.FAILED,
            },
            ExecutionStatus.RUNNING: {
                ExecutionStatus.RUNNING,
                ExecutionStatus.COMPLETED,
                ExecutionStatus.PARTIAL,
                ExecutionStatus.FAILED,
            },
            ExecutionStatus.COMPLETED: {ExecutionStatus.COMPLETED},
            ExecutionStatus.PARTIAL: {ExecutionStatus.PARTIAL},
            ExecutionStatus.FAILED: {ExecutionStatus.FAILED},
        }
        if current.status not in allowed[previous.status]:
            raise ValueError("Run status transition is not permitted.")

        if (
            previous.status is ExecutionStatus.QUEUED
            and current.status is ExecutionStatus.RUNNING
            and current.stage is not ExecutionStage.VALIDATING_TARGET
        ):
            raise ValueError("A queued run must start with target validation.")

        unavailable_stages = {
            ExecutionStage.SCANNING_XSS: "XSS",
            ExecutionStage.SCANNING_SQLI: "SQLI",
        }
        required_type = unavailable_stages.get(current.stage)
        if required_type is not None and required_type not in current.requested_vuln_types:
            raise ValueError("Run stage was not requested.")

        stage_order = {
            ExecutionStage.VALIDATING_TARGET: 0,
            ExecutionStage.SCANNING_XSS: 1,
            ExecutionStage.SCANNING_SQLI: 2,
            ExecutionStage.PUBLISHING_RAW: 3,
            ExecutionStage.AI_TRIAGE: 4,
            ExecutionStage.PUBLISHING_RESULT: 5,
        }
        if (
            previous.status is ExecutionStatus.RUNNING
            and current.status is ExecutionStatus.RUNNING
            and stage_order[current.stage] < stage_order[previous.stage]
        ):
            raise ValueError("Run stage cannot move backwards.")
        if (
            previous.status is ExecutionStatus.RUNNING
            and current.status is ExecutionStatus.RUNNING
            and current.stage is previous.stage
            and current.progress.completed < previous.progress.completed
        ):
            raise ValueError("Run progress cannot move backwards within a stage.")

    @staticmethod
    def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        try:
            with temporary_path.open("x", encoding="utf-8") as artifact:
                json.dump(payload, artifact, ensure_ascii=False, indent=2, sort_keys=True)
                artifact.write("\n")
                artifact.flush()
                os.fsync(artifact.fileno())
            os.replace(temporary_path, path)
        except BaseException:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise
