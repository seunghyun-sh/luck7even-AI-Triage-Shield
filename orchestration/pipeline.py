"""Blocking orchestration for validated scanner and triage components."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TypeAlias

from pydantic import ValidationError

from analysis.models import (
    ProcessedFinding,
    ProcessedRun,
    RawFinding,
    RawRun,
    RequestPolicy,
    RunStatus,
    TargetCase,
    TargetManifest,
)

from .deployment_registry import (
    DeploymentRegistryError,
    deployment_manifest_lease,
    resolve_deployment_manifest,
)
from .models import (
    ExecutionStage,
    ExecutionStatus,
    Progress,
    RunError,
    RunRequest,
    RunStatusDocument,
)
from .run_store import RunAlreadyActiveError, RunStore
from .target_registry import TargetRegistryError

ProgressCallback: TypeAlias = Callable[[int, int], None]
AuthProfileResolver: TypeAlias = Callable[[str], Mapping[str, str]]
ManifestResolver: TypeAlias = Callable[[str], TargetManifest]


@dataclass(frozen=True)
class ScanContext:
    """Authorized capabilities exposed to a black-box scanner adapter."""

    scan_run_id: str
    base_url: str
    request_policy: RequestPolicy
    responses_dir: Path
    resolve_auth_profile: AuthProfileResolver


Scanner: TypeAlias = Callable[
    [list[TargetCase], ScanContext, ProgressCallback], list[RawFinding]
]
Triage: TypeAlias = Callable[[RawRun], ProcessedRun]
RunCreatedCallback: TypeAlias = Callable[[str], None]


def _unconfigured_auth_profile(profile_id: str) -> Mapping[str, str]:
    raise KeyError(f"Auth profile is not configured: {profile_id}")


class TargetValidationError(ValueError):
    """Raised when an execution request's authorized manifest is invalid."""


class _PipelineFailure(RuntimeError):
    def __init__(self, code: str, message: str, retryable: bool = True) -> None:
        self.code = code
        self.message = message
        self.retryable = retryable
        super().__init__(message)


class PipelineOrchestrator:
    """Run scanners and triage serially while owning all execution state."""

    def __init__(
        self,
        store: RunStore,
        *,
        xss_scanner: Scanner,
        sqli_scanner: Scanner,
        triage: Triage,
        manifest_resolver: ManifestResolver = resolve_deployment_manifest,
        auth_profile_resolver: AuthProfileResolver = _unconfigured_auth_profile,
    ) -> None:
        self._store = store
        self._xss_scanner = xss_scanner
        self._sqli_scanner = sqli_scanner
        self._triage = triage
        self._manifest_resolver = manifest_resolver
        self._auth_profile_resolver = auth_profile_resolver

    def run(
        self,
        target_set_id: str,
        deployment_id: str,
        vuln_types: list[str],
        *,
        on_run_created: RunCreatedCallback | None = None,
    ) -> RunStatusDocument:
        """Execute a complete pipeline invocation and return its terminal status."""

        status: RunStatusDocument | None = None
        authorization = (
            deployment_manifest_lease(deployment_id)
            if self._manifest_resolver is resolve_deployment_manifest
            else nullcontext(self._load_manifest(target_set_id, deployment_id))
        )
        try:
            with authorization as authorized_manifest:
                manifest = TargetManifest.model_validate(
                    authorized_manifest.model_dump(mode="json")
                )
                if manifest.target_set_id != target_set_id:
                    raise TargetValidationError(
                        "Registered manifest identity does not match request."
                    )
                request = RunRequest(
                    target_set_id=manifest.target_set_id,
                    deployment_id=deployment_id,
                    vuln_types=vuln_types,
                )
                available_types = {
                    target.vuln_type.value for target in manifest.targets
                }
                if not set(request.vuln_types).issubset(available_types):
                    raise TargetValidationError(
                        "The target manifest does not contain every requested vulnerability type."
                    )
                status = self._store.create_run(request)
            with self._store.pipeline_lock(status.scan_run_id) as lock:
                self._store.reconcile_orphaned_runs(lock)
                if on_run_created is not None:
                    on_run_created(status.scan_run_id)
                return self._run_locked(status, manifest)
        except (DeploymentRegistryError, ValidationError) as error:
            if status is None:
                raise TargetValidationError(
                    "Unable to validate the deployment manifest."
                ) from error
            return self._save_failure(
                status.scan_run_id,
                code="DEPLOYMENT_AUTHORIZATION_FAILED",
                message="Deployment authorization failed.",
                retryable=False,
            )
        except RunAlreadyActiveError:
            if status is None:
                raise
            self._save_failure(
                status.scan_run_id,
                code="RUN_ALREADY_ACTIVE",
                message="Another pipeline run is already active.",
                retryable=True,
            )
            raise
        except _PipelineFailure as error:
            if status is None:
                raise
            return self._save_failure(
                status.scan_run_id,
                code=error.code,
                message=error.message,
                retryable=error.retryable,
            )
        except Exception:
            if status is None:
                raise
            return self._save_failure(
                status.scan_run_id,
                code="PIPELINE_CRASHED",
                message="Pipeline execution failed.",
                retryable=True,
            )

    def _load_manifest(self, target_set_id: str, deployment_id: str) -> TargetManifest:
        try:
            manifest = self._manifest_resolver(deployment_id)
            validated = TargetManifest.model_validate(manifest.model_dump(mode="json"))
            if validated.target_set_id != target_set_id:
                raise ValueError("Registered manifest identity does not match request.")
            return validated
        except (
            TargetRegistryError,
            DeploymentRegistryError,
            ValidationError,
            OSError,
            TypeError,
            ValueError,
        ) as error:
            raise TargetValidationError(
                "Unable to validate the target manifest."
            ) from error

    def _run_locked(
        self, initial_status: RunStatusDocument, manifest: TargetManifest
    ) -> RunStatusDocument:
        status = self._update(
            initial_status,
            stage=ExecutionStage.VALIDATING_TARGET,
            progress=Progress(completed=0, total=0),
        )
        findings: list[RawFinding] = []

        for vuln_type, stage, scanner in (
            ("XSS", ExecutionStage.SCANNING_XSS, self._xss_scanner),
            ("SQLI", ExecutionStage.SCANNING_SQLI, self._sqli_scanner),
        ):
            if vuln_type not in status.requested_vuln_types:
                continue
            status = self._update(
                status, stage=stage, progress=Progress(completed=0, total=0)
            )
            target_cases = [
                target
                for target in manifest.targets
                if target.vuln_type.value == vuln_type
            ]
            context = ScanContext(
                scan_run_id=status.scan_run_id,
                base_url=manifest.base_url,
                request_policy=manifest.request_policy,
                responses_dir=self._store.responses_dir(status.scan_run_id),
                resolve_auth_profile=self._auth_profile_resolver,
            )
            results = scanner(
                target_cases,
                context,
                self._progress_callback(status.scan_run_id, stage),
            )
            try:
                if not isinstance(results, list):
                    raise TypeError("Scanner did not return a finding list.")
                validated = [RawFinding.model_validate(item) for item in results]
                if any(finding.vuln_type.value != vuln_type for finding in validated):
                    raise ValueError("Scanner returned an unexpected finding type.")
                self._validate_scanner_coverage(target_cases, validated)
            except (TypeError, ValueError, ValidationError) as error:
                raise _PipelineFailure(
                    "SCANNER_CONTRACT_FAILED",
                    "A scanner returned incomplete or invalid results.",
                    retryable=False,
                ) from error
            findings.extend(validated)
            status = self._store.load_status(status.scan_run_id)

        raw_status = self._raw_status(findings)
        raw_run = RawRun(
            schema_version="1.0",
            scan_run_id=status.scan_run_id,
            target_set_id=manifest.target_set_id,
            started_at=status.started_at,
            completed_at=self._now(),
            status=raw_status,
            findings=findings,
        )
        status = self._update(
            status,
            stage=ExecutionStage.PUBLISHING_RAW,
            progress=Progress(completed=0, total=0),
        )
        try:
            raw_path = self._store.publish_raw(raw_run)
        except Exception as error:
            raise _PipelineFailure(
                "RAW_PUBLISH_FAILED", "Unable to publish raw scan results."
            ) from error
        status = self._update(status, raw_result_path=raw_path)

        if raw_status is RunStatus.FAILED:
            return self._save_failure(
                status.scan_run_id,
                code="PIPELINE_CRASHED",
                message="All requested scans failed.",
                retryable=True,
            )

        status = self._update(
            status,
            stage=ExecutionStage.AI_TRIAGE,
            progress=Progress(completed=0, total=0),
        )
        try:
            processed = ProcessedRun.model_validate(self._triage(raw_run))
            self._validate_lineage(raw_run, processed)
        except Exception as error:
            raise _PipelineFailure(
                "PROCESSED_PUBLISH_FAILED", "Unable to publish processed scan results."
            ) from error
        status = self._update(
            status,
            stage=ExecutionStage.PUBLISHING_RESULT,
            progress=Progress(completed=0, total=0),
        )
        try:
            processed_path = self._store.publish_processed(processed)
        except Exception as error:
            raise _PipelineFailure(
                "PROCESSED_PUBLISH_FAILED", "Unable to publish processed scan results."
            ) from error
        terminal = (
            ExecutionStatus.COMPLETED
            if processed.status is RunStatus.COMPLETED
            else ExecutionStatus.PARTIAL
        )
        return self._terminal(
            status,
            terminal,
            raw_result_path=raw_path,
            processed_result_path=processed_path,
        )

    @staticmethod
    def _validate_scanner_coverage(
        targets: list[TargetCase], findings: list[RawFinding]
    ) -> None:
        target_ids = {target.case_id for target in targets}
        covered: set[str] = set()
        for finding in findings:
            matches = {
                target_id
                for target_id in target_ids
                if finding.case_id == target_id
                or finding.case_id.startswith(f"{target_id}::")
            }
            if len(matches) != 1:
                raise ValueError(
                    "Scanner returned a finding for an unknown target case."
                )
            covered.update(matches)
        if covered != target_ids:
            raise ValueError("Scanner omitted one or more requested target cases.")

    @staticmethod
    def _raw_status(findings: list[RawFinding]) -> RunStatus:
        completed = sum(
            finding.scan.status.value == "COMPLETED" for finding in findings
        )
        if completed == 0:
            return RunStatus.FAILED
        if completed == len(findings):
            return RunStatus.COMPLETED
        return RunStatus.PARTIAL

    def _progress_callback(
        self, scan_run_id: str, stage: ExecutionStage
    ) -> ProgressCallback:
        def on_progress(completed: int, total: int) -> None:
            progress = Progress(completed=completed, total=total)
            current = self._store.load_status(scan_run_id)
            if current.stage is not stage:
                raise ValueError("Scanner reported progress outside its active stage.")
            if (
                progress.completed < current.progress.completed
                or progress.total < current.progress.total
            ):
                raise ValueError("Scanner progress moved backwards.")
            self._update(current, progress=progress)

        return on_progress

    @staticmethod
    def _validate_lineage(raw: RawRun, processed: ProcessedRun) -> None:
        if (
            processed.scan_run_id != raw.scan_run_id
            or processed.target_set_id != raw.target_set_id
        ):
            raise ValueError("Processed run does not match raw run identity.")
        raw_by_id = {finding.finding_id: finding for finding in raw.findings}
        processed_by_id = {
            finding.finding_id: finding for finding in processed.findings
        }
        if set(raw_by_id) != set(processed_by_id):
            raise ValueError("Processed findings do not match raw findings.")
        for finding_id, raw_finding in raw_by_id.items():
            processed_finding: ProcessedFinding = processed_by_id[finding_id]
            if (
                processed_finding.case_id != raw_finding.case_id
                or processed_finding.vuln_type != raw_finding.vuln_type
                or processed_finding.scanned_at != raw_finding.scanned_at
                or processed_finding.scan != raw_finding.scan
            ):
                raise ValueError(
                    "Processed finding lineage does not match raw finding."
                )

    def _update(
        self, status: RunStatusDocument, **changes: object
    ) -> RunStatusDocument:
        updated_at = self._now_after(status.updated_at)
        updated = status.model_copy(
            update={
                **changes,
                "status": ExecutionStatus.RUNNING,
                "updated_at": updated_at,
            }
        )
        self._store.save_status(updated)
        return updated

    def _terminal(
        self, status: RunStatusDocument, terminal: ExecutionStatus, **changes: object
    ) -> RunStatusDocument:
        now = self._now_after(status.updated_at)
        result = status.model_copy(
            update={
                "status": terminal,
                "stage": None,
                "updated_at": now,
                "completed_at": now,
                "error": None,
                **changes,
            }
        )
        self._store.save_status(result)
        return result

    def _save_failure(
        self, scan_run_id: str, *, code: str, message: str, retryable: bool
    ) -> RunStatusDocument:
        status = self._store.load_status(scan_run_id)
        if status.status in {
            ExecutionStatus.COMPLETED,
            ExecutionStatus.PARTIAL,
            ExecutionStatus.FAILED,
        }:
            return status
        return self._terminal(
            status,
            ExecutionStatus.FAILED,
            error=RunError(code=code, message=message, retryable=retryable),
        )

    @staticmethod
    def _now() -> datetime:
        return datetime.now().astimezone()

    def _now_after(self, previous: datetime) -> datetime:
        now = self._now()
        return max(now, previous)
