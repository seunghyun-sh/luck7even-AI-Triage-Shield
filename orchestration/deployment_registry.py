"""Verified deployment registry for authorized diagnostic environments."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from typing import IO, Literal
from urllib.parse import urlsplit

import requests
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
)

from analysis.models import TargetManifest

from .models import IDENTIFIER_PATTERN
from .target_registry import (
    DEFAULT_REGISTRY_PATH,
    TargetRegistryError,
    load_registered_target,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEPLOYMENTS_PATH = PROJECT_ROOT / "configs" / "deployments.local.json"
MAX_HEALTH_RESPONSE_BYTES = 16 * 1024
_PROBE_SLOT = BoundedSemaphore(value=1)


class DeploymentRegistryError(ValueError):
    """Raised when a deployment descriptor cannot be safely used."""


class _DeploymentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class DeploymentDescriptor(_DeploymentModel):
    schema_version: Literal["1.0"] = "1.0"
    deployment_id: StrictStr = Field(min_length=1)
    display_name: StrictStr = Field(min_length=1)
    target_set_id: StrictStr = Field(min_length=1)
    service: StrictStr = Field(min_length=1)
    base_url: StrictStr = Field(min_length=1)
    health_path: Literal["/health"] = "/health"
    database_engine: Literal["sqlite", "mysql"]
    deployment_version: StrictStr = Field(min_length=1)
    lifecycle: Literal["TEMPORARY", "ACTIVE", "MAINTENANCE", "RETIRED"]

    @field_validator("deployment_id", "target_set_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("must be a valid identifier")
        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("must have a valid port") from error
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or any(character.isspace() or ord(character) < 32 for character in value)
            or parsed.username is not None
            or parsed.password is not None
            or "?" in value
            or "#" in value
            or parsed.path not in {"", "/"}
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("must be an http or https origin without userinfo")
        try:
            address = ip_address(parsed.hostname)
        except ValueError as error:
            raise ValueError("must use a literal IP address") from error
        if not address.is_global and not address.is_loopback:
            raise ValueError("must use a public or loopback IP address")
        if (
            address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError("must not target a reserved network address")
        return value


class RegisteredDeployment(DeploymentDescriptor):
    verified_at: datetime

    @field_validator("verified_at")
    @classmethod
    def validate_verified_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("must include a timezone offset")
        return value


def _parse_descriptor_payload(payload: object) -> DeploymentDescriptor:
    if not isinstance(payload, dict):
        raise DeploymentRegistryError("Deployment descriptor has an invalid format.")
    try:
        return DeploymentDescriptor.model_validate(payload)
    except ValidationError as error:
        raise DeploymentRegistryError("Deployment descriptor is invalid.") from error


def parse_deployment_descriptor(
    source: bytes | str | Path | IO[bytes] | IO[str],
) -> DeploymentDescriptor:
    """Parse one strict JSON deployment descriptor without exposing its contents."""

    try:
        if isinstance(source, Path):
            content: bytes | str = source.read_bytes()
        elif isinstance(source, (bytes, str)):
            content = source
        elif hasattr(source, "read"):
            content = source.read()
        else:
            raise TypeError
        if not isinstance(content, (bytes, str)):
            raise TypeError
        payload = json.loads(content)
    except (OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeploymentRegistryError(
            "Deployment descriptor is not valid JSON."
        ) from error
    return _parse_descriptor_payload(payload)


def _health_url(descriptor: DeploymentDescriptor) -> str:
    return f"{descriptor.base_url.rstrip('/')}{descriptor.health_path}"


def _probe_deployment_blocking(
    descriptor: DeploymentDescriptor, timeout_seconds: float = 5.0
) -> RegisteredDeployment:
    """Perform one bounded-size deployment identity request."""

    if not isinstance(descriptor, DeploymentDescriptor):
        raise DeploymentRegistryError("Deployment descriptor is invalid.")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise DeploymentRegistryError("Deployment probe timeout is invalid.")
    request_timeout = min(float(timeout_seconds), 2.0)
    try:
        response = requests.get(
            _health_url(descriptor),
            timeout=(request_timeout, request_timeout),
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException as error:
        raise DeploymentRegistryError(
            "Deployment health verification failed."
        ) from error
    try:
        if response.status_code != 200 or response.is_redirect:
            raise DeploymentRegistryError("Deployment health verification failed.")
        declared_length = response.headers.get("Content-Length")
        if (
            declared_length is not None
            and int(declared_length) > MAX_HEALTH_RESPONSE_BYTES
        ):
            raise DeploymentRegistryError("Deployment health response is too large.")
        body = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            body.extend(chunk)
            if len(body) > MAX_HEALTH_RESPONSE_BYTES:
                raise DeploymentRegistryError(
                    "Deployment health response is too large."
                )
        identity = json.loads(bytes(body))
    except (OSError, TypeError, ValueError, requests.RequestException) as error:
        raise DeploymentRegistryError(
            "Deployment health verification failed."
        ) from error
    finally:
        response.close()
    expected = {
        "status": "ok",
        "target_set_id": descriptor.target_set_id,
        "service": descriptor.service,
        "database_engine": descriptor.database_engine,
        "deployment_version": descriptor.deployment_version,
    }
    if identity != expected:
        raise DeploymentRegistryError("Deployment health identity does not match.")
    return RegisteredDeployment(
        **descriptor.model_dump(), verified_at=datetime.now(timezone.utc)
    )


def probe_deployment(
    descriptor: DeploymentDescriptor,
    timeout_seconds: float = 5.0,
) -> RegisteredDeployment:
    """Verify health identity under a hard caller-visible wall-clock deadline."""

    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise DeploymentRegistryError("Deployment probe timeout is invalid.")
    if not _PROBE_SLOT.acquire(blocking=False):
        raise DeploymentRegistryError(
            "Another deployment health verification is still in progress."
        )
    results: Queue[tuple[bool, object]] = Queue(maxsize=1)

    def worker() -> None:
        try:
            results.put((True, _probe_deployment_blocking(descriptor, timeout_seconds)))
        except Exception as error:  # noqa: BLE001 - worker boundary normalizes failures
            results.put((False, error))
        finally:
            _PROBE_SLOT.release()

    try:
        thread = Thread(target=worker, name="deployment-health-probe", daemon=True)
        thread.start()
    except Exception as error:
        _PROBE_SLOT.release()
        raise DeploymentRegistryError(
            "Deployment health verification failed."
        ) from error
    thread.join(float(timeout_seconds))
    if thread.is_alive():
        raise DeploymentRegistryError("Deployment health verification timed out.")
    try:
        succeeded, result = results.get_nowait()
    except Empty as error:
        raise DeploymentRegistryError(
            "Deployment health verification failed."
        ) from error
    if not succeeded:
        if isinstance(result, DeploymentRegistryError):
            raise result
        raise DeploymentRegistryError(
            "Deployment health verification failed."
        ) from result
    if not isinstance(result, RegisteredDeployment):
        raise DeploymentRegistryError("Deployment health verification failed.")
    return result


def _load_registered_payload(
    path: Path,
    parent_fd: int | None = None,
) -> list[RegisteredDeployment]:
    try:
        if parent_fd is None:
            content = path.read_text(encoding="utf-8")
        else:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                content = handle.read()
        payload = json.loads(content)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeploymentRegistryError(
            "Unable to load the deployment registry."
        ) from error
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != "1.0"
        or not isinstance(payload.get("deployments"), list)
    ):
        raise DeploymentRegistryError("Deployment registry has an invalid format.")
    deployments: list[RegisteredDeployment] = []
    seen_ids: set[str] = set()
    for entry in payload["deployments"]:
        if not isinstance(entry, dict):
            raise DeploymentRegistryError("Deployment registry has an invalid entry.")
        try:
            deployment = RegisteredDeployment.model_validate_json(json.dumps(entry))
        except ValidationError as error:
            raise DeploymentRegistryError(
                "Deployment registry has an invalid entry."
            ) from error
        if deployment.deployment_id in seen_ids:
            raise DeploymentRegistryError(
                "Deployment registry has duplicate identifiers."
            )
        seen_ids.add(deployment.deployment_id)
        deployments.append(deployment)
    return deployments


def _validate_registry_path(path: Path) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise DeploymentRegistryError("Deployment registry path is not trusted.")
    if path == DEFAULT_DEPLOYMENTS_PATH:
        expected_parent = PROJECT_ROOT / "configs"
        if (
            expected_parent.is_symlink()
            or path.parent.resolve() != expected_parent.resolve()
        ):
            raise DeploymentRegistryError("Deployment registry path is not trusted.")


def _open_registry_parent(path: Path) -> int:
    _validate_registry_path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path.parent, flags)
    except OSError as error:
        raise DeploymentRegistryError(
            "Deployment registry path is not trusted."
        ) from error


def list_registered_deployments(
    path: Path = DEFAULT_DEPLOYMENTS_PATH,
) -> list[RegisteredDeployment]:
    """Return registered deployments, treating an absent local registry as empty."""

    registry_path = Path(path)
    if not registry_path.parent.exists():
        return []
    parent_fd = _open_registry_parent(registry_path)
    try:
        return _list_registered_at(registry_path, parent_fd)
    finally:
        os.close(parent_fd)


def _list_registered_at(path: Path, parent_fd: int) -> list[RegisteredDeployment]:
    try:
        metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise DeploymentRegistryError(
            "Unable to load the deployment registry."
        ) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise DeploymentRegistryError("Deployment registry path is not trusted.")
    return _load_registered_payload(path, parent_fd)


def _persist_deployments(
    path: Path,
    deployments: list[RegisteredDeployment],
    parent_fd: int,
) -> None:
    payload = {
        "schema_version": "1.0",
        "deployments": [
            deployment.model_dump(mode="json") for deployment in deployments
        ],
    }
    temporary_name = f".deployments-{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        with os.fdopen(descriptor, mode="w", encoding="utf-8") as handle:
            descriptor = None
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except OSError as error:
        raise DeploymentRegistryError(
            "Unable to save the deployment registry."
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


@contextmanager
def _registry_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_fd = _open_registry_parent(path)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(
            ".deployments.lock",
            flags,
            0o600,
            dir_fd=parent_fd,
        )
    except OSError as error:
        os.close(parent_fd)
        raise DeploymentRegistryError(
            "Unable to lock the deployment registry."
        ) from error
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield parent_fd
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            os.close(parent_fd)


def register_deployment(
    descriptor: DeploymentDescriptor, path: Path = DEFAULT_DEPLOYMENTS_PATH
) -> RegisteredDeployment:
    """Probe and atomically persist a verified deployment descriptor."""

    registered = probe_deployment(descriptor)
    registry_path = Path(path)
    with _registry_lock(registry_path) as parent_fd:
        existing = _list_registered_at(registry_path, parent_fd)
        updated: list[RegisteredDeployment] = []
        for deployment in existing:
            if deployment.deployment_id != registered.deployment_id:
                updated.append(deployment)
                continue
            if deployment.model_dump(exclude={"verified_at"}) != registered.model_dump(
                exclude={"verified_at"}
            ):
                raise DeploymentRegistryError(
                    "A changed deployment descriptor requires a new deployment identifier."
                )
        updated.append(registered)
        _persist_deployments(registry_path, updated, parent_fd)
    return registered


def update_deployment_lifecycle(
    deployment_id: str,
    lifecycle: Literal["ACTIVE", "MAINTENANCE", "RETIRED"],
    path: Path = DEFAULT_DEPLOYMENTS_PATH,
) -> RegisteredDeployment:
    """Apply an explicit lifecycle transition without changing deployment identity."""

    transitions = {
        "TEMPORARY": {"ACTIVE", "MAINTENANCE", "RETIRED"},
        "ACTIVE": {"MAINTENANCE", "RETIRED"},
        "MAINTENANCE": {"ACTIVE", "RETIRED"},
        "RETIRED": set(),
    }
    registry_path = Path(path)
    with _registry_lock(registry_path) as parent_fd:
        deployments = _list_registered_at(registry_path, parent_fd)
        matches = [
            deployment
            for deployment in deployments
            if deployment.deployment_id == deployment_id
        ]
        if len(matches) != 1:
            raise DeploymentRegistryError("Deployment is not registered.")
        current = matches[0]
        if lifecycle not in transitions[current.lifecycle]:
            raise DeploymentRegistryError("Deployment lifecycle transition is invalid.")
        snapshot = current

    candidate = snapshot.model_copy(update={"lifecycle": lifecycle})
    if lifecycle == "ACTIVE":
        candidate = probe_deployment(
            DeploymentDescriptor.model_validate(
                candidate.model_dump(exclude={"verified_at"})
            )
        )

    with _registry_lock(registry_path) as parent_fd:
        deployments = _list_registered_at(registry_path, parent_fd)
        matches = [
            deployment
            for deployment in deployments
            if deployment.deployment_id == deployment_id
        ]
        if len(matches) != 1 or matches[0] != snapshot:
            raise DeploymentRegistryError(
                "Deployment changed during lifecycle transition."
            )
        updated = [
            candidate if deployment.deployment_id == deployment_id else deployment
            for deployment in deployments
        ]
        _persist_deployments(registry_path, updated, parent_fd)
        return candidate


def resolve_deployment_manifest(
    deployment_id: str,
    deployments_path: Path = DEFAULT_DEPLOYMENTS_PATH,
    target_registry_path: Path = DEFAULT_REGISTRY_PATH,
) -> TargetManifest:
    """Resolve an eligible deployment against its trusted target manifest."""

    if not isinstance(deployment_id, str) or not IDENTIFIER_PATTERN.fullmatch(
        deployment_id
    ):
        raise DeploymentRegistryError("Deployment identifier is invalid.")
    matches = [
        deployment
        for deployment in list_registered_deployments(deployments_path)
        if deployment.deployment_id == deployment_id
    ]
    if len(matches) != 1:
        raise DeploymentRegistryError("Deployment is not registered.")
    deployment = matches[0]
    if deployment.lifecycle not in {"ACTIVE", "TEMPORARY"}:
        raise DeploymentRegistryError("Deployment is not eligible for diagnostics.")
    verified = probe_deployment(
        DeploymentDescriptor.model_validate(
            deployment.model_dump(exclude={"verified_at"})
        )
    )
    try:
        manifest = load_registered_target(
            verified.target_set_id, Path(target_registry_path)
        )
    except TargetRegistryError as error:
        raise DeploymentRegistryError(
            "Deployment target set is not registered."
        ) from error
    if manifest.target_set_id != verified.target_set_id:
        raise DeploymentRegistryError("Deployment target set is not registered.")
    return manifest.model_copy(update={"base_url": verified.base_url})


@contextmanager
def deployment_manifest_lease(
    deployment_id: str,
    deployments_path: Path = DEFAULT_DEPLOYMENTS_PATH,
    target_registry_path: Path = DEFAULT_REGISTRY_PATH,
):
    """Hold deployment eligibility stable while the caller creates its run."""

    manifest = resolve_deployment_manifest(
        deployment_id,
        deployments_path,
        target_registry_path,
    )
    registry_path = Path(deployments_path)
    with _registry_lock(registry_path) as parent_fd:
        matches = [
            deployment
            for deployment in _list_registered_at(registry_path, parent_fd)
            if deployment.deployment_id == deployment_id
        ]
        if (
            len(matches) != 1
            or matches[0].lifecycle not in {"ACTIVE", "TEMPORARY"}
            or matches[0].target_set_id != manifest.target_set_id
            or matches[0].base_url != manifest.base_url
        ):
            raise DeploymentRegistryError(
                "Deployment authorization changed before execution."
            )
        yield manifest
