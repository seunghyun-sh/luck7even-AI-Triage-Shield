"""Tests for verified deployment registration and resolution."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

import orchestration.deployment_registry as registry
from orchestration.deployment_registry import (
    DeploymentDescriptor,
    DeploymentRegistryError,
    RegisteredDeployment,
    list_registered_deployments,
    parse_deployment_descriptor,
    probe_deployment,
    register_deployment,
    resolve_deployment_manifest,
    update_deployment_lifecycle,
)


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers: dict[str, str] = {}
        self.closed = False

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    def iter_content(self, chunk_size: int):
        if isinstance(self._payload, Exception):
            raise self._payload
        if isinstance(self._payload, bytes):
            yield self._payload
            return
        yield json.dumps(self._payload).encode("utf-8")

    def close(self) -> None:
        self.closed = True


def _descriptor(**changes: object) -> DeploymentDescriptor:
    payload = {
        "deployment_id": "local-lab-one",
        "display_name": "Local lab",
        "target_set_id": "local-lab-v1",
        "service": "training-app",
        "base_url": "http://127.0.0.1:5000",
        "database_engine": "sqlite",
        "deployment_version": "1.0.0",
        "lifecycle": "ACTIVE",
    }
    payload.update(changes)
    return DeploymentDescriptor.model_validate(payload)


def _identity(descriptor: DeploymentDescriptor) -> dict[str, str]:
    return {
        "status": "ok",
        "target_set_id": descriptor.target_set_id,
        "service": descriptor.service,
        "database_engine": descriptor.database_engine,
        "deployment_version": descriptor.deployment_version,
    }


def test_parse_rejects_malformed_json_and_unsafe_url() -> None:
    with pytest.raises(DeploymentRegistryError, match="not valid JSON"):
        parse_deployment_descriptor("{")

    with pytest.raises(DeploymentRegistryError, match="invalid"):
        parse_deployment_descriptor(
            json.dumps(_descriptor().model_dump() | {"base_url": "https://user@host/"})
        )

    with pytest.raises(DeploymentRegistryError, match="invalid"):
        parse_deployment_descriptor(
            json.dumps(
                _descriptor().model_dump() | {"base_url": "http://169.254.169.254"}
            )
        )

    for unsafe_url in (
        "http://127.0.0.1:5000?",
        "http://127.0.0.1:5000#",
        "https://deployment.example",
    ):
        with pytest.raises(DeploymentRegistryError, match="invalid"):
            parse_deployment_descriptor(
                json.dumps(_descriptor().model_dump() | {"base_url": unsafe_url})
            )


def test_probe_uses_exact_health_url_without_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor(base_url="https://127.0.0.1/")
    observed: dict[str, object] = {}

    def fake_get(url: str, **kwargs: object) -> _Response:
        observed["url"] = url
        observed.update(kwargs)
        return _Response(200, _identity(descriptor))

    monkeypatch.setattr(registry.requests, "get", fake_get)

    registered = probe_deployment(descriptor)

    assert observed == {
        "url": "https://127.0.0.1/health",
        "timeout": (2.0, 2.0),
        "allow_redirects": False,
        "stream": True,
    }
    assert registered.verified_at.tzinfo is not None


def test_probe_rejects_redirect_and_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor()
    monkeypatch.setattr(
        registry.requests, "get", lambda *args, **kwargs: _Response(302, {})
    )
    with pytest.raises(DeploymentRegistryError, match="verification failed"):
        probe_deployment(descriptor)

    monkeypatch.setattr(
        registry.requests,
        "get",
        lambda *args, **kwargs: _Response(
            200, _identity(descriptor) | {"service": "other"}
        ),
    )
    with pytest.raises(DeploymentRegistryError, match="identity does not match"):
        probe_deployment(descriptor)

    monkeypatch.setattr(
        registry.requests,
        "get",
        lambda *args, **kwargs: _Response(
            200,
            _identity(descriptor) | {"unexpected": "value"},
        ),
    )
    with pytest.raises(DeploymentRegistryError, match="identity does not match"):
        probe_deployment(descriptor)


def test_probe_rejects_oversized_health_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        registry.requests,
        "get",
        lambda *args, **kwargs: _Response(
            200,
            b"x" * (registry.MAX_HEALTH_RESPONSE_BYTES + 1),
        ),
    )

    with pytest.raises(DeploymentRegistryError, match="verification failed"):
        probe_deployment(_descriptor())


def test_probe_enforces_total_wall_clock_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_get(*args: object, **kwargs: object) -> _Response:
        time.sleep(0.2)
        return _Response(200, _identity(_descriptor()))

    monkeypatch.setattr(registry.requests, "get", slow_get)
    started = time.monotonic()

    with pytest.raises(DeploymentRegistryError, match="timed out"):
        probe_deployment(_descriptor(), timeout_seconds=0.02)

    assert time.monotonic() - started < 0.15
    with pytest.raises(DeploymentRegistryError, match="still in progress"):
        probe_deployment(_descriptor(), timeout_seconds=0.02)
    time.sleep(0.22)


def test_register_rejects_descriptor_mutation_for_existing_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "deployments.local.json"
    descriptor = _descriptor()

    def fake_probe(value: DeploymentDescriptor) -> RegisteredDeployment:
        return RegisteredDeployment(
            **value.model_dump(), verified_at=datetime.now(timezone.utc)
        )

    monkeypatch.setattr(registry, "probe_deployment", fake_probe)
    register_deployment(descriptor, path)

    with pytest.raises(DeploymentRegistryError, match="new deployment identifier"):
        register_deployment(_descriptor(display_name="Changed"), path)


def test_register_persists_registry_via_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "deployments.local.json"
    descriptor = _descriptor()
    replaced: list[tuple[Path, Path]] = []
    original_replace = registry.os.replace

    monkeypatch.setattr(
        registry,
        "probe_deployment",
        lambda value: RegisteredDeployment(
            **value.model_dump(), verified_at=datetime.now(timezone.utc)
        ),
    )

    def tracking_replace(
        source: str | Path,
        destination: str | Path,
        **kwargs: object,
    ) -> None:
        replaced.append((Path(source), Path(destination)))
        original_replace(source, destination, **kwargs)

    monkeypatch.setattr(registry.os, "replace", tracking_replace)
    register_deployment(descriptor, path)

    assert replaced and replaced[0][0].name.startswith(".deployments-")
    assert replaced[0][1] == Path(path.name)
    assert [item.deployment_id for item in list_registered_deployments(path)] == [
        descriptor.deployment_id
    ]


def test_lifecycle_transition_preserves_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "deployments.local.json"
    descriptor = _descriptor()
    monkeypatch.setattr(
        registry,
        "probe_deployment",
        lambda value: RegisteredDeployment(
            **value.model_dump(),
            verified_at=datetime.now(timezone.utc),
        ),
    )
    register_deployment(descriptor, path)

    maintenance = update_deployment_lifecycle(
        descriptor.deployment_id,
        "MAINTENANCE",
        path,
    )
    retired = update_deployment_lifecycle(
        descriptor.deployment_id,
        "RETIRED",
        path,
    )

    assert maintenance.lifecycle == "MAINTENANCE"
    assert retired.lifecycle == "RETIRED"
    assert retired.base_url == descriptor.base_url
    with pytest.raises(DeploymentRegistryError, match="transition"):
        update_deployment_lifecycle(descriptor.deployment_id, "ACTIVE", path)


def test_registry_rejects_symlink_path(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text('{"schema_version":"1.0","deployments":[]}', encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(real)

    with pytest.raises(DeploymentRegistryError, match="not trusted"):
        list_registered_deployments(linked)


def test_resolve_overrides_only_trusted_manifest_base_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_config = (
        Path(__file__).resolve().parents[1] / "configs" / "targets.example.json"
    )
    manifest_path = tmp_path / "targets.json"
    manifest_path.write_text(
        source_config.read_text(encoding="utf-8"), encoding="utf-8"
    )
    target_registry_path = tmp_path / "target-registry.json"
    target_registry_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "targets": [
                    {
                        "target_set_id": "local-lab-v1",
                        "manifest": "targets.json",
                        "allowed_base_url": "http://127.0.0.1:5000",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    deployments_path = tmp_path / "deployments.local.json"
    deployment = RegisteredDeployment(
        **_descriptor(base_url="https://127.0.0.1").model_dump(),
        verified_at=datetime.now(timezone.utc),
    )
    deployments_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "deployments": [deployment.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        registry.requests,
        "get",
        lambda *args, **kwargs: _Response(200, _identity(deployment)),
    )
    manifest = resolve_deployment_manifest(
        deployment.deployment_id, deployments_path, target_registry_path
    )
    assert manifest.base_url == "https://127.0.0.1"
    assert manifest.target_set_id == deployment.target_set_id
    assert manifest.targets
