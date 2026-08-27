"""Trusted target-manifest registry used by the CLI and dashboard."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from analysis.models import TargetManifest

from .data_loader import ContractLoadError, load_target_manifest
from .models import IDENTIFIER_PATTERN

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY_PATH = PROJECT_ROOT / "configs" / "target-registry.json"


class TargetRegistryError(ValueError):
    """Raised when a registered target cannot be resolved safely."""


@dataclass(frozen=True)
class RegisteredTarget:
    target_set_id: str
    manifest_path: Path
    manifest: TargetManifest


def _safe_manifest_path(config_dir: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise TargetRegistryError("Target registry contains an invalid manifest path.")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in posix.parts)
        or any(part in {"", ".", ".."} for part in windows.parts)
    ):
        raise TargetRegistryError("Target registry contains an unsafe manifest path.")
    candidate = (config_dir / value).resolve()
    try:
        candidate.relative_to(config_dir.resolve())
    except ValueError as error:
        raise TargetRegistryError(
            "Target registry contains an unsafe manifest path."
        ) from error
    return candidate


def _load_registry_payload(registry_path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TargetRegistryError("Unable to load the target registry.") from error
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != "1.0"
        or not isinstance(payload.get("targets"), list)
    ):
        raise TargetRegistryError("Target registry has an invalid format.")
    return payload["targets"]


def list_registered_targets(
    registry_path: Path = DEFAULT_REGISTRY_PATH,
) -> list[RegisteredTarget]:
    """Load every trusted manifest and revalidate its registered identity and origin."""

    config_dir = registry_path.resolve().parent
    registered: list[RegisteredTarget] = []
    seen_ids: set[str] = set()
    for entry in _load_registry_payload(registry_path):
        if not isinstance(entry, dict):
            raise TargetRegistryError("Target registry has an invalid entry.")
        target_set_id = entry.get("target_set_id")
        allowed_base_url = entry.get("allowed_base_url")
        if (
            not isinstance(target_set_id, str)
            or not IDENTIFIER_PATTERN.fullmatch(target_set_id)
            or target_set_id in seen_ids
            or not isinstance(allowed_base_url, str)
        ):
            raise TargetRegistryError("Target registry has an invalid entry.")
        manifest_path = _safe_manifest_path(config_dir, entry.get("manifest"))
        try:
            manifest = load_target_manifest(manifest_path)
        except (ContractLoadError, OSError, TypeError, ValueError) as error:
            raise TargetRegistryError(
                "Unable to load a registered target manifest."
            ) from error
        if (
            manifest.target_set_id != target_set_id
            or manifest.base_url != allowed_base_url
        ):
            raise TargetRegistryError(
                "Registered target identity or base URL does not match its allowlist."
            )
        seen_ids.add(target_set_id)
        registered.append(RegisteredTarget(target_set_id, manifest_path, manifest))
    return registered


def load_registered_target(
    target_set_id: str, registry_path: Path = DEFAULT_REGISTRY_PATH
) -> TargetManifest:
    """Resolve one authorized target set by stable ID."""

    if not isinstance(target_set_id, str) or not IDENTIFIER_PATTERN.fullmatch(
        target_set_id
    ):
        raise TargetRegistryError("Target set identifier is invalid.")
    matches = [
        target.manifest
        for target in list_registered_targets(registry_path)
        if target.target_set_id == target_set_id
    ]
    if len(matches) != 1:
        raise TargetRegistryError("Target set is not registered.")
    return matches[0]
