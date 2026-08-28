"""Checked-in XSS payload profile loader.

Runtime scanners only read reviewed, version-controlled profiles from
``configs/payload-profiles``. They never generate payloads or call an AI API.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

DEFAULT_PROFILE_ROOT = (
    Path(__file__).resolve().parents[1] / "configs" / "payload-profiles"
)
_PROFILE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]*$")
_PAYLOAD_CASE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]*$")


class PayloadProfileMissingError(RuntimeError):
    """Raised when a requested reviewed payload profile is not present."""


class PayloadProfileInvalidError(RuntimeError):
    """Raised when a reviewed payload profile does not meet the schema contract."""


def _invalid(profile: str, reason: str) -> PayloadProfileInvalidError:
    return PayloadProfileInvalidError(f"Invalid payload profile '{profile}': {reason}")


def load_payload_profile(
    profile: str, profiles_root: Path = DEFAULT_PROFILE_ROOT
) -> list[tuple[str, str]]:
    """Return ordered ``(payload_case_id, payload)`` entries from a reviewed profile."""
    if not isinstance(profile, str) or not _PROFILE_IDENTIFIER.fullmatch(profile):
        raise _invalid(str(profile), "profile identifier is not valid")

    root = profiles_root.resolve()
    profile_path = (root / f"{profile}.json").resolve()
    if root not in profile_path.parents:
        raise _invalid(profile, "profile path escapes the profile root")
    if not profile_path.is_file():
        raise PayloadProfileMissingError(
            f"Reviewed payload profile '{profile}' was not found."
        )

    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _invalid(profile, "file is not valid JSON") from error

    required_keys = {"profile", "version", "source", "model", "items"}
    if not isinstance(data, dict) or set(data) != required_keys:
        raise _invalid(profile, "JSON object has an unsupported shape")
    if data["profile"] != profile:
        raise _invalid(profile, "profile name does not match its identifier")
    if data["version"] != "1.0":
        raise _invalid(profile, "unsupported version")
    if data["source"] != "reviewed-static" or data["model"] is not None:
        raise _invalid(profile, "must be a reviewed static profile without a model")
    if not isinstance(data["items"], list) or not data["items"]:
        raise _invalid(profile, "items must be a non-empty list")

    entries: list[tuple[str, str]] = []
    case_ids: set[str] = set()
    payloads: set[str] = set()
    for item in data["items"]:
        if not isinstance(item, dict) or set(item) != {"payload_case_id", "payload"}:
            raise _invalid(profile, "item has an unsupported shape")
        case_id = item["payload_case_id"]
        payload = item["payload"]
        if not isinstance(case_id, str) or not _PAYLOAD_CASE_IDENTIFIER.fullmatch(
            case_id
        ):
            raise _invalid(profile, "item has an invalid payload_case_id")
        if not isinstance(payload, str) or not payload:
            raise _invalid(profile, "item has an empty payload")
        if case_id in case_ids:
            raise _invalid(profile, "duplicate payload_case_id")
        if payload in payloads:
            raise _invalid(profile, "duplicate payload")
        case_ids.add(case_id)
        payloads.add(payload)
        entries.append((case_id, payload))
    return entries
