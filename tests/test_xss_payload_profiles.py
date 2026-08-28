"""Tests for reviewed, version-controlled XSS payload profiles."""

import json

import pytest

from scanners.payload_profiles import (
    PayloadProfileInvalidError,
    PayloadProfileMissingError,
    load_payload_profile,
)


def _write_profile(tmp_path, file_profile="xss-v1", **overrides):
    payload_profile = {
        "profile": file_profile,
        "version": "1.0",
        "source": "reviewed-static",
        "model": None,
        "items": [
            {
                "payload_case_id": "script-alert-basic",
                "payload": "<script>alert(1)</script>",
            },
            {"payload_case_id": "control-plain-text", "payload": "plain text"},
        ],
    }
    payload_profile.update(overrides)
    path = tmp_path / f"{file_profile}.json"
    path.write_text(json.dumps(payload_profile), encoding="utf-8")
    return tmp_path


def test_checked_in_xss_v1_loads_in_reviewed_order():
    expected = [
        ("script-alert-basic", "<script>alert(1)</script>"),
        ("img-onerror-basic", "<img src=x onerror=alert(1)>"),
        ("svg-onload-basic", "<svg onload=alert(1)>"),
        ("quote-breakout-img-onerror", '"><img src=x onerror=alert(1)>'),
        ("control-plain-search-text", "normal-search-text"),
        ("control-html-escaped-text", "safe &amp; harmless"),
    ]

    assert load_payload_profile("xss-v1") == expected


def test_manifest_reruns_preserve_checked_in_payload_identities_and_order():
    first_run = load_payload_profile("xss-v1")
    second_run = load_payload_profile("xss-v1")

    assert second_run == first_run


@pytest.mark.parametrize(
    ("profile", "profile_data"),
    [
        ("../xss-v1", None),
        ("xss-v1", {"items": []}),
        ("xss-v1", {"version": "2.0"}),
        ("xss-v1", {"profile": "different-profile"}),
        (
            "xss-v1",
            {
                "items": [
                    {"payload_case_id": "duplicate-id", "payload": "one"},
                    {"payload_case_id": "duplicate-id", "payload": "two"},
                ]
            },
        ),
        (
            "xss-v1",
            {
                "items": [
                    {"payload_case_id": "first-id", "payload": "duplicate"},
                    {"payload_case_id": "second-id", "payload": "duplicate"},
                ]
            },
        ),
        ("xss-v1", {"items": [{"payload_case_id": "Invalid ID", "payload": "value"}]}),
        ("xss-v1", {"items": [{"payload_case_id": "empty-value", "payload": ""}]}),
    ],
)
def test_loader_rejects_invalid_profile_content(tmp_path, profile, profile_data):
    if profile_data is not None:
        _write_profile(tmp_path, **profile_data)

    with pytest.raises(PayloadProfileInvalidError):
        load_payload_profile(profile, tmp_path)


def test_loader_distinguishes_missing_profile_from_invalid_profile(tmp_path):
    with pytest.raises(PayloadProfileMissingError):
        load_payload_profile("xss-v1", tmp_path)

    _write_profile(tmp_path, unexpected="field")
    with pytest.raises(PayloadProfileInvalidError):
        load_payload_profile("xss-v1", tmp_path)
