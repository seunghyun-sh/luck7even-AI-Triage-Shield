"""Regression contracts for evidence-grounded AI triage using fakes only."""

from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from openai import APIConnectionError, APITimeoutError, RateLimitError
from pydantic import ValidationError

from analysis.ai_triage import ProviderAnalysis, ProviderClaim, SQLiteCache, triage
from analysis.knowledge_base import KnowledgeBaseManifest
from analysis.models import AiClaimType, ProcessedRun, RawRun

NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


def raw_finding(
    *,
    case_id="case",
    finding_id="finding",
    vuln_type="XSS",
    label="SUSPECTED",
    status="COMPLETED",
    reason="reflected email admin@example.test token=topsecret eyJabc.def.ghi",
    evidence_summary="reflected in HTML",
    payload="<x>",
):
    failed = status == "FAILED"
    return {
        "case_id": case_id,
        "finding_id": finding_id,
        "scanned_at": NOW,
        "vuln_type": vuln_type,
        "scan": {
            "status": status,
            "request": {
                "url": "https://example.test/a?secret=x#fragment",
                "method": "GET",
                "input_location": "query",
                "parameter": "q",
                "payload": payload,
            },
            "response": {
                "http_status": None if failed else 200,
                "elapsed_ms": None if failed else 10,
                "baseline_elapsed_ms": None
                if failed
                else (5 if vuln_type == "SQLI" else None),
                "evidence_summary": None if failed else evidence_summary,
                "html_path": None,
            },
            "rule": {
                "label": None if failed else label,
                "reason": None if failed else reason,
            },
            "error": {"code": "SCAN", "message": "failed", "retryable": False}
            if failed
            else None,
        },
    }


def raw_run(*findings, status=None):
    findings = list(findings) or []
    status = status or (
        "FAILED"
        if not findings or all(f["scan"]["status"] == "FAILED" for f in findings)
        else "COMPLETED"
    )
    return RawRun.model_validate(
        {
            "schema_version": "1.0",
            "scan_run_id": "run",
            "target_set_id": "set",
            "started_at": NOW,
            "completed_at": NOW,
            "status": status,
            "findings": findings,
        }
    )


def kb(version="kb1", vuln_types=("XSS",)):
    return KnowledgeBaseManifest.model_validate(
        {
            "schema_version": "1.0",
            "knowledge_base_version": version,
            "vector_store_ids": ["vs_1"],
            "files": [
                {
                    "file_id": "file_1",
                    "source_id": "owasp",
                    "publisher": "OWASP",
                    "title": "Guide",
                    "version": "1",
                    "section": "S",
                    "canonical_url": "https://owasp.org/xss",
                    "document_sha256": "a" * 64,
                    "vuln_types": list(vuln_types),
                    "language": "en",
                }
            ],
        }
    )


class FakeResponses:
    def __init__(self, outcomes, parse_outcomes=None):
        self.outcomes = list(outcomes) if isinstance(outcomes, list) else [outcomes]
        self.parse_outcomes = (
            list(parse_outcomes)
            if isinstance(parse_outcomes, list)
            else ([parse_outcomes] if parse_outcomes is not None else None)
        )
        self.calls = []
        self.create_calls = []
        self.parse_calls = []
        self.last_created = None

    def create(self, **kwargs):
        self.calls.append(kwargs)
        self.create_calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        self.last_created = outcome
        return outcome

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        self.parse_calls.append(kwargs)
        outcome = (
            self.parse_outcomes.pop(0)
            if self.parse_outcomes is not None
            else self.last_created
        )
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, outcomes, parse_outcomes=None):
        self.responses = FakeResponses(outcomes, parse_outcomes)


def provider_response(claims, retrieved=("file_1",), cited=("file_1",)):
    return SimpleNamespace(
        output_parsed=ProviderAnalysis(claims=claims),
        status="completed",
        output=[
            SimpleNamespace(
                type="file_search_call",
                status="completed",
                results=[
                    SimpleNamespace(
                        file_id=x,
                        text=f"Official guidance for {x}",
                        filename=f"{x}.md",
                        score=0.9,
                    )
                    for x in retrieved
                ],
            ),
            SimpleNamespace(
                type="message",
                content=[
                    SimpleNamespace(
                        type="output_text",
                        annotations=[
                            SimpleNamespace(file_citation=SimpleNamespace(file_id=x))
                            for x in cited
                        ],
                    )
                ],
            ),
        ],
    )


def valid_claims(*, evidence_id="E1", reference_id="file_1"):
    return [
        ProviderClaim(
            claim_type=kind,
            text=kind.value,
            evidence_ids=[evidence_id],
            reference_file_ids=[]
            if kind is AiClaimType.OBSERVATION
            else [reference_id],
        )
        for kind in AiClaimType
    ]


def candidate(monkeypatch, client, run=None, manifest=None, **kwargs):
    monkeypatch.setenv("AI_TRIAGE_MODEL", "test-model")
    cache = kwargs.pop("cache", {})
    return triage(
        run or raw_run(raw_finding()),
        client=client,
        knowledge_base=manifest or kb(),
        cache=cache,
        now=lambda: NOW,
        **kwargs,
    )


def provider_error(error_type):
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    if error_type is APITimeoutError:
        return APITimeoutError(request=request)
    if error_type is APIConnectionError:
        return APIConnectionError(request=request)
    if error_type is RateLimitError:
        return RateLimitError(
            "rate limited",
            response=httpx.Response(429, request=request),
            body=None,
        )
    return ValueError("invalid tool output")


def test_mixed_scan_result_is_partial_and_failed_scan_is_not_requested(monkeypatch):
    client = FakeClient(provider_response(valid_claims()))
    result = candidate(
        monkeypatch,
        client,
        raw_run(
            raw_finding(),
            raw_finding(case_id="failed-case", finding_id="failed", status="FAILED"),
            status="PARTIAL",
        ),
    )
    assert result.status.value == "PARTIAL"
    failed = result.findings[1]
    assert (failed.ai.status.value, failed.ai.status_reason.value) == (
        "NOT_REQUESTED",
        "SCAN_FAILED",
    )
    assert len(client.responses.create_calls) == len(client.responses.parse_calls) == 1


def test_empty_and_all_failed_runs_are_failed_and_processed_11_requires_role():
    assert triage(raw_run(), cache={}).status.value == "FAILED"
    all_failed = triage(raw_run(raw_finding(status="FAILED")), cache={})
    assert all_failed.status.value == "FAILED"
    invalid = all_failed.model_dump(mode="json")
    invalid["findings"][0]["ai"]["role"] = None
    with pytest.raises(ValidationError):
        ProcessedRun.model_validate(invalid)


def test_completed_empty_retrieval_is_insufficient_even_with_a_citation(
    monkeypatch,
):
    result = candidate(
        monkeypatch, FakeClient(provider_response(valid_claims(), (), ("file_1",)))
    )
    assert result.findings[0].ai.grounding_status.value == "INSUFFICIENT"


def test_retrieved_and_cited_file_outside_manifest_is_reference_mismatch(monkeypatch):
    claims = valid_claims(reference_id="untrusted")
    result = candidate(
        monkeypatch,
        FakeClient(provider_response(claims, ("untrusted",), ("untrusted",))),
    )
    assert result.findings[0].ai.error.code == "AI_REFERENCE_MISMATCH"


def test_trusted_reference_for_wrong_vulnerability_is_reference_mismatch(monkeypatch):
    result = candidate(
        monkeypatch,
        FakeClient(provider_response(valid_claims())),
        manifest=kb(vuln_types=("SQLI",)),
    )
    assert result.findings[0].ai.error.code == "AI_REFERENCE_MISMATCH"


@pytest.mark.parametrize(
    "claims", [valid_claims(evidence_id="E99"), valid_claims()[:-1]]
)
def test_invalid_evidence_or_missing_claim_type_is_schema_invalid(monkeypatch, claims):
    result = candidate(monkeypatch, FakeClient(provider_response(claims)))
    assert result.findings[0].ai.error.code == "AI_SCHEMA_INVALID"


def test_duplicate_provider_ids_are_isolated_as_schema_invalid(monkeypatch):
    claims = valid_claims()
    claims[0].evidence_ids = ["E1", "E1"]

    result = candidate(monkeypatch, FakeClient(provider_response(claims)))

    assert result.findings[0].ai.error.code == "AI_SCHEMA_INVALID"


def test_timeout_retries_three_times_without_exposing_raw_message(monkeypatch):
    client = FakeClient([provider_error(APITimeoutError) for _ in range(3)])
    sleeps = []
    result = candidate(monkeypatch, client, sleeper=sleeps.append)
    ai = result.findings[0].ai
    assert len(client.responses.calls) == 3
    assert sleeps == [1, 2]
    assert (ai.error.code, ai.error.retryable) == ("AI_TIMEOUT", True)
    assert "Request timed out." not in ai.error.message


def test_synthesis_transient_retries_the_entire_two_step_flow(monkeypatch):
    retrieval = [provider_response(valid_claims()) for _ in range(2)]
    client = FakeClient(
        retrieval,
        [provider_error(APITimeoutError), provider_response(valid_claims())],
    )
    sleeps = []
    result = candidate(monkeypatch, client, sleeper=sleeps.append)
    assert result.findings[0].ai.grounding_status.value == "GROUNDED"
    assert len(client.responses.create_calls) == len(client.responses.parse_calls) == 2
    assert sleeps == [1]


def test_retry_after_is_capped_and_deadline_prevents_a_retry(monkeypatch):
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    rate_limited = RateLimitError(
        "rate limited",
        response=httpx.Response(429, headers={"retry-after": "99"}, request=request),
        body=None,
    )
    sleeps = []
    recovered = candidate(
        monkeypatch,
        FakeClient([rate_limited, provider_response(valid_claims())]),
        sleeper=sleeps.append,
    )
    assert sleeps == [10.0]
    assert recovered.findings[0].ai.grounding_status.value == "GROUNDED"
    blocked_client = FakeClient(rate_limited)
    blocked = candidate(
        monkeypatch,
        blocked_client,
        sleeper=lambda _: None,
        monotonic=lambda: 0.0,
        retry_budget=0.5,
    )
    assert blocked_client.responses.calls[0]["timeout"] == 0.5
    assert blocked.findings[0].ai.error.code == "AI_PROVIDER_UNAVAILABLE"


@pytest.mark.parametrize(
    "error_type, expected, retryable",
    [
        (RateLimitError, "AI_PROVIDER_UNAVAILABLE", True),
        (APIConnectionError, "AI_PROVIDER_UNAVAILABLE", True),
        (ValueError, "AI_TOOL_FAILED", False),
    ],
)
def test_provider_failure_classes_are_isolated(
    monkeypatch, error_type, expected, retryable
):
    outcomes = (
        [provider_error(error_type) for _ in range(3)]
        if error_type in {RateLimitError, APIConnectionError}
        else provider_error(error_type)
    )
    result = candidate(monkeypatch, FakeClient(outcomes), sleeper=lambda _: None)
    ai = result.findings[0].ai
    assert (ai.error.code, ai.error.retryable) == (expected, retryable)


def test_prompts_have_vulnerability_focus_and_input_excludes_url_secrets(monkeypatch):
    xss_client = FakeClient(provider_response(valid_claims()))
    candidate(monkeypatch, xss_client)
    xss = xss_client.responses.calls[0]
    assert "reflection" in xss["instructions"] and "context" in xss["instructions"]
    assert "?secret=x" not in xss["input"] and "#fragment" not in xss["input"]
    assert (
        "admin@example.test" not in xss["input"]
        and "eyJabc.def.ghi" not in xss["input"]
        and "token=" not in xss["input"]
        and "topsecret" not in xss["input"]
    )
    sqli_client = FakeClient(provider_response(valid_claims()))
    candidate(monkeypatch, sqli_client, raw_run(raw_finding(vuln_type="SQLI")))
    instructions = sqli_client.responses.calls[0]["instructions"]
    assert (
        "database errors" in instructions
        and "boolean" in instructions
        and "timing" in instructions
    )


def test_raw_scan_facts_are_preserved_exactly(monkeypatch):
    run = raw_run(
        raw_finding(reason="Case Sensitive", evidence_summary="Exact evidence")
    )
    result = candidate(monkeypatch, FakeClient(provider_response(valid_claims())), run)
    original, output = run.findings[0], result.findings[0]
    assert (output.case_id, output.finding_id, output.scanned_at, output.vuln_type) == (
        original.case_id,
        original.finding_id,
        original.scanned_at,
        original.vuln_type,
    )
    assert output.scan.model_dump(mode="json") == original.scan.model_dump(mode="json")


def test_cache_hit_skips_provider_and_invalid_cached_results_are_not_success(
    monkeypatch,
):
    cache = {}
    monkeypatch.setenv("AI_TRIAGE_MODEL", "test-model")
    first = FakeClient(provider_response(valid_claims()))
    run = raw_run(raw_finding())
    triage(run, client=first, knowledge_base=kb(), cache=cache, now=lambda: NOW)
    assert (
        len(first.responses.create_calls) == len(first.responses.parse_calls) == 1
        and len(cache) == 1
    )
    hit = FakeClient(AssertionError("provider must not be called"))
    assert (
        triage(run, client=hit, knowledge_base=kb(), cache=cache, now=lambda: NOW)
        .findings[0]
        .ai.status.value
        == "COMPLETED"
    )
    assert not hit.responses.calls
    key = next(iter(cache))
    for mutation in ({"role": None}, {"status": "FAILED"}, "broken"):
        cached = cache[key]
        cache[key] = (
            mutation
            if isinstance(mutation, str)
            else {**cached, "result": {**cached["result"], **mutation}}
        )
        replacement = FakeClient(provider_response(valid_claims()))
        result = triage(
            run, client=replacement, knowledge_base=kb(), cache=cache, now=lambda: NOW
        )
        assert result.findings[0].ai.status.value == "COMPLETED"
        assert (
            len(replacement.responses.create_calls)
            == len(replacement.responses.parse_calls)
            == 1
        )
        cache[key] = cached
    poisoned = {
        **cached,
        "result": {
            **cached["result"],
            "provenance": {
                **cached["result"]["provenance"],
                "model": "poisoned-model",
            },
            "references": [
                {**cached["result"]["references"][0], "title": "Poisoned source"}
            ],
        },
    }
    cache[key] = poisoned
    replacement = FakeClient(provider_response(valid_claims()))
    result = triage(
        run, client=replacement, knowledge_base=kb(), cache=cache, now=lambda: NOW
    )
    assert result.findings[0].ai.status.value == "COMPLETED"
    assert (
        len(replacement.responses.create_calls)
        == len(replacement.responses.parse_calls)
        == 1
    )


def test_cache_key_changes_and_failures_are_not_cached(monkeypatch):
    monkeypatch.setenv("AI_TRIAGE_MODEL", "model-a")
    cache, client = (
        {},
        FakeClient([provider_response(valid_claims()) for _ in range(5)]),
    )
    run = raw_run(raw_finding())
    for model, manifest, subject in [
        ("model-a", kb("kb1"), run),
        ("model-b", kb("kb1"), run),
        ("model-b", kb("kb2"), run),
        ("model-b", kb("kb2"), raw_run(raw_finding(evidence_summary="changed"))),
        (
            "model-b",
            kb("kb2"),
            raw_run(raw_finding(case_id="changed-case", finding_id="changed-finding")),
        ),
    ]:
        monkeypatch.setenv("AI_TRIAGE_MODEL", model)
        triage(
            subject,
            client=client,
            knowledge_base=manifest,
            cache=cache,
            now=lambda: NOW,
        )
    assert (
        len(client.responses.create_calls) == len(client.responses.parse_calls) == 5
        and len(cache) == 5
    )
    failed_cache = {}
    result = triage(
        run, client=FakeClient(ValueError("x")), knowledge_base=kb(), cache=failed_cache
    )
    assert result.findings[0].ai.status.value == "FAILED" and not failed_cache


def test_responses_file_search_contract_is_split(monkeypatch):
    client = FakeClient(provider_response(valid_claims()))
    candidate(monkeypatch, client)
    params = client.responses.create_calls[0]
    assert set(params) == {
        "model",
        "instructions",
        "input",
        "tools",
        "include",
        "max_output_tokens",
        "max_tool_calls",
        "tool_choice",
        "timeout",
    }
    assert params["model"] == "test-model"
    assert params["tools"] == [
        {"type": "file_search", "vector_store_ids": ["vs_1"], "max_num_results": 5}
    ]
    assert params["include"] == ["file_search_call.results"]
    assert params["max_output_tokens"] == 1200 and params["max_tool_calls"] == 1
    assert params["tool_choice"] == "required"
    assert params["timeout"] == 30.0
    synthesis = client.responses.parse_calls[0]
    assert synthesis["text_format"] is ProviderAnalysis
    assert "tools" not in synthesis and "include" not in synthesis
    assert len(synthesis["input"].encode("utf-8")) <= 8 * 1024
    assert '"file_id":"file_1"' in synthesis["input"]
    assert '"text":"Official guidance for file_1"' in synthesis["input"]
    assert '"evidence"' in synthesis["input"]


def test_naive_now_is_schema_invalid(monkeypatch):
    monkeypatch.setenv("AI_TRIAGE_MODEL", "test-model")
    result = triage(
        raw_run(raw_finding()),
        client=FakeClient(provider_response(valid_claims())),
        knowledge_base=kb(),
        cache={},
        now=lambda: NOW.replace(tzinfo=None),
    )
    assert result.findings[0].ai.error.code == "AI_SCHEMA_INVALID"


def test_no_candidate_path_needs_no_provider_or_configuration(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AI_TRIAGE_MODEL", raising=False)
    client = FakeClient(AssertionError("provider must not be called"))
    result = triage(
        raw_run(
            raw_finding(label="SAFE"),
            raw_finding(case_id="failed", finding_id="failed", status="FAILED"),
            status="PARTIAL",
        ),
        client=client,
        cache={},
    )
    assert [finding.ai.status_reason.value for finding in result.findings] == [
        "RULE_NOT_SUSPECTED",
        "SCAN_FAILED",
    ]
    assert not client.responses.calls


def test_untrusted_input_is_json_bounded_and_redacts_multiline_credentials(monkeypatch):
    secret = (
        "password=hunter2\nCookie: sid=secret\nAuthorization: Bearer abc.def\n"
        "csrf_token=csrf-secret api_key=key-secret " + ("inject\n" * 4000)
    )
    client = FakeClient(provider_response(valid_claims()))
    candidate(
        monkeypatch,
        client,
        raw_run(raw_finding(reason=secret, evidence_summary=secret, payload=secret)),
    )
    outbound = client.responses.calls[0]["input"]
    assert outbound.startswith("UNTRUSTED_DATA_JSON\n")
    assert len(outbound.encode("utf-8")) <= 8 * 1024
    for value in ("hunter2", "sid=secret", "abc.def", "csrf-secret", "key-secret"):
        assert value not in outbound
    assert "[TRUNCATED]" in outbound


@pytest.mark.parametrize(
    "response_status, call_status, calls, expected",
    [
        (None, "completed", 1, "AI_TOOL_FAILED"),
        ("failed", "completed", 1, "AI_TOOL_FAILED"),
        ("incomplete", "completed", 1, "AI_TOOL_FAILED"),
        ("completed", "failed", 1, "AI_TOOL_FAILED"),
        ("completed", "completed", 2, "AI_TOOL_FAILED"),
        ("completed", "completed", 1, "INSUFFICIENT"),
    ],
)
def test_file_search_lifecycle_is_required(
    monkeypatch, response_status, call_status, calls, expected
):
    response = provider_response(
        [] if expected == "INSUFFICIENT" else valid_claims(),
        () if expected == "INSUFFICIENT" else ("file_1",),
    )
    response.status = response_status
    response.output = [
        SimpleNamespace(type="file_search_call", status=call_status, results=[])
        for _ in range(calls)
    ] + response.output[1:]
    result = candidate(monkeypatch, FakeClient(response)).findings[0].ai
    if expected == "INSUFFICIENT":
        assert result.grounding_status.value == expected
    else:
        assert result.error.code == expected


def test_direct_sdk_annotation_shape_is_a_citation(monkeypatch):
    response = provider_response(valid_claims())
    response.output[1].content[0].annotations = [SimpleNamespace(file_id="file_1")]
    result = candidate(monkeypatch, FakeClient(response)).findings[0].ai
    assert result.grounding_status.value == "GROUNDED"


def test_nonempty_retrieval_without_output_text_citation_fails(monkeypatch):
    response = provider_response(valid_claims())
    response.output[1].content[0].annotations = []
    result = candidate(monkeypatch, FakeClient(response)).findings[0].ai
    assert result.error.code == "AI_TOOL_FAILED"


def test_synthesis_cannot_hallucinate_retrieved_file_id(monkeypatch):
    response = provider_response(valid_claims(reference_id="file_fake"))
    result = candidate(monkeypatch, FakeClient(response)).findings[0].ai
    assert result.error.code == "AI_REFERENCE_MISMATCH"


def test_uncited_retrieval_passage_never_reaches_synthesis(monkeypatch):
    response = provider_response(
        valid_claims(),
        retrieved=("file_1", "file_uncited"),
        cited=("file_1",),
    )
    client = FakeClient(response)

    result = candidate(monkeypatch, client)

    assert result.findings[0].ai.grounding_status.value == "GROUNDED"
    synthesis_input = client.responses.parse_calls[0]["input"]
    assert "file_1" in synthesis_input
    assert "file_uncited" not in synthesis_input


def test_missing_model_with_injected_dependencies_is_isolated(monkeypatch):
    monkeypatch.delenv("AI_TRIAGE_MODEL", raising=False)
    monkeypatch.setattr("analysis.ai_triage._load_environment", lambda: None)
    client = FakeClient(provider_response(valid_claims()))

    result = triage(
        raw_run(raw_finding()),
        client=client,
        knowledge_base=kb(),
        cache={},
    )

    assert result.findings[0].ai.error.code == "AI_TOOL_FAILED"
    assert not client.responses.calls


def test_manifest_digest_invalidates_same_version_cache(monkeypatch):
    cache = {}
    first = FakeClient(provider_response(valid_claims()))
    candidate(monkeypatch, first, cache=cache, manifest=kb("kb1"))
    changed = kb("kb1").model_copy(
        update={
            "files": [
                kb("kb1").files[0].model_copy(update={"document_sha256": "b" * 64})
            ]
        }
    )
    second = FakeClient(provider_response(valid_claims()))
    candidate(monkeypatch, second, cache=cache, manifest=changed)
    assert len(first.responses.create_calls) == len(second.responses.create_calls) == 1


def test_cache_write_error_cannot_fail_valid_provider_result(monkeypatch):
    class BrokenCache(dict):
        def set(self, key, value):
            raise OSError("disk full")

    result = candidate(
        monkeypatch, FakeClient(provider_response(valid_claims())), cache=BrokenCache()
    )
    assert result.findings[0].ai.grounding_status.value == "GROUNDED"


def test_sqlite_same_key_lease_and_stale_recovery(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = SQLiteCache("data/cache/cache.sqlite3")
    assert cache.acquire("key", "first", now=100)
    assert not cache.acquire("key", "second", now=101)
    assert cache.acquire("key", "second", now=191)
