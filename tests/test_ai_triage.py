"""Hybrid reviewed-grounding contracts; all dependencies are in-memory fakes."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier, Event, Lock
from types import SimpleNamespace

import httpx
import pytest
from openai import APIConnectionError, APIStatusError, APITimeoutError, RateLimitError
from pydantic import ValidationError

from analysis.ai_triage import (
    CompactBatchAnalysis,
    SQLiteCache,
    check_readiness,
    triage,
)
from analysis.grounding import (
    GroundingBundle,
    GroundingPassage,
    GroundingUnavailableError,
    GuidanceTemplate,
    RetrievalMode,
)
from analysis.knowledge_base import KnowledgeBaseManifest
from analysis.models import AiLabel, RawRun
from analysis.prompts import batch_triage_input, triage_instructions

NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


def finding(finding_id="finding", family="XSS", summary="reflected safely"):
    return {
        "case_id": finding_id,
        "finding_id": finding_id,
        "scanned_at": NOW,
        "vuln_type": family,
        "scan": {
            "status": "COMPLETED",
            "request": {
                "url": "https://example.test/?secret=no",
                "method": "GET",
                "input_location": "query",
                "parameter": "q",
                "payload": "<x>",
            },
            "response": {
                "http_status": 200,
                "elapsed_ms": 10,
                "baseline_elapsed_ms": 5,
                "evidence_summary": summary,
                "html_path": None,
            },
            "rule": {"label": "SUSPECTED", "reason": "candidate"},
            "error": None,
        },
    }


def run(*items, status="COMPLETED"):
    return RawRun.model_validate(
        {
            "schema_version": "1.0",
            "scan_run_id": "run",
            "target_set_id": "set",
            "started_at": NOW,
            "completed_at": NOW,
            "status": status,
            "findings": list(items),
        }
    )


def manifest():
    return KnowledgeBaseManifest.model_validate(
        {
            "schema_version": "1.0",
            "knowledge_base_version": "kb1",
            "vector_store_ids": ["must-not-be-used"],
            "files": [
                {
                    "file_id": "xss-file",
                    "source_id": "xss-source",
                    "publisher": "OWASP",
                    "title": "XSS guide",
                    "version": "1",
                    "section": "S",
                    "canonical_url": "https://owasp.org/xss",
                    "document_sha256": "a" * 64,
                    "vuln_types": ["XSS"],
                    "language": "en",
                },
                {
                    "file_id": "sqli-file",
                    "source_id": "sqli-source",
                    "publisher": "OWASP",
                    "title": "SQLi guide",
                    "version": "1",
                    "section": "S",
                    "canonical_url": "https://owasp.org/sqli",
                    "document_sha256": "b" * 64,
                    "vuln_types": ["SQLI"],
                    "language": "en",
                },
            ],
        }
    )


def bundle(family):
    file_id, source_id = (
        ("xss-file", "xss-source") if family == "XSS" else ("sqli-file", "sqli-source")
    )
    return GroundingBundle(
        family=family,
        mode=RetrievalMode.REVIEWED_PACK,
        pack_version="pack-1",
        kb_version="kb1",
        manifest_digest="c" * 64,
        bundle_digest=("d" if family == "XSS" else "e") * 64,
        passages=(
            GroundingPassage(
                passage_id=f"{family}-P1",
                source_id=source_id,
                file_id=file_id,
                section="S",
                text="Reviewed neutral candidate evidence.",
                passage_sha256="f" * 64,
            ),
        ),
        guidance={
            f"{family}-G1": GuidanceTemplate(
                guidance_id=f"{family}-G1",
                family=family,
                source_ids=(source_id,),
                impact="Reviewed impact.",
                recommendation="Reviewed recommendation.",
                manual_check="Reviewed manual check.",
            )
        },
        retrieved_file_ids=(file_id,),
    )


class Responses:
    def __init__(self, mutate=None):
        self.parse_calls = []
        self.create_calls = []
        self.mutate = mutate

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        raise AssertionError("File Search must not be used")

    def parse(self, **kwargs):
        self.parse_calls.append(kwargs)
        return _success_response(kwargs, self.mutate)


def _success_response(kwargs, mutate=None):
    payload = json.loads(kwargs["input"].split("\n", 1)[1].rsplit("\n", 1)[0])
    results = []
    for item in payload["findings"]:
        family = payload["vulnerability_type"]
        results.append(
            {
                "finding_id": item["finding_id"],
                "label": AiLabel.SAFE,
                "confidence": 0.8,
                "observation": {
                    "text": "AI observation.",
                    "evidence_ids": [f"{item['finding_id']}:E1"],
                },
                "guidance_ids": [f"{family}-G1"],
            }
        )
    if mutate:
        mutate(results)
    return SimpleNamespace(
        status="completed",
        output_parsed=CompactBatchAnalysis.model_validate({"findings": results}),
    )


def candidate(monkeypatch, raw, responses=None, resolver=None, cache=None, **kwargs):
    monkeypatch.setenv("AI_TRIAGE_MODEL", kwargs.pop("model", "test-model"))
    monkeypatch.setattr(
        "analysis.ai_triage.resolve_grounding",
        resolver or (lambda family, _: bundle(family)),
    )
    return triage(
        raw,
        client=SimpleNamespace(responses=responses or Responses()),
        knowledge_base=manifest(),
        cache={} if cache is None else cache,
        now=kwargs.pop("now", lambda: NOW),
        **kwargs,
    )


def test_local_grounding_has_no_responses_create_and_builds_reviewed_claims(
    monkeypatch,
):
    responses = Responses()
    result = candidate(monkeypatch, run(finding()), responses)
    ai = result.findings[0].ai
    assert not responses.create_calls and len(responses.parse_calls) == 1
    assert [claim.claim_id for claim in ai.claims] == ["C1", "C2", "C3", "C4"]
    assert ai.claims[0].text == "AI observation."
    assert [claim.text for claim in ai.claims[1:]] == [
        "Reviewed impact.",
        "Reviewed recommendation.",
        "Reviewed manual check.",
    ]
    assert [(ref.reference_id, ref.file_id, ref.title) for ref in ai.references] == [
        ("R1", "xss-file", "XSS guide")
    ]
    assert [claim.reference_ids for claim in ai.claims] == [[], ["R1"], ["R1"], ["R1"]]
    assert ai.provenance.vector_store_ids == []
    assert ai.provenance.retrieved_file_ids == ["xss-file"]
    assert ai.provenance.retrieval_policy_version == "hybrid-reviewed-v1"


def test_grounding_is_resolved_once_per_family_and_one_failure_is_isolated(monkeypatch):
    calls = []

    def resolver(family, _):
        calls.append(family)
        if family == "XSS":
            raise GroundingUnavailableError()
        return bundle(family)

    result = candidate(
        monkeypatch, run(finding("x", "XSS"), finding("s", "SQLI")), resolver=resolver
    )
    by_id = {item.finding_id: item.ai for item in result.findings}
    assert set(calls) == {"XSS", "SQLI"}
    assert by_id["x"].error.code == "AI_GROUNDING_UNAVAILABLE"
    assert by_id["s"].status.value == "COMPLETED"


def test_guidance_and_evidence_are_item_scoped(monkeypatch):
    def mutate(items):
        items[0]["guidance_ids"] = ["SQLI-G1"]

    xss_bundle = bundle("XSS").model_copy(
        update={"guidance": {**bundle("XSS").guidance, **bundle("SQLI").guidance}}
    )
    result = candidate(
        monkeypatch,
        run(finding("bad"), finding("good")),
        Responses(mutate),
        resolver=lambda *_: xss_bundle,
    )
    by_id = {item.finding_id: item.ai for item in result.findings}
    assert by_id["bad"].error.code == "AI_SCHEMA_INVALID"
    assert by_id["good"].status.value == "COMPLETED"


def test_cache_is_bound_to_grounding_bundle(monkeypatch):
    cache, responses = {}, Responses()
    raw = run(finding())
    candidate(monkeypatch, raw, responses, cache=cache)
    assert len(cache) == 1
    candidate(
        monkeypatch,
        raw,
        Responses(),
        resolver=lambda family, _: bundle(family).model_copy(
            update={"bundle_digest": "9" * 64}
        ),
        cache=cache,
    )
    assert len(cache) == 2


def test_compact_batches_are_sixteen_and_inputs_are_bounded(monkeypatch):
    responses = Responses()
    raw = run(*(finding(f"f-{index}") for index in range(193)))
    candidate(monkeypatch, raw, responses)
    assert len(responses.parse_calls) == 13
    assert all(
        len(json.loads(call["input"].split("\n", 1)[1].rsplit("\n", 1)[0])["findings"])
        <= 16
        for call in responses.parse_calls
    )
    assert all(
        len(call["input"].encode()) <= 64 * 1024 and call["max_output_tokens"] == 6000
        for call in responses.parse_calls
    )


def test_prompt_semantics_are_explicit_and_input_is_bounded():
    xss_instructions = triage_instructions("XSS")
    assert "Custom tags" in xss_instructions
    assert "it is never target-specific" in xss_instructions
    assert "Only local evidence can support the observation and label" in xss_instructions
    assert "benign apostrophe" in triage_instructions("SQLI")
    payload = batch_triage_input(
        "XSS",
        [{"finding_id": "f", "evidence": {"f:E1": "x"}}],
        {"passages": [], "guidance": {}},
    )
    assert len(payload.encode()) <= 64 * 1024


def test_193_progress_is_monotonic_and_safe(monkeypatch):
    events, responses = [], Responses()
    candidate(
        monkeypatch,
        run(*(finding(f"f-{index}") for index in range(193))),
        responses,
        on_progress=lambda complete, total, detail: events.append(
            (complete, total, detail)
        ),
    )
    assert events[0] == (0, 193, "AI 후보 준비 중")
    assert events[-1][:2] == (193, 193)
    assert [event[0] for event in events] == sorted(event[0] for event in events)
    assert all("<x>" not in event[2] for event in events if event[2])


def test_concurrency_is_limited_to_three(monkeypatch):
    class BlockingResponses(Responses):
        def __init__(self):
            super().__init__()
            self.active = self.maximum = 0
            self.lock, self.release = Lock(), Event()

        def parse(self, **kwargs):
            with self.lock:
                self.active += 1
                self.maximum = max(self.maximum, self.active)
                if self.active == 3:
                    self.release.set()
            self.release.wait(2)
            try:
                return super().parse(**kwargs)
            finally:
                with self.lock:
                    self.active -= 1

    responses = BlockingResponses()
    candidate(
        monkeypatch, run(*(finding(f"f-{index}") for index in range(64))), responses
    )
    assert responses.maximum == 3


def _request_error(kind):
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    if kind is APITimeoutError:
        return APITimeoutError(request=request)
    if kind is APIConnectionError:
        return APIConnectionError(request=request)
    if kind is RateLimitError:
        return RateLimitError(
            "sensitive provider detail",
            response=httpx.Response(429, request=request),
            body=None,
        )
    return APIStatusError(
        "sensitive provider detail",
        response=httpx.Response(400, request=request),
        body=None,
    )


class ScriptedResponses(Responses):
    def __init__(self, outcomes):
        super().__init__()
        self.outcomes = list(outcomes)

    def parse(self, **kwargs):
        self.parse_calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome if outcome is not None else _success_response(kwargs)


def test_timeout_retries_three_times_without_raw_error(monkeypatch):
    responses = ScriptedResponses([_request_error(APITimeoutError)] * 3)
    result = candidate(monkeypatch, run(finding()), responses, sleeper=lambda _: None)
    ai = result.findings[0].ai
    assert len(responses.parse_calls) == 3
    assert (ai.error.code, ai.error.retryable) == ("AI_TIMEOUT", True)
    assert "sensitive" not in ai.error.message


@pytest.mark.parametrize(
    ("error_type", "code", "retryable"),
    [
        (RateLimitError, "AI_PROVIDER_UNAVAILABLE", True),
        (APIConnectionError, "AI_PROVIDER_UNAVAILABLE", True),
        (APIStatusError, "AI_TOOL_FAILED", False),
    ],
)
def test_provider_error_mapping_is_safe(monkeypatch, error_type, code, retryable):
    errors = [_request_error(error_type)] * (3 if retryable else 1)
    result = candidate(
        monkeypatch, run(finding()), ScriptedResponses(errors), sleeper=lambda _: None
    )
    ai = result.findings[0].ai
    assert (ai.error.code, ai.error.retryable) == (code, retryable)
    assert "sensitive provider detail" not in ai.error.message


def test_transient_batch_recovery(monkeypatch):
    responses = ScriptedResponses([_request_error(APITimeoutError), None])
    result = candidate(monkeypatch, run(finding()), responses, sleeper=lambda _: None)
    assert result.findings[0].ai.status.value == "COMPLETED"
    assert len(responses.parse_calls) == 2


def test_circuit_breaker_stops_persistent_batch_outage(monkeypatch):
    responses = ScriptedResponses([_request_error(APITimeoutError)] * 20)
    result = candidate(
        monkeypatch,
        run(*(finding(f"f-{index}") for index in range(64))),
        responses,
        sleeper=lambda _: None,
    )
    assert len(responses.parse_calls) < 12
    assert all(item.ai.status.value == "FAILED" for item in result.findings)


def test_cache_hit_skips_provider(monkeypatch):
    cache, raw = {}, run(finding())
    candidate(monkeypatch, raw, Responses(), cache=cache)
    responses = Responses()
    result = candidate(monkeypatch, raw, responses, cache=cache)
    assert result.findings[0].ai.status.value == "COMPLETED"
    assert not responses.parse_calls


@pytest.mark.parametrize(
    "mutation",
    [
        lambda entry: "broken",
        lambda entry: {**entry, "result": {**entry["result"], "status": "FAILED"}},
        lambda entry: {
            **entry,
            "result": {
                **entry["result"],
                "provenance": {
                    **entry["result"]["provenance"],
                    "grounding_bundle_digest": "0" * 64,
                },
            },
        },
    ],
)
def test_invalid_cache_is_not_a_success(monkeypatch, mutation):
    cache, raw = {}, run(finding())
    candidate(monkeypatch, raw, Responses(), cache=cache)
    key = next(iter(cache))
    cache[key] = mutation(cache[key])
    responses = Responses()
    assert (
        candidate(monkeypatch, raw, responses, cache=cache).findings[0].ai.status.value
        == "COMPLETED"
    )
    assert len(responses.parse_calls) == 1


@pytest.mark.parametrize("change", ["model", "prompt", "manifest", "bundle"])
def test_cache_binding_invalidation(monkeypatch, change):
    cache, raw = {}, run(finding())
    candidate(monkeypatch, raw, Responses(), cache=cache)
    responses = Responses()
    if change == "model":
        candidate(monkeypatch, raw, responses, cache=cache, model="other-model")
    elif change == "prompt":
        monkeypatch.setattr("analysis.ai_triage.PROMPT_VERSION", "triage-report-v11")
        candidate(monkeypatch, raw, responses, cache=cache)
    elif change == "manifest":
        changed = manifest().model_copy(update={"knowledge_base_version": "kb2"})
        monkeypatch.setattr("analysis.ai_triage.load_knowledge_base", lambda: changed)
        monkeypatch.setattr(
            "analysis.ai_triage.resolve_grounding", lambda family, _: bundle(family)
        )
        monkeypatch.setenv("AI_TRIAGE_MODEL", "test-model")
        triage(
            raw,
            client=SimpleNamespace(responses=responses),
            knowledge_base=changed,
            cache=cache,
            now=lambda: NOW,
        )
    else:
        candidate(
            monkeypatch,
            raw,
            responses,
            cache=cache,
            resolver=lambda family, _: bundle(family).model_copy(
                update={"bundle_digest": "9" * 64}
            ),
        )
    assert len(responses.parse_calls) == 1


def test_failures_are_not_cached_and_cache_write_failure_is_safe(monkeypatch):
    failed_cache = {}
    result = candidate(
        monkeypatch,
        run(finding()),
        ScriptedResponses([ValueError("bad")]),
        cache=failed_cache,
    )
    assert result.findings[0].ai.status.value == "FAILED" and not failed_cache

    class BrokenCache(dict):
        def set(self, *_):
            raise OSError("full")

    assert (
        candidate(monkeypatch, run(finding()), Responses(), cache=BrokenCache())
        .findings[0]
        .ai.status.value
        == "COMPLETED"
    )


def test_sqlite_lease_and_stale_recovery(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = SQLiteCache("data/cache/cache.sqlite3")
    assert cache.acquire("key", "first", now=10)
    assert not cache.acquire("key", "second", now=11)
    assert cache.acquire("key", "second", now=101)


def test_sqlite_lease_prevents_duplicate_provider_batches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AI_TRIAGE_MODEL", "test-model")
    monkeypatch.setattr(
        "analysis.ai_triage.resolve_grounding", lambda family, _: bundle(family)
    )
    cache = SQLiteCache("data/cache/cache.sqlite3")
    barrier = Barrier(2)

    class SlowResponses(Responses):
        def parse(self, **kwargs):
            self.parse_calls.append(kwargs)
            time.sleep(0.15)
            return _success_response(kwargs, self.mutate)

    responses = SlowResponses()

    def invoke():
        barrier.wait()
        return triage(
            run(finding()),
            client=SimpleNamespace(responses=responses),
            knowledge_base=manifest(),
            cache=cache,
            now=lambda: NOW,
            sleeper=time.sleep,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (executor.submit(invoke), executor.submit(invoke))
        results = [future.result() for future in futures]
    assert len(responses.parse_calls) == 1
    assert all(result.findings[0].ai.status.value == "COMPLETED" for result in results)


def test_triage_loads_only_candidate_family_when_manifest_is_not_injected(
    monkeypatch,
):
    monkeypatch.setenv("AI_TRIAGE_MODEL", "test-model")
    monkeypatch.setattr("analysis.ai_triage.load_knowledge_base", manifest)

    def resolver(family, _):
        if family == "SQLI":
            raise GroundingUnavailableError()
        return bundle(family)

    monkeypatch.setattr("analysis.ai_triage.resolve_grounding", resolver)
    result = triage(
        run(finding("x", "XSS")),
        client=SimpleNamespace(responses=Responses()),
        cache={},
        now=lambda: NOW,
    )
    assert result.findings[0].ai.status.value == "COMPLETED"
    with pytest.raises(RuntimeError, match="knowledge base is unavailable"):
        check_readiness()


def test_provider_exception_releases_acquired_batch_lease(monkeypatch):
    class LeaseCache(dict):
        def __init__(self):
            super().__init__()
            self.releases = []

        def acquire(self, *_):
            return True

        def release(self, key, owner):
            self.releases.append((key, owner))

    cache = LeaseCache()
    result = candidate(
        monkeypatch,
        run(finding()),
        ScriptedResponses([ValueError("provider failed")]),
        cache=cache,
    )
    assert result.findings[0].ai.status.value == "FAILED"
    assert len(cache.releases) == 1


def test_raw_facts_order_and_one_to_one_are_preserved(monkeypatch):
    original = run(finding("first", "XSS"), finding("second", "SQLI"))
    result = candidate(monkeypatch, original, Responses())
    assert [item.finding_id for item in result.findings] == ["first", "second"]
    for source, processed in zip(original.findings, result.findings, strict=True):
        assert processed.scan.model_dump(mode="json") == source.scan.model_dump(
            mode="json"
        )


def test_safe_and_failed_scans_are_not_requested(monkeypatch):
    safe, failed = finding("safe"), finding("failed")
    safe["scan"]["rule"]["label"] = "SAFE"
    failed["scan"]["status"] = "FAILED"
    failed["scan"]["rule"] = {"label": None, "reason": None}
    failed["scan"]["response"] = {
        "http_status": None,
        "elapsed_ms": None,
        "baseline_elapsed_ms": None,
        "evidence_summary": None,
        "html_path": None,
    }
    failed["scan"]["error"] = {"code": "SCAN", "message": "failed", "retryable": False}
    result = candidate(monkeypatch, run(safe, failed, status="PARTIAL"), Responses())
    assert [
        (item.ai.status_reason.value, item.ai.needs_human_review)
        for item in result.findings
    ] == [("RULE_NOT_SUSPECTED", False), ("SCAN_FAILED", True)]


def test_partial_failed_and_completion_statuses(monkeypatch):
    failed = finding("failed")
    failed["scan"]["status"], failed["scan"]["rule"] = (
        "FAILED",
        {"label": None, "reason": None},
    )
    failed["scan"]["response"] = {
        "http_status": None,
        "elapsed_ms": None,
        "baseline_elapsed_ms": None,
        "evidence_summary": None,
        "html_path": None,
    }
    failed["scan"]["error"] = {"code": "SCAN", "message": "failed", "retryable": False}
    completed = datetime(2026, 8, 29, tzinfo=timezone.utc)
    result = candidate(
        monkeypatch,
        run(finding(), failed, status="PARTIAL"),
        Responses(),
        now=lambda: completed,
    )
    assert result.status.value == "PARTIAL" and result.completed_at == completed


def test_empty_and_all_failed_runs_are_failed_without_configuration(monkeypatch):
    monkeypatch.delenv("AI_TRIAGE_MODEL", raising=False)
    assert triage(run(status="FAILED"), cache={}).status.value == "FAILED"
    failed = finding("failed")
    failed["scan"]["status"], failed["scan"]["rule"] = (
        "FAILED",
        {"label": None, "reason": None},
    )
    failed["scan"]["response"] = {
        "http_status": None,
        "elapsed_ms": None,
        "baseline_elapsed_ms": None,
        "evidence_summary": None,
        "html_path": None,
    }
    failed["scan"]["error"] = {"code": "SCAN", "message": "failed", "retryable": False}
    assert triage(run(failed, status="FAILED"), cache={}).status.value == "FAILED"


def test_no_candidates_need_no_configuration_or_provider(monkeypatch):
    monkeypatch.delenv("AI_TRIAGE_MODEL", raising=False)
    safe = finding()
    safe["scan"]["rule"]["label"] = "SAFE"
    responses = Responses()
    assert (
        triage(run(safe), client=SimpleNamespace(responses=responses), cache={})
        .findings[0]
        .ai.status.value
        == "NOT_REQUESTED"
    )
    assert not responses.parse_calls and not responses.create_calls


def test_missing_model_is_isolated(monkeypatch):
    monkeypatch.delenv("AI_TRIAGE_MODEL", raising=False)
    monkeypatch.setattr("analysis.ai_triage._load_environment", lambda: None)
    responses = Responses()
    result = triage(
        run(finding()),
        client=SimpleNamespace(responses=responses),
        knowledge_base=manifest(),
        cache={},
    )
    assert result.findings[0].ai.error.code == "AI_TOOL_FAILED"
    assert not responses.parse_calls and not responses.create_calls


def test_naive_now_is_rejected(monkeypatch):
    with pytest.raises(ValidationError):
        candidate(
            monkeypatch,
            run(finding()),
            Responses(),
            now=lambda: NOW.replace(tzinfo=None),
        )


def test_encoded_input_is_redacted_and_hard_bounded(monkeypatch):
    secret = "password=hunter2 Cookie: sid=secret token=topsecret " + (
        "\\x00\\n" * 10000
    )
    responses = Responses()
    candidate(monkeypatch, run(finding(summary=secret)), responses)
    outbound = responses.parse_calls[0]["input"]
    assert len(outbound.encode()) <= 64 * 1024
    assert all(
        value not in outbound for value in ("hunter2", "sid=secret", "topsecret")
    )


@pytest.mark.parametrize("kind", ["missing", "duplicate"])
def test_invalid_envelope_fails_only_its_batch(monkeypatch, kind):
    class InvalidEnvelope(Responses):
        def parse(self, **kwargs):
            response = super().parse(**kwargs)
            if len(self.parse_calls) == 1:
                if kind == "missing":
                    response.output_parsed.findings.pop()
                else:
                    response.output_parsed.findings[
                        -1
                    ].finding_id = response.output_parsed.findings[0].finding_id
            return response

    result = candidate(
        monkeypatch,
        run(*(finding(f"f-{index}") for index in range(17))),
        InvalidEnvelope(),
    )
    assert all(
        item.ai.error.code == "AI_SCHEMA_INVALID" for item in result.findings[:16]
    )
    assert result.findings[16].ai.status.value == "COMPLETED"


def test_sibling_evidence_is_item_isolated(monkeypatch):
    def mutate(items):
        items[0]["observation"]["evidence_ids"] = [f"{items[1]['finding_id']}:E1"]

    result = candidate(
        monkeypatch, run(finding("bad"), finding("good")), Responses(mutate)
    )
    assert result.findings[0].ai.error.code == "AI_SCHEMA_INVALID"
    assert result.findings[1].ai.status.value == "COMPLETED"


def test_unknown_guidance_is_item_isolated(monkeypatch):
    def mutate(items):
        items[0]["guidance_ids"] = ["unknown"]

    result = candidate(
        monkeypatch, run(finding("bad"), finding("good")), Responses(mutate)
    )
    assert result.findings[0].ai.error.code == "AI_SCHEMA_INVALID"
    assert result.findings[1].ai.status.value == "COMPLETED"


def test_manifest_family_mismatch_cannot_create_references(monkeypatch):
    bad = bundle("XSS").model_copy(update={"retrieved_file_ids": ("sqli-file",)})
    result = candidate(
        monkeypatch, run(finding()), Responses(), resolver=lambda *_: bad
    )
    assert result.findings[0].ai.error.code == "AI_REFERENCE_MISMATCH"


def test_provider_can_never_supply_reference_metadata(monkeypatch):
    responses = Responses()
    candidate(monkeypatch, run(finding()), responses)
    grounding = json.loads(
        responses.parse_calls[0]["input"].split("\n", 1)[1].rsplit("\n", 1)[0]
    )["grounding"]
    assert "file_id" not in grounding["guidance"]["XSS-G1"]["description"]
    assert "canonical_url" not in grounding["guidance"]["XSS-G1"]["description"]


def test_prompt_has_no_ground_truth_claim(monkeypatch):
    instructions = triage_instructions("XSS")
    assert "Ground truth is not available" in instructions
    assert "script tag, event handler, or javascript: URL" in instructions
