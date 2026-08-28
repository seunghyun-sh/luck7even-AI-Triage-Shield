"""Stateful Streamlit dashboard integration tests."""

import json
import shutil
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

import dashboard.app as dashboard_app
from dashboard.app import (
    _available_processed_results,
    _build_filtered_evaluation,
    _display_ai_verdict,
    _display_enum,
    _display_rule_verdict,
    _load_discovered_processed_run,
    _preflight_fingerprint,
    _priority_table,
    _processed_display_name,
    _render_charts,
    _report_frame,
)
from dashboard.data_loader import (
    findings_to_dataframe,
    load_ground_truth,
    load_processed_data,
)
from dashboard.metrics import (
    build_ai_verdict_counts,
    build_rule_ai_comparison,
    build_summary,
    build_type_counts,
)
from orchestration.models import ExecutionStage, ExecutionStatus, RunError, RunRequest
from orchestration.run_store import RunStore

APP_PATH = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
SAMPLE_PATH = (
    Path(__file__).resolve().parents[1] / "configs" / "triaged-results.example.json"
)
GROUND_TRUTH_PATH = (
    Path(__file__).resolve().parents[1] / "configs" / "ground-truth.example.json"
)
PROCESSED_PATH = Path(__file__).resolve().parents[1] / "data" / "processed"


def _terminal_run(store: RunStore, initial, status: ExecutionStatus) -> None:
    running_time = initial.updated_at + timedelta(microseconds=1)
    running = initial.model_copy(
        update={
            "status": ExecutionStatus.RUNNING,
            "stage": ExecutionStage.VALIDATING_TARGET,
            "updated_at": running_time,
        }
    )
    store.save_status(running)
    terminal_time = running_time + timedelta(microseconds=1)
    store.save_status(
        running.model_copy(
            update={
                "status": status,
                "stage": None,
                "updated_at": terminal_time,
                "completed_at": terminal_time,
                "raw_result_path": f"raw/{initial.scan_run_id}/findings.json",
                "processed_result_path": (
                    f"processed/{initial.scan_run_id}/results.json"
                    if status is not ExecutionStatus.FAILED
                    else None
                ),
                "error": (
                    RunError(
                        code="PIPELINE_FAILED",
                        message="Diagnostic failed.",
                        retryable=False,
                    )
                    if status is ExecutionStatus.FAILED
                    else None
                ),
            }
        )
    )


def _write_processed_run(store: RunStore, initial, status: ExecutionStatus) -> Path:
    payload = json.loads(SAMPLE_PATH.read_text())
    payload.update(
        {
            "scan_run_id": initial.scan_run_id,
            "target_set_id": initial.target_set_id,
            "status": status.value,
        }
    )
    if status is ExecutionStatus.COMPLETED:
        payload["findings"] = [
            finding
            for finding in payload["findings"]
            if finding["scan"]["status"] == "COMPLETED"
            and finding["ai"]["status"] != "FAILED"
        ]
    path = PROCESSED_PATH / initial.scan_run_id / "results.json"
    path.parent.mkdir()
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _review(app: AppTest) -> AppTest:
    app.session_state["dashboard_view"] = "결과 검토"
    return app.run(timeout=30)


def _button(app: AppTest, label: str):
    return next(button for button in app.button if button.label == label)


def test_preflight_fingerprint_binds_deployment_identity_and_version() -> None:
    assert _preflight_fingerprint("lab-a", "2026.08.28", ["SQLI", "XSS"]) == (
        "lab-a",
        "2026.08.28",
        ("SQLI", "XSS"),
    )


def test_first_visit_renders_execution_only_without_review_side_effects() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

    assert not app.exception
    assert any(expander.label == "배포환경 관리" for expander in app.expander)
    assert any(
        uploader.label == "Deployment Descriptor JSON" for uploader in app.file_uploader
    )
    assert not any(selectbox.label == "허가된 배포환경" for selectbox in app.selectbox)
    assert not app.title
    assert not app.metric
    assert not app.get("download_button")
    assert not app.radio


def test_navigation_renders_review_only_after_selection() -> None:
    app = _review(AppTest.from_file(str(APP_PATH)).run(timeout=30))

    assert not app.exception
    assert [title.value for title in app.title] == ["Triage Shield · 취약점 검토 관제"]
    assert not any(selectbox.label == "허가된 배포환경" for selectbox in app.selectbox)
    assert len(app.get("download_button")) == 1


def test_execution_setup_without_registered_deployment_keeps_registration_available() -> (
    None
):
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)
    registration_authorization = next(
        checkbox
        for checkbox in app.checkbox
        if checkbox.label
        == "환경구축팀이 전달한 허가된 격리 진단 환경임을 확인했습니다."
    )
    registration_authorization.set_value(True).run(timeout=30)

    assert _button(app, "배포환경 등록").disabled
    assert any("ACTIVE 또는 TEMPORARY" in info.value for info in app.info)


def test_active_run_is_rediscovered_and_hides_setup_controls() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    status = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    try:
        with store.pipeline_lock(status.scan_run_id):
            app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

            assert not app.exception
            assert not any(
                selectbox.label == "허가된 배포환경" for selectbox in app.selectbox
            )
            assert any("대기" in markdown.value for markdown in app.markdown)
            assert any(
                status.scan_run_id in str(element.value) for element in app.get("json")
            )
    finally:
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / status.scan_run_id)


def test_orphaned_nonterminal_run_does_not_hide_execution_setup() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    orphan = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    try:
        app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

        assert not app.exception
        assert any(expander.label == "배포환경 관리" for expander in app.expander)
    finally:
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / orphan.scan_run_id)


def test_live_lock_owner_wins_over_orphaned_nonterminal_run() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    orphan = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    live = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    try:
        with store.pipeline_lock(live.scan_run_id):
            app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

            assert any(
                live.scan_run_id in str(element.value) for element in app.get("json")
            )
            assert not any(
                orphan.scan_run_id in str(element.value) for element in app.get("json")
            )
    finally:
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / orphan.scan_run_id)
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / live.scan_run_id)


def test_rediscovered_active_run_keeps_terminal_handoff_selection() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    initial = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    results_path = _write_processed_run(store, initial, ExecutionStatus.PARTIAL)
    try:
        app = AppTest.from_file(str(APP_PATH))
        with store.pipeline_lock(initial.scan_run_id):
            app.run(timeout=30)
            assert app.session_state["scan_run_id"] == initial.scan_run_id
            _terminal_run(store, initial, ExecutionStatus.PARTIAL)

        app.run(timeout=30)
        assert _button(app, "부분 결과 검토")
    finally:
        results_path.unlink()
        results_path.parent.rmdir()
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / initial.scan_run_id)


def test_completed_and_partial_runs_offer_explicit_review_handoff() -> None:
    for terminal_status, label in (
        (ExecutionStatus.COMPLETED, "이 결과 검토"),
        (ExecutionStatus.PARTIAL, "부분 결과 검토"),
    ):
        store = RunStore(PROCESSED_PATH.parent)
        initial = store.create_run(
            RunRequest(
                target_set_id="local-lab-v1",
                deployment_id="local-lab-deployment",
                vuln_types=["XSS"],
            )
        )
        results_path = _write_processed_run(store, initial, terminal_status)
        try:
            _terminal_run(store, initial, terminal_status)
            app = AppTest.from_file(str(APP_PATH))
            app.session_state["scan_run_id"] = initial.scan_run_id
            app.run(timeout=30)

            _button(app, label).click().run(timeout=30)
            assert app.session_state["dashboard_view"] == "결과 검토"
            assert app.session_state["review_scan_run_id"] == initial.scan_run_id
        finally:
            results_path.unlink()
            results_path.parent.rmdir()
            shutil.rmtree(PROCESSED_PATH.parent / "runs" / initial.scan_run_id)


def test_failed_and_unsafe_artifact_runs_do_not_offer_review_handoff() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    failed = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    unsafe = store.create_run(
        RunRequest(
            target_set_id="local-lab-v2",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    try:
        _terminal_run(store, failed, ExecutionStatus.FAILED)
        _terminal_run(store, unsafe, ExecutionStatus.COMPLETED)
        for run in (failed, unsafe):
            app = AppTest.from_file(str(APP_PATH))
            app.session_state["scan_run_id"] = run.scan_run_id
            app.run(timeout=30)
            assert not any(
                button.label in {"이 결과 검토", "부분 결과 검토"}
                for button in app.button
            )
    finally:
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / failed.scan_run_id)
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / unsafe.scan_run_id)


def test_dashboard_renders_conditional_sqli_evaluation() -> None:
    app = _review(AppTest.from_file(str(APP_PATH)).run(timeout=30))
    app.radio[1].set_value("샘플 사용").run(timeout=30)

    assert not app.exception
    evaluation_metrics = {
        metric.label: metric.value
        for metric in app.metric
        if metric.label
        in {
            "Accuracy",
            "Precision",
            "Recall",
            "N_labeled",
            "N_scored",
            "Scored coverage",
        }
    }
    assert evaluation_metrics == {
        "Accuracy": "100.0%",
        "Precision": "100.0%",
        "Recall": "100.0%",
        "N_labeled": "4",
        "N_scored": "1",
        "Scored coverage": "25.0%",
    }


def _evaluation_inputs():
    findings = findings_to_dataframe(load_processed_data(SAMPLE_PATH))
    ground_truth = load_ground_truth(GROUND_TRUTH_PATH)
    xss_only = findings.loc[findings["vuln_type"].eq("XSS")].copy()
    return findings, xss_only, ground_truth


@pytest.mark.parametrize(
    ("invalid_ground_truth", "invalid_findings", "error"),
    [
        (
            lambda truth: truth.model_copy(
                update={
                    "cases": [
                        *truth.cases,
                        truth.cases[0].model_copy(update={"case_id": "unknown-case"}),
                    ]
                }
            ),
            lambda findings: findings,
            "missing",
        ),
        (
            lambda truth: truth.model_copy(
                update={"target_set_id": "wrong-target-set"}
            ),
            lambda findings: findings,
            "missing",
        ),
        (
            lambda truth: truth.model_copy(
                update={
                    "cases": [
                        truth.cases[0].model_copy(update={"vuln_type": "XSS"}),
                        *truth.cases[1:],
                    ]
                }
            ),
            lambda findings: findings,
            "SQLI",
        ),
        (
            lambda truth: truth,
            lambda findings: findings.assign(
                vuln_type=findings["vuln_type"].mask(
                    findings["case_id"].eq("sqli-search-a"), "XSS"
                )
            ),
            "vuln_type",
        ),
    ],
)
def test_filter_scoped_evaluation_rejects_full_input_errors_hidden_by_xss_filter(
    invalid_ground_truth, invalid_findings, error: str
) -> None:
    findings, xss_only, ground_truth = _evaluation_inputs()

    with pytest.raises(ValueError, match=error):
        _build_filtered_evaluation(
            invalid_findings(findings), xss_only, invalid_ground_truth(ground_truth)
        )


def test_filter_scoped_evaluation_allows_empty_sqli_scope_after_full_validation() -> (
    None
):
    findings, xss_only, ground_truth = _evaluation_inputs()

    evaluation = _build_filtered_evaluation(findings, xss_only, ground_truth)

    assert evaluation["n_labeled"] == 0
    assert evaluation["annotations"] == []


def test_dashboard_shows_empty_evaluation_for_xss_only_filter() -> None:
    app = _review(AppTest.from_file(str(APP_PATH)).run(timeout=30))
    app.radio[1].set_value("샘플 사용").run(timeout=30)
    vuln_type_filter = next(
        multiselect
        for multiselect in app.multiselect
        if multiselect.label == "취약점 유형"
    )
    vuln_type_filter.set_value(["XSS"]).run(timeout=30)

    assert not app.exception
    assert any(
        "현재 필터에 평가 가능한 SQLi 항목이 없습니다." in info.value
        for info in app.info
    )


def test_report_frame_adds_ground_truth_annotations_and_unlabeled_exclusion() -> None:
    filtered = pd.DataFrame(
        [
            {"target_set_id": "targets", "case_id": "labeled"},
            {"target_set_id": "targets", "case_id": "unlabeled"},
        ]
    )
    evaluation = {
        "annotations": [
            {
                "target_set_id": "targets",
                "case_id": "labeled",
                "ground_truth_label": "VULNERABLE",
                "evaluation_exclusion_reason": None,
            }
        ]
    }

    report = _report_frame(filtered, evaluation)

    assert report.to_dict(orient="records") == [
        {
            "target_set_id": "targets",
            "case_id": "labeled",
            "ground_truth_label": "VULNERABLE",
            "evaluation_exclusion_reason": None,
        },
        {
            "target_set_id": "targets",
            "case_id": "unlabeled",
            "ground_truth_label": None,
            "evaluation_exclusion_reason": "NO_GROUND_TRUTH",
        },
    ]


def test_dashboard_distinguishes_zero_run_from_filter_reset() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    initial = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    results_path = PROCESSED_PATH / initial.scan_run_id / "results.json"
    zero_run = json.loads(SAMPLE_PATH.read_text())
    zero_run.update(
        {
            "scan_run_id": initial.scan_run_id,
            "target_set_id": initial.target_set_id,
            "status": "COMPLETED",
            "findings": [],
        }
    )
    results_path.parent.mkdir()
    results_path.write_text(json.dumps(zero_run), encoding="utf-8")
    try:
        _terminal_run(store, initial, ExecutionStatus.COMPLETED)
        app = AppTest.from_file(str(APP_PATH))
        app.session_state["review_scan_run_id"] = initial.scan_run_id
        app = _review(app.run(timeout=30))

        assert [(metric.label, metric.value) for metric in app.metric] == [
            ("전체 Finding", "0"),
            ("AI 취약 판정", "0"),
            ("AI 판정 불가", "0"),
            ("수동 검토 필요", "0"),
            ("AI 처리 실패", "0"),
            ("규칙 취약 의심", "0"),
        ]
        assert len(app.get("download_button")) == 1
    finally:
        results_path.unlink()
        results_path.parent.rmdir()
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / initial.scan_run_id)


def test_discovery_prefers_completed_and_honors_preferred_partial() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    completed = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    partial = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    completed_path = _write_processed_run(store, completed, ExecutionStatus.COMPLETED)
    partial_path = _write_processed_run(store, partial, ExecutionStatus.PARTIAL)
    try:
        _terminal_run(store, completed, ExecutionStatus.COMPLETED)
        _terminal_run(store, partial, ExecutionStatus.PARTIAL)

        discovered = _available_processed_results()
        assert (
            store.load_status(partial.scan_run_id).completed_at
            > store.load_status(completed.scan_run_id).completed_at
        )
        assert discovered.index(completed_path) < discovered.index(partial_path)
        assert "완료" in _processed_display_name(completed_path)
        assert "부분 완료" in _processed_display_name(partial_path)

        app = _review(AppTest.from_file(str(APP_PATH)).run(timeout=30))
        result_selectbox = next(
            selectbox
            for selectbox in app.selectbox
            if selectbox.label == "발견된 결과 파일"
        )
        assert result_selectbox.value == completed_path

        app.session_state["review_scan_run_id"] = partial.scan_run_id
        app = _review(app.run(timeout=30))
        result_selectbox = next(
            selectbox
            for selectbox in app.selectbox
            if selectbox.label == "발견된 결과 파일"
        )
        assert result_selectbox.value == partial_path
    finally:
        completed_path.unlink()
        completed_path.parent.rmdir()
        partial_path.unlink()
        partial_path.parent.rmdir()
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / completed.scan_run_id)
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / partial.scan_run_id)


def test_reviewer_enum_mapping_preserves_canonical_filter_and_aggregation_inputs() -> (
    None
):
    findings = findings_to_dataframe(load_processed_data(SAMPLE_PATH))
    canonical = findings.copy(deep=True)
    before_counts = (
        build_type_counts(findings),
        build_ai_verdict_counts(findings),
        build_rule_ai_comparison(findings),
    )

    table = _priority_table(findings)

    pd.testing.assert_frame_equal(findings, canonical)
    pd.testing.assert_frame_equal(build_type_counts(findings), before_counts[0])
    pd.testing.assert_frame_equal(build_ai_verdict_counts(findings), before_counts[1])
    pd.testing.assert_frame_equal(build_rule_ai_comparison(findings), before_counts[2])
    assert set(findings["vuln_type"]) == {"XSS", "SQLI"}
    assert "크로스 사이트 스크립팅 (XSS)" in set(table["vuln_type"])
    assert "완료" in set(table["scan_status"])
    assert "취약 의심" in set(table["rule_label"])
    assert "미요청" in set(table["ai_status"])
    assert "미판정" in set(table["ai_label"])
    assert (
        _display_enum("ai_status_reason", "RULE_NOT_SUSPECTED")
        == "규칙상 의심되지 않음"
    )


@pytest.mark.parametrize(
    "replace_artifact",
    [
        lambda payload: payload.update({"scan_run_id": "run-20260827-000000-deadbe"}),
        lambda payload: payload.update({"target_set_id": "replaced-target"}),
        lambda payload: payload.clear(),
    ],
)
def test_discovered_artifact_replacement_cannot_bypass_runstore_snapshot_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_artifact,
) -> None:
    store = RunStore(tmp_path)
    monkeypatch.setattr(dashboard_app, "RUN_STORE", store)
    monkeypatch.setattr(dashboard_app, "DATA_ROOT", tmp_path)
    initial = store.create_run(
        RunRequest(
            target_set_id="local-lab-v1",
            deployment_id="local-lab-deployment",
            vuln_types=["XSS"],
        )
    )
    payload = json.loads(SAMPLE_PATH.read_text())
    payload.update(
        {
            "scan_run_id": initial.scan_run_id,
            "target_set_id": initial.target_set_id,
            "status": "PARTIAL",
        }
    )
    artifact = tmp_path / "processed" / initial.scan_run_id / "results.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    _terminal_run(store, initial, ExecutionStatus.PARTIAL)

    assert _available_processed_results() == [artifact]

    replace_artifact(payload)
    artifact.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="not available for review"):
        _load_discovered_processed_run(artifact)


def test_mixed_chart_display_mapping_keeps_canonical_aggregations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = pd.DataFrame(
        [
            {
                "vuln_type": "XSS",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "VULNERABLE",
            },
            {
                "vuln_type": "XSS",
                "scan_status": "COMPLETED",
                "rule_label": "SAFE",
                "ai_status": "NOT_REQUESTED",
                "ai_label": None,
            },
            {
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SAFE",
                "ai_status": "FAILED",
                "ai_label": None,
            },
            {
                "vuln_type": "SQLI",
                "scan_status": "FAILED",
                "rule_label": None,
                "ai_status": "NOT_REQUESTED",
                "ai_label": None,
            },
        ]
    )
    canonical_comparison = build_rule_ai_comparison(findings)
    figures = []
    monkeypatch.setattr(dashboard_app.st, "markdown", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        dashboard_app.st, "columns", lambda count: [nullcontext() for _ in range(count)]
    )
    monkeypatch.setattr(
        dashboard_app.st,
        "plotly_chart",
        lambda figure, **kwargs: figures.append(figure),
    )

    _render_charts(findings)

    pd.testing.assert_frame_equal(
        build_rule_ai_comparison(findings), canonical_comparison
    )
    assert _display_ai_verdict("NOT_REQUESTED") == "미요청"
    assert _display_ai_verdict("FAILED") == "실패"
    assert _display_rule_verdict("FAILED") == "실패"
    assert set(figures[1].data[0].labels) == {"취약", "미요청", "실패"}
    assert {trace.name for trace in figures[2].data} == {"취약", "미요청", "실패"}
    assert {value for trace in figures[2].data for value in trace.x} == {
        "취약 의심",
        "양호",
        "실패",
    }


def test_partial_banner_uses_unfiltered_full_run_counts() -> None:
    findings = findings_to_dataframe(load_processed_data(SAMPLE_PATH))
    summary = build_summary(findings)
    app = _review(AppTest.from_file(str(APP_PATH)).run(timeout=30))
    warning = next(
        element.value
        for element in app.warning
        if "필터 적용 전 전체 Finding 기준" in element.value
    )

    vuln_type_filter = next(
        multiselect
        for multiselect in app.multiselect
        if multiselect.label == "취약점 유형"
    )
    app = vuln_type_filter.set_value(["XSS"]).run(timeout=30)
    filtered_warning = next(
        element.value
        for element in app.warning
        if "필터 적용 전 전체 Finding 기준" in element.value
    )
    expected_counts = (
        f"스캔 실패 {summary['scan_failed']}건 · "
        f"AI 미요청 {summary['ai_not_requested']}건 · "
        f"AI 실패 {summary['ai_failed']}건 · "
        f"수동 검토 필요 {summary['needs_human_review']}건"
    )
    assert expected_counts in warning
    assert filtered_warning == warning
