"""Stateful Streamlit dashboard integration tests."""

import json
import shutil
from datetime import timedelta
from pathlib import Path

import pandas as pd
from streamlit.testing.v1 import AppTest

from dashboard.app import _report_frame
from orchestration.models import ExecutionStage, ExecutionStatus, RunError, RunRequest
from orchestration.run_store import RunStore

APP_PATH = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "configs" / "triaged-results.example.json"
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
                    RunError(code="PIPELINE_FAILED", message="Diagnostic failed.", retryable=False)
                    if status is ExecutionStatus.FAILED
                    else None
                ),
            }
        )
    )


def _review(app: AppTest) -> AppTest:
    app.session_state["dashboard_view"] = "결과 검토"
    return app.run(timeout=30)


def _button(app: AppTest, label: str):
    return next(button for button in app.button if button.label == label)


def test_first_visit_renders_execution_only_without_review_side_effects() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

    assert not app.exception
    assert any(selectbox.label == "허가된 대상 manifest" for selectbox in app.selectbox)
    assert not app.title
    assert not app.metric
    assert not app.get("download_button")
    assert not app.radio


def test_navigation_renders_review_only_after_selection() -> None:
    app = _review(AppTest.from_file(str(APP_PATH)).run(timeout=30))

    assert not app.exception
    assert [title.value for title in app.title] == ["Triage Shield · 취약점 검토 관제"]
    assert not any(selectbox.label == "허가된 대상 manifest" for selectbox in app.selectbox)
    assert len(app.get("download_button")) == 1


def test_execution_setup_requires_explicit_preflight_and_shows_blockers() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)
    app.multiselect[0].set_value(["XSS", "SQLI"]).run(timeout=30)

    assert _button(app, "진단 실행 시작").disabled
    assert any("격리·허가 확인이 필요합니다." in caption.value for caption in app.caption)
    _button(app, "준비 상태 확인/새로고침").click().run(timeout=30)

    assert any("준비 " in markdown.value and "차단 " in markdown.value for markdown in app.markdown)
    assert any("XSS 스캐너를 사용할 수 없습니다." in caption.value for caption in app.caption)
    assert _button(app, "진단 실행 시작").disabled


def test_active_run_is_rediscovered_and_hides_setup_controls() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    status = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
    try:
        app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

        assert not app.exception
        assert not any(selectbox.label == "허가된 대상 manifest" for selectbox in app.selectbox)
        assert any("QUEUED" in markdown.value for markdown in app.markdown)
        assert any(
            status.scan_run_id in str(element.value) for element in app.get("json")
        )
    finally:
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / status.scan_run_id)


def test_completed_and_partial_runs_offer_explicit_review_handoff() -> None:
    for terminal_status, label in (
        (ExecutionStatus.COMPLETED, "이 결과 검토"),
        (ExecutionStatus.PARTIAL, "부분 결과 검토"),
    ):
        store = RunStore(PROCESSED_PATH.parent)
        initial = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
        results_path = PROCESSED_PATH / initial.scan_run_id / "results.json"
        results_path.parent.mkdir()
        results_path.write_text(SAMPLE_PATH.read_text())
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
    failed = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
    unsafe = store.create_run(RunRequest(target_set_id="local-lab-v2", vuln_types=["XSS"]))
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
        in {"Accuracy", "Precision", "Recall", "N_labeled", "N_scored", "Scored coverage"}
    }
    assert evaluation_metrics == {
        "Accuracy": "100.0%",
        "Precision": "100.0%",
        "Recall": "100.0%",
        "N_labeled": "4",
        "N_scored": "1",
        "Scored coverage": "25.0%",
    }


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
    initial = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
    results_path = PROCESSED_PATH / initial.scan_run_id / "results.json"
    zero_run = json.loads(SAMPLE_PATH.read_text())
    zero_run.update({"status": "COMPLETED", "findings": []})
    results_path.parent.mkdir()
    results_path.write_text(json.dumps(zero_run))
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
