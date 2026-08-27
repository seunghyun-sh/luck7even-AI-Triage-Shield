"""Streamlit dashboard integration smoke test."""

import json
import shutil
from datetime import timedelta
from pathlib import Path

import pandas as pd
from streamlit.testing.v1 import AppTest

from dashboard.app import _report_frame
from orchestration.models import ExecutionStage, ExecutionStatus, RunRequest
from orchestration.run_store import RunStore

APP_PATH = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "configs" / "triaged-results.example.json"
PROCESSED_PATH = Path(__file__).resolve().parents[1] / "data" / "processed"


def _complete_run(store: RunStore, initial) -> None:
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
                "status": ExecutionStatus.COMPLETED,
                "stage": None,
                "updated_at": terminal_time,
                "completed_at": terminal_time,
                "raw_result_path": f"raw/{initial.scan_run_id}/findings.json",
                "processed_result_path": (
                    f"processed/{initial.scan_run_id}/results.json"
                ),
            }
        )
    )


def test_dashboard_renders_contract_sample() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

    assert not app.exception
    assert [title.value for title in app.title] == ["Triage Shield · 취약점 검토 관제"]
    assert [(metric.label, metric.value) for metric in app.metric] == [
        ("전체 Finding", "7"),
        ("AI 취약 판정", "2"),
        ("AI 판정 불가", "1"),
        ("수동 검토 필요", "3"),
        ("AI 처리 실패", "1"),
        ("규칙 취약 의심", "5"),
    ]
    assert len(app.dataframe) == 1
    assert len(app.get("download_button")) == 1


def test_execution_tab_lists_only_contract_manifest_and_disables_default_launch() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

    assert not app.exception
    manifest_selector = next(
        selectbox
        for selectbox in app.selectbox
        if selectbox.label == "허가된 대상 manifest"
    )
    assert manifest_selector.value == (
        Path(__file__).resolve().parents[1] / "configs" / "targets.example.json"
    )
    launch_button = next(
        button for button in app.button if button.label == "진단 실행 시작"
    )
    assert launch_button.disabled


def test_execution_tab_shows_preflight_panel_and_blocks_missing_components() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)
    app.multiselect[0].set_value(["XSS", "SQLI"]).run(timeout=30)

    assert not app.exception
    assert any(
        markdown.value == "#### 실행 준비 상태" for markdown in app.markdown
    )
    assert any(
        "XSS 스캐너를 사용할 수 없습니다." in error.value for error in app.error
    )
    assert any(
        "SQLI 스캐너를 사용할 수 없습니다." in error.value for error in app.error
    )
    assert any(
        "AI triage를 사용할 수 없습니다." in error.value for error in app.error
    )
    launch_button = next(
        button for button in app.button if button.label == "진단 실행 시작"
    )
    assert launch_button.disabled


def test_execution_tab_displays_authoritative_run_status() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    status = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
    try:
        app = AppTest.from_file(str(APP_PATH))
        app.session_state["scan_run_id"] = status.scan_run_id
        app.run(timeout=30)

        assert not app.exception
        assert any(
            "상태: **QUEUED**" in markdown.value for markdown in app.markdown
        )
    finally:
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / status.scan_run_id)


def test_dashboard_renders_conditional_sqli_evaluation() -> None:
    app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

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
    assert len(app.dataframe) == 3


def test_dashboard_uses_discovered_actual_results_by_default() -> None:
    store = RunStore(PROCESSED_PATH.parent)
    initial = store.create_run(RunRequest(target_set_id="local-lab-v1", vuln_types=["XSS"]))
    results_path = PROCESSED_PATH / initial.scan_run_id / "results.json"
    results_path.parent.mkdir()
    results_path.write_text(SAMPLE_PATH.read_text())
    try:
        _complete_run(store, initial)
        app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

        assert not app.exception
        assert app.radio[0].value == "발견된 결과 사용"
        assert app.sidebar.selectbox[0].value == results_path
    finally:
        results_path.unlink()
        results_path.parent.rmdir()
        shutil.rmtree(PROCESSED_PATH.parent / "runs" / initial.scan_run_id)


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
        _complete_run(store, initial)
        app = AppTest.from_file(str(APP_PATH)).run(timeout=30)

        assert not app.exception
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
