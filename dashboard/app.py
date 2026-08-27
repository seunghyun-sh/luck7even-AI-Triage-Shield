"""Streamlit dashboard for authorized diagnostics and triage review."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.data_loader import (
    DataLoadError,
    findings_to_dataframe,
    load_ground_truth,
    load_processed_data,
)
from dashboard.metrics import (
    build_ai_verdict_counts,
    build_evaluation,
    build_rule_ai_comparison,
    build_summary,
    build_type_counts,
)
from dashboard.report_builder import build_excel_report
from orchestration.launcher import RunLaunchError, start_run
from orchestration.preflight import Readiness, run_preflight
from orchestration.run_store import RunStore
from orchestration.target_registry import (
    TargetRegistryError,
    list_registered_targets,
)

SAMPLE_PROCESSED = PROJECT_ROOT / "configs" / "triaged-results.example.json"
SAMPLE_GROUND_TRUTH = PROJECT_ROOT / "configs" / "ground-truth.example.json"
DATA_ROOT = PROJECT_ROOT / "data"
RUN_STORE = RunStore(DATA_ROOT)
ACTIVE_STATUSES = {"QUEUED", "RUNNING"}
TERMINAL_STATUSES = {"COMPLETED", "PARTIAL", "FAILED"}

TRUSTED_CSS = """
<style>
.block-container { max-width: 1500px; padding-top: 1.4rem; }
[data-testid="stMetric"] { background: #0e1b2b; border: 1px solid #1e3a50; border-radius: 10px; padding: .75rem; }
[data-testid="stDataFrame"] { border: 1px solid #1e3a50; border-radius: 8px; }
.section-label { color: #7dd3fc; font-size: .75rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
</style>
"""


def _text(value: Any, fallback: str = "—") -> str:
    """Present missing nullable contract fields consistently without coercing them."""

    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    return str(value)


def _format_metric(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "N/A"
    if isinstance(value, float):
        return f"{value:.1%}" if 0 <= value <= 1 else f"{value:.2f}"
    return str(value)


def _run_metadata(run: Any) -> dict[str, Any]:
    return {
        "scan_run_id": run.scan_run_id,
        "target_set_id": run.target_set_id,
        "status": run.status.value,
        "started_at": run.started_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


def _apply_filters(df: pd.DataFrame) -> pd.DataFrame:
    st.sidebar.subheader("검토 필터")
    filter_keys = (
        "filter_vuln_types",
        "filter_rule_labels",
        "filter_ai_statuses",
        "filter_ai_labels",
        "filter_human_review",
        "filter_query",
    )
    if st.sidebar.button("필터 초기화"):
        for key in filter_keys:
            st.session_state.pop(key, None)
        st.rerun()

    filtered = df.copy()
    vuln_types = sorted(filtered["vuln_type"].unique())
    selected_types = st.sidebar.multiselect(
        "취약점 유형", vuln_types, default=vuln_types, key="filter_vuln_types"
    )
    filtered = filtered[filtered["vuln_type"].isin(selected_types)]

    rule_values = filtered["rule_label"].where(
        filtered["scan_status"].eq("COMPLETED"), "SCAN_FAILED"
    )
    selected_rules = st.sidebar.multiselect(
        "규칙 판정",
        ["SUSPECTED", "SAFE", "SCAN_FAILED"],
        default=["SUSPECTED", "SAFE", "SCAN_FAILED"],
        key="filter_rule_labels",
    )
    filtered = filtered[rule_values.isin(selected_rules)]

    ai_statuses = sorted(filtered["ai_status"].unique())
    selected_statuses = st.sidebar.multiselect(
        "AI 상태", ai_statuses, default=ai_statuses, key="filter_ai_statuses"
    )
    filtered = filtered[filtered["ai_status"].isin(selected_statuses)]

    ai_values = filtered["ai_label"].fillna("미판정")
    selected_labels = st.sidebar.multiselect(
        "AI 판정",
        ["VULNERABLE", "SAFE", "INCONCLUSIVE", "미판정"],
        default=["VULNERABLE", "SAFE", "INCONCLUSIVE", "미판정"],
        key="filter_ai_labels",
    )
    filtered = filtered[ai_values.isin(selected_labels)]
    review = st.sidebar.radio(
        "수동 검토",
        ("전체", "필요", "불필요"),
        horizontal=True,
        key="filter_human_review",
    )
    if review != "전체":
        filtered = filtered[filtered["needs_human_review"] == (review == "필요")]

    query = st.sidebar.text_input(
        "URL · case_id · finding_id 검색", key="filter_query"
    )
    if query:
        mask = (
            filtered["url"].str.contains(query, case=False, na=False, regex=False)
            | filtered["case_id"].str.contains(query, case=False, na=False, regex=False)
            | filtered["finding_id"].str.contains(
                query, case=False, na=False, regex=False
            )
        )
        filtered = filtered[mask]
    return filtered.copy()


def _available_processed_results() -> list[Path]:
    """Return only contract-published terminal results."""

    if not RUN_STORE.runs_dir.is_dir():
        return []
    results: list[Path] = []
    for run_dir in RUN_STORE.runs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        result = _safe_processed_path(run_dir.name)
        if result is not None:
            results.append(result)
    return sorted(
        results,
        key=lambda path: (path.parent.name, path.name),
        reverse=True,
    )


def _processed_display_name(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


def _dark_figure(figure: Any, title: str) -> Any:
    figure.update_layout(
        title=title,
        template="plotly_dark",
        paper_bgcolor="#0e1b2b",
        plot_bgcolor="#0e1b2b",
        margin={"l": 20, "r": 20, "t": 50, "b": 20},
        legend_title_text="",
    )
    return figure


def _count_label_column(counts: pd.DataFrame) -> str:
    """Use the metrics-provided label column without duplicating its aggregation."""

    return next(column for column in counts.columns if column != "count")


def _render_charts(df: pd.DataFrame) -> None:
    st.markdown("<p class='section-label'>분석</p>", unsafe_allow_html=True)
    type_counts = build_type_counts(df)
    verdict_counts = build_ai_verdict_counts(df)
    comparison = build_rule_ai_comparison(df)
    left, middle, right = st.columns(3)
    with left:
        if type_counts.empty:
            st.info("표시할 유형별 데이터가 없습니다.")
        else:
            label = _count_label_column(type_counts)
            st.plotly_chart(
                _dark_figure(
                    px.bar(type_counts, x=label, y="count", color=label),
                    "취약점 유형별 Finding",
                ),
                width="stretch",
            )
    with middle:
        if verdict_counts.empty:
            st.info("완료된 AI 판정이 없습니다.")
        else:
            st.plotly_chart(
                _dark_figure(
                    px.pie(
                        verdict_counts,
                        names=_count_label_column(verdict_counts),
                        values="count",
                        hole=0.55,
                    ),
                    "AI 판정 결과 분포",
                ),
                width="stretch",
            )
    with right:
        if comparison.empty:
            st.info("비교할 규칙·AI 판정이 없습니다.")
        else:
            st.plotly_chart(
                _dark_figure(
                    px.bar(
                        comparison,
                        x="rule_label",
                        y="count",
                        color="ai_label",
                        barmode="group",
                    ),
                    "규칙 판정과 AI 판정 비교",
                ),
                width="stretch",
            )


def _priority_table(df: pd.DataFrame) -> pd.DataFrame:
    priorities = pd.Series(5, index=df.index)
    priorities.loc[df["ai_status"].eq("FAILED")] = 1
    priorities.loc[df["needs_human_review"].eq(True) & priorities.gt(1)] = 2
    priorities.loc[df["ai_label"].eq("INCONCLUSIVE") & priorities.gt(2)] = 3
    priorities.loc[df["ai_label"].eq("VULNERABLE") & priorities.gt(3)] = 4
    columns = [
        "finding_id",
        "case_id",
        "vuln_type",
        "url",
        "parameter",
        "scan_status",
        "rule_label",
        "ai_status",
        "ai_label",
        "confidence",
        "needs_human_review",
    ]
    return df.assign(_priority=priorities).sort_values(["_priority", "finding_id"])[
        columns
    ]


def _render_detail(df: pd.DataFrame) -> None:
    st.markdown("<p class='section-label'>Finding 상세</p>", unsafe_allow_html=True)
    selected_id = st.selectbox("검토할 Finding", df["finding_id"].tolist())
    finding = df.loc[df["finding_id"].eq(selected_id)].iloc[0]
    request_tab, rule_tab, ai_tab, recommendation_tab = st.tabs(
        ["요청", "규칙", "AI", "권고"]
    )
    with request_tab:
        st.code(
            "\n".join(
                (
                    f"{_text(finding['method'])} {_text(finding['url'])}",
                    f"입력 위치: {_text(finding['input_location'])}",
                    f"파라미터: {_text(finding['parameter'])}",
                    f"Payload: {_text(finding['payload'])}",
                )
            ),
            language="text",
        )
        st.write(
            f"HTTP status: {_text(finding['http_status'])} · 응답: {_text(finding['elapsed_ms'])} ms · 기준: {_text(finding['baseline_elapsed_ms'])} ms"
        )
    with rule_tab:
        st.write(
            f"Scan 상태: **{_text(finding['scan_status'])}** · 규칙 판정: **{_text(finding['rule_label'])}**"
        )
        st.caption("규칙 근거")
        st.code(_text(finding["rule_reason"]), language="text")
        st.caption("원시 증거 요약")
        st.code(_text(finding["scan_evidence"]), language="text")
        if pd.notna(finding["scan_error"]):
            st.error(_text(finding["scan_error"]))
    with ai_tab:
        st.write(
            f"AI 상태: **{_text(finding['ai_status'])}** · 판정: **{_text(finding['ai_label'])}** · Confidence: **{_text(finding['confidence'])}**"
        )
        if pd.notna(finding["ai_status_reason"]):
            st.info(f"미요청 사유: {_text(finding['ai_status_reason'])}")
        if pd.notna(finding["ai_error"]):
            st.error(_text(finding["ai_error"]))
        for label, column in (
            ("분석 요약", "assessment_summary"),
            ("소스 증거", "source_evidence"),
        ):
            st.caption(label)
            st.code(_text(finding[column]), language="text")
    with recommendation_tab:
        for label, column in (
            ("예상 영향도", "impact"),
            ("조치 권고", "recommendation"),
            ("수동 확인 방법", "manual_check"),
            ("보고서 문장 초안", "report_paragraph"),
        ):
            st.caption(label)
            st.code(_text(finding[column]), language="text")


def _render_evaluation(df: pd.DataFrame, ground_truth: Any) -> dict[str, Any] | None:
    if ground_truth is None:
        return None
    st.markdown("<p class='section-label'>SQLi 조건부 평가</p>", unsafe_allow_html=True)
    try:
        filtered_ground_truth = ground_truth.model_copy(
            update={
                "cases": [
                    case
                    for case in ground_truth.cases
                    if case.case_id
                    in set(df.loc[df["vuln_type"].eq("SQLI"), "case_id"])
                ]
            }
        )
        evaluation = build_evaluation(df, filtered_ground_truth)
    except (ValueError, KeyError, TypeError) as error:
        st.warning(f"평가 데이터를 결합할 수 없습니다: {_text(error)}")
        return None

    if not evaluation:
        st.info("현재 필터에 평가 가능한 SQLi 항목이 없습니다.")
        return evaluation
    metrics = [
        ("Accuracy", evaluation.get("accuracy")),
        ("Precision", evaluation.get("precision")),
        ("Recall", evaluation.get("recall")),
        ("N_labeled", evaluation.get("n_labeled")),
        ("N_scored", evaluation.get("n_scored")),
        ("Scored coverage", evaluation.get("scored_coverage")),
    ]
    for column, (label, value) in zip(st.columns(6), metrics):
        column.metric(label, _format_metric(value))

    confusion = {key: evaluation.get(key, 0) for key in ("tp", "fp", "tn", "fn")}
    st.dataframe(
        pd.DataFrame([confusion], index=["AI vs ground truth"]),
        width="stretch",
    )
    support = evaluation.get("support")
    if support:
        st.caption(
            f"정답 support · 취약: {support.get('vulnerable', 0)} · 양호: {support.get('safe', 0)}"
        )
    exclusions = (
        evaluation.get("excluded_counts")
        or evaluation.get("exclusions")
        or evaluation.get("excluded")
    )
    if exclusions:
        st.caption("평가 제외 상태별 건수")
        st.dataframe(
            pd.DataFrame(list(exclusions.items()), columns=["상태", "건수"]),
            hide_index=True,
            width="stretch",
        )
    false_positive = evaluation.get("false_positive_cases") or evaluation.get(
        "false_positives"
    )
    false_negative = evaluation.get("false_negative_cases") or evaluation.get(
        "false_negatives"
    )
    if false_positive or false_negative:
        st.caption(
            f"오탐: {_text(false_positive, '없음')} · 미탐: {_text(false_negative, '없음')}"
        )
    return evaluation


def _report_frame(
    filtered: pd.DataFrame, evaluation: dict[str, Any] | None
) -> pd.DataFrame:
    """Attach validated evaluation annotations to the exact filtered export frame."""

    report = filtered.copy()
    report["ground_truth_label"] = None
    report["evaluation_exclusion_reason"] = "NO_GROUND_TRUTH"
    if not evaluation:
        return report

    annotations = pd.DataFrame(evaluation.get("annotations", []))
    annotation_columns = [
        "target_set_id",
        "case_id",
        "ground_truth_label",
        "evaluation_exclusion_reason",
    ]
    if annotations.empty:
        return report
    missing = set(annotation_columns).difference(annotations.columns)
    if missing:
        raise ValueError("평가 주석 형식이 올바르지 않습니다.")

    report = report.drop(
        columns=["ground_truth_label", "evaluation_exclusion_reason"], errors="ignore"
    ).merge(
        annotations[annotation_columns],
        on=["target_set_id", "case_id"],
        how="left",
        validate="one_to_one",
        indicator=True,
    )
    report.loc[
        report["_merge"].eq("left_only"), "evaluation_exclusion_reason"
    ] = "NO_GROUND_TRUTH"
    report["ground_truth_label"] = report["ground_truth_label"].astype(object).where(
        report["ground_truth_label"].notna(), None
    )
    return report.drop(columns="_merge")


def _load_inputs() -> tuple[Any | None, Any | None]:
    st.sidebar.header("결과 선택")
    available_results = _available_processed_results()
    source_modes = (
        ("발견된 결과 사용", "샘플 사용", "JSON 업로드")
        if available_results
        else ("샘플 사용", "JSON 업로드")
    )
    preferred_run_id = st.session_state.get("review_scan_run_id")
    preferred_path = None
    if preferred_run_id:
        preferred_path = _safe_processed_path(preferred_run_id)
    default_mode = (
        "발견된 결과 사용"
        if preferred_path in available_results
        else source_modes[0]
    )
    processed_mode = st.sidebar.radio(
        "Processed 결과", source_modes, index=source_modes.index(default_mode)
    )
    source: Any | None
    if processed_mode == "발견된 결과 사용":
        index = (
            available_results.index(preferred_path)
            if preferred_path in available_results
            else 0
        )
        source = st.sidebar.selectbox(
            "발견된 결과 파일",
            available_results,
            index=index,
            format_func=_processed_display_name,
        )
    elif processed_mode == "샘플 사용":
        source = SAMPLE_PROCESSED
    else:
        source = st.sidebar.file_uploader("Processed JSON 업로드", type="json")
        if source is None:
            st.info("검토할 Processed JSON을 업로드하세요.")
            return None, None
    try:
        run = load_processed_data(source)
    except DataLoadError as error:
        st.error(f"Processed 결과를 읽을 수 없습니다: {error}")
        return None, None

    ground_truth_mode = st.sidebar.radio(
        "SQLi ground truth", ("사용 안 함", "샘플 사용", "JSON 업로드")
    )
    ground_truth = None
    if ground_truth_mode == "샘플 사용":
        try:
            ground_truth = load_ground_truth(SAMPLE_GROUND_TRUTH)
        except DataLoadError as error:
            st.warning(f"Ground truth를 읽을 수 없습니다: {error}")
    elif ground_truth_mode == "JSON 업로드":
        uploaded_ground_truth = st.sidebar.file_uploader(
            "Ground truth JSON 업로드", type="json"
        )
        if uploaded_ground_truth is not None:
            try:
                ground_truth = load_ground_truth(uploaded_ground_truth)
            except DataLoadError as error:
                st.warning(f"Ground truth를 읽을 수 없습니다: {error}")
        else:
            st.info("선택적 평가를 위해 ground truth JSON을 업로드하세요.")
    return run, ground_truth


def _available_target_manifests() -> list[tuple[Path, Any]]:
    try:
        return [
            (target.manifest_path, target.manifest)
            for target in list_registered_targets()
        ]
    except TargetRegistryError:
        return []


def _safe_processed_path(scan_run_id: str) -> Path | None:
    """Return a reviewed run's canonical path after RunStore coupling validation."""

    try:
        RUN_STORE.load_reviewable_processed_run(scan_run_id)
    except (FileNotFoundError, ValueError):
        return None
    return DATA_ROOT / "processed" / scan_run_id / "results.json"


def _active_run_id() -> str | None:
    """Return only the nonterminal owner of the live advisory pipeline lock."""

    status = RUN_STORE.active_run_status()
    return status.scan_run_id if status is not None else None


def _render_run_status(scan_run_id: str, *, polling: bool) -> None:
    try:
        status = RUN_STORE.load_status(scan_run_id)
    except (FileNotFoundError, ValueError):
        st.warning("실행 상태를 읽을 수 없습니다.")
        return

    details = {
        "Run ID": status.scan_run_id,
        "Target set": status.target_set_id,
        "요청 유형": ", ".join(status.requested_vuln_types),
        "상태": status.status.value,
        "단계": status.stage.value if status.stage else "대기 중",
        "진행": (
            f"{status.progress.completed}/{status.progress.total}"
            if status.progress.total
            else "전체 건수 계산 중"
        ),
        "업데이트": status.updated_at.isoformat(),
    }
    st.json(details, expanded=False)
    if status.progress.total:
        st.progress(
            status.progress.completed / status.progress.total,
            text=f"진행률: {status.progress.completed}/{status.progress.total}",
        )
    else:
        st.caption("진행률: 전체 건수 계산 중")
    if polling and status.status.value in TERMINAL_STATUSES:
        st.rerun()


def _set_review_selection(scan_run_id: str) -> None:
    """Navigate only when the published artifact is still safe to review."""

    if _safe_processed_path(scan_run_id) is None:
        return
    st.session_state["review_scan_run_id"] = scan_run_id
    st.session_state["dashboard_view"] = "결과 검토"


def _set_execution_view() -> None:
    st.session_state["dashboard_view"] = "진단 실행"


def _clear_run_selection() -> None:
    st.session_state.pop("scan_run_id", None)


def _preflight_fingerprint(selected_path: Path, selected_types: list[str]) -> tuple[str, tuple[str, ...]]:
    return (str(selected_path), tuple(sorted(selected_types)))


def _render_readiness(preflight: Any) -> None:
    ready_checks = [
        check for check in preflight.checks if check.readiness is Readiness.READY
    ]
    blockers = [
        check for check in preflight.checks if check.readiness is not Readiness.READY
    ]
    st.markdown(f"**준비 {len(ready_checks)} · 차단 {len(blockers)}**")
    for check in blockers:
        st.caption(f"차단 · {check.name}: {check.message} ({check.code})")
    if ready_checks:
        with st.expander(f"통과 항목 {len(ready_checks)}"):
            for check in ready_checks:
                st.caption(f"{check.name}: {check.message} ({check.code})")


def _render_terminal_status(status: Any) -> None:
    status_text = {
        "COMPLETED": "진단이 완료되었습니다. 게시된 결과를 검토할 수 있습니다.",
        "PARTIAL": "진단이 일부 완료되었습니다. 게시된 부분 결과를 검토할 수 있습니다.",
        "FAILED": "진단이 실패했습니다. 결과 검토로 전달하지 않습니다.",
    }[status.status.value]
    color = {"COMPLETED": "green", "PARTIAL": "orange", "FAILED": "red"}[
        status.status.value
    ]
    st.markdown(f":{color}-badge[{status.status.value}]")
    st.write(status_text)
    _render_run_status(status.scan_run_id, polling=False)
    processed_path = _safe_processed_path(status.scan_run_id)
    if processed_path is not None:
        label = "이 결과 검토" if status.status.value == "COMPLETED" else "부분 결과 검토"
        st.button(
            label,
            type="primary",
            on_click=_set_review_selection,
            args=(status.scan_run_id,),
        )
    elif status.status.value != "FAILED":
        st.warning("검토에 사용할 안전한 processed 결과를 찾을 수 없습니다.")
    if status.status.value == "FAILED" and status.error is not None:
        st.caption(f"{status.error.code}: {status.error.message}")
    st.button("새 진단 준비", on_click=_clear_run_selection)


def _render_execution_tab() -> None:
    st.subheader("진단 실행")
    active_run_id = _active_run_id()
    if active_run_id is not None:
        st.session_state["scan_run_id"] = active_run_id
    selected_run_id = active_run_id or st.session_state.get("scan_run_id")
    status = None
    if selected_run_id:
        try:
            status = RUN_STORE.load_status(selected_run_id)
        except (FileNotFoundError, ValueError):
            st.session_state.pop("scan_run_id", None)
    if status is not None and status.status.value in ACTIVE_STATUSES:
        st.markdown(f":blue-badge[{status.status.value}]")
        st.caption("실행 중에는 설정을 변경할 수 없습니다.")

        @st.fragment(run_every=2)
        def active_status_fragment() -> None:
            _render_run_status(status.scan_run_id, polling=True)

        active_status_fragment()
        return
    if status is not None and status.status.value in TERMINAL_STATUSES:
        _render_terminal_status(status)
        return

    manifests = _available_target_manifests()
    if not manifests:
        st.error("검증된 대상 manifest가 없습니다.")
        return

    paths = [path for path, _ in manifests]
    manifest_names = {path: manifest.target_set_id for path, manifest in manifests}
    setup_card, readiness_card = st.columns([3, 2])
    with setup_card, st.container(border=True):
        selected_path = st.selectbox(
            "허가된 대상 manifest",
            paths,
            format_func=lambda path: f"{path.name} · {manifest_names[path]}",
            key="execution_manifest_path",
        )
        selected_types = st.multiselect(
            "진단 유형", ("XSS", "SQLI"), key="execution_types"
        )
        acknowledged = st.checkbox(
            "격리되고 허가된 진단 환경임을 확인했습니다.",
            key="execution_authorized",
        )
        fingerprint = _preflight_fingerprint(selected_path, selected_types)
        cached = st.session_state.get("execution_preflight")
        preflight = (
            cached["result"]
            if cached and cached["fingerprint"] == fingerprint
            else None
        )
        if not selected_types:
            disabled_reason = "진단 유형을 선택하세요."
        elif not acknowledged:
            disabled_reason = "격리·허가 확인이 필요합니다."
        elif preflight is None:
            disabled_reason = "준비 확인이 필요합니다."
        elif not preflight.ready:
            disabled_reason = "차단 항목을 해결하세요."
        else:
            disabled_reason = ""
        if st.button("진단 실행 시작", type="primary", disabled=bool(disabled_reason)):
            fresh = run_preflight(
                dict(manifests)[selected_path], selected_types, DATA_ROOT
            )
            st.session_state["execution_preflight"] = {
                "fingerprint": fingerprint,
                "result": fresh,
            }
            if not fresh.ready:
                st.rerun()
            else:
                try:
                    st.session_state["scan_run_id"] = start_run(
                        manifest_names[selected_path], selected_types
                    )
                except RunLaunchError as error:
                    st.error(str(error))
                else:
                    st.rerun()
        if disabled_reason:
            st.caption(disabled_reason)
    with readiness_card, st.container(border=True):
        st.markdown("#### 실행 준비 상태")
        if st.button("준비 상태 확인/새로고침"):
            result = run_preflight(
                dict(manifests)[selected_path], selected_types, DATA_ROOT
            )
            st.session_state["execution_preflight"] = {
                "fingerprint": fingerprint,
                "result": result,
            }
            st.rerun()
        if preflight is None:
            st.caption("선택한 manifest와 진단 유형의 준비 상태를 확인하세요.")
        else:
            _render_readiness(preflight)


def _render_review_tab() -> None:
    active_run_id = _active_run_id()
    if active_run_id:
        banner, action = st.columns([5, 1])
        banner.info(f"진단 {active_run_id}이 실행 중입니다.")
        action.button("실행 상태 보기", on_click=_set_execution_view)
    run, ground_truth = _load_inputs()
    if run is None:
        return

    metadata = _run_metadata(run)
    st.title("Triage Shield · 취약점 검토 관제")
    st.caption(
        "AI 분석과 Excel은 검토용 초안입니다. 최종 확인·수정·승인은 담당자가 수행해야 합니다."
    )
    header, status = st.columns([5, 1])
    header.text(
        f"Run {metadata['scan_run_id']} · Target {metadata['target_set_id']} · "
        f"시작 {metadata['started_at']} · 완료 {_text(metadata['completed_at'])}"
    )
    status.markdown(
        f":{'red' if run.status.value == 'FAILED' else 'orange' if run.status.value == 'PARTIAL' else 'green'}-badge[{run.status.value}]"
    )

    if run.status.value == "FAILED":
        st.error(
            "FAILED 실행은 오류 확인만 가능합니다. 지표와 Excel 초안은 생성되지 않습니다."
        )
        failed_findings = findings_to_dataframe(run)
        errors = failed_findings.loc[
            failed_findings["scan_error"].notna() | failed_findings["ai_error"].notna(),
            ["finding_id", "case_id", "scan_error", "ai_error"],
        ]
        if errors.empty:
            st.info("실행 상태 외에 Finding 수준 오류가 제공되지 않았습니다.")
        else:
            st.dataframe(errors, hide_index=True, width="stretch")
        st.stop()
    if run.status.value == "PARTIAL":
        st.warning(
            "PARTIAL 실행입니다. 실패 또는 제외된 Finding을 확인한 뒤 결과를 검토하세요."
        )

    findings = findings_to_dataframe(run)
    filtered = _apply_filters(findings)
    if findings.empty:
        st.info("이 실행에는 처리된 Finding이 없습니다. 0건 요약과 빈 Excel 초안을 제공합니다.")
    elif filtered.empty:
        st.info(
            "활성 필터와 일치하는 Finding이 없습니다. 사이드바에서 필터를 초기화하세요."
        )

    summary = build_summary(filtered)
    card_specs = [
        ("전체 Finding", "total_findings"),
        ("AI 취약 판정", "ai_vulnerable"),
        ("AI 판정 불가", "ai_inconclusive"),
        ("수동 검토 필요", "needs_human_review"),
        ("AI 처리 실패", "ai_failed"),
        ("규칙 취약 의심", "rule_suspected"),
    ]
    st.markdown("<p class='section-label'>활성 범위 요약</p>", unsafe_allow_html=True)
    for column, (label, key) in zip(st.columns(6), card_specs):
        column.metric(label, _format_metric(summary.get(key, summary.get("total", 0))))

    if not filtered.empty:
        _render_charts(filtered)
        st.markdown(
            "<p class='section-label'>우선순위 검토 작업목록</p>",
            unsafe_allow_html=True,
        )
        st.dataframe(
            _priority_table(filtered),
            hide_index=True,
            width="stretch",
            column_config={"confidence": st.column_config.NumberColumn(format="%.2f")},
        )
        _render_detail(filtered)
    evaluation = _render_evaluation(filtered, ground_truth)

    try:
        report = build_excel_report(
            _report_frame(filtered, evaluation), metadata, evaluation=evaluation
        )
    except (ValueError, KeyError, TypeError) as error:
        st.warning(f"Excel 초안을 생성할 수 없습니다: {_text(error)}")
    else:
        st.download_button(
            "현재 필터 결과 Excel 초안 다운로드",
            data=report,
            file_name=f"vulnerability_review_{run.scan_run_id}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )


def main() -> None:
    st.set_page_config(page_title="Triage Shield | 검토 대시보드", layout="wide")
    st.markdown(TRUSTED_CSS, unsafe_allow_html=True)
    st.session_state.setdefault("dashboard_view", "진단 실행")
    view = st.segmented_control(
        "대시보드 보기",
        ("진단 실행", "결과 검토"),
        key="dashboard_view",
        label_visibility="collapsed",
    )
    if view == "진단 실행":
        _render_execution_tab()
    elif view == "결과 검토":
        _render_review_tab()


if __name__ == "__main__":
    main()
