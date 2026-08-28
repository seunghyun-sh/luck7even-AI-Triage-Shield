"""Streamlit dashboard for authorized diagnostics and triage review."""

from __future__ import annotations

import json
import os
import re
import sys
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
from orchestration import deployment_registry
from orchestration.deployment_registry import (
    DEFAULT_DEPLOYMENTS_PATH,
    DeploymentRegistryError,
    parse_deployment_descriptor,
    register_deployment,
    resolve_deployment_manifest,
)
from orchestration.launcher import RunLaunchError, start_run
from orchestration.models import ExecutionStage
from orchestration.preflight import Readiness, run_preflight
from orchestration.run_store import RunStore

SAMPLE_PROCESSED = PROJECT_ROOT / "configs" / "triaged-results.example.json"
SAMPLE_GROUND_TRUTH = PROJECT_ROOT / "configs" / "ground-truth.example.json"
DATA_ROOT = Path(
    os.environ.get("AI_TRIAGE_DASHBOARD_DATA_ROOT", str(PROJECT_ROOT / "data"))
).resolve()
RUN_STORE = RunStore(DATA_ROOT)
ACTIVE_STATUSES = {"QUEUED", "RUNNING"}
TERMINAL_STATUSES = {"COMPLETED", "PARTIAL", "FAILED"}
STAGE_LABELS = {
    ExecutionStage.VALIDATING_TARGET: "대상 검증",
    ExecutionStage.SCANNING_XSS: "XSS 스캔",
    ExecutionStage.SCANNING_SQLI: "SQLi 스캔",
    ExecutionStage.PUBLISHING_RAW: "Raw 결과 저장",
    ExecutionStage.AI_TRIAGE: "AI 2차 분류",
    ExecutionStage.PUBLISHING_RESULT: "결과 게시",
}
AI_PROGRESS_DETAILS = (
    re.compile(r"AI 후보 (?:계산 중|준비 중|없음)"),
    re.compile(r"캐시 결과 재사용 · \d+/\d+"),
    re.compile(r"AI 처리 완료 · \d+/\d+"),
    re.compile(r"공식 근거 검색 · (?:XSS|SQLI)"),
    re.compile(r"AI 배치 처리 · \d+/\d+"),
)
DISPLAY_LABELS = {
    "run_status": {
        "COMPLETED": "완료",
        "PARTIAL": "부분 완료",
        "FAILED": "실패",
        "QUEUED": "대기",
        "RUNNING": "실행 중",
    },
    "scan_status": {"COMPLETED": "완료", "FAILED": "실패"},
    "rule_label": {
        "SUSPECTED": "취약 의심",
        "SAFE": "양호",
        "SCAN_FAILED": "스캔 실패",
    },
    "ai_status": {
        "COMPLETED": "완료",
        "NOT_REQUESTED": "미요청",
        "FAILED": "실패",
    },
    "ai_label": {
        "VULNERABLE": "취약",
        "SAFE": "양호",
        "INCONCLUSIVE": "판정 불가",
        None: "미판정",
    },
    "ai_status_reason": {
        "RULE_NOT_SUSPECTED": "규칙상 의심되지 않음",
        "SCAN_FAILED": "스캔 실패",
        "POLICY_EXCLUDED": "정책 제외",
    },
    "vuln_type": {
        "XSS": "크로스 사이트 스크립팅 (XSS)",
        "SQLI": "SQL 삽입 (SQLI)",
    },
}

TRUSTED_CSS = """
<style>
.block-container { max-width: 1500px; padding-top: 1.4rem; }
[data-testid="stMetric"] { background: #0e1b2b; border: 1px solid #1e3a50; border-radius: 10px; padding: .75rem; }
[data-testid="stDataFrame"] { border: 1px solid #1e3a50; border-radius: 8px; }
.section-label { color: #7dd3fc; font-size: .75rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.stage-flow { display: flex; gap: .65rem; margin: .75rem 0 1rem; overflow-x: auto; padding-bottom: .2rem; }
.stage-card { flex: 1 0 10rem; border: 1px solid #334155; border-radius: .6rem; padding: .65rem .75rem; color: #94a3b8; background: #0f172a; }
.stage-card.completed { border-color: #166534; color: #bbf7d0; }
.stage-card.current { border-color: #2563eb; color: #dbeafe; background: #172554; }
.stage-card.failed { border-color: #dc2626; color: #fecaca; background: #450a0a; }
.stage-card .stage-state { align-items: center; display: flex; font-size: .78rem; font-weight: 700; gap: .35rem; min-height: 1rem; }
.stage-card .stage-label { font-size: .92rem; font-weight: 650; margin-top: .35rem; }
.stage-spinner { animation: stage-spin .9s linear infinite; border: 2px solid #93c5fd; border-right-color: transparent; border-radius: 50%; display: inline-block; height: .7rem; width: .7rem; }
@keyframes stage-spin { to { transform: rotate(360deg); } }
@media (max-width: 720px) { .stage-flow { flex-direction: column; overflow-x: visible; } .stage-card { flex-basis: auto; } }
</style>
"""


def _text(value: Any, fallback: str = "—") -> str:
    """Present missing nullable contract fields consistently without coercing them."""

    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    return str(value)


def _display_enum(category: str, value: Any) -> str:
    """Translate canonical enum values only at the reviewer-facing boundary."""

    if value is None or (isinstance(value, float) and pd.isna(value)):
        return DISPLAY_LABELS.get(category, {}).get(None, "—")
    return DISPLAY_LABELS.get(category, {}).get(value, str(value))


def _display_ai_verdict(value: Any) -> str:
    """Display a mixed AI verdict without changing its canonical chart value."""

    label = DISPLAY_LABELS["ai_label"].get(value)
    if label is not None:
        return label
    return _display_enum("ai_status", value)


def _display_rule_verdict(value: Any) -> str:
    """Display a mixed rule verdict without changing its canonical chart value."""

    label = DISPLAY_LABELS["rule_label"].get(value)
    if label is not None:
        return label
    return _display_enum("scan_status", value)


def _safe_official_url(value: Any) -> str | None:
    """Return only direct HTTPS OWASP/KISA URLs safe to offer as dashboard links."""

    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not (
            hostname in {"owasp.org", "kisa.or.kr"}
            or hostname.endswith((".owasp.org", ".kisa.or.kr"))
        )
    ):
        return None
    return value


def _json_list(value: Any) -> list[dict[str, Any]]:
    """Read flattened contract JSON defensively for the reviewer display."""

    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return (
        [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, list)
        else []
    )


def _format_metric(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "N/A"
    if isinstance(value, float):
        return f"{value:.1%}" if 0 <= value <= 1 else f"{value:.2f}"
    return str(value)


def _run_metadata(run: Any) -> dict[str, Any]:
    deployment_id = None
    try:
        request = RUN_STORE.load_request(run.scan_run_id)
        if request.target_set_id == run.target_set_id:
            deployment_id = request.deployment_id
    except (FileNotFoundError, ValueError):
        pass
    return {
        "scan_run_id": run.scan_run_id,
        "target_set_id": run.target_set_id,
        "deployment_id": deployment_id,
        "status": run.status.value,
        "started_at": run.started_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


def _ai_error_breakdown(run: Any) -> dict[str, int]:
    """Count failed AI findings by their validated, canonical error code."""

    counts: dict[str, int] = {}
    for finding in run.findings:
        error = finding.ai.error
        if finding.ai.status.value == "FAILED" and error is not None:
            counts[error.code] = counts.get(error.code, 0) + 1
    return dict(sorted(counts.items()))


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
        "취약점 유형",
        vuln_types,
        default=vuln_types,
        key="filter_vuln_types",
        format_func=lambda value: _display_enum("vuln_type", value),
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
        format_func=lambda value: _display_enum("rule_label", value),
    )
    filtered = filtered[rule_values.isin(selected_rules)]

    ai_statuses = sorted(filtered["ai_status"].unique())
    selected_statuses = st.sidebar.multiselect(
        "AI 상태",
        ai_statuses,
        default=ai_statuses,
        key="filter_ai_statuses",
        format_func=lambda value: _display_enum("ai_status", value),
    )
    filtered = filtered[filtered["ai_status"].isin(selected_statuses)]

    ai_values = filtered["ai_label"]
    selected_labels = st.sidebar.multiselect(
        "AI 보조 판정",
        ["VULNERABLE", "SAFE", "INCONCLUSIVE", None],
        default=["VULNERABLE", "SAFE", "INCONCLUSIVE", None],
        key="filter_ai_labels",
        format_func=lambda value: _display_enum("ai_label", value),
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

    query = st.sidebar.text_input("URL · case_id · finding_id 검색", key="filter_query")
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

    def sort_key(path: Path) -> tuple[int, float, str]:
        status = RUN_STORE.load_status(path.parent.name)
        completed_at = (
            status.completed_at.timestamp() if status.completed_at else float("-inf")
        )
        return (
            {"COMPLETED": 0, "PARTIAL": 1}.get(status.status.value, 2),
            -completed_at,
            path.parent.name,
        )

    return sorted(results, key=sort_key)


def _processed_display_name(path: Path) -> str:
    status = RUN_STORE.load_status(path.parent.name)
    return (
        f"{path.parent.name} · {_display_enum('run_status', status.status.value)}"
        f" · {path.name}"
    )


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
            displayed_counts = type_counts.assign(
                **{
                    label: type_counts[label].map(
                        lambda value: _display_enum("vuln_type", value)
                    )
                }
            )
            st.plotly_chart(
                _dark_figure(
                    px.bar(displayed_counts, x=label, y="count", color=label),
                    "취약점 유형별 Finding",
                ),
                width="stretch",
            )
    with middle:
        if verdict_counts.empty:
            st.info("완료된 AI 보조 판정이 없습니다.")
        else:
            label = _count_label_column(verdict_counts)
            displayed_counts = verdict_counts.assign(
                **{label: verdict_counts[label].map(_display_ai_verdict)}
            )
            st.plotly_chart(
                _dark_figure(
                    px.pie(
                        displayed_counts,
                        names=label,
                        values="count",
                        hole=0.55,
                    ),
                    "AI 보조 판정 결과 분포",
                ),
                width="stretch",
            )
    with right:
        if comparison.empty:
            st.info("비교할 규칙·AI 보조 판정이 없습니다.")
        else:
            displayed_comparison = comparison.assign(
                rule_label=comparison["rule_label"].map(_display_rule_verdict),
                ai_label=comparison["ai_label"].map(_display_ai_verdict),
            )
            st.plotly_chart(
                _dark_figure(
                    px.bar(
                        displayed_comparison,
                        x="rule_label",
                        y="count",
                        color="ai_label",
                        barmode="group",
                    ),
                    "규칙 판정과 AI 보조 판정 비교",
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
    table = (
        df.assign(_priority=priorities)
        .sort_values(["_priority", "finding_id"])[columns]
        .copy()
    )
    for column in (
        "vuln_type",
        "scan_status",
        "rule_label",
        "ai_status",
        "ai_label",
    ):
        table[column] = table[column].map(
            lambda value, field=column: _display_enum(field, value)
        )
    return table


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
            f"Scan 상태: **{_display_enum('scan_status', finding['scan_status'])}** · "
            f"규칙 판정: **{_display_enum('rule_label', finding['rule_label'])}**"
        )
        st.caption("규칙 근거")
        st.code(_text(finding["rule_reason"]), language="text")
        st.caption("원시 증거 요약")
        st.code(_text(finding["scan_evidence"]), language="text")
        if pd.notna(finding["scan_error"]):
            st.error(_text(finding["scan_error"]))
    with ai_tab:
        st.write(
            f"AI 상태: **{_display_enum('ai_status', finding['ai_status'])}** · "
            f"AI 보조 분류: **{_display_enum('ai_label', finding['ai_label'])}** · "
            f"Confidence: **{_text(finding['confidence'])}**"
        )
        grounding_status = _text(finding.get("grounding_status"))
        st.markdown(f":blue-badge[근거 상태: {grounding_status}]")
        if pd.notna(finding["ai_status_reason"]):
            st.info(
                "미요청 사유: "
                f"{_display_enum('ai_status_reason', finding['ai_status_reason'])}"
            )
        if pd.notna(finding["ai_error"]):
            st.error(_text(finding["ai_error"]))
        for label, column in (
            ("분석 요약", "assessment_summary"),
            ("소스 증거", "source_evidence"),
        ):
            st.caption(label)
            st.code(_text(finding[column]), language="text")
        if finding.get("grounding_status") == "INSUFFICIENT":
            st.warning("공식 근거 부족")
        elif finding.get("grounding_status") == "GROUNDED":
            claims = _json_list(finding.get("claims_json"))
            references = _json_list(finding.get("references_json"))
            for claim_type in (
                "OBSERVATION",
                "IMPACT",
                "RECOMMENDATION",
                "MANUAL_CHECK",
            ):
                typed_claims = [
                    claim for claim in claims if claim.get("claim_type") == claim_type
                ]
                if not typed_claims:
                    continue
                st.caption(claim_type)
                for claim in typed_claims:
                    details = [
                        f"{claim.get('claim_id', 'C?')}: {claim.get('text', '')}"
                    ]
                    evidence_ids = claim.get("evidence_ids") or []
                    reference_ids = claim.get("reference_ids") or []
                    if evidence_ids:
                        details.append(
                            f"로컬 증거: {', '.join(map(str, evidence_ids))}"
                        )
                    if reference_ids:
                        details.append(
                            f"공식 근거: {', '.join(map(str, reference_ids))}"
                        )
                    st.code("\n".join(details), language="text")
            st.caption("공식 근거")
            for reference in references:
                st.write(
                    " · ".join(
                        _text(reference.get(key))
                        for key in (
                            "reference_id",
                            "publisher",
                            "title",
                            "version",
                            "section",
                        )
                    )
                )
                canonical_url = reference.get("canonical_url")
                safe_url = _safe_official_url(canonical_url)
                if safe_url:
                    st.link_button(
                        safe_url,
                        safe_url,
                        key=f"reference-{selected_id}-{reference.get('reference_id')}",
                    )
                else:
                    st.caption(f"Canonical URL: {_text(canonical_url)}")
            st.caption("생성 이력")
            st.code(
                "\n".join(
                    f"{label}: {_text(finding.get(column))}"
                    for label, column in (
                        ("model", "provenance_model"),
                        ("prompt", "provenance_prompt_version"),
                        ("KB", "provenance_knowledge_base_version"),
                        ("schema", "provenance_output_schema_version"),
                        ("retrieval policy", "provenance_retrieval_policy_version"),
                        ("generated_at", "provenance_generated_at"),
                    )
                ),
                language="text",
            )
    with recommendation_tab:
        if finding.get("grounding_status") == "INSUFFICIENT":
            st.warning("공식 근거 부족: 보고서 초안을 표시하지 않습니다.")
            return
        for label, column in (
            ("예상 영향도", "impact"),
            ("조치 권고", "recommendation"),
            ("수동 확인 방법", "manual_check"),
            ("보고서 문장 초안", "report_paragraph"),
        ):
            st.caption(label)
            st.code(_text(finding[column]), language="text")


def _build_filtered_evaluation(
    full_findings: pd.DataFrame,
    filtered_findings: pd.DataFrame,
    ground_truth: Any,
) -> dict[str, Any] | None:
    """Validate all inputs before calculating evaluation for the visible SQLi scope."""

    if ground_truth is None:
        return None

    build_evaluation(full_findings, ground_truth)
    filtered_sqli_case_ids = set(
        filtered_findings.loc[filtered_findings["vuln_type"].eq("SQLI"), "case_id"]
    )
    filtered_ground_truth = ground_truth.model_copy(
        update={
            "cases": [
                case
                for case in ground_truth.cases
                if case.case_id in filtered_sqli_case_ids
            ]
        }
    )
    return build_evaluation(filtered_findings, filtered_ground_truth)


def _render_evaluation(
    full_findings: pd.DataFrame,
    filtered_findings: pd.DataFrame,
    ground_truth: Any,
) -> dict[str, Any] | None:
    if ground_truth is None:
        return None
    st.markdown("<p class='section-label'>SQLi 조건부 평가</p>", unsafe_allow_html=True)
    try:
        evaluation = _build_filtered_evaluation(
            full_findings, filtered_findings, ground_truth
        )
    except (ValueError, KeyError, TypeError):
        st.warning("평가 데이터를 결합할 수 없습니다.")
        return None

    if not evaluation or evaluation["n_labeled"] == 0:
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
    report.loc[report["_merge"].eq("left_only"), "evaluation_exclusion_reason"] = (
        "NO_GROUND_TRUTH"
    )
    report["ground_truth_label"] = (
        report["ground_truth_label"]
        .astype(object)
        .where(report["ground_truth_label"].notna(), None)
    )
    return report.drop(columns="_merge")


def _load_discovered_processed_run(path: Path) -> Any:
    """Consume the RunStore-validated snapshot selected during discovery."""

    return RUN_STORE.load_reviewable_processed_run(path.parent.name)


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
        "발견된 결과 사용" if preferred_path in available_results else source_modes[0]
    )
    if (
        preferred_path in available_results
        and st.session_state.get("review_preferred_run_applied") != preferred_run_id
    ):
        st.session_state["review_processed_mode"] = "발견된 결과 사용"
        st.session_state["review_processed_result"] = preferred_path
        st.session_state["review_preferred_run_applied"] = preferred_run_id
    processed_mode = st.sidebar.radio(
        "Processed 결과",
        source_modes,
        index=source_modes.index(default_mode),
        key="review_processed_mode",
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
            key="review_processed_result",
        )
    elif processed_mode == "샘플 사용":
        source = SAMPLE_PROCESSED
    else:
        source = st.sidebar.file_uploader("Processed JSON 업로드", type="json")
        if source is None:
            st.info("검토할 Processed JSON을 업로드하세요.")
            return None, None
    try:
        if processed_mode == "발견된 결과 사용":
            run = _load_discovered_processed_run(source)
        else:
            run = load_processed_data(source)
    except (DataLoadError, FileNotFoundError, ValueError) as error:
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


def _available_deployments() -> list[Any]:
    return deployment_registry.list_registered_deployments(DEFAULT_DEPLOYMENTS_PATH)


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


def _stage_rows(status: Any) -> list[dict[str, str | ExecutionStage]]:
    """Return the requested pipeline stages with their display state."""

    stages = [ExecutionStage.VALIDATING_TARGET]
    if "XSS" in status.requested_vuln_types:
        stages.append(ExecutionStage.SCANNING_XSS)
    if "SQLI" in status.requested_vuln_types:
        stages.append(ExecutionStage.SCANNING_SQLI)
    stages.extend(
        (
            ExecutionStage.PUBLISHING_RAW,
            ExecutionStage.AI_TRIAGE,
            ExecutionStage.PUBLISHING_RESULT,
        )
    )

    terminal_complete = status.status.value in {"COMPLETED", "PARTIAL"}
    current_stage = (
        status.failed_stage if status.status.value == "FAILED" else status.stage
    )
    rows = []
    for index, stage in enumerate(stages):
        if terminal_complete:
            state = "COMPLETED"
        elif stage == current_stage:
            state = "FAILED" if status.status.value == "FAILED" else "CURRENT"
        elif current_stage in stages and index < stages.index(current_stage):
            state = "COMPLETED"
        else:
            state = "PENDING"
        rows.append({"stage": stage, "label": STAGE_LABELS[stage], "state": state})
    return rows


def _progress_detail(status: Any) -> str | None:
    """Return only a dashboard-safe description of the current work."""

    detail = status.progress.detail
    if not detail:
        return None
    if status.stage is ExecutionStage.AI_TRIAGE:
        return (
            detail
            if any(pattern.fullmatch(detail) for pattern in AI_PROGRESS_DETAILS)
            else "AI 2차 분류 진행 중"
        )
    return detail


def _render_stage_flow(status: Any) -> None:
    state_content = {
        "COMPLETED": "&#10003; 완료",
        "CURRENT": '<span class="stage-spinner"></span>진행 중',
        "PENDING": "대기",
        "FAILED": "실패",
    }
    cards = "".join(
        (
            f'<div class="stage-card {row["state"].lower()}">'
            f'<div class="stage-state">{state_content[row["state"]]}</div>'
            f'<div class="stage-label">{escape(str(row["label"]))}</div>'
            "</div>"
        )
        for row in _stage_rows(status)
    )
    st.markdown(f'<div class="stage-flow">{cards}</div>', unsafe_allow_html=True)


def _render_run_status(scan_run_id: str, *, polling: bool) -> None:
    try:
        status = RUN_STORE.load_status(scan_run_id)
    except (FileNotFoundError, ValueError):
        st.warning("실행 상태를 읽을 수 없습니다.")
        return

    details = {
        "Run ID": status.scan_run_id,
        "Target set": status.target_set_id,
        "구축환경": status.deployment_id,
        "요청 유형": ", ".join(
            _display_enum("vuln_type", value) for value in status.requested_vuln_types
        ),
        "상태": _display_enum("run_status", status.status.value),
        "단계": STAGE_LABELS.get(status.stage or status.failed_stage, "대기 중"),
        "진행": (
            f"{status.progress.completed}/{status.progress.total}"
            if status.progress.total
            else "전체 건수 계산 중"
        ),
        "업데이트": status.updated_at.isoformat(),
    }
    _render_stage_flow(status)
    detail = _progress_detail(status)
    if detail:
        st.caption(f"현재 작업: {detail}")
    st.json(details, expanded=False)
    if status.progress.total:
        percentage = status.progress.completed / status.progress.total * 100
        st.progress(
            status.progress.completed / status.progress.total,
            text=(
                f"진행률: {status.progress.completed}/{status.progress.total} "
                f"({percentage:.1f}%)"
            ),
        )
    elif status.stage is ExecutionStage.AI_TRIAGE and detail == "AI 후보 없음":
        st.caption("진행률: AI 후보 없음")
    elif status.stage is ExecutionStage.AI_TRIAGE and detail:
        st.caption("진행률: 후보 계산 중")
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


def _preflight_fingerprint(
    deployment_id: str, deployment_version: str, selected_types: list[str]
) -> tuple[str, str, tuple[str, ...]]:
    return (deployment_id, deployment_version, tuple(sorted(selected_types)))


def _deployment_origin(base_url: str) -> str:
    """Display an endpoint origin without credentials, paths, or query data."""

    parsed = urlsplit(base_url)
    if not parsed.scheme or not parsed.hostname:
        return "—"
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port is not None:
        origin = f"{origin}:{parsed.port}"
    return origin


def _deployment_label(deployment: Any) -> str:
    return (
        f"{deployment.display_name} · {deployment.target_set_id} · "
        f"{deployment.database_engine} · {deployment.lifecycle}"
    )


def _render_deployment_management() -> None:
    """Render registration controls without exposing descriptor secrets."""

    with st.expander("배포환경 관리"):
        uploaded = st.file_uploader("Deployment Descriptor JSON", type="json")
        registration_authorized = st.checkbox(
            "환경구축팀이 전달한 허가된 격리 진단 환경임을 확인했습니다.",
            key="deployment_registration_authorized",
        )
        if st.button(
            "배포환경 등록",
            disabled=uploaded is None or not registration_authorized,
        ):
            try:
                descriptor = parse_deployment_descriptor(uploaded.getvalue())
                registered = register_deployment(descriptor, DEFAULT_DEPLOYMENTS_PATH)
            except DeploymentRegistryError as error:
                st.error(f"배포환경을 등록할 수 없습니다: {error}")
            else:
                st.success(f"배포환경을 등록했습니다: {registered.deployment_id}")

        deployments = _available_deployments()
        if not deployments:
            st.info(
                "등록된 배포환경이 없습니다. Descriptor JSON을 업로드하여 등록하세요."
            )
            return
        st.markdown("#### 등록된 배포환경")
        for deployment in deployments:
            st.caption(
                f"{_deployment_label(deployment)} · "
                f"{_deployment_origin(deployment.base_url)} · "
                f"버전 {deployment.deployment_version}"
            )


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
    st.markdown(f":{color}-badge[{_display_enum('run_status', status.status.value)}]")
    st.write(status_text)
    _render_run_status(status.scan_run_id, polling=False)
    processed_path = _safe_processed_path(status.scan_run_id)
    if processed_path is not None:
        label = (
            "이 결과 검토" if status.status.value == "COMPLETED" else "부분 결과 검토"
        )
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
        st.markdown(f":blue-badge[{_display_enum('run_status', status.status.value)}]")
        st.caption("실행 중에는 설정을 변경할 수 없습니다.")

        @st.fragment(run_every=2)
        def active_status_fragment() -> None:
            _render_run_status(status.scan_run_id, polling=True)

        active_status_fragment()
        return
    if status is not None and status.status.value in TERMINAL_STATUSES:
        _render_terminal_status(status)
        return

    try:
        _render_deployment_management()
        deployments = _available_deployments()
    except DeploymentRegistryError:
        st.error(
            "배포환경 registry를 안전하게 읽을 수 없습니다. "
            "손상된 설정을 복구하기 전에는 등록과 진단을 진행할 수 없습니다."
        )
        return
    selectable_deployments = [
        deployment
        for deployment in deployments
        if deployment.lifecycle in {"ACTIVE", "TEMPORARY"}
    ]
    if not selectable_deployments:
        st.info("진단하려면 ACTIVE 또는 TEMPORARY 배포환경을 등록하세요.")
        return

    deployment_ids = [deployment.deployment_id for deployment in selectable_deployments]
    deployments_by_id = {
        deployment.deployment_id: deployment for deployment in selectable_deployments
    }
    setup_card, readiness_card = st.columns([3, 2])
    with setup_card, st.container(border=True):
        selected_deployment_id = st.selectbox(
            "허가된 배포환경",
            deployment_ids,
            format_func=lambda deployment_id: _deployment_label(
                deployments_by_id[deployment_id]
            ),
            key="execution_deployment_id",
        )
        selected_deployment = deployments_by_id[selected_deployment_id]
        selected_types = st.multiselect(
            "진단 유형", ("XSS", "SQLI"), key="execution_types"
        )
        acknowledged = st.checkbox(
            "격리되고 허가된 진단 환경임을 확인했습니다.",
            key="execution_authorized",
        )
        fingerprint = _preflight_fingerprint(
            selected_deployment.deployment_id,
            selected_deployment.deployment_version,
            selected_types,
        )
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
            try:
                manifest = resolve_deployment_manifest(selected_deployment_id)
                fresh = run_preflight(
                    manifest,
                    selected_types,
                    DATA_ROOT,
                    target_identity_verified=True,
                )
            except DeploymentRegistryError as error:
                st.error(f"배포환경을 해석할 수 없습니다: {error}")
                return
            st.session_state["execution_preflight"] = {
                "fingerprint": fingerprint,
                "result": fresh,
            }
            if not fresh.ready:
                st.rerun()
            else:
                try:
                    st.session_state["scan_run_id"] = start_run(
                        selected_deployment.target_set_id,
                        selected_deployment_id,
                        selected_types,
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
            try:
                manifest = resolve_deployment_manifest(selected_deployment_id)
                result = run_preflight(
                    manifest,
                    selected_types,
                    DATA_ROOT,
                    target_identity_verified=True,
                )
            except DeploymentRegistryError as error:
                st.error(f"배포환경을 해석할 수 없습니다: {error}")
            else:
                st.session_state["execution_preflight"] = {
                    "fingerprint": fingerprint,
                    "result": result,
                }
                st.rerun()
        if preflight is None:
            st.caption("선택한 배포환경과 진단 유형의 준비 상태를 확인하세요.")
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
        "AI 생성 검토용 초안과 Excel은 검토용 초안입니다. 최종 확인·수정·승인은 담당자가 수행해야 합니다."
    )
    if run.schema_version == "1.0":
        st.warning("출처 없는 기존 AI 초안")
    header, status = st.columns([5, 1])
    header.text(
        f"Run {metadata['scan_run_id']} · Target {metadata['target_set_id']} · "
        f"Deployment {metadata['deployment_id'] or '외부 업로드'} · "
        f"시작 {metadata['started_at']} · 완료 {_text(metadata['completed_at'])}"
    )
    status.markdown(
        f":{'red' if run.status.value == 'FAILED' else 'orange' if run.status.value == 'PARTIAL' else 'green'}-badge["
        f"{_display_enum('run_status', run.status.value)}]"
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
    findings = findings_to_dataframe(run)
    if run.status.value == "PARTIAL":
        full_summary = build_summary(findings)
        error_breakdown = _ai_error_breakdown(run)
        error_summary = (
            " · ".join(f"{code} {count}건" for code, count in error_breakdown.items())
            if error_breakdown
            else "상세 코드 없음"
        )
        st.warning(
            "부분 완료 실행입니다. 필터 적용 전 전체 Finding 기준 · "
            f"스캔 실패 {full_summary['scan_failed']}건 · "
            f"AI 미요청 {full_summary['ai_not_requested']}건 · "
            f"AI 실패 {full_summary['ai_failed']}건 · "
            f"AI 실패 코드 {error_summary} · "
            f"수동 검토 필요 {full_summary['needs_human_review']}건"
        )
    filtered = _apply_filters(findings)
    if findings.empty:
        st.info(
            "이 실행에는 처리된 Finding이 없습니다. 0건 요약과 빈 Excel 초안을 제공합니다."
        )
    elif filtered.empty:
        st.info(
            "활성 필터와 일치하는 Finding이 없습니다. 사이드바에서 필터를 초기화하세요."
        )

    summary = build_summary(filtered)
    card_specs = [
        ("전체 Finding", "total_findings"),
        ("AI 보조 취약", "ai_vulnerable"),
        ("AI 보조 안전", "ai_safe"),
        ("AI 판정 불가", "ai_inconclusive"),
        ("공식근거 확보", "ai_grounded"),
        ("AI 처리 실패", "ai_failed"),
        ("수동 검토 필요", "needs_human_review"),
        ("규칙 취약 의심", "rule_suspected"),
    ]
    st.markdown("<p class='section-label'>활성 범위 요약</p>", unsafe_allow_html=True)
    for column, (label, key) in zip(st.columns(8), card_specs):
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
    evaluation = _render_evaluation(findings, filtered, ground_truth)

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
