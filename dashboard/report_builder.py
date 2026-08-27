"""Excel report generation utilities."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from dashboard.metrics import build_summary

_DRAFT_WARNING = "AI 생성 검토용 초안이며 최종 확인이 필요함"
_TITLE_FILL = PatternFill("solid", fgColor="17365D")
_HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
_WARNING_FILL = PatternFill("solid", fgColor="FFF2CC")
_AI_FAILURE_FILL = PatternFill("solid", fgColor="FCE4D6")
_HUMAN_REVIEW_FILL = PatternFill("solid", fgColor="FFF2CC")
_WHITE_BOLD_FONT = Font(color="FFFFFF", bold=True)
_BOLD_FONT = Font(bold=True)

_DETAIL_COLUMNS = (
    ("case_id", "케이스 ID"),
    ("finding_id", "Finding ID"),
    ("scanned_at", "스캔 시각"),
    ("vuln_type", "취약점 유형"),
    ("url", "URL"),
    ("method", "메서드"),
    ("input_location", "입력 위치"),
    ("parameter", "파라미터"),
    ("payload", "Payload"),
    ("scan_status", "스캔 상태"),
    ("http_status", "HTTP 상태"),
    ("elapsed_ms", "응답 시간(ms)"),
    ("baseline_elapsed_ms", "기준 응답 시간(ms)"),
    ("rule_label", "규칙 판정"),
    ("rule_reason", "규칙 근거"),
    ("scan_evidence", "스캔 증거"),
    ("scan_error", "스캔 오류"),
    ("ai_status", "AI 상태"),
    ("ai_status_reason", "AI 상태 사유"),
    ("ai_label", "AI 판정"),
    ("confidence", "AI 신뢰도"),
    ("needs_human_review", "수동 검토 필요"),
    ("assessment_summary", "AI 분석 요약"),
    ("source_evidence", "AI 소스 증거"),
    ("ai_error", "AI 오류"),
)
_RECOMMENDATION_COLUMNS = (
    ("case_id", "케이스 ID"),
    ("finding_id", "Finding ID"),
    ("vuln_type", "취약점 유형"),
    ("url", "URL"),
    ("ai_status", "AI 상태"),
    ("ai_label", "AI 판정"),
    ("needs_human_review", "수동 검토 필요"),
    ("impact", "예상 영향도"),
    ("recommendation", "조치 권고"),
    ("manual_check", "수동 확인 방법"),
    ("report_paragraph", "보고서 문장 초안"),
    ("ai_error", "AI 오류"),
)
_COMPARISON_COLUMNS = (
    ("case_id", "케이스 ID"),
    ("finding_id", "Finding ID"),
    ("vuln_type", "취약점 유형"),
    ("rule_label", "규칙 판정"),
    ("ai_status", "AI 상태"),
    ("ai_label", "AI 판정"),
    ("ground_truth_label", "정답 판정"),
    ("rule_ai_match", "규칙-AI 일치"),
    ("evaluation_exclusion_reason", "평가 제외 사유"),
    ("needs_human_review", "수동 검토 필요"),
)
_ILLEGAL_XML_C0 = frozenset(
    chr(code) for code in (*range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20))
)


def _safe_cell_value(value: Any) -> Any:
    """Return a cell value that cannot be interpreted as an Excel formula."""

    if value is None:
        return None
    if isinstance(value, str):
        escaped = "".join(
            f"\\x{ord(character):02X}"
            if character in _ILLEGAL_XML_C0
            else character
            for character in value
        )
        return f"'{escaped}" if escaped.startswith(("=", "+", "-", "@")) else escaped
    if isinstance(value, (datetime, pd.Timestamp)):
        return value.isoformat()
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def _metadata_value(metadata: Mapping[str, Any] | Any, key: str) -> Any:
    if isinstance(metadata, Mapping):
        return metadata.get(key)
    return getattr(metadata, key, None)


def _is_true(value: Any) -> bool:
    try:
        return not pd.isna(value) and bool(value)
    except (TypeError, ValueError):
        return False


def _write_sheet_preamble(worksheet: Any, title: str, width: int) -> int:
    worksheet.cell(1, 1, title).font = Font(color="FFFFFF", bold=True, size=14)
    worksheet.cell(1, 1).fill = _TITLE_FILL
    worksheet.cell(1, 2, _safe_cell_value(datetime.now(timezone.utc).isoformat()))
    worksheet.cell(1, 2).font = _WHITE_BOLD_FONT
    worksheet.cell(1, 2).fill = _TITLE_FILL
    worksheet.merge_cells(
        start_row=2, start_column=1, end_row=2, end_column=max(width, 1)
    )
    warning = worksheet.cell(2, 1, _DRAFT_WARNING)
    warning.font = _BOLD_FONT
    warning.fill = _WARNING_FILL
    warning.alignment = Alignment(wrap_text=True)
    return 4


def _fit_columns(worksheet: Any) -> None:
    for column in range(1, worksheet.max_column + 1):
        values = (
            len(str(cell.value)) if cell.value is not None else 0
            for cell in worksheet[get_column_letter(column)]
        )
        worksheet.column_dimensions[get_column_letter(column)].width = min(
            max(max(values, default=0) + 2, 12), 48
        )


def _write_table(
    worksheet: Any,
    columns: tuple[tuple[str, str], ...],
    rows: list[dict[str, Any]],
    title: str,
) -> None:
    header_row = _write_sheet_preamble(worksheet, title, len(columns))
    for column_index, (_, label) in enumerate(columns, start=1):
        cell = worksheet.cell(header_row, column_index, _safe_cell_value(label))
        cell.font = _WHITE_BOLD_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = Alignment(wrap_text=True)

    for row_index, row in enumerate(rows, start=header_row + 1):
        for column_index, (key, _) in enumerate(columns, start=1):
            cell = worksheet.cell(
                row_index, column_index, _safe_cell_value(row.get(key))
            )
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        fill = (
            _AI_FAILURE_FILL
            if str(row.get("ai_status", "")).upper() == "FAILED"
            else _HUMAN_REVIEW_FILL
            if _is_true(row.get("needs_human_review"))
            else None
        )
        if fill is not None:
            for cell in worksheet[row_index]:
                cell.fill = fill

    worksheet.freeze_panes = f"A{header_row + 1}"
    worksheet.auto_filter.ref = f"A{header_row}:{get_column_letter(len(columns))}{max(header_row, header_row + len(rows))}"
    _fit_columns(worksheet)


def _flatten_evaluation(
    evaluation: Mapping[str, Any], prefix: str = ""
) -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    for key, value in evaluation.items():
        if key == "annotations":
            continue
        label = f"{prefix}{key}"
        if isinstance(value, Mapping):
            values.extend(_flatten_evaluation(value, f"{label}."))
        elif isinstance(value, (list, tuple, set)):
            values.append((label, ", ".join(str(item) for item in value)))
        else:
            values.append((label, value))
    return values


def build_excel_report(
    df: pd.DataFrame,
    run_metadata: Mapping[str, Any] | Any,
    evaluation: Mapping[str, Any] | None = None,
) -> bytes:
    """Build an in-memory, review-only Excel workbook for the filtered findings."""

    frame = df.copy() if isinstance(df, pd.DataFrame) else pd.DataFrame(df)
    rows = frame.to_dict(orient="records")
    workbook = Workbook()
    summary = workbook.active
    summary.title = "진단요약"

    dashboard_summary = build_summary(frame)
    summary_rows = [
        ("scan_run_id", _metadata_value(run_metadata, "scan_run_id")),
        ("target_set_id", _metadata_value(run_metadata, "target_set_id")),
        ("run_status", _metadata_value(run_metadata, "status")),
        ("started_at", _metadata_value(run_metadata, "started_at")),
        ("completed_at", _metadata_value(run_metadata, "completed_at")),
        ("필터 결과 건수", len(frame)),
        ("전체 Finding", dashboard_summary["total_findings"]),
        ("AI 취약 판정", dashboard_summary["ai_vulnerable"]),
        ("AI 판정 불가", dashboard_summary["ai_inconclusive"]),
        ("AI 처리 실패", dashboard_summary["ai_failed"]),
        ("수동 검토 필요", dashboard_summary["needs_human_review"]),
        ("규칙 취약 의심", dashboard_summary["rule_suspected"]),
    ]
    if evaluation:
        summary_rows.extend(
            [
                ("평가 라벨 모수", evaluation.get("n_labeled")),
                ("평가 채점 모수", evaluation.get("n_scored")),
            ]
        )
        summary_rows.extend(_flatten_evaluation(evaluation, "evaluation."))
    summary_data = [{"항목": key, "값": value} for key, value in summary_rows]
    _write_table(
        summary, (("항목", "항목"), ("값", "값")), summary_data, "진단 결과 요약"
    )

    detail = workbook.create_sheet("상세결과")
    _write_table(detail, _DETAIL_COLUMNS, rows, "진단 상세 결과")

    recommendations = workbook.create_sheet("조치권고")
    _write_table(recommendations, _RECOMMENDATION_COLUMNS, rows, "조치 권고")

    comparison_rows = []
    for row in rows:
        comparison = dict(row)
        comparison["rule_ai_match"] = (
            "일치"
            if comparison.get("scan_status") == "COMPLETED"
            and comparison.get("ai_status") == "COMPLETED"
            and (
                (comparison.get("rule_label") == "SUSPECTED"
                 and comparison.get("ai_label") == "VULNERABLE")
                or (comparison.get("rule_label") == "SAFE"
                    and comparison.get("ai_label") == "SAFE")
            )
            else "불일치"
            if comparison.get("scan_status") == "COMPLETED"
            and comparison.get("ai_status") == "COMPLETED"
            and comparison.get("rule_label") in {"SUSPECTED", "SAFE"}
            and comparison.get("ai_label") in {"VULNERABLE", "SAFE"}
            else None
        )
        comparison_rows.append(comparison)
    comparison = workbook.create_sheet("판정비교")
    _write_table(comparison, _COMPARISON_COLUMNS, comparison_rows, "판정 비교")

    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
