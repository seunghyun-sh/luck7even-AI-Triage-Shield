from io import BytesIO

import pandas as pd
from openpyxl import load_workbook

from dashboard.report_builder import build_excel_report


def test_excel_report_has_safe_review_sheets_and_round_trips() -> None:
    findings = pd.DataFrame(
        [
            {
                "case_id": "case-1",
                "finding_id": "finding-1",
                "vuln_type": "SQLI",
                "url": "=https://example.test/search",
                "payload": "+OR 1=1",
                "scan_evidence": "@evidence",
                "scan_error": "-scanner error",
                "rule_label": "SUSPECTED",
                "ai_status": "FAILED",
                "ai_status_reason": "SCAN_FAILED",
                "needs_human_review": True,
                "ai_error": "=AI unavailable",
                "recommendation": "=review manually",
                "assessment_summary": "bad\x00value",
                "ground_truth_label": None,
                "evaluation_exclusion_reason": "NO_GROUND_TRUTH",
            }
        ]
    )

    report = build_excel_report(
        findings,
        {"scan_run_id": "run-1", "target_set_id": "targets-1", "status": "PARTIAL"},
        {"accuracy": 0.5, "n_labeled": 1, "n_scored": 1},
    )

    workbook = load_workbook(BytesIO(report), data_only=False)
    assert workbook.sheetnames == ["진단요약", "상세결과", "조치권고", "판정비교"]
    for worksheet in workbook.worksheets:
        assert worksheet["A2"].value == "AI 생성 검토용 초안이며 최종 확인이 필요함"
        assert worksheet.auto_filter.ref is not None
        assert worksheet.freeze_panes == "A5"

    detail = workbook["상세결과"]
    assert detail.auto_filter.ref == "A4:Y5"
    assert detail["E5"].value == "'=https://example.test/search"
    assert detail["I5"].value == "'+OR 1=1"
    assert detail["P5"].value == "'@evidence"
    assert detail["Q5"].value == "'-scanner error"
    assert detail["S5"].value == "SCAN_FAILED"
    assert detail["W5"].value == "bad\\x00value"
    assert all(
        cell.data_type != "f"
        for worksheet in workbook.worksheets
        for row in worksheet.iter_rows()
        for cell in row
    )


def test_excel_report_supports_an_empty_filtered_result() -> None:
    report = build_excel_report(pd.DataFrame(), {"scan_run_id": "empty-run"})

    workbook = load_workbook(BytesIO(report))
    assert workbook.sheetnames == ["진단요약", "상세결과", "조치권고", "판정비교"]
    assert workbook["상세결과"].auto_filter.ref == "A4:Y4"


def test_excel_comparison_uses_semantic_rule_ai_matches() -> None:
    findings = pd.DataFrame(
        [
            {
                "case_id": "suspected",
                "finding_id": "finding-1",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "VULNERABLE",
                "needs_human_review": False,
            },
            {
                "case_id": "safe",
                "finding_id": "finding-2",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SAFE",
                "ai_status": "COMPLETED",
                "ai_label": "SAFE",
                "needs_human_review": False,
            },
            {
                "case_id": "unscored",
                "finding_id": "finding-3",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "NOT_REQUESTED",
                "ai_label": None,
                "needs_human_review": True,
            },
        ]
    )

    workbook = load_workbook(
        BytesIO(build_excel_report(findings, {"scan_run_id": "run-1"}))
    )
    comparison = workbook["판정비교"]
    assert [comparison.cell(row, 8).value for row in range(5, 8)] == [
        "일치",
        "일치",
        None,
    ]
