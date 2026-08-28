import json
from io import BytesIO

import pandas as pd
from openpyxl import load_workbook

from dashboard.metrics import build_summary
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
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "FAILED",
                "ai_status_reason": "SCAN_FAILED",
                "ai_label": None,
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
    assert workbook.sheetnames == [
        "진단요약",
        "상세결과",
        "조치권고",
        "판정비교",
        "공식근거",
    ]
    for worksheet in workbook.worksheets:
        assert worksheet["A2"].value == "AI 생성 검토용 초안이며 최종 확인이 필요함"
        assert worksheet.auto_filter.ref is not None
        assert worksheet.freeze_panes == "A5"

    detail = workbook["상세결과"]
    assert detail.auto_filter.ref == "A4:AG5"
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
    assert workbook.sheetnames == [
        "진단요약",
        "상세결과",
        "조치권고",
        "판정비교",
        "공식근거",
    ]
    assert workbook["상세결과"].auto_filter.ref == "A4:AG4"


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


def test_excel_exports_official_references_and_grounding_counts() -> None:
    findings = pd.DataFrame(
        [
            {
                "finding_id": "finding-1",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "INCONCLUSIVE",
                "needs_human_review": True,
                "grounding_status": "GROUNDED",
                "claims_json": json.dumps(
                    [
                        {
                            "claim_id": "C1",
                            "claim_type": "IMPACT",
                            "text": "Impact",
                            "evidence_ids": [],
                            "reference_ids": ["R1"],
                        }
                    ]
                ),
                "references_json": json.dumps(
                    [
                        {
                            "reference_id": "R1",
                            "publisher": "OWASP",
                            "title": "=Guide\x00",
                            "version": "2026",
                            "section": "A1",
                            "canonical_url": "https://owasp.org/guide",
                            "document_sha256": "a" * 64,
                            "source_id": "source-1",
                            "file_id": "file-1",
                        }
                    ]
                ),
                "provenance_vector_store_ids_json": '["vs-1"]',
                "provenance_retrieved_file_ids_json": '["file-1"]',
            },
            {
                "finding_id": "finding-2",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "INCONCLUSIVE",
                "needs_human_review": True,
                "grounding_status": "INSUFFICIENT",
            },
        ]
    )
    workbook = load_workbook(
        BytesIO(build_excel_report(findings, {"scan_run_id": "run-1"})),
        data_only=False,
    )
    references = workbook["공식근거"]
    summary_rows = {
        row[0]: row[1]
        for row in workbook["진단요약"].iter_rows(min_row=5, values_only=True)
        if row[0] is not None
    }

    assert references.max_row == 5
    assert [references.cell(5, column).value for column in range(1, 11)] == [
        "finding-1",
        "R1",
        "OWASP",
        "'=Guide\\x00",
        "2026",
        "A1",
        "https://owasp.org/guide",
        "a" * 64,
        "source-1",
        "file-1",
    ]
    assert summary_rows["GROUNDED"] == 1
    assert summary_rows["INSUFFICIENT"] == 1
    assert summary_rows["NOT_APPLICABLE"] == 0


def test_excel_rejects_forged_or_unbound_official_references() -> None:
    findings = pd.DataFrame(
        [
            {
                "finding_id": "forged",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "INCONCLUSIVE",
                "needs_human_review": True,
                "grounding_status": "GROUNDED",
                "claims_json": (
                    '[{"claim_id":"C1","claim_type":"IMPACT","text":"x",'
                    '"evidence_ids":[],"reference_ids":["R1"]}]'
                ),
                "references_json": json.dumps(
                    [
                        {
                            "reference_id": "R1",
                            "publisher": "OWASP",
                            "title": "Forged",
                            "version": "1",
                            "section": "A",
                            "canonical_url": "https://unsafe.example/guide",
                            "document_sha256": "a" * 64,
                            "source_id": "forged",
                            "file_id": "file-forged",
                        }
                    ]
                ),
                "provenance_vector_store_ids_json": '["vs-1"]',
                "provenance_retrieved_file_ids_json": '["file-forged"]',
            }
        ]
    )

    workbook = load_workbook(
        BytesIO(build_excel_report(findings, {"scan_run_id": "run-1"}))
    )

    assert workbook["공식근거"].max_row == 4


def test_partial_report_summary_matches_dashboard_status_counts_and_evaluation() -> (
    None
):
    findings = pd.DataFrame(
        [
            {
                "case_id": "completed",
                "finding_id": "finding-1",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "VULNERABLE",
                "needs_human_review": False,
            },
            {
                "case_id": "not-requested",
                "finding_id": "finding-2",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SAFE",
                "ai_status": "NOT_REQUESTED",
                "ai_label": None,
                "needs_human_review": True,
            },
            {
                "case_id": "ai-failed",
                "finding_id": "finding-3",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "FAILED",
                "ai_label": None,
                "needs_human_review": True,
            },
            {
                "case_id": "scan-failed",
                "finding_id": "finding-4",
                "vuln_type": "SQLI",
                "scan_status": "FAILED",
                "rule_label": None,
                "ai_status": "NOT_REQUESTED",
                "ai_label": None,
                "needs_human_review": True,
            },
        ]
    )
    evaluation = {
        "n_labeled": 4,
        "n_scored": 1,
        "scored_coverage": 0.25,
        "excluded_counts": {
            "ai_inconclusive": 0,
            "ai_not_requested": 1,
            "ai_failed": 1,
            "scan_failed": 1,
            "invalid_ai_label": 0,
        },
    }

    workbook = load_workbook(
        BytesIO(
            build_excel_report(
                findings,
                {"scan_run_id": "partial-run", "status": "PARTIAL"},
                evaluation,
            )
        )
    )
    summary_rows = {
        row[0]: row[1]
        for row in workbook["진단요약"].iter_rows(min_row=5, values_only=True)
        if row[0] is not None
    }
    dashboard_summary = build_summary(findings)

    assert {
        "전체 Finding": summary_rows["전체 Finding"],
        "스캔 완료": summary_rows["스캔 완료"],
        "스캔 실패": summary_rows["스캔 실패"],
        "AI 완료": summary_rows["AI 완료"],
        "AI 미요청": summary_rows["AI 미요청"],
        "AI 보조 취약 판정": summary_rows["AI 보조 취약 판정"],
        "AI 보조 판정 불가": summary_rows["AI 보조 판정 불가"],
        "AI 처리 실패": summary_rows["AI 처리 실패"],
        "수동 검토 필요": summary_rows["수동 검토 필요"],
        "규칙 취약 의심": summary_rows["규칙 취약 의심"],
    } == {
        "전체 Finding": dashboard_summary["total_findings"],
        "스캔 완료": dashboard_summary["scan_completed"],
        "스캔 실패": dashboard_summary["scan_failed"],
        "AI 완료": dashboard_summary["ai_completed"],
        "AI 미요청": dashboard_summary["ai_not_requested"],
        "AI 보조 취약 판정": dashboard_summary["ai_vulnerable"],
        "AI 보조 판정 불가": dashboard_summary["ai_inconclusive"],
        "AI 처리 실패": dashboard_summary["ai_failed"],
        "수동 검토 필요": dashboard_summary["needs_human_review"],
        "규칙 취약 의심": dashboard_summary["rule_suspected"],
    }
    assert {
        key: summary_rows[key]
        for key in (
            "evaluation.n_labeled",
            "evaluation.n_scored",
            "evaluation.scored_coverage",
            "evaluation.excluded_counts.ai_inconclusive",
            "evaluation.excluded_counts.ai_not_requested",
            "evaluation.excluded_counts.ai_failed",
            "evaluation.excluded_counts.scan_failed",
            "evaluation.excluded_counts.invalid_ai_label",
        )
    } == {
        "evaluation.n_labeled": 4,
        "evaluation.n_scored": 1,
        "evaluation.scored_coverage": 0.25,
        "evaluation.excluded_counts.ai_inconclusive": 0,
        "evaluation.excluded_counts.ai_not_requested": 1,
        "evaluation.excluded_counts.ai_failed": 1,
        "evaluation.excluded_counts.scan_failed": 1,
        "evaluation.excluded_counts.invalid_ai_label": 0,
    }
