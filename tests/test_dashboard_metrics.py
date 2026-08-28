from __future__ import annotations

import pandas as pd
import pytest

from analysis.models import GroundTruthSet
from dashboard.metrics import (
    build_ai_verdict_counts,
    build_evaluation,
    build_rule_ai_comparison,
    build_summary,
    build_type_counts,
)


def _findings() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "target_set_id": "lab-v1",
                "case_id": "tp",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "VULNERABLE",
                "needs_human_review": False,
            },
            {
                "target_set_id": "lab-v1",
                "case_id": "fp",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "VULNERABLE",
                "needs_human_review": True,
            },
            {
                "target_set_id": "lab-v1",
                "case_id": "tn",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SAFE",
                "ai_status": "COMPLETED",
                "ai_label": "SAFE",
                "needs_human_review": False,
            },
            {
                "target_set_id": "lab-v1",
                "case_id": "fn",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SAFE",
                "ai_status": "COMPLETED",
                "ai_label": "SAFE",
                "needs_human_review": False,
            },
            {
                "target_set_id": "lab-v1",
                "case_id": "inconclusive",
                "vuln_type": "SQLI",
                "scan_status": "COMPLETED",
                "rule_label": "SUSPECTED",
                "ai_status": "COMPLETED",
                "ai_label": "INCONCLUSIVE",
                "needs_human_review": True,
            },
            {
                "target_set_id": "lab-v1",
                "case_id": "failed",
                "vuln_type": "XSS",
                "scan_status": "FAILED",
                "rule_label": None,
                "ai_status": "FAILED",
                "ai_label": None,
                "needs_human_review": True,
            },
        ]
    )


def _ground_truth(cases: list[tuple[str, str, str]] | None = None) -> GroundTruthSet:
    cases = cases or [
        ("tp", "SQLI", "VULNERABLE"),
        ("fp", "SQLI", "SAFE"),
        ("tn", "SQLI", "SAFE"),
        ("fn", "SQLI", "VULNERABLE"),
        ("inconclusive", "SQLI", "VULNERABLE"),
    ]
    return GroundTruthSet.model_validate(
        {
            "schema_version": "1.0",
            "assessment_set_id": "assessment-v1",
            "target_set_id": "lab-v1",
            "assessor_tool": "Burp Suite",
            "created_at": "2026-08-27T10:00:00+09:00",
            "cases": [
                {
                    "case_id": case_id,
                    "vuln_type": vuln_type,
                    "label": label,
                    "evidence_summary": "Verified by assessor.",
                    "assessed_at": "2026-08-27T09:55:00+09:00",
                }
                for case_id, vuln_type, label in cases
            ],
        }
    )


def test_aggregations_follow_dashboard_rules() -> None:
    findings = _findings()

    assert build_summary(findings) == {
        "total_findings": 6,
        "ai_vulnerable": 2,
        "ai_inconclusive": 1,
        "scan_completed": 5,
        "scan_failed": 1,
        "ai_completed": 5,
        "ai_not_requested": 0,
        "ai_failed": 1,
        "needs_human_review": 3,
        "rule_suspected": 3,
    }
    assert build_type_counts(findings).to_dict("records") == [
        {"label": "SQLI", "count": 5},
        {"label": "XSS", "count": 1},
    ]
    assert build_ai_verdict_counts(findings).to_dict("records") == [
        {"label": "FAILED", "count": 1},
        {"label": "INCONCLUSIVE", "count": 1},
        {"label": "SAFE", "count": 2},
        {"label": "VULNERABLE", "count": 2},
    ]
    assert build_rule_ai_comparison(findings).to_dict("records") == [
        {"rule_label": "FAILED", "ai_label": "FAILED", "count": 1},
        {"rule_label": "SAFE", "ai_label": "SAFE", "count": 2},
        {"rule_label": "SUSPECTED", "ai_label": "INCONCLUSIVE", "count": 1},
        {"rule_label": "SUSPECTED", "ai_label": "VULNERABLE", "count": 2},
    ]


def test_empty_findings_are_safe() -> None:
    empty = pd.DataFrame()

    assert build_summary(empty) == {
        "total_findings": 0,
        "ai_vulnerable": 0,
        "ai_inconclusive": 0,
        "scan_completed": 0,
        "scan_failed": 0,
        "ai_completed": 0,
        "ai_not_requested": 0,
        "ai_failed": 0,
        "needs_human_review": 0,
        "rule_suspected": 0,
    }
    assert build_type_counts(empty).empty
    assert build_ai_verdict_counts(empty).empty
    assert build_rule_ai_comparison(empty).empty


def test_summary_counts_only_canonical_statuses() -> None:
    findings = _findings().iloc[:2].copy()
    findings.loc[0, "scan_status"] = None
    findings.loc[0, "ai_status"] = "UNKNOWN"
    findings.loc[1, "scan_status"] = "completed"
    findings.loc[1, "ai_status"] = "failed"

    summary = build_summary(findings)

    assert {
        key: summary[key]
        for key in (
            "scan_completed",
            "scan_failed",
            "ai_completed",
            "ai_not_requested",
            "ai_failed",
        )
    } == {
        "scan_completed": 0,
        "scan_failed": 0,
        "ai_completed": 0,
        "ai_not_requested": 0,
        "ai_failed": 0,
    }
    assert build_ai_verdict_counts(findings).empty
    assert build_rule_ai_comparison(findings).empty


def test_evaluation_reports_cohort_metrics_exclusions_and_error_cases() -> None:
    evaluation = build_evaluation(_findings(), _ground_truth())

    assert evaluation["accuracy"] == pytest.approx(0.5)
    assert evaluation["precision"] == pytest.approx(0.5)
    assert evaluation["recall"] == pytest.approx(0.5)
    assert {key: evaluation[key] for key in ("tp", "fp", "tn", "fn")} == {
        "tp": 1,
        "fp": 1,
        "tn": 1,
        "fn": 1,
    }
    assert evaluation["n_labeled"] == 5
    assert evaluation["n_scored"] == 4
    assert evaluation["support"] == {"vulnerable": 3, "safe": 2}
    assert evaluation["scored_coverage"] == pytest.approx(0.8)
    assert evaluation["excluded_counts"] == {
        "scan_failed": 0,
        "ai_inconclusive": 1,
        "ai_not_requested": 0,
        "ai_failed": 0,
        "invalid_ai_label": 0,
    }
    assert evaluation["false_positive_cases"] == ["fp"]
    assert evaluation["false_negative_cases"] == ["fn"]
    assert evaluation["annotations"] == [
        {
            "target_set_id": "lab-v1",
            "case_id": "tp",
            "ground_truth_label": "VULNERABLE",
            "evaluation_exclusion_reason": None,
        },
        {
            "target_set_id": "lab-v1",
            "case_id": "fp",
            "ground_truth_label": "SAFE",
            "evaluation_exclusion_reason": None,
        },
        {
            "target_set_id": "lab-v1",
            "case_id": "tn",
            "ground_truth_label": "SAFE",
            "evaluation_exclusion_reason": None,
        },
        {
            "target_set_id": "lab-v1",
            "case_id": "fn",
            "ground_truth_label": "VULNERABLE",
            "evaluation_exclusion_reason": None,
        },
        {
            "target_set_id": "lab-v1",
            "case_id": "inconclusive",
            "ground_truth_label": "VULNERABLE",
            "evaluation_exclusion_reason": "AI_INCONCLUSIVE",
        },
    ]


def test_evaluation_excludes_failed_scans_before_ai_status() -> None:
    findings = _findings()
    failed_scan = findings.iloc[0].copy()
    failed_scan["case_id"] = "scan-failed"
    failed_scan["scan_status"] = "FAILED"
    failed_scan["ai_status"] = "NOT_REQUESTED"
    failed_scan["ai_label"] = None
    findings = pd.concat([findings, pd.DataFrame([failed_scan])], ignore_index=True)

    evaluation = build_evaluation(
        findings,
        _ground_truth(
            [
                ("tp", "SQLI", "VULNERABLE"),
                ("scan-failed", "SQLI", "SAFE"),
            ]
        ),
    )

    assert evaluation["n_scored"] == 1
    assert evaluation["excluded_counts"] == {
        "scan_failed": 1,
        "ai_inconclusive": 0,
        "ai_not_requested": 0,
        "ai_failed": 0,
        "invalid_ai_label": 0,
    }
    assert evaluation["annotations"][1]["evaluation_exclusion_reason"] == "SCAN_FAILED"


def test_evaluation_returns_none_for_zero_precision_and_recall_denominators() -> None:
    findings = _findings().iloc[:2].copy()
    findings["ai_label"] = "SAFE"
    truth = _ground_truth([("tp", "SQLI", "SAFE"), ("fp", "SQLI", "SAFE")])

    evaluation = build_evaluation(findings, truth)

    assert evaluation["precision"] is None
    assert evaluation["recall"] is None
    assert evaluation["accuracy"] == 1.0


def test_evaluation_rejects_missing_duplicate_and_type_mismatched_joins() -> None:
    findings = _findings()

    with pytest.raises(ValueError, match="missing"):
        build_evaluation(findings, _ground_truth([("unknown", "SQLI", "SAFE")]))

    with pytest.raises(ValueError, match="duplicate"):
        build_evaluation(
            pd.concat([findings.iloc[:1], findings.iloc[:1]]),
            _ground_truth([("tp", "SQLI", "SAFE")]),
        )

    with pytest.raises(ValueError, match="vuln_type"):
        build_evaluation(findings, _ground_truth([("tp", "XSS", "VULNERABLE")]))
