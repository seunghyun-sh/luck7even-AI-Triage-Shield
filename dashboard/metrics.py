"""Deterministic metrics and chart-ready aggregations."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pandas as pd

from analysis.models import AiStatus, ScanStatus

_BINARY_LABELS = frozenset({"VULNERABLE", "SAFE"})
_EVALUATION_KEY = ["target_set_id", "case_id"]
_SCAN_COMPLETED = ScanStatus.COMPLETED.value
_SCAN_FAILED = ScanStatus.FAILED.value
_AI_COMPLETED = AiStatus.COMPLETED.value
_AI_NOT_REQUESTED = AiStatus.NOT_REQUESTED.value
_AI_FAILED = AiStatus.FAILED.value


def _empty_counts(label_column: str) -> pd.DataFrame:
    return pd.DataFrame(columns=[label_column, "count"])


def _require_columns(df: pd.DataFrame, columns: Iterable[str]) -> None:
    """Reject malformed non-empty view models while permitting an empty frame."""

    missing = sorted(set(columns).difference(df.columns))
    if missing and not df.empty:
        raise ValueError(
            f"Findings data is missing required columns: {', '.join(missing)}."
        )


def _ai_verdicts(df: pd.DataFrame) -> pd.Series:
    """Return chart labels without treating null AI labels as a verdict."""

    _require_columns(df, ["ai_status", "ai_label"])
    if df.empty:
        return pd.Series(dtype="object", index=df.index)

    status = df["ai_status"]
    label = df["ai_label"]
    return pd.Series(
        [
            value
            if current_status == _AI_COMPLETED
            and value in _BINARY_LABELS | {"INCONCLUSIVE"}
            else None
            if current_status == _AI_COMPLETED
            else current_status
            if current_status in {_AI_NOT_REQUESTED, _AI_FAILED}
            else None
            for current_status, value in zip(status, label, strict=True)
        ],
        index=df.index,
        name="ai_verdict",
    )


def build_summary(df: pd.DataFrame) -> dict[str, int]:
    """Build the dashboard KPI values for an already-filtered findings frame."""

    _require_columns(
        df,
        ["ai_status", "ai_label", "needs_human_review", "scan_status", "rule_label"],
    )
    if df.empty:
        return {
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

    return {
        "total_findings": len(df),
        "ai_vulnerable": int(
            (
                (df["ai_status"] == _AI_COMPLETED)
                & (df["ai_label"] == "VULNERABLE")
            ).sum()
        ),
        "ai_inconclusive": int(
            (
                (df["ai_status"] == _AI_COMPLETED) & (df["ai_label"] == "INCONCLUSIVE")
            ).sum()
        ),
        "scan_completed": int((df["scan_status"] == _SCAN_COMPLETED).sum()),
        "scan_failed": int((df["scan_status"] == _SCAN_FAILED).sum()),
        "ai_completed": int((df["ai_status"] == _AI_COMPLETED).sum()),
        "ai_not_requested": int((df["ai_status"] == _AI_NOT_REQUESTED).sum()),
        "ai_failed": int((df["ai_status"] == _AI_FAILED).sum()),
        "needs_human_review": int(
            df["needs_human_review"].map(lambda value: value is True).sum()
        ),
        "rule_suspected": int(
            (
                (df["scan_status"] == _SCAN_COMPLETED)
                & (df["rule_label"] == "SUSPECTED")
            ).sum()
        ),
    }


def build_type_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Count findings by vulnerability type in a stable chart-ready shape."""

    _require_columns(df, ["vuln_type"])
    if df.empty:
        return _empty_counts("label")
    return (
        df.groupby("vuln_type", dropna=True)
        .size()
        .rename("count")
        .reset_index()
        .rename(columns={"vuln_type": "label"})
        .sort_values("label", kind="stable")
        .reset_index(drop=True)
    )


def build_ai_verdict_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Count completed AI labels and non-completed AI states separately."""

    verdicts = _ai_verdicts(df)
    if verdicts.empty:
        return _empty_counts("label")
    return (
        verdicts.groupby(verdicts, dropna=True)
        .size()
        .rename("count")
        .reset_index(name="count")
        .rename(columns={"index": "label", "ai_verdict": "label"})
        .sort_values("label", kind="stable")
        .reset_index(drop=True)
    )


def build_rule_ai_comparison(df: pd.DataFrame) -> pd.DataFrame:
    """Count rule verdict and AI verdict combinations for the comparison chart."""

    _require_columns(df, ["scan_status", "rule_label", "ai_status", "ai_label"])
    if df.empty:
        return pd.DataFrame(columns=["rule_label", "ai_label", "count"])

    rule_verdict = df["rule_label"].where(
        df["scan_status"] == _SCAN_COMPLETED,
        df["scan_status"].where(df["scan_status"] == _SCAN_FAILED),
    )
    comparison = pd.DataFrame(
        {"rule_label": rule_verdict, "ai_label": _ai_verdicts(df)}
    ).dropna(subset=["rule_label", "ai_label"])
    return (
        comparison.groupby(["rule_label", "ai_label"], dropna=True)
        .size()
        .rename("count")
        .reset_index()
        .sort_values(["rule_label", "ai_label"], kind="stable")
        .reset_index(drop=True)
    )


def _ground_truth_frame(ground_truth: Any) -> pd.DataFrame:
    """Adapt the validated GroundTruthSet model to the evaluation join shape."""

    try:
        target_set_id = ground_truth.target_set_id
        cases = ground_truth.cases
    except AttributeError as error:
        raise ValueError("Ground truth must be a validated GroundTruthSet.") from error

    return pd.DataFrame(
        [
            {
                "target_set_id": target_set_id,
                "case_id": case.case_id,
                "ground_truth_vuln_type": getattr(
                    case.vuln_type, "value", case.vuln_type
                ),
                "ground_truth_label": getattr(case.label, "value", case.label),
            }
            for case in cases
        ],
        columns=[*_EVALUATION_KEY, "ground_truth_vuln_type", "ground_truth_label"],
    )


def _validate_evaluation_inputs(df: pd.DataFrame, truth: pd.DataFrame) -> None:
    _require_columns(
        df,
        [*_EVALUATION_KEY, "vuln_type", "scan_status", "ai_status", "ai_label"],
    )

    if df.duplicated(_EVALUATION_KEY).any():
        raise ValueError(
            "Processed findings contain duplicate (target_set_id, case_id) keys."
        )
    if truth.duplicated(_EVALUATION_KEY).any():
        raise ValueError(
            "Ground truth contains duplicate (target_set_id, case_id) keys."
        )

    unsupported = truth.loc[truth["ground_truth_vuln_type"] != "SQLI"]
    if not unsupported.empty:
        raise ValueError("Ground-truth vuln_type must be SQLI.")

    processed_keys = pd.MultiIndex.from_frame(df[_EVALUATION_KEY])
    truth_keys = pd.MultiIndex.from_frame(truth[_EVALUATION_KEY])
    if not truth_keys.isin(processed_keys).all():
        raise ValueError("Ground truth contains cases missing from processed findings.")


def build_evaluation(df: pd.DataFrame, ground_truth: Any) -> dict[str, Any]:
    """Evaluate binary completed AI SQLi verdicts against validated ground truth.

    Unlabeled processed findings are intentionally not an error: a ground-truth set
    may cover only part of a scan.  Every supplied ground-truth case must, however,
    have exactly one processed finding.
    """

    if df.empty:
        df = df.reindex(
            columns=df.columns.union(
                [
                    *_EVALUATION_KEY,
                    "vuln_type",
                    "scan_status",
                    "ai_status",
                    "ai_label",
                ]
            )
        )
    truth = _ground_truth_frame(ground_truth)
    _validate_evaluation_inputs(df, truth)
    if truth.empty:
        return {
            "accuracy": None,
            "precision": None,
            "recall": None,
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "n_labeled": 0,
            "n_scored": 0,
            "support": {"vulnerable": 0, "safe": 0},
            "scored_coverage": None,
            "excluded_counts": {
                "scan_failed": 0,
                "ai_inconclusive": 0,
                "ai_not_requested": 0,
                "ai_failed": 0,
                "invalid_ai_label": 0,
            },
            "false_positive_cases": [],
            "false_negative_cases": [],
            "annotations": [],
        }

    joined = truth.merge(
        df[
            [
                *_EVALUATION_KEY,
                "vuln_type",
                "scan_status",
                "ai_status",
                "ai_label",
            ]
        ],
        on=_EVALUATION_KEY,
        how="left",
        validate="one_to_one",
    )
    if (joined["vuln_type"] != joined["ground_truth_vuln_type"]).any():
        raise ValueError("Processed finding vuln_type does not match ground truth.")

    scored = (
        (joined["scan_status"] == _SCAN_COMPLETED)
        & (joined["ai_status"] == _AI_COMPLETED)
        & joined["ai_label"].isin(_BINARY_LABELS)
    )
    exclusion_reason = pd.Series(None, index=joined.index, dtype="object")
    exclusion_reason.loc[joined["scan_status"] == _SCAN_FAILED] = "SCAN_FAILED"
    exclusion_reason.loc[
        exclusion_reason.isna()
        & (joined["ai_status"] == _AI_COMPLETED)
        & (joined["ai_label"] == "INCONCLUSIVE")
    ] = "AI_INCONCLUSIVE"
    exclusion_reason.loc[
        exclusion_reason.isna() & (joined["ai_status"] == _AI_NOT_REQUESTED)
    ] = "AI_NOT_REQUESTED"
    exclusion_reason.loc[
        exclusion_reason.isna() & (joined["ai_status"] == _AI_FAILED)
    ] = "AI_FAILED"
    exclusion_reason.loc[exclusion_reason.isna() & ~scored] = "INVALID_AI_LABEL"
    excluded = {
        "scan_failed": int((exclusion_reason == "SCAN_FAILED").sum()),
        "ai_inconclusive": int((exclusion_reason == "AI_INCONCLUSIVE").sum()),
        "ai_not_requested": int((exclusion_reason == "AI_NOT_REQUESTED").sum()),
        "ai_failed": int((exclusion_reason == "AI_FAILED").sum()),
        "invalid_ai_label": int((exclusion_reason == "INVALID_AI_LABEL").sum()),
    }
    scored_rows = joined.loc[scored]
    truth_positive = scored_rows["ground_truth_label"] == "VULNERABLE"
    predicted_positive = scored_rows["ai_label"] == "VULNERABLE"
    tp = int((truth_positive & predicted_positive).sum())
    fp = int((~truth_positive & predicted_positive).sum())
    tn = int((~truth_positive & ~predicted_positive).sum())
    fn = int((truth_positive & ~predicted_positive).sum())
    n_labeled = len(joined)
    n_scored = len(scored_rows)

    return {
        "accuracy": (tp + tn) / n_scored if n_scored else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n_labeled": n_labeled,
        "n_scored": n_scored,
        "support": {
            "vulnerable": int((joined["ground_truth_label"] == "VULNERABLE").sum()),
            "safe": int((joined["ground_truth_label"] == "SAFE").sum()),
        },
        "scored_coverage": n_scored / n_labeled if n_labeled else None,
        "excluded_counts": excluded,
        "false_positive_cases": scored_rows.loc[
            ~truth_positive & predicted_positive, "case_id"
        ].tolist(),
        "false_negative_cases": scored_rows.loc[
            truth_positive & ~predicted_positive, "case_id"
        ].tolist(),
        "annotations": joined.assign(
            evaluation_exclusion_reason=exclusion_reason.where(~scored, None)
        )[
            [
                "target_set_id",
                "case_id",
                "ground_truth_label",
                "evaluation_exclusion_reason",
            ]
        ].to_dict("records"),
    }
