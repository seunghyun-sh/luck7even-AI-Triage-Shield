"""Command-line entry point for the scan-to-triage pipeline."""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Callable
from typing import Any

from orchestration.pipeline import PipelineOrchestrator, TargetValidationError
from orchestration.run_store import RunAlreadyActiveError, RunStore


class ComponentUnavailableError(RuntimeError):
    """Raised when a production scanner or triage component is not installed."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the web vulnerability assessment pipeline."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="Run a validated diagnostic pipeline.")
    run.add_argument(
        "--target-set-id", required=True, help="Registered target set identifier."
    )
    run.add_argument(
        "--deployment-id", required=True, help="Registered deployment identifier."
    )
    run.add_argument(
        "--types",
        nargs="+",
        required=True,
        choices=("XSS", "SQLI"),
        help="Vulnerability types to scan.",
    )
    return parser.parse_args(argv)


def _component_callable(module_name: str, attribute: str) -> Callable[..., Any]:
    try:
        component = getattr(importlib.import_module(module_name), attribute)
    except Exception as error:
        raise ComponentUnavailableError(
            "A required pipeline component is unavailable."
        ) from error
    if not callable(component):
        raise ComponentUnavailableError("A required pipeline component is unavailable.")
    return component


def _unrequested_scanner(*args: object, **kwargs: object) -> None:
    raise RuntimeError("An unrequested scanner was invoked.")


def _load_components(
    vuln_types: list[str],
) -> tuple[Callable[..., Any], Callable[..., Any], Callable[..., Any]]:
    return (
        _component_callable("scanners.xss", "scan")
        if "XSS" in vuln_types
        else _unrequested_scanner,
        _component_callable("scanners.sqli", "scan")
        if "SQLI" in vuln_types
        else _unrequested_scanner,
        _component_callable("analysis.ai_triage", "triage"),
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        xss_scanner, sqli_scanner, triage = _load_components(args.types)
    except ComponentUnavailableError:
        print("A required pipeline component is unavailable.", file=sys.stderr)
        return 5

    orchestrator = PipelineOrchestrator(
        RunStore(),
        xss_scanner=xss_scanner,
        sqli_scanner=sqli_scanner,
        triage=triage,
    )
    try:
        final_status = orchestrator.run(
            args.target_set_id,
            args.deployment_id,
            args.types,
            on_run_created=print,
        )
    except TargetValidationError:
        print("Unable to validate the target manifest.", file=sys.stderr)
        return 4
    except RunAlreadyActiveError:
        return 3

    return {
        "COMPLETED": 0,
        "PARTIAL": 2,
        "FAILED": 5,
    }[final_status.status.value]


if __name__ == "__main__":
    raise SystemExit(main())
