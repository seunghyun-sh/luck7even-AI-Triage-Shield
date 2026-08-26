"""Local entry point for the scan-to-report pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the web vulnerability assessment pipeline."
    )
    parser.add_argument(
        "--targets",
        type=Path,
        default=Path("configs/targets.example.json"),
        help="Path to the target configuration JSON file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(f"Pipeline scaffold ready. Targets: {args.targets}")


if __name__ == "__main__":
    main()
