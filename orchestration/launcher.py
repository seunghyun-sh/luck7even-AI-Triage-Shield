"""Background launcher for the contract-defined diagnostic CLI."""

from __future__ import annotations

import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import TextIO

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_HANDSHAKE_TIMEOUT_SECONDS = 3.0
_RUN_ID_PATTERN = re.compile(r"run-\d{8}-\d{6}-[0-9a-f]{6}\Z")


class RunLaunchError(RuntimeError):
    """Raised when a diagnostic process cannot safely be launched."""


def _drain(stream: TextIO | None) -> None:
    if stream is not None:
        for _ in stream:
            pass


def _reap(process: subprocess.Popen[str]) -> None:
    """Drain inherited pipes and collect the child without retaining its output."""

    stderr_thread = threading.Thread(target=_drain, args=(process.stderr,), daemon=True)
    stderr_thread.start()
    _drain(process.stdout)
    try:
        process.wait()
    finally:
        stderr_thread.join()


def _terminate_and_reap(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    threading.Thread(target=_reap, args=(process,), daemon=True).start()


def _read_first_line(stream: TextIO | None, output: queue.Queue[str]) -> None:
    output.put("" if stream is None else stream.readline())


def start_run(targets_path: Path, vuln_types: list[str]) -> str:
    """Launch ``main.py run`` and return its contract-issued run identifier."""

    command = [
        sys.executable,
        "-u",
        "main.py",
        "run",
        "--targets",
        str(targets_path),
        "--types",
        *vuln_types,
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=_PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as error:
        raise RunLaunchError("Unable to start diagnostic run.") from error

    first_line: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(
        target=_read_first_line, args=(process.stdout, first_line), daemon=True
    )
    reader.start()
    try:
        line = first_line.get(timeout=_HANDSHAKE_TIMEOUT_SECONDS)
    except queue.Empty as error:
        _terminate_and_reap(process)
        raise RunLaunchError("Diagnostic run did not start in time.") from error

    scan_run_id = line.strip()
    if not _RUN_ID_PATTERN.fullmatch(scan_run_id):
        _terminate_and_reap(process)
        if not scan_run_id:
            raise RunLaunchError("Diagnostic run was rejected.")
        raise RunLaunchError("Diagnostic run returned an invalid identifier.")

    threading.Thread(target=_reap, args=(process,), daemon=True).start()
    return scan_run_id
