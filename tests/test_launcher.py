"""Tests for the bounded background CLI launcher."""

from __future__ import annotations

import io
import threading
from pathlib import Path

import pytest

from orchestration import launcher


class FakeProcess:
    def __init__(self, stdout: io.StringIO, *, returncode: int | None = None) -> None:
        self.stdout = stdout
        self.stderr = io.StringIO("sensitive stderr detail")
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.waited = threading.Event()

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0 if self.returncode is None else self.returncode
        self.waited.set()
        return self.returncode


def test_start_run_builds_safe_command_handshakes_and_reaps(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(io.StringIO("run-20260827-111500-a1b2c3\nextra output\n"))
    captured: dict[str, object] = {}

    def popen(command: list[str], **kwargs: object) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(launcher.subprocess, "Popen", popen)

    scan_run_id = launcher.start_run(Path("configs/targets.example.json"), ["XSS", "SQLI"])

    assert scan_run_id == "run-20260827-111500-a1b2c3"
    assert captured["command"] == [
        launcher.sys.executable,
        "-u",
        "main.py",
        "run",
        "--targets",
        "configs/targets.example.json",
        "--types",
        "XSS",
        "SQLI",
    ]
    assert captured["kwargs"] == {
        "cwd": launcher._PROJECT_ROOT,
        "stdin": launcher.subprocess.DEVNULL,
        "stdout": launcher.subprocess.PIPE,
        "stderr": launcher.subprocess.PIPE,
        "text": True,
        "start_new_session": True,
    }
    assert process.waited.wait(1)


def test_start_run_terminates_on_handshake_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    blocked = threading.Event()
    process = FakeProcess(_BlockingStream(blocked))
    monkeypatch.setattr(launcher, "_HANDSHAKE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(launcher.RunLaunchError, match="did not start"):
        launcher.start_run(Path("configs/targets.example.json"), ["XSS"])

    blocked.set()
    assert process.terminated
    assert process.waited.is_set()


def test_start_run_rejects_early_failure_without_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(io.StringIO(""), returncode=5)
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(launcher.RunLaunchError) as error:
        launcher.start_run(Path("configs/targets.example.json"), ["XSS"])

    assert str(error.value) == "Diagnostic run was rejected."
    assert "sensitive" not in str(error.value)


def test_start_run_rejects_invalid_identifier(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(io.StringIO("not-a-run-id\n"))
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(launcher.RunLaunchError, match="invalid identifier"):
        launcher.start_run(Path("configs/targets.example.json"), ["XSS"])

    assert process.terminated


class _BlockingStream(io.StringIO):
    def __init__(self, unblock: threading.Event) -> None:
        super().__init__()
        self._unblock = unblock

    def readline(self, size: int = -1) -> str:
        self._unblock.wait()
        return ""
