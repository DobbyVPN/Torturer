from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from torturer_checks.hosted.deadline import DeadlineError, main, run


class HostedDeadlineTests(unittest.TestCase):
    def test_child_output_is_retained_privately_and_success_is_preserved(self) -> None:
        code = run(
            [
                sys.executable,
                "-c",
                "import sys; print('deadline-child-stdout', flush=True); "
                "print('deadline-child-stderr', file=sys.stderr, flush=True)",
            ],
            timeout_seconds=5,
            grace_seconds=1,
        )
        self.assertEqual(code, 0)

    def test_failure_writes_safe_summary_without_child_bytes_or_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hosted-deadline-summary-") as directory:
            root = Path(directory)
            summary = root / "summary.json"
            raw = root / "raw"
            secret = "summary-secret-must-not-escape"
            with mock.patch.dict(
                os.environ,
                {
                    "TORTURER_HOSTED_DEADLINE_EVIDENCE_DIR": str(raw),
                    "TORTURER_HOSTED_DEADLINE_SUMMARY_PATH": str(summary),
                },
                clear=False,
            ):
                code = run(
                    [sys.executable, "-c", "raise SystemExit(7)", secret],
                    timeout_seconds=5,
                    grace_seconds=1,
                )
            self.assertEqual(code, 7)
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "dobbyvpn.hosted.deadline-summary")
            self.assertEqual(payload["status"], "failed")
            self.assertEqual(payload["return_code"], 7)
            self.assertTrue(payload["evidence"])
            rendered = summary.read_text(encoding="utf-8")
            self.assertNotIn(secret, rendered)
            self.assertNotIn("SystemExit", rendered)
            self.assertEqual(summary.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX timeout summary test")
    def test_timeout_writes_timed_out_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hosted-deadline-timeout-summary-") as directory:
            root = Path(directory)
            summary = root / "summary.json"
            with mock.patch.dict(
                os.environ,
                {
                    "TORTURER_HOSTED_DEADLINE_EVIDENCE_DIR": str(root / "raw"),
                    "TORTURER_HOSTED_DEADLINE_SUMMARY_PATH": str(summary),
                },
                clear=False,
            ):
                code = run(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    timeout_seconds=1,
                    grace_seconds=1,
                )
            self.assertEqual(code, 124)
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "timed-out")
            self.assertEqual(payload["return_code"], 124)

    def test_module_cli_executes_and_does_not_echo_raw_arguments(self) -> None:
        secret_argument = "profile-token-must-not-be-printed"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "torturer_checks.hosted.deadline",
                "--timeout-seconds",
                "5",
                sys.executable,
                "-c",
                "print('deadline-cli-child', flush=True)",
                secret_argument,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(completed.stdout)
        sys.stdout.flush()
        sys.stderr.write(completed.stderr)
        sys.stderr.flush()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        combined = completed.stdout + completed.stderr
        self.assertNotIn("deadline-cli-child", combined)
        self.assertIn("evidence status=completed", combined)
        self.assertIn("command_arg_count=4", combined)
        self.assertNotIn(secret_argument, combined)
        self.assertNotIn("print('deadline-cli-child', flush=True)", combined)

    def test_empty_cli_command_fails_without_echoing_arguments(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--timeout-seconds", "1"])
        self.assertEqual(code, 2)
        self.assertIn("invalid-request=DeadlineError", stderr.getvalue())

    @unittest.skipIf(os.name == "nt", "POSIX process-group timing test")
    def test_timeout_terminates_the_child_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            child_script = (
                "import pathlib, subprocess, sys, time; "
                f"child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid), encoding='ascii'); "
                "print('deadline-child-started', flush=True); "
                "print('deadline-child-waiting', file=sys.stderr, flush=True); time.sleep(30)"
            )
            code = run(
                [sys.executable, "-c", child_script],
                timeout_seconds=1,
                grace_seconds=1,
            )
            self.assertEqual(code, 124)
            child_pid = int(pid_file.read_text(encoding="ascii"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                try:
                    os.kill(child_pid, 9)
                except ProcessLookupError:
                    pass
                self.fail("deadline left a child process running")

    @unittest.skipIf(os.name == "nt", "POSIX adopted-child lifecycle test")
    def test_deadline_returns_after_an_intentional_detached_child_is_finalized(self) -> None:
        leader_script = """
import os
import signal
import subprocess
import sys
from pathlib import Path

from torturer_checks.hosted.cli import CommandResult
from torturer_checks.hosted.linux import LinuxServiceProcessController

service = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"],
    start_new_session=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
pid = service.pid
service_binary = Path(sys.executable)

def service_stat():
    return Path(f"/proc/{pid}/stat").read_bytes()

stat_fields = service_stat().decode("ascii").rsplit(") ", 1)[1].split()
service_start = stat_fields[19]
service_group = int(stat_fields[2])

class Runner:
    def run(self, command, *, timeout_seconds):
        argv = tuple(command)
        inner = argv[2:] if argv[:2] == ("sudo", "-n") else argv
        if inner[:2] == ("kill", "-0"):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return CommandResult(argv, 1, b"", b"")
            return CommandResult(argv, 0, b"", b"")
        if inner[:2] == ("ps", "-o"):
            result = subprocess.run(
                ["ps", "-o", "state=", "-p", str(pid)],
                check=False,
                capture_output=True,
            )
            return CommandResult(argv, result.returncode, result.stdout, result.stderr)
        if inner[:2] == ("ps", "-axo"):
            result = subprocess.run(
                ["ps", "-o", "pid=,ppid=,pgid=,state=", "-p", str(pid)],
                check=False,
                capture_output=True,
            )
            return CommandResult(argv, result.returncode, result.stdout, result.stderr)
        if inner[:2] == ("sh", "-c") and inner[-1] == str(pid):
            try:
                return CommandResult(argv, 0, service_stat(), b"")
            except FileNotFoundError:
                return CommandResult(argv, 2, b"service_probe_absent\\n", b"")
        if inner[:2] == ("readlink", "-f"):
            return CommandResult(argv, 0, (sys.executable + "\\n").encode(), b"")
        if inner[:2] == ("kill", "-TERM"):
            os.killpg(service_group, signal.SIGTERM)
            return CommandResult(argv, 0, b"", b"")
        if inner[:2] == ("kill", "-KILL"):
            os.killpg(service_group, signal.SIGKILL)
            return CommandResult(argv, 0, b"", b"")
        raise AssertionError(argv)

controller = object.__new__(LinuxServiceProcessController)
controller.pid = pid
controller.binary = service_binary
controller.runner = Runner()
controller._restart_number = 1
controller._replacement_identity = (service_start, service_group)
controller._replacement_tree = ()
controller.stop_restarted_service(3.0)
print("service-finalized", flush=True)
"""
        started = time.monotonic()
        code = run(
            [sys.executable, "-c", leader_script],
            timeout_seconds=5,
            grace_seconds=1,
        )
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 4.0)

    @unittest.skipIf(os.name == "nt", "POSIX process-tree timing probe")
    def test_timeout_total_wall_clock_includes_cleanup_and_reap(self) -> None:
        started = time.monotonic()
        code = run(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout_seconds=1,
            grace_seconds=1,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(code, 124)
        self.assertLess(elapsed, 1.8)

    def test_invalid_bounds_and_empty_commands_fail_closed(self) -> None:
        for timeout in (0, 1801):
            with self.subTest(timeout=timeout), self.assertRaises(DeadlineError):
                run([sys.executable], timeout_seconds=timeout, grace_seconds=1)
        for grace in (0, 61):
            with self.subTest(grace=grace), self.assertRaises(DeadlineError):
                run([sys.executable], timeout_seconds=1, grace_seconds=grace)
        with self.assertRaises(DeadlineError):
            run([], timeout_seconds=1, grace_seconds=1)
