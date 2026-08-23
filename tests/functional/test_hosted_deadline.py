from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

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
