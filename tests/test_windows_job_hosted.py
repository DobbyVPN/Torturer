from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import torturer_checks.hosted.cli as hosted_cli
from torturer_checks.hosted.cli import HostedAdapterError, SubprocessRunner
from torturer_checks.windows_job import (
    WindowsJobCleanup,
    WindowsJobCloseDiagnostics,
    WindowsJobError,
)


class _FakeProcess:
    pid = 9137
    returncode = 0
    stdout = None
    stderr = None

    def __init__(self, *, timeout: bool = False) -> None:
        self._timeout = timeout
        self.communicate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def communicate(self, **_kwargs):
        self.communicate_calls += 1
        if self._timeout and self.communicate_calls == 1:
            raise subprocess.TimeoutExpired(
                ("synthetic-command",), 0.1,
                output=b"timeout-stdout\x00", stderr=b"timeout-stderr\x00",
            )
        return b"complete-stdout\x00", b"complete-stderr\x00"

    def poll(self) -> int:
        return self.returncode

    def kill(self) -> None:
        self.kill_calls += 1

    def wait(self, *, timeout: float | None = None) -> int:
        self.wait_calls += 1
        return self.returncode


class _FakeMonitor:
    identities = ()

    def start(self) -> None:
        return None

    def stop(self, _timeout: float) -> bool:
        return True


class _FakeSnapshotProvider:
    diagnostics = b""

    def invalidate(self, *, deadline: float | None = None) -> None:
        return None


class HostedWindowsJobRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def _runner_patches(
        self,
        process: _FakeProcess,
        *,
        finish: tuple[bytes, str] = (b"PROCESS_TREE_STATUS=gone\n", "gone"),
        close: tuple[str, ...] = (),
    ):
        job = object()
        return {
            "_linux_containment_required": mock.Mock(return_value=False),
            "popen_with_windows_job": mock.Mock(return_value=process),
            "_ProcessSnapshotProvider": mock.Mock(return_value=_FakeSnapshotProvider()),
            "_ProcessTreeMonitor": mock.Mock(return_value=_FakeMonitor()),
            "windows_job_for": mock.Mock(return_value=job),
            "close_windows_job": mock.Mock(return_value=close),
            "_finish_process_tree": mock.Mock(return_value=finish),
        }

    def test_normal_completion_survivor_fails_after_complete_diagnostics(self) -> None:
        raw = Path(self.directory.name) / "survivor-raw"
        process = _FakeProcess()
        replacements = self._runner_patches(
            process,
            finish=(
                b"WINDOWS_JOB_INITIAL_ACTIVE_PROCESSES=2\n"
                b"PROCESS_TREE_FINAL_STATUS=gone\n",
                "survivor",
            ),
        )
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_linux_containment_required", replacements["_linux_containment_required"]),
            mock.patch.object(hosted_cli, "popen_with_windows_job", replacements["popen_with_windows_job"]),
            mock.patch.object(hosted_cli, "_ProcessSnapshotProvider", replacements["_ProcessSnapshotProvider"]),
            mock.patch.object(hosted_cli, "_ProcessTreeMonitor", replacements["_ProcessTreeMonitor"]),
            mock.patch.object(hosted_cli, "windows_job_for", replacements["windows_job_for"]),
            mock.patch.object(hosted_cli, "close_windows_job", replacements["close_windows_job"]),
            mock.patch.object(hosted_cli, "_finish_process_tree", replacements["_finish_process_tree"]),
        ):
            with self.assertRaisesRegex(HostedAdapterError, "PROCESS_TREE_UNPROVEN"):
                SubprocessRunner(raw).run(("synthetic-command",), timeout_seconds=1.0)

        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"complete-stdout\x00", retained)
        self.assertIn(b"complete-stderr\x00", retained)
        self.assertIn(b"WINDOWS_JOB_INITIAL_ACTIVE_PROCESSES=2", retained)
        replacements["close_windows_job"].assert_called_once()

    def test_normal_completion_close_failure_is_retained_and_fails_closed(self) -> None:
        raw = Path(self.directory.name) / "close-failure-raw"
        process = _FakeProcess()
        replacements = self._runner_patches(
            process,
            close=("stage=hosted-cli-command api=CloseHandle winerror=6",),
        )
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_linux_containment_required", replacements["_linux_containment_required"]),
            mock.patch.object(hosted_cli, "popen_with_windows_job", replacements["popen_with_windows_job"]),
            mock.patch.object(hosted_cli, "_ProcessSnapshotProvider", replacements["_ProcessSnapshotProvider"]),
            mock.patch.object(hosted_cli, "_ProcessTreeMonitor", replacements["_ProcessTreeMonitor"]),
            mock.patch.object(hosted_cli, "windows_job_for", replacements["windows_job_for"]),
            mock.patch.object(hosted_cli, "close_windows_job", replacements["close_windows_job"]),
            mock.patch.object(hosted_cli, "_finish_process_tree", replacements["_finish_process_tree"]),
        ):
            with self.assertRaisesRegex(HostedAdapterError, "PROCESS_TREE_UNPROVEN"):
                SubprocessRunner(raw).run(("synthetic-command",), timeout_seconds=1.0)

        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"WINDOWS_JOB_CLOSE_DIAGNOSTIC=stage=hosted-cli-command api=CloseHandle winerror=6", retained)
        self.assertIn(b"PROCESS_TREE_STATUS=gone", retained)

    def test_close_failure_is_retried_before_evidence_is_finalized(self) -> None:
        raw = Path(self.directory.name) / "close-retry-raw"
        process = _FakeProcess()
        replacements = self._runner_patches(process)
        # The shared helper performs the two native attempts.  The hosted
        # caller must invoke it once and preserve its transient diagnostic
        # without converting the eventual close success into a failure.
        jobs = [object(), None]
        replacements["windows_job_for"].side_effect = (
            lambda _process: jobs.pop(0) if jobs else None
        )
        replacements["close_windows_job"].return_value = WindowsJobCloseDiagnostics(
            ("stage=hosted-cli-command api=CloseHandle winerror=6", "stage=hosted-cli-command detail=close-retry attempt=2"),
            failed=False,
        )
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_linux_containment_required", replacements["_linux_containment_required"]),
            mock.patch.object(hosted_cli, "popen_with_windows_job", replacements["popen_with_windows_job"]),
            mock.patch.object(hosted_cli, "_ProcessSnapshotProvider", replacements["_ProcessSnapshotProvider"]),
            mock.patch.object(hosted_cli, "_ProcessTreeMonitor", replacements["_ProcessTreeMonitor"]),
            mock.patch.object(hosted_cli, "windows_job_for", replacements["windows_job_for"]),
            mock.patch.object(hosted_cli, "close_windows_job", replacements["close_windows_job"]),
            mock.patch.object(hosted_cli, "_finish_process_tree", replacements["_finish_process_tree"]),
        ):
            result = SubprocessRunner(raw).run(("synthetic-command",), timeout_seconds=1.0)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(replacements["close_windows_job"].call_count, 1)
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"api=CloseHandle winerror=6", retained)
        self.assertIn(b"detail=close-retry attempt=2", retained)

    def test_timeout_uses_job_cleanup_and_retains_active_process_zero(self) -> None:
        raw = Path(self.directory.name) / "timeout-raw"
        process = _FakeProcess(timeout=True)
        replacements = self._runner_patches(process)
        cleanup = (
            b"WINDOWS_JOB_TERMINATE_ACTIVE_PROCESSES=0\n"
            b"WINDOWS_JOB_TERMINATE_DIAGNOSTIC=api=QueryInformationJobObject winerror=0\n"
            b"PROCESS_TREE_STATUS=gone\n"
        )
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_linux_containment_required", replacements["_linux_containment_required"]),
            mock.patch.object(hosted_cli, "popen_with_windows_job", replacements["popen_with_windows_job"]),
            mock.patch.object(hosted_cli, "_ProcessSnapshotProvider", replacements["_ProcessSnapshotProvider"]),
            mock.patch.object(hosted_cli, "_ProcessTreeMonitor", replacements["_ProcessTreeMonitor"]),
            mock.patch.object(hosted_cli, "windows_job_for", replacements["windows_job_for"]),
            mock.patch.object(hosted_cli, "close_windows_job", replacements["close_windows_job"]),
            mock.patch.object(hosted_cli, "_kill_process_tree", return_value=cleanup) as kill_tree,
            mock.patch.object(hosted_cli, "_tree_status", return_value="gone"),
            mock.patch.object(hosted_cli, "_bounded_reap_process", return_value=(True, True, b"", b"", b"")),
        ):
            with self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"):
                SubprocessRunner(raw).run(("synthetic-command",), timeout_seconds=0.4)

        kill_tree.assert_called_once()
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"timeout-stdout\x00", retained)
        self.assertIn(b"timeout-stderr\x00", retained)
        self.assertIn(b"WINDOWS_JOB_TERMINATE_ACTIVE_PROCESSES=0", retained)

    def test_setup_failure_retains_complete_output_and_numeric_diagnostics(self) -> None:
        raw = Path(self.directory.name) / "setup-failure-raw"
        error = WindowsJobError(
            "hosted-cli-command",
            ("api=AssignProcessToJobObject winerror=5",),
            stdout=b"setup-stdout\x00\xff",
            stderr=b"setup-stderr\x00\xfe",
        )
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_linux_containment_required", return_value=False),
            mock.patch.object(hosted_cli, "popen_with_windows_job", side_effect=error),
        ):
            with self.assertRaisesRegex(HostedAdapterError, "PROCESS_CONTAINMENT_UNAVAILABLE"):
                SubprocessRunner(raw).run(("synthetic-command",), timeout_seconds=1.0)

        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"setup-stdout\x00\xff", retained)
        self.assertIn(b"setup-stderr\x00\xfe", retained)
        self.assertIn(b"api=AssignProcessToJobObject winerror=5", retained)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1 reason=windows-job-setup", retained)

    def test_windows_job_cleanup_path_does_not_call_taskkill(self) -> None:
        process = _FakeProcess()
        job = object()
        cleanup = WindowsJobCleanup(True, 0, ("api=QueryInformationJobObject winerror=0",))
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_tracked_processes", return_value=()),
            mock.patch.object(hosted_cli, "windows_job_for", return_value=job),
            mock.patch.object(hosted_cli, "terminate_windows_job", return_value=cleanup) as terminate,
            mock.patch.object(hosted_cli, "_bounded_capture", side_effect=AssertionError("taskkill must not run")),
        ):
            diagnostics = hosted_cli._kill_process_tree(
                process,
                deadline=time.monotonic() + 1.0,
            )

        terminate.assert_called_once()
        self.assertIn(b"WINDOWS_JOB_TERMINATE_ACTIVE_PROCESSES=0", diagnostics)
        self.assertIn(b"PROCESS_TREE_STATUS=gone", diagnostics)

    def test_missing_windows_job_kills_only_leader_and_fails_closed(self) -> None:
        process = _FakeProcess()
        with (
            mock.patch.object(hosted_cli.os, "name", "nt"),
            mock.patch.object(hosted_cli, "_tracked_processes", return_value=()),
            mock.patch.object(hosted_cli, "windows_job_for", return_value=None),
            mock.patch.object(
                hosted_cli,
                "_bounded_capture",
                side_effect=AssertionError("PID-recursive taskkill must not run"),
            ),
        ):
            diagnostics = hosted_cli._kill_process_tree(
                process,
                deadline=time.monotonic() + 1.0,
            )

        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_calls, 1)
        self.assertIn(b"WINDOWS_JOB_CONTAINMENT_MISSING=1", diagnostics)
        self.assertIn(b"PROCESS_TREE_UNPROVEN=1", diagnostics)
        self.assertIn(b"PROCESS_TREE_STATUS=unknown", diagnostics)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1 reason=windows-job-missing", diagnostics)


if __name__ == "__main__":
    unittest.main()
