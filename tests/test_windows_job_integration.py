"""Native Windows Job Object integration tests for hosted CI."""

from __future__ import annotations

import os
import stat
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from torturer_checks.windows_job import (
    close_for,
    job_for,
    popen_with_windows_job,
    terminate_and_prove_empty,
    wait_for_empty,
)
from torturer_checks.hosted.cli import SubprocessRunner
from torturer_checks.hosted import finalize_windows_service
from torturer_checks.hosted.windows import WindowsServiceProcessController
from torturer_checks.source_checkout import run_bounded_preflight
from torturer_checks import desktop_slice


@unittest.skipUnless(os.name == "nt", "native Windows Job Objects require Windows")
class WindowsJobIntegrationTests(unittest.TestCase):
    """Exercise the same native boundary used by hosted ordinary commands."""

    def _process_identity(self, pid: int) -> str:
        # ``powershell.exe -Command <script> <arg>`` does not bind the final
        # token to ``$args`` consistently across Windows PowerShell versions:
        # it can execute it as a second command instead.  Embed this
        # test-created integer in the script so the probe cannot accidentally
        # query PID 0 and append the argument as an extra output line.
        process_id = int(pid)
        script = (
            '$ErrorActionPreference="Stop"; '
            f'$processId={process_id}; '
            '$p=Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $processId); '
            'if ($null -eq $p -or $null -eq $p.CreationDate) { exit 2 }; '
            'Write-Output ([string]$p.ProcessId + "|" + '
            '[string]$p.CreationDate.ToUniversalTime().Ticks)'
        )
        result = subprocess.run(
            (
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        identity = result.stdout.decode("ascii").strip()
        self.assertRegex(identity, rf"^{pid}\|[1-9][0-9]+$")
        return identity

    @staticmethod
    def _unused_tcp_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def _launch(self, code: str, *, stage: str):
        return popen_with_windows_job(
            subprocess.Popen,
            [sys.executable, "-c", code],
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stage=stage,
            deadline=time.monotonic() + 30.0,
        )

    def _close_process(self, process) -> None:
        failures: list[str] = []
        job = job_for(process)
        if job is not None:
            teardown_deadline = time.monotonic() + 10.0
            active = job.query_active_processes(deadline=teardown_deadline)
            if active is None:
                failures.append(
                    "initial active-process query failed: " + "; ".join(job.diagnostics)
                )
            elif active != 0:
                cleanup = terminate_and_prove_empty(
                    process,
                    deadline=teardown_deadline,
                    stage="integration-teardown",
                )
                if not cleanup.process_tree_proven or cleanup.active_processes != 0:
                    failures.append(
                        "terminate proof failed: " + "; ".join(cleanup.diagnostics)
                    )
            try:
                process.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                failures.append("communicate timeout")
                try:
                    process.kill()
                    process.communicate(timeout=5.0)
                except (OSError, subprocess.TimeoutExpired) as error:
                    failures.append(f"reap failed: {type(error).__name__}")
            except OSError as error:
                failures.append(f"communicate failed: {type(error).__name__}")
            close_diagnostics = close_for(
                process,
                stage="integration-teardown",
                deadline=time.monotonic() + 5.0,
            )
            if close_diagnostics:
                failures.append("close failed: " + "; ".join(close_diagnostics))
        elif process.poll() is None:
            try:
                process.kill()
                process.communicate(timeout=5.0)
            except (OSError, subprocess.TimeoutExpired) as error:
                failures.append(f"uncontained reap failed: {type(error).__name__}")
        if failures:
            self.fail("; ".join(failures))

    def test_suspended_process_is_assigned_before_resume_and_proves_empty(self) -> None:
        process = self._launch(
            "import sys; sys.stdout.write('resumed\\n'); sys.stdout.flush()",
            stage="integration-suspended",
        )
        try:
            job = job_for(process)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertTrue(job.assigned)
            stdout, stderr = process.communicate(timeout=10.0)
            self.assertEqual(stdout, b"resumed" + os.linesep.encode("ascii"))
            self.assertEqual(stderr, b"")
            self.assertTrue(
                wait_for_empty(process, deadline=time.monotonic() + 10.0).process_tree_proven
            )
        finally:
            self._close_process(process)

    def test_root_exit_with_child_and_grandchild_is_contained_and_cleaned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-job-descendants-") as temporary:
            root = Path(temporary)
            child_ready = root / "child.ready"
            grandchild_ready = root / "grandchild.ready"
            grandchild_code = (
                "import pathlib, time; "
                f"pathlib.Path({str(grandchild_ready)!r}).write_text('ready'); "
                "time.sleep(30)"
            )
            child_code = (
                "import pathlib, subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', {grandchild_code!r}], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                f"pathlib.Path({str(child_ready)!r}).write_text('ready'); "
                "time.sleep(30)"
            )
            code = (
                "import pathlib, subprocess, sys, time\n"
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                f"deadline = time.monotonic() + 10\n"
                f"ready = pathlib.Path({str(child_ready)!r}), pathlib.Path({str(grandchild_ready)!r})\n"
                "while time.monotonic() < deadline and not all(path.is_file() for path in ready):\n"
                "    time.sleep(0.01)\n"
                "print('root-exited', flush=True)\n"
            )
            process = self._launch(code, stage="integration-descendants")
            try:
                stdout, stderr = process.communicate(timeout=15.0)
                self.assertEqual(stdout, b"root-exited" + os.linesep.encode("ascii"))
                self.assertEqual(stderr, b"")
                self.assertIsNotNone(process.returncode)
                self.assertTrue(child_ready.is_file())
                self.assertTrue(grandchild_ready.is_file())
                job = job_for(process)
                self.assertIsNotNone(job)
                assert job is not None
                active = job.query_active_processes(deadline=time.monotonic() + 10.0)
                self.assertIsNotNone(active)
                self.assertGreaterEqual(active or 0, 2)
                cleanup = terminate_and_prove_empty(
                    process,
                    deadline=time.monotonic() + 10.0,
                    stage="integration-descendants",
                )
                self.assertTrue(cleanup.process_tree_proven, cleanup.diagnostics)
                self.assertEqual(cleanup.active_processes, 0)
            finally:
                self._close_process(process)

    def test_job_termination_does_not_touch_outside_sentinel(self) -> None:
        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process = self._launch("import time; time.sleep(30)", stage="integration-sentinel")
        try:
            cleanup = terminate_and_prove_empty(
                process,
                deadline=time.monotonic() + 10.0,
                stage="integration-sentinel",
            )
            self.assertTrue(cleanup.process_tree_proven, cleanup.diagnostics)
            self.assertIsNone(sentinel.poll())
        finally:
            self._close_process(process)
            sentinel.kill()
            sentinel.wait(timeout=10.0)

    def test_complete_stdout_and_stderr_are_retained(self) -> None:
        expected_stdout = b"complete-out\x00\xff"
        expected_stderr = b"complete-err\x00\xfe"
        with tempfile.TemporaryDirectory() as temporary:
            raw_directory = Path(temporary) / "runner-raw"
            runner = SubprocessRunner(raw_directory)
            result = runner.run(
                (
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'complete-out\\x00\\xff'); "
                    "sys.stderr.buffer.write(b'complete-err\\x00\\xfe'); "
                    "sys.stdout.flush(); sys.stderr.flush()",
                ),
                timeout_seconds=10.0,
            )

            self.assertEqual(result.stdout, expected_stdout)
            self.assertEqual(result.stderr, expected_stderr)
            retained_files = list(raw_directory.glob("command-001*.raw.log"))
            self.assertEqual(len(retained_files), 1)
            retained = retained_files[0]
            content = retained.read_bytes()
            self.assertIn(b"stdout-begin\n" + expected_stdout + b"\nstdout-end\n", content)
            self.assertIn(b"stderr-begin\n" + expected_stderr + b"\nstderr-end\n", content)
            # POSIX mode bits are the applicable owner-only contract on this
            # test host.  Windows uses the runner's inherited private ACL
            # boundary instead; mode bits are not an ACL assertion there.
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o600)

    def test_source_checkout_preflight_uses_job_and_retains_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-job-preflight-") as temporary:
            evidence = Path(temporary) / "evidence"
            result = run_bounded_preflight(
                (
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'preflight-out\\x00\\xff'); "
                    "sys.stderr.buffer.write(b'preflight-err\\x00\\xfe'); "
                    "sys.stdout.flush(); sys.stderr.flush()",
                ),
                timeout_seconds=10.0,
                evidence_directory=evidence,
                evidence_stem="native-preflight",
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.process_tree_proven)
            self.assertEqual(result.stdout, b"preflight-out\x00\xff")
            self.assertEqual(result.stderr, b"preflight-err\x00\xfe")
            self.assertEqual(
                (evidence / "native-preflight.stdout.raw.log").read_bytes(),
                result.stdout,
            )
            self.assertEqual(
                (evidence / "native-preflight.stderr.raw.log").read_bytes(),
                result.stderr,
            )

    def test_desktop_command_uses_job_and_retains_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-job-desktop-command-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            result = desktop_slice.run_command(
                (
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'desktop-out\\x00\\xff'); "
                    "sys.stderr.buffer.write(b'desktop-err\\x00\\xfe'); "
                    "sys.stdout.flush(); sys.stderr.flush()",
                ),
                cwd=root,
                env=os.environ.copy(),
                timeout_seconds=10.0,
                evidence_directory=evidence,
                evidence_label="native-desktop-command",
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.process_tree_proven)
            self.assertEqual(result.stdout_bytes, b"desktop-out\x00\xff")
            self.assertEqual(result.stderr_bytes, b"desktop-err\x00\xfe")
            self.assertEqual(
                (evidence / "native-desktop-command.stdout.raw.log").read_bytes(),
                result.stdout_bytes,
            )
            self.assertEqual(
                (evidence / "native-desktop-command.stderr.raw.log").read_bytes(),
                result.stderr_bytes,
            )

    def test_desktop_service_teardown_uses_job_and_retains_service_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-job-desktop-service-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            service_log_path = root / "service.combined.log"
            with service_log_path.open("wb", buffering=0) as service_log:
                process = popen_with_windows_job(
                    subprocess.Popen,
                    [
                        sys.executable,
                        "-c",
                        "import sys, time; print('synthetic-service', flush=True); time.sleep(30)",
                    ],
                    stdin=None,
                    stdout=service_log,
                    stderr=subprocess.STDOUT,
                    stage="integration-desktop-service",
                    deadline=time.monotonic() + 10.0,
                )
                try:
                    self.assertIsNotNone(job_for(process))
                    marker_deadline = time.monotonic() + 10.0
                    expected_marker = b"synthetic-service" + os.linesep.encode("ascii")
                    while time.monotonic() < marker_deadline:
                        service_log.flush()
                        if service_log_path.read_bytes() == expected_marker:
                            break
                        time.sleep(0.01)
                    else:
                        self.fail("synthetic service did not emit its readiness marker before teardown")
                    desktop_slice.stop_service(
                        process,
                        None,
                        timeout_seconds=max(0.1, marker_deadline - time.monotonic()),
                        evidence_directory=evidence,
                    )
                finally:
                    # If readiness or stop_service fails, the normal cleanup
                    # call is never reached.  Close the native Job here before
                    # TemporaryDirectory removal, while the service log is
                    # still open, so descendants cannot retain its handle.
                    try:
                        self._close_process(process)
                    finally:
                        service_log.flush()
            desktop_slice._emit_and_retain_service_log(service_log_path, evidence)
            self.assertEqual(
                (evidence / "service.combined.raw.log").read_bytes(),
                b"synthetic-service" + os.linesep.encode("ascii"),
            )
            self.assertIsNone(job_for(process))

    def test_parent_can_close_redirected_handles_immediately(self) -> None:
        expected_stdout = b"delayed-out\x00\xff"
        expected_stderr = b"delayed-err\x00\xfe"
        with tempfile.TemporaryDirectory(prefix="windows-job-closed-handles-") as temporary:
            root = Path(temporary)
            stdout_path = root / "child.stdout"
            stderr_path = root / "child.stderr"
            stdout_file = stdout_path.open("wb", buffering=0)
            stderr_file = stderr_path.open("wb", buffering=0)
            try:
                process = popen_with_windows_job(
                    subprocess.Popen,
                    [
                        sys.executable,
                        "-c",
                        "import sys, time; time.sleep(0.2); "
                        "sys.stdout.buffer.write(b'delayed-out\\x00\\xff'); "
                        "sys.stderr.buffer.write(b'delayed-err\\x00\\xfe'); "
                        "sys.stdout.flush(); sys.stderr.flush()",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    stage="integration-closed-parent-handles",
                    deadline=time.monotonic() + 10.0,
                )
            finally:
                # The child owns inherited duplicates of these native handles;
                # the hosted controller may close its parent-side objects as
                # soon as Popen returns.
                stdout_file.close()
                stderr_file.close()
            try:
                process.wait(timeout=10.0)
                self.assertTrue(
                    wait_for_empty(process, deadline=time.monotonic() + 10.0).process_tree_proven
                )
            finally:
                self._close_process(process)
            self.assertEqual(stdout_path.read_bytes(), expected_stdout)
            self.assertEqual(stderr_path.read_bytes(), expected_stderr)
            self.assertIsNone(job_for(process))

    def test_windows_service_controller_owns_native_replacement_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-service-controller-") as temporary:
            root = Path(temporary)
            raw = root / "raw"
            raw.mkdir()
            identity_file = root / "service.identity"
            pid_file = root / "service.pid"
            port = self._unused_tcp_port()
            initial = subprocess.Popen(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            controller = None
            try:
                identity = self._process_identity(initial.pid)
                identity_file.write_text(identity + "\n", encoding="ascii")
                replacement_code = (
                    "import socket,time; "
                    "listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM); "
                    "listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                    f"listener.bind(('127.0.0.1',{port})); listener.listen(); "
                    "print('service-ready',flush=True); time.sleep(30)"
                )
                controller = WindowsServiceProcessController(
                    pid=initial.pid,
                    binary=Path(sys.executable),
                    pid_file=pid_file,
                    identity_file=identity_file,
                    runner=SubprocessRunner(raw),
                    raw_directory=raw,
                    control_address=f"127.0.0.1:{port}",
                    expected_initial_identity=identity,
                    initialization_deadline=time.monotonic() + 10.0,
                    replacement_command=(sys.executable, "-c", replacement_code),
                )
                controller.restart_after_loss(25.0)
                initial.wait(timeout=10.0)
                initial_stdout, initial_stderr = initial.communicate(timeout=1.0)
                self.assertEqual(initial_stdout, b"")
                self.assertEqual(initial_stderr, b"")
                replacement = controller._replacement_process
                self.assertIsNotNone(replacement)
                assert replacement is not None
                self.assertIsNotNone(job_for(replacement))
                controller.finalize_restarted_service(15.0)
                controller.finalize_evidence(5.0)
                self.assertIsNotNone(replacement.poll())
                self.assertIsNone(job_for(replacement))
            finally:
                if controller is not None and controller._replacement_process is not None:
                    replacement = controller._replacement_process
                    terminate_and_prove_empty(
                        replacement,
                        deadline=time.monotonic() + 5.0,
                        stage="integration-service-controller-finally",
                    )
                    try:
                        replacement.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        replacement.kill()
                        replacement.wait(timeout=5.0)
                    close_for(
                        replacement,
                        stage="integration-service-controller-finally",
                        deadline=time.monotonic() + 5.0,
                    )
                if initial.poll() is None:
                    initial.kill()
                    initial.wait(timeout=5.0)
                initial.communicate(timeout=1.0)

    def test_windows_service_finalizer_stops_exact_external_process(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-service-finalizer-") as temporary:
            root = Path(temporary)
            raw = root / "raw"
            raw.mkdir()
            identity_file = root / "service.identity"
            process = subprocess.Popen(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                identity_file.write_text(
                    self._process_identity(process.pid) + "\n",
                    encoding="ascii",
                )
                status = finalize_windows_service.main(
                    [
                        "--service-identity-file",
                        str(identity_file),
                        "--service-binary",
                        sys.executable,
                        "--raw-log-dir",
                        str(raw),
                        "--timeout-seconds",
                        "20",
                    ]
                )
                self.assertEqual(status, 0)
                process.wait(timeout=10.0)
                stdout, stderr = process.communicate(timeout=1.0)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5.0)
                process.communicate(timeout=1.0)


if __name__ == "__main__":
    unittest.main()
