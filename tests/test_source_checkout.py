from __future__ import annotations

import gc
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import signal
import tempfile
import time
import unittest
import warnings
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import torturer_checks.source_checkout as source_checkout
from torturer_checks.source_checkout import (
    MAX_PREFLIGHT_SECONDS,
    SourceCheckoutError,
    TreeCleanup,
    _proc_descendants,
    _wait_for_tree,
    run_bounded_preflight,
    verify_source_checkout,
)


class SourceCheckoutTest(unittest.TestCase):
    def test_accepts_exact_clean_commit_and_rejects_tracked_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Torturer"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "torturer@example.invalid"],
                check=True,
            )
            tracked = root / "tracked.txt"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "fixture"], check=True)
            commit_result = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=None,
            )
            print(commit_result.stdout, end="")
            commit = commit_result.stdout.strip()

            verify_source_checkout(root, commit)
            (root / "untracked.txt").write_text("allowed\n", encoding="utf-8")
            verify_source_checkout(root, commit)
            tracked.write_text("modified\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceCheckoutError, "modified tracked"):
                verify_source_checkout(root, commit)

    def test_rejects_abbreviated_or_wrong_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(SourceCheckoutError, "exactly 40"):
                verify_source_checkout(root, "abc123")

    @unittest.skipIf(os.name == "nt", "the SIGTERM-resistant descendant regression uses POSIX process groups")
    def test_bounded_preflight_kills_descendants_and_retains_exact_streams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-timeout-regression-") as temporary:
            root = Path(temporary)
            pid_file = root / "descendant.pid"
            evidence = root / "evidence"
            command = (
                os.environ.get("PYTHON", "python3"),
                "-c",
                (
                    "import os, signal, sys, time; "
                    f"pid = os.fork(); "
                    f"marker=open({str(pid_file)!r}, 'w', encoding='ascii'); marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                    "print('preflight-stdout', flush=True); "
                    "print('preflight-stderr', file=sys.stderr, flush=True); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                    "time.sleep(60)"
                ),
            )
            captured_stdout = io.StringIO()
            captured_stderr = io.StringIO()
            with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
                with self.assertRaisesRegex(SourceCheckoutError, "timed out"):
                    run_bounded_preflight(
                        command,
                        timeout_seconds=0.2,
                        evidence_directory=evidence,
                        evidence_stem="sigterm-resistant-descendant",
                    )
            self.assertNotIn("preflight-stdout", captured_stdout.getvalue())
            self.assertNotIn("preflight-stderr", captured_stderr.getvalue())
            self.assertIn("diagnostic_evidence", captured_stdout.getvalue())
            self.assertEqual(
                (evidence / "sigterm-resistant-descendant.stdout.raw.log").read_bytes(),
                b"preflight-stdout\n" * 2,
            )
            self.assertEqual(
                (evidence / "sigterm-resistant-descendant.stderr.raw.log").read_bytes(),
                b"preflight-stderr\n" * 2,
            )
            descendant_pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"SIGTERM-resistant descendant {descendant_pid} survived preflight cleanup")

    def test_preflight_timeout_is_capped_at_the_lane_limit_and_evidence_is_non_overwriting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-bound-") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            with self.assertRaisesRegex(SourceCheckoutError, "between 1 and 1800"):
                run_bounded_preflight(
                    ("python3", "-c", "print('never-run')"),
                    timeout_seconds=MAX_PREFLIGHT_SECONDS + 1,
                    evidence_directory=evidence,
                )
            run_bounded_preflight(
                ("python3", "-c", "print('one')"),
                timeout_seconds=5,
                evidence_directory=evidence,
                evidence_stem="same-label",
            )
            with self.assertRaisesRegex(SourceCheckoutError, "overwrite existing"):
                run_bounded_preflight(
                    ("python3", "-c", "print('two')"),
                    timeout_seconds=5,
                    evidence_directory=evidence,
                    evidence_stem="same-label",
                )

    @unittest.skipIf(os.name == "nt", "the wall-clock probe uses POSIX process groups")
    def test_total_preflight_timeout_includes_cleanup_and_does_not_run_grace_after_deadline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-total-bound-", dir="/tmp") as temporary:
            evidence = Path(temporary) / "evidence"
            started = time.monotonic()
            with self.assertRaisesRegex(SourceCheckoutError, "timed out"):
                run_bounded_preflight(
                    ("python3", "-c", "import time; print('bounded', flush=True); time.sleep(60)"),
                    timeout_seconds=0.4,
                    evidence_directory=evidence,
                    evidence_stem="total-bound",
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.2)
            metadata = json.loads(
                (evidence / "total-bound.metadata.raw.json").read_text(encoding="utf-8")
            )
            self.assertLess(metadata["elapsed_seconds"], 1.2)
            self.assertFalse(metadata["deadline_exceeded"])

    def test_fallback_process_census_uses_remaining_deadline(self) -> None:
        class EmptyProcessListing:
            stdout = b""

        with patch.object(source_checkout.Path, "is_dir", return_value=False), patch.object(
            source_checkout.subprocess,
            "run",
            return_value=EmptyProcessListing(),
        ) as run:
            deadline = time.monotonic() + 0.1
            _proc_descendants(123, deadline=deadline)
            timeout = run.call_args.kwargs["timeout"]
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 0.1)

    def test_partial_original_is_never_deleted_and_metadata_marks_incomplete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-partial-", dir="/tmp") as temporary:
            evidence = Path(temporary) / "evidence"
            calls = 0

            def fail_once(output: object, payload: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    getattr(output, "write")(payload[:3])
                    raise OSError("injected write failure")
                getattr(output, "write")(payload)

            with patch.object(source_checkout, "_write_payload", side_effect=fail_once):
                with self.assertRaisesRegex(SourceCheckoutError, "evidence incomplete"):
                    run_bounded_preflight(
                        ("python3", "-c", "print('complete-stream')"),
                        timeout_seconds=5,
                        evidence_directory=evidence,
                        evidence_stem="partial-original",
                    )

            partial = evidence / "partial-original.stdout.raw.log"
            self.assertEqual(partial.read_bytes(), b"com")
            self.assertEqual(stat.S_IMODE(partial.stat().st_mode), 0o600)
            metadata = json.loads(
                (evidence / "partial-original.metadata.raw.json").read_text(encoding="utf-8")
            )
            self.assertTrue(metadata["evidence_incomplete"])
            self.assertFalse(metadata["evidence_complete"])
            self.assertIn(str(partial), metadata["stdout_path"])

    def test_rejects_relative_symlinked_and_non_private_evidence_directories(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-unsafe-", dir="/tmp") as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(SourceCheckoutError, "symlink"):
                run_bounded_preflight(
                    ("python3", "-c", "print('not-run')"),
                    evidence_directory=link,
                )
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            unsafe.chmod(0o755)
            with self.assertRaisesRegex(SourceCheckoutError, "mode 0700"):
                run_bounded_preflight(
                    ("python3", "-c", "print('not-run')"),
                    evidence_directory=unsafe,
                )
            with self.assertRaisesRegex(SourceCheckoutError, "must be absolute"):
                run_bounded_preflight(
                    ("python3", "-c", "print('not-run')"),
                    evidence_directory=Path("relative-evidence"),
                )

    def test_permission_denial_is_unproven_liveness(self) -> None:
        with patch.object(source_checkout.os, "kill", side_effect=PermissionError):
            self.assertTrue(source_checkout._pid_alive(os.getpid()))

    def test_windows_leader_exit_without_descendant_census_fails_closed(self) -> None:
        class ExitedProcess:
            pid = 12345

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

        with patch.object(source_checkout.os, "name", "nt"):
            self.assertFalse(_wait_for_tree(ExitedProcess(), set(), 0.0))  # type: ignore[arg-type]

    def test_windows_unavailable_census_cannot_become_a_clean_result(self) -> None:
        class ExitedProcess:
            pid = 12345
            _torturer_tree_census_observed = True

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

        process = ExitedProcess()
        with patch.object(source_checkout.os, "name", "nt"):
            self.assertFalse(_wait_for_tree(process, set(), 0.0))  # type: ignore[arg-type]
            self.assertFalse(process._torturer_tree_census_observed)

    @unittest.skipIf(os.name == "nt", "the detached descendant regression uses POSIX sessions")
    def test_zero_exit_leader_cleans_detached_resistant_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-zero-exit-", dir="/tmp") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            child_pid_file = root / "child.pid"
            command = (
                "python3",
                "-c",
                (
                    "import os, signal, time; "
                    f"pid=os.fork(); "
                    f"marker=open({str(child_pid_file)!r}, 'w', encoding='ascii'); marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                    "(os.setsid(), "
                    "os.close(1), os.close(2), signal.signal(signal.SIGTERM, signal.SIG_IGN), time.sleep(60)) "
                    "if pid == 0 else (print('leader-ok', flush=True), time.sleep(0.25))"
                ),
            )
            with self.assertRaisesRegex(SourceCheckoutError, "normal completion left"):
                run_bounded_preflight(
                    command,
                    timeout_seconds=5,
                    evidence_directory=evidence,
                    evidence_stem="zero-exit-detached",
                )
            child_pid = int(child_pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"detached resistant descendant {child_pid} survived normal-completion cleanup")
            metadata = json.loads(
                (evidence / "zero-exit-detached.metadata.raw.json").read_text(encoding="utf-8")
            )
            self.assertFalse(metadata["evidence_incomplete"])
            self.assertTrue(metadata["process_tree_proven"])
            self.assertFalse(metadata["cleanup_errors"] == [])

    @unittest.skipIf(os.name == "nt", "the process-tree survivor regression uses POSIX process groups")
    def test_timeout_drain_survivor_is_recorded_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preflight-survivor-", dir="/tmp") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            child_pid_file = root / "child.pid"
            command = (
                "python3",
                "-c",
                (
                    "import os, signal, time; "
                    f"pid=os.fork(); "
                    f"marker=open({str(child_pid_file)!r}, 'w', encoding='ascii'); marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                    "time.sleep(60)"
                ),
            )

            def fake_cleanup(
                process: subprocess.Popen[bytes],
                *,
                grace_seconds: float,
                force_immediately: bool = False,
            ) -> TreeCleanup:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                return TreeCleanup(False, (process.pid,), "injected survivor")

            try:
                with patch.object(source_checkout, "_terminate_tree", side_effect=fake_cleanup):
                    with self.assertRaisesRegex(SourceCheckoutError, "injected survivor"):
                        run_bounded_preflight(
                            command,
                            timeout_seconds=0.2,
                            evidence_directory=evidence,
                            evidence_stem="survivor-drain",
                        )
                metadata = json.loads(
                    (evidence / "survivor-drain.metadata.raw.json").read_text(encoding="utf-8")
                )
                self.assertTrue(metadata["timed_out"])
                self.assertFalse(metadata["process_tree_proven"])
                self.assertTrue(metadata["evidence_incomplete"])
                self.assertTrue(metadata["survivor_pids"])
            finally:
                if child_pid_file.exists():
                    try:
                        os.kill(int(child_pid_file.read_text(encoding="ascii")), signal.SIGKILL)
                    except (OSError, ValueError):
                        pass

    @unittest.skipIf(os.name == "nt", "the pipe-survivor regression uses POSIX process groups")
    def test_repeated_pipe_survivor_cleanup_has_no_resource_warnings(self) -> None:
        """Repeated failed drains close Popen pipes and reap the leader."""

        with tempfile.TemporaryDirectory(prefix="preflight-pipe-load-", dir="/tmp") as temporary:
            root = Path(temporary)
            for index in range(6):
                run_root = root / str(index)
                run_root.mkdir()
                child_pid_file = run_root / "child.pid"
                evidence = run_root / "evidence"
                command = (
                    "python3",
                    "-c",
                    (
                        "import os, signal, time; "
                        "pid=os.fork(); "
                        f"marker=open({str(child_pid_file)!r}, 'w', encoding='ascii'); marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                        "time.sleep(60)"
                    ),
                )

                def fake_cleanup(
                    process: subprocess.Popen[bytes],
                    *,
                    grace_seconds: float,
                    force_immediately: bool = False,
                ) -> TreeCleanup:
                    process.kill()
                    return TreeCleanup(False, (process.pid,), "injected survivor")

                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always", ResourceWarning)
                    try:
                        with patch.object(source_checkout, "_terminate_tree", side_effect=fake_cleanup):
                            with self.assertRaisesRegex(SourceCheckoutError, "injected survivor"):
                                run_bounded_preflight(
                                    command,
                                    timeout_seconds=0.2,
                                    evidence_directory=evidence,
                                    evidence_stem="pipe-survivor-load",
                                )
                        gc.collect()
                        self.assertEqual(
                            [warning for warning in captured if issubclass(warning.category, ResourceWarning)],
                            [],
                        )
                    finally:
                        if child_pid_file.exists():
                            try:
                                os.kill(int(child_pid_file.read_text(encoding="ascii")), signal.SIGKILL)
                            except (OSError, ValueError):
                                pass

    def test_auto_evidence_path_is_reported_and_metadata_is_exclusive(self) -> None:
        captured_stderr = io.StringIO()
        with redirect_stderr(captured_stderr):
            result = run_bounded_preflight(
                ("python3", "-c", "print('auto-path')"),
                timeout_seconds=5,
                evidence_stem="auto-path",
            )
        self.assertIsNotNone(result.evidence_directory)
        self.assertIsNotNone(result.metadata_path)
        self.assertNotIn(str(result.evidence_directory), captured_stderr.getvalue())
        metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["evidence_directory"], str(result.evidence_directory))
        self.assertFalse(metadata["evidence_incomplete"])


if __name__ == "__main__":
    unittest.main()
