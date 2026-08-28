from __future__ import annotations

import gc
import io
import json
import os
from pathlib import Path
import stat
import signal
import sys
import tempfile
import time
import unittest
import warnings
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch


TORTURER_ROOT = Path(__file__).resolve().parents[3]
if str(TORTURER_ROOT) not in sys.path:
    sys.path.insert(0, str(TORTURER_ROOT))

import torturer_checks.desktop_slice as desktop_slice
from torturer_checks.desktop_slice import (
    BUILD_SCRIPT_RELATIVE_PATH,
    CLI_RELATIVE_PATHS,
    CLEANUP_RESERVE_SECONDS,
    GRADLE_RELATIVE_PATH,
    MAX_RUN_SECONDS,
    MALFORMED_CONFIG,
    SERVICE_RELATIVE_PATHS,
    RunBudget,
    WINDOWS_GRADLE_RELATIVE_PATH,
    CommandResult,
    ProcessTreeResult,
    SliceFailure,
    app_build_command,
    build_runtime_paths,
    candidate_path,
    cli_command,
    require_nonzero,
    run_command,
    require_success,
    service_build_command,
    service_command,
    service_environment,
    safe_failure_reason,
    stop_service,
    _prepare_evidence_directory,
    _validate_evidence_directory,
    validate_target,
    wait_for_tcp,
    wait_for_unix_socket,
)
from torturer_checks.source_checkout import _pid_alive


class DesktopSliceHelperTest(unittest.TestCase):
    def test_build_commands_use_public_candidate_interfaces(self) -> None:
        root = Path("/candidate")
        self.assertEqual(
            service_build_command(root, "macos", "arm64", skip_dependencies=True),
            [
                sys.executable,
                "/candidate/.github/scripts/desktop_build.py",
                "libs",
                "--platform",
                "macos",
                "--arch",
                "arm64",
                "--skip-deps",
            ],
        )
        self.assertEqual(
            app_build_command(root, "windows", skip_dependencies=False),
            [
                sys.executable,
                "/candidate/.github/scripts/desktop_build.py",
                "app",
                "--platform",
                "windows",
                "--skip-libs",
            ],
        )
        self.assertEqual(
            cli_command(root, "macos", "status", "--json"),
            [
                "/candidate/kmp_module/services/dobby-cli",
                "status",
                "--json",
            ],
        )
        self.assertEqual(
            cli_command(root, "windows", "disconnect"),
            ["/candidate/kmp_module/services/dobby-cli.exe", "disconnect"],
        )

    def test_service_commands_are_argument_vectors(self) -> None:
        self.assertEqual(service_command(Path("/service"), "macos", None), ["/service"])
        self.assertEqual(
            service_command(Path("C:/service.exe"), "windows", 50151),
            ["C:/service.exe", "-port", "50151"],
        )
        with self.assertRaisesRegex(SliceFailure, "requires a loopback"):
            service_command(Path("C:/service.exe"), "windows", None)

    def test_runner_validation_accounts_for_both_macos_architectures(self) -> None:
        validate_target("macos", "arm64", host_os="Darwin", host_machine="aarch64")
        validate_target("macos", "amd64", host_os="Darwin", host_machine="x86_64")
        validate_target("windows", "amd64", host_os="Windows", host_machine="AMD64")
        with self.assertRaisesRegex(SliceFailure, "matching arm64 hardware"):
            validate_target("macos", "arm64", host_os="Darwin", host_machine="x86_64")
        with self.assertRaisesRegex(SliceFailure, "macOS runner"):
            validate_target("macos", "amd64", host_os="Linux", host_machine="x86_64")
        with self.assertRaisesRegex(SliceFailure, "Windows public slice currently supports amd64"):
            validate_target("windows", "arm64", host_os="Windows", host_machine="arm64")

    def test_fixture_is_malformed_and_non_routable(self) -> None:
        self.assertIn("[\n", MALFORMED_CONFIG)
        self.assertNotIn("://", MALFORMED_CONFIG)
        self.assertNotIn("[[", MALFORMED_CONFIG)

    def test_runtime_environment_is_private_and_does_not_accept_token_overrides(self) -> None:
        old_path = os.environ.get("DOBBYVPN_CONTROL_TOKEN_PATH")
        old_user = os.environ.get("DOBBYVPN_CONTROL_TOKEN_USER")
        os.environ["DOBBYVPN_CONTROL_TOKEN_PATH"] = "should-not-survive"
        os.environ["DOBBYVPN_CONTROL_TOKEN_USER"] = "should-not-survive"
        try:
            runtime = build_runtime_paths(Path("/tmp/runtime"), "windows")
            environment = service_environment("windows", runtime, 50151)
            self.assertEqual(environment["PROGRAMDATA"], "/tmp/runtime/ProgramData")
            self.assertEqual(environment["PORT"], "50151")
            self.assertNotIn("DOBBYVPN_CONTROL_TOKEN_PATH", environment)
            self.assertNotIn("DOBBYVPN_CONTROL_TOKEN_USER", environment)

            mac_runtime = build_runtime_paths(Path("/tmp/mac-runtime"), "macos")
            mac_environment = service_environment("macos", mac_runtime, None)
            self.assertEqual(mac_environment["DOBBYVPN_CONTROL_SOCKET"], "/tmp/mac-runtime/control.sock")
            self.assertEqual(mac_environment["DOBBYVPN_CONTROL_PEER_UID"], str(os.getuid()))
        finally:
            if old_path is None:
                os.environ.pop("DOBBYVPN_CONTROL_TOKEN_PATH", None)
            else:
                os.environ["DOBBYVPN_CONTROL_TOKEN_PATH"] = old_path
            if old_user is None:
                os.environ.pop("DOBBYVPN_CONTROL_TOKEN_USER", None)
            else:
                os.environ["DOBBYVPN_CONTROL_TOKEN_USER"] = old_user

    def test_readiness_helpers_run_on_linux_with_fakes(self) -> None:
        wait_for_tcp(50151, _FakeProcess(), 1, connector=lambda address, timeout: _FakeConnection())
        wait_for_unix_socket(_FakeSocketPath(mode=stat.S_IFSOCK | 0o600), _FakeProcess(), 1)  # type: ignore[arg-type]
        with self.assertRaisesRegex(SliceFailure, "exit code 7"):
            wait_for_tcp(50151, _FakeProcess(returncode=7), 1)

    def test_unix_socket_readiness_waits_for_initial_permission_transition(self) -> None:
        clock = _FakeClock()
        path = _FakeSocketPath(modes=(stat.S_IFSOCK | 0o755, stat.S_IFSOCK | 0o600))

        wait_for_unix_socket(  # type: ignore[arg-type]
            path,
            _FakeProcess(),
            1,
            clock=clock,
            sleeper=clock.sleep,
        )

        self.assertEqual(path.stat_calls, 2)

    def test_unix_socket_readiness_reports_persistent_unsafe_permission_at_timeout(self) -> None:
        clock = _FakeClock()
        path = _FakeSocketPath(mode=stat.S_IFSOCK | 0o755)

        with self.assertRaisesRegex(SliceFailure, r"last observed mode 755"):
            wait_for_unix_socket(  # type: ignore[arg-type]
                path,
                _FakeProcess(),
                0.2,
                clock=clock,
                sleeper=clock.sleep,
            )

        self.assertGreaterEqual(path.stat_calls, 1)

    def test_unix_socket_readiness_still_rejects_non_socket_paths_and_exited_service(self) -> None:
        clock = _FakeClock()
        with self.assertRaisesRegex(SliceFailure, "is not a Unix socket"):
            wait_for_unix_socket(  # type: ignore[arg-type]
                _FakeSocketPath(mode=stat.S_IFREG | 0o600),
                _FakeProcess(),
                1,
                clock=clock,
                sleeper=clock.sleep,
            )
        with self.assertRaisesRegex(SliceFailure, "exit code 7"):
            wait_for_unix_socket(  # type: ignore[arg-type]
                _FakeSocketPath(mode=stat.S_IFSOCK | 0o755),
                _FakeProcess(returncode=7),
                1,
                clock=_FakeClock(),
                sleeper=lambda _: None,
            )

    def test_stop_service_removes_only_a_socket(self) -> None:
        socket_path = _FakeSocketPath(mode=stat.S_IFSOCK | 0o600)
        stop_service(_FakeProcess(), socket_path)  # type: ignore[arg-type]
        self.assertFalse(socket_path.exists())
        regular_path = _FakeSocketPath(mode=stat.S_IFREG | 0o600)
        with self.assertRaisesRegex(SliceFailure, "refusing to remove"):
            stop_service(_FakeProcess(returncode=0), regular_path)  # type: ignore[arg-type]

    def test_run_command_streams_stdout_and_stderr(self) -> None:
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        command = (
            sys.executable,
            "-c",
            "import sys; print('child stdout'); print('child stderr', file=sys.stderr)",
        )
        with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
            result = run_command(command, cwd=Path.cwd(), env=os.environ.copy())
        self.assertEqual(result.returncode, 0)
        self.assertIn("diagnostic_evidence kind=desktop-command", captured_stdout.getvalue())
        self.assertNotIn("child stdout", captured_stdout.getvalue())
        self.assertNotIn("child stderr", captured_stderr.getvalue())

    @unittest.skipIf(os.name == "nt", "the SIGTERM-resistant descendant regression uses POSIX process groups")
    def test_run_command_timeout_kills_descendants_and_retains_complete_streams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desktop-timeout-regression-") as temporary:
            root = Path(temporary)
            pid_file = root / "descendant.pid"
            evidence = root / "evidence"
            command = (
                sys.executable,
                "-c",
                (
                    "import os, signal, sys, time; "
                    f"pid = os.fork(); "
                    f"marker=open({str(pid_file)!r}, 'w', encoding='ascii'); marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                    "print('parent-or-descendant-stdout', flush=True); "
                    "print('parent-or-descendant-stderr', file=sys.stderr, flush=True); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                    "time.sleep(60)"
                ),
            )
            captured_stdout = io.StringIO()
            captured_stderr = io.StringIO()
            with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
                with self.assertRaisesRegex(SliceFailure, "command timed out"):
                    run_command(
                        command,
                        cwd=root,
                        env=os.environ.copy(),
                        timeout_seconds=0.2,
                        evidence_directory=evidence,
                        evidence_label="sigterm-resistant-descendant",
                    )
            self.assertIn("diagnostic_evidence kind=desktop-command", captured_stdout.getvalue())
            self.assertNotIn("parent-or-descendant-stdout", captured_stdout.getvalue())
            self.assertNotIn("parent-or-descendant-stderr", captured_stderr.getvalue())
            self.assertEqual(
                (evidence / "sigterm-resistant-descendant.stdout.raw.log").read_bytes(),
                b"parent-or-descendant-stdout\n" * 2,
            )
            self.assertEqual(
                (evidence / "sigterm-resistant-descendant.stderr.raw.log").read_bytes(),
                b"parent-or-descendant-stderr\n" * 2,
            )
            descendant_pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"SIGTERM-resistant descendant {descendant_pid} survived process-group cleanup")

    @unittest.skipIf(os.name == "nt", "the detached descendant regression uses POSIX sessions")
    def test_zero_exit_leader_cleans_detached_resistant_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desktop-zero-exit-", dir="/tmp") as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            child_pid_file = root / "child.pid"
            command = (
                sys.executable,
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
            with self.assertRaisesRegex(SliceFailure, "normal completion left"):
                run_command(
                    command,
                    cwd=root,
                    env=os.environ.copy(),
                    timeout_seconds=5,
                    evidence_directory=evidence,
                    evidence_label="zero-exit-detached",
                )
            child_pid = int(child_pid_file.read_text(encoding="ascii"))
            cleanup = json.loads(
                (evidence / "zero-exit-detached.cleanup.raw.json").read_text(encoding="utf-8")
            )
            self.assertTrue(cleanup["process_tree_proven"], cleanup)
            self.assertTrue(cleanup["diagnostics"])
            for _ in range(40):
                if not _pid_alive(child_pid):
                    break
                time.sleep(0.05)
            else:
                self.fail(f"detached resistant descendant {child_pid} survived normal-completion cleanup")

    @unittest.skipIf(os.name == "nt", "the pipe-survivor regression uses POSIX process groups")
    def test_repeated_pipe_survivor_cleanup_has_no_resource_warnings(self) -> None:
        """Repeated failed drains close Popen pipes and reap the leader."""

        with tempfile.TemporaryDirectory(prefix="desktop-pipe-load-", dir="/tmp") as temporary:
            root = Path(temporary)
            for index in range(6):
                run_root = root / str(index)
                run_root.mkdir()
                child_pid_file = run_root / "child.pid"
                evidence = run_root / "evidence"
                command = (
                    sys.executable,
                    "-c",
                    (
                        "import os, signal, sys, time; "
                        "print('leader-before-cleanup-stdout', flush=True); "
                        "print('leader-before-cleanup-stderr', file=sys.stderr, flush=True); "
                        "pid=os.fork(); "
                        f"marker=open({str(child_pid_file)!r}, 'w', encoding='ascii'); marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                        "time.sleep(60)"
                    ),
                )
                leaders: list[object] = []

                def fake_cleanup(
                    process: object,
                    *,
                    grace_seconds: float | None = None,
                    description: str,
                    force_immediately: bool = False,
                    evidence_directory: Path | None = None,
                    deadline: float | None = None,
                ) -> ProcessTreeResult:
                    leaders.append(process)
                    process.kill()  # type: ignore[attr-defined]
                    return ProcessTreeResult(False, (process.pid,), ("injected survivor",))  # type: ignore[attr-defined]

                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always", ResourceWarning)
                    try:
                        with patch.object(desktop_slice, "_terminate_process_tree", side_effect=fake_cleanup):
                            with self.assertRaisesRegex(SliceFailure, "injected survivor"):
                                run_command(
                                    command,
                                    cwd=run_root,
                                    env=os.environ.copy(),
                                    timeout_seconds=0.2,
                                    evidence_directory=evidence,
                                    evidence_label="pipe-survivor-load",
                                )
                        gc.collect()
                        self.assertEqual(
                            [warning for warning in captured if issubclass(warning.category, ResourceWarning)],
                            [],
                        )
                        self.assertTrue(leaders)
                        for leader in leaders:
                            self.assertIsNotNone(leader.poll())  # type: ignore[attr-defined]
                            self.assertTrue(leader.stdout.closed)  # type: ignore[attr-defined]
                            self.assertTrue(leader.stderr.closed)  # type: ignore[attr-defined]
                        self.assertEqual(
                            (evidence / "pipe-survivor-load.stdout.raw.log").read_bytes(),
                            b"leader-before-cleanup-stdout\n",
                        )
                        self.assertEqual(
                            (evidence / "pipe-survivor-load.stderr.raw.log").read_bytes(),
                            b"leader-before-cleanup-stderr\n",
                        )
                    finally:
                        if child_pid_file.exists():
                            try:
                                os.kill(int(child_pid_file.read_text(encoding="ascii")), signal.SIGKILL)
                            except (OSError, ValueError):
                                pass

    def test_default_evidence_is_durable_reported_private_and_non_overwriting(self) -> None:
        captured_stderr = io.StringIO()
        command = (sys.executable, "-c", "print('default-evidence')")
        with redirect_stderr(captured_stderr):
            result = run_command(
                command,
                cwd=Path.cwd(),
                env=os.environ.copy(),
                evidence_label="default-persistent",
            )
        self.assertIsNotNone(result.evidence_directory)
        self.assertIsNotNone(result.stdout_path)
        self.assertIsNotNone(result.stderr_path)
        self.assertIsNotNone(result.cleanup_path)
        evidence = result.evidence_directory
        self.assertFalse(evidence.is_symlink())
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(result.stdout_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(result.stderr_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(result.cleanup_path.stat().st_mode), 0o600)
        self.assertNotIn(str(evidence), captured_stderr.getvalue())
        self.assertEqual(result.stdout_path.read_bytes(), b"default-evidence\n")
        with self.assertRaisesRegex(SliceFailure, "overwrite existing"):
            run_command(
                command,
                cwd=Path.cwd(),
                env=os.environ.copy(),
                evidence_directory=evidence,
                evidence_label="default-persistent",
            )

    def test_default_evidence_resolves_os_managed_temp_aliases(self) -> None:
        """macOS's /var -> /private/var alias must not reject fresh evidence."""

        with tempfile.TemporaryDirectory(prefix="desktop-temp-alias-") as temporary:
            root = Path(temporary)
            real_temp = root / "private" / "var" / "folders"
            real_temp.mkdir(parents=True)
            aliased_temp = root / "var"
            aliased_temp.symlink_to(root / "private" / "var", target_is_directory=True)
            generated = aliased_temp / "folders" / "torturer"
            generated.mkdir(mode=0o700)
            with patch.object(desktop_slice.tempfile, "mkdtemp", return_value=str(generated)):
                evidence = _prepare_evidence_directory(None)
            self.assertEqual(evidence, generated.resolve())
            self.assertFalse(evidence.is_symlink())
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)

    def test_explicit_evidence_target_symlink_is_still_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desktop-explicit-evidence-") as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(SliceFailure, "contains a symlink"):
                _validate_evidence_directory(link)

    def test_windows_evidence_validation_does_not_apply_posix_mode_bits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desktop-windows-evidence-") as temporary:
            directory = Path(temporary) / "evidence"
            directory.mkdir(mode=0o755)
            _validate_evidence_directory(directory, host_os="nt")

    def test_run_budget_enforces_1800_seconds_and_preserves_cleanup_reserve(self) -> None:
        self.assertEqual(MAX_RUN_SECONDS, 1800)
        self.assertGreater(CLEANUP_RESERVE_SECONDS, 0)
        clock = _FakeClock()
        budget = RunBudget(max_seconds=10, cleanup_reserve_seconds=2, clock=clock)
        self.assertEqual(budget.operation_timeout(), 8)
        clock.value = 7
        self.assertEqual(budget.operation_timeout(), 1)
        clock.value = 8.1
        with self.assertRaisesRegex(SliceFailure, "functional budget"):
            budget.operation_timeout()
        self.assertLessEqual(budget.cleanup_timeout(), 2)

    @unittest.skipIf(os.name == "nt", "the wall-clock probe uses POSIX process groups")
    def test_total_command_timeout_includes_cleanup_and_does_not_run_grace_after_deadline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desktop-total-bound-", dir="/tmp") as temporary:
            evidence = Path(temporary) / "evidence"
            started = time.monotonic()
            with self.assertRaisesRegex(SliceFailure, "command timed out"):
                run_command(
                    (sys.executable, "-c", "import time; print('bounded', flush=True); time.sleep(60)"),
                    cwd=Path(temporary),
                    env=os.environ.copy(),
                    timeout_seconds=0.4,
                    evidence_directory=evidence,
                    evidence_label="total-bound",
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.2)
            cleanup = json.loads(
                (evidence / "total-bound.cleanup.raw.json").read_text(encoding="utf-8")
            )
            self.assertIn("process_tree_proven", cleanup)

    def test_result_assertions_report_command_output(self) -> None:
        failure = CommandResult(("tool",), 1, "out", "err")
        with self.assertRaisesRegex(SliceFailure, "exit_code=1"):
            require_success(failure, "phase")
        with self.assertRaisesRegex(SliceFailure, "unexpectedly succeeded"):
            require_nonzero(CommandResult(("tool",), 0, "", ""), "phase")

    def test_safe_failure_reason_preserves_contract_detail_without_secrets(self) -> None:
        reason = safe_failure_reason(
            SliceFailure(
                "service exited before readiness (exit code 1); "
                "token=private-token Authorization: Bearer private-bearer "
                '\"password\": \"private-json\" '
                "access_token=private-access refresh-token=private-refresh "
                "id_token=private-id client_secret=private-client "
                "private_key=private-key Bearer private-unlabelled "
                "https://profile.example.test/config?secret=private"
            )
        )
        self.assertIn("service exited before readiness (exit code 1)", reason)
        self.assertIn("token=<redacted>", reason)
        self.assertIn("Authorization: <redacted>", reason)
        self.assertIn('\"password\": <redacted>', reason)
        self.assertIn("<redacted-url>", reason)
        self.assertNotIn("private-token", reason)
        self.assertNotIn("private-bearer", reason)
        self.assertNotIn("private-json", reason)
        self.assertNotIn("private-access", reason)
        self.assertNotIn("private-refresh", reason)
        self.assertNotIn("private-id", reason)
        self.assertNotIn("private-client", reason)
        self.assertNotIn("private-key", reason)
        self.assertNotIn("private-unlabelled", reason)
        self.assertNotIn("profile.example.test", reason)

    def test_safe_failure_reason_never_publishes_retained_command_streams(self) -> None:
        reason = safe_failure_reason(
            SliceFailure(
                "CLI status failed\n"
                "command=('tool',) returncode=1 stdout='private-output' "
                "stderr='private-error'"
            )
        )
        self.assertEqual(reason, "CLI status failed")
        self.assertNotIn("private-output", reason)
        self.assertNotIn("private-error", reason)

    def test_main_publishes_safe_failure_reason_instead_of_only_exception_type(self) -> None:
        captured_stderr = io.StringIO()
        failure = SliceFailure("service exited before readiness (exit code 7)")
        with patch.object(desktop_slice, "run_slice", side_effect=failure):
            with redirect_stderr(captured_stderr):
                result = desktop_slice.main(
                    [
                        "--candidate",
                        "/candidate",
                        "--commit-sha",
                        "0123456789abcdef0123456789abcdef01234567",
                        "--platform",
                        "macos",
                        "--arch",
                        "arm64",
                    ]
                )
        self.assertEqual(result, 1)
        self.assertIn(
            "desktop_slice status=failed code=SliceFailure reason=service exited before readiness (exit code 7)",
            captured_stderr.getvalue(),
        )

    def test_candidate_path_requires_both_gradle_launchers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / BUILD_SCRIPT_RELATIVE_PATH).parent.mkdir(parents=True)
            (root / BUILD_SCRIPT_RELATIVE_PATH).touch()
            (root / GRADLE_RELATIVE_PATH).parent.mkdir(parents=True, exist_ok=True)
            (root / GRADLE_RELATIVE_PATH).touch()
            (root / "go_module").mkdir()
            (root / "kmp_module").mkdir(exist_ok=True)
            with self.assertRaisesRegex(SliceFailure, "gradlew.bat"):
                candidate_path(temporary)
            (root / WINDOWS_GRADLE_RELATIVE_PATH).touch()
            self.assertEqual(candidate_path(temporary), root.resolve())

    def test_service_paths_match_public_build_outputs(self) -> None:
        self.assertEqual(str(SERVICE_RELATIVE_PATHS["macos"]), "kmp_module/services/macos_grpcvpnserver")
        self.assertEqual(str(SERVICE_RELATIVE_PATHS["windows"]), "kmp_module/services/windows_grpcvpnserver.exe")
        self.assertEqual(str(CLI_RELATIVE_PATHS["macos"]), "kmp_module/services/dobby-cli")
        self.assertEqual(str(CLI_RELATIVE_PATHS["windows"]), "kmp_module/services/dobby-cli.exe")


class _FakeProcess:
    def __init__(self, returncode: int | None = None) -> None:
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.returncode = -9


class _FakeConnection:
    def close(self) -> None:
        pass


class _FakeSocketPath:
    def __init__(self, *, mode: int | None = None, modes: tuple[int, ...] | None = None) -> None:
        if (mode is None) == (modes is None):
            raise ValueError("provide exactly one of mode or modes")
        self.modes = modes or (mode,)
        self.mode = self.modes[0]
        self.present = True
        self.stat_calls = 0

    def stat(self):  # type: ignore[no-untyped-def]
        if not self.present:
            raise FileNotFoundError
        index = min(self.stat_calls, len(self.modes) - 1)
        self.mode = self.modes[index]
        self.stat_calls += 1
        return _FakeStat(self.mode)

    def lstat(self):  # type: ignore[no-untyped-def]
        return self.stat()

    def exists(self) -> bool:
        return self.present

    def is_socket(self) -> bool:
        return self.present and stat.S_ISSOCK(self.mode)

    def unlink(self) -> None:
        self.present = False

    def __str__(self) -> str:
        return "/fake/control.sock"


class _FakeStat:
    def __init__(self, mode: int) -> None:
        self.st_mode = mode


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


if __name__ == "__main__":
    unittest.main()
