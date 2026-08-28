from __future__ import annotations

import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

TORTURER_ROOT = Path(__file__).resolve().parents[3]
if str(TORTURER_ROOT) not in sys.path:
    sys.path.insert(0, str(TORTURER_ROOT))

import torturer_checks.linux_slice as linux_slice
from torturer_checks.linux_slice import (
    BUILD_SCRIPT_RELATIVE_PATH,
    CLI_RELATIVE_PATH,
    CLEANUP_RESERVE_SECONDS,
    MAX_FUNCTIONAL_SECONDS,
    MAX_RUN_SECONDS,
    GRADLE_RELATIVE_PATH,
    MALFORMED_CONFIG,
    SERVICE_RELATIVE_PATH,
    CommandResult,
    RunBudget,
    SliceFailure,
    _link_state,
    assert_cli_contract,
    app_build_command,
    build_command,
    candidate_path,
    cli_command,
    probe_linux_capabilities,
    run_transfer_metrics,
    run_network_transition,
    run_sleep_wake,
    require_nonzero,
    run_command,
    require_success,
    service_environment,
    stop_service,
    _open_owner_only_service_log,
    verify_expected_process,
    wait_for_socket,
)


class LinuxSliceHelperTest(unittest.TestCase):
    def test_build_commands_use_public_candidate_interfaces(self) -> None:
        root = Path("/candidate")
        self.assertEqual(
            build_command(root, skip_dependencies=True),
            [
                sys.executable,
                "/candidate/.github/scripts/desktop_build.py",
                "libs",
                "--platform",
                "linux",
                "--arch",
                "amd64",
                "--skip-deps",
            ],
        )
        self.assertEqual(
            app_build_command(root, skip_dependencies=False),
            [
                sys.executable,
                "/candidate/.github/scripts/desktop_build.py",
                "app",
                "--platform",
                "linux",
                "--skip-libs",
            ],
        )
        self.assertEqual(
            cli_command(root, "status", "--json"),
            [
                "/candidate/kmp_module/services/dobby-cli",
                "status",
                "--json",
            ],
        )

    def test_fixture_is_non_routable_and_malformed(self) -> None:
        self.assertIn("[\n", MALFORMED_CONFIG)
        self.assertNotIn("://", MALFORMED_CONFIG)
        self.assertNotIn("[[", MALFORMED_CONFIG)

    def test_cli_status_json_accepts_compact_and_spaced_output(self) -> None:
        for status_output in (
            '{"code":0,"state":"Disconnected"}',
            '{\n  "code": 0,\n  "state": "Disconnected"\n}',
        ):
            with patch.object(
                linux_slice,
                "run_command",
                side_effect=[
                    CommandResult((), 0, "check-config verify-session", ""),
                    CommandResult((), 0, status_output, ""),
                    CommandResult((), 1, "", ""),
                    CommandResult((), 0, "", ""),
                ],
            ):
                assert_cli_contract(
                    Path("/candidate"),
                    {},
                    Path("/fixture"),
                    budget=RunBudget(max_seconds=30, cleanup_reserve_seconds=1),
                    evidence_directory=None,
                )

    def test_cli_status_json_rejects_malformed_extra_and_wrong_state(self) -> None:
        for status_output in (
            "not-json",
            '{"code":0,"state":"Disconnected","extra":true}',
            '{"code":2,"state":"Connected"}',
        ):
            with self.subTest(status_output=status_output):
                with patch.object(
                    linux_slice,
                    "run_command",
                    side_effect=[
                        CommandResult((), 0, "check-config verify-session", ""),
                        CommandResult((), 0, status_output, ""),
                    ],
                ):
                    with self.assertRaisesRegex(
                        SliceFailure, r"(?:CLI status JSON was invalid|initial disconnected)"
                    ):
                        assert_cli_contract(
                            Path("/candidate"),
                            {},
                            Path("/fixture"),
                            budget=RunBudget(max_seconds=30, cleanup_reserve_seconds=1),
                            evidence_directory=None,
                        )

    def test_run_command_streams_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-command-evidence-") as temporary:
            evidence = Path(temporary) / "evidence"
            captured_stdout = io.StringIO()
            captured_stderr = io.StringIO()
            command = (
                sys.executable,
                "-c",
                "import sys; print('child stdout'); print('child stderr', file=sys.stderr)",
            )
            with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
                result = run_command(
                    command,
                    cwd=Path.cwd(),
                    env=os.environ.copy(),
                    evidence_directory=evidence,
                    evidence_label="streams",
                )
            self.assertEqual(result.returncode, 0)
            self.assertIn("diagnostic_evidence kind=linux-command", captured_stdout.getvalue())
            self.assertIn("child stdout", (evidence / "streams.stdout.raw.log").read_text())
            self.assertIn("child stderr", (evidence / "streams.stderr.raw.log").read_text())
            self.assertNotIn("child stdout", captured_stdout.getvalue())
            self.assertNotIn("child stderr", captured_stderr.getvalue())

    @unittest.skipIf(os.name == "nt", "the SIGTERM-resistant descendant regression uses POSIX process groups")
    def test_run_command_timeout_kills_descendants_and_retains_complete_streams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-timeout-regression-") as temporary:
            root = Path(temporary)
            pid_file = root / "descendant.pid"
            evidence = root / "evidence"
            command = (
                sys.executable,
                "-c",
                (
                    "import os, signal, sys, time; "
                    f"pid = os.fork(); "
                    f"open({str(pid_file)!r}, 'w', encoding='ascii').write(str(os.getpid()) if pid == 0 else str(pid)); "
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
            self.assertIn("diagnostic_evidence kind=linux-command", captured_stdout.getvalue())
            self.assertNotIn("parent-or-descendant-stdout", captured_stdout.getvalue())
            self.assertNotIn("parent-or-descendant-stderr", captured_stderr.getvalue())
            stdout_evidence = (evidence / "sigterm-resistant-descendant.stdout.raw.log").read_bytes()
            stderr_evidence = (evidence / "sigterm-resistant-descendant.stderr.raw.log").read_bytes()
            self.assertGreaterEqual(stdout_evidence.count(b"parent-or-descendant-stdout\n"), 2)
            self.assertGreaterEqual(stderr_evidence.count(b"parent-or-descendant-stderr\n"), 2)
            descendant_pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"SIGTERM-resistant descendant {descendant_pid} survived process-group cleanup")

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "detached-descendant regression requires a POSIX /proc process table",
    )
    def test_run_command_timeout_kills_detached_descendants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-detached-timeout-regression-") as temporary:
            root = Path(temporary)
            pid_file = root / "detached-descendant.pid"
            command = (
                sys.executable,
                "-c",
                (
                    "import os, signal, time; "
                    f"pid = os.fork(); "
                    f"os.setsid() if pid == 0 else None; "
                    f"open({str(pid_file)!r}, 'w', encoding='ascii').write(str(os.getpid()) if pid == 0 else str(pid)); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                    "time.sleep(60)"
                ),
            )
            with self.assertRaisesRegex(SliceFailure, "command timed out"):
                run_command(
                    command,
                    cwd=root,
                    env=os.environ.copy(),
                    timeout_seconds=0.2,
                    evidence_directory=root / "evidence",
                    evidence_label="detached-descendant",
                )
            detached_pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                try:
                    os.kill(detached_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"detached descendant {detached_pid} survived process-tree cleanup")

    def test_run_budget_enforces_1800_seconds_and_preserves_cleanup_reserve(self) -> None:
        self.assertEqual(MAX_RUN_SECONDS, 1800)
        self.assertEqual(CLEANUP_RESERVE_SECONDS, 120)
        self.assertEqual(MAX_FUNCTIONAL_SECONDS, 1680)
        clock = _FakeClock()
        budget = RunBudget(max_seconds=10, cleanup_reserve_seconds=2, clock=clock)
        self.assertEqual(budget.operation_timeout(), 8)
        clock.value = 7
        self.assertEqual(budget.operation_timeout(), 1)
        clock.value = 8.1
        with self.assertRaisesRegex(SliceFailure, "functional budget"):
            budget.operation_timeout()
        self.assertLessEqual(budget.cleanup_timeout(), 2)
        with self.assertRaisesRegex(SliceFailure, "cleanup window"):
            with tempfile.TemporaryDirectory(prefix="linux-budget-reject-") as temporary:
                run_sleep_wake(
                    cwd=Path(temporary),
                    env=os.environ.copy(),
                    timeout_seconds=MAX_RUN_SECONDS,
                    evidence_directory=Path(temporary) / "evidence",
                )

    def test_command_evidence_is_owner_only_and_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-evidence-regression-") as temporary:
            evidence = Path(temporary) / "evidence"
            command = (sys.executable, "-c", "print('one')")
            run_command(
                command,
                cwd=Path.cwd(),
                env=os.environ.copy(),
                evidence_directory=evidence,
                evidence_label="exclusive",
            )
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                (evidence / "exclusive.stdout.raw.log").stat().st_mode & 0o777,
                0o600,
            )
            with self.assertRaisesRegex(SliceFailure, "overwrite"):
                run_command(
                    command,
                    cwd=Path.cwd(),
                    env=os.environ.copy(),
                    evidence_directory=evidence,
                    evidence_label="exclusive",
                )

    def test_service_diagnostics_are_binary_retained_and_not_truncated(self) -> None:
        source = (TORTURER_ROOT / "torturer_checks" / "linux_slice.py").read_text(encoding="utf-8")
        self.assertIn('path.open("xb", buffering=0)', source)
        self.assertIn("os.fchmod(service_log.fileno(), 0o600)", source)
        self.assertNotIn("service_log.chmod", source)
        self.assertIn("service.combined.raw.log", source)
        self.assertIn("path.read_bytes()", source)
        self.assertNotIn("logs[-", source)

    def test_service_log_creation_enforces_owner_only_mode_on_path(self) -> None:
        """Exercise the FileIO permission boundary used by the service launch."""

        with tempfile.TemporaryDirectory(prefix="linux-service-log-") as temporary:
            path = Path(temporary) / "service.combined.log"
            with _open_owner_only_service_log(path) as service_log:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                service_log.write(b"complete service diagnostic\n")
                service_log.flush()
            self.assertEqual(path.read_bytes(), b"complete service diagnostic\n")

    def test_canonical_linux_primitives_require_state_repair_and_process_proofs(self) -> None:
        source = (TORTURER_ROOT / "torturer_checks" / "linux_slice.py").read_text(encoding="utf-8")
        self.assertIn("def probe_linux_capabilities(", source)
        self.assertIn("def run_network_transition(", source)
        self.assertIn("network transition would destroy its control path", source)
        self.assertIn("network transition control path was not preserved", source)
        self.assertIn("network transition down state was not proved", source)
        self.assertIn("network transition restored state was not proved", source)
        self.assertIn("_start_delayed_process", source)
        self.assertIn("_finish_delayed_process", source)
        self.assertIn("def run_sleep_wake(", source)
        self.assertIn("CLOCK_BOOTTIME", source)
        self.assertIn("def run_transfer_metrics(", source)
        self.assertIn("curl-latency-", source)
        self.assertIn("curl-download-", source)
        self.assertIn("curl-upload-", source)
        self.assertIn("def verify_expected_process(", source)
        self.assertIn("process PID is not bound to the expected product executable", source)

    def test_link_state_parser_rejects_ambiguous_or_wrong_states(self) -> None:
        self.assertEqual(_link_state("2: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP"), (("BROADCAST", "UP", "LOWER_UP"), "UP"))
        self.assertEqual(_link_state("2: eth0: <BROADCAST> mtu 1500 state DOWN"), (("BROADCAST",), "DOWN"))
        self.assertIsNone(_link_state("not an ip link record"))

    def test_curl_metrics_keep_unique_raw_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-curl-metrics-") as temporary:
            root = Path(temporary)
            fake_curl = root / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "args=' '.join(sys.argv)\n"
                "value='0.25,200' if 'time_total' in args else ('1000000,200' if 'speed_download' in args else '2000000,200')\n"
                "print(value)\n"
                "print('curl complete diagnostic', file=sys.stderr)\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o700)
            evidence = root / "evidence"
            metrics = run_transfer_metrics(
                "https://download.invalid/blob", "https://upload.invalid/blob",
                cwd=root, env={**os.environ, "PATH": f"{root}:{os.environ.get('PATH', '')}"},
                timeout_seconds=10, evidence_directory=evidence,
            )
            self.assertEqual(metrics, {"latency_ms": 250.0, "download_mbps": 8.0, "upload_mbps": 16.0})
            raw = sorted(evidence.glob("curl-*.raw.log"))
            self.assertEqual(len(raw), 6)
            self.assertEqual(len({path.name for path in raw}), 6)
            self.assertTrue(any(b"1000000,200" in path.read_bytes() for path in raw))
            self.assertTrue(all(b"curl complete diagnostic" in path.read_bytes() for path in raw if path.name.endswith("stderr.raw.log")))

    def test_process_identity_binds_to_exact_expected_binary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-process-identity-") as temporary:
            root = Path(temporary)
            expected = root / "service"
            expected.write_text("candidate", encoding="utf-8")
            expected.chmod(0o700)
            fake_sudo = root / "sudo"
            fake_sudo.write_text(
                "#!/bin/sh\n"
                "shift 1\n"
                "if [ \"$1\" = readlink ]; then printf '%s\\n' \"$EXPECTED_BINARY\"; exit 0; fi\n"
                "exit 1\n",
                encoding="utf-8",
            )
            fake_sudo.chmod(0o700)
            env = {**os.environ, "PATH": str(root), "EXPECTED_BINARY": str(expected)}
            verify_expected_process(123, expected, cwd=root, env=env, timeout_seconds=5, evidence_directory=root / "evidence")
            other = root / "other-service"
            other.write_text("other", encoding="utf-8")
            other.chmod(0o700)
            with self.assertRaisesRegex(SliceFailure, "not bound"):
                verify_expected_process(123, other, cwd=root, env=env, timeout_seconds=5, evidence_directory=root / "evidence-2")

    def test_capability_probe_requires_live_network_and_privilege_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-capability-probe-") as temporary:
            root = Path(temporary)
            (root / "sh").write_text(
                "#!/bin/sh\n"
                "case \"$2\" in\n"
                "  'command -v ip') printf '%s\\n' /usr/bin/ip ;;\n"
                "  'command -v rtcwake') printf '%s\\n' /usr/bin/rtcwake ;;\n"
                "  'command -v ps') printf '%s\\n' /bin/ps ;;\n"
                "  'command -v kill') printf '%s\\n' /bin/kill ;;\n"
                "  'command -v readlink') printf '%s\\n' /usr/bin/readlink ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            (root / "ip").write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'default via 192.0.2.1 dev eth0'\n",
                encoding="utf-8",
            )
            (root / "cat").write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'mem disk'\n",
                encoding="utf-8",
            )
            (root / "sudo").write_text(
                "#!/bin/sh\n"
                "[ \"${FAIL_SUDO:-}\" = 1 ] && exit 1\n"
                "exit 0\n",
                encoding="utf-8",
            )
            for tool in ("sh", "ip", "cat", "sudo"):
                (root / tool).chmod(0o700)
            environment = {**os.environ, "PATH": f"{root}:{os.environ.get('PATH', '')}"}
            capabilities = probe_linux_capabilities(
                cwd=root,
                env=environment,
                evidence_directory=root / "evidence-live",
            )
            self.assertIn("network_transition", capabilities)
            self.assertIn("sleep_wake", capabilities)
            self.assertIn("process_loss", capabilities)

            unavailable = probe_linux_capabilities(
                cwd=root,
                env={**environment, "FAIL_SUDO": "1"},
                evidence_directory=root / "evidence-unprivileged",
            )
            self.assertNotIn("network_transition", unavailable)
            self.assertNotIn("sleep_wake", unavailable)

    @unittest.skipIf(os.name == "nt", "Linux link-state primitive requires POSIX commands")
    def test_network_transition_proves_down_and_restored_with_independent_repair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-network-transition-") as temporary:
            root = Path(temporary)
            state = root / "state"
            state.write_text("up", encoding="ascii")
            ip = root / "ip"
            ip.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys\n"
                "state=pathlib.Path(os.environ['FAKE_LINK_STATE'])\n"
                "args=sys.argv[1:]\n"
                "if args[:4] == ['-o','route','show','default']:\n"
                " print('default via 192.0.2.1 dev eth0')\n"
                "elif args[:4] == ['-o','link','show','dev']:\n"
                " iface=args[4]\n"
                " print(f'2: {iface}: <BROADCAST,UP,LOWER_UP> state UP' if state.read_text().strip() == 'up' else f'2: {iface}: <BROADCAST> state DOWN')\n"
                "else: raise SystemExit(2)\n",
                encoding="utf-8",
            )
            ip.chmod(0o700)
            sudo = root / "sudo"
            sudo.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys\n"
                "args=sys.argv[1:]\n"
                "if args[:2] == ['-n','true']: raise SystemExit(0)\n"
                "if args[:5] == ['-n','ip','link','set','dev']:\n"
                " pathlib.Path(os.environ['FAKE_LINK_STATE']).write_text('down' if args[6] == 'down' else 'up')\n"
                " raise SystemExit(0)\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
            sudo.chmod(0o700)
            environment = {**os.environ, "PATH": f"{root}:{os.environ.get('PATH', '')}", "FAKE_LINK_STATE": str(state)}
            result = run_network_transition(
                "eth0", control_interface="ssh0", cwd=root, env=environment,
                timeout_seconds=10, evidence_directory=root / "evidence",
            )
            self.assertEqual(result["network_transition_verified"], True)
            self.assertEqual(state.read_text(encoding="ascii"), "up")
            with self.assertRaisesRegex(SliceFailure, "destroy its control path"):
                run_network_transition(
                    "eth0", control_interface="eth0", cwd=root, env=environment,
                    timeout_seconds=10, evidence_directory=root / "evidence-same-path",
                )

    @unittest.skipIf(os.name == "nt", "Linux sleep primitive requires POSIX commands")
    def test_sleep_wake_retains_event_timing_and_process_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-sleep-wake-") as temporary:
            root = Path(temporary)
            sudo = root / "sudo"
            sudo.write_text(
                "#!/bin/sh\n"
                "if [ \"$2\" = rtcwake ]; then sleep 4; exit 0; fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            sudo.chmod(0o700)
            result = run_sleep_wake(
                cwd=root, env={**os.environ, "PATH": f"{root}:{os.environ.get('PATH', '')}"},
                timeout_seconds=8, evidence_directory=root / "evidence",
            )
            self.assertTrue(result["sleep_wake_verified"])
            self.assertGreaterEqual(int(result["boottime_elapsed_ns"]), 4_000_000_000)
            self.assertTrue(list((root / "evidence").glob("sleep-wake-*.raw.log")))

    def test_timeout_final_drain_proves_tree_and_default_evidence_is_persistent(self) -> None:
        source = (TORTURER_ROOT / "torturer_checks" / "linux_slice.py").read_text(encoding="utf-8")
        self.assertIn('results_root = Path.cwd() / "results"', source)
        self.assertIn('dir=results_root', source)
        self.assertIn('description="command-final-drain"', source)
        self.assertIn("_wait_for_process_tree(process, tracked, 0.0)", source)

    def test_timeout_and_oserror_drains_merge_each_partial_stream_once(self) -> None:
        class FakeProcess:
            pid = 1234
            returncode = 0

            def __init__(self) -> None:
                self.calls = 0

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(
                        ("safe-command",), timeout,
                        output=b"partial-out", stderr=b"partial-err",
                    )
                if self.calls == 2:
                    error = OSError(5, "pipe failed")
                    error.stdout = b"partial-out"  # type: ignore[attr-defined]
                    error.stderr = b"partial-err"  # type: ignore[attr-defined]
                    raise error
                return b"partial-out-final", b"partial-err-final"

            def wait(self, *, timeout: float) -> int:
                return 0

            def poll(self) -> int:
                return self.returncode

        process = FakeProcess()
        with patch.object(
            linux_slice,
            "_terminate_process_tree",
            return_value={process.pid},
        ):
            stdout, stderr, diagnostics, complete = linux_slice._drain_after_failure(
                process,
                b"partial-out",
                b"partial-err",
                timeout_seconds=1.0,
                description="command",
                tracked={process.pid},
            )
        self.assertEqual(stdout, b"partial-out-final")
        self.assertEqual(stderr, b"partial-err-final")
        self.assertTrue(complete)
        # A pipe exception occurred even though a later retry reached EOF;
        # preserve that uncertainty in the diagnostic record.
        self.assertIn(b"EVIDENCE_INCOMPLETE=1", diagnostics)

    def test_unproven_linux_drain_retains_partial_bytes_and_marks_incomplete(self) -> None:
        class FakeProcess:
            pid = 1235
            returncode = None

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                error = OSError(5, "pipe failed")
                error.stdout = b"partial-out"  # type: ignore[attr-defined]
                error.stderr = b"partial-err"  # type: ignore[attr-defined]
                raise error

            def wait(self, *, timeout: float) -> int:
                raise subprocess.TimeoutExpired(("safe-command",), timeout)

            def poll(self) -> None:
                return None

        process = FakeProcess()
        with patch.object(linux_slice, "_terminate_process_tree", return_value={process.pid}):
            stdout, stderr, diagnostics, complete = linux_slice._drain_after_failure(
                process,
                b"partial-out",
                b"partial-err",
                timeout_seconds=0.01,
                description="command",
                tracked={process.pid},
            )
        self.assertEqual(stdout, b"partial-out")
        self.assertEqual(stderr, b"partial-err")
        self.assertFalse(complete)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1", diagnostics)

    def test_result_assertions_report_output(self) -> None:
        failure = CommandResult(("tool",), 1, "out", "err")
        with self.assertRaisesRegex(SliceFailure, "exit_code=1"):
            require_success(failure, "phase")
        with self.assertRaisesRegex(SliceFailure, "unexpectedly succeeded"):
            require_nonzero(CommandResult(("tool",), 0, "", ""), "phase")

    def test_candidate_path_rejects_missing_public_interfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(SliceFailure, "desktop build interfaces"):
                candidate_path(temporary)

    def test_candidate_path_accepts_minimal_public_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / BUILD_SCRIPT_RELATIVE_PATH).parent.mkdir(parents=True)
            (root / BUILD_SCRIPT_RELATIVE_PATH).touch()
            (root / GRADLE_RELATIVE_PATH).parent.mkdir(parents=True, exist_ok=True)
            (root / GRADLE_RELATIVE_PATH).touch()
            (root / "go_module").mkdir()
            self.assertEqual(candidate_path(temporary), root.resolve())

    def test_service_environment_uses_current_user_and_private_socket(self) -> None:
        environment = service_environment(Path("/candidate/services"), Path("/tmp/control.sock"))
        self.assertEqual(environment["DOBBYVPN_CONTROL_PEER_UID"], str(os.getuid()))
        self.assertEqual(environment["DOBBYVPN_CONTROL_SOCKET"], "/tmp/control.sock")
        self.assertEqual(environment["LD_LIBRARY_PATH"], "/candidate/services")

    def test_wait_for_socket_requires_socket_and_private_mode(self) -> None:
        path = _FakeSocketPath(mode=stat.S_IFSOCK | 0o600)
        wait_for_socket(path, _FakeProcess(), 1)  # type: ignore[arg-type]

    def test_wait_for_socket_rejects_wrong_mode(self) -> None:
        with self.assertRaisesRegex(SliceFailure, "expected 600"):
            wait_for_socket(  # type: ignore[arg-type]
                _FakeSocketPath(mode=stat.S_IFSOCK | 0o666), _FakeProcess(), 1
            )

    def test_stop_service_removes_only_a_socket(self) -> None:
        path = _FakeSocketPath(mode=stat.S_IFSOCK | 0o600)
        stop_service(_FakeProcess(), path)  # type: ignore[arg-type]
        self.assertFalse(path.exists())

    def test_stop_service_refuses_non_socket_cleanup_target(self) -> None:
        path = _FakeSocketPath(mode=stat.S_IFREG | 0o600)
        with self.assertRaisesRegex(SliceFailure, "refusing to remove"):
            stop_service(_FakeProcess(returncode=0), path)  # type: ignore[arg-type]
        self.assertTrue(path.exists())

    def test_service_relative_path_is_expected_linux_output(self) -> None:
        self.assertEqual(str(SERVICE_RELATIVE_PATH), "kmp_module/services/ubuntu_grpcvpnserver")
        self.assertEqual(str(CLI_RELATIVE_PATH), "kmp_module/services/dobby-cli")

    def test_main_publishes_safe_failure_reason_without_retained_command_streams(self) -> None:
        captured_stderr = io.StringIO()
        failure = SliceFailure(
            "CLI status failed\n"
            "stdout=private-output stderr=private-error token=private-token "
            "https://profile.example.test/config"
        )
        with patch.object(linux_slice, "run_slice", side_effect=failure):
            with redirect_stderr(captured_stderr):
                result = linux_slice.main(
                    [
                        "--candidate",
                        "/candidate",
                        "--commit-sha",
                        "0123456789abcdef0123456789abcdef01234567",
                    ]
                )
        self.assertEqual(result, 1)
        output = captured_stderr.getvalue()
        self.assertIn("reason=CLI status failed", output)
        self.assertNotIn("private-output", output)
        self.assertNotIn("private-error", output)
        self.assertNotIn("private-token", output)
        self.assertNotIn("profile.example.test", output)


class _FakeProcess:
    def __init__(self, returncode: int | None = None) -> None:
        self.returncode = returncode
        self.sent_signal: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def send_signal(self, value: int) -> None:
        self.sent_signal = value
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.returncode = -9


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class _FakeSocketPath:
    def __init__(self, *, mode: int) -> None:
        self.mode = mode
        self.present = True

    def stat(self):  # type: ignore[no-untyped-def]
        if not self.present:
            raise FileNotFoundError
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


if __name__ == "__main__":
    unittest.main()
