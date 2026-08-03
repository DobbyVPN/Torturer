from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


TORTURER_ROOT = Path(__file__).resolve().parents[3]
if str(TORTURER_ROOT) not in sys.path:
    sys.path.insert(0, str(TORTURER_ROOT))

from torturer_checks.desktop_slice import (
    BUILD_SCRIPT_RELATIVE_PATH,
    GRADLE_RELATIVE_PATH,
    MALFORMED_CONFIG,
    SERVICE_RELATIVE_PATHS,
    WINDOWS_GRADLE_RELATIVE_PATH,
    CommandResult,
    SliceFailure,
    app_build_command,
    build_runtime_paths,
    candidate_path,
    cli_command,
    require_nonzero,
    require_success,
    service_build_command,
    service_command,
    service_environment,
    stop_service,
    validate_target,
    wait_for_tcp,
    wait_for_unix_socket,
)


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
                "/candidate/kmp_module/gradlew",
                "--no-daemon",
                "--quiet",
                ":app:run",
                "--args=status --json",
            ],
        )
        self.assertEqual(
            cli_command(root, "windows", "disconnect")[0], "/candidate/kmp_module/gradlew.bat")

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

    def test_result_assertions_report_command_output(self) -> None:
        failure = CommandResult(("tool",), 1, "out", "err")
        with self.assertRaisesRegex(SliceFailure, "exit code: 1"):
            require_success(failure, "phase")
        with self.assertRaisesRegex(SliceFailure, "unexpectedly succeeded"):
            require_nonzero(CommandResult(("tool",), 0, "", ""), "phase")

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
