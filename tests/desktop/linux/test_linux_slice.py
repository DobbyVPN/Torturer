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

from torturer_checks.linux_slice import (
    BUILD_SCRIPT_RELATIVE_PATH,
    GRADLE_RELATIVE_PATH,
    MALFORMED_CONFIG,
    SERVICE_RELATIVE_PATH,
    CommandResult,
    SliceFailure,
    app_build_command,
    build_command,
    candidate_path,
    cli_command,
    require_nonzero,
    require_success,
    service_environment,
    stop_service,
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
                "/candidate/kmp_module/gradlew",
                "--no-daemon",
                "--quiet",
                ":app:run",
                "--args=status --json",
            ],
        )

    def test_fixture_is_non_routable_and_malformed(self) -> None:
        self.assertIn("[\n", MALFORMED_CONFIG)
        self.assertNotIn("://", MALFORMED_CONFIG)
        self.assertNotIn("[[", MALFORMED_CONFIG)

    def test_result_assertions_report_output(self) -> None:
        failure = CommandResult(("tool",), 1, "out", "err")
        with self.assertRaisesRegex(SliceFailure, "exit code: 1"):
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
