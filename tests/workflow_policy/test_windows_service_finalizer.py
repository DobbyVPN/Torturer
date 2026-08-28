"""Contract tests for the shared Windows service finalizer entrypoint."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from torturer_checks.hosted import finalize_windows_service as finalizer
from torturer_checks.hosted import windows as hosted_windows


class _Runner:
    def __init__(self, raw_directory: Path) -> None:
        self.raw_directory = raw_directory

    def safe_evidence(self):
        return ({"evidence_id": "e" * 32, "evidence_bytes": 7, "evidence_sha256": "f" * 64},)


class _Controller:
    instances: list["_Controller"] = []
    failure: Exception | None = None

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.calls: list[tuple[float, float | None]] = []
        type(self).instances.append(self)
        if type(self).failure is not None:
            raise type(self).failure

    def finalize_initial_service(self, timeout_seconds: float, *, deadline: float | None = None) -> None:
        self.calls.append((timeout_seconds, deadline))


class WindowsServiceFinalizerContractTests(unittest.TestCase):
    def _arguments(self, root: Path, identity: Path, binary: Path, raw: Path) -> list[str]:
        return [
            "--service-identity-file",
            str(identity),
            "--service-binary",
            str(binary),
            "--raw-log-dir",
            str(raw),
            "--timeout-seconds",
            "4",
        ]

    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory(prefix="windows-finalizer-contract-")
        root = Path(temporary.name)
        identity = root / "service.identity"
        binary = root / "service.exe"
        raw = root / "raw"
        identity.write_text("123|456\n", encoding="ascii")
        identity.chmod(0o600)
        binary.write_bytes(b"synthetic executable")
        binary.chmod(0o700)
        raw.mkdir(mode=0o700)
        return temporary, root, identity, binary, raw

    def test_success_uses_public_finalizer_and_prints_safe_evidence(self) -> None:
        temporary, root, identity, binary, raw = self._fixture()
        try:
            _Controller.instances.clear()
            _Controller.failure = None
            stdout, stderr = StringIO(), StringIO()
            with mock.patch.object(finalizer, "SubprocessRunner", _Runner), mock.patch.object(
                finalizer, "WindowsServiceProcessController", _Controller
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                status = finalizer.main(self._arguments(root, identity, binary, raw))
            self.assertEqual(status, 0)
            self.assertIn("windows_service_finalizer=controller tree=proven", stdout.getvalue())
            self.assertIn("windows_service_finalizer_evidence=", stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(len(_Controller.instances), 1)
            self.assertEqual(
                _Controller.instances[0].kwargs["expected_initial_identity"],
                "123|456",
            )
            self.assertEqual(_Controller.instances[0].calls[0][0], 4.0)
            self.assertEqual(
                _Controller.instances[0].kwargs["initialization_deadline"],
                _Controller.instances[0].calls[0][1],
            )
        finally:
            temporary.cleanup()

    def test_invalid_and_symlink_identity_fail_closed_before_controller(self) -> None:
        temporary, root, identity, binary, raw = self._fixture()
        try:
            _Controller.instances.clear()
            _Controller.failure = None
            identity.write_text("not-an-identity\n", encoding="ascii")
            identity.chmod(0o600)
            stderr = StringIO()
            with mock.patch.object(finalizer, "SubprocessRunner", _Runner), mock.patch.object(
                finalizer, "WindowsServiceProcessController", _Controller
            ), redirect_stderr(stderr):
                status = finalizer.main(self._arguments(root, identity, binary, raw))
            self.assertEqual(status, 1)
            self.assertIn("code=SERVICE_PID_PROBE_FAILED", stderr.getvalue())
            self.assertEqual(_Controller.instances, [])

            target = root / "identity-target"
            target.write_text("123|456\n", encoding="ascii")
            target.chmod(0o600)
            identity.unlink()
            try:
                identity.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            stderr = StringIO()
            with mock.patch.object(finalizer, "SubprocessRunner", _Runner), mock.patch.object(
                finalizer, "WindowsServiceProcessController", _Controller
            ), redirect_stderr(stderr):
                status = finalizer.main(self._arguments(root, identity, binary, raw))
            self.assertEqual(status, 1)
            self.assertIn("code=SERVICE_PID_PROBE_FAILED", stderr.getvalue())
            self.assertEqual(_Controller.instances, [])
        finally:
            temporary.cleanup()

    def test_identity_replacement_after_open_fails_closed(self) -> None:
        temporary, root, identity, binary, raw = self._fixture()
        try:
            replacement = root / "replacement.identity"
            replacement.write_text("999|888\n", encoding="ascii")
            replacement.chmod(0o600)
            real_open = hosted_windows.os.open

            def replace_after_open(path, flags, *args):
                descriptor = real_open(path, flags, *args)
                if Path(path) == identity:
                    identity.unlink()
                    replacement.rename(identity)
                return descriptor

            # Exercise the descriptor/path identity comparison even on a
            # platform where O_NOFOLLOW is not available.
            with mock.patch.object(hosted_windows.os, "O_NOFOLLOW", 0, create=True), mock.patch.object(
                hosted_windows.os, "open", side_effect=replace_after_open
            ):
                with self.assertRaises(hosted_windows.ScenarioExecutionError) as raised:
                    finalizer._identity_value(identity)
            self.assertEqual(raised.exception.reason_code, "SERVICE_PID_PROBE_FAILED")
        finally:
            temporary.cleanup()

    def test_controller_failure_prints_only_stable_reason_code_and_evidence(self) -> None:
        temporary, root, identity, binary, raw = self._fixture()
        try:
            _Controller.instances.clear()
            _Controller.failure = ValueError("secret path and identity")
            stdout, stderr = StringIO(), StringIO()
            with mock.patch.object(finalizer, "SubprocessRunner", _Runner), mock.patch.object(
                finalizer, "WindowsServiceProcessController", _Controller
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                status = finalizer.main(self._arguments(root, identity, binary, raw))
            self.assertEqual(status, 1)
            self.assertIn("windows_service_finalizer=failed code=FINALIZE_FAILED", stderr.getvalue())
            self.assertNotIn("secret path", stderr.getvalue())
            self.assertIn("windows_service_finalizer_evidence=", stdout.getvalue())
        finally:
            _Controller.failure = None
            temporary.cleanup()

    def test_symlink_raw_directory_is_rejected_before_controller(self) -> None:
        temporary, root, identity, binary, raw = self._fixture()
        try:
            target = root / "raw-target"
            target.mkdir(mode=0o700)
            link = root / "raw-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            _Controller.instances.clear()
            _Controller.failure = None
            stderr = StringIO()
            with mock.patch.object(finalizer, "SubprocessRunner", _Runner), mock.patch.object(
                finalizer, "WindowsServiceProcessController", _Controller
            ), redirect_stderr(stderr):
                status = finalizer.main(self._arguments(root, identity, binary, link))
            self.assertEqual(status, 1)
            self.assertIn("code=EVIDENCE_PATH_UNSAFE", stderr.getvalue())
            self.assertEqual(_Controller.instances, [])
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
