from __future__ import annotations
import os

from pathlib import Path
import tempfile
import unittest

from unittest import mock
from torturer_checks.hosted.cli import CommandResult, HostedAdapterError
from torturer_checks.hosted.factory import adapter_for_platform
from torturer_checks.hosted.macos import MacOSHostedAdapter, _default_control_socket
from torturer_checks.hosted.windows import (
    WindowsHostedAdapter,
    _WINDOWS_PORT_READY_SCRIPT,
    _WINDOWS_PROCESS_ALIVE_SCRIPT,
)
from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import FunctionalEngine
from torturer_contract.functional.scenarios import get_scenario


class HostedDesktopProcessRunner:
    """Deterministic command seam for the two hosted process controllers."""

    def __init__(self, *, platform: str, binary: Path) -> None:
        self.platform = platform
        self.binary = binary
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[float] = []
        self.raw_directory: Path | None = None
        self.service_alive = True
        self.connected = False
        self.external_calls = 0

    def run(self, command, *, timeout_seconds):
        argv = tuple(command)
        self.calls.append(argv)
        self.timeouts.append(float(timeout_seconds))

        if argv[:2] == ("sudo", "-n"):
            return self.run(argv[2:], timeout_seconds=timeout_seconds)

        if argv[0] == "taskkill.exe":
            self.service_alive = False
            return CommandResult(argv, 0, b"terminated\n", b"")
        if argv[0] == "kill":
            if argv[1] == "-KILL":
                self.service_alive = False
                return CommandResult(argv, 0, b"", b"")
            if argv[1] == "-0":
                return CommandResult(argv, 0 if self.service_alive else 1, b"", b"")
        if argv[0] == "sh" and argv[1] == "-c":
            self.service_alive = True
            return CommandResult(argv, 0, b"456\n", b"")
        if argv[0] == "python3":
            return CommandResult(argv, 0 if self.service_alive else 1, b"", b"")
        if argv[0] == "ps":
            return CommandResult(argv, 0, (str(self.binary.resolve()) + "\n").encode(), b"")
        if argv[0] == "powershell.exe":
            script = argv[argv.index("-Command") + 1]
            if "Start-Process" in script:
                self.service_alive = True
                return CommandResult(argv, 0, b"456\n", b"")
            if "Get-CimInstance" in script:
                return CommandResult(
                    argv, 0 if self.service_alive else 1,
                    (str(self.binary.resolve()) + "\n").encode(), b"",
                )
            if "Get-Process" in script:
                return CommandResult(argv, 0 if self.service_alive else 1, b"", b"")
            if "Test-NetConnection" in script:
                return CommandResult(argv, 0 if self.service_alive else 1, b"True\n", b"")

        if argv[0] == str(self.binary):
            operation = argv[1]
            if operation == "check-config":
                return CommandResult(argv, 0, b"profiles=1 source=file\n", b"")
            if operation == "connect-profile":
                self.connected = True
                return CommandResult(argv, 0, b"CONNECTED\n", b"")
            if operation == "status":
                state = b"Connected" if self.connected else b"Disconnected"
                code = b"2" if self.connected else b"0"
                return CommandResult(argv, 0, b'{"code":' + code + b',"state":"' + state + b'"}\n', b"")
            if operation == "external-ip":
                self.external_calls += 1
                value = (
                    b"198.51.100.10\n"
                    if self.external_calls == 1 or not self.connected
                    else b"203.0.113.10\n"
                )
                return CommandResult(argv, 0, value, b"")
            if operation == "disconnect":
                self.connected = False
                return CommandResult(argv, 0, b"DISCONNECTED\n", b"")
        raise AssertionError(argv)


class HostedDesktopAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="hosted-desktop-adapter-")
        root = Path(self.directory.name)
        self.cli = root / "dobby-cli"
        self.cli.write_bytes(b"synthetic executable")
        self.cli.chmod(0o700)
        self.profile = root / "profile.toml"
        self.profile.write_text("[[Outline]]\nPassword = \"synthetic\"\n", encoding="utf-8")
        self.profile.chmod(0o600)
        self.addCleanup(self.directory.cleanup)

    def _provenance(self, adapter, platform: str):
        from torturer_contract.functional.results import RunProvenance

        return RunProvenance(
            source_repository="DobbyVPN/DobbyVPN",
            source_sha="1" * 40,
            torturer_sha="2" * 40,
            artifact_sha256="3" * 64,
            server_image_digest="sha256:" + "4" * 64,
            platform=platform,
            adapter_id=adapter.adapter_id,
            adapter_version=adapter.adapter_version,
            capabilities=frozenset(item.value for item in adapter.capabilities),
        )

    def _adapter(self, platform: str, runner: HostedDesktopProcessRunner):
        root = Path(self.directory.name)
        return adapter_for_platform(
            platform,
            cli=self.cli,
            profile=self.profile,
            runner=runner,
            service_pid=123,
            service_binary=self.cli,
            service_pid_file=root / f"{platform}.pid",
            service_socket=(
                Path("127.0.0.1:50051")
                if platform == "windows"
                else root / "control.sock"
            ),
        )

    def test_windows_and_macos_process_loss_are_canonical_and_bounded(self) -> None:
        scenario = get_scenario("functional.product-process-loss")
        for platform, adapter_class in (("windows", WindowsHostedAdapter), ("macos", MacOSHostedAdapter)):
            runner = HostedDesktopProcessRunner(platform=platform, binary=self.cli)
            runner.raw_directory = Path(self.directory.name) / f"{platform}-raw"
            adapter = self._adapter(platform, runner)
            self.assertIsInstance(adapter, adapter_class)
            self.assertIn(Capability.PROCESS_LOSS, adapter.capabilities)

            result = FunctionalEngine("a" * 64).run(
                scenario, adapter, self._provenance(adapter, platform)
            )

            self.assertEqual(result.outcome, "passed")
            self.assertTrue(result.cleanup["verified"])
            self.assertTrue(any(call[0] in {"taskkill.exe", "kill"} for call in runner.calls))
            self.assertTrue(any(call[0] in {"powershell.exe", "sh"} for call in runner.calls))
            self.assertTrue(all(timeout <= 45 for timeout in runner.timeouts))
            self.assertEqual((Path(self.directory.name) / f"{platform}.pid").read_text(), "456\n")

            if platform == "windows":
                self.assertTrue(any(call[0] == "powershell.exe" and "Start-Process" in call[5] for call in runner.calls))
                self.assertTrue(any(call[0] == "powershell.exe" and "Test-NetConnection" in call[5] for call in runner.calls))
            else:
                privileged = [call[2:] for call in runner.calls if call[:2] == ("sudo", "-n")]
                self.assertTrue(any(call[:2] == ("kill", "-KILL") for call in privileged))
                self.assertTrue(any(call[:1] == ("ps",) for call in privileged))
                self.assertTrue(any(call[:2] == ("sh", "-c") for call in privileged))
                self.assertTrue(any(call[:2] == ("python3", "-c") for call in runner.calls))
                launch = next(call for call in privileged if call[:2] == ("sh", "-c"))
                self.assertEqual(launch[-2], str(Path(self.directory.name) / "control.sock"))

    def test_windows_process_probes_preserve_diagnostics(self) -> None:
        self.assertNotIn("Out-Null", _WINDOWS_PROCESS_ALIVE_SCRIPT)
        self.assertIn("Write-Output", _WINDOWS_PROCESS_ALIVE_SCRIPT)
        self.assertNotIn("-InformationLevel Quiet", _WINDOWS_PORT_READY_SCRIPT)
        self.assertIn("Write-Output $ready", _WINDOWS_PORT_READY_SCRIPT)
        self.assertIn("$ready.TcpTestSucceeded", _WINDOWS_PORT_READY_SCRIPT)

    def test_factory_wires_each_desktop_process_seam_without_changing_linux(self) -> None:
        for platform in ("windows", "macos"):
            runner = HostedDesktopProcessRunner(platform=platform, binary=self.cli)
            runner.raw_directory = Path(self.directory.name) / f"{platform}-factory-raw"
            adapter = self._adapter(platform, runner)
            self.assertIn(Capability.PROCESS_LOSS, adapter.capabilities)

    def test_desktop_process_seam_fails_closed_on_incomplete_or_unsafe_configuration(self) -> None:
        runner = HostedDesktopProcessRunner(platform="windows", binary=self.cli)
        runner.raw_directory = Path(self.directory.name) / "invalid-raw"
        with self.assertRaisesRegex(HostedAdapterError, "SERVICE_CONTROL_INCOMPLETE"):
            WindowsHostedAdapter(
                cli=self.cli, profile=self.profile, runner=runner, service_pid=123
            )
        for adapter_class in (WindowsHostedAdapter, MacOSHostedAdapter):
            with self.assertRaisesRegex(HostedAdapterError, "SERVICE_CONTROL_INCOMPLETE"):
                adapter_class(
                    cli=self.cli,
                    profile=self.profile,
                    runner=runner,
                    service_pid=123,
                    service_binary=self.cli,
                    service_socket=(
                        Path("127.0.0.1:50051")
                        if adapter_class is WindowsHostedAdapter
                        else Path(self.directory.name) / "control.sock"
                    ),
                )
        with self.assertRaisesRegex(HostedAdapterError, "SERVICE_CONTROL_ADDRESS_INVALID"):
            WindowsHostedAdapter(
                cli=self.cli,
                profile=self.profile,
                runner=runner,
                service_pid=123,
                service_binary=self.cli,
                service_pid_file=Path(self.directory.name) / "invalid-windows.pid",
                service_socket=Path("0.0.0.0:50051"),
            )
        with self.assertRaisesRegex(HostedAdapterError, "SERVICE_CONTROL_SOCKET_INVALID"):
            MacOSHostedAdapter(
                cli=self.cli,
                profile=self.profile,
                runner=runner,
                service_pid=123,
                service_binary=self.cli,
                service_pid_file=Path(self.directory.name) / "invalid-macos.pid",
                service_socket=Path("relative.sock"),
            )


    def test_macos_default_control_socket_matches_product_runtime_layout(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("torturer_checks.hosted.macos.Path.home", return_value=Path("/Users/test")):
                self.assertEqual(
                    _default_control_socket(),
                    Path("/Users/test/Library/Application Support/DobbyVPN/control.sock"),
                )
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/tmp/runtime"}, clear=True):
            self.assertEqual(_default_control_socket(), Path("/tmp/runtime/DobbyVPN/control.sock"))
if __name__ == "__main__":
    unittest.main()
