from __future__ import annotations

import json
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest

from torturer_checks.ios_simulator_app import (
    CommandResult,
    IOSSimulatorAppContract,
    IOSSimulatorAppContractError,
    PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
    run_ios_simulator_app_contract,
    select_available_iphone,
    xcodebuild_app_command,
)


UDID = "A12B34C5-1234-5678-9ABC-123456789ABC"


def fake_macho() -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x0100000C) + b"\0" * 24


class FakeRunner:
    def __init__(self, *, work_dir: Path, inventory: dict[str, object], fail: tuple[str, ...] | None = None) -> None:
        self.work_dir = work_dir
        self.inventory = inventory
        self.fail = fail
        self.commands: list[list[str]] = []

    def run(self, command: list[str] | tuple[str, ...], *, cwd: Path | None = None) -> CommandResult:
        del cwd
        command = list(command)
        self.commands.append(command)
        if self.fail is not None and tuple(command[:len(self.fail)]) == self.fail:
            return CommandResult(9, "candidate output that must not be echoed")
        if command == ["xcrun", "simctl", "list", "devices", "available", "-j"]:
            return CommandResult(0, json.dumps(self.inventory))
        if command[:2] == ["xcodebuild", "build"]:
            self._write_app()
            return CommandResult(0)
        if command[:2] == ["xcodebuild", "test"]:
            self._write_xcresult()
            return CommandResult(0)
        if command[:4] == ["xcrun", "xcresulttool", "get", "test-results"]:
            return CommandResult(0, '{"passedTests":1,"failedTests":0}')
        return CommandResult(0, "current state: Booted" if command[:3] == ["xcrun", "simctl", "boot"] else "")

    def _write_app(self) -> None:
        app = PUBLIC_IOS_SIMULATOR_APP_CONTRACT.app_path(self.work_dir)
        app.mkdir(parents=True)
        (app / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundlePackageType": "APPL",
            "CFBundleIdentifier": "vpn.dobby.app",
            "CFBundleExecutable": "doBBYVPN",
        }))
        (app / "doBBYVPN").write_bytes(fake_macho())

    def _write_xcresult(self) -> None:
        result = self.work_dir / "app-tests.xcresult"
        result.mkdir()
        (result / "Info.plist").write_bytes(plistlib.dumps({"version": "3.0"}))
        (result / "Data").mkdir()
        (result / "Data" / "result.0").write_bytes(b"public test evidence")


def simulator_inventory() -> dict[str, object]:
    return {
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-18-5": [{
                "isAvailable": True, "name": "iPhone 16", "udid": "00000000-0000-0000-0000-000000000001",
            }],
            "com.apple.CoreSimulator.SimRuntime.iOS-26-2": [{
                "isAvailable": True, "name": "iPhone 17", "udid": UDID,
            }],
            "com.apple.CoreSimulator.SimRuntime.iOS-26-2-unavailable": [{
                "isAvailable": False, "name": "iPhone 99", "udid": "00000000-0000-0000-0000-000000000002",
            }],
            "com.apple.CoreSimulator.SimRuntime.tvOS-26-2": [{
                "isAvailable": True, "name": "Apple TV", "udid": "00000000-0000-0000-0000-000000000003",
            }],
        }
    }


class IOSSimulatorAppContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        subprocess.run(["git", "init", "-q", str(self.candidate)], check=True)
        subprocess.run(["git", "-C", str(self.candidate), "config", "user.name", "Torturer"], check=True)
        subprocess.run(
            ["git", "-C", str(self.candidate), "config", "user.email", "torturer@example.invalid"],
            check=True,
        )
        (self.candidate / "tracked.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.candidate), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.candidate), "commit", "-qm", "fixture"], check=True)
        self.commit = subprocess.run(
            ["git", "-C", str(self.candidate), "rev-parse", "HEAD"],
            check=True, text=True, capture_output=True,
        ).stdout.strip()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_selects_newest_available_iphone_with_stable_tie_breaks(self) -> None:
        selected = select_available_iphone(json.dumps(simulator_inventory()))
        self.assertEqual(selected.udid, UDID)
        self.assertEqual(selected.name, "iPhone 17")
        self.assertEqual(selected.runtime, "com.apple.CoreSimulator.SimRuntime.iOS-26-2")
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "no available"):
            select_available_iphone('{"devices": {}}')
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "readable"):
            select_available_iphone("not json")

    def test_fixed_build_command_is_unsigned_argument_vector(self) -> None:
        command = xcodebuild_app_command(
            PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
            candidate_root=self.candidate,
            device_udid=UDID,
            work_dir=self.root / "work",
        )
        self.assertEqual(command[:5], ["xcodebuild", "build", "-project", str(self.candidate / "swift_module/iosApp.xcodeproj"), "-scheme"])
        self.assertIn("CODE_SIGNING_ALLOWED=NO", command)
        self.assertIn("CODE_SIGNING_REQUIRED=NO", command)
        self.assertIn("CODE_SIGN_IDENTITY=", command)
        self.assertIn(f"platform=iOS Simulator,id={UDID}", command)
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "fixed"):
            IOSSimulatorAppContract(scheme="candidate-script; rm -rf /")
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "product name is fixed"):
            IOSSimulatorAppContract(app_product_name="candidate.app")
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "UDID"):
            xcodebuild_app_command(
                PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
                candidate_root=self.candidate, device_udid="$(candidate)", work_dir=self.root / "work",
            )

    def test_orchestrates_build_inspection_install_launch_terminate_and_xctest(self) -> None:
        work_dir = self.root / "work"
        runner = FakeRunner(work_dir=work_dir, inventory=simulator_inventory())
        evidence = run_ios_simulator_app_contract(
            candidate_root=self.candidate,
            repository="DobbyVPN/DobbyVPN",
            commit_sha=self.commit,
            work_dir=work_dir,
            runner=runner,
            with_xctest=True,
        )
        self.assertEqual(evidence.simulator.udid, UDID)
        self.assertEqual(evidence.app.bundle_identifier, "vpn.dobby.app")
        self.assertIsNotNone(evidence.xcresult)
        rendered = [" ".join(command) for command in runner.commands]
        install = next(i for i, value in enumerate(rendered) if " simctl install " in f" {value} ")
        launch = next(i for i, value in enumerate(rendered) if " simctl launch " in f" {value} ")
        terminate = next(i for i, value in enumerate(rendered) if " simctl terminate " in f" {value} ")
        self.assertLess(install, launch)
        self.assertLess(launch, terminate)
        self.assertTrue(any(command[:2] == ["xcodebuild", "test"] for command in runner.commands))
        self.assertTrue(any(command[:4] == ["xcrun", "xcresulttool", "get", "test-results"] for command in runner.commands))

    def test_app_stages_run_without_xctest_and_failures_do_not_echo_output(self) -> None:
        work_dir = self.root / "work"
        runner = FakeRunner(work_dir=work_dir, inventory=simulator_inventory(), fail=("xcrun", "simctl", "install"))
        with self.assertRaises(IOSSimulatorAppContractError) as raised:
            run_ios_simulator_app_contract(
                candidate_root=self.candidate,
                repository="DobbyVPN/DobbyVPN",
                commit_sha=self.commit,
                work_dir=work_dir,
                runner=runner,
            )
        self.assertIn("install Simulator app failed with exit code 9", str(raised.exception))
        self.assertNotIn("candidate output", str(raised.exception))
        self.assertFalse(any(command[:2] == ["xcodebuild", "test"] for command in runner.commands))


if __name__ == "__main__":
    unittest.main()
