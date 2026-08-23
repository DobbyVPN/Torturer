from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from torturer_checks.ios_simulator_app import (
    CommandResult,
    CLEANUP_RESERVE_SECONDS,
    IOSSimulatorAppContract,
    IOSSimulatorAppContractError,
    PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
    MAX_RUN_SECONDS,
    RunBudget,
    SubprocessCommandRunner,
    public_ios_simulator_app_contract,
    run_ios_simulator_app_contract,
    select_available_iphone,
    xcodebuild_app_command,
)
from tests.ios.run_app_contract import parse_arguments


UDID = "A12B34C5-1234-5678-9ABC-123456789ABC"


def fake_macho(architecture: str) -> bytes:
    cpu = {"arm64": 0x0100000C, "amd64": 0x01000007}[architecture]
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + b"\0" * 24


class FakeRunner:
    def __init__(
        self,
        *,
        work_dir: Path,
        inventory: dict[str, object],
        fail: tuple[str, ...] | None = None,
        terminate_returncodes: tuple[int, ...] = (),
        contract: IOSSimulatorAppContract = PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
    ) -> None:
        self.work_dir = work_dir
        self.inventory = inventory
        self.fail = fail
        self.terminate_returncodes = iter(terminate_returncodes)
        self.contract = contract
        self.commands: list[list[str]] = []

    def run(
        self,
        command: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        del cwd
        del timeout_seconds
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
        if command[:3] == ["xcrun", "simctl", "terminate"]:
            return CommandResult(next(self.terminate_returncodes, 0))
        return CommandResult(0, "current state: Booted" if command[:3] == ["xcrun", "simctl", "boot"] else "")

    def _write_app(self) -> None:
        app = self.contract.app_path(self.work_dir)
        app.mkdir(parents=True)
        (app / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundlePackageType": "APPL",
            "CFBundleIdentifier": "vpn.dobby.app",
            "CFBundleExecutable": "doBBYVPN",
        }))
        (app / "doBBYVPN").write_bytes(fake_macho(self.contract.architecture))

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
        subprocess.run(["git", "init", str(self.candidate)], check=True)
        subprocess.run(["git", "-C", str(self.candidate), "config", "user.name", "Torturer"], check=True)
        subprocess.run(
            ["git", "-C", str(self.candidate), "config", "user.email", "torturer@example.invalid"],
            check=True,
        )
        (self.candidate / "tracked.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.candidate), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.candidate), "commit", "-m", "fixture"], check=True)
        commit_result = subprocess.run(
            ["git", "-C", str(self.candidate), "rev-parse", "HEAD"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=None,
        )
        print(commit_result.stdout, end="")
        self.commit = commit_result.stdout.strip()

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
        self.assertIn("ARCHS=arm64", command)
        self.assertIn(f"platform=iOS Simulator,id={UDID}", command)
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "fixed"):
            IOSSimulatorAppContract(scheme="candidate-script; rm -rf /")
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "product name is fixed"):
            IOSSimulatorAppContract(app_product_name="candidate.app")
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "arm64 or amd64"):
            IOSSimulatorAppContract(architecture="x86_64")
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "UDID"):
            xcodebuild_app_command(
                PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
                candidate_root=self.candidate, device_udid="$(candidate)", work_dir=self.root / "work",
            )

    def test_intel_contract_enforces_x86_64_build_and_inspection(self) -> None:
        contract = public_ios_simulator_app_contract("amd64")
        command = xcodebuild_app_command(
            contract, candidate_root=self.candidate, device_udid=UDID, work_dir=self.root / "work",
        )
        self.assertIn("ARCHS=x86_64", command)
        runner = FakeRunner(
            work_dir=self.root / "work", inventory=simulator_inventory(), contract=contract,
        )
        evidence = run_ios_simulator_app_contract(
            candidate_root=self.candidate,
            repository="DobbyVPN/DobbyVPN",
            commit_sha=self.commit,
            work_dir=self.root / "work",
            runner=runner,
            contract=contract,
        )
        self.assertEqual(evidence.app.architecture, "amd64")
        self.assertEqual(
            sum(command[:3] == ["xcrun", "simctl", "terminate"] for command in runner.commands), 1,
        )

    def test_cli_architecture_is_limited_to_the_two_public_simulator_slices(self) -> None:
        arguments = parse_arguments([
            "--candidate-root", "/candidate",
            "--source-repository", "DobbyVPN/DobbyVPN",
            "--commit-sha", "a" * 40,
            "--work-dir", "/work",
            "--architecture", "amd64",
        ])
        self.assertEqual(arguments.architecture, "amd64")
        self.assertEqual(parse_arguments([
            "--candidate-root", "/candidate",
            "--source-repository", "DobbyVPN/DobbyVPN",
            "--commit-sha", "a" * 40,
            "--work-dir", "/work",
        ]).architecture, "arm64")

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
        self.assertTrue(any(command[:3] == ["xcrun", "simctl", "shutdown"] for command in runner.commands))

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "detached-descendant regression requires a POSIX /proc process table",
    )
    def test_subprocess_runner_timeout_kills_detached_resistant_descendant(self) -> None:
        raw_directory = self.root / "timeout-raw"
        runner = SubprocessCommandRunner(raw_directory)
        pid_file = self.root / "ios-descendant.pid"
        command = (
            sys.executable,
            "-c",
            (
                "import os, signal, time; "
                "pid = os.fork(); "
                "os.setsid() if pid == 0 else None; "
                    f"marker = open({str(pid_file)!r}, 'w', encoding='ascii'); "
                    "marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                "time.sleep(60)"
            ),
        )
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "timed out"):
            runner.run(command, timeout_seconds=0.2)
        descendant_pid = int(pid_file.read_text(encoding="ascii"))
        for _ in range(40):
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail(f"detached iOS command descendant {descendant_pid} survived cleanup")

    def test_run_budget_keeps_the_documented_cleanup_reserve(self) -> None:
        self.assertEqual(MAX_RUN_SECONDS, 1800)
        self.assertEqual(CLEANUP_RESERVE_SECONDS, 120)
        clock = iter((0.0, 0.0, 7.0, 8.1))
        budget = RunBudget(max_seconds=10, cleanup_reserve_seconds=2, clock=lambda: next(clock))
        self.assertEqual(budget.operation_timeout(), 8.0)
        self.assertEqual(budget.operation_timeout(), 1.0)
        with self.assertRaisesRegex(IOSSimulatorAppContractError, "functional budget"):
            budget.operation_timeout()

    def test_policy_binds_every_host_command_and_unconditional_shutdown(self) -> None:
        source = (Path(__file__).resolve().parents[2] / "torturer_checks" / "ios_simulator_app.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("timeout_seconds", source)
        self.assertIn("start_new_session=True", source)
        self.assertIn('["xcrun", "simctl", "shutdown", simulator.udid]', source)
        self.assertIn("finally:", source)

    def test_subprocess_runner_retains_complete_raw_output_without_public_echo(self) -> None:
        raw_directory = self.root / "raw"
        runner = SubprocessCommandRunner(raw_directory)
        result = runner.run((
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'out\\x00\\xff'); sys.stderr.buffer.write(b'err\\xfe')",
        ))

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "out\x00\ufffd" + "err\ufffd")
        raw_path = next(raw_directory.glob("command-*.raw.log"))
        self.assertEqual(raw_path.read_bytes(), b"out\x00\xfferr\xfe")
        self.assertEqual(raw_directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(raw_path.stat().st_mode & 0o777, 0o600)

    def test_retries_transient_terminate_not_running_result_after_launch(self) -> None:
        runner = FakeRunner(
            work_dir=self.root / "work",
            inventory=simulator_inventory(),
            terminate_returncodes=(3, 0),
        )
        run_ios_simulator_app_contract(
            candidate_root=self.candidate,
            repository="DobbyVPN/DobbyVPN",
            commit_sha=self.commit,
            work_dir=self.root / "work",
            runner=runner,
        )
        terminate_commands = [
            command for command in runner.commands
            if command[:3] == ["xcrun", "simctl", "terminate"]
        ]
        self.assertEqual(len(terminate_commands), 2)

    def test_persistent_terminate_not_running_result_fails_after_one_retry(self) -> None:
        runner = FakeRunner(
            work_dir=self.root / "work",
            inventory=simulator_inventory(),
            terminate_returncodes=(3, 3),
        )
        with self.assertRaisesRegex(
            IOSSimulatorAppContractError,
            "terminate Simulator app failed with exit code 3",
        ):
            run_ios_simulator_app_contract(
                candidate_root=self.candidate,
                repository="DobbyVPN/DobbyVPN",
                commit_sha=self.commit,
                work_dir=self.root / "work",
                runner=runner,
            )
        terminate_commands = [
            command for command in runner.commands
            if command[:3] == ["xcrun", "simctl", "terminate"]
        ]
        self.assertEqual(len(terminate_commands), 3)


if __name__ == "__main__":
    unittest.main()
