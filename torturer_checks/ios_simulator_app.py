"""Public, secretless orchestration for the fixed Dobby iOS Simulator app.

This is H3 preparation only.  It is deliberately independent from GitHub
Actions: callers inject command execution, so its selection, sequencing, and
evidence checks are testable on Linux.  H4 may call the CLI after pinning this
helper revision.  No command is passed through a shell.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from typing import Protocol, Sequence

from torturer_checks.ios_simulator import (
    IOSSimulatorContractError,
    SimulatorAppInspection,
    SimulatorTestContract,
    XCResultInspection,
    inspect_simulator_app,
    inspect_xcresult_bundle,
    simctl_boot_command,
    simctl_bootstatus_command,
    simctl_install_command,
    simctl_launch_command,
    simctl_terminate_command,
    source_identity_from_simulator_checkout,
    validate_xcresult_summary,
    xcodebuild_test_command,
    xcresult_summary_command,
)


_RUNTIME = re.compile(r"com\.apple\.CoreSimulator\.SimRuntime\.iOS-(\d+(?:-\d+)*)\Z")
_SIMPLE_PRODUCT = re.compile(r"[A-Za-z0-9 ._-]{1,100}\.app\Z")
_PROJECT_PATH = Path("swift_module/iosApp.xcodeproj")
_SCHEME_NAME = "iosApp"
_CONFIGURATION = "Debug"
_APP_PRODUCT = "doBBYVPN.app"
_BUNDLE_IDENTIFIER = "vpn.dobby.app"
_ARCHITECTURE = "arm64"
_TEST_IDENTIFIER = (
    "IOSSimulatorAppContractTests/IOSSimulatorAppContractTests/"
    "testAppLaunchesWithoutCredentials"
)


class IOSSimulatorAppContractError(RuntimeError):
    """The fixed public app contract could not be executed or verified."""


@dataclass(frozen=True)
class CommandResult:
    """The only command result the orchestrator needs from a host runner."""

    returncode: int
    stdout: str = ""


class CommandRunner(Protocol):
    """Injectable, argument-vector-only host command executor."""

    def run(self, command: Sequence[str], *, cwd: Path | None = None) -> CommandResult:
        """Run one host command without a shell."""


class SubprocessCommandRunner:
    """Production executor for H4's ephemeral GitHub-hosted macOS job."""

    def run(self, command: Sequence[str], *, cwd: Path | None = None) -> CommandResult:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return CommandResult(returncode=completed.returncode, stdout=completed.stdout)


@dataclass(frozen=True)
class AvailableSimulator:
    """One deterministically selected available iPhone Simulator."""

    udid: str
    name: str
    runtime: str


@dataclass(frozen=True)
class IOSSimulatorAppContract:
    """The fixed, public, unsigned app contract DobbyVPN must expose."""

    project_relative_path: Path = _PROJECT_PATH
    scheme: str = _SCHEME_NAME
    configuration: str = _CONFIGURATION
    app_product_name: str = _APP_PRODUCT
    bundle_identifier: str = _BUNDLE_IDENTIFIER
    architecture: str = _ARCHITECTURE
    test_identifier: str = _TEST_IDENTIFIER

    def __post_init__(self) -> None:
        if self.project_relative_path != _PROJECT_PATH:
            raise IOSSimulatorAppContractError("iOS Simulator project path is fixed by the public contract")
        if self.scheme != _SCHEME_NAME or self.configuration != _CONFIGURATION:
            raise IOSSimulatorAppContractError("iOS Simulator scheme and configuration are fixed")
        if not _SIMPLE_PRODUCT.fullmatch(self.app_product_name):
            raise IOSSimulatorAppContractError("Simulator app product name has unsupported characters")
        if self.app_product_name != _APP_PRODUCT:
            raise IOSSimulatorAppContractError("Simulator app product name is fixed by the public contract")
        if self.bundle_identifier != _BUNDLE_IDENTIFIER or self.architecture != _ARCHITECTURE:
            raise IOSSimulatorAppContractError("Simulator app identity is fixed by the public contract")
        if self.test_identifier != _TEST_IDENTIFIER:
            raise IOSSimulatorAppContractError("Simulator XCTest identifier is fixed by the public contract")
        # SimulatorTestContract validates the bundle/test/architecture values.
        self.test_contract(Path("/contract"))

    def test_contract(self, candidate_root: Path) -> SimulatorTestContract:
        return SimulatorTestContract(
            container=candidate_root / self.project_relative_path,
            container_kind="project",
            scheme=self.scheme,
            bundle_identifier=self.bundle_identifier,
            test_identifier=self.test_identifier,
            architecture=self.architecture,
        )

    def app_path(self, work_dir: Path) -> Path:
        return (
            work_dir / "derived-data" / "Build" / "Products"
            / f"{self.configuration}-iphonesimulator" / self.app_product_name
        )


PUBLIC_IOS_SIMULATOR_APP_CONTRACT = IOSSimulatorAppContract()


@dataclass(frozen=True)
class IOSSimulatorAppEvidence:
    """Public evidence collected by one successful app-contract invocation."""

    simulator: AvailableSimulator
    app: SimulatorAppInspection
    xcresult: XCResultInspection | None


def select_available_iphone(simctl_devices_json: str) -> AvailableSimulator:
    """Choose the newest available iPhone deterministically from host simctl JSON."""
    try:
        document = json.loads(simctl_devices_json)
        devices = document["devices"]
    except (KeyError, TypeError, ValueError) as error:
        raise IOSSimulatorAppContractError("simctl did not provide a readable device inventory") from error
    if not isinstance(devices, dict):
        raise IOSSimulatorAppContractError("simctl device inventory has an invalid shape")
    candidates: list[tuple[tuple[int, ...], str, str, str]] = []
    for runtime, entries in devices.items():
        match = _RUNTIME.fullmatch(runtime) if isinstance(runtime, str) else None
        if match is None or not isinstance(entries, list):
            continue
        version = tuple(int(part) for part in match.group(1).split("-"))
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("isAvailable") is not True:
                continue
            name, udid = entry.get("name"), entry.get("udid")
            if not isinstance(name, str) or not name.startswith("iPhone"):
                continue
            try:
                validated_udid = simctl_boot_command(udid)[-1]
            except IOSSimulatorContractError:
                continue
            candidates.append((version, name, validated_udid, runtime))
    if not candidates:
        raise IOSSimulatorAppContractError("no available iPhone Simulator was found")
    # Prefer the newest runtime, then a stable device name and UDID tie-break.
    version, name, udid, runtime = sorted(
        candidates, key=lambda item: (item[0], item[1], item[2]), reverse=True
    )[0]
    del version
    return AvailableSimulator(udid=udid, name=name, runtime=runtime)


def xcodebuild_app_command(
    contract: IOSSimulatorAppContract, *, candidate_root: Path, device_udid: str, work_dir: Path
) -> list[str]:
    """Construct the fixed unsigned app build command without a shell."""
    test_contract = contract.test_contract(candidate_root)
    try:
        validated_udid = simctl_boot_command(device_udid)[-1]
    except IOSSimulatorContractError as error:
        raise IOSSimulatorAppContractError(str(error)) from error
    return [
        "xcodebuild", "build", test_contract.container_flag, str(test_contract.container),
        "-scheme", contract.scheme, "-configuration", contract.configuration,
        "-sdk", "iphonesimulator", "-destination", f"platform=iOS Simulator,id={validated_udid}",
        "-derivedDataPath", str(work_dir / "derived-data"),
        "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO", "CODE_SIGN_IDENTITY=",
    ]


def run_ios_simulator_app_contract(
    *,
    candidate_root: Path,
    repository: str,
    commit_sha: str,
    work_dir: Path,
    runner: CommandRunner,
    with_xctest: bool = False,
    contract: IOSSimulatorAppContract = PUBLIC_IOS_SIMULATOR_APP_CONTRACT,
) -> IOSSimulatorAppEvidence:
    """Build, inspect, install, launch and terminate the fixed Simulator app.

    ``with_xctest`` remains opt-in until DobbyVPN exposes the named app test
    target.  Its result is independently inspected and summarized when used.
    """
    try:
        source = source_identity_from_simulator_checkout(
            candidate_root, repository=repository, expected_commit=commit_sha
        )
    except IOSSimulatorContractError as error:
        raise IOSSimulatorAppContractError(str(error)) from error
    work_dir.mkdir(parents=True, exist_ok=True)
    inventory = _require_success(runner, ["xcrun", "simctl", "list", "devices", "available", "-j"], "list Simulators")
    simulator = select_available_iphone(inventory.stdout)
    boot = runner.run(simctl_boot_command(simulator.udid))
    if boot.returncode and "current state: Booted" not in boot.stdout:
        raise IOSSimulatorAppContractError("boot Simulator failed")
    _require_success(runner, simctl_bootstatus_command(simulator.udid), "wait for Simulator boot")
    _require_success(
        runner,
        xcodebuild_app_command(
            contract, candidate_root=candidate_root, device_udid=simulator.udid, work_dir=work_dir
        ),
        "build unsigned Simulator app",
    )
    try:
        app = inspect_simulator_app(
            contract.app_path(work_dir), source=source,
            expected_bundle_identifier=contract.bundle_identifier,
            architecture=contract.architecture,
        )
    except IOSSimulatorContractError as error:
        raise IOSSimulatorAppContractError(str(error)) from error
    _require_success(runner, simctl_install_command(simulator.udid, app.app_path), "install Simulator app")
    _require_success(runner, simctl_launch_command(simulator.udid, contract.bundle_identifier), "launch Simulator app")
    _require_success(runner, simctl_terminate_command(simulator.udid, contract.bundle_identifier), "terminate Simulator app")

    xcresult: XCResultInspection | None = None
    if with_xctest:
        result_path = work_dir / "app-tests.xcresult"
        _require_success(
            runner,
            xcodebuild_test_command(
                contract.test_contract(candidate_root), device_udid=simulator.udid,
                result_bundle=result_path,
            ),
            "run named Simulator XCTest",
        )
        try:
            xcresult = inspect_xcresult_bundle(
                result_path, source=source, required_test_identifier=contract.test_identifier
            )
        except IOSSimulatorContractError as error:
            raise IOSSimulatorAppContractError(str(error)) from error
        summary = _require_success(runner, xcresult_summary_command(result_path), "read XCTest summary")
        try:
            validate_xcresult_summary(summary.stdout)
        except IOSSimulatorContractError as error:
            raise IOSSimulatorAppContractError(str(error)) from error
    return IOSSimulatorAppEvidence(simulator=simulator, app=app, xcresult=xcresult)


def _require_success(runner: CommandRunner, command: Sequence[str], stage: str) -> CommandResult:
    result = runner.run(command)
    if result.returncode:
        # Do not echo candidate-controlled build/test output in public diagnostics.
        raise IOSSimulatorAppContractError(f"{stage} failed with exit code {result.returncode}")
    return result
