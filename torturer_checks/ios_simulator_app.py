"""Public, secretless orchestration for the fixed Dobby iOS Simulator app.

This is H3 preparation only.  It is deliberately independent from GitHub
Actions: callers inject command execution, so its selection, sequencing, and
evidence checks are testable on Linux.  H4 may call the CLI after pinning this
helper revision.  No command is passed through a shell.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
from typing import Protocol, Sequence

from torturer_checks.public_output import emit_evidence, safe_diagnostic_excerpt

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
_DEFAULT_ARCHITECTURE = "arm64"
_SUPPORTED_ARCHITECTURES = frozenset(("arm64", "amd64"))
_XCODE_ARCHITECTURES = {"arm64": "arm64", "amd64": "x86_64"}
_TERMINATE_NOT_RUNNING_EXIT_CODE = 3
_TERMINATE_RETRY_DELAY_SECONDS = 1.0
MAX_RUN_SECONDS = 30 * 60
CLEANUP_RESERVE_SECONDS = 120
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
COMMAND_TERMINATION_GRACE_SECONDS = 15
_TEST_IDENTIFIER = (
    "IOSSimulatorAppContractTests/IOSSimulatorAppContractTests/"
    "testAppLaunchesWithoutCredentials"
)


class IOSSimulatorAppContractError(RuntimeError):
    """The fixed public app contract could not be executed or verified."""


class RunBudget:
    """Track one iOS lane's hard deadline and reserved cleanup window."""

    def __init__(
        self,
        *,
        max_seconds: float = MAX_RUN_SECONDS,
        cleanup_reserve_seconds: float = CLEANUP_RESERVE_SECONDS,
        clock=time.monotonic,
    ) -> None:
        if max_seconds <= 0 or cleanup_reserve_seconds < 0 or cleanup_reserve_seconds >= max_seconds:
            raise ValueError("cleanup reserve must be non-negative and smaller than the run deadline")
        self.max_seconds = float(max_seconds)
        self.cleanup_reserve_seconds = float(cleanup_reserve_seconds)
        self.clock = clock
        self.started_at = clock()

    @property
    def deadline(self) -> float:
        return self.started_at + self.max_seconds

    def operation_timeout(self, requested: float | None = None) -> float:
        remaining = self.deadline - self.clock() - self.cleanup_reserve_seconds
        if remaining <= 0:
            raise IOSSimulatorAppContractError("iOS lane exhausted its functional budget before cleanup reserve")
        if requested is None:
            return remaining
        if requested <= 0:
            raise IOSSimulatorAppContractError("iOS command timeout must be positive")
        return min(float(requested), remaining)

    def cleanup_timeout(self) -> float:
        return max(0.0, min(self.cleanup_reserve_seconds, self.deadline - self.clock()))

    def assert_within_deadline(self) -> None:
        if self.clock() > self.deadline:
            raise IOSSimulatorAppContractError("iOS lane exceeded its strict 1800-second deadline")


@dataclass(frozen=True)
class CommandResult:
    """The only command result the orchestrator needs from a host runner."""

    returncode: int
    stdout: str = ""
    raw_log: Path | None = None


class CommandRunner(Protocol):
    """Injectable, argument-vector-only host command executor."""

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        """Run one host command without a shell."""


def _process_group_alive(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _proc_descendants(
    root_pid: int,
    *,
    process: subprocess.Popen[bytes] | None = None,
) -> set[int]:
    """Return descendants and retain an unreliable census on ``process``."""

    parent_by_pid: dict[int, int] = {}
    reliable = True
    census_diagnostics = bytearray()
    proc_root = Path("/proc")
    if proc_root.is_dir():
        try:
            for entry in proc_root.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    stat_line = (entry / "stat").read_text(encoding="ascii")
                    close = stat_line.rfind(")")
                    fields = stat_line[close + 2 :].split()
                    parent_by_pid[int(entry.name)] = int(fields[1])
                except FileNotFoundError:
                    # A process can disappear between directory enumeration
                    # and reading /proc/<pid>; this is an expected race.
                    continue
                except (OSError, UnicodeError, ValueError, IndexError) as error:
                    reliable = False
                    census_diagnostics.extend(
                        f"procfs-census-entry={entry.name} error={error!r}\n".encode(
                            "utf-8", errors="replace"
                        )
                    )
        except OSError as error:
            reliable = False
            census_diagnostics.extend(
                f"procfs-census-iteration-error={error!r}\n".encode(
                    "utf-8", errors="replace"
                )
            )
    else:
        listing_bytes = b""
        ps_stderr = b""
        ps_returncode: int | None = None
        try:
            completed = subprocess.run(
                ["ps", "-axo", "pid=,ppid="],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
            )
            listing_bytes = completed.stdout or b""
            listing = listing_bytes.decode("ascii", errors="ignore")
            ps_stderr = completed.stderr or b""
            ps_returncode = completed.returncode
            if ps_returncode != 0 or ps_stderr:
                reliable = False
                census_diagnostics.extend(
                    b"ps-census-returncode="
                    + str(ps_returncode).encode("ascii", errors="replace")
                    + b"\nps-census-stdout-begin\n"
                    + listing_bytes
                    + b"\nps-census-stdout-end\nps-census-stderr-begin\n"
                    + ps_stderr
                    + b"\nps-census-stderr-end\n"
                )
        except subprocess.TimeoutExpired as error:
            reliable = False
            listing = ""
            stdout = getattr(error, "stdout", None) or getattr(error, "output", None) or b""
            stderr = getattr(error, "stderr", None) or b""
            if not isinstance(stdout, bytes):
                stdout = str(stdout).encode("utf-8", errors="replace")
            if not isinstance(stderr, bytes):
                stderr = str(stderr).encode("utf-8", errors="replace")
            census_diagnostics.extend(
                b"ps-census-timeout\nstdout-begin\n"
                + stdout
                + b"\nstdout-end\nstderr-begin\n"
                + stderr
                + b"\nstderr-end\n"
            )
        except OSError as error:
            reliable = False
            listing = ""
            census_diagnostics.extend(
                f"ps-census-launch-error={error!r}\n".encode(
                    "utf-8", errors="replace"
                )
            )
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) == 2:
                try:
                    parent_by_pid[int(fields[0])] = int(fields[1])
                except ValueError:
                    reliable = False
                    census_diagnostics.extend(
                        f"ps-census-malformed-line={line!r}\n".encode(
                            "utf-8", errors="replace"
                        )
                    )
            elif line.strip():
                reliable = False
                census_diagnostics.extend(
                    f"ps-census-malformed-line={line!r}\n".encode(
                        "utf-8", errors="replace"
                    )
                )
    if process is not None:
        process._ios_tree_census_observed = reliable  # type: ignore[attr-defined]
        if census_diagnostics:
            prior = getattr(process, "_ios_tree_census_diagnostics", b"")
            process._ios_tree_census_diagnostics = (  # type: ignore[attr-defined]
                prior + bytes(census_diagnostics)
            )
    descendants: set[int] = set()
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        for child, child_parent in parent_by_pid.items():
            if child_parent == parent and child not in descendants:
                descendants.add(child)
                frontier.append(child)
    return descendants


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if Path(f"/proc/{pid}/stat").is_file():
        try:
            stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            close = stat_line.rfind(")")
            return stat_line[close + 2 :].split()[0] != "Z"
        except (OSError, ValueError, IndexError):
            return True
    return True


def _wait_for_process_tree(
    process: subprocess.Popen[bytes], tracked: set[int], timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        tracked.update(_proc_descendants(process.pid, process=process))
        if not getattr(process, "_ios_tree_census_observed", True):
            return False
        if (
            process.poll() is not None
            and not _process_group_alive(process)
            and not any(_pid_alive(pid) for pid in tracked if pid != process.pid)
        ):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            pass


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    tracked: set[int] | None = None,
    grace_seconds: float,
    description: str,
) -> set[int]:
    tracked = tracked if tracked is not None else set()
    tracked.update({process.pid} | _proc_descendants(process.pid, process=process))
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for pid in tracked:
        if pid != process.pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    if _wait_for_process_tree(process, tracked, grace_seconds):
        return tracked
    print(f"[ios-simulator-process] {description} graceful-stop-expired", file=sys.stderr)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    tracked.update(_proc_descendants(process.pid, process=process))
    for pid in tracked:
        if pid != process.pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    if not _wait_for_process_tree(process, tracked, max(1.0, grace_seconds)):
        raise IOSSimulatorAppContractError(f"{description} process tree survived forced termination")
    return tracked


class SubprocessCommandRunner:
    """Production executor for H4's ephemeral GitHub-hosted macOS job."""

    def __init__(self, raw_directory: Path | None = None) -> None:
        configured = raw_directory or Path(
            os.environ.get("TORTURER_IOS_RAW_LOG_DIR", ".torturer-ios-command-raw")
        )
        self.raw_directory = Path(configured)
        self.raw_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.raw_directory, 0o700)
        self._sequence = 0

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        timeout = timeout_seconds if timeout_seconds is not None else DEFAULT_COMMAND_TIMEOUT_SECONDS
        if timeout <= 0:
            raise IOSSimulatorAppContractError("iOS command timeout must be positive")
        try:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            self._sequence += 1
            raw_output = (
                b"--- command-launch-error ---\n"
                + repr(error).encode("utf-8", errors="replace")
                + b"\n"
            )
            raw_path = self.raw_directory / f"command-{secrets.token_hex(16)}.raw.log"
            with raw_path.open("xb") as raw_handle:
                raw_handle.write(raw_output)
                raw_handle.flush()
                os.fsync(raw_handle.fileno())
            os.chmod(raw_path, 0o600)
            emit_evidence("ios-command", status="failed", payloads={"combined": raw_output})
            raise IOSSimulatorAppContractError(
                f"iOS command could not start ({type(error).__name__}); complete diagnostics retained privately"
            ) from error
        tracked = {process.pid}
        try:
            raw_output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raw_output = error.output or b""
            print(
                f"[ios-simulator-command] timeout after {timeout:g}s; terminating process tree",
                file=sys.stderr,
            )
            termination_error: IOSSimulatorAppContractError | None = None
            try:
                tracked = _terminate_process_tree(
                    process,
                    tracked=tracked,
                    grace_seconds=min(COMMAND_TERMINATION_GRACE_SECONDS, max(1.0, timeout)),
                    description="command",
                )
            except IOSSimulatorAppContractError as cleanup_error:
                termination_error = cleanup_error
            try:
                recovered, _ = process.communicate(timeout=max(1.0, COMMAND_TERMINATION_GRACE_SECONDS))
                raw_output += recovered or b""
            except subprocess.TimeoutExpired as drain_error:
                raw_output += drain_error.output or b""
                termination_error = termination_error or IOSSimulatorAppContractError(
                    "iOS command process tree and diagnostic pipe survived final cleanup"
                )
            try:
                if not _wait_for_process_tree(process, tracked, 0.0):
                    termination_error = termination_error or IOSSimulatorAppContractError(
                        "iOS command process tree remained after final diagnostic drain"
                    )
            except IOSSimulatorAppContractError as cleanup_error:
                termination_error = termination_error or cleanup_error
            tree_diagnostics = getattr(process, "_ios_tree_census_diagnostics", b"")
            if tree_diagnostics:
                raw_output += b"\n--- ios-process-tree-census-diagnostics ---\n" + tree_diagnostics
            self._sequence += 1
            raw_path = self.raw_directory / f"command-{secrets.token_hex(16)}.raw.log"
            with raw_path.open("xb") as raw_handle:
                raw_handle.write(raw_output)
                raw_handle.flush()
                os.fsync(raw_handle.fileno())
            os.chmod(raw_path, 0o600)
            detail = f"; cleanup={termination_error}" if termination_error is not None else ""
            emit_evidence("ios-command", status="timed-out", payloads={"combined": raw_output})
            raise IOSSimulatorAppContractError(
                f"iOS command timed out after {timeout:g}s{detail}; complete diagnostics retained privately"
            )
        raw_output = raw_output or b""
        tree_diagnostics = getattr(process, "_ios_tree_census_diagnostics", b"")
        if tree_diagnostics:
            raw_output += b"\n--- ios-process-tree-census-diagnostics ---\n" + tree_diagnostics
        self._sequence += 1
        raw_path = self.raw_directory / f"command-{secrets.token_hex(16)}.raw.log"
        with raw_path.open("xb") as raw_handle:
            raw_handle.write(raw_output)
            raw_handle.flush()
            os.fsync(raw_handle.fileno())
        os.chmod(raw_path, 0o600)
        emit_evidence(
            "ios-command",
            status=("failed" if process.returncode else "completed"),
            payloads={"combined": raw_output},
        )
        return CommandResult(
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=raw_output.decode("utf-8", errors="replace"),
            raw_log=raw_path,
        )


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
    architecture: str = _DEFAULT_ARCHITECTURE
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
        if self.bundle_identifier != _BUNDLE_IDENTIFIER:
            raise IOSSimulatorAppContractError("Simulator app bundle identity is fixed by the public contract")
        if self.architecture not in _SUPPORTED_ARCHITECTURES:
            raise IOSSimulatorAppContractError("Simulator app architecture must be arm64 or amd64")
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


def public_ios_simulator_app_contract(architecture: str) -> IOSSimulatorAppContract:
    """Return the fixed public contract for one supported Simulator CPU."""
    return IOSSimulatorAppContract(architecture=architecture)


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
        f"ARCHS={_XCODE_ARCHITECTURES[contract.architecture]}",
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
    budget: RunBudget | None = None,
) -> IOSSimulatorAppEvidence:
    """Build, inspect, install, launch and terminate the fixed Simulator app.

    ``with_xctest`` remains opt-in until DobbyVPN exposes the named app test
    target.  Its result is independently inspected and summarized when used.
    """
    budget = budget or RunBudget()
    try:
        source = source_identity_from_simulator_checkout(
            candidate_root, repository=repository, expected_commit=commit_sha
        )
    except IOSSimulatorContractError as error:
        raise IOSSimulatorAppContractError(str(error)) from error

    work_dir.mkdir(parents=True, exist_ok=True)
    simulator: AvailableSimulator | None = None
    app_launched = False
    termination_attempted = False
    failure: IOSSimulatorAppContractError | None = None
    evidence: IOSSimulatorAppEvidence | None = None
    try:
        inventory = _require_success(
            runner,
            ["xcrun", "simctl", "list", "devices", "available", "-j"],
            "list Simulators",
            budget=budget,
        )
        simulator = select_available_iphone(inventory.stdout)
        boot = runner.run(
            simctl_boot_command(simulator.udid),
            timeout_seconds=budget.operation_timeout(60),
        )
        if boot.returncode and "current state: Booted" not in boot.stdout:
            raise IOSSimulatorAppContractError(
                "boot Simulator failed; complete diagnostics retained privately"
            )
        _require_success(
            runner,
            simctl_bootstatus_command(simulator.udid),
            "wait for Simulator boot",
            budget=budget,
        )
        _require_success(
            runner,
            xcodebuild_app_command(
                contract, candidate_root=candidate_root, device_udid=simulator.udid, work_dir=work_dir
            ),
            "build unsigned Simulator app",
            budget=budget,
        )
        try:
            app = inspect_simulator_app(
                contract.app_path(work_dir), source=source,
                expected_bundle_identifier=contract.bundle_identifier,
                architecture=contract.architecture,
            )
        except IOSSimulatorContractError as error:
            raise IOSSimulatorAppContractError(str(error)) from error
        _require_success(
            runner,
            simctl_install_command(simulator.udid, app.app_path),
            "install Simulator app",
            budget=budget,
        )
        _require_success(
            runner,
            simctl_launch_command(simulator.udid, contract.bundle_identifier),
            "launch Simulator app",
            budget=budget,
        )
        app_launched = True
        _terminate_simulator_app(
            runner,
            simulator.udid,
            contract.bundle_identifier,
            budget=budget,
        )
        termination_attempted = True
        app_launched = False

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
                budget=budget,
            )
            try:
                xcresult = inspect_xcresult_bundle(
                    result_path, source=source, required_test_identifier=contract.test_identifier
                )
            except IOSSimulatorContractError as error:
                raise IOSSimulatorAppContractError(str(error)) from error
            summary = _require_success(
                runner,
                xcresult_summary_command(result_path),
                "read XCTest summary",
                budget=budget,
            )
            try:
                validate_xcresult_summary(summary.stdout)
            except IOSSimulatorContractError as error:
                raise IOSSimulatorAppContractError(str(error)) from error
        evidence = IOSSimulatorAppEvidence(simulator=simulator, app=app, xcresult=xcresult)
    except IOSSimulatorAppContractError as error:
        failure = error
    except Exception as error:
        failure = IOSSimulatorAppContractError(f"iOS Simulator command failed: {error}")
    finally:
        if simulator is not None and app_launched and not termination_attempted:
            try:
                _terminate_simulator_app(
                    runner,
                    simulator.udid,
                    contract.bundle_identifier,
                    budget=budget,
                )
            except IOSSimulatorAppContractError as cleanup_error:
                failure = cleanup_error if failure is None else IOSSimulatorAppContractError(
                    f"{failure}; app cleanup failed: {cleanup_error}"
                )
            except Exception as cleanup_error:
                cleanup_failure = IOSSimulatorAppContractError(f"app cleanup failed: {cleanup_error}")
                failure = cleanup_failure if failure is None else IOSSimulatorAppContractError(
                    f"{failure}; {cleanup_failure}"
                )
        if simulator is not None:
            try:
                shutdown = runner.run(
                    ["xcrun", "simctl", "shutdown", simulator.udid],
                    timeout_seconds=budget.cleanup_timeout(),
                )
                if shutdown.returncode:
                    cleanup_error = IOSSimulatorAppContractError(
                        f"Simulator shutdown failed with exit code {shutdown.returncode}"
                    )
                    failure = cleanup_error if failure is None else IOSSimulatorAppContractError(
                        f"{failure}; {cleanup_error}"
                    )
            except Exception as cleanup_error:
                failure = IOSSimulatorAppContractError(
                    f"{failure}; Simulator shutdown failed: {cleanup_error}"
                ) if failure is not None else IOSSimulatorAppContractError(
                    f"Simulator shutdown failed: {cleanup_error}"
                )
    if failure is not None:
        raise failure
    if evidence is None:
        raise IOSSimulatorAppContractError("iOS Simulator contract produced no evidence")
    budget.assert_within_deadline()
    return evidence


def _require_success(
    runner: CommandRunner,
    command: Sequence[str],
    stage: str,
    *,
    budget: RunBudget | None = None,
) -> CommandResult:
    timeout = budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS) if budget else DEFAULT_COMMAND_TIMEOUT_SECONDS
    result = runner.run(command, timeout_seconds=timeout)
    if result.returncode:
        excerpt = safe_diagnostic_excerpt(result.stdout)
        diagnostic = f"\n{excerpt}" if excerpt else ""
        raise IOSSimulatorAppContractError(
            f"{stage} failed with exit code {result.returncode};"
            f" complete diagnostics retained privately{diagnostic}"
        )
    return result


def _terminate_simulator_app(
    runner: CommandRunner,
    device_udid: str,
    bundle_identifier: str,
    *,
    budget: RunBudget | None = None,
) -> CommandResult:
    """Terminate a just-launched app, retrying one transient not-running result."""
    command = simctl_terminate_command(device_udid, bundle_identifier)
    timeout = budget.operation_timeout(60) if budget else 60
    result = runner.run(command, timeout_seconds=timeout)
    if result.returncode == _TERMINATE_NOT_RUNNING_EXIT_CODE:
        time.sleep(_TERMINATE_RETRY_DELAY_SECONDS)
        retry_timeout = budget.operation_timeout(60) if budget else 60
        result = runner.run(command, timeout_seconds=retry_timeout)
    if result.returncode:
            raise IOSSimulatorAppContractError(
                "terminate Simulator app failed with exit code "
                f"{result.returncode}; complete diagnostics retained privately"
            )
    return result
