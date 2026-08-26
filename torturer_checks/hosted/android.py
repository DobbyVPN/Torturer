"""Hosted Android adapter for the canonical profile-session seam.

The adapter executes one complete semantic scenario per instrumentation
invocation. DobbyVPN owns Android session state and cleanup; Torturer owns the
scenario catalog, assertions, result schema, and private evidence runner.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Mapping
import uuid

from torturer_contract.functional.android_observation import (
    AndroidObservationError,
    AndroidProfileObservation,
)
from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import (
    CapabilityUnavailable,
    ScenarioExecutionError,
)
from torturer_contract.functional.scenarios import ScenarioDefinition, ScenarioStep

from .cli import (
    CommandResult,
    CommandRunner,
    HostedAdapterError,
    _ensure_owner_only_directory,
    _owner_only_profile,
    _executable_file,
    _https_endpoint,
)


_PACKAGE_NAME = "com.dobby.vpn"
_INSTRUMENTATION_COMPONENT = "com.dobby.vpn.test/com.dobby.TestApplicationRunner"
_INSTRUMENTATION_CLASS = (
    "com.dobby.feature.vpn_service.AndroidHostedProfileInstrumentationTest"
)
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_ALLOWED_OPERATIONS = {
    "configure",
    "connect",
    "observe_tunnel",
    "observe_routing_identity",
    "measure_stability",
    "measure_throughput",
    "disconnect",
    "reconnect",
    "inspect_cleanup",
}
_CORE_CAPABILITIES = frozenset(
    {
        Capability.CONFIGURE,
        Capability.CONNECT,
        Capability.TUNNEL_INTERFACE,
        Capability.ROUTING_IDENTITY,
        Capability.TRAFFIC_MEASUREMENT,
        Capability.DISCONNECT,
        Capability.RECONNECT,
        Capability.RESOURCE_CLEANUP,
    }
)
_LANE_MAX_SECONDS = 1_800.0
_DIAGNOSTICS_RESERVE_FRACTION = 0.125
_CLEANUP_RESERVE_FRACTION = 0.125
_MIN_FINALIZATION_RESERVE_SECONDS = 1.0
_MAX_FINALIZATION_RESERVE_SECONDS = 60.0
_FINALIZATION_COMMAND_MAX_SECONDS = 5.0


def _remaining(deadline: float, code: str) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise ScenarioExecutionError(code)
    return value


def _scenario_deadlines(
    started: float, scenario_seconds: float
) -> tuple[float, float, float]:
    """Return work, diagnostics, and cleanup deadlines within one lane.

    The canonical engine measures the complete adapter call against the
    scenario bound, so finalization reserves are carved out of that bound
    rather than extending it. The reserve scales for the short configure
    scenario while remaining non-zero and never exceeds the hard 1,800-second
    Android lane.
    """
    if scenario_seconds <= 0 or scenario_seconds > _LANE_MAX_SECONDS:
        raise ScenarioExecutionError("SCENARIO_TIMEOUT_INVALID")
    diagnostics_reserve = max(
        _MIN_FINALIZATION_RESERVE_SECONDS,
        scenario_seconds * _DIAGNOSTICS_RESERVE_FRACTION,
    )
    cleanup_reserve = max(
        _MIN_FINALIZATION_RESERVE_SECONDS,
        scenario_seconds * _CLEANUP_RESERVE_FRACTION,
    )
    finalization_scale = min(
        1.0,
        _MAX_FINALIZATION_RESERVE_SECONDS
        / (diagnostics_reserve + cleanup_reserve),
    )
    diagnostics_reserve *= finalization_scale
    cleanup_reserve *= finalization_scale
    finalization_reserve = diagnostics_reserve + cleanup_reserve
    if finalization_reserve >= scenario_seconds:
        # There must still be a positive work window. This only applies to a
        # malformed future scenario whose bound is too short to qualify.
        raise ScenarioExecutionError("SCENARIO_TIMEOUT_INVALID")
    work_deadline = started + scenario_seconds - finalization_reserve
    diagnostics_deadline = work_deadline + diagnostics_reserve
    cleanup_deadline = diagnostics_deadline + cleanup_reserve
    if cleanup_deadline > started + _LANE_MAX_SECONDS:
        raise ScenarioExecutionError("SCENARIO_TIMEOUT_INVALID")
    return work_deadline, diagnostics_deadline, cleanup_deadline


def _finalization_error(
    diagnostic_error: ScenarioExecutionError | None,
    cleanup_error: ScenarioExecutionError | None,
) -> ScenarioExecutionError | None:
    """Map all finalization failures to stable public reason codes."""
    if diagnostic_error is not None and cleanup_error is not None:
        return ScenarioExecutionError("ANDROID_FINALIZATION_FAILED")
    if diagnostic_error is not None:
        return ScenarioExecutionError("ANDROID_DIAGNOSTICS_FAILED")
    if cleanup_error is not None:
        return ScenarioExecutionError("ANDROID_CLEANUP_FAILED")
    return None


def _finalization_timeout(deadline: float, code: str) -> float:
    """Bound each evidence/cleanup command while retaining later attempts."""
    return min(_remaining(deadline, code), _FINALIZATION_COMMAND_MAX_SECONDS)


class AndroidHostedAdapter:
    """Run canonical scenarios through DobbyVPN Android instrumentation."""

    adapter_id = "hosted-android-app"
    adapter_version = "v3"

    def __init__(
        self,
        *,
        runner: CommandRunner,
        profile: Path,
        adb: Path | None = None,
        source_sha: str | None = None,
        identity_url: str | None = None,
        latency_url: str | None = None,
        download_url: str | None = None,
        upload_url: str | None = None,
        cli: Path | None = None,
        **kwargs: object,
    ) -> None:
        if kwargs:
            raise HostedAdapterError("ANDROID_ARGUMENT_UNEXPECTED")
        _owner_only_profile(profile)
        if adb is not None:
            _executable_file(adb, "ANDROID_ADB_UNAVAILABLE")
        if source_sha is not None and (
            _SOURCE_SHA.fullmatch(source_sha) is None
            or source_sha == "0" * 40
        ):
            raise HostedAdapterError("SOURCE_SHA_INVALID")
        endpoint_values = (identity_url, latency_url, download_url, upload_url)
        if any(value is not None for value in endpoint_values) and not all(
            value is not None for value in endpoint_values
        ):
            raise HostedAdapterError("ENDPOINTS_REQUIRED")
        self.runner = runner
        self.profile = profile
        self.adb = adb
        self.source_sha = source_sha
        self.identity_url = (
            _https_endpoint(identity_url, "identity_url") if identity_url is not None else None
        )
        self.latency_url = (
            _https_endpoint(latency_url, "latency_url") if latency_url is not None else None
        )
        self.download_url = (
            _https_endpoint(download_url, "download_url") if download_url is not None else None
        )
        self.upload_url = (
            _https_endpoint(upload_url, "upload_url") if upload_url is not None else None
        )

    @property
    def capabilities(self) -> frozenset[Capability]:
        return _CORE_CAPABILITIES if self._ready else frozenset()

    @property
    def _ready(self) -> bool:
        return (
            self.adb is not None
            and self.source_sha is not None
            and all(
                value is not None
                for value in (
                    self.identity_url,
                    self.latency_url,
                    self.download_url,
                    self.upload_url,
                )
            )
        )

    def execute(self, step: ScenarioStep) -> Mapping[str, object]:
        del step
        if not self._ready:
            raise CapabilityUnavailable()
        raise ScenarioExecutionError("ANDROID_BULK_SCENARIO_REQUIRED")

    def execute_scenario(self, scenario: ScenarioDefinition) -> Mapping[str, object]:
        """Stage one opaque profile and ordered command, then parse safe facts.

        Current Android emulator images do not consistently allow the app UID
        selected by ``run-as`` to read ``/data/local/tmp``.  Stream both
        payloads over the authenticated ``adb shell run-as`` stdin instead of
        relying on a cross-domain temporary-file copy.  The payloads remain
        input-only: the command vector and retained diagnostics never contain
        profile bytes.
        """
        if not self._ready:
            raise CapabilityUnavailable()
        if scenario.max_duration_seconds > _LANE_MAX_SECONDS:
            raise ScenarioExecutionError("SCENARIO_TIMEOUT_INVALID")
        command_file, profile_name, output_name = self._write_command(scenario)
        device_profile = f"files/{profile_name}"
        device_command = f"files/{command_file.name}"
        device_output = f"files/{output_name}"
        started = time.monotonic()
        deadline, diagnostic_deadline, cleanup_deadline = _scenario_deadlines(
            started, float(scenario.max_duration_seconds)
        )
        try:
            stream_payloads = callable(getattr(self.runner, "run_with_input", None))
            if stream_payloads:
                try:
                    profile_bytes = self.profile.read_bytes()
                except OSError as error:
                    raise ScenarioExecutionError("ANDROID_PROFILE_STAGE_FAILED") from error
                self._adb(
                    (
                        "shell",
                        "-T",
                        "run-as",
                        _PACKAGE_NAME,
                        "sh",
                        "-c",
                        f"cat > {device_profile}",
                    ),
                    _remaining(deadline, "ANDROID_PROFILE_STAGE_TIMEOUT"),
                    "ANDROID_PROFILE_STAGE_FAILED",
                    input_bytes=profile_bytes,
                )
                del profile_bytes
            else:
                staged_profile = f"/data/local/tmp/{profile_name}"
                self._adb(
                    ("push", str(self.profile), staged_profile),
                    _remaining(deadline, "ANDROID_PROFILE_STAGE_TIMEOUT"),
                    "ANDROID_PROFILE_STAGE_FAILED",
                )
                self._adb(
                    ("shell", "run-as", _PACKAGE_NAME, "cp", staged_profile, device_profile),
                    _remaining(deadline, "ANDROID_PROFILE_STAGE_TIMEOUT"),
                    "ANDROID_PROFILE_STAGE_FAILED",
                )
            self._adb(
                ("shell", "run-as", _PACKAGE_NAME, "chmod", "600", device_profile),
                _remaining(deadline, "ANDROID_PROFILE_STAGE_TIMEOUT"),
                "ANDROID_PROFILE_STAGE_FAILED",
            )
            if stream_payloads:
                try:
                    command_bytes = command_file.read_bytes()
                except OSError as error:
                    raise ScenarioExecutionError("ANDROID_COMMAND_STAGE_FAILED") from error
                self._adb(
                    (
                        "shell",
                        "-T",
                        "run-as",
                        _PACKAGE_NAME,
                        "sh",
                        "-c",
                        f"cat > {device_command}",
                    ),
                    _remaining(deadline, "ANDROID_COMMAND_STAGE_TIMEOUT"),
                    "ANDROID_COMMAND_STAGE_FAILED",
                    input_bytes=command_bytes,
                )
                del command_bytes
            else:
                staged_command = f"/data/local/tmp/{command_file.name}"
                self._adb(
                    ("push", str(command_file), staged_command),
                    _remaining(deadline, "ANDROID_COMMAND_STAGE_TIMEOUT"),
                    "ANDROID_COMMAND_STAGE_FAILED",
                )
                self._adb(
                    ("shell", "run-as", _PACKAGE_NAME, "cp", staged_command, device_command),
                    _remaining(deadline, "ANDROID_COMMAND_STAGE_TIMEOUT"),
                    "ANDROID_COMMAND_STAGE_FAILED",
                )
            self._adb(
                ("shell", "run-as", _PACKAGE_NAME, "chmod", "600", device_command),
                _remaining(deadline, "ANDROID_COMMAND_STAGE_TIMEOUT"),
                "ANDROID_COMMAND_STAGE_FAILED",
            )
            instrument = self._adb(
                (
                    "shell",
                    "am",
                    "instrument",
                    "-w",
                    "-r",
                    "-e",
                    "dobby.real_profile",
                    "1",
                    "-e",
                    "dobby.hosted_command_file",
                    command_file.name,
                    "-e",
                    "class",
                    _INSTRUMENTATION_CLASS,
                    _INSTRUMENTATION_COMPONENT,
                ),
                _remaining(deadline, "ANDROID_INSTRUMENTATION_TIMEOUT"),
                "ANDROID_INSTRUMENTATION_FAILED",
                allow_nonzero=True,
            )
            output = self._adb(
                ("exec-out", "run-as", _PACKAGE_NAME, "cat", device_output),
                _remaining(deadline, "ANDROID_OBSERVATION_TIMEOUT"),
                "ANDROID_OBSERVATION_UNAVAILABLE",
            )
            try:
                value = json.loads(output.stdout.decode("utf-8"))
                observation = AndroidProfileObservation.from_mapping(
                    value, expected_source_sha=self.source_sha
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                AndroidObservationError,
            ) as error:
                raise ScenarioExecutionError("ANDROID_OBSERVATION_INVALID") from error
            if instrument.returncode != 0 or instrument.timed_out:
                raise ScenarioExecutionError("ANDROID_INSTRUMENTATION_FAILED")
            try:
                return observation.to_observations()
            except AndroidObservationError as error:
                raise ScenarioExecutionError("ANDROID_OBSERVATION_ERROR") from error
        finally:
            diagnostic_error = self._capture_diagnostics(diagnostic_deadline)
            cleanup_error = self._cleanup_device(
                (profile_name, command_file.name, output_name), cleanup_deadline
            )
            finalization_error = _finalization_error(diagnostic_error, cleanup_error)
            if finalization_error is not None:
                # Do not suppress finalization evidence when the product
                # operation already failed. The runner has retained every
                # command stream; this stable code makes the failure visible
                # in the canonical result as well.
                raise finalization_error

    def reset(self, timeout_seconds: float = 5.0) -> None:
        if not self._ready:
            return
        if timeout_seconds <= 0:
            raise HostedAdapterError("INVALID_RESET_TIMEOUT")
        self._adb(
            ("shell", "am", "force-stop", _PACKAGE_NAME),
            timeout_seconds,
            "ANDROID_RESET_FAILED",
        )

    def _write_command(self, scenario: ScenarioDefinition) -> tuple[Path, str, str]:
        raw_directory = getattr(self.runner, "raw_directory", None)
        if not isinstance(raw_directory, Path):
            raise ScenarioExecutionError("ANDROID_EVIDENCE_UNAVAILABLE")
        try:
            _ensure_owner_only_directory(raw_directory)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        assert self.source_sha is not None
        token = hashlib.sha256(
            f"{scenario.id}:{self.source_sha}".encode("utf-8")
        ).hexdigest()[:16] + "-" + uuid.uuid4().hex[:12]
        profile_name = f"android-hosted-{token}.profile"
        command_name = f"android-hosted-{token}.command.json"
        output_name = f"android-hosted-{token}.observation.json"
        for name in (profile_name, command_name, output_name):
            if _FILE_NAME.fullmatch(name) is None:
                raise ScenarioExecutionError("ANDROID_COMMAND_NAME_INVALID")
        operations = []
        for step in scenario.steps:
            if step.operation not in _ALLOWED_OPERATIONS:
                raise ScenarioExecutionError("ANDROID_OPERATION_UNSUPPORTED")
            operations.append(step.to_dict())
        command = {
            "schema": 1,
            "kind": "dobbyvpn.android.profile-command",
            "platform": "android",
            "source_sha": self.source_sha,
            "profile_file": profile_name,
            "output_file": output_name,
            "endpoints": {
                "identity_url": self.identity_url,
                "latency_url": self.latency_url,
                "download_url": self.download_url,
                "upload_url": self.upload_url,
            },
            "operations": operations,
        }
        command_file = raw_directory / command_name
        try:
            descriptor = os.open(
                command_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as error:
            raise ScenarioExecutionError("ANDROID_EVIDENCE_COLLISION") from error
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                descriptor = -1
                output.write(json.dumps(command, sort_keys=True, separators=(",", ":")) + "\n")
                output.flush()
                os.fsync(output.fileno())
        finally:
            if descriptor != -1:
                os.close(descriptor)
        command_file.chmod(0o600)
        return command_file, profile_name, output_name

    def _adb(
        self,
        arguments: tuple[str, ...],
        timeout_seconds: float,
        failure_code: str,
        *,
        allow_nonzero: bool = False,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        if self.adb is None:
            raise ScenarioExecutionError("ANDROID_ADB_UNAVAILABLE")
        try:
            command = (str(self.adb), *arguments)
            if input_bytes is not None:
                run_with_input = getattr(self.runner, "run_with_input", None)
                if callable(run_with_input):
                    result = run_with_input(
                        command,
                        timeout_seconds=timeout_seconds,
                        input_bytes=input_bytes,
                    )
                else:
                    # Small synthetic runners used by contract tests need not
                    # model stdin; they still exercise the same command
                    # vector and result handling.
                    result = self.runner.run(
                        command, timeout_seconds=timeout_seconds
                    )
            else:
                result = self.runner.run(command, timeout_seconds=timeout_seconds)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        if result.timed_out:
            raise ScenarioExecutionError("ANDROID_COMMAND_TIMEOUT")
        if result.returncode != 0 and not allow_nonzero:
            raise ScenarioExecutionError(failure_code)
        return result

    def _capture_diagnostics(self, deadline: float) -> ScenarioExecutionError | None:
        error: ScenarioExecutionError | None = None
        for command in (
            ("logcat", "-d", "-b", "all"),
            ("shell", "dumpsys", "connectivity"),
            ("shell", "dumpsys", "package", _PACKAGE_NAME),
            ("shell", "ps", "-A"),
        ):
            try:
                self._adb(
                    command,
                    _finalization_timeout(deadline, "ANDROID_DIAGNOSTICS_TIMEOUT"),
                    "ANDROID_DIAGNOSTICS_FAILED",
                )
            except ScenarioExecutionError as failure:
                error = error or failure
        return error

    def _cleanup_device(
        self, names: tuple[str, str, str], deadline: float
    ) -> ScenarioExecutionError | None:
        profile_name, command_name, output_name = names
        error: ScenarioExecutionError | None = None
        for command in (
            (
                "shell",
                "run-as",
                _PACKAGE_NAME,
                "rm",
                "-f",
                f"files/{profile_name}",
                f"files/{command_name}",
                f"files/{output_name}",
            ),
            (
                "shell",
                "rm",
                "-f",
                f"/data/local/tmp/{profile_name}",
                f"/data/local/tmp/{command_name}",
            ),
            ("shell", "am", "force-stop", _PACKAGE_NAME),
        ):
            try:
                self._adb(
                    command,
                    _finalization_timeout(deadline, "ANDROID_CLEANUP_TIMEOUT"),
                    "ANDROID_CLEANUP_FAILED",
                )
            except ScenarioExecutionError as failure:
                error = error or failure
        # ADB may leave an instrumentation/service descendant behind even
        # after the app force-stop returns success.  Require an explicit empty
        # process query; a non-empty result is a cleanup failure, while the
        # runner retains the complete stdout/stderr and any timeout bytes.
        try:
            process_result = self._adb(
                ("shell", "pidof", _PACKAGE_NAME),
                _finalization_timeout(deadline, "ANDROID_CLEANUP_TIMEOUT"),
                "ANDROID_CLEANUP_FAILED",
                allow_nonzero=True,
            )
            if process_result.stdout.strip():
                raise ScenarioExecutionError("ANDROID_PROCESS_TREE_SURVIVED")
        except ScenarioExecutionError as failure:
            error = error or failure
        return error
