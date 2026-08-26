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
import shlex
import threading
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
    "network_transition",
    "sleep_wake",
    "process_loss",
}
_EXTERNAL_OPERATIONS = frozenset(
    {"network_transition", "sleep_wake", "process_loss"}
)
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
    adapter_version = "v4"

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
        self._active_controls: tuple[tuple[str, str, str, float], ...] = ()

    @property
    def capabilities(self) -> frozenset[Capability]:
        if not self._ready:
            return frozenset()
        return _CORE_CAPABILITIES | frozenset(
            {
                Capability.SLEEP_WAKE,
                Capability.PROCESS_LOSS,
            }
        )

    @property
    def capability_unavailable_reasons(self) -> dict[Capability, str]:
        return {
            # Airplane-mode toggling alone does not prove that the emulator's
            # non-VPN uplink/default route was lost and restored. The public
            # google_apis image is not provisioned with a reliable isolated
            # root-controlled data interface, so fail closed until that seam
            # exists rather than calling a settings change a transition.
            Capability.NETWORK_TRANSITION: "ANDROID_UPLINK_TOGGLE_UNSUPPORTED",
            Capability.ENDURANCE: "ANDROID_ENDURANCE_SEAM_UNSUPPORTED",
        }

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
                        # ``adb shell`` joins its argument vector before it
                        # sends it to the device shell.  Quote the complete
                        # ``sh -c`` payload so the remote shell passes the
                        # command as one argument; without this, ``sh -c``
                        # receives only ``mkdir`` and toybox reports
                        # ``mkdir: Needs 1 argument``.
                        shlex.quote(f"mkdir -p files && cat > {device_profile}"),
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
                        shlex.quote(f"mkdir -p files && cat > {device_command}"),
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
            instrument = self._run_instrumentation(command_file.name, deadline)
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
                (
                    profile_name,
                    command_file.name,
                    output_name,
                    tuple(control[0] for control in self._active_controls),
                ),
                cleanup_deadline,
            )
            self._active_controls = ()
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

    def _run_instrumentation(self, command_name: str, deadline: float) -> CommandResult:
        arguments = (
            "shell", "am", "instrument", "-w", "-r", "-e", "dobby.real_profile", "1",
            "-e", "dobby.hosted_command_file", command_name, "-e", "class",
            _INSTRUMENTATION_CLASS, _INSTRUMENTATION_COMPONENT,
        )
        controls = self._active_controls
        if not controls:
            return self._adb(
                arguments,
                _remaining(deadline, "ANDROID_INSTRUMENTATION_TIMEOUT"),
                "ANDROID_INSTRUMENTATION_FAILED",
                allow_nonzero=True,
            )

        holder: dict[str, object] = {}

        def invoke() -> None:
            try:
                holder["result"] = self._adb(
                    arguments,
                    _remaining(deadline, "ANDROID_INSTRUMENTATION_TIMEOUT"),
                    "ANDROID_INSTRUMENTATION_FAILED",
                    allow_nonzero=True,
                )
            except Exception as error:  # surfaced on the owner thread below
                holder["error"] = error

        worker = threading.Thread(target=invoke, name="dobbyvpn-android-instrument", daemon=True)
        worker.start()
        try:
            for control_file, operation, token, timeout in controls:
                self._complete_external_control(
                    control_file, operation, token,
                    min(deadline, time.monotonic() + timeout),
                )
            worker.join(timeout=_remaining(deadline, "ANDROID_INSTRUMENTATION_TIMEOUT"))
            if worker.is_alive():
                raise ScenarioExecutionError("ANDROID_INSTRUMENTATION_TIMEOUT")
            error = holder.get("error")
            if isinstance(error, ScenarioExecutionError):
                raise error
            if isinstance(error, Exception):
                raise ScenarioExecutionError("ANDROID_INSTRUMENTATION_FAILED") from error
            result = holder.get("result")
            if not isinstance(result, CommandResult):
                raise ScenarioExecutionError("ANDROID_INSTRUMENTATION_FAILED")
            return result
        except Exception:
            # If a control action fails, wait only until the already-declared
            # work deadline for the runner to reap the instrumentation process
            # and retain its final bytes. The diagnostics/cleanup reserve is
            # outside this clock and remains available to the caller.
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
            raise
        finally:
            # The command runner owns bounded process cleanup.  This join is
            # deliberately non-blocking so a failed control cannot extend the
            # scenario deadline; the runner's timeout retains its diagnostics.
            worker.join(timeout=0)

    def _complete_external_control(
        self, control_file: str, operation: str, token: str, deadline: float
    ) -> None:
        self._wait_device_file(control_file + ".ready", deadline)
        self._perform_external_control(operation, deadline)
        raw_directory = getattr(self.runner, "raw_directory", None)
        if not isinstance(raw_directory, Path):
            raise ScenarioExecutionError("ANDROID_CONTROL_EVIDENCE_UNAVAILABLE")
        control_path = raw_directory / control_file
        payload = json.dumps(
            {"operation": operation, "token": token},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        descriptor = -1
        try:
            descriptor = os.open(
                control_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "wb") as output:
                descriptor = -1
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            staged = f"/data/local/tmp/{control_file}"
            self._adb(
                ("push", str(control_path), staged),
                _remaining(deadline, "ANDROID_CONTROL_STAGE_TIMEOUT"),
                "ANDROID_CONTROL_STAGE_FAILED",
            )
            self._adb(
                ("shell", "run-as", _PACKAGE_NAME, "cp", staged, f"files/{control_file}"),
                _remaining(deadline, "ANDROID_CONTROL_STAGE_TIMEOUT"),
                "ANDROID_CONTROL_STAGE_FAILED",
            )
            self._adb(
                ("shell", "run-as", _PACKAGE_NAME, "chmod", "600", f"files/{control_file}"),
                _remaining(deadline, "ANDROID_CONTROL_STAGE_TIMEOUT"),
                "ANDROID_CONTROL_STAGE_FAILED",
            )
            self._wait_device_file(control_file + ".ready", deadline, present=False)
        finally:
            if descriptor != -1:
                os.close(descriptor)
            try:
                control_path.unlink()
            except FileNotFoundError:
                pass

    def _wait_device_file(
        self, name: str, deadline: float, *, present: bool = True
    ) -> None:
        if _FILE_NAME.fullmatch(name) is None:
            raise ScenarioExecutionError("ANDROID_CONTROL_NAME_INVALID")
        expected = b"READY" if present else b"ABSENT"
        while time.monotonic() < deadline:
            result = self._adb(
                (
                    "shell", "run-as", _PACKAGE_NAME, "sh", "-c",
                    f"if test -f files/{name}; then printf READY; else printf ABSENT; fi",
                ),
                min(2.0, _remaining(deadline, "ANDROID_CONTROL_TIMEOUT")),
                "ANDROID_CONTROL_PROBE_FAILED",
                allow_nonzero=True,
            )
            if result.returncode == 0 and result.stdout.strip() == expected:
                return
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        raise ScenarioExecutionError("ANDROID_CONTROL_TIMEOUT")

    def _perform_external_control(self, operation: str, deadline: float) -> None:
        if operation == "network_transition":
            # Do not confuse an airplane-mode setting change with a real
            # uplink transition. This hosted image currently has no reliable
            # isolated interface whose link/default route can be toggled
            # while ADB remains reachable, so the capability is unavailable.
            del deadline
            raise ScenarioExecutionError("ANDROID_UPLINK_TOGGLE_UNSUPPORTED")
        if operation == "sleep_wake":
            awake_before = self._device_text(
                ("shell", "dumpsys", "power"), deadline,
                "ANDROID_SLEEP_WAKE_PROBE_FAILED",
            ).upper()
            if not self._power_state(awake_before, asleep=False):
                raise ScenarioExecutionError("ANDROID_SLEEP_WAKE_PRECONDITION")
            sleep_sent = False
            self._adb(
                ("shell", "input", "keyevent", "223"),
                _remaining(deadline, "ANDROID_SLEEP_WAKE_SLEEP_FAILED"),
                "ANDROID_SLEEP_WAKE_SLEEP_FAILED",
            )
            sleep_sent = True
            try:
                state = self._device_text(
                    ("shell", "dumpsys", "power"), deadline,
                    "ANDROID_SLEEP_WAKE_PROBE_FAILED",
                ).upper()
                if not self._power_state(state, asleep=True):
                    raise ScenarioExecutionError("ANDROID_SLEEP_WAKE_NOT_OBSERVED")
                self._observe_android_vpn(deadline, "ANDROID_SLEEP_WAKE_ACTIVE")
            finally:
                if sleep_sent:
                    self._adb(
                        ("shell", "input", "keyevent", "224"),
                        _remaining(deadline, "ANDROID_SLEEP_WAKE_WAKE_FAILED"),
                        "ANDROID_SLEEP_WAKE_WAKE_FAILED",
                    )
                    state = self._device_text(
                        ("shell", "dumpsys", "power"), deadline,
                        "ANDROID_SLEEP_WAKE_PROBE_FAILED",
                    ).upper()
                    if not self._power_state(state, asleep=False):
                        raise ScenarioExecutionError("ANDROID_SLEEP_WAKE_NOT_RESTORED")
                    self._observe_android_vpn(deadline, "ANDROID_SLEEP_WAKE_RESTORED")
            return
        if operation == "process_loss":
            before = self._device_text(
                ("shell", "pidof", _PACKAGE_NAME), deadline,
                "ANDROID_PROCESS_LOSS_PROBE_FAILED",
            )
            if not before:
                raise ScenarioExecutionError("ANDROID_PROCESS_LOSS_PRECONDITION")
            self._adb(
                ("shell", "am", "force-stop", _PACKAGE_NAME),
                _remaining(deadline, "ANDROID_PROCESS_LOSS_STOP_FAILED"),
                "ANDROID_PROCESS_LOSS_STOP_FAILED",
            )
            absent_probes = 0
            while time.monotonic() < deadline:
                current = self._adb(
                    ("shell", "pidof", _PACKAGE_NAME),
                    min(2.0, _remaining(deadline, "ANDROID_PROCESS_LOSS_TIMEOUT")),
                    "ANDROID_PROCESS_LOSS_PROBE_FAILED",
                    allow_nonzero=True,
                )
                if current.returncode in (0, 1) and not current.stdout.strip():
                    absent_probes += 1
                    if absent_probes >= 2:
                        return
                else:
                    absent_probes = 0
                time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            raise ScenarioExecutionError("ANDROID_PROCESS_LOSS_NOT_ABSENT")
        raise ScenarioExecutionError("ANDROID_OPERATION_UNSUPPORTED")

    def _device_text(self, arguments: tuple[str, ...], deadline: float, failure: str) -> str:
        result = self._adb(arguments, _remaining(deadline, failure), failure, allow_nonzero=True)
        if result.returncode != 0:
            raise ScenarioExecutionError(failure)
        return result.stdout.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _power_state(value: str, *, asleep: bool) -> bool:
        """Recognize the Android power boundary, not Doze/device-idle state."""
        if asleep:
            return bool(
                re.search(r"\bmWakefulness\s*=\s*Asleep\b", value, re.IGNORECASE)
                or re.search(r"Display Power:.*\bstate=OFF\b", value, re.IGNORECASE)
            )
        return bool(
            re.search(r"\bmWakefulness\s*=\s*Awake\b", value, re.IGNORECASE)
            or re.search(r"Display Power:.*\bstate=ON\b", value, re.IGNORECASE)
        )

    def _observe_android_vpn(self, deadline: float, failure: str) -> None:
        connectivity = self._device_text(
            ("shell", "dumpsys", "connectivity"), deadline, failure
        ).lower()
        links = self._device_text(("shell", "ip", "-o", "link"), deadline, failure).lower()
        routes = self._device_text(("shell", "ip", "route"), deadline, failure).lower()
        if "vpn" not in connectivity or ("tun" not in links and "tun" not in routes):
            raise ScenarioExecutionError(failure)

    def _write_command(self, scenario: ScenarioDefinition) -> tuple[Path, str, str]:
        self._active_controls = ()
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
        controls: list[tuple[str, str, str, float]] = []
        for step in scenario.steps:
            if step.operation not in _ALLOWED_OPERATIONS:
                raise ScenarioExecutionError("ANDROID_OPERATION_UNSUPPORTED")
            item = step.to_dict()
            if step.operation in _EXTERNAL_OPERATIONS:
                control_file = f"{token}.external-{len(controls)}.json"
                control_token = hashlib.sha256(
                    f"{scenario.id}\0{step.id}\0{step.operation}\0{self.source_sha}".encode(
                        "ascii"
                    )
                ).hexdigest()
                if _FILE_NAME.fullmatch(control_file) is None:
                    raise ScenarioExecutionError("ANDROID_CONTROL_NAME_INVALID")
                item["control_file"] = control_file
                item["control_token"] = control_token
                controls.append(
                    (control_file, step.operation, control_token, float(step.timeout_seconds))
                )
            operations.append(item)
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
        self._active_controls = tuple(controls)
        return command_file, profile_name, output_name

    def _adb(
        self,
        arguments: tuple[str, ...],
        timeout_seconds: float,
        failure_code: str,
        *,
        allow_nonzero: bool = False,
        allow_partial_timeout: bool = False,
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
            # SubprocessRunner retains a complete raw record before raising
            # COMMAND_TIMEOUT or COMMAND_DEADLINE_EXCEEDED. For the
            # deliberately best-effort logcat diagnostic, recover that
            # retained stream as a normal timed-out result so
            # _capture_diagnostics can accept it when bytes were actually
            # captured. This keeps the original bytes intact while avoiding
            # a false finalization failure merely because Android's log
            # buffer is larger than the short reserve.
            if allow_partial_timeout and error.code in {
                "COMMAND_TIMEOUT",
                "COMMAND_DEADLINE_EXCEEDED",
            }:
                return self._partial_timeout_result(command)
            raise ScenarioExecutionError(error.code) from error
        if result.timed_out and not allow_partial_timeout:
            raise ScenarioExecutionError("ANDROID_COMMAND_TIMEOUT")
        if result.returncode != 0 and not allow_nonzero:
            raise ScenarioExecutionError(failure_code)
        return result

    def _partial_timeout_result(self, command: tuple[str, ...]) -> CommandResult:
        """Rehydrate a timed-out command from the runner's retained raw file."""

        raw_directory = getattr(self.runner, "raw_directory", None)
        if not isinstance(raw_directory, Path):
            return CommandResult(command, 124, timed_out=True)
        try:
            candidates = list(raw_directory.glob("command-*.raw.log"))
            if not candidates:
                return CommandResult(command, 124, timed_out=True)
            raw_path = max(candidates, key=lambda path: path.stat().st_mtime_ns)
            payload = raw_path.read_bytes()
        except OSError:
            return CommandResult(command, 124, timed_out=True)

        def section(name: str) -> bytes:
            match = re.search(
                rb"(?ms)^" + name.encode("ascii") + rb"-begin\n(.*?)\n"
                + name.encode("ascii") + rb"-end\n",
                payload,
            )
            return match.group(1) if match else b""

        return CommandResult(
            command,
            124,
            stdout=section("stdout"),
            stderr=section("stderr"),
            timed_out=True,
        )

    def _capture_diagnostics(self, deadline: float) -> ScenarioExecutionError | None:
        error: ScenarioExecutionError | None = None
        # Drain bounded structural diagnostics first.  A large Android log
        # buffer may consume the remaining slice and is intentionally last;
        # its partial bytes are still retained and accepted below.
        for command in (
            ("shell", "dumpsys", "connectivity"),
            ("shell", "dumpsys", "package", _PACKAGE_NAME),
            ("shell", "ps", "-A"),
            ("logcat", "-d", "-b", "all"),
        ):
            try:
                result = self._adb(
                    command,
                    _finalization_timeout(deadline, "ANDROID_DIAGNOSTICS_TIMEOUT"),
                    "ANDROID_DIAGNOSTICS_FAILED",
                    allow_nonzero=command[0] == "logcat",
                    allow_partial_timeout=command[0] == "logcat",
                )
                # A full-buffer logcat dump can exceed the short per-scenario
                # finalization slice.  The runner has already retained every
                # byte received before the bounded timeout; accept that
                # partial diagnostic only when it contains output, while
                # preserving a failure for an empty or non-timeout command.
                if command[0] == "logcat" and result.timed_out:
                    if result.stdout:
                        continue
                    error = error or ScenarioExecutionError("ANDROID_DIAGNOSTICS_FAILED")
                elif command[0] == "logcat" and result.returncode != 0:
                    error = error or ScenarioExecutionError("ANDROID_DIAGNOSTICS_FAILED")
            except ScenarioExecutionError as failure:
                error = error or failure
        return error

    def _cleanup_device(
        self, names: tuple[str, str, str, tuple[str, ...]], deadline: float
    ) -> ScenarioExecutionError | None:
        profile_name, command_name, output_name, control_names = names
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
                *(f"files/{name}" for name in control_names),
                *(f"files/{name}.ready" for name in control_names),
                *(f"files/{name}.tmp" for name in control_names),
            ),
            (
                "shell",
                "rm",
                "-f",
                f"/data/local/tmp/{profile_name}",
                f"/data/local/tmp/{command_name}",
                *(f"/data/local/tmp/{name}" for name in control_names),
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
