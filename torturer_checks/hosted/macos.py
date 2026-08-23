"""macOS hosted adapter using DobbyVPN's public CLI."""

from __future__ import annotations

import os
from pathlib import Path
import time

from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import CapabilityUnavailable, ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep

from .cli import (
    CommandRunner,
    HostedAdapterError,
    HostedCLIAdapter,
    HostedServiceProcessController,
)


_MACOS_SERVICE_LAUNCH_SCRIPT = """set -eu
binary=$1
log_path=$2
control_socket=$3
peer_uid=$4
env DOBBYVPN_CONTROL_SOCKET="$control_socket" \
  DOBBYVPN_CONTROL_PEER_UID="$peer_uid" \
  "$binary" >"$log_path" 2>&1 < /dev/null &
printf '%s\\n' "$!"
"""
_MACOS_SOCKET_PROBE = """import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(0.5)
    connection.connect(sys.argv[1])
"""


def _default_control_socket() -> Path:
    configured = os.environ.get("DOBBYVPN_CONTROL_SOCKET")
    if configured:
        return Path(configured)
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        return Path(runtime_dir) / "DobbyVPN" / "control.sock"
    return Path.home() / "Library" / "Application Support" / "DobbyVPN" / "control.sock"


class MacOSServiceProcessController(HostedServiceProcessController):
    """Restart the exact macOS service binary and prove its Unix socket."""

    def __init__(
        self,
        *,
        pid: int,
        binary: Path,
        pid_file: Path | None,
        runner: CommandRunner,
        raw_directory: Path,
        control_socket: Path,
    ) -> None:
        if not control_socket.is_absolute():
            raise HostedAdapterError("SERVICE_CONTROL_SOCKET_INVALID")
        super().__init__(
            pid=pid,
            binary=binary,
            pid_file=pid_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        self.control_socket = control_socket
        self._write_pid(pid)
        try:
            self._verify_candidate_pid(5.0)
        except ScenarioExecutionError as error:
            raise HostedAdapterError(error.reason_code) from error

    def _alive(self, timeout: float) -> bool:
        result = self._probe(
            ("sudo", "-n", "kill", "-0", str(self.pid)),
            timeout,
            "SERVICE_PROBE_FAILED",
        )
        return result.returncode == 0

    def _terminate(self, timeout: float) -> None:
        self._checked(
            ("sudo", "-n", "kill", "-KILL", str(self.pid)),
            timeout,
            "SERVICE_KILL_FAILED",
        )

    def _verify_candidate_pid(self, timeout: float) -> None:
        result = self._probe(
            ("sudo", "-n", "ps", "-p", str(self.pid), "-o", "command="),
            timeout,
            "SERVICE_PID_PROBE_FAILED",
        )
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        actual = result.stdout_text.strip()
        expected = str(self.binary.resolve())
        if actual != expected and not actual.startswith(f"{expected} "):
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")

    def _control_ready(self, timeout: float) -> bool:
        result = self._probe(
            (
                "python3",
                "-c",
                _MACOS_SOCKET_PROBE,
                str(self.control_socket),
            ),
            timeout,
            "SERVICE_CONTROL_PROBE_FAILED",
        )
        return result.returncode == 0

    def _start(self, timeout: float) -> None:
        self._restart_number += 1
        log_path = self.raw_directory / f"service-restart-{self._restart_number:03d}.raw.log"
        deadline = time.monotonic() + timeout
        result = self._probe(
            (
                "sudo",
                "-n",
                "sh",
                "-c",
                _MACOS_SERVICE_LAUNCH_SCRIPT,
                "dobbyvpn-service",
                str(self.binary),
                str(log_path),
                str(self.control_socket),
                str(os.getuid()),
            ),
            min(10.0, self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")),
            "SERVICE_RESTART_UNAVAILABLE",
        )
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE")
        value = result.stdout_text.strip()
        if _service_pid(value) is None:
            raise ScenarioExecutionError("SERVICE_RESTART_PID_INVALID")
        self.pid = int(value)
        self._write_pid(self.pid)
        while time.monotonic() < deadline:
            remaining = self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
            if not self._alive(remaining):
                raise ScenarioExecutionError("SERVICE_RESTART_EXITED")
            if self._control_ready(remaining):
                self._verify_candidate_pid(remaining)
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise ScenarioExecutionError("SERVICE_RESTART_NOT_READY")


def _service_pid(value: str) -> int | None:
    if value.isdigit() and 0 < int(value) <= 9_999_999_999:
        return int(value)
    return None


class MacOSHostedAdapter(HostedCLIAdapter):
    adapter_id = "hosted-macos-cli"
    adapter_version = "v3"

    def __init__(
        self,
        *,
        cli: Path,
        profile: Path,
        runner: CommandRunner,
        download_url: str | None = None,
        upload_url: str | None = None,
        service_pid: int | None = None,
        service_binary: Path | None = None,
        service_pid_file: Path | None = None,
        service_socket: Path | None = None,
    ) -> None:
        super().__init__(
            cli=cli,
            profile=profile,
            runner=runner,
            download_url=download_url,
            upload_url=upload_url,
        )
        if any(value is not None for value in (service_pid, service_binary, service_pid_file)):
            if service_pid is None or service_binary is None or service_pid_file is None:
                raise HostedAdapterError("SERVICE_CONTROL_INCOMPLETE")
            raw_directory = getattr(runner, "raw_directory", None)
            if not isinstance(raw_directory, Path):
                raise HostedAdapterError("SERVICE_EVIDENCE_UNAVAILABLE")
            control_socket = service_socket or _default_control_socket()
            self.service: MacOSServiceProcessController | None = MacOSServiceProcessController(
                pid=service_pid,
                binary=service_binary,
                pid_file=service_pid_file,
                runner=runner,
                raw_directory=raw_directory,
                control_socket=control_socket,
            )
        else:
            self.service = None

    @property
    def capabilities(self) -> frozenset[Capability]:
        result = set(super().capabilities)
        if self.service is not None:
            result.add(Capability.PROCESS_LOSS)
        return frozenset(result)

    def execute(self, step: ScenarioStep) -> dict[str, object]:
        if step.operation == "process_loss":
            return self._process_loss(float(step.timeout_seconds))
        return super().execute(step)

    def _process_loss(self, timeout: float) -> dict[str, object]:
        if self.service is None:
            raise CapabilityUnavailable()
        deadline = time.monotonic() + timeout
        self.service.restart_after_loss(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"))
        self._command(
            ("connect-profile", str(self.profile), "0"),
            self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"),
            "PROCESS_LOSS_CONNECT_FAILED",
        )
        if not self._connected(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")):
            raise ScenarioExecutionError("PROCESS_LOSS_NOT_RECOVERED")
        if not self._routing_identity_changed(
            self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")
        ):
            raise ScenarioExecutionError("PROCESS_LOSS_ROUTING_NOT_RECOVERED")
        return {"process_loss_verified": True}


__all__ = ["MacOSHostedAdapter", "MacOSServiceProcessController"]
