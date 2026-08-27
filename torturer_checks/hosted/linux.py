"""Linux hosted adapter with explicit, bounded runner controls."""

from __future__ import annotations

import os
from pathlib import Path
import re
import socket
import time

from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import CapabilityUnavailable, ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep

from .cli import (
    CommandRunner,
    HostedAdapterError,
    HostedCLIAdapter,
    _allocate_owner_only_path,
    _ensure_owner_only_directory,
)


_PID = re.compile(r"^[1-9][0-9]{0,9}$")
_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_SERVICE_LAUNCH_SCRIPT = """\
set -eu
binary=$1
control_socket=$2
peer_uid=$3
library_path=$4
log_path=$5
if [ -n "$library_path" ]; then
  env \
    DOBBYVPN_CONTROL_SOCKET="$control_socket" \
    DOBBYVPN_CONTROL_PEER_UID="$peer_uid" \
    LD_LIBRARY_PATH="$library_path" \
    "$binary" >> "$log_path" 2>&1 < /dev/null &
else
  env \
    DOBBYVPN_CONTROL_SOCKET="$control_socket" \
    DOBBYVPN_CONTROL_PEER_UID="$peer_uid" \
    "$binary" >> "$log_path" 2>&1 < /dev/null &
fi
printf '%s\n' "$!"
"""


class LinuxServiceProcessController:
    """Restart exactly the trusted candidate service after a process-loss step."""

    def __init__(
        self,
        *,
        pid: int,
        binary: Path,
        socket: Path,
        library_path: Path | None,
        pid_file: Path,
        runner: CommandRunner,
        raw_directory: Path,
    ) -> None:
        if pid <= 0 or not _PID.fullmatch(str(pid)):
            raise HostedAdapterError("SERVICE_PID_INVALID")
        if not binary.is_file() or binary.is_symlink():
            raise HostedAdapterError("SERVICE_BINARY_UNAVAILABLE")
        if not socket.is_absolute() or not pid_file.is_absolute():
            raise HostedAdapterError("SERVICE_PATH_INVALID")
        if library_path is not None and (not library_path.is_dir() or library_path.is_symlink()):
            raise HostedAdapterError("SERVICE_LIBRARY_UNAVAILABLE")
        self.pid = pid
        self.binary = binary
        self.socket = socket
        self.library_path = library_path
        self.pid_file = pid_file
        self.runner = runner
        self.raw_directory = raw_directory
        _ensure_owner_only_directory(self.raw_directory)
        self._restart_number = 0
        self._write_pid(pid)
        self._verify_candidate_pid()

    @staticmethod
    def _remaining(deadline: float, failure: str) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScenarioExecutionError(failure)
        return remaining

    def _write_pid(self, pid: int) -> None:
        temporary = self.pid_file.with_name(f".{self.pid_file.name}.tmp")
        temporary.write_text(str(pid) + "\n", encoding="ascii")
        temporary.chmod(0o600)
        temporary.replace(self.pid_file)
        self.pid_file.chmod(0o600)

    def _sudo(self, args: tuple[str, ...], timeout: float, failure: str):
        try:
            result = self.runner.run(("sudo", "-n", *args), timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        return result

    def _alive(self, timeout: float) -> bool:
        result = self._sudo(("kill", "-0", str(self.pid)), timeout, "SERVICE_PROBE_FAILED")
        return result.returncode == 0 and not result.timed_out

    def _verify_candidate_pid(self, timeout: float = 5.0) -> None:
        try:
            result = self.runner.run(
                ("sudo", "-n", "readlink", "-f", f"/proc/{self.pid}/exe"),
                timeout_seconds=timeout,
            )
        except HostedAdapterError as error:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED") from error
        if result.returncode != 0 or result.timed_out:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED")
        value = result.stdout_text.strip()
        if not value:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED")
        executable = Path(value).resolve()
        expected = self.binary.resolve()
        if executable != expected:
            raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")

    def _wait_dead(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._alive(self._remaining(deadline, "SERVICE_DID_NOT_EXIT")):
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise ScenarioExecutionError("SERVICE_DID_NOT_EXIT")

    def _socket_ready(self, timeout: float = 0.2) -> bool:
        if not self.socket.is_socket():
            return False
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(timeout)
            probe.connect(str(self.socket))
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def _start(self, timeout: float) -> None:
        self._restart_number += 1
        log_path = _allocate_owner_only_path(
            self.raw_directory,
            f"service-restart-{self._restart_number:03d}",
            ".raw.log",
        )
        deadline = time.monotonic() + timeout
        library_value = str(self.library_path) if self.library_path is not None else ""
        command = (
            "sudo", "-n", "sh", "-c", _SERVICE_LAUNCH_SCRIPT,
            "dobbyvpn-service",
            str(self.binary),
            str(self.socket),
            str(os.getuid()),
            library_value,
            str(log_path),
        )
        try:
            launcher = getattr(self.runner, "run_detached", None)
            if not callable(launcher):
                launcher = self.runner.run
            result = launcher(
                command,
                timeout_seconds=min(
                    10.0, self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
                ),
            )
        except HostedAdapterError as error:
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE") from error
        if result.returncode != 0 or result.timed_out:
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE")
        value = result.stdout_text.strip()
        if _PID.fullmatch(value) is None:
            raise ScenarioExecutionError("SERVICE_RESTART_PID_INVALID")
        self.pid = int(value)
        self._write_pid(self.pid)
        while True:
            remaining = self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
            if not self._alive(remaining):
                raise ScenarioExecutionError("SERVICE_RESTART_EXITED")
            # Reserve half of the observed remainder for the socket probe and
            # use the other half for the candidate-PID proof. This keeps both
            # operations inside the same absolute restart deadline without a
            # second unbounded wait or an extra clock race.
            socket_timeout = min(0.2, remaining / 2.0)
            if self._socket_ready(socket_timeout):
                verify_timeout = remaining - socket_timeout
                if verify_timeout <= 0:
                    raise ScenarioExecutionError("SERVICE_RESTART_TIMEOUT")
                self._verify_candidate_pid(verify_timeout)
                return
            time.sleep(min(0.5, remaining))

    def restart_after_loss(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        remaining = self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")
        result = self._sudo(("kill", "-KILL", str(self.pid)), remaining, "SERVICE_KILL_FAILED")
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_KILL_FAILED")
        self._wait_dead(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"))
        self._start(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"))


class LinuxHostedAdapter(HostedCLIAdapter):
    """Drive the Linux CLI and optional explicit service/network test seams."""

    adapter_id = "hosted-linux-cli"
    adapter_version = "v2"

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
        service_socket: Path | None = None,
        service_library_path: Path | None = None,
        service_pid_file: Path | None = None,
        network_interface: str | None = None,
    ) -> None:
        super().__init__(
            cli=cli, profile=profile, runner=runner,
            download_url=download_url, upload_url=upload_url,
        )
        self.network_interface = network_interface
        if network_interface is not None and not _INTERFACE.fullmatch(network_interface):
            raise HostedAdapterError("NETWORK_INTERFACE_INVALID")
        self.service: LinuxServiceProcessController | None = None
        if any(value is not None for value in (service_pid, service_binary, service_socket, service_pid_file)):
            if None in (service_pid, service_binary, service_socket, service_pid_file):
                raise HostedAdapterError("SERVICE_CONTROL_INCOMPLETE")
            raw_directory = getattr(runner, "raw_directory", None)
            if not isinstance(raw_directory, Path):
                raise HostedAdapterError("SERVICE_EVIDENCE_UNAVAILABLE")
            self.service = LinuxServiceProcessController(
                pid=service_pid, binary=service_binary, socket=service_socket,
                library_path=service_library_path, pid_file=service_pid_file,
                runner=runner, raw_directory=raw_directory,
            )

    @property
    def capabilities(self) -> frozenset[Capability]:
        result = set(super().capabilities)
        if self.network_interface is not None:
            result.add(Capability.NETWORK_TRANSITION)
        if self.service is not None:
            result.add(Capability.PROCESS_LOSS)
        return frozenset(result)

    @property
    def capability_unavailable_reasons(self) -> dict[Capability, str]:
        """Keep the hosted suspend limitation explicit and stable."""

        return {
            Capability.SLEEP_WAKE: "HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
        }

    def execute(self, step: ScenarioStep) -> dict[str, object]:
        if step.operation == "network_transition":
            return self._network_transition(float(step.timeout_seconds))
        if step.operation == "process_loss":
            return self._process_loss(float(step.timeout_seconds))
        return super().execute(step)

    def _network_transition(self, timeout: float) -> dict[str, object]:
        if self.network_interface is None:
            raise CapabilityUnavailable()
        deadline = time.monotonic() + timeout
        down_succeeded = False
        try:
            down = self._privileged(("ip", "link", "set", "dev", self.network_interface, "down"), timeout, "NETWORK_DOWN_FAILED")
            if down.returncode != 0:
                raise ScenarioExecutionError("NETWORK_DOWN_FAILED")
            down_succeeded = True
            time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
        finally:
            if down_succeeded:
                up = self._privileged(
                    ("ip", "link", "set", "dev", self.network_interface, "up"),
                    self._remaining(deadline, "NETWORK_UP_FAILED"),
                    "NETWORK_UP_FAILED",
                )
                if up.returncode != 0:
                    raise ScenarioExecutionError("NETWORK_UP_FAILED")
        last_error: ScenarioExecutionError | None = None
        while True:
            remaining = self._remaining(deadline, "NETWORK_TUNNEL_NOT_RESTORED")
            try:
                if not self._connected(remaining):
                    last_error = ScenarioExecutionError("NETWORK_TUNNEL_NOT_RESTORED")
                elif self._routing_identity_changed(remaining):
                    return {"network_transition_verified": time.monotonic() <= deadline}
                else:
                    last_error = ScenarioExecutionError("NETWORK_ROUTING_NOT_RESTORED")
            except ScenarioExecutionError as error:
                if error.reason_code not in {
                    "STATUS_FAILED",
                    "STATUS_INVALID",
                    "EXTERNAL_IDENTITY_FAILED",
                    "EXTERNAL_IDENTITY_INVALID",
                }:
                    raise
                last_error = error
            if time.monotonic() >= deadline:
                break
            time.sleep(min(0.5, self._remaining(deadline, "NETWORK_TUNNEL_NOT_RESTORED")))
        raise last_error or ScenarioExecutionError("NETWORK_ROUTING_NOT_RESTORED")

    def _privileged(self, args: tuple[str, ...], timeout: float, failure: str):
        try:
            return self.runner.run(("sudo", "-n", *args), timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error

    def _process_loss(self, timeout: float) -> dict[str, object]:
        if self.service is None:
            raise CapabilityUnavailable()
        deadline = time.monotonic() + timeout
        self.service.restart_after_loss(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"))
        self._command(("connect-profile", str(self.profile), "0"),
                      self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"), "PROCESS_LOSS_CONNECT_FAILED")
        if not self._connected(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")):
            raise ScenarioExecutionError("PROCESS_LOSS_NOT_RECOVERED")
        if not self._routing_identity_changed(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")):
            raise ScenarioExecutionError("PROCESS_LOSS_ROUTING_NOT_RECOVERED")
        return {"process_loss_verified": True}

__all__ = ["LinuxHostedAdapter", "LinuxServiceProcessController"]
