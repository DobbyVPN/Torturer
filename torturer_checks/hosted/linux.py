"""Linux hosted adapter with explicit, bounded runner controls."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import time

from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import CapabilityUnavailable, ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep

from .cli import CommandRunner, HostedAdapterError, HostedCLIAdapter


_PID = re.compile(r"^[1-9][0-9]{0,9}$")
_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


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
        self.raw_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.raw_directory, 0o700)
        self._restart_number = 0
        self._write_pid(pid)
        self._verify_candidate_pid()

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

    def _verify_candidate_pid(self) -> None:
        try:
            executable = Path(os.readlink(f"/proc/{self.pid}/exe")).resolve()
            expected = self.binary.resolve()
        except OSError as error:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED") from error
        if executable != expected:
            raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")

    def _wait_dead(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._alive(max(0.2, deadline - time.monotonic())):
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise ScenarioExecutionError("SERVICE_DID_NOT_EXIT")

    def _start(self, timeout: float) -> None:
        self._restart_number += 1
        log_path = self.raw_directory / f"service-restart-{self._restart_number:03d}.raw.log"
        log = log_path.open("wb")
        log_path.chmod(0o600)
        command = [
            "sudo", "-n", "env",
            f"DOBBYVPN_CONTROL_SOCKET={self.socket}",
            f"DOBBYVPN_CONTROL_PEER_UID={os.getuid()}",
        ]
        if self.library_path is not None:
            command.append(f"LD_LIBRARY_PATH={self.library_path}")
        command.append(str(self.binary))
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            log.close()
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE") from error
        self._log = log
        self.pid = process.pid
        self._write_pid(self.pid)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ScenarioExecutionError("SERVICE_RESTART_EXITED")
            if self.socket.exists():
                self._verify_candidate_pid()
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise ScenarioExecutionError("SERVICE_RESTART_NOT_READY")

    def restart_after_loss(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        remaining = max(0.2, deadline - time.monotonic())
        result = self._sudo(("kill", "-KILL", str(self.pid)), remaining, "SERVICE_KILL_FAILED")
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_KILL_FAILED")
        self._wait_dead(max(0.2, deadline - time.monotonic()))
        self._start(max(0.2, deadline - time.monotonic()))


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
        if self.download_url is not None and self.upload_url is not None:
            result.add(Capability.ENDURANCE)
        return frozenset(result)

    def execute(self, step: ScenarioStep) -> dict[str, object]:
        if step.operation == "network_transition":
            return self._network_transition(float(step.timeout_seconds))
        if step.operation == "process_loss":
            return self._process_loss(float(step.timeout_seconds))
        if step.operation == "measure_endurance":
            return self._endurance(float(step.timeout_seconds))
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
                up = self._privileged(("ip", "link", "set", "dev", self.network_interface, "up"), max(0.2, deadline - time.monotonic()), "NETWORK_UP_FAILED")
                if up.returncode != 0:
                    raise ScenarioExecutionError("NETWORK_UP_FAILED")
        if not self._connected(max(0.2, deadline - time.monotonic())):
            raise ScenarioExecutionError("NETWORK_TUNNEL_NOT_RESTORED")
        self._external_ip(max(0.2, deadline - time.monotonic()))
        return {"network_transition_verified": time.monotonic() <= deadline}

    def _privileged(self, args: tuple[str, ...], timeout: float, failure: str):
        try:
            return self.runner.run(("sudo", "-n", *args), timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error

    def _process_loss(self, timeout: float) -> dict[str, object]:
        if self.service is None:
            raise CapabilityUnavailable()
        self.service.restart_after_loss(timeout)
        self._command(("connect-profile", str(self.profile), "0"), timeout, "PROCESS_LOSS_CONNECT_FAILED")
        if not self._connected(timeout):
            raise ScenarioExecutionError("PROCESS_LOSS_NOT_RECOVERED")
        return {"process_loss_verified": True}

    def _endurance(self, timeout: float) -> dict[str, object]:
        if self.download_url is None or self.upload_url is None:
            raise CapabilityUnavailable()
        deadline = time.monotonic() + timeout
        last_metrics: dict[str, object] = {}
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"endurance_verified": True, **last_metrics}
            if not self._connected(min(30.0, remaining)):
                raise ScenarioExecutionError("ENDURANCE_DISCONNECTED")
            self._external_ip(min(30.0, remaining))
            last_metrics = self._throughput(min(30.0, remaining))
            if time.monotonic() >= deadline:
                return {"endurance_verified": True, **last_metrics}
            time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))


__all__ = ["LinuxHostedAdapter", "LinuxServiceProcessController"]
