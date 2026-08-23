"""A narrow, secret-safe adapter around DobbyVPN's public CLI.

The adapter never interprets a product result as a canonical pass. It executes
validated command vectors, converts independently observed facts to the small
observation vocabulary, and leaves all assertions/outcomes to Torturer's
canonical engine. Raw command bytes are retained in a private runner-local
folder for the duration of a trusted job; only canonical results are emitted.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time
from typing import Protocol, Sequence
from urllib.parse import urlparse
import uuid

from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import CapabilityUnavailable, ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep


_MIN_ENDURANCE_SAMPLE_SECONDS = 5.0


class HostedAdapterError(RuntimeError):
    """A bounded adapter or command-runner failure without sensitive detail."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CommandResult:
    """A command result with output retained for parsing and private evidence."""

    command: tuple[str, ...]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")


class CommandRunner(Protocol):
    def run(self, command: Sequence[str], *, timeout_seconds: float) -> CommandResult: ...


class SubprocessRunner:
    """Execute argument vectors and retain complete output in a private folder."""

    def __init__(self, raw_directory: Path) -> None:
        self.raw_directory = raw_directory
        self.raw_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.raw_directory, 0o700)
        self._sequence = 0
        self._evidence: list[dict[str, object]] = []

    def run(self, command: Sequence[str], *, timeout_seconds: float) -> CommandResult:
        if timeout_seconds <= 0 or any(not isinstance(item, str) or not item for item in command):
            raise HostedAdapterError("INVALID_COMMAND")
        argv = tuple(command)
        self._sequence += 1
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                list(argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **_process_group_kwargs(),
            )
            stdout, stderr = process.communicate(timeout=timeout_seconds)
            result = CommandResult(argv, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as error:
            partial_stdout = _output_bytes(error.stdout)
            partial_stderr = _output_bytes(error.stderr)
            kill_diagnostics = _kill_process_tree(process)
            try:
                recovered_stdout, recovered_stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as recovery_error:
                kill_diagnostics += b"communicate-after-kill-timeout\n"
                kill_diagnostics += _kill_process(process)
                recovered_stdout = _output_bytes(recovery_error.stdout)
                recovered_stderr = _output_bytes(recovery_error.stderr)
                try:
                    final_stdout, final_stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired as final_error:
                    kill_diagnostics += b"communicate-after-second-kill-timeout\\n"
                    recovered_stdout = _merge_output(
                        recovered_stdout, _output_bytes(final_error.stdout)
                    )
                    recovered_stderr = _merge_output(
                        recovered_stderr, _output_bytes(final_error.stderr)
                    )
                except OSError as final_error:
                    kill_diagnostics += (
                        b"communicate-after-final-kill-error="
                        + repr(final_error).encode("utf-8", errors="replace")
                        + b"\n"
                    )
                else:
                    recovered_stdout = _merge_output(recovered_stdout, final_stdout)
                    recovered_stderr = _merge_output(recovered_stderr, final_stderr)
            stdout = _merge_output(partial_stdout, recovered_stdout)
            stderr = _merge_output(partial_stderr, recovered_stderr)
            result = CommandResult(argv, 124, stdout, stderr, timed_out=True)
            self._retain(result, time.monotonic() - started, kill_diagnostics)
            raise HostedAdapterError("COMMAND_TIMEOUT")
        except OSError as error:
            self._retain_exception(argv, error, time.monotonic() - started)
            raise HostedAdapterError("COMMAND_UNAVAILABLE") from error
        self._retain(result, time.monotonic() - started, b"")
        return result

    def safe_evidence(self) -> tuple[dict[str, object], ...]:
        """Return diagnostics metadata without command arguments or payloads."""
        return tuple(dict(item) for item in self._evidence)

    def _retain(
        self,
        result: CommandResult,
        duration_seconds: float,
        runner_diagnostics: bytes,
    ) -> None:
        label = f"command-{self._sequence:03d}"
        path, descriptor = self._allocate_evidence(label, ".raw.log")
        with os.fdopen(descriptor, "wb") as output:
            output.write(b"argv=" + " ".join(result.command).encode("utf-8", errors="replace") + b"\n")
            output.write(b"returncode=" + str(result.returncode).encode("ascii") + b"\n")
            output.write(b"stdout-begin\n" + result.stdout + b"\nstdout-end\n")
            output.write(b"stderr-begin\n" + result.stderr + b"\nstderr-end\n")
            if runner_diagnostics:
                output.write(b"runner-diagnostics-begin\n" + runner_diagnostics)
                if not runner_diagnostics.endswith(b"\n"):
                    output.write(b"\n")
                output.write(b"runner-diagnostics-end\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
        self._evidence.append({
            "sequence": self._sequence,
            "evidence_file": path.name,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": max(0, int(duration_seconds * 1000)),
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
        })

    def _retain_exception(self, command: Sequence[str], error: OSError, duration_seconds: float) -> None:
        label = f"command-{self._sequence:03d}"
        path, descriptor = self._allocate_evidence(label, ".exception.raw.log")
        with os.fdopen(descriptor, "wb") as output:
            output.write(
                b"argv=" + " ".join(command).encode("utf-8", errors="replace")
                + b"\nexception=" + repr(error).encode("utf-8", errors="replace") + b"\n"
            )
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
        self._evidence.append({
            "sequence": self._sequence,
            "evidence_file": path.name,
            "returncode": None,
            "timed_out": False,
            "duration_ms": max(0, int(duration_seconds * 1000)),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "exception": type(error).__name__,
        })

    def _allocate_evidence(self, label: str, suffix: str) -> tuple[Path, int]:
        """Reserve a fresh evidence file without ever replacing an old one."""

        base = self.raw_directory / f"{label}{suffix}"
        candidates = (base,)
        for _ in range(100):
            for path in candidates:
                try:
                    descriptor = os.open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                except FileExistsError:
                    continue
                os.fchmod(descriptor, 0o600)
                return path, descriptor
            candidates = (
                self.raw_directory / f"{label}-{uuid.uuid4().hex}{suffix}",
            )
        raise HostedAdapterError("EVIDENCE_UNAVAILABLE")


def _output_bytes(value: bytes | str | None) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return b""


def _merge_output(partial: bytes, recovered: bytes) -> bytes:
    """Merge TimeoutExpired output with the post-kill communicate result."""

    if not partial:
        return recovered
    if not recovered or recovered.startswith(partial) or partial.startswith(recovered):
        return recovered if len(recovered) >= len(partial) else partial
    return partial + recovered


def _process_group_kwargs() -> dict[str, int | bool]:
    if os.name == "nt":
        creation_flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return {"creationflags": creation_flag} if creation_flag else {}
    return {"start_new_session": True}


def _kill_process(process: subprocess.Popen[bytes]) -> bytes:
    try:
        process.kill()
    except OSError as error:
        return b"process-kill-error=" + repr(error).encode("utf-8", errors="replace") + b"\n"
    return b""


def _kill_process_tree(process: subprocess.Popen[bytes]) -> bytes:
    """Terminate the process and all children created in its process group."""

    diagnostics = bytearray()
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            diagnostics.extend(b"taskkill-stdout=" + result.stdout + b"\n")
            diagnostics.extend(b"taskkill-stderr=" + result.stderr + b"\n")
            if result.returncode != 0:
                diagnostics.extend(
                    b"taskkill-returncode=" + str(result.returncode).encode("ascii") + b"\n"
                )
                diagnostics.extend(_kill_process(process))
        except OSError as error:
            diagnostics.extend(
                b"taskkill-error=" + repr(error).encode("utf-8", errors="replace") + b"\n"
            )
            diagnostics.extend(_kill_process(process))
        return bytes(diagnostics)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        diagnostics.extend(
            b"killpg-error=" + repr(error).encode("utf-8", errors="replace") + b"\n"
        )
        diagnostics.extend(_kill_process(process))
    return bytes(diagnostics)


def _https_endpoint(value: str | None, name: str) -> str:
    if not isinstance(value, str) or not 12 <= len(value) <= 512:
        raise HostedAdapterError(f"{name.upper()}_INVALID")
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise HostedAdapterError(f"{name.upper()}_INVALID") from error
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or any(character.isspace() for character in value)
    ):
        raise HostedAdapterError(f"{name.upper()}_INVALID")
    return value


_SERVICE_PID = re.compile(r"^[1-9][0-9]{0,9}$")


class HostedServiceProcessController:
    """Common bounded process-loss lifecycle for hosted desktop adapters.

    Platform adapters provide only the OS command vectors for terminating,
    probing, launching, and checking readiness. The deadline accounting,
    PID-file handling, and complete command-runner diagnostics stay shared so
    every hosted desktop lane has the same failure and cleanup semantics.
    """

    def __init__(
        self,
        *,
        pid: int,
        binary: Path,
        pid_file: Path | None,
        runner: CommandRunner,
        raw_directory: Path,
    ) -> None:
        if pid <= 0 or not _SERVICE_PID.fullmatch(str(pid)):
            raise HostedAdapterError("SERVICE_PID_INVALID")
        if not binary.is_file() or binary.is_symlink():
            raise HostedAdapterError("SERVICE_BINARY_UNAVAILABLE")
        if pid_file is not None and not pid_file.is_absolute():
            raise HostedAdapterError("SERVICE_PATH_INVALID")
        if not raw_directory.is_absolute():
            raise HostedAdapterError("SERVICE_EVIDENCE_PATH_INVALID")
        raw_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(raw_directory, 0o700)
        self.pid = pid
        self.binary = binary
        self.pid_file = pid_file
        self.runner = runner
        self.raw_directory = raw_directory
        self._restart_number = 0

    @staticmethod
    def _remaining(deadline: float, failure: str) -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise ScenarioExecutionError(failure)
        return value

    def _probe(
        self,
        command: Sequence[str],
        timeout: float,
        failure: str,
    ) -> CommandResult:
        try:
            result = self.runner.run(command, timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        if result.timed_out:
            raise ScenarioExecutionError(failure)
        return result

    def _checked(
        self,
        command: Sequence[str],
        timeout: float,
        failure: str,
    ) -> CommandResult:
        result = self._probe(command, timeout, failure)
        if result.returncode != 0:
            raise ScenarioExecutionError(failure)
        return result

    def _write_pid(self, pid: int) -> None:
        if self.pid_file is None:
            return
        if _SERVICE_PID.fullmatch(str(pid)) is None:
            raise ScenarioExecutionError("SERVICE_RESTART_PID_INVALID")
        self.pid_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.pid_file.with_name(f".{self.pid_file.name}.tmp")
        temporary.write_text(f"{pid}\n", encoding="ascii")
        temporary.chmod(0o600)
        temporary.replace(self.pid_file)
        self.pid_file.chmod(0o600)

    def _wait_dead(self, deadline: float) -> None:
        while time.monotonic() < deadline:
            if not self._alive(self._remaining(deadline, "SERVICE_LOSS_TIMEOUT")):
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise ScenarioExecutionError("SERVICE_DID_NOT_EXIT")

    def restart_after_loss(self, timeout: float) -> None:
        """Kill the recorded candidate and restart that exact binary."""
        if timeout <= 0:
            raise ScenarioExecutionError("PROCESS_LOSS_TIMEOUT")
        deadline = time.monotonic() + timeout
        self._terminate(self._remaining(deadline, "SERVICE_KILL_FAILED"))
        self._wait_dead(deadline)
        self._start(self._remaining(deadline, "SERVICE_RESTART_TIMEOUT"))

    def _alive(self, timeout: float) -> bool:
        raise NotImplementedError

    def _terminate(self, timeout: float) -> None:
        raise NotImplementedError

    def _start(self, timeout: float) -> None:
        raise NotImplementedError


def _owner_only_profile(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise HostedAdapterError("PROFILE_UNAVAILABLE") from error
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise HostedAdapterError("PROFILE_NOT_OWNER_ONLY")
    # POSIX jobs prove mode 600 here. Windows jobs use an ACL-hardened
    # ephemeral directory because chmod mode bits are not an ACL boundary.
    if os.name != "nt" and info.st_mode & 0o077:
        raise HostedAdapterError("PROFILE_NOT_OWNER_ONLY")


def _executable_file(path: Path, code: str) -> None:
    if not isinstance(path, Path):
        raise HostedAdapterError(code)
    try:
        info = path.lstat()
    except OSError as error:
        raise HostedAdapterError(code) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or not os.access(path, os.X_OK)
    ):
        raise HostedAdapterError(code)


class HostedCLIAdapter:
    """Drive one installed DobbyVPN CLI through semantic adapter operations."""

    adapter_id = "hosted-cli"
    adapter_version = "v1"

    def __init__(
        self,
        *,
        cli: Path,
        profile: Path,
        runner: CommandRunner,
        download_url: str | None = None,
        upload_url: str | None = None,
        stability_samples: int = 3,
    ) -> None:
        if not cli.is_file() or cli.is_symlink():
            raise HostedAdapterError("CLI_UNAVAILABLE")
        _owner_only_profile(profile)
        if not 2 <= stability_samples <= 10:
            raise HostedAdapterError("INVALID_STABILITY_BOUND")
        if (download_url is None) != (upload_url is None):
            raise HostedAdapterError("THROUGHPUT_URL_PAIR_REQUIRED")
        for url in (download_url, upload_url):
            if url is not None:
                _https_endpoint(url, "throughput_url")
        self.cli = cli
        self.profile = profile
        self.runner = runner
        self.download_url = download_url
        self.upload_url = upload_url
        self.stability_samples = stability_samples
        self._baseline_ip: str | None = None
        self._tunneled_ips: set[str] = set()

    @property
    def capabilities(self) -> frozenset[Capability]:
        result = {
            Capability.CONFIGURE,
            Capability.CONNECT,
            Capability.TUNNEL_INTERFACE,
            Capability.ROUTING_IDENTITY,
            Capability.DISCONNECT,
            Capability.RECONNECT,
            Capability.RESOURCE_CLEANUP,
        }
        if self.download_url is not None and self.upload_url is not None:
            result.add(Capability.TRAFFIC_MEASUREMENT)
            result.add(Capability.ENDURANCE)
        return frozenset(result)

    def execute(self, step: ScenarioStep) -> dict[str, object]:
        operation = step.operation
        timeout = float(step.timeout_seconds)
        if operation == "configure":
            return {"configured": self._configure(timeout)}
        if operation == "connect":
            deadline = time.monotonic() + timeout
            self._capture_baseline(self._remaining(deadline, "CONNECT_TIMEOUT"))
            self._command(("connect-profile", str(self.profile), "0"),
                          self._remaining(deadline, "CONNECT_TIMEOUT"), "CONNECT_FAILED")
            return {}
        if operation == "observe_tunnel":
            key = "second_tunnel_interface" if step.id == "second-tunnel" else "tunnel_interface"
            return {key: self._connected(timeout)}
        if operation == "observe_routing_identity":
            changed = self._routing_identity_changed(timeout)
            key = "second_routing_identity_changed" if step.id == "second-routing" else "routing_identity_changed"
            return {key: changed}
        if operation == "measure_stability":
            return {"stability_verified": self._stability(timeout)}
        if operation == "measure_throughput":
            return self._throughput(timeout)
        if operation == "measure_endurance":
            return self._endurance(timeout)
        if operation == "disconnect":
            clean = self._disconnect_clean(timeout)
            key = "final_disconnect_clean" if step.id == "final-disconnect" else "disconnect_clean"
            return {key: clean}
        if operation == "reconnect":
            return self._reconnect(timeout)
        if operation == "inspect_cleanup":
            return {"cleanup_verified": self._cleanup_verified(timeout)}
        raise ScenarioExecutionError("UNSUPPORTED_OPERATION")

    @staticmethod
    def _remaining(deadline: float, failure: str) -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise ScenarioExecutionError(failure)
        return value

    def reset(self, timeout_seconds: float = 30.0) -> None:
        """Stop a scenario's session within one total timeout window."""
        if timeout_seconds <= 0:
            raise HostedAdapterError("INVALID_RESET_TIMEOUT")
        deadline = time.monotonic() + timeout_seconds

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise HostedAdapterError("RESET_TIMEOUT")
            return value

        try:
            if self._connected(remaining()):
                self._command(("disconnect",), remaining(), "RESET_FAILED")
            if self._baseline_ip is not None and not self._cleanup_verified(remaining()):
                raise HostedAdapterError("RESET_CLEANUP_UNVERIFIED")
        finally:
            self._baseline_ip = None
            self._tunneled_ips.clear()

    def _command(self, arguments: Sequence[str], timeout: float, failure: str) -> CommandResult:
        command = (str(self.cli), *arguments)
        try:
            result = self.runner.run(command, timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        if result.timed_out:
            raise ScenarioExecutionError("COMMAND_TIMEOUT")
        if result.returncode != 0:
            raise ScenarioExecutionError(failure)
        return result

    def _configure(self, timeout: float) -> bool:
        result = self._command(("check-config", str(self.profile)), timeout, "CONFIGURE_REJECTED")
        match = re.search(r"(?:^|\s)profiles=([1-9][0-9]*)\s", result.stdout_text)
        return match is not None

    def _capture_baseline(self, timeout: float) -> None:
        self._tunneled_ips.clear()
        self._baseline_ip = self._external_ip(timeout)

    def _routing_identity_changed(self, timeout: float) -> bool:
        current = self._external_ip(timeout)
        self._tunneled_ips.add(current)
        return self._baseline_ip is not None and current != self._baseline_ip

    def _connected(self, timeout: float) -> bool:
        result = self._command(("status", "--json"), timeout, "STATUS_FAILED")
        try:
            value = json.loads(result.stdout_text)
        except (TypeError, ValueError) as error:
            raise ScenarioExecutionError("STATUS_INVALID") from error
        return isinstance(value, dict) and value.get("state") == "Connected"

    def _external_ip(self, timeout: float) -> str:
        result = self._command(("external-ip",), timeout, "EXTERNAL_IDENTITY_FAILED")
        candidate = result.stdout_text.strip()
        if "\n" in candidate or "\r" in candidate:
            raise ScenarioExecutionError("EXTERNAL_IDENTITY_INVALID")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as error:
            raise ScenarioExecutionError("EXTERNAL_IDENTITY_INVALID") from error

    def _stability(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        for index in range(self.stability_samples):
            if not self._connected(max(0.1, deadline - time.monotonic())):
                return False
            if index + 1 < self.stability_samples:
                time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
        return time.monotonic() <= deadline

    def _throughput(self, timeout: float) -> dict[str, object]:
        if self.download_url is None or self.upload_url is None:
            raise ScenarioExecutionError("THROUGHPUT_UNAVAILABLE")
        deadline = time.monotonic() + timeout
        download = self._curl_metric(self.download_url, self._remaining(deadline, "THROUGHPUT_TIMEOUT"), upload=False)
        upload = self._curl_metric(self.upload_url, self._remaining(deadline, "THROUGHPUT_TIMEOUT"), upload=True)
        return {
            "latency_ms": download[0],
            "download_mbps": download[1],
            "upload_mbps": upload[1],
        }

    def _endurance(self, timeout: float) -> dict[str, object]:
        if self.download_url is None or self.upload_url is None:
            raise CapabilityUnavailable()
        deadline = time.monotonic() + timeout
        last_metrics: dict[str, object] = {}
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if not last_metrics:
                    raise ScenarioExecutionError("ENDURANCE_NO_COMPLETE_SAMPLE")
                return {"endurance_verified": True, **last_metrics}
            # A download/upload pair needs a meaningful transfer window. Once
            # at least one complete sample exists, preserve the final partial
            # interval instead of starting a transfer pair that is guaranteed
            # to be terminated by the endurance deadline.
            if last_metrics and remaining < _MIN_ENDURANCE_SAMPLE_SECONDS:
                time.sleep(remaining)
                return {"endurance_verified": True, **last_metrics}
            if not self._connected(min(30.0, remaining)):
                raise ScenarioExecutionError("ENDURANCE_DISCONNECTED")
            if not self._routing_identity_changed(min(30.0, remaining)):
                raise ScenarioExecutionError("ENDURANCE_ROUTING_LOST")
            last_metrics = self._throughput(min(30.0, remaining))
            if time.monotonic() >= deadline:
                return {"endurance_verified": True, **last_metrics}
            time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))

    def _reconnect(self, timeout: float) -> dict[str, object]:
        """Establish and verify the next session generation within one bound.

        The scenario owns the explicit disconnect before this operation and
        the final disconnect/cleanup after its independent observations. This
        operation composes only the public connect and status commands; it
        does not hide a second disconnect or cleanup inside the observation.
        """
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise ScenarioExecutionError("RECONNECT_TIMEOUT")
            return value

        self._command(
            ("connect-profile", str(self.profile), "0"),
            remaining(),
            "RECONNECT_CONNECT_FAILED",
        )
        if not self._connected(remaining()):
            raise ScenarioExecutionError("RECONNECT_NOT_ESTABLISHED")
        return {
            "restart_verified": True,
            "reconnect_bounded": time.monotonic() <= deadline,
        }

    def _curl_metric(self, url: str, timeout: float, *, upload: bool) -> tuple[float, float]:
        if upload:
            payload = self._upload_payload()
            transfer_args = (
                "--request", "POST", "--upload-file", str(payload),
                "--write-out", "%{time_total}\t%{size_upload}",
            )
        else:
            transfer_args = (
                "--output", os.devnull,
                "--write-out", "%{time_total}\t%{size_download}",
            )
        result = self.runner.run(
            (
                "curl", "--fail", "--location", "--show-error",
                "--max-time", str(max(1, int(timeout))), *transfer_args, url,
            ),
            timeout_seconds=timeout,
        )
        if result.timed_out or result.returncode != 0:
            raise ScenarioExecutionError("THROUGHPUT_FAILED")
        try:
            seconds_text, bytes_text = result.stdout_text.strip().split("\t", 1)
            seconds = float(seconds_text)
            bytes_count = float(bytes_text)
        except (ValueError, TypeError) as error:
            raise ScenarioExecutionError("THROUGHPUT_INVALID") from error
        if seconds <= 0 or bytes_count <= 0:
            raise ScenarioExecutionError("THROUGHPUT_INVALID")
        return seconds * 1000.0, bytes_count * 8.0 / seconds / 1_000_000.0

    def _upload_payload(self) -> Path:
        raw_directory = getattr(self.runner, "raw_directory", None)
        if not isinstance(raw_directory, Path):
            raise ScenarioExecutionError("THROUGHPUT_UPLOAD_UNAVAILABLE")
        raw_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(raw_directory, 0o700)
        payload = raw_directory / "traffic-upload.bin"
        if not payload.exists():
            with payload.open("wb") as output:
                output.write(b"\0" * (1024 * 1024))
            payload.chmod(0o600)
        return payload

    def _disconnect_clean(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise ScenarioExecutionError("DISCONNECT_TIMEOUT")
            return value

        self._command(("disconnect",), remaining(), "DISCONNECT_FAILED")
        return self._cleanup_verified(remaining())

    def _cleanup_verified(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise ScenarioExecutionError("CLEANUP_TIMEOUT")
            return value

        result = self._command(("status", "--json"), remaining(), "CLEANUP_STATUS_FAILED")
        try:
            value = json.loads(result.stdout_text)
        except (TypeError, ValueError) as error:
            raise ScenarioExecutionError("CLEANUP_STATUS_INVALID") from error
        if not isinstance(value, dict) or value.get("state") != "Disconnected":
            return False
        if self._baseline_ip is None or not self._tunneled_ips:
            return False
        return self._external_ip(remaining()) not in self._tunneled_ips


__all__ = [
    "CommandResult",
    "HostedAdapterError",
    "HostedCLIAdapter",
    "HostedServiceProcessController",
    "SubprocessRunner",
]
