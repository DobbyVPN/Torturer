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
import stat
import subprocess
import time
from typing import Protocol, Sequence

from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep


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

    def run(self, command: Sequence[str], *, timeout_seconds: float) -> CommandResult:
        if timeout_seconds <= 0 or any(not isinstance(item, str) or not item for item in command):
            raise HostedAdapterError("INVALID_COMMAND")
        argv = tuple(command)
        self._sequence += 1
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
            )
            result = CommandResult(argv, completed.returncode, completed.stdout, completed.stderr)
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout if isinstance(error.stdout, bytes) else (error.stdout or b"")
            stderr = error.stderr if isinstance(error.stderr, bytes) else (error.stderr or b"")
            result = CommandResult(argv, 124, stdout, stderr, timed_out=True)
            self._retain(result)
            raise HostedAdapterError("COMMAND_TIMEOUT")
        except OSError as error:
            self._retain_exception(argv, error)
            raise HostedAdapterError("COMMAND_UNAVAILABLE") from error
        self._retain(result)
        return result

    def _retain(self, result: CommandResult) -> None:
        label = f"command-{self._sequence:03d}"
        path = self.raw_directory / f"{label}.raw.log"
        with path.open("wb") as output:
            output.write(b"argv=" + " ".join(result.command).encode("utf-8", errors="replace") + b"\n")
            output.write(b"returncode=" + str(result.returncode).encode("ascii") + b"\n")
            output.write(b"stdout-begin\n" + result.stdout + b"\nstdout-end\n")
            output.write(b"stderr-begin\n" + result.stderr + b"\nstderr-end\n")
        os.chmod(path, 0o600)

    def _retain_exception(self, command: Sequence[str], error: OSError) -> None:
        label = f"command-{self._sequence:03d}"
        path = self.raw_directory / f"{label}.exception.raw.log"
        path.write_bytes(
            b"argv=" + " ".join(command).encode("utf-8", errors="replace")
            + b"\nexception=" + repr(error).encode("utf-8", errors="replace") + b"\n"
        )
        os.chmod(path, 0o600)


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
            if url is not None and (not url.startswith("https://") or any(ch.isspace() for ch in url)):
                raise HostedAdapterError("THROUGHPUT_URL_INVALID")
        self.cli = cli
        self.profile = profile
        self.runner = runner
        self.download_url = download_url
        self.upload_url = upload_url
        self.stability_samples = stability_samples
        self._baseline_ip: str | None = None

    @property
    def capabilities(self) -> frozenset[Capability]:
        result = {
            Capability.CONFIGURE,
            Capability.CONNECT,
            Capability.TUNNEL_INTERFACE,
            Capability.ROUTING_IDENTITY,
            Capability.DISCONNECT,
            Capability.RESOURCE_CLEANUP,
        }
        if self.download_url is not None and self.upload_url is not None:
            result.add(Capability.TRAFFIC_MEASUREMENT)
        return frozenset(result)

    def execute(self, step: ScenarioStep) -> dict[str, object]:
        operation = step.operation
        timeout = float(step.timeout_seconds)
        if operation == "configure":
            return {"configured": self._configure(timeout)}
        if operation == "connect":
            self._capture_baseline(timeout)
            self._command(("connect-profile", str(self.profile), "0"), timeout, "CONNECT_FAILED")
            return {}
        if operation == "observe_tunnel":
            return {"tunnel_interface": self._connected(timeout)}
        if operation == "observe_routing_identity":
            current = self._external_ip(timeout)
            return {"routing_identity_changed": self._baseline_ip is not None and current != self._baseline_ip}
        if operation == "measure_stability":
            return {"stability_verified": self._stability(timeout)}
        if operation == "measure_throughput":
            return self._throughput(timeout)
        if operation == "disconnect":
            self._command(("disconnect",), timeout, "DISCONNECT_FAILED")
            return {"disconnect_clean": True}
        if operation == "inspect_cleanup":
            return {"cleanup_verified": self._cleanup_verified(timeout)}
        raise ScenarioExecutionError("UNSUPPORTED_OPERATION")

    def reset(self, timeout_seconds: float = 30.0) -> None:
        """Stop a scenario's session before the next independent scenario."""
        try:
            if self._connected(timeout_seconds):
                self._command(("disconnect",), timeout_seconds, "RESET_FAILED")
        finally:
            self._baseline_ip = None

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
        self._baseline_ip = self._external_ip(timeout)

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
        download = self._curl_metric(self.download_url, timeout)
        upload = self._curl_metric(self.upload_url, timeout)
        return {
            "latency_ms": download[0],
            "download_mbps": download[1],
            "upload_mbps": upload[1],
        }

    def _curl_metric(self, url: str, timeout: float) -> tuple[float, float]:
        result = self.runner.run(
            (
                "curl", "--fail", "--location", "--show-error",
                "--max-time", str(max(1, int(timeout))), "--output", os.devnull,
                "--write-out", "%{time_total}\\t%{size_download}", url,
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

    def _cleanup_verified(self, timeout: float) -> bool:
        result = self._command(("status", "--json"), timeout, "CLEANUP_STATUS_FAILED")
        try:
            value = json.loads(result.stdout_text)
        except (TypeError, ValueError) as error:
            raise ScenarioExecutionError("CLEANUP_STATUS_INVALID") from error
        return isinstance(value, dict) and value.get("state") == "Disconnected"


__all__ = ["CommandResult", "HostedAdapterError", "HostedCLIAdapter", "SubprocessRunner"]
