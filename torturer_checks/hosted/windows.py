"""Windows hosted adapter using DobbyVPN's public CLI."""

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
    _allocate_owner_only_path,
    _evidence_metadata,
)


_WINDOWS_SERVICE_LAUNCH_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$binary = $args[0]
$stdout = $args[1]
$stderr = $args[2]
$port = $args[3]
foreach ($path in @($stdout, $stderr)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "diagnostic path is a reparse point"
    }
}
$process = Start-Process -FilePath $binary -ArgumentList @("-port", $port) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
$process.Id
"""
_WINDOWS_PROCESS_ALIVE_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$process = Get-Process -Id ([int]$args[0])
Write-Output ("service_probe_pid=" + $process.Id)
exit 0
"""
_WINDOWS_PROCESS_PATH_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f ([int]$args[0]))
if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
    exit 1
}
$process.ExecutablePath
"""
_WINDOWS_PROCESS_TREE_SNAPSHOT_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$root = [int]$args[0]
$pending = New-Object System.Collections.Generic.Queue[int]
$seen = New-Object 'System.Collections.Generic.HashSet[int]'
$pending.Enqueue($root)
$survivor = $false
while ($pending.Count -gt 0) {
    $processId = $pending.Dequeue()
    if (-not $seen.Add($processId)) { continue }
    $process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $processId)
    if ($null -eq $process) { continue }
    Write-Output ("tree_pid=" + $process.ProcessId)
    $creationTicks = $process.CreationDate.ToUniversalTime().Ticks
    Write-Output ("tree_identity=" + $process.ProcessId + "|" + $creationTicks)
    $children = Get-CimInstance Win32_Process -Filter ("ParentProcessId = {0}" -f $processId)
    foreach ($child in @($children)) { $pending.Enqueue([int]$child.ProcessId) }
}
exit 0
"""
_WINDOWS_PROCESS_TREE_VERIFY_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$survivor = $false
$success = $true
foreach ($value in $args) {
    $parts = $value -split '\|', 2
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
        Write-Output ("identity_invalid=" + $value)
        $success = $false
        continue
    }
    $processId = [int]$parts[0]
    $expectedTicks = [long]$parts[1]
    $process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $processId)
    if ($null -ne $process) {
        $actualTicks = $process.CreationDate.ToUniversalTime().Ticks
        if ($actualTicks -eq $expectedTicks) {
            $survivor = $true
            Write-Output ("survivor_pid=" + $process.ProcessId)
            Write-Output ("survivor_identity=" + $process.ProcessId + "|" + $actualTicks)
        } else {
            Write-Output ("identity_mismatch_pid=" + $process.ProcessId)
            Write-Output ("identity_expected=" + $process.ProcessId + "|" + $expectedTicks)
            Write-Output ("identity_observed=" + $process.ProcessId + "|" + $actualTicks)
        }
    }
}
if (-not $success) { exit 2 }
if ($survivor) { exit 1 }
exit 0
"""
_WINDOWS_PORT_READY_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$ready = Test-NetConnection -ComputerName $args[0] -Port ([int]$args[1])
Write-Output $ready
if ($ready.TcpTestSucceeded) {
    exit 0
}
exit 1
"""


def _parse_control_address(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.count(":") != 1:
        raise HostedAdapterError("SERVICE_CONTROL_ADDRESS_INVALID")
    host, port_text = value.rsplit(":", 1)
    if host.lower() not in {"127.0.0.1", "localhost"}:
        raise HostedAdapterError("SERVICE_CONTROL_ADDRESS_INVALID")
    try:
        port = int(port_text)
    except ValueError as error:
        raise HostedAdapterError("SERVICE_CONTROL_ADDRESS_INVALID") from error
    if not 1 <= port <= 65535:
        raise HostedAdapterError("SERVICE_CONTROL_ADDRESS_INVALID")
    return host, port


def _parse_windows_tree_identities(stdout: str) -> tuple[str, ...]:
    """Parse PID plus creation-time identities from the bounded tree probe.

    A PID alone is not a safe process identity: Windows can reuse it after
    the original service exits.  The PowerShell probe therefore emits a
    decimal creation-time tick value alongside each PID.  Malformed records
    are ignored here, but the caller fails closed if no complete identity (or
    the recorded root identity) remains.
    """
    identities: list[str] = []
    for line in stdout.splitlines():
        value = line.strip()
        if not value.startswith("tree_identity="):
            continue
        identity = value.split("=", 1)[1]
        parts = identity.split("|", 1)
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        if int(parts[0]) <= 0 or int(parts[1]) <= 0:
            continue
        identities.append(f"{int(parts[0])}|{int(parts[1])}")
    return tuple(dict.fromkeys(identities))


class WindowsServiceProcessController(HostedServiceProcessController):
    """Restart the exact Windows service binary through PowerShell."""

    def __init__(
        self,
        *,
        pid: int,
        binary: Path,
        pid_file: Path | None,
        runner: CommandRunner,
        raw_directory: Path,
        control_address: str,
    ) -> None:
        super().__init__(
            pid=pid,
            binary=binary,
            pid_file=pid_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        self._service_evidence_paths: tuple[Path, Path] | None = None
        self._tree_proof_for_evidence = False
        self.control_host, self.control_port = _parse_control_address(control_address)
        self._write_pid(pid)
        try:
            self._verify_candidate_pid(5.0)
        except ScenarioExecutionError as error:
            raise HostedAdapterError(error.reason_code) from error

    @staticmethod
    def _powershell(script: str, *arguments: str) -> tuple[str, ...]:
        return (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            *arguments,
        )

    def _alive(self, timeout: float) -> bool:
        result = self._probe(
            self._powershell(_WINDOWS_PROCESS_ALIVE_SCRIPT, str(self.pid)),
            timeout,
            "SERVICE_PROBE_FAILED",
        )
        return result.returncode == 0

    def _terminate(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        snapshot = self._probe(
            self._powershell(_WINDOWS_PROCESS_TREE_SNAPSHOT_SCRIPT, str(self.pid)),
            self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED"),
            "SERVICE_TREE_PROBE_FAILED",
        )
        tree_identities = _parse_windows_tree_identities(snapshot.stdout_text)
        if not tree_identities:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        if not any(identity.split("|", 1)[0] == str(self.pid) for identity in tree_identities):
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        self._checked(
            ("taskkill.exe", "/PID", str(self.pid), "/T", "/F"),
            self._remaining(deadline, "SERVICE_KILL_FAILED"),
            "SERVICE_KILL_FAILED",
        )
        tree = self._probe(
            self._powershell(_WINDOWS_PROCESS_TREE_VERIFY_SCRIPT, *tree_identities),
            self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED"),
            "SERVICE_TREE_PROBE_FAILED",
        )
        if tree.returncode != 0:
            if b"survivor_pid=" in tree.stdout:
                raise ScenarioExecutionError("SERVICE_TREE_SURVIVED")
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        self._tree_proof_for_evidence = True

    def _verify_candidate_pid(self, timeout: float) -> None:
        result = self._probe(
            self._powershell(_WINDOWS_PROCESS_PATH_SCRIPT, str(self.pid)),
            timeout,
            "SERVICE_PID_PROBE_FAILED",
        )
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        actual = result.stdout_text.strip()
        expected = str(self.binary.resolve())
        if os.path.normcase(actual) != os.path.normcase(expected):
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")

    def _control_ready(self, timeout: float) -> bool:
        result = self._probe(
            self._powershell(
                _WINDOWS_PORT_READY_SCRIPT,
                self.control_host,
                str(self.control_port),
            ),
            timeout,
            "SERVICE_CONTROL_PROBE_FAILED",
        )
        return result.returncode == 0

    def _start(self, timeout: float) -> None:
        # Establish the restart's total deadline before finalizing evidence
        # from the predecessor.  Hashing and publishing those files is part
        # of the same bounded restart operation, never an unbudgeted prefix.
        deadline = time.monotonic() + timeout
        if self._service_evidence_paths is not None:
            self._finalize_service_evidence(deadline)
        self._restart_number += 1
        stdout_path = _allocate_owner_only_path(
            self.raw_directory,
            f"service-restart-{self._restart_number:03d}",
            ".stdout.raw.log",
        )
        stderr_path = _allocate_owner_only_path(
            self.raw_directory,
            f"service-restart-{self._restart_number:03d}",
            ".stderr.raw.log",
        )
        self._service_evidence_paths = (stdout_path, stderr_path)
        self._tree_proof_for_evidence = False
        result = self._probe(
            self._powershell(
                _WINDOWS_SERVICE_LAUNCH_SCRIPT,
                str(self.binary),
                str(stdout_path),
                str(stderr_path),
                str(self.control_port),
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

    def _finalize_service_evidence(self, deadline: float | None = None) -> None:
        """Hash completed service streams without replacing or deleting them."""

        paths = self._service_evidence_paths
        if paths is None:
            return
        if not self._tree_proof_for_evidence:
            raise ScenarioExecutionError("SERVICE_TREE_UNPROVEN")
        for path, kind in zip(paths, ("windows-service-stdout", "windows-service-stderr")):
            if deadline is not None:
                self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
            try:
                _evidence_metadata(path)
                retain = getattr(self.runner, "retain_external_evidence", None)
                if callable(retain):
                    retain(path, evidence_kind=kind)
            except (OSError, HostedAdapterError) as error:
                raise ScenarioExecutionError("SERVICE_EVIDENCE_INCOMPLETE") from error
            if deadline is not None:
                self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
        self._service_evidence_paths = None

    def finalize_evidence(self) -> None:
        """Finalize the most recent stream pair after its process is gone."""

        deadline = time.monotonic() + 5.0
        if self._alive(self._remaining(deadline, "SERVICE_EVIDENCE_TIMEOUT")):
            raise ScenarioExecutionError("SERVICE_EVIDENCE_PROCESS_LIVE")
        self._finalize_service_evidence(deadline)


def _service_pid(value: str) -> int | None:
    if value.isdigit() and 0 < int(value) <= 9_999_999_999:
        return int(value)
    return None


class WindowsHostedAdapter(HostedCLIAdapter):
    """Drive the Windows CLI and an optional exact service process seam."""

    adapter_id = "hosted-windows-cli"
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
            control_address = str(
                service_socket
                or os.environ.get("DOBBYVPN_CONTROL_ADDRESS", "127.0.0.1:50051")
            )
            self.service: WindowsServiceProcessController | None = WindowsServiceProcessController(
                pid=service_pid,
                binary=service_binary,
                pid_file=service_pid_file,
                runner=runner,
                raw_directory=raw_directory,
                control_address=control_address,
            )
        else:
            self.service = None

    @property
    def capabilities(self) -> frozenset[Capability]:
        result = set(super().capabilities)
        if self.service is not None:
            result.add(Capability.PROCESS_LOSS)
        return frozenset(result)

    @property
    def capability_unavailable_reasons(self) -> dict[Capability, str]:
        reasons = dict(super().capability_unavailable_reasons)
        reasons[Capability.NETWORK_TRANSITION] = "HOSTED_WINDOWS_UPLINK_TOGGLE_UNSUPPORTED"
        return reasons

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


__all__ = ["WindowsHostedAdapter", "WindowsServiceProcessController"]
