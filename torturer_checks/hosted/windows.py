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
    _call_with_deadline,
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
try {
    $process = Get-Process -Id ([int]$args[0]) -ErrorAction Stop
    Write-Output ("service_probe_pid=" + $process.Id)
    exit 0
} catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
    Write-Output "service_probe_absent"
    exit 2
} catch {
    Write-Output "service_probe_error"
    exit 1
}
"""
_WINDOWS_PROCESS_IDENTITY_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f ([int]$args[0]))
if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.ExecutablePath) -or $null -eq $process.CreationDate) {
    exit 1
}
$creationTicks = $process.CreationDate.ToUniversalTime().Ticks
Write-Output ("service_identity=" + $process.ProcessId + "|" + $creationTicks)
Write-Output ("service_path=" + $process.ExecutablePath)
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


def _parse_windows_tree_snapshot(stdout: str) -> tuple[tuple[str, ...], bool]:
    """Parse a tree snapshot and report whether every record was complete.

    The compatibility parser above intentionally projects only valid identity
    lines for callers that inspect diagnostics.  Cleanup is stricter: a
    malformed or orphaned ``tree_pid`` line means the probe did not establish
    the full set of identities and must never authorize ``taskkill /T``.
    """

    pids: set[int] = set()
    identity_by_pid: dict[int, str] = {}
    identities: list[str] = []
    complete = True
    for line in stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        if value.startswith("tree_pid="):
            raw_pid = value.split("=", 1)[1]
            if not raw_pid.isdigit() or int(raw_pid) <= 0:
                complete = False
            else:
                pid = int(raw_pid)
                if pid in pids:
                    complete = False
                pids.add(pid)
            continue
        if value.startswith("tree_identity="):
            raw_identity = value.split("=", 1)[1]
            parts = raw_identity.split("|", 1)
            if (
                len(parts) != 2
                or not parts[0].isdigit()
                or not parts[1].isdigit()
                or int(parts[0]) <= 0
                or int(parts[1]) <= 0
            ):
                complete = False
            else:
                pid = int(parts[0])
                identity = f"{pid}|{int(parts[1])}"
                if pid in identity_by_pid:
                    # Duplicate identities are ambiguous even when the
                    # repeated record has the same creation time.  A
                    # conflicting record must likewise never authorize
                    # recursive taskkill.
                    complete = False
                identity_by_pid[pid] = identity
                identities.append(identity)
            continue
        # Unexpected output can be a warning or an error emitted alongside a
        # partial snapshot.  Retain it in the runner evidence but fail closed.
        complete = False
    unique = tuple(dict.fromkeys(identities))
    identity_pids = set(identity_by_pid)
    if (
        not pids
        or pids != identity_pids
        or len(identities) != len(pids)
        or len(unique) != len(identities)
    ):
        complete = False
    return unique, complete


def _parse_windows_process_identity(stdout: str, pid: int) -> tuple[str, str]:
    """Parse the native root identity without accepting partial records."""

    values: dict[str, str] = {}
    for line in stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        key, separator, field = value.partition("=")
        if (
            not separator
            or key not in {"service_identity", "service_path"}
            or key in values
        ):
            raise ValueError("malformed process identity")
        values[key] = field.strip()
    if set(values) != {"service_identity", "service_path"}:
        raise ValueError("incomplete process identity")
    identity = values["service_identity"]
    path = values["service_path"]
    parts = identity.split("|", 1)
    if (
        len(parts) != 2
        or not parts[0].isdigit()
        or not parts[1].isdigit()
        or int(parts[0]) != pid
        or int(parts[1]) <= 0
        or not path
    ):
        raise ValueError("invalid process identity")
    return f"{pid}|{int(parts[1])}", path


class WindowsServiceProcessController(HostedServiceProcessController):
    """Restart the exact Windows service binary through PowerShell."""

    def __init__(
        self,
        *,
        pid: int,
        binary: Path,
        pid_file: Path | None,
        identity_file: Path | None = None,
        runner: CommandRunner,
        raw_directory: Path,
        control_address: str,
    ) -> None:
        super().__init__(
            pid=pid,
            binary=binary,
            pid_file=pid_file,
            identity_file=identity_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        self._service_evidence_paths: tuple[Path, Path] | None = None
        self._tree_proof_for_evidence = False
        self._initial_identity: str | None = None
        self._replacement_identity: str | None = None
        self.control_host, self.control_port = _parse_control_address(control_address)
        self._write_pid(pid)
        try:
            identity_deadline = time.monotonic() + 5.0
            self._initial_identity = self._verify_candidate_pid(
                self._remaining(identity_deadline, "SERVICE_PID_PROBE_FAILED")
            )
            self._persist_identity(self._initial_identity)
        except ScenarioExecutionError as error:
            raise HostedAdapterError(error.reason_code) from error

    def _persist_identity(self, identity: str) -> None:
        if self.identity_file is None:
            return
        temporary = self.identity_file.with_name(f".{self.identity_file.name}.tmp")
        try:
            self.identity_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary.write_text(identity + "\n", encoding="ascii")
            temporary.chmod(0o600)
            temporary.replace(self.identity_file)
            self.identity_file.chmod(0o600)
        except OSError as error:
            raise ScenarioExecutionError("SERVICE_IDENTITY_PERSIST_FAILED") from error

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
        if result.returncode == 0:
            if result.stdout_text.strip() != f"service_probe_pid={self.pid}":
                raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
            return True
        if (
            result.returncode == 2
            and result.stdout_text.strip() == "service_probe_absent"
            and not result.stderr.strip()
        ):
            return False
        raise ScenarioExecutionError("SERVICE_PROBE_FAILED")

    def _candidate_process_identity(self, timeout: float) -> str:
        result = self._probe(
            self._powershell(_WINDOWS_PROCESS_IDENTITY_SCRIPT, str(self.pid)),
            timeout,
            "SERVICE_PID_PROBE_FAILED",
        )
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        try:
            identity, path = _parse_windows_process_identity(
                result.stdout_text, self.pid
            )
        except ValueError:
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        expected = str(self.binary.resolve())
        if os.path.normcase(path) != os.path.normcase(expected):
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        return identity

    def _terminate(self, timeout: float, *, deadline: float | None = None) -> None:
        if deadline is None:
            deadline = time.monotonic() + timeout
        snapshot = self._probe(
            self._powershell(_WINDOWS_PROCESS_TREE_SNAPSHOT_SCRIPT, str(self.pid)),
            self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED"),
            "SERVICE_TREE_PROBE_FAILED",
        )
        if snapshot.returncode != 0:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        tree_identities, complete = _parse_windows_tree_snapshot(snapshot.stdout_text)
        if not complete or not tree_identities:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        if not any(identity.split("|", 1)[0] == str(self.pid) for identity in tree_identities):
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        if self._replacement_identity is not None and self._replacement_identity not in tree_identities:
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        # Repeat the native identity proof immediately before the destructive
        # taskkill.  This closes the snapshot-to-signal PID-reuse window for
        # both the initial process-loss target and a replacement.
        self._verify_candidate_pid(
            self._remaining(deadline, "SERVICE_PID_PROBE_FAILED")
        )
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

    def _verify_candidate_pid(self, timeout: float) -> str:
        identity = self._candidate_process_identity(timeout)
        expected = self._replacement_identity or self._initial_identity
        if expected is not None and identity != expected:
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        return identity

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
        # Invalidate the predecessor sidecar before the launcher runs.  If
        # identity proof or readiness fails, outer cleanup must not trust the
        # predecessor as the current replacement.
        self._invalidate_identity_file()
        command = self._powershell(
            _WINDOWS_SERVICE_LAUNCH_SCRIPT,
            str(self.binary),
            str(stdout_path),
            str(stderr_path),
            str(self.control_port),
        )
        # Start-Process creates a service outside the PowerShell launcher.
        # Use the explicit detached runner when available so ordinary command
        # tree cleanup cannot terminate the replacement before its readiness
        # and exact-tree finalization checks run.
        launcher = getattr(self.runner, "run_detached", None)
        if not callable(launcher):
            launcher = self.runner.run
        try:
            result = launcher(
                command,
                timeout_seconds=min(
                    10.0, self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
                ),
            )
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        if result.returncode != 0 or result.timed_out:
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE")
        value = result.stdout_text.strip()
        if _service_pid(value) is None:
            raise ScenarioExecutionError("SERVICE_RESTART_PID_INVALID")
        self.pid = int(value)
        self._initial_identity = None
        self._replacement_identity = None
        # Commit the exact creation-time identity before waiting for the
        # control port.  A valid but not-yet-ready replacement remains safely
        # owned for catch-path finalization; an unvalidated PID is not owned.
        self._replacement_identity = self._verify_candidate_pid(
            self._remaining(deadline, "SERVICE_RESTART_UNAVAILABLE")
        )
        self._persist_identity(self._replacement_identity)
        # PID-file persistence is deliberately after the identity proof.  A
        # failed persistence operation must still leave the exact replacement
        # owned by this controller for catch-path cleanup.
        self._write_pid(self.pid)
        while time.monotonic() < deadline:
            remaining = self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
            if not self._alive(remaining):
                raise ScenarioExecutionError("SERVICE_RESTART_EXITED")
            if self._control_ready(remaining):
                self._verify_candidate_pid(
                    self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
                )
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

    def finalize_evidence(
        self, timeout_seconds: float = 5.0, *, deadline: float | None = None
    ) -> None:
        """Finalize the most recent stream pair after its process is gone."""

        if timeout_seconds <= 0:
            raise ScenarioExecutionError("INVALID_FINALIZE_TIMEOUT")
        if deadline is None:
            deadline = time.monotonic() + timeout_seconds
        elif deadline <= time.monotonic():
            raise ScenarioExecutionError("SERVICE_EVIDENCE_TIMEOUT")
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
        identity_url: str | None = None,
        download_url: str | None = None,
        upload_url: str | None = None,
        service_pid: int | None = None,
        service_binary: Path | None = None,
        service_pid_file: Path | None = None,
        service_identity_file: Path | None = None,
        service_socket: Path | None = None,
    ) -> None:
        super().__init__(
            cli=cli,
            profile=profile,
            runner=runner,
            identity_url=identity_url,
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
                identity_file=service_identity_file,
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

    def finalize(
        self, timeout_seconds: float = 30.0, *, deadline: float | None = None
    ) -> None:
        super().finalize(timeout_seconds, deadline=deadline)
        if self.service is None or self.service._restart_number == 0:
            return
        if deadline is None:
            deadline = time.monotonic() + timeout_seconds
        elif deadline <= time.monotonic():
            raise ScenarioExecutionError("SERVICE_FINALIZE_TIMEOUT")
        _call_with_deadline(
            self.service.finalize_restarted_service,
            self._remaining(deadline, "SERVICE_FINALIZE_TIMEOUT"),
            deadline,
        )
        _call_with_deadline(
            self.service.finalize_evidence,
            self._remaining(deadline, "SERVICE_FINALIZE_TIMEOUT"),
            deadline,
        )

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
        if not self._wait_for_routing_identity_changed(
            self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")
        ):
            raise ScenarioExecutionError("PROCESS_LOSS_ROUTING_NOT_RECOVERED")
        return {"process_loss_verified": True}


__all__ = ["WindowsHostedAdapter", "WindowsServiceProcessController"]
