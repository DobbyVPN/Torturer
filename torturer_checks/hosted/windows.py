"""Windows hosted adapter using DobbyVPN's public CLI."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import stat
import subprocess
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
    _ensure_owner_only_directory,
)
from torturer_checks.windows_job import (
    WindowsJobError,
    close_for as close_windows_job,
    job_for as windows_job_for,
    popen_with_windows_job,
    terminate_and_prove_empty as terminate_windows_job,
)


# This script is only for the externally supplied process.  It is deliberately
# not used to launch replacements: an external launcher would create a child
# outside the Job Object assigned to this controller.  The creation-time
# token and exact executable path are checked again in PowerShell immediately
# before the stop request, in addition to the Python-side proof.
_WINDOWS_EXTERNAL_PROCESS_STOP_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$processId = [int]$args[0]
$expectedTicks = [long]$args[1]
$expectedPath = [string]$args[2]
$process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $processId)
if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.ExecutablePath) -or $null -eq $process.CreationDate) {
    exit 1
}
if ([System.StringComparer]::OrdinalIgnoreCase.Equals($process.ExecutablePath, $expectedPath) -eq $false) {
    exit 2
}
if ($process.CreationDate.ToUniversalTime().Ticks -ne $expectedTicks) {
    exit 3
}
Stop-Process -Id $processId -Force -ErrorAction Stop
Write-Output ("external_service_stop=" + $processId)
exit 0
"""
_WINDOWS_EXTERNAL_DESCENDANT_SNAPSHOT_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$root = [int]$args[0]
$pending = New-Object System.Collections.Generic.Queue[int]
$seen = New-Object 'System.Collections.Generic.HashSet[int]'
$pending.Enqueue($root)
while ($pending.Count -gt 0) {
    $parentId = $pending.Dequeue()
    $children = Get-CimInstance Win32_Process -Filter ("ParentProcessId = {0}" -f $parentId)
    foreach ($child in @($children)) {
        $childId = [int]$child.ProcessId
        if (-not $seen.Add($childId)) { continue }
        if ($null -eq $child.CreationDate) { exit 1 }
        Write-Output ("late_tree_pid=" + $childId)
        $creationTicks = $child.CreationDate.ToUniversalTime().Ticks
        Write-Output ("late_tree_identity=" + $childId + "|" + $creationTicks)
        $pending.Enqueue($childId)
    }
}
exit 0
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

_WINDOWS_SERVICE_IDENTITY = re.compile(r"^[1-9][0-9]{0,9}\|[1-9][0-9]+$")
_MAX_WINDOWS_SERVICE_IDENTITY_BYTES = 256


def _owner_private_regular(info: os.stat_result) -> bool:
    current_uid = getattr(os, "getuid", lambda: None)()
    return (
        stat.S_ISREG(info.st_mode)
        and (current_uid is None or info.st_uid == current_uid)
        and (os.name == "nt" or not stat.S_IMODE(info.st_mode) & 0o077)
    )


def read_windows_service_identity(path: Path, *, expected_pid: int | None = None) -> str:
    """Read one exact owner-private PID/start-time identity without races."""

    if not path.is_absolute():
        raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
    try:
        _ensure_owner_only_directory(path.parent)
        if path.is_symlink():
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            descriptor_info = os.fstat(descriptor)
            path_info = path.lstat()
            if (
                not _owner_private_regular(descriptor_info)
                or not _owner_private_regular(path_info)
                or descriptor_info.st_dev != path_info.st_dev
                or descriptor_info.st_ino != path_info.st_ino
            ):
                raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                payload = stream.read(_MAX_WINDOWS_SERVICE_IDENTITY_BYTES)
                if stream.read(1):
                    raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        identity = payload.decode("ascii").strip()
    except (OSError, UnicodeDecodeError, HostedAdapterError) as error:
        raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED") from error
    if _WINDOWS_SERVICE_IDENTITY.fullmatch(identity) is None:
        raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
    if expected_pid is not None and int(identity.split("|", 1)[0]) != expected_pid:
        raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
    return identity


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
    the full set of identities and must never authorize recursive signalling.
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
                    # recursive signalling.
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


def _parse_windows_late_descendant_snapshot(stdout: str) -> tuple[tuple[str, ...], bool]:
    """Parse the fresh post-stop census rooted by ParentProcessId.

    Unlike the pre-stop tree snapshot, this probe intentionally permits an
    empty result when the original root has already exited.  Any complete
    descendant identity is a survivor; malformed or unexpected output is an
    unproven cleanup and therefore fails closed.
    """

    pids: set[int] = set()
    identity_by_pid: dict[int, str] = {}
    identities: list[str] = []
    complete = True
    for line in stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        if value.startswith("late_tree_pid="):
            raw_pid = value.split("=", 1)[1]
            if not raw_pid.isdigit() or int(raw_pid) <= 0:
                complete = False
            else:
                pid = int(raw_pid)
                if pid in pids:
                    complete = False
                pids.add(pid)
            continue
        if value.startswith("late_tree_identity="):
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
                    complete = False
                identity_by_pid[pid] = identity
                identities.append(identity)
            continue
        complete = False
    if (
        pids != set(identity_by_pid)
        or len(identities) != len(pids)
        or len(set(identities)) != len(identities)
    ):
        complete = False
    return tuple(dict.fromkeys(identities)), complete


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
    """Restart the exact Windows service binary inside a native Job."""

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
        expected_initial_identity: str | None = None,
        initialization_deadline: float | None = None,
        replacement_command: tuple[str, ...] | None = None,
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
        self._service_diagnostics_path: Path | None = None
        self._service_diagnostics: list[str] = []
        self._service_diagnostics_write_failed = False
        self._tree_proof_for_evidence = False
        self._external_tree_cleanup_proven = False
        self._initial_identity: str | None = None
        self._replacement_identity: str | None = None
        self._replacement_process: object | None = None
        self._replacement_cleanup_proven = False
        self.control_host, self.control_port = _parse_control_address(control_address)
        if expected_initial_identity is not None:
            if (
                _WINDOWS_SERVICE_IDENTITY.fullmatch(expected_initial_identity) is None
                or int(expected_initial_identity.split("|", 1)[0]) != pid
            ):
                raise HostedAdapterError("SERVICE_PID_PROBE_FAILED")
        self._expected_initial_identity = expected_initial_identity
        if replacement_command is not None:
            if (
                not replacement_command
                or any(
                    not isinstance(value, str) or not value or "\x00" in value
                    for value in replacement_command
                )
                or Path(replacement_command[0]).resolve() != binary.resolve()
            ):
                raise HostedAdapterError("SERVICE_REPLACEMENT_COMMAND_INVALID")
            self._replacement_command = replacement_command
        else:
            self._replacement_command = (str(binary), "-port", str(self.control_port))
        self._write_pid(pid)
        try:
            identity_deadline = time.monotonic() + 5.0
            if initialization_deadline is not None:
                identity_deadline = min(identity_deadline, initialization_deadline)
            observed_identity = self._verify_candidate_pid(
                self._remaining(identity_deadline, "SERVICE_PID_PROBE_FAILED")
            )
            if (
                self._expected_initial_identity is not None
                and observed_identity != self._expected_initial_identity
            ):
                raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
            self._initial_identity = observed_identity
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
        """Invoke a fixed script with an exact, injection-safe argument array.

        ``powershell.exe -Command <script> <arg>`` is not an argument-array
        interface on the Windows PowerShell versions used by hosted runners:
        trailing tokens can be parsed as additional command text instead of
        becoming the script block's ``$args``.  Keep the command line to one
        fixed wrapper and carry the script and each caller-supplied value as
        base64 data.  Base64's alphabet contains no PowerShell syntax, so
        paths, quotes, pipes, newlines, and other argument content cannot
        alter the wrapper or the fixed script.
        """
        if not isinstance(script, str) or any(
            not isinstance(argument, str) for argument in arguments
        ):
            raise TypeError("PowerShell script and arguments must be strings")
        script_payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
        argument_expressions = ", ".join(
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
            f"'{base64.b64encode(argument.encode('utf-8')).decode('ascii')}'"
            "))"
            for argument in arguments
        )
        wrapper = (
            "$__dobbyvpnScript = [Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{script_payload}')); "
            "$__dobbyvpnArguments = @("
            f"{argument_expressions}); "
            "& ([ScriptBlock]::Create($__dobbyvpnScript)) "
            "@__dobbyvpnArguments"
        )
        return (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            wrapper,
        )

    def _record_service_diagnostics(self, *diagnostics: str) -> None:
        """Retain every bounded service-operation diagnostic in owner storage."""

        values = tuple(value for value in diagnostics if value)
        if not values:
            return
        self._service_diagnostics.extend(values)
        path = self._service_diagnostics_path
        if path is None or self._service_diagnostics_write_failed:
            return
        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_APPEND
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            if nofollow:
                flags |= nofollow
            descriptor = os.open(path, flags)
            descriptor_info = os.fstat(descriptor)
            path_info = path.lstat()
            current_uid = getattr(os, "getuid", lambda: None)()
            if (
                not stat.S_ISREG(descriptor_info.st_mode)
                or not stat.S_ISREG(path_info.st_mode)
                or descriptor_info.st_dev != path_info.st_dev
                or descriptor_info.st_ino != path_info.st_ino
                or current_uid is not None and descriptor_info.st_uid != current_uid
                or os.name != "nt" and stat.S_IMODE(descriptor_info.st_mode) & 0o077
            ):
                raise OSError("diagnostics path changed")
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "ab", buffering=0) as output:
                descriptor = -1
                for value in values:
                    output.write(value.encode("utf-8", errors="replace"))
                    output.write(b"\n")
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            # The in-memory list is retained for the final failure report, but
            # an unwriteable owner-only diagnostics stream makes evidence
            # incomplete and is never treated as a successful stop.
            self._service_diagnostics_write_failed = True
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    self._service_diagnostics_write_failed = True

    @staticmethod
    def _open_service_stream(path: Path):
        """Open one already-reserved raw stream without following a link."""

        flags = os.O_WRONLY | os.O_APPEND
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        descriptor = os.open(path, flags)
        try:
            descriptor_info = os.fstat(descriptor)
            path_info = path.lstat()
            current_uid = getattr(os, "getuid", lambda: None)()
            if (
                not stat.S_ISREG(descriptor_info.st_mode)
                or not stat.S_ISREG(path_info.st_mode)
                or descriptor_info.st_dev != path_info.st_dev
                or descriptor_info.st_ino != path_info.st_ino
                or current_uid is not None and descriptor_info.st_uid != current_uid
                or os.name != "nt" and stat.S_IMODE(descriptor_info.st_mode) & 0o077
            ):
                raise OSError("service stream path changed")
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            return os.fdopen(descriptor, "ab", buffering=0)
        except BaseException:
            os.close(descriptor)
            raise

    def _terminate_uncontained_replacement(self, deadline: float) -> None:
        """Best-effort leader cleanup when Job setup itself failed.

        This path is intentionally never reported as a contained cleanup
        proof.  It exists only to avoid leaving a directly-created leader live
        when a mocked or broken native helper returns without a Job.
        """

        process = self._replacement_process
        if process is None:
            return
        try:
            process.kill()  # type: ignore[attr-defined]
            self._record_service_diagnostics("api=ProcessTerminate detail=leader-only")
        except (OSError, ProcessLookupError, AttributeError, ValueError) as error:
            self._record_service_diagnostics(
                f"api=ProcessTerminate error={type(error).__name__}"
            )
        try:
            process.wait(timeout=self._remaining(deadline, "SERVICE_REAP_FAILED"))  # type: ignore[attr-defined]
        except subprocess.TimeoutExpired:
            self._record_service_diagnostics(
                "api=ProcessWait winerror=1460 detail=leader-only"
            )
        except (OSError, AttributeError, ValueError) as error:
            self._record_service_diagnostics(
                f"api=ProcessWait error={type(error).__name__} detail=leader-only"
            )

    def _cleanup_start_failure(self, error: Exception, deadline: float) -> None:
        """Attempt owned Job cleanup before propagating a start failure."""

        reason = getattr(error, "reason_code", None)
        if not isinstance(reason, str) or not reason:
            reason = type(error).__name__
        self._record_service_diagnostics(
            f"stage=service-start detail=primary-failure reason={reason}",
        )
        if self._replacement_process is None:
            return
        try:
            self._terminate_replacement(deadline)
        except Exception as cleanup_error:
            cleanup_reason = getattr(cleanup_error, "reason_code", None)
            if not isinstance(cleanup_reason, str) or not cleanup_reason:
                cleanup_reason = type(cleanup_error).__name__
            self._record_service_diagnostics(
                "stage=service-start-cleanup "
                f"detail=cleanup-failure reason={cleanup_reason}",
            )
            try:
                error.add_note(
                    f"replacement cleanup failed: {cleanup_reason}"
                )
            except (AttributeError, TypeError):
                pass

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

    def _snapshot_external_tree(self, deadline: float) -> tuple[str, ...]:
        """Capture the initial host-owned tree with complete identities."""

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
        if self._initial_identity is None or self._initial_identity not in tree_identities:
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        return tree_identities

    def _terminate_initial_external(self, deadline: float) -> None:
        """Stop the workflow-supplied service without pretending it was in a Job."""

        tree_identities = self._snapshot_external_tree(deadline)
        # This native identity proof is adjacent to the destructive request.
        # The externally-created process cannot be retroactively attached to a
        # Job, so this is an exact PID/path/start-time check plus a bounded
        # post-stop census—not a Job ActiveProcesses proof.
        identity = self._verify_candidate_pid(
            self._remaining(deadline, "SERVICE_PID_PROBE_FAILED")
        )
        ticks = identity.split("|", 1)[1]
        self._checked(
            self._powershell(
                _WINDOWS_EXTERNAL_PROCESS_STOP_SCRIPT,
                str(self.pid),
                ticks,
                str(self.binary.resolve()),
            ),
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
        # The original snapshot cannot see a child created after the root was
        # sampled.  Re-census by ParentProcessId after stopping the root,
        # including when that root has already exited, so a late descendant
        # cannot be mistaken for a clean external-process stop.
        late = self._probe(
            self._powershell(
                _WINDOWS_EXTERNAL_DESCENDANT_SNAPSHOT_SCRIPT,
                str(self.pid),
            ),
            self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED"),
            "SERVICE_TREE_PROBE_FAILED",
        )
        if late.returncode != 0 or late.stderr.strip():
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        late_identities, late_complete = _parse_windows_late_descendant_snapshot(
            late.stdout_text
        )
        if not late_complete:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        if late_identities:
            raise ScenarioExecutionError("SERVICE_TREE_SURVIVED")
        self._external_tree_cleanup_proven = True
        self._record_service_diagnostics(
            "stage=initial-external-cleanup detail=identity-and-tree-proven",
        )

    def finalize_initial_service(
        self, timeout_seconds: float, *, deadline: float | None = None
    ) -> None:
        """Finalize the workflow-owned initial process through the exact path."""

        if timeout_seconds <= 0:
            raise ScenarioExecutionError("INVALID_FINALIZE_TIMEOUT")
        if self._restart_number != 0 or self._replacement_process is not None:
            raise ScenarioExecutionError("SERVICE_INITIAL_FINALIZE_UNAVAILABLE")
        if deadline is None:
            deadline = time.monotonic() + timeout_seconds
        elif deadline <= time.monotonic():
            raise ScenarioExecutionError("SERVICE_FINALIZE_TIMEOUT")
        self._terminate_initial_external(deadline)

    def _terminate_replacement(self, deadline: float) -> None:
        """Terminate, reap, and close the controller-owned replacement Job."""

        process = self._replacement_process
        if process is None:
            raise ScenarioExecutionError("SERVICE_JOB_UNAVAILABLE")
        if windows_job_for(process) is None:
            self._record_service_diagnostics(
                "api=JobObject winerror=6 detail=replacement-not-attached",
            )
            self._terminate_uncontained_replacement(deadline)
            raise ScenarioExecutionError("SERVICE_JOB_UNAVAILABLE")

        try:
            cleanup = terminate_windows_job(
                process,
                deadline=deadline,
                stage="hosted-windows-service",
            )
        except (OSError, ValueError, TypeError) as error:
            self._record_service_diagnostics(
                f"api=TerminateJobObject error={type(error).__name__}",
            )
            raise ScenarioExecutionError("SERVICE_JOB_PROOF_FAILED") from error
        self._record_service_diagnostics(*cleanup.diagnostics)
        if not cleanup.process_tree_proven or cleanup.active_processes != 0:
            self._record_service_diagnostics(
                "stage=hosted-windows-service detail=active-processes-unproven",
            )
            raise ScenarioExecutionError("SERVICE_JOB_PROOF_FAILED")

        # The native helper's ActiveProcesses=0 proves the Job is empty, but
        # Popen's leader still needs an independent bounded wait/reap before
        # the Job handle may be closed.
        try:
            process.wait(timeout=self._remaining(deadline, "SERVICE_REAP_FAILED"))  # type: ignore[attr-defined]
        except subprocess.TimeoutExpired as error:
            self._record_service_diagnostics(
                "api=ProcessWait winerror=1460 detail=replacement-reap",
            )
            raise ScenarioExecutionError("SERVICE_REAP_FAILED") from error
        except (OSError, AttributeError, ValueError) as error:
            self._record_service_diagnostics(
                f"api=ProcessWait error={type(error).__name__} detail=replacement-reap",
            )
            raise ScenarioExecutionError("SERVICE_REAP_FAILED") from error
        if getattr(process, "poll", lambda: None)() is None:  # type: ignore[attr-defined]
            self._record_service_diagnostics(
                "api=ProcessWait winerror=1460 detail=replacement-still-live",
            )
            raise ScenarioExecutionError("SERVICE_REAP_FAILED")

        try:
            close_diagnostics = close_windows_job(
                process,
                stage="hosted-windows-service",
                deadline=deadline,
            )
        except (OSError, ValueError, TypeError) as error:
            self._record_service_diagnostics(
                f"api=CloseHandle error={type(error).__name__} detail=replacement-job",
            )
            raise ScenarioExecutionError("SERVICE_JOB_CLOSE_FAILED") from error
        self._record_service_diagnostics(*close_diagnostics)
        if close_diagnostics or windows_job_for(process) is not None:
            self._record_service_diagnostics(
                "api=CloseHandle winerror=6 detail=replacement-job-still-attached",
            )
            raise ScenarioExecutionError("SERVICE_JOB_CLOSE_FAILED")
        if self._service_diagnostics_write_failed:
            raise ScenarioExecutionError("SERVICE_EVIDENCE_INCOMPLETE")

        self._replacement_process = None
        self._replacement_cleanup_proven = True
        self._tree_proof_for_evidence = True

    def _terminate(self, timeout: float, *, deadline: float | None = None) -> None:
        if deadline is None:
            deadline = time.monotonic() + timeout
        if self._replacement_process is not None:
            self._terminate_replacement(deadline)
            return
        self._terminate_initial_external(deadline)

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
        diagnostics_path = _allocate_owner_only_path(
            self.raw_directory,
            f"service-restart-{self._restart_number:03d}",
            ".diagnostics.raw.log",
        )
        self._service_evidence_paths = (stdout_path, stderr_path)
        self._service_diagnostics_path = diagnostics_path
        self._service_diagnostics = []
        self._service_diagnostics_write_failed = False
        self._tree_proof_for_evidence = False
        self._replacement_cleanup_proven = False
        # Invalidate the predecessor sidecar before the launcher runs.  If
        # identity proof or readiness fails, outer cleanup must not trust the
        # predecessor as the current replacement.
        self._invalidate_identity_file()

        # The replacement is the one process this controller owns.  Create it
        # directly suspended; popen_with_windows_job adds CREATE_SUSPENDED,
        # creates the kill-on-close Job, assigns the process, and resumes the
        # initial thread only after assignment.  A PowerShell launcher cannot
        # provide that ownership boundary because its child would be created
        # outside the Job.
        command = self._replacement_command
        stdout_stream = None
        stderr_stream = None
        try:
            stdout_stream = self._open_service_stream(stdout_path)
            stderr_stream = self._open_service_stream(stderr_path)
            process = popen_with_windows_job(
                subprocess.Popen,
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=stdout_stream,
                stderr=stderr_stream,
                stage="hosted-windows-service",
                deadline=deadline,
            )
        except WindowsJobError as error:
            self._record_service_diagnostics(*error.diagnostics)
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE") from error
        except (OSError, ValueError, TypeError) as error:
            self._record_service_diagnostics(
                f"api=CreateProcess error={type(error).__name__}",
            )
            raise ScenarioExecutionError("SERVICE_RESTART_UNAVAILABLE") from error
        finally:
            for stream in (stdout_stream, stderr_stream):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError) as error:
                        self._record_service_diagnostics(
                            f"api=ClosePipe error={type(error).__name__}",
                        )

        try:
            self._replacement_process = process
            if os.name == "nt" and windows_job_for(process) is None:
                self._record_service_diagnostics(
                    "api=JobObject winerror=6 detail=replacement-not-attached",
                )
                raise ScenarioExecutionError("SERVICE_JOB_UNAVAILABLE")
            try:
                process_pid = int(getattr(process, "pid"))
            except (AttributeError, TypeError, ValueError) as process_error:
                self._record_service_diagnostics(
                    f"api=ProcessId error={type(process_error).__name__}",
                )
                raise ScenarioExecutionError("SERVICE_RESTART_PID_INVALID") from process_error
            if _service_pid(str(process_pid)) is None:
                self._record_service_diagnostics("api=ProcessId error=invalid")
                raise ScenarioExecutionError("SERVICE_RESTART_PID_INVALID")
            self.pid = process_pid
            self._initial_identity = None
            self._replacement_identity = None
            # Commit the exact creation-time identity before waiting for the
            # control port.  A valid but not-yet-ready replacement remains
            # safely owned for catch-path finalization; an unvalidated PID is
            # still contained by its Job and can be safely terminated there.
            self._replacement_identity = self._verify_candidate_pid(
                self._remaining(deadline, "SERVICE_RESTART_UNAVAILABLE")
            )
            self._persist_identity(self._replacement_identity)
            # PID-file persistence is deliberately after the identity proof.
            # A failed persistence operation must still leave the exact
            # replacement owned by this controller for catch-path cleanup.
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
        except Exception as error:
            self._cleanup_start_failure(error, deadline)
            raise

    def _finalize_service_evidence(self, deadline: float | None = None) -> None:
        """Hash completed service streams without replacing or deleting them."""

        paths = self._service_evidence_paths
        if paths is None:
            return
        if not self._tree_proof_for_evidence:
            raise ScenarioExecutionError("SERVICE_TREE_UNPROVEN")
        if self._service_diagnostics_write_failed:
            raise ScenarioExecutionError("SERVICE_EVIDENCE_INCOMPLETE")
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
        diagnostics_path = self._service_diagnostics_path
        if diagnostics_path is not None:
            if deadline is not None:
                self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
            try:
                _evidence_metadata(diagnostics_path)
                retain = getattr(self.runner, "retain_external_evidence", None)
                if callable(retain):
                    retain(
                        diagnostics_path,
                        evidence_kind="windows-service-diagnostics",
                    )
            except (OSError, HostedAdapterError) as error:
                raise ScenarioExecutionError("SERVICE_EVIDENCE_INCOMPLETE") from error
            if deadline is not None:
                self._remaining(deadline, "SERVICE_RESTART_TIMEOUT")
        self._service_evidence_paths = None
        self._service_diagnostics_path = None

    def finalize_restarted_service(
        self, timeout_seconds: float, *, deadline: float | None = None
    ) -> None:
        """Clean an owned Job even when identity validation failed mid-launch."""

        if timeout_seconds <= 0:
            raise ScenarioExecutionError("INVALID_FINALIZE_TIMEOUT")
        if self._restart_number == 0:
            return
        process = self._replacement_process
        if process is not None:
            if deadline is None:
                deadline = time.monotonic() + timeout_seconds
            elif deadline <= time.monotonic():
                raise ScenarioExecutionError("SERVICE_FINALIZE_TIMEOUT")
            # Once a direct Popen has returned, its Job is the ownership
            # authority even if the subsequent path/start-time probe failed.
            # Terminating that Job is safe and is required to avoid orphaning
            # a partially validated replacement.
            if self._replacement_identity is not None:
                if self._alive(self._remaining(deadline, "SERVICE_FINALIZE_TIMEOUT")):
                    self._verify_candidate_pid(
                        self._remaining(deadline, "SERVICE_FINALIZE_TIMEOUT")
                    )
            self._terminate_replacement(deadline)
            return
        if self._replacement_cleanup_proven:
            return
        if self._replacement_identity is None:
            # No Popen/Job was retained (for example, native setup failed).
            # Without an explicit proof from the helper, leave evidence
            # unfinalized and fail closed rather than claiming cleanup.
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        super().finalize_restarted_service(timeout_seconds, deadline=deadline)

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
            expected_initial_identity = None
            if service_identity_file is not None:
                try:
                    expected_initial_identity = read_windows_service_identity(
                        service_identity_file,
                        expected_pid=service_pid,
                    )
                except ScenarioExecutionError as error:
                    raise HostedAdapterError(error.reason_code) from error
            self.service: WindowsServiceProcessController | None = WindowsServiceProcessController(
                pid=service_pid,
                binary=service_binary,
                pid_file=service_pid_file,
                identity_file=service_identity_file,
                runner=runner,
                raw_directory=raw_directory,
                control_address=control_address,
                expected_initial_identity=expected_initial_identity,
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
        now = time.monotonic()
        if deadline is None:
            deadline = now + timeout_seconds
        else:
            if deadline <= now:
                raise ScenarioExecutionError("SERVICE_FINALIZE_TIMEOUT")
            # The lane deadline is an outer bound; never let it expand the
            # finalizer's explicit timeout budget.
            deadline = min(deadline, now + timeout_seconds)
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
