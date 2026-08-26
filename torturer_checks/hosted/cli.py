"""A narrow, secret-safe adapter around DobbyVPN's public CLI.

The adapter never interprets a product result as a canonical pass. It executes
validated command vectors, converts independently observed facts to the small
observation vocabulary, and leaves all assertions/outcomes to Torturer's
canonical engine. Raw command bytes are retained in a private runner-local
folder for the duration of a trusted job; only canonical results are emitted.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
import time
from typing import Protocol, Sequence
from urllib.parse import urlparse
import uuid

from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import CapabilityUnavailable, ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep


_MIN_ENDURANCE_SAMPLE_SECONDS = 5.0
_DEFAULT_CLEANUP_RESERVE_SECONDS = 5.0
_MIN_PROCESS_CLEANUP_SECONDS = 0.01
_PROCESS_REAP_RESERVE_SECONDS = 0.05


def _opaque_evidence_id() -> str:
    """Return a schema-safe opaque id with no ordinal or filename meaning."""

    return "e" + uuid.uuid4().hex[:31]


def _remaining_until(deadline: float, *, cap: float | None = None) -> float:
    """Return time left without manufacturing a post-deadline minimum."""

    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, max(0.0, cap))


def _current_uid() -> int | None:
    """Return the POSIX owner id when the host exposes one."""

    getter = getattr(os, "getuid", None)
    return int(getter()) if getter is not None else None


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


def _ensure_owner_only_directory(path: Path) -> None:
    """Create and validate a private evidence directory without following links.

    Evidence must be private at the directory boundary.  Existing ancestors
    are inspected with ``lstat`` so a user-controlled symlink or non-directory
    cannot be silently followed by ``mkdir(parents=True)``.  A sticky system
    directory such as ``/tmp`` is an acceptable *outer* parent; the evidence
    directory itself and any user-owned parent must still be owner-only.
    """

    if not path.is_absolute():
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
            if cursor == cursor.parent:
                raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
            cursor = cursor.parent
            continue
        except OSError as error:
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE") from error
        if cursor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
        break

    current_uid = _current_uid()
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        try:
            info = directory.lstat()
        except OSError as error:
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE") from error
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
        if current_uid is not None and info.st_uid != current_uid:
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
        os.chmod(directory, 0o700)

    try:
        info = path.lstat()
        parent_info = path.parent.lstat()
    except OSError as error:
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or current_uid is not None and info.st_uid != current_uid
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode):
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
    parent_mode = stat.S_IMODE(parent_info.st_mode)
    parent_is_sticky = bool(parent_mode & stat.S_ISVTX)
    if current_uid is not None and parent_info.st_uid != current_uid and not parent_is_sticky:
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
    if parent_mode & 0o077 and not parent_is_sticky:
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
    os.chmod(path, 0o700)


class SubprocessRunner:
    """Execute argument vectors and retain complete output in a private folder."""

    def __init__(
        self,
        raw_directory: Path,
        *,
        cleanup_reserve_seconds: float = _DEFAULT_CLEANUP_RESERVE_SECONDS,
    ) -> None:
        if cleanup_reserve_seconds <= 0:
            raise HostedAdapterError("INVALID_CLEANUP_RESERVE")
        self.raw_directory = raw_directory
        _ensure_owner_only_directory(self.raw_directory)
        self.cleanup_reserve_seconds = float(cleanup_reserve_seconds)
        self._sequence = 0
        self._evidence: list[dict[str, object]] = []

    def run(self, command: Sequence[str], *, timeout_seconds: float) -> CommandResult:
        if timeout_seconds <= 0 or any(not isinstance(item, str) or not item for item in command):
            raise HostedAdapterError("INVALID_COMMAND")
        argv = tuple(command)
        self._sequence += 1
        started = time.monotonic()
        # The supplied command timeout is the complete lane budget for this
        # invocation.  Reserve a bounded tail for tree termination, output
        # draining, and proof; a timeout must never start an unbounded second
        # wait after the functional deadline has expired.
        cleanup_reserve = min(
            self.cleanup_reserve_seconds,
            max(_MIN_PROCESS_CLEANUP_SECONDS, timeout_seconds / 2.0),
        )
        deadline = started + timeout_seconds
        work_timeout = _remaining_until(
            deadline,
            cap=max(0.0, timeout_seconds - cleanup_reserve),
        )
        try:
            process = subprocess.Popen(
                list(argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **_process_group_kwargs(),
            )
            snapshot_provider = _ProcessSnapshotProvider()
            monitor = _ProcessTreeMonitor(process.pid, snapshot_provider)
            monitor.start()
            stdout, stderr = process.communicate(timeout=work_timeout)
            monitor_stopped = monitor.stop(
                _remaining_until(deadline, cap=cleanup_reserve)
            )
            # The macOS census is cached for monitor sampling.  Force a fresh
            # snapshot after the leader has exited before proving its tree is
            # gone; otherwise a just-exited leader can look alive briefly.
            snapshot_provider.invalidate()
            tree_diagnostics, tree_status = _finish_process_tree(
                process,
                monitor.identities,
                _remaining_until(deadline),
                monitor_complete=monitor_stopped,
                snapshot_provider=snapshot_provider,
            )
            tree_diagnostics += snapshot_provider.diagnostics
            result = CommandResult(argv, process.returncode, stdout, stderr)
            self._retain(result, time.monotonic() - started, tree_diagnostics)
            if time.monotonic() > deadline:
                self._evidence[-1]["deadline_exceeded"] = True
                raise HostedAdapterError("COMMAND_DEADLINE_EXCEEDED")
            if tree_status != "gone":
                raise HostedAdapterError("PROCESS_TREE_UNPROVEN")
            return result
        except subprocess.TimeoutExpired as error:
            partial_stdout = _output_bytes(error.stdout)
            partial_stderr = _output_bytes(error.stderr)
            cleanup_deadline = deadline
            # Every timeout cleanup phase shares one absolute deadline.  Keep
            # an explicit tail exclusively for waitpid()/Popen reaping; a
            # tree census or pipe drain must not consume the only interval in
            # which the leader can be reaped without a ResourceWarning.
            reap_reserve = min(_PROCESS_REAP_RESERVE_SECONDS, cleanup_reserve)
            cleanup_work_deadline = max(
                time.monotonic(), cleanup_deadline - reap_reserve,
            )
            monitor_stopped = monitor.stop(
                _remaining_until(cleanup_work_deadline, cap=cleanup_reserve)
            )
            # Leave a small, explicit tail for reaping the Popen leader.  A
            # process census can reach its deadline while the leader has
            # already exited but has not yet been waitpid(2)-reaped; giving
            # the tree killer the entire reserve would then leak a live
            # Popen object and its final diagnostic warning.
            tree_cleanup_timeout = _remaining_until(cleanup_work_deadline)
            kill_diagnostics = _kill_process_tree(
                process,
                tree_cleanup_timeout,
                identities=monitor.identities,
                snapshot_provider=snapshot_provider,
            )
            kill_diagnostics += snapshot_provider.diagnostics
            if not monitor_stopped:
                kill_diagnostics += b"PROCESS_TREE_MONITOR_STOP_TIMEOUT=1\n"
                kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=tree-monitor\n"
            if b"PROCESS_TREE_STATUS=gone" not in kill_diagnostics:
                kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=process-tree\n"
            try:
                recovered_stdout, recovered_stderr = process.communicate(
                    timeout=_remaining_until(cleanup_work_deadline)
                )
            except subprocess.TimeoutExpired as recovery_error:
                kill_diagnostics += b"OUTPUT_DRAIN_TIMEOUT=1\n"
                kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=output-drain\n"
                kill_diagnostics += _kill_process(process)
                recovered_stdout = _output_bytes(recovery_error.stdout)
                recovered_stderr = _output_bytes(recovery_error.stderr)
                reaped, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                    process, _remaining_until(cleanup_deadline, cap=reap_reserve)
                )
                recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                kill_diagnostics += reap_notes
                if not reaped:
                    kill_diagnostics += b"PROCESS_REAP_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
                else:
                    kill_diagnostics += b"PROCESS_REAP_STATUS=gone\n"
                final_status = _tree_status(
                    process.pid,
                    _tracked_processes(process.pid, snapshot_provider),
                    snapshot_provider,
                )
                kill_diagnostics += (
                    b"PROCESS_TREE_FINAL_STATUS="
                    + final_status.encode("ascii")
                    + b"\n"
                )
                if final_status != "gone":
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=final-tree\n"
            except OSError as recovery_error:
                kill_diagnostics += (
                    b"OUTPUT_DRAIN_ERROR="
                    + repr(recovery_error).encode("utf-8", errors="replace")
                    + b"\n"
                )
                recovered_stdout = b""
                recovered_stderr = b""
                reaped, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                    process, _remaining_until(cleanup_deadline, cap=reap_reserve)
                )
                recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                kill_diagnostics += reap_notes
                if not reaped:
                    kill_diagnostics += b"PROCESS_REAP_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
            # ``communicate`` normally reaps the leader, but a zero-length
            # cleanup tail (or a race with a just-exiting leader) can leave a
            # Popen object unreaped even after the process census says the
            # tree is gone.  Close that gap with one final bounded reap.  A
            # failed reap is evidence-incomplete; never turn it into an
            # unbounded wait or silently let the Popen destructor report it.
            if process.poll() is None:
                kill_diagnostics += _kill_process(process)
                reaped, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                    process, _remaining_until(cleanup_deadline, cap=reap_reserve)
                )
                recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                kill_diagnostics += reap_notes
                if not reaped:
                    kill_diagnostics += b"PROCESS_REAP_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
                else:
                    kill_diagnostics += b"PROCESS_REAP_STATUS=gone\n"
            stdout = _merge_output(partial_stdout, recovered_stdout)
            stderr = _merge_output(partial_stderr, recovered_stderr)
            result = CommandResult(argv, 124, stdout, stderr, timed_out=True)
            if time.monotonic() > deadline:
                kill_diagnostics += b"COMMAND_DEADLINE_EXCEEDED=1\n"
            self._retain(result, time.monotonic() - started, kill_diagnostics)
            if time.monotonic() > deadline:
                self._evidence[-1]["deadline_exceeded"] = True
            raise HostedAdapterError("COMMAND_TIMEOUT")
        except OSError as error:
            self._retain_exception(argv, error, time.monotonic() - started)
            raise HostedAdapterError("COMMAND_UNAVAILABLE") from error
        self._retain(result, time.monotonic() - started, b"PROCESS_TREE_STATUS=gone\n")
        return result

    def run_detached(self, command: Sequence[str], *, timeout_seconds: float) -> CommandResult:
        """Run a short launcher while intentionally retaining its detached child.

        The ordinary runner proves that the entire child tree disappears when
        a command completes.  A service restart is the one deliberate
        exception: the launcher must exit while the exact service child stays
        alive for the adapter to probe.  Keep the leader bounded and retain
        its complete output, but do not apply ordinary completion tree cleanup
        to the service it just launched.
        """

        if timeout_seconds <= 0 or any(not isinstance(item, str) or not item for item in command):
            raise HostedAdapterError("INVALID_COMMAND")
        argv = tuple(command)
        self._sequence += 1
        started = time.monotonic()
        deadline = started + timeout_seconds
        try:
            process = subprocess.Popen(
                list(argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **_process_group_kwargs(),
            )
            try:
                stdout, stderr = process.communicate(timeout=_remaining_until(deadline))
            except subprocess.TimeoutExpired as error:
                partial_stdout = _output_bytes(error.stdout)
                partial_stderr = _output_bytes(error.stderr)
                diagnostics = bytearray(b"DETACHED_LAUNCH_TIMEOUT=1\n")
                diagnostics.extend(
                    _kill_process_tree(process, _remaining_until(deadline))
                )
                try:
                    recovered_stdout, recovered_stderr = process.communicate(
                        timeout=_remaining_until(deadline)
                    )
                except subprocess.TimeoutExpired as recovery_error:
                    diagnostics.extend(b"DETACHED_LAUNCH_OUTPUT_DRAIN_TIMEOUT=1\n")
                    recovered_stdout = _output_bytes(recovery_error.stdout)
                    recovered_stderr = _output_bytes(recovery_error.stderr)
                    _kill_process(process)
                    reaped, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                        process, _remaining_until(deadline)
                    )
                    recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                    recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                    diagnostics.extend(reap_notes)
                    if not reaped:
                        diagnostics.extend(b"DETACHED_LAUNCH_REAP_TIMEOUT=1\n")
                stdout = _merge_output(partial_stdout, recovered_stdout)
                stderr = _merge_output(partial_stderr, recovered_stderr)
                result = CommandResult(argv, 124, stdout, stderr, timed_out=True)
                self._retain(result, time.monotonic() - started, bytes(diagnostics))
                raise HostedAdapterError("COMMAND_TIMEOUT")
            result = CommandResult(argv, process.returncode, stdout, stderr)
            self._retain(
                result,
                time.monotonic() - started,
                b"DETACHED_LAUNCH_LEADER_STATUS=gone\n",
            )
            if time.monotonic() > deadline:
                self._evidence[-1]["deadline_exceeded"] = True
                raise HostedAdapterError("COMMAND_DEADLINE_EXCEEDED")
            return result
        except OSError as error:
            self._retain_exception(argv, error, time.monotonic() - started)
            raise HostedAdapterError("COMMAND_UNAVAILABLE") from error

    def safe_evidence(self) -> tuple[dict[str, object], ...]:
        """Return diagnostics metadata without private filenames or payloads."""
        return tuple(
            {key: value for key, value in item.items() if key != "evidence_file"}
            for item in self._evidence
        )

    def retain_external_evidence(self, path: Path, *, evidence_kind: str) -> None:
        """Publish metadata for a completed service-owned raw evidence file."""

        evidence_bytes, evidence_sha256 = _evidence_metadata(path)
        self._evidence.append({
            "sequence": self._sequence,
            "evidence_id": _opaque_evidence_id(),
            "evidence_file": path.name,
            "evidence_kind": evidence_kind,
            "evidence_bytes": evidence_bytes,
            "evidence_sha256": evidence_sha256,
        })

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
        evidence_bytes, evidence_sha256 = _evidence_metadata(path)
        self._evidence.append({
            "sequence": self._sequence,
            "evidence_id": _opaque_evidence_id(),
            "evidence_file": path.name,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": max(0, int(duration_seconds * 1000)),
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
            "evidence_bytes": evidence_bytes,
            "evidence_sha256": evidence_sha256,
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
        evidence_bytes, evidence_sha256 = _evidence_metadata(path)
        self._evidence.append({
            "sequence": self._sequence,
            "evidence_id": _opaque_evidence_id(),
            "evidence_file": path.name,
            "returncode": None,
            "timed_out": False,
            "duration_ms": max(0, int(duration_seconds * 1000)),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "exception": type(error).__name__,
            "evidence_bytes": evidence_bytes,
            "evidence_sha256": evidence_sha256,
        })

    def _allocate_evidence(self, label: str, suffix: str) -> tuple[Path, int]:
        """Reserve a fresh evidence file without ever replacing an old one."""

        for _ in range(100):
            path = self.raw_directory / f"{label}-{uuid.uuid4().hex}{suffix}"
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
        raise HostedAdapterError("EVIDENCE_UNAVAILABLE")


def _evidence_metadata(path: Path) -> tuple[int, str]:
    """Hash one retained raw file after validating its private inode."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        current_uid = _current_uid()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o077
            or current_uid is not None and info.st_uid != current_uid
        ):
            raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
        try:
            os.fsync(descriptor)
        except OSError as error:
            raise HostedAdapterError("EVIDENCE_FSYNC_FAILED") from error
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        return total, digest.hexdigest()
    finally:
        os.close(descriptor)


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


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    start_time: str
    process_group: int | None = None


class _ProcessTreeMonitor:
    """Continuously retain process identities before a leader can disappear."""

    def __init__(
        self,
        root_pid: int,
        snapshot_provider: _ProcessSnapshotProvider | None = None,
    ) -> None:
        self.root_pid = root_pid
        self.snapshot_provider = snapshot_provider
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._seen: dict[tuple[int, str], _ProcessIdentity] = {}
        self._thread = threading.Thread(
            target=self._run,
            name=f"dobbyvpn-process-tree-{root_pid}",
            daemon=True,
        )

    def start(self) -> None:
        self._sample()
        self._thread.start()

    def _sample(self) -> None:
        for identity in _tracked_processes(self.root_pid, self.snapshot_provider):
            with self._lock:
                self._seen[(identity.pid, identity.start_time)] = identity

    def _run(self) -> None:
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(0.005)

    def stop(self, timeout: float) -> bool:
        self._stop.set()
        self._thread.join(timeout=max(0.0, timeout))
        return not self._thread.is_alive()

    @property
    def identities(self) -> tuple[_ProcessIdentity, ...]:
        with self._lock:
            return tuple(self._seen.values())


def _proc_stat(pid: int) -> tuple[int, int, str, str] | None:
    """Read one Linux process identity without treating a vanished PID as live."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        _comm, fields = value.rsplit(") ", 1)
        columns = fields.split()
        # After the closing parenthesis: state=0, ppid=1, pgrp=2,
        # starttime=19.  The start time prevents a reused PID from being
        # mistaken for the timed-out child.
        return int(columns[1]), int(columns[2]), columns[19], columns[0]
    except (OSError, ValueError, IndexError):
        return None


def _windows_process_start_time(pid: int) -> str | None:
    """Read a Windows creation timestamp to distinguish PID reuse."""

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        try:
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                return None
            return str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
        finally:
            kernel32.CloseHandle(handle)
    except (AttributeError, OSError):
        return None


def _windows_process_snapshot() -> dict[int, tuple[int, int, str, str]] | None:
    """Enumerate Windows parent links without relying on a leader-only probe."""

    try:
        import ctypes
        from ctypes import wintypes

        class ProcessEntry(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot_handle = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        invalid = ctypes.c_void_p(-1).value
        if snapshot_handle in (None, invalid):
            return None
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(ProcessEntry)
        result: dict[int, tuple[int, int, str, str]] = {}
        try:
            first = kernel32.Process32FirstW(snapshot_handle, ctypes.byref(entry))
            while first:
                pid = int(entry.th32ProcessID)
                start_time = _windows_process_start_time(pid)
                if start_time is not None:
                    result[pid] = (int(entry.th32ParentProcessID), 0, start_time, "R")
                first = kernel32.Process32NextW(snapshot_handle, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot_handle)
        return result
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _process_snapshot() -> dict[int, tuple[int, int, str, str]] | None:
    if os.name == "nt":
        return _windows_process_snapshot()
    if os.name != "posix" or not Path("/proc").is_dir():
        return None
    snapshot: dict[int, tuple[int, int, str, str]] = {}
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        stat_value = _proc_stat(int(entry.name))
        if stat_value is not None:
            snapshot[int(entry.name)] = stat_value
    return snapshot


_MACOS_PROCESS_CENSUS_COMMAND = (
    "ps", "-axo", "pid=,ppid=,pgid=,lstart="
)
_MACOS_PROCESS_CENSUS_TIMEOUT_SECONDS = 0.25


def _parse_macos_process_snapshot(stdout: bytes) -> dict[int, tuple[int, int, str, str]]:
    """Parse a complete BSD ``ps`` census with PID/start-time identities."""

    snapshot: dict[int, tuple[int, int, str, str]] = {}
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 4 or not all(field.isdigit() for field in fields[:3]):
            continue
        pid, parent, process_group = (int(field) for field in fields[:3])
        start_time = " ".join(fields[3:])
        if pid > 0 and parent >= 0 and process_group >= 0 and start_time:
            snapshot[pid] = (parent, process_group, start_time, "R")
    return snapshot


class _ProcessSnapshotProvider:
    """Provide bounded process snapshots and retain macOS probe bytes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached_at = 0.0
        self._cached: dict[int, tuple[int, int, str, str]] | None = None
        self._has_cached = False
        self._diagnostics = bytearray()

    def invalidate(self) -> None:
        """Discard a cached census before a lifecycle proof boundary."""

        with self._lock:
            self._has_cached = False

    def __call__(self) -> dict[int, tuple[int, int, str, str]] | None:
        if os.name != "posix" or Path("/proc").is_dir():
            return _process_snapshot()
        now = time.monotonic()
        with self._lock:
            if self._has_cached and now - self._cached_at < 0.05:
                return self._cached
            stdout = b""
            stderr = b""
            returncode: int | None = None
            timed_out = False
            try:
                completed = subprocess.run(
                    _MACOS_PROCESS_CENSUS_COMMAND,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=_MACOS_PROCESS_CENSUS_TIMEOUT_SECONDS,
                )
                stdout = completed.stdout
                stderr = completed.stderr
                returncode = completed.returncode
            except subprocess.TimeoutExpired as error:
                timed_out = True
                stdout = _output_bytes(error.stdout)
                stderr = _output_bytes(error.stderr)
            except OSError as error:
                stderr = repr(error).encode("utf-8", errors="replace")
            self._diagnostics.extend(
                b"MAC_PROCESS_CENSUS_BEGIN\n"
                + b"returncode=" + str(returncode).encode("ascii")
                + b" timed_out=" + str(timed_out).encode("ascii") + b"\n"
                + b"stdout-begin\n" + stdout + b"\nstdout-end\n"
                + b"stderr-begin\n" + stderr + b"\nstderr-end\n"
                + b"MAC_PROCESS_CENSUS_END\n"
            )
            snapshot = (
                _parse_macos_process_snapshot(stdout)
                if not timed_out and returncode == 0
                else None
            )
            self._cached = snapshot
            self._cached_at = time.monotonic()
            self._has_cached = True
            return snapshot

    @property
    def diagnostics(self) -> bytes:
        with self._lock:
            return bytes(self._diagnostics)


def _tracked_processes(
    root_pid: int,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> tuple[_ProcessIdentity, ...]:
    snapshot = snapshot_provider() if snapshot_provider is not None else _process_snapshot()
    if snapshot is None:
        return ()
    children: dict[int, list[int]] = {}
    for pid, (ppid, _pgrp, _start, _state) in snapshot.items():
        children.setdefault(ppid, []).append(pid)
    pending = [root_pid]
    seen: set[int] = set()
    identities: list[_ProcessIdentity] = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        value = snapshot.get(pid)
        if value is None:
            continue
        _ppid, pgrp, start_time, _state = value
        identities.append(_ProcessIdentity(pid, str(start_time), pgrp))
        pending.extend(children.get(pid, ()))
    return tuple(identities)


def _identity_live(
    identity: _ProcessIdentity,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> bool | None:
    if os.name == "nt":
        snapshot = _process_snapshot()
        if snapshot is None:
            return None
        value = snapshot.get(identity.pid)
        if value is None:
            return False
        _ppid, _pgrp, start_time, _state = value
        if start_time != identity.start_time:
            return False
        return True
    if snapshot_provider is not None and not Path("/proc").is_dir():
        snapshot = snapshot_provider()
        if snapshot is None:
            return None
        value = snapshot.get(identity.pid)
        if value is None:
            return False
        _ppid, pgrp, start_time, state = value
        if str(start_time) != identity.start_time:
            return False
        if identity.process_group is not None and pgrp != identity.process_group:
            return False
        return state != "Z"
    value = _proc_stat(identity.pid)
    if value is None:
        return False
    _ppid, pgrp, start_time, state = value
    if str(start_time) != identity.start_time:
        return False
    if identity.process_group is not None and pgrp != identity.process_group:
        return False
    return state != "Z"


def _tree_status(
    root_pid: int,
    identities: tuple[_ProcessIdentity, ...],
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> str:
    if os.name in {"posix", "nt"}:
        snapshot = snapshot_provider() if snapshot_provider is not None else _process_snapshot()
        if snapshot is None:
            return "unknown"
        if os.name == "nt" and not identities:
            return "unknown"
        live = [_identity_live(identity, snapshot_provider) for identity in identities]
        if any(value is None for value in live):
            return "unknown"
        if any(value for value in live):
            return "alive"
        if os.name == "posix":
            # Catch a child created just after the initial recursive snapshot
            # but before the leader was terminated. Detached descendants remain
            # in the tracked identity set above; same-group late children are
            # covered here.
            if any(
                pgrp == root_pid and state != "Z"
                for _pid, (_ppid, pgrp, _start, state) in snapshot.items()
            ):
                return "alive"
        return "gone"
    return "unknown"


def _merge_process_identities(
    *groups: tuple[_ProcessIdentity, ...],
) -> tuple[_ProcessIdentity, ...]:
    merged: dict[tuple[int, str], _ProcessIdentity] = {}
    for group in groups:
        for identity in group:
            merged[(identity.pid, identity.start_time)] = identity
    return tuple(merged.values())


def _finish_process_tree(
    process: subprocess.Popen[bytes],
    observed: tuple[_ProcessIdentity, ...],
    timeout: float,
    *,
    monitor_complete: bool,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> tuple[bytes, str]:
    """Prove a normally-returned leader left no observed descendant behind."""

    deadline = time.monotonic() + max(0.0, timeout)
    if snapshot_provider is not None:
        snapshot_provider.invalidate()
    identities = _merge_process_identities(
        observed,
        _tracked_processes(process.pid, snapshot_provider),
    )
    diagnostics = bytearray(
        b"PROCESS_TREE_TRACKED="
        + b",".join(str(identity.pid).encode("ascii") for identity in identities)
        + b"\n"
    )
    initial_status = (
        _tree_status(process.pid, identities, snapshot_provider)
        if monitor_complete else "unknown"
    )
    status = initial_status
    if status != "gone":
        diagnostics.extend(
            _kill_process_tree(
                process,
                _remaining_until(deadline),
                identities=identities,
                snapshot_provider=snapshot_provider,
            )
        )
        if snapshot_provider is not None:
            snapshot_provider.invalidate()
        status = _tree_status(process.pid, identities, snapshot_provider)
    if status == "gone":
        diagnostics.extend(b"PROCESS_TREE_STATUS=gone\n")
    else:
        diagnostics.extend(
            b"PROCESS_TREE_FINAL_STATUS=" + status.encode("ascii") + b"\n"
        )
        diagnostics.extend(b"EVIDENCE_INCOMPLETE=1 reason=process-tree\n")
    if initial_status != "gone":
        diagnostics.extend(b"PROCESS_TREE_SURVIVOR_DETECTED=1\n")
        diagnostics.extend(b"EVIDENCE_INCOMPLETE=1 reason=process-tree\n")
        return bytes(diagnostics), "survivor"
    return bytes(diagnostics), status


def _wait_tree_gone(
    root_pid: int,
    identities: tuple[_ProcessIdentity, ...],
    deadline: float,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> str:
    while time.monotonic() < deadline:
        status = _tree_status(root_pid, identities, snapshot_provider)
        if status != "alive":
            return status
        time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    return _tree_status(root_pid, identities, snapshot_provider)


def _signal_tracked(
    identities: tuple[_ProcessIdentity, ...],
    signum: int,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> bytes:
    diagnostics = bytearray()
    for identity in identities:
        live = _identity_live(identity, snapshot_provider)
        if live is False:
            continue
        if live is None:
            diagnostics.extend(
                b"PROCESS_IDENTITY_UNKNOWN pid="
                + str(identity.pid).encode("ascii")
                + b"\n"
            )
            continue
        try:
            os.kill(identity.pid, signum)
        except ProcessLookupError:
            continue
        except OSError as error:
            diagnostics.extend(
                b"PROCESS_ID_SIGNAL_FAILURE pid="
                + str(identity.pid).encode("ascii")
                + b" error="
                + repr(error).encode("utf-8", errors="replace")
                + b"\n"
            )
    return bytes(diagnostics)


def _kill_process(process: subprocess.Popen[bytes]) -> bytes:
    try:
        process.kill()
    except OSError as error:
        return b"process-kill-error=" + repr(error).encode("utf-8", errors="replace") + b"\n"
    return b""


def _bounded_reap_process(
    process: subprocess.Popen[bytes], timeout: float,
) -> tuple[bool, bytes, bytes, bytes]:
    """Drain and reap a killed leader without an unbounded wait."""

    try:
        stdout, stderr = process.communicate(timeout=max(0.0, timeout))
        return True, _output_bytes(stdout), _output_bytes(stderr), b""
    except subprocess.TimeoutExpired as error:
        return (
            False,
            _output_bytes(error.stdout),
            _output_bytes(error.stderr),
            b"",
        )
    except OSError as error:
        return (
            False,
            b"",
            b"",
            b"PROCESS_REAP_ERROR="
            + repr(error).encode("utf-8", errors="replace")
            + b"\n",
        )
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
    return process.returncode is not None


def _bounded_capture(
    command: Sequence[str], timeout: float
) -> tuple[int | None, bytes, bytes, bool]:
    """Run a cleanup helper with a hard timeout and retain all available bytes."""

    started = time.monotonic()
    deadline = started + max(0.0, timeout)
    helper = subprocess.Popen(
        list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **_process_group_kwargs()
    )
    try:
        stdout, stderr = helper.communicate(
            timeout=_remaining_until(deadline)
        )
        return helper.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired as error:
        partial_stdout = _output_bytes(error.stdout)
        partial_stderr = _output_bytes(error.stderr)
        try:
            helper.kill()
        except OSError:
            pass
        try:
            stdout, stderr = helper.communicate(timeout=_remaining_until(deadline))
        except subprocess.TimeoutExpired as final_error:
            reaped, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                helper, _remaining_until(deadline)
            )
            return (
                None,
                _merge_output(
                    partial_stdout,
                    _merge_output(_output_bytes(final_error.stdout), drained_stdout),
                ),
                _merge_output(
                    partial_stderr,
                    _merge_output(_output_bytes(final_error.stderr), drained_stderr),
                ) + reap_notes,
                True,
            )
        return (
            helper.returncode,
            _merge_output(partial_stdout, stdout),
            _merge_output(partial_stderr, stderr),
            True,
        )


def _windows_pid_present(pid: int, timeout: float) -> bool | None:
    if os.name != "nt":
        return False
    try:
        code, stdout, _stderr, timed_out = _bounded_capture(
            ("tasklist.exe", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"), timeout
        )
    except OSError:
        return None
    if timed_out or code is None:
        return None
    return code == 0 and str(pid).encode("ascii") in stdout


def _kill_process_tree(
    process: subprocess.Popen[bytes],
    timeout: float = _DEFAULT_CLEANUP_RESERVE_SECONDS,
    *,
    identities: tuple[_ProcessIdentity, ...] = (),
    snapshot_provider: _ProcessSnapshotProvider | None = None,
) -> bytes:
    """Terminate, drain, and prove disappearance of the complete child tree."""

    diagnostics = bytearray()
    timeout = max(0.0, timeout)
    deadline = time.monotonic() + timeout
    if snapshot_provider is not None:
        snapshot_provider.invalidate()
    identities = _merge_process_identities(
        identities,
        _tracked_processes(process.pid, snapshot_provider),
    )
    diagnostics.extend(
        b"PROCESS_TREE_TRACKED="
        + b",".join(str(identity.pid).encode("ascii") for identity in identities)
        + b"\n"
    )
    if os.name == "nt":
        taskkill_timed_out = False
        try:
            returncode, stdout, stderr, taskkill_timed_out = _bounded_capture(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                _remaining_until(deadline),
            )
            diagnostics.extend(b"taskkill-stdout=" + stdout + b"\n")
            diagnostics.extend(b"taskkill-stderr=" + stderr + b"\n")
            if taskkill_timed_out:
                diagnostics.extend(b"TASKKILL_TIMEOUT=1\n")
            if returncode != 0:
                diagnostics.extend(
                    b"TASKKILL_RETURN_CODE="
                    + str(returncode).encode("ascii")
                    + b"\n"
                )
                diagnostics.extend(_kill_process(process))
        except OSError as error:
            diagnostics.extend(
                b"taskkill-error=" + repr(error).encode("utf-8", errors="replace") + b"\n"
            )
            diagnostics.extend(_kill_process(process))
        status = _wait_tree_gone(process.pid, identities, deadline, snapshot_provider)
        if status != "gone":
            # A detached child is no longer reachable through the leader's
            # /T traversal.  Kill each identity captured while the leader was
            # alive, with the same hard cleanup deadline, and verify again.
            for identity in identities:
                if time.monotonic() >= deadline:
                    break
                if _identity_live(identity, snapshot_provider) is not True:
                    continue
                try:
                    code, stdout, stderr, timed_out = _bounded_capture(
                        ["taskkill", "/PID", str(identity.pid), "/T", "/F"],
                        _remaining_until(deadline),
                    )
                    diagnostics.extend(
                        b"taskkill-descendant-stdout=" + stdout + b"\n"
                    )
                    diagnostics.extend(
                        b"taskkill-descendant-stderr=" + stderr + b"\n"
                    )
                    if timed_out:
                        diagnostics.extend(b"TASKKILL_DESCENDANT_TIMEOUT=1\n")
                    if code not in (0, None):
                        diagnostics.extend(
                            b"TASKKILL_DESCENDANT_RETURN_CODE="
                            + str(code).encode("ascii")
                            + b"\n"
                        )
                except OSError as error:
                    diagnostics.extend(
                        b"taskkill-descendant-error="
                        + repr(error).encode("utf-8", errors="replace")
                        + b"\n"
                    )
            status = _wait_tree_gone(process.pid, identities, deadline, snapshot_provider)
        if status != "gone":
            diagnostics.extend(b"PROCESS_TREE_KILL_FAILURE=1\n")
            diagnostics.extend(b"PROCESS_TREE_SURVIVORS=1\n")
        else:
            diagnostics.extend(b"PROCESS_TREE_STATUS=gone\n")
        return bytes(diagnostics)
    diagnostics.extend(_signal_tracked(identities, signal.SIGTERM, snapshot_provider))
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        diagnostics.extend(b"PROCESS_GROUP_TERM=gone\n")
    except OSError as error:
        diagnostics.extend(
            b"PROCESS_GROUP_TERM_FAILURE="
            + repr(error).encode("utf-8", errors="replace")
            + b"\n"
        )
    status = _wait_tree_gone(
        process.pid,
        identities,
        min(deadline, time.monotonic() + max(0.0, timeout / 3.0)),
        snapshot_provider,
    )
    if status == "alive":
        diagnostics.extend(_signal_tracked(identities, signal.SIGKILL, snapshot_provider))
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            diagnostics.extend(b"PROCESS_GROUP_KILL=gone\n")
        except OSError as error:
            diagnostics.extend(
                b"PROCESS_GROUP_KILL_FAILURE="
                + repr(error).encode("utf-8", errors="replace")
                + b"\n"
            )
        if snapshot_provider is not None:
            snapshot_provider.invalidate()
        status = _wait_tree_gone(process.pid, identities, deadline, snapshot_provider)
    if status != "gone":
        diagnostics.extend(b"PROCESS_TREE_SURVIVORS=1\n")
        if status == "unknown":
            diagnostics.extend(b"PROCESS_TREE_STATUS=unknown\n")
        else:
            diagnostics.extend(b"PROCESS_TREE_KILL_FAILURE=1\n")
    else:
        diagnostics.extend(b"PROCESS_TREE_STATUS=gone\n")
    return bytes(diagnostics)


def _allocate_owner_only_path(directory: Path, stem: str, suffix: str) -> Path:
    """Reserve a private path with O_EXCL; never reuse an old evidence file."""

    try:
        info = directory.lstat()
    except OSError as error:
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE") from error
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or _current_uid() is not None and info.st_uid != _current_uid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise HostedAdapterError("EVIDENCE_PATH_UNSAFE")
    for candidate in (
        directory / f"{stem}{suffix}",
        directory / f"{stem}-{uuid.uuid4().hex}{suffix}",
    ):
        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            continue
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        return candidate
    raise HostedAdapterError("EVIDENCE_UNAVAILABLE")


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
        _ensure_owner_only_directory(raw_directory)
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
            # A download/upload pair needs a meaningful transfer window. Take
            # one complete traffic sample, then spend the rest of the bounded
            # interval observing the live session. Repeating public transfer
            # endpoints throughout the interval makes the endurance result
            # depend on an unrelated endpoint's transient rate limit rather
            # than on the VPN session remaining routed and responsive.
            if last_metrics and remaining < _MIN_ENDURANCE_SAMPLE_SECONDS:
                time.sleep(remaining)
                return {"endurance_verified": True, **last_metrics}
            try:
                if not self._connected(min(30.0, remaining)):
                    raise ScenarioExecutionError("ENDURANCE_DISCONNECTED")
            except ScenarioExecutionError as error:
                if error.reason_code == "COMMAND_TIMEOUT":
                    raise ScenarioExecutionError("ENDURANCE_STATUS_TIMEOUT") from error
                raise
            try:
                if not self._routing_identity_changed(min(30.0, remaining)):
                    raise ScenarioExecutionError("ENDURANCE_ROUTING_LOST")
            except ScenarioExecutionError as error:
                if error.reason_code == "COMMAND_TIMEOUT":
                    raise ScenarioExecutionError("ENDURANCE_IDENTITY_TIMEOUT") from error
                raise
            if not last_metrics:
                try:
                    last_metrics = self._throughput(min(30.0, remaining))
                except ScenarioExecutionError as error:
                    if error.reason_code == "COMMAND_TIMEOUT":
                        raise ScenarioExecutionError("ENDURANCE_THROUGHPUT_TIMEOUT") from error
                    raise
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
        try:
            result = self.runner.run(
                (
                    "curl", "--fail", "--location", "--show-error",
                    "--max-time", str(max(1, int(timeout))), *transfer_args, url,
                ),
                timeout_seconds=timeout,
            )
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
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
        try:
            _ensure_owner_only_directory(raw_directory)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
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
