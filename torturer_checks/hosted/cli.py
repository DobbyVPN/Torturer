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
import select
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
_PROCESS_TREE_PROOF_RESERVE_SECONDS = 0.05
_PROCESS_TREE_MONITOR_STOP_RESERVE_SECONDS = 0.01


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

    def run(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        if input_bytes is not None and not isinstance(input_bytes, bytes):
            raise HostedAdapterError("INVALID_INPUT_BYTES")
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
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.PIPE if input_bytes is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **_process_group_kwargs(),
            )
            snapshot_provider = _ProcessSnapshotProvider()
            monitor = _ProcessTreeMonitor(
                process.pid,
                snapshot_provider,
                deadline=deadline,
                process=process,
            )
            monitor.start()
            if input_bytes is None:
                # Preserve the ordinary runner's minimal communicate call;
                # synthetic process doubles and existing callers rely on it.
                stdout, stderr = process.communicate(timeout=work_timeout)
            else:
                stdout, stderr = process.communicate(
                    input=input_bytes,
                    timeout=work_timeout,
                )
            monitor_stopped = monitor.stop(
                _remaining_until(deadline, cap=cleanup_reserve)
            )
            # The macOS census is cached for monitor sampling.  Force a fresh
            # snapshot after the leader has exited before proving its tree is
            # gone; otherwise a just-exited leader can look alive briefly.
            snapshot_provider.invalidate(deadline=deadline)
            tree_diagnostics, tree_status = _finish_process_tree(
                process,
                monitor.identities,
                _remaining_until(deadline),
                monitor_complete=monitor_stopped,
                snapshot_provider=snapshot_provider,
                deadline=deadline,
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
            proof_reserve = min(
                _PROCESS_TREE_PROOF_RESERVE_SECONDS,
                max(0.0, cleanup_reserve - reap_reserve),
            )
            cleanup_work_deadline = min(
                cleanup_deadline,
                cleanup_deadline - reap_reserve - proof_reserve,
            )
            proof_deadline = min(cleanup_deadline, cleanup_work_deadline + proof_reserve)
            monitor_stopped = monitor.stop(
                _remaining_until(
                    cleanup_work_deadline,
                    cap=min(
                        cleanup_reserve,
                        _PROCESS_TREE_MONITOR_STOP_RESERVE_SECONDS,
                    ),
                )
            )
            # Leave a small, explicit tail for reaping the Popen leader.  A
            # process census can reach its deadline while the leader has
            # already exited but has not yet been waitpid(2)-reaped; giving
            # the tree killer the entire reserve would then leak a live
            # Popen object and its final diagnostic warning.
            kill_diagnostics = _kill_process_tree(
                process,
                identities=monitor.identities,
                snapshot_provider=snapshot_provider,
                deadline=cleanup_work_deadline,
                force_immediately=True,
            )
            kill_diagnostics += snapshot_provider.diagnostics
            if not monitor_stopped:
                kill_diagnostics += b"PROCESS_TREE_MONITOR_STOP_TIMEOUT=1\n"
                # The initial short join must not consume the tree-cleanup
                # budget, but an in-flight census may discover a detached
                # identity only after the leader has been killed.  Give that
                # already-stopped monitor the separate proof interval to
                # finish, then signal any identities it learned before proof.
                monitor_stopped = monitor.stop(_remaining_until(proof_deadline))
                if not monitor_stopped:
                    kill_diagnostics += b"PROCESS_TREE_MONITOR_FINAL_STOP_TIMEOUT=1\n"
                late_identities = _merge_process_identities(
                    monitor.identities,
                    getattr(process, "_torturer_tree_identities", ()),
                )
                if late_identities:
                    kill_diagnostics += _signal_tracked(
                        late_identities,
                        signal.SIGKILL,
                        snapshot_provider,
                        deadline=proof_deadline,
                    )
            tree_identities = _merge_process_identities(
                monitor.identities,
                getattr(process, "_torturer_tree_identities", ()),
            )
            # Prove the terminated tree before consuming the separate
            # waitpid/output-drain tail.  This uses the same caller deadline,
            # with no grace interval, but guarantees that a slow full census
            # cannot leave no time for the only cleanup proof.
            pre_reap_status = _tree_status(
                process.pid,
                tree_identities,
                snapshot_provider,
                deadline=proof_deadline,
                allow_direct_fallback=True,
                census_complete=getattr(
                    process, "_torturer_tree_census_observed", False
                ),
            )
            try:
                recovered_stdout, recovered_stderr = process.communicate(
                    timeout=_remaining_until(proof_deadline)
                )
            except subprocess.TimeoutExpired as recovery_error:
                kill_diagnostics += _kill_process(process)
                recovered_stdout = _output_bytes(recovery_error.stdout)
                recovered_stderr = _output_bytes(recovery_error.stderr)
                reaped, output_complete, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                    process,
                    deadline=min(
                        cleanup_deadline,
                        time.monotonic() + reap_reserve,
                    ),
                )
                recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                kill_diagnostics += reap_notes
                if not output_complete:
                    kill_diagnostics += b"OUTPUT_DRAIN_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=output-drain\n"
                if not reaped:
                    kill_diagnostics += b"PROCESS_REAP_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
                else:
                    kill_diagnostics += b"PROCESS_REAP_STATUS=gone\n"
            except OSError as recovery_error:
                kill_diagnostics += (
                    b"OUTPUT_DRAIN_ERROR="
                    + repr(recovery_error).encode("utf-8", errors="replace")
                    + b"\n"
                )
                # The failed communicate call means its output boundary was
                # not proven, even if a later closed-stream probe happens to
                # report EOF. Never certify a possibly partial diagnostic.
                kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
                # OSError is allowed to carry bytes read before the pipe
                # failed.  Keep those bytes; the explicit incomplete marker
                # below prevents them from being mistaken for a complete
                # stream.
                recovered_stdout = _output_bytes(
                    getattr(recovery_error, "stdout", None)
                )
                recovered_stderr = _output_bytes(
                    getattr(recovery_error, "stderr", None)
                )
                reaped, output_complete, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                    process,
                    deadline=min(
                        cleanup_deadline,
                        time.monotonic() + reap_reserve,
                    ),
                )
                recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                kill_diagnostics += reap_notes
                if not output_complete:
                    kill_diagnostics += b"OUTPUT_DRAIN_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=output-drain\n"
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
                reaped, output_complete, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                    process,
                    deadline=min(
                        cleanup_deadline,
                        time.monotonic() + reap_reserve,
                    ),
                )
                recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                kill_diagnostics += reap_notes
                if not output_complete:
                    kill_diagnostics += b"OUTPUT_DRAIN_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=output-drain\n"
                if not reaped:
                    kill_diagnostics += b"PROCESS_REAP_TIMEOUT=1\n"
                    kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
                else:
                    kill_diagnostics += b"PROCESS_REAP_STATUS=gone\n"
            # Re-check after output/reaping when the deadline still allows
            # it.  A definitive post-reap result wins; if that probe reaches
            # the deadline, retain a definitive pre-reap proof rather than
            # converting a completed cleanup into an unknown result.
            post_reap_status = _tree_status(
                process.pid,
                tree_identities,
                snapshot_provider,
                deadline=deadline,
                allow_direct_fallback=True,
                census_complete=getattr(
                    process, "_torturer_tree_census_observed", False
                ),
            )
            final_status = (
                post_reap_status
                if post_reap_status != "unknown"
                else pre_reap_status
            )
            kill_diagnostics += (
                b"PROCESS_TREE_FINAL_STATUS="
                + final_status.encode("ascii")
                + b"\n"
            )
            if final_status == "gone":
                kill_diagnostics += b"PROCESS_TREE_STATUS=gone\n"
            else:
                kill_diagnostics += b"EVIDENCE_INCOMPLETE=1 reason=final-tree\n"
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
            partial_stdout = _output_bytes(getattr(error, "stdout", None))
            partial_stderr = _output_bytes(getattr(error, "stderr", None))
            if process is None:
                self._retain_exception(argv, error, time.monotonic() - started)
            else:
                diagnostics = bytearray(
                    b"OUTPUT_DRAIN_ERROR="
                    + repr(error).encode("utf-8", errors="replace")
                    + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
                )
                try:
                    monitor.stop(_remaining_until(deadline, cap=cleanup_reserve))
                    diagnostics.extend(
                        _kill_process_tree(
                            process,
                            identities=monitor.identities,
                            snapshot_provider=snapshot_provider,
                            deadline=deadline,
                            force_immediately=True,
                        )
                    )
                except (OSError, HostedAdapterError) as cleanup_error:
                    diagnostics.extend(
                        b"CLEANUP_ERROR="
                        + repr(cleanup_error).encode("utf-8", errors="replace")
                        + b"\nEVIDENCE_INCOMPLETE=1 reason=process-tree-cleanup-error\n"
                    )
                    diagnostics.extend(_kill_process(process))
                try:
                    reaped, output_complete, drained_stdout, drained_stderr, reap_notes = (
                        _bounded_reap_process(process, deadline=deadline)
                    )
                    partial_stdout = _merge_output(partial_stdout, drained_stdout)
                    partial_stderr = _merge_output(partial_stderr, drained_stderr)
                    diagnostics.extend(reap_notes)
                    if not output_complete:
                        diagnostics.extend(
                            b"EVIDENCE_INCOMPLETE=1 reason=output-drain\n"
                        )
                    if not reaped:
                        diagnostics.extend(
                            b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
                        )
                except (OSError, HostedAdapterError) as reap_error:
                    diagnostics.extend(
                        b"REAP_ERROR="
                        + repr(reap_error).encode("utf-8", errors="replace")
                        + b"\nEVIDENCE_INCOMPLETE=1 reason=process-reap-error\n"
                    )
                self._retain(
                    CommandResult(
                        argv,
                        process.returncode if process.returncode is not None else -1,
                        partial_stdout,
                        partial_stderr,
                    ),
                    time.monotonic() - started,
                    bytes(diagnostics),
                )
            raise HostedAdapterError("COMMAND_UNAVAILABLE") from error
        self._retain(result, time.monotonic() - started, b"PROCESS_TREE_STATUS=gone\n")
        return result

    def run_with_input(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        input_bytes: bytes,
    ) -> CommandResult:
        """Run a command with private bytes supplied on stdin.

        The ordinary command path intentionally has no stdin payload.  A
        hosted Android app cannot reliably copy a file from ``/data/local/tmp``
        into its package-private directory on current emulator images, so the
        Android adapter uses this narrow path to stream the already validated
        profile/command bytes through ``adb shell run-as``.  The bytes are
        never written to the command vector or diagnostic metadata; stdout,
        stderr, exit status, and process-tree evidence retain the same
        complete owner-only treatment as every other command.
        """

        return self.run(
            command,
            timeout_seconds=timeout_seconds,
            input_bytes=input_bytes,
        )

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
        process: subprocess.Popen[bytes] | None = None
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
                    _kill_process_tree(
                        process,
                        deadline=deadline,
                        force_immediately=True,
                    )
                )
                try:
                    recovered_stdout, recovered_stderr = process.communicate(
                        timeout=_remaining_until(deadline)
                    )
                except subprocess.TimeoutExpired as recovery_error:
                    recovered_stdout = _output_bytes(recovery_error.stdout)
                    recovered_stderr = _output_bytes(recovery_error.stderr)
                    _kill_process(process)
                    reaped, output_complete, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                        process, deadline=deadline,
                    )
                    recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                    recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                    diagnostics.extend(reap_notes)
                    if not output_complete:
                        diagnostics.extend(b"DETACHED_LAUNCH_OUTPUT_DRAIN_TIMEOUT=1\n")
                    if not reaped:
                        diagnostics.extend(b"DETACHED_LAUNCH_REAP_TIMEOUT=1\n")
                except OSError as recovery_error:
                    diagnostics.extend(
                        b"DETACHED_LAUNCH_OUTPUT_ERROR="
                        + repr(recovery_error).encode("utf-8", errors="replace")
                        + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
                    )
                    recovered_stdout = _output_bytes(
                        getattr(recovery_error, "stdout", None)
                    )
                    recovered_stderr = _output_bytes(
                        getattr(recovery_error, "stderr", None)
                    )
                    diagnostics.extend(_kill_process(process))
                    reaped, output_complete, drained_stdout, drained_stderr, reap_notes = _bounded_reap_process(
                        process, deadline=deadline,
                    )
                    recovered_stdout = _merge_output(recovered_stdout, drained_stdout)
                    recovered_stderr = _merge_output(recovered_stderr, drained_stderr)
                    diagnostics.extend(reap_notes)
                    if not output_complete:
                        diagnostics.extend(b"DETACHED_LAUNCH_OUTPUT_DRAIN_TIMEOUT=1\n")
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
            partial_stdout = _output_bytes(getattr(error, "stdout", None))
            partial_stderr = _output_bytes(getattr(error, "stderr", None))
            if process is None:
                self._retain_exception(argv, error, time.monotonic() - started)
            else:
                diagnostics = bytearray(
                    b"DETACHED_LAUNCH_OUTPUT_ERROR="
                    + repr(error).encode("utf-8", errors="replace")
                    + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
                )
                diagnostics.extend(_kill_process(process))
                try:
                    reaped, output_complete, drained_stdout, drained_stderr, reap_notes = (
                        _bounded_reap_process(process, deadline=deadline)
                    )
                    partial_stdout = _merge_output(partial_stdout, drained_stdout)
                    partial_stderr = _merge_output(partial_stderr, drained_stderr)
                    diagnostics.extend(reap_notes)
                    if not output_complete:
                        diagnostics.extend(
                            b"EVIDENCE_INCOMPLETE=1 reason=output-drain\n"
                        )
                    if not reaped:
                        diagnostics.extend(
                            b"EVIDENCE_INCOMPLETE=1 reason=process-reap\n"
                        )
                except (OSError, HostedAdapterError) as reap_error:
                    diagnostics.extend(
                        b"REAP_ERROR="
                        + repr(reap_error).encode("utf-8", errors="replace")
                        + b"\nEVIDENCE_INCOMPLETE=1 reason=process-reap-error\n"
                    )
                self._retain(
                    CommandResult(
                        argv,
                        process.returncode if process.returncode is not None else -1,
                        partial_stdout,
                        partial_stderr,
                    ),
                    time.monotonic() - started,
                    bytes(diagnostics),
                )
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


class _ProcessProbeError(RuntimeError):
    """A process identity probe failed instead of observing disappearance."""


class _ProcessTreeMonitor:
    """Continuously retain process identities before a leader can disappear."""

    def __init__(
        self,
        root_pid: int,
        snapshot_provider: _ProcessSnapshotProvider | None = None,
        *,
        deadline: float | None = None,
        process: subprocess.Popen[bytes] | None = None,
    ) -> None:
        self.root_pid = root_pid
        self.snapshot_provider = snapshot_provider
        self.deadline = deadline
        self.process = process
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
        for identity in _tracked_processes(
            self.root_pid,
            self.snapshot_provider,
            deadline=self.deadline,
        ):
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


def _proc_stat(
    pid: int, *, deadline: float | None = None,
) -> tuple[int, int, str, str] | None:
    """Read one Linux process identity without treating a vanished PID as live."""

    if deadline is not None and time.monotonic() >= deadline:
        return None
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        if deadline is not None and time.monotonic() > deadline:
            return None
        _comm, fields = value.rsplit(") ", 1)
        columns = fields.split()
        # After the closing parenthesis: state=0, ppid=1, pgrp=2,
        # starttime=19.  The start time prevents a reused PID from being
        # mistaken for the timed-out child.
        return int(columns[1]), int(columns[2]), columns[19], columns[0]
    except FileNotFoundError:
        # The process can disappear between the directory listing and this
        # read.  That is an ordinary gone observation, not a probe failure.
        return None
    except (OSError, ValueError, IndexError) as error:
        # Permission, malformed, and other read failures must not be folded
        # into "gone" by callers that have time left to retry/prove them.
        raise _ProcessProbeError from error


def _windows_process_start_time(
    pid: int, *, deadline: float | None = None,
) -> str | None:
    """Read a Windows creation timestamp to distinguish PID reuse."""

    if deadline is not None and time.monotonic() >= deadline:
        return None
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
            value = str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
            if deadline is not None and time.monotonic() > deadline:
                return None
            return value
        finally:
            kernel32.CloseHandle(handle)
    except (AttributeError, OSError):
        return None


def _windows_process_snapshot(
    *, deadline: float | None = None,
) -> dict[int, tuple[int, int, str, str]] | None:
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
            if deadline is not None and time.monotonic() >= deadline:
                return None
            first = kernel32.Process32FirstW(snapshot_handle, ctypes.byref(entry))
            if not first:
                # An empty process list is not a trustworthy census for a
                # launched process.  Treat both an API failure and an
                # unexpected empty result as incomplete.
                return None
            while first:
                pid = int(entry.th32ProcessID)
                start_time = _windows_process_start_time(pid, deadline=deadline)
                # Keep a census entry whose identity could not be read, but
                # mark it unknown.  Callers can then fail closed only when
                # that process is in the launched tree instead of silently
                # dropping a protected descendant from the census.
                result[pid] = (
                    int(entry.th32ParentProcessID),
                    0,
                    start_time or "",
                    "R",
                )
                if deadline is not None and time.monotonic() >= deadline:
                    return None
                first = kernel32.Process32NextW(snapshot_handle, ctypes.byref(entry))
                if not first:
                    # ERROR_NO_MORE_FILES (18) is the only normal end of a
                    # Toolhelp enumeration.  A different last-error means
                    # the census is partial and must not be used to certify
                    # that the process tree is gone.
                    if ctypes.get_last_error() != 18:
                        return None
        finally:
            kernel32.CloseHandle(snapshot_handle)
        return result
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _process_snapshot(
    *, deadline: float | None = None,
) -> dict[int, tuple[int, int, str, str]] | None:
    if os.name == "nt":
        return _windows_process_snapshot(deadline=deadline)
    if os.name != "posix" or not Path("/proc").is_dir():
        return None
    snapshot: dict[int, tuple[int, int, str, str]] = {}
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    if deadline is not None and time.monotonic() >= deadline:
        return None
    for entry in entries:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        if not entry.name.isdigit():
            continue
        try:
            stat_value = _proc_stat(int(entry.name), deadline=deadline)
        except _ProcessProbeError:
            return None
        if stat_value is not None:
            snapshot[int(entry.name)] = stat_value
        else:
            # A process can disappear between the directory listing and its
            # stat read; that is an ordinary gone result.  If the entry still
            # exists, however, the census read was incomplete (permission,
            # malformed data, or a deadline-crossing read) and must fail
            # closed rather than silently omit a possible descendant.
            try:
                entry.stat()
            except FileNotFoundError:
                pass
            except OSError:
                return None
            else:
                return None
        if deadline is not None and time.monotonic() > deadline:
            return None
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


def _parse_macos_process_snapshot_strict(
    stdout: bytes,
) -> dict[int, tuple[int, int, str, str]] | None:
    """Reject a partially malformed ``ps`` listing instead of proving from it."""

    snapshot = _parse_macos_process_snapshot(stdout)
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if (
            len(fields) < 4
            or not all(field.isdigit() for field in fields[:3])
            or int(fields[0]) <= 0
            or int(fields[1]) < 0
            or int(fields[2]) < 0
            or not " ".join(fields[3:])
        ):
            return None
    return snapshot


class _ProcessSnapshotProvider:
    """Provide bounded process snapshots and retain macOS probe bytes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached_at = 0.0
        self._cached: dict[int, tuple[int, int, str, str]] | None = None
        self._has_cached = False
        self._diagnostics = bytearray()

    def invalidate(self, *, deadline: float | None = None) -> bool:
        """Discard a cached census before a lifecycle proof boundary."""

        if deadline is None:
            acquired = self._lock.acquire()
        else:
            acquired = self._lock.acquire(timeout=_remaining_until(deadline))
        if not acquired:
            self._diagnostics.extend(b"MAC_PROCESS_CENSUS_DEADLINE=1\n")
            return False
        try:
            self._has_cached = False
            return True
        finally:
            self._lock.release()

    def __call__(
        self, deadline: float | None = None,
    ) -> dict[int, tuple[int, int, str, str]] | None:
        if os.name != "posix" or Path("/proc").is_dir():
            return _process_snapshot(deadline=deadline)
        if deadline is None:
            acquired = self._lock.acquire()
        else:
            acquired = self._lock.acquire(timeout=_remaining_until(deadline))
        if not acquired:
            self._diagnostics.extend(b"MAC_PROCESS_CENSUS_DEADLINE=1\n")
            return None
        try:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                self._diagnostics.extend(b"MAC_PROCESS_CENSUS_DEADLINE=1\n")
                self._cached = None
                self._cached_at = now
                self._has_cached = True
                return None
            if self._has_cached and now - self._cached_at < 0.05:
                return self._cached
            stdout = b""
            stderr = b""
            returncode: int | None = None
            timed_out = False
            try:
                census_timeout = _remaining_until(
                    deadline,
                    cap=_MACOS_PROCESS_CENSUS_TIMEOUT_SECONDS,
                ) if deadline is not None else _MACOS_PROCESS_CENSUS_TIMEOUT_SECONDS
                if census_timeout <= 0:
                    raise subprocess.TimeoutExpired(
                        _MACOS_PROCESS_CENSUS_COMMAND, 0.0,
                    )
                completed = subprocess.run(
                    _MACOS_PROCESS_CENSUS_COMMAND,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=census_timeout,
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
                _parse_macos_process_snapshot_strict(stdout)
                if not timed_out and returncode == 0
                else None
            )
            if not timed_out and returncode == 0 and snapshot is None:
                self._diagnostics.extend(
                    b"MAC_PROCESS_CENSUS_PARSE_ERROR=1\n"
                    b"EVIDENCE_INCOMPLETE=1 reason=process-census-parse-error\n"
                )
            if deadline is not None and time.monotonic() > deadline:
                timed_out = True
                snapshot = None
                self._diagnostics.extend(b"MAC_PROCESS_CENSUS_DEADLINE=1\n")
            self._cached = snapshot
            self._cached_at = time.monotonic()
            self._has_cached = True
            return snapshot
        finally:
            self._lock.release()

    @property
    def diagnostics(self) -> bytes:
        with self._lock:
            return bytes(self._diagnostics)


def _tracked_processes(
    root_pid: int,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
    *,
    deadline: float | None = None,
    process: subprocess.Popen[bytes] | None = None,
) -> tuple[_ProcessIdentity, ...]:
    snapshot = (
        snapshot_provider(deadline)
        if snapshot_provider is not None
        else _process_snapshot(deadline=deadline)
    )
    if snapshot is None:
        if process is not None:
            process._torturer_tree_census_observed = False  # type: ignore[attr-defined]
        return ()
    children: dict[int, list[int]] = {}
    for pid, (ppid, _pgrp, _start, _state) in snapshot.items():
        children.setdefault(ppid, []).append(pid)
    pending = [root_pid]
    seen: set[int] = set()
    identities: list[_ProcessIdentity] = []
    while pending:
        if deadline is not None and time.monotonic() >= deadline:
            if process is not None:
                process._torturer_tree_census_observed = False  # type: ignore[attr-defined]
            return ()
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
    if process is not None:
        process._torturer_tree_census_observed = True  # type: ignore[attr-defined]
    return tuple(identities)


def _identity_live(
    identity: _ProcessIdentity,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
    *,
    deadline: float | None = None,
) -> bool | None:
    if os.name == "nt":
        snapshot = _process_snapshot(deadline=deadline)
        if snapshot is None:
            return None
        value = snapshot.get(identity.pid)
        if value is None:
            return False
        _ppid, _pgrp, start_time, _state = value
        if not identity.start_time or not start_time:
            return None
        if start_time != identity.start_time:
            return False
        return True
    if snapshot_provider is not None and not Path("/proc").is_dir():
        snapshot = snapshot_provider(deadline)
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
    if deadline is not None and time.monotonic() >= deadline:
        # A deadline-bound identity probe that did not run is inconclusive;
        # it must not be treated as a vanished process.
        return None
    try:
        value = _proc_stat(identity.pid, deadline=deadline)
    except _ProcessProbeError:
        return None
    if value is None:
        if deadline is not None and time.monotonic() >= deadline:
            # _proc_stat deliberately returns no value when its read crossed
            # the absolute deadline.  Distinguish that incomplete probe from
            # a normal ENOENT so cleanup cannot be falsely certified gone.
            return None
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
    *,
    deadline: float | None = None,
    allow_direct_fallback: bool = False,
    census_complete: bool = False,
) -> str:
    if os.name in {"posix", "nt"}:
        if allow_direct_fallback and census_complete and os.name == "posix":
            # A full census has already bounded the set of identities that
            # existed before termination.  Probe those identities and their
            # process group first so a slow final /proc enumeration cannot
            # consume the remaining cleanup budget before a proof is made.
            direct_status = _direct_tree_status(
                root_pid,
                identities,
                deadline=deadline,
            )
            if direct_status != "unknown":
                return direct_status
        snapshot = (
            snapshot_provider(deadline)
            if snapshot_provider is not None
            else _process_snapshot(deadline=deadline)
        )
        if snapshot is None:
            # A complete Linux census already captured every descendant before
            # termination.  If a last full rescan loses a race with /proc
            # disappearance, direct identity and process-group probes can
            # still prove the known tree gone within the same deadline.  This
            # fallback is deliberately opt-in; an incomplete census remains
            # unknown and can never be certified from a partial listing.
            if allow_direct_fallback and census_complete:
                direct_status = _direct_tree_status(
                    root_pid,
                    identities,
                    deadline=deadline,
                )
                if direct_status != "unknown":
                    return direct_status
            return "unknown"
        if os.name == "nt" and not identities:
            return "unknown"
        live = [
            _identity_live(identity, snapshot_provider, deadline=deadline)
            for identity in identities
        ]
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


def _direct_tree_status(
    root_pid: int,
    identities: tuple[_ProcessIdentity, ...],
    *,
    deadline: float | None = None,
) -> str:
    """Prove a previously complete Linux tree after a /proc disappearance race."""

    if os.name != "posix" or not Path("/proc").is_dir():
        return "unknown"
    if deadline is not None and time.monotonic() >= deadline:
        return "unknown"
    live = [
        _identity_live(identity, deadline=deadline)
        for identity in identities
    ]
    if any(value is None for value in live):
        return "unknown"
    if any(live):
        return "alive"
    try:
        os.killpg(root_pid, 0)
    except ProcessLookupError:
        return "gone"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"
    return "alive"


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
    timeout: float | None = None,
    *,
    monitor_complete: bool,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
    deadline: float | None = None,
) -> tuple[bytes, str]:
    """Prove a normally-returned leader left no observed descendant behind."""

    if deadline is None:
        if timeout is None:
            raise HostedAdapterError("PROCESS_TREE_DEADLINE_INVALID")
        deadline = time.monotonic() + max(0.0, timeout)
    if snapshot_provider is not None:
        snapshot_provider.invalidate(deadline=deadline)
    identities = _merge_process_identities(
        observed,
        _tracked_processes(
            process.pid,
            snapshot_provider,
            deadline=deadline,
            process=process,
        ),
    )
    diagnostics = bytearray(
        b"PROCESS_TREE_TRACKED="
        + b",".join(str(identity.pid).encode("ascii") for identity in identities)
        + b"\n"
    )
    initial_status = (
        _tree_status(process.pid, identities, snapshot_provider, deadline=deadline)
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
                deadline=deadline,
            )
        )
        if snapshot_provider is not None:
            snapshot_provider.invalidate(deadline=deadline)
        status = _tree_status(
            process.pid,
            identities,
            snapshot_provider,
            deadline=deadline,
            allow_direct_fallback=True,
            census_complete=getattr(
                process, "_torturer_tree_census_observed", False
            ),
        )
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
    *,
    allow_direct_fallback: bool = False,
    census_complete: bool = False,
) -> str:
    while time.monotonic() < deadline:
        status = _tree_status(
            root_pid,
            identities,
            snapshot_provider,
            deadline=deadline,
            allow_direct_fallback=allow_direct_fallback,
            census_complete=census_complete,
        )
        if status != "alive":
            return status
        time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    return _tree_status(
        root_pid,
        identities,
        snapshot_provider,
        deadline=deadline,
        allow_direct_fallback=allow_direct_fallback,
        census_complete=census_complete,
    )


def _signal_tracked(
    identities: tuple[_ProcessIdentity, ...],
    signum: int,
    snapshot_provider: _ProcessSnapshotProvider | None = None,
    *,
    deadline: float | None = None,
) -> bytes:
    diagnostics = bytearray()
    for identity in identities:
        live = _identity_live(identity, snapshot_provider, deadline=deadline)
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
                + b"EVIDENCE_INCOMPLETE=1 reason=process-signal-error\n"
            )
    return bytes(diagnostics)


def _kill_process(process: subprocess.Popen[bytes]) -> bytes:
    try:
        process.kill()
    except OSError as error:
        return (
            b"process-kill-error="
            + repr(error).encode("utf-8", errors="replace")
            + b"\nEVIDENCE_INCOMPLETE=1 reason=process-kill-error\n"
        )
    return b""


def _bounded_reap_process(
    process: subprocess.Popen[bytes], timeout: float | None = None,
    *,
    deadline: float | None = None,
) -> tuple[bool, bool, bytes, bytes, bytes]:
    """Independently prove leader reaping and pipe EOF inside one bound.

    ``Popen.communicate(timeout=0)`` can raise ``TimeoutExpired`` even after
    the leader has exited and both pipes are already at EOF.  Reaping and
    output completion are different facts: ``poll``/``wait`` proves the
    former, while a non-blocking POSIX drain proves the latter without
    manufacturing time beyond the caller's absolute deadline.
    """

    if deadline is None:
        if timeout is None:
            raise HostedAdapterError("PROCESS_REAP_DEADLINE_INVALID")
        deadline = time.monotonic() + max(0.0, timeout)
    diagnostics = bytearray()
    reaped = process.poll() is not None

    output_complete = False
    stdout = b""
    stderr = b""
    if os.name == "posix":
        if not reaped and _remaining_until(deadline) > 0:
            try:
                process.wait(timeout=_remaining_until(deadline))
                reaped = True
            except subprocess.TimeoutExpired:
                reaped = process.poll() is not None
            except OSError as error:
                diagnostics.extend(
                    b"PROCESS_REAP_ERROR="
                    + repr(error).encode("utf-8", errors="replace")
                    + b"\n"
                    + b"EVIDENCE_INCOMPLETE=1 reason=process-reap-error\n"
                )
        output_complete, stdout, stderr, drain_notes = _drain_posix_pipes(
            process, deadline
        )
        diagnostics.extend(drain_notes)
    else:
        output_complete, stdout, stderr, drain_notes = _drain_windows_pipes(
            process, deadline
        )
        diagnostics.extend(drain_notes)
        reaped = reaped or process.poll() is not None

    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError as error:
                diagnostics.extend(
                    b"OUTPUT_PIPE_CLOSE_ERROR="
                    + repr(error).encode("utf-8", errors="replace")
                    + b"\n"
                    + b"EVIDENCE_INCOMPLETE=1 reason=output-close-error\n"
                )
                output_complete = False
    return reaped, output_complete, stdout, stderr, bytes(diagnostics)


def _drain_windows_pipes(
    process: subprocess.Popen[bytes], deadline: float,
) -> tuple[bool, bytes, bytes, bytes]:
    """Drain Windows reader threads in slices while polling the leader.

    ``Popen.wait`` does not consume the reader threads used by Windows
    ``communicate``. Waiting for the leader first can therefore spend the full
    bound before any output is collected. Repeated bounded communicate calls
    let the reader threads drain while ``poll`` independently records whether
    the leader has been reaped. A live descendant holding a pipe open keeps
    output completion unproven and is reported as incomplete.
    """

    stdout = b""
    stderr = b""
    diagnostics = bytearray()
    while True:
        remaining = _remaining_until(deadline)
        if remaining <= 0:
            return False, stdout, stderr, bytes(diagnostics)
        # Poll independently of the reader threads.  The leader can be
        # reaped while a descendant still holds either inherited pipe open;
        # waiting on communicate alone cannot distinguish those states.
        try:
            process.poll()
        except OSError as error:
            diagnostics.extend(
                b"PROCESS_REAP_ERROR="
                + repr(error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=process-reap-error\n"
            )
        try:
            current_stdout, current_stderr = process.communicate(
                timeout=min(0.05, remaining),
            )
            stdout = _merge_output(stdout, _output_bytes(current_stdout))
            stderr = _merge_output(stderr, _output_bytes(current_stderr))
            return True, stdout, stderr, bytes(diagnostics)
        except subprocess.TimeoutExpired as error:
            stdout = _merge_output(stdout, _output_bytes(error.stdout))
            stderr = _merge_output(stderr, _output_bytes(error.stderr))
            if _remaining_until(deadline) <= 0:
                return False, stdout, stderr, bytes(diagnostics)
        except OSError as error:
            diagnostics.extend(
                b"OUTPUT_DRAIN_ERROR="
                + repr(error).encode("utf-8", errors="replace")
                + b"\n"
                + b"EVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
            )
            stdout = _merge_output(
                stdout, _output_bytes(getattr(error, "stdout", None))
            )
            stderr = _merge_output(
                stderr, _output_bytes(getattr(error, "stderr", None))
            )
            return False, stdout, stderr, bytes(diagnostics)


def _drain_posix_pipes(
    process: subprocess.Popen[bytes], deadline: float,
) -> tuple[bool, bytes, bytes, bytes]:
    """Drain every immediately available byte and prove EOF on POSIX pipes."""

    outputs: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    open_streams: dict[int, str] = {}
    diagnostics = bytearray()
    for name in ("stdout", "stderr"):
        stream = getattr(process, name, None)
        if stream is None or stream.closed:
            continue
        try:
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
        except (OSError, ValueError) as error:
            diagnostics.extend(
                b"OUTPUT_PIPE_SETUP_ERROR stream="
                + name.encode("ascii")
                + b" error="
                + repr(error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=output-pipe-setup-error\n"
            )
            return False, bytes(outputs["stdout"]), bytes(outputs["stderr"]), bytes(diagnostics)
        open_streams[descriptor] = name

    while open_streams:
        made_progress = False
        for descriptor, name in tuple(open_streams.items()):
            try:
                chunk = os.read(descriptor, 64 * 1024)
            except BlockingIOError:
                continue
            except OSError as error:
                diagnostics.extend(
                    b"OUTPUT_DRAIN_ERROR stream="
                    + name.encode("ascii")
                    + b" error="
                    + repr(error).encode("utf-8", errors="replace")
                    + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
                )
                return False, bytes(outputs["stdout"]), bytes(outputs["stderr"]), bytes(diagnostics)
            if chunk:
                outputs[name].extend(chunk)
                made_progress = True
            else:
                del open_streams[descriptor]
                made_progress = True
        if not open_streams:
            break
        # A successful non-blocking read consumed immediately available data;
        # probe again even at the deadline so an already-closed writer can be
        # proven by the following zero-byte EOF read.  Only waiting for new
        # data consumes time.
        if made_progress:
            continue
        remaining = _remaining_until(deadline)
        if remaining <= 0:
            return False, bytes(outputs["stdout"]), bytes(outputs["stderr"]), bytes(diagnostics)
        try:
            select.select(tuple(open_streams), (), (), min(0.01, remaining))
        except (OSError, ValueError) as error:
            diagnostics.extend(
                b"OUTPUT_DRAIN_WAIT_ERROR="
                + repr(error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
            )
            return False, bytes(outputs["stdout"]), bytes(outputs["stderr"]), bytes(diagnostics)
    return True, bytes(outputs["stdout"]), bytes(outputs["stderr"]), bytes(diagnostics)


def _bounded_capture(
    command: Sequence[str],
    timeout: float | None = None,
    *,
    deadline: float | None = None,
) -> tuple[int | None, bytes, bytes, bool]:
    """Run a cleanup helper with a hard timeout and retain all available bytes."""

    started = time.monotonic()
    if deadline is None:
        if timeout is None:
            raise HostedAdapterError("PROCESS_CAPTURE_DEADLINE_INVALID")
        deadline = started + max(0.0, timeout)
    else:
        deadline = float(deadline)
    helper = subprocess.Popen(
        list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **_process_group_kwargs()
    )
    drain_diagnostics = bytearray()

    def bounded_reap() -> tuple[bool, bool, bytes, bytes, bytes]:
        try:
            return _bounded_reap_process(helper, deadline=deadline)
        except OSError as reap_error:
            return (
                False,
                False,
                b"",
                b"",
                b"REAP_ERROR="
                + repr(reap_error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=process-reap-error\n",
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
        except OSError as kill_error:
            # A failed post-timeout kill is part of the evidence, not a
            # disposable implementation detail.  Keep the timeout output and
            # surface the failed cleanup explicitly.
            drain_diagnostics.extend(
                b"PROCESS_KILL_ERROR="
                + repr(kill_error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=process-kill-error\n"
            )
        try:
            stdout, stderr = helper.communicate(timeout=_remaining_until(deadline))
        except subprocess.TimeoutExpired as final_error:
            reaped, output_complete, drained_stdout, drained_stderr, reap_notes = bounded_reap()
            return (
                None,
                _merge_output(
                    partial_stdout,
                    _merge_output(_output_bytes(final_error.stdout), drained_stdout),
                ),
                _merge_output(
                    partial_stderr,
                    _merge_output(
                        _output_bytes(final_error.stderr),
                        _merge_output(drained_stderr, bytes(drain_diagnostics)),
                    ),
                ) + reap_notes + (
                    b"OUTPUT_DRAIN_TIMEOUT=1\n" if not output_complete else b""
                ) + (
                    b"PROCESS_REAP_TIMEOUT=1\n" if not reaped else b""
                ),
                True,
            )
        except OSError as final_error:
            reaped, output_complete, drained_stdout, drained_stderr, reap_notes = bounded_reap()
            final_diagnostics = (
                bytes(drain_diagnostics)
                + b"OUTPUT_DRAIN_ERROR="
                + repr(final_error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
            )
            return (
                None,
                _merge_output(
                    partial_stdout,
                    _merge_output(
                        _output_bytes(getattr(final_error, "stdout", None)),
                        drained_stdout,
                    ),
                ),
                _merge_output(
                    partial_stderr,
                    _merge_output(
                        _output_bytes(getattr(final_error, "stderr", None)),
                        drained_stderr,
                    ),
                ) + final_diagnostics + reap_notes + (
                    b"OUTPUT_DRAIN_TIMEOUT=1\n" if not output_complete else b""
                ) + (
                    b"PROCESS_REAP_TIMEOUT=1\n" if not reaped else b""
                ),
                True,
            )
        return (
            helper.returncode,
            _merge_output(partial_stdout, stdout),
            _merge_output(partial_stderr, stderr) + bytes(drain_diagnostics),
            True,
        )
    except OSError as error:
        # Preserve bytes attached to an initial communication failure and
        # retain an explicit incomplete-output diagnostic.  This path is also
        # bounded: kill/reap uses the same absolute helper deadline.
        diagnostics = (
            b"OUTPUT_DRAIN_ERROR="
            + repr(error).encode("utf-8", errors="replace")
            + b"\nEVIDENCE_INCOMPLETE=1 reason=output-drain-error\n"
        )
        try:
            helper.kill()
        except OSError as kill_error:
            diagnostics += (
                b"PROCESS_KILL_ERROR="
                + repr(kill_error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=process-kill-error\n"
            )
        reaped, output_complete, drained_stdout, drained_stderr, reap_notes = bounded_reap()
        return (
            None,
            _merge_output(
                _output_bytes(getattr(error, "stdout", None)),
                drained_stdout,
            ),
            _merge_output(
                _output_bytes(getattr(error, "stderr", None)),
                drained_stderr,
            ) + diagnostics + reap_notes + (
                b"OUTPUT_DRAIN_TIMEOUT=1\n" if not output_complete else b""
            ) + (
                b"PROCESS_REAP_TIMEOUT=1\n" if not reaped else b""
            ),
            False,
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
    timeout: float | None = _DEFAULT_CLEANUP_RESERVE_SECONDS,
    *,
    identities: tuple[_ProcessIdentity, ...] = (),
    snapshot_provider: _ProcessSnapshotProvider | None = None,
    deadline: float | None = None,
    force_immediately: bool = False,
) -> bytes:
    """Terminate, drain, and prove disappearance of the complete child tree."""

    diagnostics = bytearray()
    if deadline is None:
        if timeout is None:
            raise HostedAdapterError("PROCESS_TREE_DEADLINE_INVALID")
        deadline = time.monotonic() + max(0.0, timeout)
    else:
        deadline = float(deadline)
    timeout_budget = (
        max(0.0, float(timeout))
        if timeout is not None
        else _remaining_until(deadline)
    )
    if snapshot_provider is not None:
        snapshot_provider.invalidate(deadline=deadline)
    identities = _merge_process_identities(
        identities,
        _tracked_processes(
            process.pid,
            snapshot_provider,
            deadline=deadline,
            process=process,
        ),
    )
    process._torturer_tree_identities = identities  # type: ignore[attr-defined]
    census_complete = getattr(process, "_torturer_tree_census_observed", False)
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
                deadline=deadline,
            )
            diagnostics.extend(b"taskkill-stdout=" + stdout + b"\n")
            diagnostics.extend(b"taskkill-stderr=" + stderr + b"\n")
            if taskkill_timed_out:
                diagnostics.extend(b"TASKKILL_TIMEOUT=1\n")
                diagnostics.extend(b"EVIDENCE_INCOMPLETE=1 reason=taskkill-timeout\n")
            if returncode != 0:
                diagnostics.extend(
                    b"TASKKILL_RETURN_CODE="
                    + str(returncode).encode("ascii")
                    + b"\n"
                )
                diagnostics.extend(_kill_process(process))
        except OSError as error:
            diagnostics.extend(
                b"taskkill-error="
                + repr(error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=taskkill-error\n"
            )
            diagnostics.extend(_kill_process(process))
        status = _wait_tree_gone(
            process.pid,
            identities,
            deadline,
            snapshot_provider,
            allow_direct_fallback=True,
            census_complete=census_complete,
        )
        if status != "gone":
            # A detached child is no longer reachable through the leader's
            # /T traversal.  Kill each identity captured while the leader was
            # alive, with the same hard cleanup deadline, and verify again.
            for identity in identities:
                if time.monotonic() >= deadline:
                    break
                if _identity_live(identity, snapshot_provider, deadline=deadline) is not True:
                    continue
                try:
                    code, stdout, stderr, timed_out = _bounded_capture(
                        ["taskkill", "/PID", str(identity.pid), "/T", "/F"],
                        deadline=deadline,
                    )
                    diagnostics.extend(
                        b"taskkill-descendant-stdout=" + stdout + b"\n"
                    )
                    diagnostics.extend(
                        b"taskkill-descendant-stderr=" + stderr + b"\n"
                    )
                    if timed_out:
                        diagnostics.extend(b"TASKKILL_DESCENDANT_TIMEOUT=1\n")
                        diagnostics.extend(
                            b"EVIDENCE_INCOMPLETE=1 reason=taskkill-timeout\n"
                        )
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
                        + b"\nEVIDENCE_INCOMPLETE=1 reason=taskkill-descendant-error\n"
                    )
            status = _wait_tree_gone(
                process.pid,
                identities,
                deadline,
                snapshot_provider,
                allow_direct_fallback=True,
                census_complete=census_complete,
            )
        if status != "gone":
            diagnostics.extend(b"PROCESS_TREE_KILL_FAILURE=1\n")
            diagnostics.extend(b"PROCESS_TREE_SURVIVORS=1\n")
        else:
            diagnostics.extend(b"PROCESS_TREE_STATUS=gone\n")
        return bytes(diagnostics)
    if force_immediately:
        diagnostics.extend(
            _signal_tracked(
                identities,
                signal.SIGKILL,
                snapshot_provider,
                deadline=deadline,
            )
        )
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            diagnostics.extend(b"PROCESS_GROUP_KILL=gone\n")
        except OSError as error:
            diagnostics.extend(
                b"PROCESS_GROUP_KILL_FAILURE="
                + repr(error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=process-group-kill-error\n"
            )
        if snapshot_provider is not None:
            snapshot_provider.invalidate(deadline=deadline)
        status = _wait_tree_gone(
            process.pid,
            identities,
            deadline,
            snapshot_provider,
            allow_direct_fallback=True,
            census_complete=census_complete,
        )
        if status == "gone":
            diagnostics.extend(b"PROCESS_TREE_STATUS=gone\n")
        else:
            diagnostics.extend(b"PROCESS_TREE_SURVIVORS=1\n")
            diagnostics.extend(
                b"PROCESS_TREE_STATUS=" + status.encode("ascii") + b"\n"
            )
        return bytes(diagnostics)
    diagnostics.extend(
        _signal_tracked(
            identities,
            signal.SIGTERM,
            snapshot_provider,
            deadline=deadline,
        )
    )
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        diagnostics.extend(b"PROCESS_GROUP_TERM=gone\n")
    except OSError as error:
        diagnostics.extend(
            b"PROCESS_GROUP_TERM_FAILURE="
            + repr(error).encode("utf-8", errors="replace")
            + b"\nEVIDENCE_INCOMPLETE=1 reason=process-group-term-error\n"
        )
    status = _wait_tree_gone(
        process.pid,
        identities,
        min(deadline, time.monotonic() + timeout_budget / 3.0),
        snapshot_provider,
        allow_direct_fallback=True,
        census_complete=census_complete,
    )
    if status != "gone":
        diagnostics.extend(
            _signal_tracked(
                identities,
                signal.SIGKILL,
                snapshot_provider,
                deadline=deadline,
            )
        )
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            diagnostics.extend(b"PROCESS_GROUP_KILL=gone\n")
        except OSError as error:
            diagnostics.extend(
                b"PROCESS_GROUP_KILL_FAILURE="
                + repr(error).encode("utf-8", errors="replace")
                + b"\nEVIDENCE_INCOMPLETE=1 reason=process-group-kill-error\n"
            )
        if snapshot_provider is not None:
            snapshot_provider.invalidate(deadline=deadline)
        status = _wait_tree_gone(
            process.pid,
            identities,
            deadline,
            snapshot_provider,
            allow_direct_fallback=True,
            census_complete=census_complete,
        )
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

    @property
    def capability_unavailable_reasons(self) -> dict[Capability, str]:
        """Explain capabilities that this hosted shell cannot safely provide."""

        return {
            Capability.NETWORK_TRANSITION: "HOSTED_RUNNER_UPLINK_TOGGLE_UNSUPPORTED",
            Capability.SLEEP_WAKE: "HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
            Capability.PROCESS_LOSS: "HOSTED_SERVICE_CONTROL_UNAVAILABLE",
        }

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
                for attempt in range(2):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ScenarioExecutionError("ENDURANCE_THROUGHPUT_TIMEOUT")
                    try:
                        last_metrics = self._throughput(min(30.0, remaining))
                        break
                    except ScenarioExecutionError as error:
                        if error.reason_code == "COMMAND_TIMEOUT":
                            raise ScenarioExecutionError("ENDURANCE_THROUGHPUT_TIMEOUT") from error
                        if (
                            error.reason_code not in {"THROUGHPUT_FAILED", "THROUGHPUT_INVALID"}
                            or attempt == 1
                        ):
                            raise
                        # One bounded retry prevents a single transient public
                        # transfer-endpoint response from deciding the entire
                        # endurance scenario. Both attempts retain their full
                        # command streams, and a persistent failure remains a
                        # hard scenario failure.
                        remaining = deadline - time.monotonic()
                        if remaining < _MIN_ENDURANCE_SAMPLE_SECONDS:
                            raise
                        time.sleep(min(1.0, remaining))
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
