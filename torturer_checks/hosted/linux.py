"""Linux hosted adapter with explicit, bounded runner controls."""

from __future__ import annotations

import os
from dataclasses import dataclass
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
    _call_with_deadline,
    _ensure_owner_only_directory,
)


_PID = re.compile(r"^[1-9][0-9]{0,9}$")
_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_LINUX_PROCESS_CENSUS = (
    "sudo", "-n", "ps", "-axo", "pid=,ppid=,pgid=,state="
)
_LINUX_PROCESS_STAT_SCRIPT = r'''\
set -eu
pid=$1
case "$pid" in
  ''|*[!0-9]*) printf 'service_probe_error\n'; exit 1;;
esac
path="/proc/$pid/stat"
if [ ! -e "$path" ]; then
  printf 'service_probe_absent\n'
  exit 2
fi
if ! record=$(cat "$path"); then
  printf 'service_probe_error\n'
  exit 1
fi
printf '%s\n' "$record"
'''
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


@dataclass(frozen=True)
class _LinuxProcessRecord:
    pid: int
    parent: int
    process_group: int
    start: str
    state: str


def _parse_linux_process_census(stdout: str) -> dict[int, _LinuxProcessRecord]:
    records: dict[int, _LinuxProcessRecord] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            raise ValueError("malformed process census row")
        try:
            pid, parent, process_group = (int(value) for value in fields[:3])
        except ValueError:
            raise ValueError("malformed process census identity") from None
        state = fields[3].strip()
        if (
            pid <= 0
            or parent < 0
            or process_group <= 0
            or len(state) != 1
        ):
            raise ValueError("invalid process census row")
        if pid in records:
            raise ValueError("duplicate process census PID")
        records[pid] = _LinuxProcessRecord(
            pid, parent, process_group, "", state[0].upper()
        )
    return records


def _linux_process_tree(
    records: dict[int, _LinuxProcessRecord], root_pid: int
) -> tuple[_LinuxProcessRecord, ...]:
    children: dict[int, list[int]] = {}
    for record in records.values():
        children.setdefault(record.parent, []).append(record.pid)
    pending = [root_pid]
    seen: set[int] = set()
    tree: list[_LinuxProcessRecord] = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        record = records.get(pid)
        if record is None:
            continue
        tree.append(record)
        pending.extend(children.get(pid, ()))
    return tuple(tree)


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
        identity_file: Path | None = None,
        runner: CommandRunner,
        raw_directory: Path,
    ) -> None:
        if pid <= 0 or not _PID.fullmatch(str(pid)):
            raise HostedAdapterError("SERVICE_PID_INVALID")
        if not binary.is_file() or binary.is_symlink():
            raise HostedAdapterError("SERVICE_BINARY_UNAVAILABLE")
        if not socket.is_absolute() or not pid_file.is_absolute():
            raise HostedAdapterError("SERVICE_PATH_INVALID")
        if identity_file is not None and not identity_file.is_absolute():
            raise HostedAdapterError("SERVICE_PATH_INVALID")
        if library_path is not None and (not library_path.is_dir() or library_path.is_symlink()):
            raise HostedAdapterError("SERVICE_LIBRARY_UNAVAILABLE")
        self.pid = pid
        self.binary = binary
        self.socket = socket
        self.library_path = library_path
        self.pid_file = pid_file
        self.identity_file = identity_file
        self.runner = runner
        self.raw_directory = raw_directory
        _ensure_owner_only_directory(self.raw_directory)
        self._restart_number = 0
        self._initial_identity: tuple[str, int] | None = None
        self._replacement_identity: tuple[str, int] | None = None
        self._replacement_tree: tuple[_LinuxProcessRecord, ...] = ()
        self._initial_identity = self._read_persisted_identity(pid)
        if self.identity_file is not None and self._initial_identity is None:
            raise HostedAdapterError("SERVICE_IDENTITY_UNAVAILABLE")
        self._write_pid(pid)
        identity_deadline = time.monotonic() + 5.0
        self._initial_identity = self._verify_candidate_pid(
            self._remaining(identity_deadline, "SERVICE_PID_PROBE_FAILED")
        )

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

    def _read_persisted_identity(self, pid: int) -> tuple[str, int] | None:
        """Read the launch-time native token supplied by the trusted workflow."""

        if getattr(self, "identity_file", None) is None:
            return None
        try:
            value = self.identity_file.read_text(encoding="ascii").strip()
        except OSError as error:
            raise HostedAdapterError("SERVICE_IDENTITY_UNAVAILABLE") from error
        fields = value.split("|")
        if (
            len(fields) != 3
            or not all(field.isdigit() for field in fields)
            or int(fields[0]) != pid
            or int(fields[1]) <= 0
            or int(fields[2]) <= 0
        ):
            raise HostedAdapterError("SERVICE_IDENTITY_UNAVAILABLE")
        return fields[1], int(fields[2])

    def _persist_identity(self, identity: tuple[str, int]) -> None:
        if getattr(self, "identity_file", None) is None:
            return
        start, process_group = identity
        temporary = self.identity_file.with_name(f".{self.identity_file.name}.tmp")
        try:
            self.identity_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary.write_text(
                f"{self.pid}|{start}|{process_group}\n", encoding="ascii"
            )
            temporary.chmod(0o600)
            temporary.replace(self.identity_file)
            self.identity_file.chmod(0o600)
        except OSError as error:
            raise ScenarioExecutionError("SERVICE_IDENTITY_PERSIST_FAILED") from error

    def _invalidate_identity_file(self) -> None:
        if getattr(self, "identity_file", None) is None:
            return
        temporary = self.identity_file.with_name(f".{self.identity_file.name}.tmp")
        try:
            temporary.write_text("pending\n", encoding="ascii")
            temporary.chmod(0o600)
            temporary.replace(self.identity_file)
            self.identity_file.chmod(0o600)
        except OSError as error:
            raise ScenarioExecutionError("SERVICE_IDENTITY_PERSIST_FAILED") from error

    def _sudo(self, args: tuple[str, ...], timeout: float, failure: str):
        try:
            result = self.runner.run(("sudo", "-n", *args), timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError(error.code) from error
        return result

    def _alive(self, timeout: float) -> bool:
        """Return whether the candidate is live, treating a zombie as gone.

        The hosted lane is itself run under a Linux subreaper.  A deliberately
        detached replacement therefore remains visible to ``kill -0`` as a
        zombie until that outer subreaper reaps it.  Waiting on ``kill -0``
        alone consequently deadlocks finalization.  Keep the signal probe for
        the normal liveness check, but pair it with a retained ``ps`` state
        probe and regard only an explicitly reported zombie as exited.
        """

        deadline = time.monotonic() + timeout
        result = self._sudo(
            ("kill", "-0", str(self.pid)),
            self._remaining(deadline, "SERVICE_PROBE_FAILED"),
            "SERVICE_PROBE_FAILED",
        )
        if result.timed_out:
            raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
        state = self._sudo(
            ("ps", "-o", "state=", "-p", str(self.pid)),
            self._remaining(deadline, "SERVICE_PROBE_FAILED"),
            "SERVICE_PROBE_FAILED",
        )
        if state.timed_out:
            raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
        if state.returncode != 0:
            # A real ``ps`` miss has no output.  Any retained diagnostic means
            # the probe itself failed and must not be mistaken for absence.
            if state.stdout_text.strip() or state.stderr.strip():
                raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
            # ``kill -0`` succeeded, so an empty failed ``ps`` response cannot
            # prove that the process is absent.  Treat it as a probe failure;
            # only a failed signal probe plus a clean ps miss is true absence.
            if result.returncode == 0:
                raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
            if result.stdout_text.strip() or result.stderr.strip():
                raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
            return False
        value = state.stdout_text.strip()
        if not value or value[0].upper() not in "RSDTXYZIKWPNL":
            raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
        if value[0].upper() == "Z":
            return False
        if result.returncode != 0:
            # The process is demonstrably present, so a failed signal probe
            # is a probe failure rather than evidence that it has exited.
            raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
        return True

    def _candidate_process_identity(self, timeout: float) -> tuple[str, int]:
        try:
            record = self._read_process_stat(self.pid, timeout)
        except ScenarioExecutionError as error:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED") from error
        if record is None:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED")
        return record.start, record.process_group

    def _read_process_stat(
        self, pid: int, timeout: float
    ) -> _LinuxProcessRecord | None:
        try:
            result = self.runner.run(
                (
                    "sudo", "-n", "sh", "-c", _LINUX_PROCESS_STAT_SCRIPT,
                    "dobbyvpn-process-stat", str(pid),
                ),
                timeout_seconds=timeout,
            )
        except HostedAdapterError as error:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED") from error
        if result.timed_out:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        if result.returncode != 0:
            # The helper emits an explicit absence marker.  Empty output or
            # any other marker is a failed probe, never evidence of exit.
            if (
                result.returncode == 2
                and result.stdout_text.strip() == "service_probe_absent"
                and not result.stderr.strip()
            ):
                return None
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        value = result.stdout_text.strip()
        try:
            prefix, fields = value.rsplit(") ", 1)
            actual_pid = int(prefix.split("(", 1)[0].strip())
            columns = fields.split()
            state = columns[0]
            parent = int(columns[1])
            process_group = int(columns[2])
            start = columns[19]
        except (ValueError, IndexError):
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED") from None
        if (
            actual_pid != pid
            or parent < 0
            or process_group <= 0
            or not start.isdigit()
            or int(start) <= 0
            or len(state) != 1
        ):
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        return _LinuxProcessRecord(
            pid, parent, process_group, start, state[0].upper()
        )

    def _census(self, timeout: float) -> dict[int, _LinuxProcessRecord]:
        try:
            result = self.runner.run(_LINUX_PROCESS_CENSUS, timeout_seconds=timeout)
        except HostedAdapterError as error:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED") from error
        if result.returncode != 0 or result.timed_out:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        try:
            return _parse_linux_process_census(result.stdout_text)
        except ValueError as error:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED") from error

    def _tracked_tree(self, timeout: float) -> tuple[_LinuxProcessRecord, ...]:
        deadline = time.monotonic() + timeout
        records = self._census(
            self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED")
        )
        topology = _linux_process_tree(records, self.pid)
        if not topology or topology[0].pid != self.pid:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        precise: list[_LinuxProcessRecord] = []
        for candidate in topology:
            current = self._read_process_stat(
                candidate.pid,
                self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED"),
            )
            if current is None:
                if candidate.pid == self.pid:
                    raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
                # A descendant can exit between the census and the stat
                # reads.  It needs no signal, while all remaining identities
                # are still proven from precise /proc start ticks.
                continue
            if current.parent != candidate.parent:
                raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
            precise.append(current)
        tree = tuple(precise)
        if not tree or tree[0].pid != self.pid:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        if self._replacement_identity is not None:
            root = tree[0]
            start, process_group = self._replacement_identity
            if root.start != start or root.process_group != process_group:
                raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
            # A process-group signal is safe only when the group is isolated
            # to the captured replacement tree.  Any unowned peer makes the
            # proof incomplete, so finalization fails closed.
            tree_pids = {record.pid for record in tree}
            if any(
                record.process_group == process_group and record.pid not in tree_pids
                for record in records.values()
            ):
                raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        return tree

    @staticmethod
    def _record_live(
        records: dict[int, _LinuxProcessRecord],
        expected: _LinuxProcessRecord,
    ) -> bool:
        current = records.get(expected.pid)
        return (
            current is not None
            and current.start == expected.start
            and current.state != "Z"
        )

    @staticmethod
    def _record_reused(
        records: dict[int, _LinuxProcessRecord],
        expected: _LinuxProcessRecord,
    ) -> bool:
        current = records.get(expected.pid)
        return current is not None and current.start != expected.start

    def _replacement_records(
        self, deadline: float
    ) -> tuple[tuple[_LinuxProcessRecord, ...], tuple[_LinuxProcessRecord, ...]]:
        survivors: list[_LinuxProcessRecord] = []
        reused: list[_LinuxProcessRecord] = []
        for expected in self._replacement_tree:
            current = self._read_process_stat(
                expected.pid,
                self._remaining(deadline, "SERVICE_FINALIZE_TIMEOUT"),
            )
            if current is None:
                continue
            if current.start != expected.start:
                reused.append(current)
                continue
            # A zombie has terminated and cannot execute or retain the
            # service's resources.  The outer hosted subreaper is responsible
            # for reaping it after this controller returns; requiring /proc to
            # disappear here would deadlock on an adopted child whose parent
            # is still inside the canonical lane.
            if current.state != "Z":
                survivors.append(current)
        return tuple(survivors), tuple(reused)

    def _wait_replacement_tree(self, deadline: float) -> tuple[_LinuxProcessRecord, ...]:
        while True:
            try:
                survivors, reused = self._replacement_records(deadline)
            except ScenarioExecutionError as error:
                if error.reason_code == "SERVICE_FINALIZE_TIMEOUT":
                    raise HostedAdapterError(error.reason_code) from error
                raise
            if reused:
                raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
            if not survivors:
                return ()
            if time.monotonic() >= deadline:
                raise HostedAdapterError("SERVICE_FINALIZE_TIMEOUT")
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))

    def _verify_candidate_pid(
        self, timeout: float = 5.0, *, deadline: float | None = None
    ) -> tuple[str, int]:
        if deadline is None:
            deadline = time.monotonic() + timeout
        else:
            self._remaining(deadline, "SERVICE_PID_PROBE_FAILED")
        try:
            result = self.runner.run(
                ("sudo", "-n", "readlink", "-f", f"/proc/{self.pid}/exe"),
                timeout_seconds=self._remaining(deadline, "SERVICE_PID_PROBE_FAILED"),
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
        expected_identity = self._replacement_identity or self._initial_identity
        observed = self._candidate_process_identity(
            self._remaining(deadline, "SERVICE_PID_PROBE_FAILED")
        )
        if expected_identity is not None and observed != expected_identity:
            raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
        return observed

    def _wait_dead(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # The process-loss operation has just sent SIGKILL.  Do not pair
            # a signal probe with a later ``ps`` probe here: the process can
            # exit between those two commands, and the otherwise useful
            # fail-closed liveness policy would misclassify that normal race
            # as SERVICE_PROBE_FAILED.  The bounded /proc identity helper is
            # the authoritative post-kill check and explicitly distinguishes
            # an absent process from a probe error.
            record = self._read_process_stat(
                self.pid,
                self._remaining(deadline, "SERVICE_DID_NOT_EXIT"),
            )
            if record is None or record.state == "Z":
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
        # Invalidate the predecessor token before launch.  A partial launch
        # must never leave an outer cleanup hook treating the old service as
        # the replacement authority.
        self._invalidate_identity_file()
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
        self._initial_identity = None
        self._replacement_identity = None
        self._replacement_tree = ()
        # Commit ownership as soon as the detached launcher proves the PID's
        # exact executable and /proc start token.  Readiness is a later
        # service property; if it fails, finalization can still safely clean
        # this owned but not-ready replacement.
        self._replacement_identity = _call_with_deadline(
            self._verify_candidate_pid,
            self._remaining(deadline, "SERVICE_RESTART_UNAVAILABLE"),
            deadline,
        )
        self._persist_identity(self._replacement_identity)
        # Persist only after ownership is committed.  If this write fails,
        # the in-memory identity remains available to the catch-path
        # finalizer, while a stale PID file is never treated as authority.
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
                # Recompute after the socket probe and keep the identity
                # proof on the canonical absolute restart deadline.
                _call_with_deadline(
                    self._verify_candidate_pid,
                    self._remaining(deadline, "SERVICE_RESTART_TIMEOUT"),
                    deadline,
                )
                self._replacement_tree = ()
                return
            time.sleep(min(0.5, remaining))

    def restart_after_loss(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        _call_with_deadline(
            self._verify_candidate_pid,
            self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"),
            deadline,
        )
        # Re-prove the initial service immediately adjacent to the
        # destructive signal.  PID reuse between the earlier validation and
        # this command must fail closed even when the replacement has not yet
        # been launched.
        _call_with_deadline(
            self._verify_candidate_pid,
            self._remaining(deadline, "SERVICE_PID_PROBE_FAILED"),
            deadline,
        )
        result = self._sudo(
            ("kill", "-KILL", str(self.pid)),
            self._remaining(deadline, "SERVICE_KILL_FAILED"),
            "SERVICE_KILL_FAILED",
        )
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_KILL_FAILED")
        self._wait_dead(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"))
        self._start(self._remaining(deadline, "PROCESS_LOSS_TIMEOUT"))

    def stop_restarted_service(
        self, timeout: float, *, deadline: float | None = None
    ) -> None:
        """Stop the exact service deliberately retained by a restart launcher."""

        if timeout <= 0:
            raise HostedAdapterError("INVALID_FINALIZE_TIMEOUT")
        if self._restart_number == 0:
            return
        if deadline is None:
            deadline = time.monotonic() + timeout
        elif deadline <= time.monotonic():
            raise HostedAdapterError("SERVICE_FINALIZE_TIMEOUT")

        def remaining(failure: str) -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise HostedAdapterError(failure)
            return value

        def alive() -> bool:
            return self._alive(min(5.0, remaining("SERVICE_FINALIZE_TIMEOUT")))

        if self._replacement_identity is None:
            raise HostedAdapterError("SERVICE_PID_PROBE_FAILED")
        if not alive():
            # The leader's disappearance is not a cleanup proof: tracked
            # descendants may have escaped its process group.  There is no
            # safe way to reconstruct an unobserved tree after the root is
            # gone, so fail closed instead of certifying a false pass.
            raise HostedAdapterError("SERVICE_TREE_PROBE_FAILED")
        _call_with_deadline(
            self._verify_candidate_pid,
            min(5.0, remaining("SERVICE_FINALIZE_TIMEOUT")),
            deadline,
        )

        tree = self._tracked_tree(
            min(5.0, remaining("SERVICE_TREE_PROBE_FAILED"))
        )
        _root_start, process_group = self._replacement_identity
        if tree[0].process_group != process_group:
            raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
        if tree[0].start == "":
            raise HostedAdapterError("SERVICE_TREE_PROBE_FAILED")
        self._replacement_tree = tree

        # Re-census the exact tree and process group immediately before the
        # first group signal.  The earlier check establishes ownership; this
        # one closes both the PID-reuse window and a late unrelated process
        # joining the captured PGID.
        tree = self._tracked_tree(
            min(5.0, remaining("SERVICE_TREE_PROBE_FAILED"))
        )
        self._replacement_tree = tree
        _call_with_deadline(
            self._verify_candidate_pid,
            min(5.0, remaining("SERVICE_FINALIZE_TIMEOUT")),
            deadline,
        )

        terminated = self._sudo(
            ("kill", "-TERM", "--", f"-{process_group}"),
            min(5.0, remaining("SERVICE_FINALIZE_TIMEOUT")),
            "SERVICE_FINALIZE_TERM_FAILED",
        )
        if terminated.returncode != 0:
            raise HostedAdapterError("SERVICE_FINALIZE_TERM_FAILED")

        term_remaining = remaining("SERVICE_FINALIZE_TIMEOUT")
        term_grace = min(5.0, term_remaining / 2.0)
        if term_grace <= 0:
            raise HostedAdapterError("SERVICE_FINALIZE_TIMEOUT")
        term_deadline = min(deadline, time.monotonic() + term_grace)
        try:
            self._wait_replacement_tree(term_deadline)
            return
        except HostedAdapterError as error:
            if error.code not in {"SERVICE_FINALIZE_TIMEOUT"}:
                raise

        # A resistant same-group descendant is covered by the group signal;
        # an escaped descendant must be checked and signaled by its captured
        # start identity individually. Never certify cleanup from a leader
        # disappearance alone.
        survivors, reused = self._replacement_records(deadline)
        if reused:
            raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
        if not survivors:
            return
        # If the root is still present, a second group-membership proof lets
        # us use the captured PGID for the final escalation.  If it has
        # already gone, do not signal that PGID (which may have been reused);
        # escaped survivors are handled by their own start-tick identities.
        root_record = self._read_process_stat(
            self.pid,
            min(5.0, remaining("SERVICE_PID_PROBE_FAILED")),
        )
        if root_record is not None:
            root_start, root_group = self._replacement_identity
            if root_record.start != root_start or root_record.process_group != root_group:
                raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
            # Before escalating to a PGID KILL, prove the current membership
            # again.  This prevents a process that joined the group after the
            # TERM census from being treated as owned by this replacement.
            final_tree = self._tracked_tree(
                min(5.0, remaining("SERVICE_TREE_PROBE_FAILED"))
            )
            self._replacement_tree = final_tree
            survivors, reused = self._replacement_records(deadline)
            if reused:
                raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
            if not survivors:
                return
            root_record = final_tree[0]
            if (
                root_record.pid != self.pid
                or root_record.start != root_start
                or root_record.process_group != root_group
            ):
                raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
        group_owned = root_record is not None
        for expected in survivors:
            if group_owned and expected.process_group == process_group:
                continue
            current = self._read_process_stat(
                expected.pid,
                min(5.0, remaining("SERVICE_FINALIZE_KILL_FAILED")),
            )
            if current is None or current.start != expected.start:
                raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
            killed = self._sudo(
                ("kill", "-KILL", str(expected.pid)),
                min(5.0, remaining("SERVICE_FINALIZE_KILL_FAILED")),
                "SERVICE_FINALIZE_KILL_FAILED",
            )
            if killed.returncode != 0:
                raise HostedAdapterError("SERVICE_FINALIZE_KILL_FAILED")

        if group_owned:
            # Revalidate the root's precise /proc start tick and group
            # immediately before the group KILL.  A PID reuse or group change
            # must never turn the final escalation into an unrelated-host kill.
            current_start, current_group = self._candidate_process_identity(
                min(5.0, remaining("SERVICE_PID_PROBE_FAILED"))
            )
            if (current_start, current_group) != self._replacement_identity:
                raise HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")
            killed = self._sudo(
                ("kill", "-KILL", "--", f"-{process_group}"),
                min(5.0, remaining("SERVICE_FINALIZE_TIMEOUT")),
                "SERVICE_FINALIZE_KILL_FAILED",
            )
            if killed.returncode != 0:
                # The group may already be gone while an escaped child
                # remains; the final tree proof below decides whether cleanup
                # succeeded.
                raise HostedAdapterError("SERVICE_FINALIZE_KILL_FAILED")
        self._wait_replacement_tree(deadline)


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
        identity_url: str | None = None,
        download_url: str | None = None,
        upload_url: str | None = None,
        service_pid: int | None = None,
        service_binary: Path | None = None,
        service_socket: Path | None = None,
        service_library_path: Path | None = None,
        service_pid_file: Path | None = None,
        service_identity_file: Path | None = None,
        network_interface: str | None = None,
    ) -> None:
        super().__init__(
            cli=cli, profile=profile, runner=runner,
            identity_url=identity_url,
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
                identity_file=service_identity_file,
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
        reasons = dict(super().capability_unavailable_reasons)
        if self.network_interface is None:
            reasons[Capability.NETWORK_TRANSITION] = "HOSTED_LINUX_INTERFACE_REQUIRED"
        return reasons

    def execute(self, step: ScenarioStep) -> dict[str, object]:
        if step.operation == "network_transition":
            return self._network_transition(float(step.timeout_seconds))
        if step.operation == "process_loss":
            return self._process_loss(float(step.timeout_seconds))
        return super().execute(step)

    def finalize(
        self, timeout_seconds: float = 30.0, *, deadline: float | None = None
    ) -> None:
        super().finalize(timeout_seconds, deadline=deadline)
        if self.service is not None:
            effective_deadline = deadline
            if effective_deadline is None:
                _call_with_deadline(
                    self.service.stop_restarted_service, timeout_seconds, None
                )
            else:
                _call_with_deadline(
                    self.service.stop_restarted_service,
                    self._remaining(effective_deadline, "SERVICE_FINALIZE_TIMEOUT"),
                    effective_deadline,
                )

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
        if not self._wait_for_routing_identity_changed(
            self._remaining(deadline, "PROCESS_LOSS_TIMEOUT")
        ):
            raise ScenarioExecutionError("PROCESS_LOSS_ROUTING_NOT_RECOVERED")
        return {"process_loss_verified": True}

__all__ = ["LinuxHostedAdapter", "LinuxServiceProcessController"]
