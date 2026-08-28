"""macOS hosted adapter using DobbyVPN's public CLI."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path
import re
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
)


_MACOS_SERVICE_LAUNCH_SCRIPT = """set -eu
binary=$1
log_path=$2
control_socket=$3
peer_uid=$4
# A replacement must own an isolated process group.  The shell launcher is
# short-lived, so use a Python child to call setsid() before exec'ing the
# service; the child keeps the launcher PID while the shell publishes it.
python3 - "$binary" "$log_path" "$control_socket" "$peer_uid" <<'PY' &
import os
import sys

binary, log_path, control_socket, peer_uid = sys.argv[1:]
os.setsid()
log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.dup2(log_fd, 1)
os.dup2(log_fd, 2)
if log_fd > 2:
    os.close(log_fd)
environment = os.environ.copy()
environment.update({
    "DOBBYVPN_CONTROL_SOCKET": control_socket,
    "DOBBYVPN_CONTROL_PEER_UID": peer_uid,
})
os.execve(binary, [binary], environment)
PY
printf '%s\\n' "$!"
"""
_MACOS_SOCKET_PROBE = """import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(0.5)
    connection.connect(sys.argv[1])
"""
_MACOS_PROCESS_CENSUS = ("sudo", "-n", "ps", "-axo", "pid=,ppid=,pgid=,state=")
_MACOS_PROCESS_ALIVE_SCRIPT = r'''
import subprocess
import sys

pid = sys.argv[1]
try:
    result = subprocess.run(
        ("ps", "-p", pid, "-o", "pid="),
        capture_output=True,
        text=True,
        check=False,
    )
except Exception:
    print("service_probe_error")
    raise SystemExit(1)
if result.returncode == 0 and result.stdout.strip() == pid:
    print("service_probe_pid=" + pid)
    raise SystemExit(0)
if result.returncode != 0 and not result.stdout.strip() and not result.stderr.strip():
    print("service_probe_absent")
    raise SystemExit(2)
print("service_probe_error")
raise SystemExit(1)
'''
_MACOS_PROCESS_ALIVE = (
    "sudo", "-n", "python3", "-c", _MACOS_PROCESS_ALIVE_SCRIPT, "{pid}"
)
_MACOS_PROCESS_IDENTITY_SCRIPT = r"""
import ctypes
import ctypes.util
import os
import sys

class ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]

pid = int(sys.argv[1])
try:
    os.kill(pid, 0)
except ProcessLookupError:
    print("service_probe_absent")
    raise SystemExit(2)
except OSError:
    print("service_probe_error")
    raise SystemExit(1)
library_name = ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib"
if not library_name:
    print("service_probe_error")
    raise SystemExit(1)
libproc = ctypes.CDLL(library_name, use_errno=True)
libproc.proc_pidinfo.argtypes = [
    ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
    ctypes.c_void_p, ctypes.c_int,
]
libproc.proc_pidinfo.restype = ctypes.c_int
info = ProcBsdInfo()
size = libproc.proc_pidinfo(
    pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)
)
path = ctypes.create_string_buffer(4096)
libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
libproc.proc_pidpath.restype = ctypes.c_int
path_size = libproc.proc_pidpath(pid, path, ctypes.sizeof(path))
if size == 0 or path_size == 0:
    # A zero libproc result is not by itself an absence proof: permissions,
    # a transient API failure, and an exited process all produce zero.  The
    # second kill(2) probe is the explicit absence discriminator; if the
    # process is still signal-visible, fail closed as a probe error.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        print("service_probe_absent")
        raise SystemExit(2)
    except OSError:
        print("service_probe_error")
        raise SystemExit(1)
    print("service_probe_error")
    raise SystemExit(1)
if (
    size != ctypes.sizeof(info)
    or info.pbi_pid != pid
    or info.pbi_start_tvsec <= 0
    or info.pbi_start_tvusec >= 1000000
    or path_size < 0
):
    print("service_probe_error")
    raise SystemExit(1)
print("service_identity=%d|%d.%06d" % (
    pid, info.pbi_start_tvsec, info.pbi_start_tvusec,
))
print("service_path=" + path.value.decode("utf-8", errors="replace"))
"""
_MACOS_PROCESS_IDENTITY = (
    "sudo", "-n", "python3", "-c", _MACOS_PROCESS_IDENTITY_SCRIPT, "{pid}"
)


def _parse_macos_process_census(stdout: str) -> dict[int, tuple[int, str]]:
    """Parse the bounded ``ps`` census into PID, parent, and start identity."""

    processes: dict[int, tuple[int, str]] = {}
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        pid = int(fields[0])
        parent = int(fields[1])
        start = " ".join(fields[2:])
        if pid > 0 and parent >= 0 and start:
            processes[pid] = (parent, start)
    return processes


def _parse_macos_process_census_strict(
    stdout: str,
) -> dict[int, "_MacOSProcessRecord"]:
    """Parse a complete process/PGID census, rejecting malformed rows."""

    processes: dict[int, _MacOSProcessRecord] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4 or not all(value.isdigit() for value in fields[:3]):
            raise ValueError("malformed process census row")
        pid, parent, process_group = (int(value) for value in fields[:3])
        state = fields[3].upper()
        if (
            pid <= 0
            or parent < 0
            or process_group <= 0
            or len(state) != 1
        ):
            raise ValueError("invalid process census row")
        if pid in processes:
            raise ValueError("duplicate process census PID")
        processes[pid] = _MacOSProcessRecord(pid, parent, process_group, state)
    return processes


@dataclass(frozen=True)
class _MacOSProcessRecord:
    pid: int
    parent: int
    process_group: int
    state: str


def _macos_process_record_tree(
    processes: dict[int, _MacOSProcessRecord], root_pid: int
) -> tuple[_MacOSProcessRecord, ...]:
    """Return root and descendants from one strict process census."""

    children: dict[int, list[int]] = {}
    for record in processes.values():
        children.setdefault(record.parent, []).append(record.pid)
    pending = [root_pid]
    seen: set[int] = set()
    tree: list[_MacOSProcessRecord] = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        record = processes.get(pid)
        if record is None:
            continue
        tree.append(record)
        pending.extend(children.get(pid, ()))
    return tuple(tree)


def _macos_process_tree(
    processes: dict[int, tuple[int, str]], root_pid: int
) -> tuple[tuple[int, str], ...]:
    """Return the root and all descendants using one complete census."""

    children: dict[int, list[int]] = {}
    for pid, (parent, _start) in processes.items():
        children.setdefault(parent, []).append(pid)
    pending = [root_pid]
    seen: set[int] = set()
    tree: list[tuple[int, str]] = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        current = processes.get(pid)
        if current is None:
            continue
        parent, start = current
        tree.append((pid, start))
        pending.extend(children.get(pid, ()))
    return tuple(tree)


def _parse_macos_process_identity(
    stdout: str, pid: int
) -> tuple[str, str]:
    """Parse one native identity/path pair without accepting extras."""

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
        or int(parts[0]) != pid
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]{6}", parts[1]) is None
        or int(parts[1].split(".", 1)[1]) >= 1_000_000
        or not path
    ):
        raise ValueError("invalid process identity")
    return f"{pid}|{parts[1]}", path


def _default_control_socket() -> Path:
    configured = os.environ.get("DOBBYVPN_CONTROL_SOCKET")
    if configured:
        return Path(configured)
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        return Path(runtime_dir) / "DobbyVPN" / "control.sock"
    return Path.home() / "Library" / "Application Support" / "DobbyVPN" / "control.sock"


class MacOSServiceProcessController(HostedServiceProcessController):
    """Restart the exact macOS service binary and prove its Unix socket."""

    def __init__(
        self,
        *,
        pid: int,
        binary: Path,
        pid_file: Path | None,
        identity_file: Path | None = None,
        runner: CommandRunner,
        raw_directory: Path,
        control_socket: Path,
    ) -> None:
        if not control_socket.is_absolute():
            raise HostedAdapterError("SERVICE_CONTROL_SOCKET_INVALID")
        super().__init__(
            pid=pid,
            binary=binary,
            pid_file=pid_file,
            identity_file=identity_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        self.control_socket = control_socket
        self._tree_identities: tuple[tuple[int, str], ...] = ()
        self._initial_identity: str | None = None
        self._replacement_identity: str | None = None
        self._owned_process_group: int | None = None
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
        try:
            pid_text, native_start = identity.split("|", 1)
            value = {
                "command": str(self.binary.resolve()),
                "native_start": native_start,
                "pid": int(pid_text),
                # Keep the historical field populated for older readers; new
                # cleanup paths prefer native_start.
                "start": native_start,
            }
            temporary = self.identity_file.with_name(f".{self.identity_file.name}.tmp")
            self.identity_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(self.identity_file)
            self.identity_file.chmod(0o600)
        except (OSError, ValueError, TypeError) as error:
            raise ScenarioExecutionError("SERVICE_IDENTITY_PERSIST_FAILED") from error

    def _alive(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        presence = self._probe(
            tuple(value.format(pid=self.pid) for value in _MACOS_PROCESS_ALIVE),
            self._remaining(deadline, "SERVICE_PROBE_FAILED"),
            "SERVICE_PROBE_FAILED",
        )
        if presence.returncode == 0:
            if presence.stdout_text.strip() != f"service_probe_pid={self.pid}":
                raise ScenarioExecutionError("SERVICE_PROBE_FAILED")
            return True
        if (
            presence.returncode == 2
            and presence.stdout_text.strip() == "service_probe_absent"
            and not presence.stderr.strip()
        ):
            return False
        raise ScenarioExecutionError("SERVICE_PROBE_FAILED")

    def _process_identity(
        self, pid: int, timeout: float, *, check_path: bool
    ) -> str | None:
        result = self._probe(
            tuple(value.format(pid=pid) for value in _MACOS_PROCESS_IDENTITY),
            timeout,
            "SERVICE_PID_PROBE_FAILED",
        )
        if result.returncode != 0:
            if (
                result.returncode == 2
                and result.stdout_text.strip() == "service_probe_absent"
                and not result.stderr.strip()
            ):
                return None
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        try:
            identity, path = _parse_macos_process_identity(
                result.stdout_text, pid
            )
        except ValueError:
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        expected = str(self.binary.resolve())
        if check_path and os.path.normcase(path) != os.path.normcase(expected):
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        return identity

    def _candidate_process_identity(self, timeout: float) -> str:
        identity = self._process_identity(self.pid, timeout, check_path=True)
        if identity is None:
            raise ScenarioExecutionError("SERVICE_PID_PROBE_FAILED")
        return identity

    def _terminate(self, timeout: float, *, deadline: float | None = None) -> None:
        if deadline is None:
            deadline = time.monotonic() + timeout
        expected_root = self._replacement_identity or self._initial_identity
        known: dict[int, str] = {}
        kill_failed = False

        def capture() -> tuple[
            dict[int, _MacOSProcessRecord],
            tuple[_MacOSProcessRecord, ...],
            tuple[_MacOSProcessRecord, ...],
        ]:
            snapshot = self._census(
                self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED")
            )
            root = snapshot.get(self.pid)
            if root is not None:
                # The launch script creates a process group whose leader is the
                # exact service PID.  Refuse to signal a shared inherited group.
                if root.process_group != self.pid:
                    raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
                self._owned_process_group = root.process_group
                topology = _macos_process_record_tree(snapshot, self.pid)
                if not topology or topology[0].pid != self.pid:
                    raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
            elif self._owned_process_group is None:
                raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
            else:
                topology = ()
            group_records = tuple(
                record
                for record in snapshot.values()
                if record.process_group == self._owned_process_group
                and record.state != "Z"
            )
            if root is not None and not group_records:
                raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
            return snapshot, topology, group_records

        # Establish ownership from a complete census before any signal.  This
        # also proves that the replacement's root group is isolated.
        _snapshot, topology, group_records = capture()
        if not topology or topology[0].pid != self.pid:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        for record in group_records:
            identity = self._process_identity(
                record.pid,
                self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED"),
                check_path=record.pid == self.pid,
            )
            if identity is None:
                if record.pid == self.pid:
                    raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
                continue
            known[record.pid] = identity
        root_identity = known.get(self.pid)
        if root_identity is None:
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        if expected_root is not None and root_identity != expected_root:
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")

        while time.monotonic() < deadline:
            # Recensus immediately before every signaling pass.  New children
            # are added to the owned set, including descendants that appeared
            # after the original census; a changed native token is a hard stop.
            _snapshot, topology, group_records = capture()
            current_records = {record.pid: record for record in group_records}
            topology_ids = {
                record.pid for record in topology if record.state != "Z"
            }
            for record in topology:
                # A zombie has no signalable executable and is already gone
                # for cleanup purposes.  Do not send it through the native
                # identity probe, which correctly treats a zombie's missing
                # proc_pidpath as a probe failure.
                if record.state != "Z":
                    current_records[record.pid] = record
            survivors: list[tuple[int, str]] = []
            for pid, record in current_records.items():
                current = self._process_identity(
                    pid,
                    self._remaining(deadline, "SERVICE_PID_PROBE_FAILED"),
                    check_path=pid == self.pid,
                )
                if current is None:
                    continue
                expected = known.get(pid)
                if expected is not None and current != expected:
                    raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
                known[pid] = current
                survivors.append((pid, current))
            # Processes that escaped the parent tree retain their previously
            # proven native identity and must still be checked/terminated.
            for pid, expected in tuple(known.items()):
                if pid in current_records:
                    continue
                current = self._process_identity(
                    pid,
                    self._remaining(deadline, "SERVICE_PID_PROBE_FAILED"),
                    check_path=pid == self.pid,
                )
                if current is None:
                    continue
                if current != expected:
                    raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
                survivors.append((pid, current))
            self._tree_identities = tuple(sorted(known.items()))
            if not survivors:
                # A full census must prove that the isolated group is empty;
                # root disappearance alone is never a success condition.
                final_snapshot = self._census(
                    self._remaining(deadline, "SERVICE_TREE_PROBE_FAILED")
                )
                if any(
                    record.process_group == self._owned_process_group
                    and record.state != "Z"
                    for record in final_snapshot.values()
                ):
                    continue
                return

            # Revalidate the exact root identity immediately before group
            # signal, and every escaped process immediately before its signal.
            group_alive = any(
                record.process_group == self._owned_process_group
                and record.state != "Z"
                for record in current_records.values()
            )
            # A process can join a PGID without appearing as a descendant in
            # this census.  Do not broad-signal such a mixed group; the
            # individually revalidated identities below are the safe path.
            group_members_are_owned = all(
                record.pid in topology_ids for record in group_records
            )
            if group_alive and group_members_are_owned:
                current_root = self._process_identity(
                    self.pid,
                    self._remaining(deadline, "SERVICE_PID_PROBE_FAILED"),
                    check_path=True,
                )
                if current_root is None or current_root != known.get(self.pid):
                    raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
                result = self._probe(
                    (
                        "sudo",
                        "-n",
                        "kill",
                        "-KILL",
                        f"-{self._owned_process_group}",
                    ),
                    self._remaining(deadline, "SERVICE_KILL_FAILED"),
                    "SERVICE_KILL_FAILED",
                )
                if result.returncode != 0:
                    kill_failed = True
            for pid, expected in survivors:
                record = current_records.get(pid)
                if (
                    group_members_are_owned
                    and record is not None
                    and record.process_group == self._owned_process_group
                ):
                    continue
                current = self._process_identity(
                    pid,
                    self._remaining(deadline, "SERVICE_PID_PROBE_FAILED"),
                    check_path=pid == self.pid,
                )
                if current is None:
                    continue
                if current != expected:
                    raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
                result = self._probe(
                    ("sudo", "-n", "kill", "-KILL", str(pid)),
                    self._remaining(deadline, "SERVICE_KILL_FAILED"),
                    "SERVICE_KILL_FAILED",
                )
                if result.returncode != 0:
                    kill_failed = True
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if kill_failed:
            raise ScenarioExecutionError("SERVICE_KILL_FAILED")
        raise ScenarioExecutionError("SERVICE_TREE_SURVIVED")

    def _census(self, timeout: float) -> dict[int, _MacOSProcessRecord]:
        result = self._probe(
            _MACOS_PROCESS_CENSUS,
            timeout,
            "SERVICE_TREE_PROBE_FAILED",
        )
        if result.returncode != 0:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED")
        try:
            return _parse_macos_process_census_strict(result.stdout_text)
        except ValueError as error:
            raise ScenarioExecutionError("SERVICE_TREE_PROBE_FAILED") from error

    def _verify_candidate_pid(self, timeout: float) -> str:
        identity = self._candidate_process_identity(timeout)
        expected = self._replacement_identity or self._initial_identity
        if expected is not None and identity != expected:
            raise ScenarioExecutionError("SERVICE_PID_NOT_CANDIDATE")
        return identity

    def _control_ready(self, timeout: float) -> bool:
        result = self._probe(
            (
                "python3",
                "-c",
                _MACOS_SOCKET_PROBE,
                str(self.control_socket),
            ),
            timeout,
            "SERVICE_CONTROL_PROBE_FAILED",
        )
        return result.returncode == 0

    def _start(self, timeout: float) -> None:
        self._restart_number += 1
        log_path = _allocate_owner_only_path(
            self.raw_directory,
            f"service-restart-{self._restart_number:03d}",
            ".raw.log",
        )
        deadline = time.monotonic() + timeout
        # Invalidate the predecessor sidecar before launching.  A partial
        # replacement must never leave outer cleanup believing the old
        # identity is authoritative.
        self._invalidate_identity_file()
        command = (
            "sudo",
            "-n",
            "sh",
            "-c",
            _MACOS_SERVICE_LAUNCH_SCRIPT,
            "dobbyvpn-service",
            str(self.binary),
            str(log_path),
            str(self.control_socket),
            str(os.getuid()),
        )
        # The launcher exits while the replacement remains alive.  The
        # ordinary runner intentionally proves and kills all command
        # descendants, so use its explicit detached path when available and
        # leave the exact replacement to this controller's finalizer.
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
        # Commit ownership immediately after the launcher proves the exact
        # native start token/path.  Readiness may fail later, but this token
        # permits safe catch-path cleanup of the owned partial replacement.
        self._replacement_identity = self._verify_candidate_pid(
            self._remaining(deadline, "SERVICE_RESTART_UNAVAILABLE")
        )
        self._persist_identity(self._replacement_identity)
        # Keep the proven identity in memory before PID-file persistence: a
        # write failure must not orphan a valid replacement from finalization.
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


def _service_pid(value: str) -> int | None:
    if value.isdigit() and 0 < int(value) <= 9_999_999_999:
        return int(value)
    return None


class MacOSHostedAdapter(HostedCLIAdapter):
    adapter_id = "hosted-macos-cli"
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
            control_socket = service_socket or _default_control_socket()
            self.service: MacOSServiceProcessController | None = MacOSServiceProcessController(
                pid=service_pid,
                binary=service_binary,
                pid_file=service_pid_file,
                identity_file=service_identity_file,
                runner=runner,
                raw_directory=raw_directory,
                control_socket=control_socket,
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
        reasons[Capability.NETWORK_TRANSITION] = "HOSTED_MACOS_UPLINK_TOGGLE_UNSUPPORTED"
        return reasons

    def finalize(
        self, timeout_seconds: float = 30.0, *, deadline: float | None = None
    ) -> None:
        super().finalize(timeout_seconds, deadline=deadline)
        if self.service is not None:
            if deadline is None:
                deadline = time.monotonic() + timeout_seconds
            elif deadline <= time.monotonic():
                raise ScenarioExecutionError("SERVICE_FINALIZE_TIMEOUT")
            _call_with_deadline(
                self.service.finalize_restarted_service,
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


__all__ = ["MacOSHostedAdapter", "MacOSServiceProcessController"]
