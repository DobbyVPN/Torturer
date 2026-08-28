"""Secretless public Linux desktop verification for one DobbyVPN checkout.

This is deliberately a black-box slice.  It only calls the candidate's public
desktop build entry point and its native operator CLI.  The fixture is
an invalid local file: it contains no profile, endpoint, credential, or URL,
so the check must reject it before any tunnel can be started.

Run from the Torturer checkout::

    python3 -m torturer_checks.linux_slice --candidate /path/to/DobbyVPN \
        --commit-sha 0123456789abcdef0123456789abcdef01234567

The candidate must be a Linux/amd64 checkout with the dependencies documented
by ``.github/scripts/desktop_build.py`` already installed.  By default the
slice passes ``--skip-deps`` to make that prerequisite explicit and prevent the
check from installing system packages or downloading toolchains.  Use
``--allow-bootstrap`` only in a disposable runner when the candidate build is
allowed to provision its documented local tools.

It is intentionally not a real VPN test: it does not invoke ``connect`` or
``verify-session``, install a package, use a provider profile, or make an
external-IP assertion.  Packaging is not covered until the public candidate
build exposes a package without signing material.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO, Callable, Sequence

from torturer_checks.public_output import emit_evidence


SERVICE_RELATIVE_PATH = Path("kmp_module/services/ubuntu_grpcvpnserver")
CLI_RELATIVE_PATH = Path("kmp_module/services/dobby-cli")
BUILD_SCRIPT_RELATIVE_PATH = Path(".github/scripts/desktop_build.py")
GRADLE_RELATIVE_PATH = Path("kmp_module/gradlew")
MALFORMED_CONFIG_NAME = "malformed-public-fixture.toml"
# No valid TOML profile table, endpoint, credential, hostname, or routable URL.
MALFORMED_CONFIG = "[\nthis cannot be parsed as TOML\n"
MAX_RUN_SECONDS = 30 * 60
CLEANUP_RESERVE_SECONDS = 120
MAX_FUNCTIONAL_SECONDS = MAX_RUN_SECONDS - CLEANUP_RESERVE_SECONDS
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
COMMAND_TERMINATION_GRACE_SECONDS = 15
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
_FAILURE_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s]+")
_FAILURE_AUTH_SCHEME = re.compile(r"(?i)\b(?:bearer|basic)\s+[^\s,;]+")
_FAILURE_SECRET = re.compile(
    r'''(?ix)
    (?P<label>
        ["']?
        \b(?:
            token|access[_-]?token|refresh[_-]?token|id[_-]?token|
            password|passwd|secret|client[_-]?secret|credential|
            api[_-]?key|private[_-]?key|authorization|cookie
        )\b
        ["']?
        \s*[:=]\s*
    )
    (?:(?:bearer|basic)\s+)?
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)
    '''
)


class SliceFailure(RuntimeError):
    """One required public-contract assertion did not hold."""


def safe_failure_reason(error: BaseException) -> str:
    """Return one useful, secretless line for the hosted status boundary."""

    message = str(error).splitlines()[0].strip() if str(error) else ""
    if not message:
        return "unspecified failure"
    message = _FAILURE_URL.sub("<redacted-url>", message)
    message = _FAILURE_SECRET.sub(r"\g<label><redacted>", message)
    message = _FAILURE_AUTH_SCHEME.sub("<redacted-auth>", message)
    return message


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    stdout_bytes: bytes = b""
    stderr_bytes: bytes = b""

    def describe(self) -> str:
        return (
            f"command_result exit_code={self.returncode} "
            f"stdout_bytes={len(self.stdout_bytes)} "
            f"stdout_sha256={hashlib.sha256(self.stdout_bytes).hexdigest()} "
            f"stderr_bytes={len(self.stderr_bytes)} "
            f"stderr_sha256={hashlib.sha256(self.stderr_bytes).hexdigest()}"
        )


class RunBudget:
    """Track one Linux lane's hard deadline and reserved cleanup window."""

    def __init__(
        self,
        *,
        max_seconds: float = MAX_RUN_SECONDS,
        cleanup_reserve_seconds: float = CLEANUP_RESERVE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_seconds <= 0 or cleanup_reserve_seconds < 0 or cleanup_reserve_seconds >= max_seconds:
            raise ValueError("cleanup reserve must be non-negative and smaller than the run deadline")
        self.max_seconds = float(max_seconds)
        self.cleanup_reserve_seconds = float(cleanup_reserve_seconds)
        self.clock = clock
        self.started_at = clock()

    @property
    def deadline(self) -> float:
        return self.started_at + self.max_seconds

    def operation_timeout(self, requested: float | None = None) -> float:
        """Return a timeout that cannot consume the reserved cleanup window."""

        remaining = self.deadline - self.clock() - self.cleanup_reserve_seconds
        if remaining <= 0:
            raise SliceFailure("Linux lane exhausted its functional budget before cleanup reserve")
        if requested is None:
            return remaining
        if requested <= 0:
            raise SliceFailure("Linux lane operation timeout must be positive")
        return min(float(requested), remaining)

    def cleanup_timeout(self) -> float:
        """Return the remaining bounded cleanup window."""

        return max(0.0, min(self.cleanup_reserve_seconds, self.deadline - self.clock()))

    def assert_within_deadline(self) -> None:
        if self.clock() > self.deadline:
            raise SliceFailure("Linux lane exceeded its strict 1800-second deadline")


def _lane_operation_timeout(timeout_seconds: float, operation: str) -> float:
    """Keep reusable Linux primitives inside the lane's functional budget."""

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise SliceFailure(f"{operation} timeout must be positive and finite")
    if timeout_seconds > MAX_FUNCTIONAL_SECONDS:
        raise SliceFailure(
            f"{operation} timeout would consume the reserved {CLEANUP_RESERVE_SECONDS:g}-second cleanup window"
        )
    return float(timeout_seconds)


def candidate_path(value: str) -> Path:
    """Return a checked-out candidate root, rejecting a partial/wrong tree."""

    root = Path(value).expanduser().resolve()
    required = (
        root / BUILD_SCRIPT_RELATIVE_PATH,
        root / GRADLE_RELATIVE_PATH,
        root / "go_module",
        root / "kmp_module",
    )
    missing = [str(path.relative_to(root)) for path in required if not path.exists()]
    if missing:
        raise SliceFailure(
            "candidate is not a DobbyVPN checkout with the public desktop build "
            f"interfaces: missing {', '.join(missing)}"
        )
    return root


def build_command(root: Path, *, skip_dependencies: bool) -> list[str]:
    """Build the Linux service through the candidate's documented entry point."""

    command = [
        sys.executable,
        str(root / BUILD_SCRIPT_RELATIVE_PATH),
        "libs",
        "--platform",
        "linux",
        "--arch",
        "amd64",
    ]
    if skip_dependencies:
        command.append("--skip-deps")
    return command


def app_build_command(root: Path, *, skip_dependencies: bool) -> list[str]:
    """Build the desktop application and native CLI without rebuilding the service."""

    command = [
        sys.executable,
        str(root / BUILD_SCRIPT_RELATIVE_PATH),
        "app",
        "--platform",
        "linux",
        "--skip-libs",
    ]
    if skip_dependencies:
        command.append("--skip-deps")
    return command


def cli_command(root: Path, *arguments: str) -> list[str]:
    """Run the candidate's built native operator CLI directly."""

    return [str(root / CLI_RELATIVE_PATH), *arguments]


def emit_command_diagnostics(result: CommandResult) -> None:
    """Publish only metadata after the caller has retained complete streams."""

    emit_evidence(
        "linux-command",
        status=("failed" if result.returncode != 0 else "completed"),
        payloads={"stdout": result.stdout_bytes, "stderr": result.stderr_bytes},
    )


def _safe_evidence_stem(label: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("._")
    return stem or "command"


def _retain_bytes(path: Path, payload: bytes) -> None:
    """Create one owner-only evidence file without following or replacing paths."""

    if path.exists() or path.is_symlink():
        raise SliceFailure(f"refusing to overwrite existing Linux evidence: {path}")
    with path.open("xb", buffering=0) as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    path.chmod(0o600)


def _retain_command_streams(
    evidence_directory: Path | None,
    label: str,
    stdout: bytes,
    stderr: bytes,
) -> None:
    """Retain complete original command streams in an owner-only directory."""

    if evidence_directory is None:
        raise SliceFailure("Linux command diagnostics require an owner-only evidence directory")
    if evidence_directory.is_symlink():
        raise SliceFailure("Linux command evidence directory must not be a symlink")
    evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence_directory.chmod(0o700)
    stem = _safe_evidence_stem(label)
    _retain_bytes(evidence_directory / f"{stem}.stdout.raw.log", stdout)
    _retain_bytes(evidence_directory / f"{stem}.stderr.raw.log", stderr)


def _retain_exception(evidence_directory: Path | None, label: str, error: BaseException) -> None:
    if evidence_directory is None:
        raise SliceFailure("Linux startup diagnostics require an owner-only evidence directory")
    if evidence_directory.is_symlink():
        raise SliceFailure("Linux command evidence directory must not be a symlink")
    evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence_directory.chmod(0o700)
    _retain_bytes(
        evidence_directory / f"{_safe_evidence_stem(label)}.exception.raw.log",
        (f"exception={type(error).__name__}: {error}\n").encode("utf-8", errors="replace"),
    )


def _process_group_alive(process: subprocess.Popen[bytes]) -> bool:
    """Return whether the complete POSIX process group still has a member."""

    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _proc_descendants(root_pid: int) -> set[int]:
    """Return a recursive snapshot of descendants, including detached children."""

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        raise SliceFailure("cannot inspect the Linux process tree because /proc is unavailable")
    parent_by_pid: dict[int, int] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_line = (entry / "stat").read_text(encoding="ascii")
            close = stat_line.rfind(")")
            fields = stat_line[close + 2 :].split()
            parent_by_pid[int(entry.name)] = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
    descendants: set[int] = set()
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        for child, child_parent in parent_by_pid.items():
            if child_parent == parent and child not in descendants:
                descendants.add(child)
                frontier.append(child)
    return descendants


def _pid_alive(pid: int) -> bool:
    """Return whether a PID is still running, treating unreadable state as alive."""

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = stat_line.rfind(")")
        fields = stat_line[close + 2 :].split()
        return bool(fields) and fields[0] != "Z"
    except FileNotFoundError:
        return False
    except (OSError, ValueError, IndexError):
        return True


def _wait_for_process_tree(
    process: subprocess.Popen[bytes],
    tracked: set[int],
    timeout_seconds: float,
) -> bool:
    """Wait for the leader, process group, and detached descendants to disappear."""

    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        tracked.update(_proc_descendants(process.pid))
        leader_gone = process.poll() is not None
        if (
            leader_gone
            and not _process_group_alive(process)
            and not any(_pid_alive(pid) for pid in tracked if pid != process.pid)
        ):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            pass


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float,
    description: str,
    tracked: set[int] | None = None,
) -> set[int]:
    """Terminate and prove disappearance of the full POSIX process group."""

    process_id = getattr(process, "pid", None)
    if process_id is None:
        # Preserve the lightweight fake-process seam used by direct tests.
        if process.poll() is None:
            terminate = getattr(process, "terminate", None)
            if callable(terminate):
                terminate()
            else:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=max(0.0, grace_seconds))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=max(1.0, grace_seconds))
        if process.poll() is None:
            raise SliceFailure(f"{description} process survived termination")
        return set()

    tracked = tracked if tracked is not None else set()
    tracked.update({process_id} | _proc_descendants(process_id))
    try:
        os.killpg(process_id, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for pid in tracked:
        if pid == process_id:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    if _wait_for_process_tree(process, tracked, grace_seconds):
        return tracked

    print(f"[torturer-process] {description} graceful-stop-expired", file=sys.stderr)
    try:
        os.killpg(process_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    tracked.update(_proc_descendants(process_id))
    for pid in tracked:
        if pid == process_id:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if not _wait_for_process_tree(process, tracked, max(0.0, grace_seconds)):
        raise SliceFailure(f"{description} POSIX process group survived forced termination")
    return tracked


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    evidence_directory: Path | None = None,
    evidence_label: str = "command",
) -> CommandResult:
    """Execute an argument vector with a hard timeout and complete evidence."""

    if timeout_seconds <= 0:
        raise SliceFailure("Linux command timeout must be positive")
    argv = tuple(command)
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=env,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        try:
            _retain_exception(evidence_directory, evidence_label, error)
        except SliceFailure as retention_error:
            raise retention_error from error
        raise SliceFailure(f"Linux command could not start (diagnostics retained privately): {type(error).__name__}") from error

    timed_out = False
    tracked: set[int] = {process.pid}
    termination_error: SliceFailure | None = None
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = error.output or b""
        stderr = error.stderr or b""
        print(
            f"[torturer-command] timeout after {timeout_seconds:g}s; terminating process tree",
            file=sys.stderr,
        )
        try:
            tracked = _terminate_process_tree(
                process,
                grace_seconds=min(COMMAND_TERMINATION_GRACE_SECONDS, max(1.0, timeout_seconds)),
                description="command",
                tracked=tracked,
            )
        except SliceFailure as cleanup_error:
            termination_error = cleanup_error
            print(f"[torturer-command] cleanup-error={cleanup_error}", file=sys.stderr)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            recovered_stdout, recovered_stderr = process.communicate(
                timeout=max(1.0, COMMAND_TERMINATION_GRACE_SECONDS)
            )
        except subprocess.TimeoutExpired as drain_error:
            termination_error = termination_error or SliceFailure(
                "command diagnostics could not be completely drained after forced termination"
            )
            recovered_stdout = drain_error.output or b""
            recovered_stderr = drain_error.stderr or b""
            try:
                tracked = _terminate_process_tree(
                    process,
                    grace_seconds=COMMAND_TERMINATION_GRACE_SECONDS,
                    description="command-final-drain",
                    tracked=tracked,
                )
            except SliceFailure as cleanup_error:
                termination_error = termination_error or cleanup_error
            try:
                final_stdout, final_stderr = process.communicate(
                    timeout=max(1.0, COMMAND_TERMINATION_GRACE_SECONDS)
                )
            except subprocess.TimeoutExpired as final_error:
                termination_error = termination_error or SliceFailure(
                    "command process tree and diagnostic pipes survived final cleanup"
                )
                final_stdout = final_error.output or b""
                final_stderr = final_error.stderr or b""
            recovered_stdout += final_stdout
            recovered_stderr += final_stderr
        stdout = stdout + recovered_stdout if recovered_stdout else stdout
        stderr = stderr + recovered_stderr if recovered_stderr else stderr

        try:
            if not _wait_for_process_tree(process, tracked, 0.0):
                termination_error = termination_error or SliceFailure(
                    "command process tree remained after final diagnostic drain"
                )
        except SliceFailure as cleanup_error:
            termination_error = termination_error or cleanup_error

    result = CommandResult(
        argv,
        process.returncode if process.returncode is not None else -1,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
        stdout,
        stderr,
    )
    retention_error: SliceFailure | None = None
    try:
        _retain_command_streams(evidence_directory, evidence_label, stdout, stderr)
    except SliceFailure as error:
        retention_error = error
        print(f"[torturer-command] evidence-error={error}", file=sys.stderr)
    if retention_error is not None:
        raise retention_error
    emit_evidence(
        "linux-command",
        status=("timed-out" if timed_out else ("failed" if result.returncode != 0 else "completed")),
        payloads={"stdout": stdout, "stderr": stderr},
    )
    if termination_error is not None:
        raise SliceFailure(f"{termination_error}\n{result.describe()}") from termination_error
    if timed_out:
        raise SliceFailure(f"command timed out after {timeout_seconds:g}s\n{result.describe()}")
    return result


def require_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        raise SliceFailure(f"{description} failed\n{result.describe()}")


def require_nonzero(result: CommandResult, description: str) -> None:
    if result.returncode == 0:
        raise SliceFailure(f"{description} unexpectedly succeeded\n{result.describe()}")


def _link_state(output: str) -> tuple[tuple[str, ...], str] | None:
    """Parse one ``ip -o link`` record without accepting an ambiguous state."""

    match = re.search(r"<([^>]*)>.*?\bstate\s+(\S+)", output)
    if match is None:
        return None
    return tuple(match.group(1).split(",")), match.group(2)


def _link_is_up(output: str, interface: str) -> bool:
    """Require both the requested interface identity and an explicit UP state."""

    if re.search(
        rf"(?m)^\s*\d+:\s*{re.escape(interface)}(?:@[^ :]+)?\s*:",
        output,
    ) is None:
        return False
    parsed = _link_state(output)
    return parsed is not None and "UP" in parsed[0] and parsed[1] == "UP"


def _start_delayed_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    delay_seconds: float,
    evidence_label: str,
    evidence_directory: Path | None,
) -> tuple[subprocess.Popen[bytes], tuple[str, ...]]:
    """Start (but do not wait for) an autonomous local repair process."""

    delayed = (
        sys.executable,
        "-c",
        "import subprocess,sys,time; time.sleep(float(sys.argv[1])); "
        "raise SystemExit(subprocess.call(sys.argv[2:]))",
        str(max(0.0, delay_seconds)),
        *command,
    )
    try:
        process = subprocess.Popen(
            list(delayed), cwd=cwd, env=env, stdin=None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError as error:
        _retain_exception(evidence_directory, evidence_label, error)
        raise SliceFailure(f"{evidence_label} could not start: {error}") from error
    return process, delayed


def _finish_delayed_process(
    process: subprocess.Popen[bytes],
    command: tuple[str, ...],
    *,
    timeout_seconds: float,
    evidence_directory: Path | None,
    evidence_label: str,
) -> CommandResult:
    """Bound, drain, and retain the complete output of a started repair."""

    tracked = {process.pid}
    try:
        stdout, stderr = process.communicate(timeout=max(0.1, timeout_seconds))
    except subprocess.TimeoutExpired as error:
        stdout = error.output or b""
        stderr = error.stderr or b""
        _terminate_process_tree(
            process, grace_seconds=min(COMMAND_TERMINATION_GRACE_SECONDS, max(1.0, timeout_seconds)),
            description=evidence_label, tracked=tracked,
        )
        recovered_stdout, recovered_stderr = process.communicate(timeout=max(1.0, COMMAND_TERMINATION_GRACE_SECONDS))
        stdout += recovered_stdout
        stderr += recovered_stderr
        _retain_command_streams(evidence_directory, evidence_label, stdout, stderr)
        result = CommandResult(
            command, process.returncode if process.returncode is not None else -1,
            stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), stdout, stderr,
        )
        emit_command_diagnostics(result)
        raise SliceFailure(f"{evidence_label} timed out\n{result.describe()}") from error
    _retain_command_streams(evidence_directory, evidence_label, stdout, stderr)
    result = CommandResult(
        command, process.returncode if process.returncode is not None else -1,
        stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), stdout, stderr,
    )
    emit_command_diagnostics(result)
    return result


def probe_linux_capabilities(
    *,
    cwd: Path,
    env: dict[str, str],
    evidence_directory: Path | None,
) -> frozenset[str]:
    """Advertise optional Linux operations only after live prerequisite probes."""

    capabilities = {
        "configure", "connect", "tunnel_interface", "routing_identity",
        "traffic_measurement", "disconnect", "resource_cleanup", "reconnect",
    }

    def successful(label: str, command: Sequence[str]) -> CommandResult | None:
        try:
            result = run_command(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=10.0,
                evidence_directory=evidence_directory,
                evidence_label=label,
            )
        except SliceFailure:
            return None
        return result if result.returncode == 0 else None

    ip_tool = successful("capability-ip", ("sh", "-c", "command -v ip"))
    sudo = successful("capability-sudo", ("sudo", "-n", "true"))
    default_route = successful(
        "capability-default-route",
        ("ip", "-o", "route", "show", "default"),
    )
    if (
        ip_tool is not None
        and sudo is not None
        and default_route is not None
        and default_route.stdout.strip()
    ):
        capabilities.add("network_transition")

    power_state = successful("capability-power-state", ("cat", "/sys/power/state"))
    rtcwake = successful("capability-rtcwake", ("sh", "-c", "command -v rtcwake"))
    if (
        power_state is not None
        and "mem" in power_state.stdout.split()
        and rtcwake is not None
        and sudo is not None
    ):
        capabilities.add("sleep_wake")

    process_tools = all(
        successful(f"capability-{name}", ("sh", "-c", f"command -v {name}")) is not None
        for name in ("ps", "kill", "readlink")
    )
    if process_tools:
        capabilities.add("process_loss")
    return frozenset(capabilities)


def run_network_transition(
    interface: str,
    *,
    control_interface: str,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    evidence_directory: Path | None,
) -> dict[str, object]:
    """Toggle a physical uplink, prove both states, and use an independent repair path."""

    timeout_seconds = _lane_operation_timeout(timeout_seconds, "network transition")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise SliceFailure("network transition interface is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", control_interface):
        raise SliceFailure("network transition control interface is invalid")
    if interface == control_interface:
        raise SliceFailure("network transition would destroy its control path")
    deadline = time.monotonic() + timeout_seconds
    before = run_command(
        ("ip", "-o", "link", "show", "dev", interface), cwd=cwd, env=env,
        timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
        evidence_directory=evidence_directory, evidence_label="network-link-before",
    )
    before_state = _link_state(before.stdout)
    if before.returncode != 0 or before_state is None or not _link_is_up(before.stdout, interface):
        raise SliceFailure("network transition uplink was not proved up before toggle")
    control_before = run_command(
        ("ip", "-o", "link", "show", "dev", control_interface), cwd=cwd, env=env,
        timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
        evidence_directory=evidence_directory, evidence_label="network-control-before",
    )
    if control_before.returncode != 0 or not _link_is_up(control_before.stdout, control_interface):
        raise SliceFailure("network transition control path was not proved up before toggle")

    repair = None
    repair_process: subprocess.Popen[bytes] | None = None
    repair_command: tuple[str, ...] | None = None
    primary_error: SliceFailure | None = None
    try:
        repair_process, repair_command = _start_delayed_process(
            ("sudo", "-n", "ip", "link", "set", "dev", interface, "up"),
            cwd=cwd, env=env, evidence_directory=evidence_directory,
            evidence_label="network-autonomous-repair",
            delay_seconds=min(3.0, max(0.0, timeout_seconds / 3.0)),
        )
    except SliceFailure as error:
        primary_error = error
    try:
        down = run_command(
            ("sudo", "-n", "ip", "link", "set", "dev", interface, "down"), cwd=cwd, env=env,
            timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
            evidence_directory=evidence_directory, evidence_label="network-link-down",
        )
        state = run_command(
            ("ip", "-o", "link", "show", "dev", interface), cwd=cwd, env=env,
            timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
            evidence_directory=evidence_directory, evidence_label="network-link-down-state",
        )
        down_state = _link_state(state.stdout)
        if down.returncode != 0 or state.returncode != 0 or down_state is None or "UP" in down_state[0] or down_state[1] != "DOWN":
            raise SliceFailure("network transition down state was not proved")
    except SliceFailure as error:
        primary_error = primary_error or error
    if repair_process is not None and repair_command is not None:
        try:
            repair = _finish_delayed_process(
                repair_process, repair_command,
                timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
                evidence_directory=evidence_directory, evidence_label="network-autonomous-repair",
            )
        except SliceFailure as error:
            primary_error = primary_error or error
    elif primary_error is None:
        primary_error = SliceFailure("network autonomous repair did not start")
    if repair is not None and repair.returncode != 0:
        primary_error = primary_error or SliceFailure("network autonomous repair failed")
    after = run_command(
        ("ip", "-o", "link", "show", "dev", interface), cwd=cwd, env=env,
        timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
        evidence_directory=evidence_directory, evidence_label="network-link-restored-state",
    )
    after_state = _link_state(after.stdout)
    if after.returncode != 0 or after_state is None or not _link_is_up(after.stdout, interface):
        primary_error = primary_error or SliceFailure("network transition restored state was not proved")
    control_after = run_command(
        ("ip", "-o", "link", "show", "dev", control_interface), cwd=cwd, env=env,
        timeout_seconds=min(10.0, max(0.1, deadline - time.monotonic())),
        evidence_directory=evidence_directory, evidence_label="network-control-after",
    )
    if control_after.returncode != 0 or not _link_is_up(control_after.stdout, control_interface):
        primary_error = primary_error or SliceFailure("network transition control path was not preserved")
    if primary_error is not None:
        raise primary_error
    return {"network_transition_verified": time.monotonic() <= deadline}


def run_sleep_wake(
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    evidence_directory: Path | None,
) -> dict[str, object]:
    """Run a bounded kernel sleep/wake and prove elapsed BOOTTIME plus cleanup."""

    timeout_seconds = _lane_operation_timeout(timeout_seconds, "sleep/wake")
    started_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if evidence_directory is not None:
        evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _retain_bytes(evidence_directory / f"sleep-wake-start-{time.time_ns()}.raw.log", f"{started_ns}\n".encode())
    result = run_command(
        ("sudo", "-n", "rtcwake", "-m", "mem", "-s", "5"), cwd=cwd, env=env,
        timeout_seconds=timeout_seconds, evidence_directory=evidence_directory,
        evidence_label="sleep-wake-kernel",
    )
    ended_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    elapsed_ns = ended_ns - started_ns
    if evidence_directory is not None:
        _retain_bytes(evidence_directory / f"sleep-wake-end-{time.time_ns()}.raw.log", f"{ended_ns}\n".encode())
        _retain_bytes(evidence_directory / f"sleep-wake-validation-{time.time_ns()}.raw.log", f"boottime_elapsed_ns={elapsed_ns}\n".encode())
    if result.returncode != 0 or elapsed_ns < 4_000_000_000:
        raise SliceFailure("kernel sleep/wake elapsed proof was not established")
    return {"sleep_wake_verified": True, "boottime_elapsed_ns": elapsed_ns}


def run_transfer_metrics(
    download_url: str,
    upload_url: str,
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    evidence_directory: Path | None,
) -> dict[str, float]:
    """Run curl metrics with unique retained stdout and stderr for every probe."""

    timeout_seconds = _lane_operation_timeout(timeout_seconds, "transfer metrics")
    if not download_url or not upload_url:
        raise SliceFailure("transfer URLs are required")
    deadline = time.monotonic() + timeout_seconds
    latency = run_command(
        ("curl", "--show-error", "--fail", "--max-time", str(max(1, int(timeout_seconds))),
         "--output", os.devnull, "--write-out", "%{time_total},%{http_code}", download_url),
        cwd=cwd, env=env, timeout_seconds=max(0.1, deadline - time.monotonic()),
        evidence_directory=evidence_directory, evidence_label=f"curl-latency-{time.time_ns()}",
    )
    download = run_command(
        ("curl", "--show-error", "--fail", "--max-time", str(max(1, int(timeout_seconds))),
         "--output", os.devnull, "--write-out", "%{speed_download},%{http_code}", download_url),
        cwd=cwd, env=env, timeout_seconds=max(0.1, deadline - time.monotonic()),
        evidence_directory=evidence_directory, evidence_label=f"curl-download-{time.time_ns()}",
    )
    upload = run_command(
        ("curl", "--show-error", "--fail", "--max-time", str(max(1, int(timeout_seconds))),
         "--request", "POST", "--upload-file", os.devnull, "--write-out", "%{speed_upload},%{http_code}", upload_url),
        cwd=cwd, env=env, timeout_seconds=max(0.1, deadline - time.monotonic()),
        evidence_directory=evidence_directory, evidence_label=f"curl-upload-{time.time_ns()}",
    )

    def metric(result: CommandResult, label: str) -> float:
        fields = result.stdout.strip().split(",")
        if result.returncode != 0 or len(fields) != 2 or not fields[0] or not fields[1].startswith("2"):
            raise SliceFailure(f"{label} metric failed; complete curl evidence was retained")
        try:
            value = float(fields[0])
        except ValueError as error:
            raise SliceFailure(f"{label} metric was malformed") from error
        if not math.isfinite(value) or value < 0:
            raise SliceFailure(f"{label} metric was non-finite or negative")
        return value

    return {
        "latency_ms": metric(latency, "latency") * 1000.0,
        "download_mbps": metric(download, "download") * 8.0 / 1_000_000.0,
        "upload_mbps": metric(upload, "upload") * 8.0 / 1_000_000.0,
    }


def verify_expected_process(
    pid: int,
    expected_binary: Path,
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    evidence_directory: Path | None,
) -> None:
    """Bind the process-loss PID to the exact candidate executable before killing it."""

    timeout_seconds = _lane_operation_timeout(timeout_seconds, "process identity")
    if pid <= 0 or not expected_binary.is_file() or expected_binary.is_symlink():
        raise SliceFailure("expected product process identity is unavailable")
    result = run_command(
        ("sudo", "-n", "readlink", "-f", f"/proc/{pid}/exe"), cwd=cwd, env=env,
        timeout_seconds=timeout_seconds, evidence_directory=evidence_directory,
        evidence_label=f"process-identity-{pid}",
    )
    actual = Path(result.stdout.strip()).resolve() if result.returncode == 0 and result.stdout.strip() else None
    if actual is None or actual != expected_binary.resolve():
        raise SliceFailure("process PID is not bound to the expected product executable")


def wait_for_socket(path: Path, process: subprocess.Popen[bytes], timeout_seconds: float) -> None:
    """Wait for a real owner-only Unix socket while detecting an early exit."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SliceFailure(f"service exited before readiness (exit code {process.returncode})")
        try:
            details = path.stat()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        if not stat.S_ISSOCK(details.st_mode):
            raise SliceFailure(f"control path exists but is not a Unix socket: {path}")
        if stat.S_IMODE(details.st_mode) != 0o600:
            raise SliceFailure(
                f"control socket permissions are {stat.S_IMODE(details.st_mode):o}, expected 600"
            )
        return
    raise SliceFailure(f"service did not create its Unix control socket within {timeout_seconds:g}s: {path}")


def stop_service(
    process: subprocess.Popen[bytes],
    socket_path: Path,
    *,
    timeout_seconds: float = COMMAND_TERMINATION_GRACE_SECONDS,
) -> None:
    """Terminate the complete service process group and remove only its socket."""

    _terminate_process_tree(
        process,
        grace_seconds=max(0.0, timeout_seconds),
        description="service",
    )

    # The current service has no signal handler that closes its listener.  A
    # process killed by SIGTERM can therefore leave the pathname behind; remove
    # only the socket owned by this per-run directory and verify it is gone.
    if socket_path.exists() or socket_path.is_socket():
        details = socket_path.lstat()
        if not stat.S_ISSOCK(details.st_mode):
            raise SliceFailure(f"refusing to remove non-socket cleanup path: {socket_path}")
        socket_path.unlink()
    if socket_path.exists() or socket_path.is_socket():
        raise SliceFailure(f"control socket remained after cleanup: {socket_path}")


def service_environment(services_dir: Path, socket_path: Path) -> dict[str, str]:
    """Constrain the service to this unprivileged test user's private runtime dir."""

    environment = os.environ.copy()
    environment.update(
        {
            "DOBBYVPN_CONTROL_SOCKET": str(socket_path),
            "DOBBYVPN_CONTROL_PEER_UID": str(os.getuid()),
            "LD_LIBRARY_PATH": str(services_dir),
        }
    )
    return environment


def assert_cli_contract(
    root: Path,
    environment: dict[str, str],
    fixture: Path,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    """Exercise safe CLI surfaces against the ready service, never a tunnel."""

    budget = budget or RunBudget()
    help_result = run_command(
        cli_command(root, "--help"),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
        evidence_directory=evidence_directory,
        evidence_label="cli-help",
    )
    require_success(help_result, "CLI help")
    if "check-config" not in help_result.stdout or "verify-session" not in help_result.stdout:
        raise SliceFailure(f"CLI help did not expose the documented command surface\n{help_result.describe()}")

    status_result = run_command(
        cli_command(root, "status", "--json"),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
        evidence_directory=evidence_directory,
        evidence_label="cli-status",
    )
    require_success(status_result, "CLI status")
    if '"state": "Disconnected"' not in status_result.stdout:
        raise SliceFailure(f"CLI did not report the initial disconnected state\n{status_result.describe()}")

    malformed_result = run_command(
        cli_command(root, "check-config", str(fixture)),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
        evidence_directory=evidence_directory,
        evidence_label="cli-check-config",
    )
    require_nonzero(malformed_result, "CLI malformed local configuration rejection")

    disconnect_result = run_command(
        cli_command(root, "disconnect"),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
        evidence_directory=evidence_directory,
        evidence_label="cli-disconnect",
    )
    require_success(disconnect_result, "CLI disconnect after malformed input")


def verify_candidate_checkout(
    root: Path,
    expected_commit: str,
    *,
    budget: RunBudget,
    evidence_directory: Path | None,
) -> None:
    """Verify exact clean source identity with the same bounded runner as all commands."""

    if FULL_SHA.fullmatch(expected_commit) is None:
        raise SliceFailure("commit SHA must be exactly 40 lowercase hexadecimal characters")
    actual = run_command(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        cwd=root,
        env=os.environ.copy(),
        timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
        evidence_directory=evidence_directory,
        evidence_label="source-rev-parse",
    )
    require_success(actual, "candidate source identity check")
    if actual.stdout.strip() != expected_commit:
        raise SliceFailure("candidate HEAD does not match the requested commit")
    tracked = run_command(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        env=os.environ.copy(),
        timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
        evidence_directory=evidence_directory,
        evidence_label="source-status",
    )
    require_success(tracked, "candidate source cleanliness check")
    if tracked.stdout.strip():
        raise SliceFailure("candidate checkout has modified tracked files")


def _emit_and_retain_service_log(path: Path, evidence_directory: Path | None) -> None:
    """Retain the complete service log before publishing only safe metadata."""

    if not path.is_file():
        return
    if evidence_directory is None:
        raise SliceFailure("Linux service diagnostics require an owner-only evidence directory")
    if evidence_directory.is_symlink():
        raise SliceFailure("Linux service evidence directory must not be a symlink")
    payload = path.read_bytes()
    evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence_directory.chmod(0o700)
    _retain_bytes(evidence_directory / "service.combined.raw.log", payload)
    emit_evidence("linux-service", status="retained", payloads={"service": payload})


def _open_owner_only_service_log(path: Path) -> BinaryIO:
    """Create the service log exclusively and enforce its owner-only mode.

    The returned object is a binary ``FileIO`` stream, so permission changes
    must target the path (or its integer file descriptor), not the stream
    object itself.  Keeping this operation in one helper makes the security
    boundary testable without launching the full desktop build.
    """

    service_log = path.open("xb", buffering=0)
    try:
        # Bind the mode change to the exclusively opened descriptor. A path
        # chmod would introduce a replacement window between open and chmod.
        os.fchmod(service_log.fileno(), 0o600)
    except BaseException:
        service_log.close()
        raise
    return service_log


def run_slice(
    candidate: Path,
    *,
    expected_commit: str,
    skip_dependencies: bool,
    timeout_seconds: float,
) -> None:
    """Build, launch, verify and clean up one candidate.  Any missing phase fails."""

    budget = RunBudget()
    root = candidate_path(str(candidate))
    configured_evidence = os.environ.get("TORTURER_EVIDENCE_DIR")
    if configured_evidence:
        evidence_root = Path(configured_evidence).expanduser()
        evidence_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        # Keep the default bundle under the ignored checkout results directory;
        # a failed run must remain discoverable after the process exits.
        results_root = Path.cwd() / "results"
        results_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        results_root.chmod(0o700)
        evidence_root = Path(tempfile.mkdtemp(prefix="linux-evidence-", dir=results_root))
    evidence_root.chmod(0o700)
    verify_candidate_checkout(
        root,
        expected_commit,
        budget=budget,
        evidence_directory=evidence_root,
    )
    build_environment = os.environ.copy()
    require_success(
        run_command(
            build_command(root, skip_dependencies=skip_dependencies),
            cwd=root,
            env=build_environment,
            timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
            evidence_directory=evidence_root,
            evidence_label="service-build",
        ),
        "public Linux service build",
    )
    require_success(
        run_command(
            app_build_command(root, skip_dependencies=skip_dependencies),
            cwd=root,
            env=build_environment,
            timeout_seconds=budget.operation_timeout(DEFAULT_COMMAND_TIMEOUT_SECONDS),
            evidence_directory=evidence_root,
            evidence_label="application-build",
        ),
        "public desktop application and native CLI build",
    )

    service = root / SERVICE_RELATIVE_PATH
    if not service.is_file() or not os.access(service, os.X_OK):
        raise SliceFailure(f"public build did not produce an executable Linux service: {service}")
    cli = root / CLI_RELATIVE_PATH
    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise SliceFailure(f"public build did not produce an executable Linux operator CLI: {cli}")

    with tempfile.TemporaryDirectory(prefix="torturer-linux-") as temporary:
        runtime = Path(temporary)
        runtime.chmod(0o700)
        socket_path = runtime / "control.sock"
        fixture = runtime / MALFORMED_CONFIG_NAME
        fixture.write_text(MALFORMED_CONFIG, encoding="utf-8")
        fixture.chmod(0o600)
        environment = service_environment(service.parent, socket_path)
        service_log_path = runtime / "service.combined.log"
        with _open_owner_only_service_log(service_log_path) as service_log:
            process = subprocess.Popen(
                [str(service)],
                cwd=root,
                env=environment,
                stdin=None,
                stdout=service_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            phase_error: SliceFailure | None = None
            try:
                wait_for_socket(
                    socket_path,
                    process,
                    budget.operation_timeout(timeout_seconds),
                )
                assert_cli_contract(
                    root,
                    environment,
                    fixture,
                    budget=budget,
                    evidence_directory=evidence_root,
                )
            except SliceFailure as error:
                phase_error = error
            finally:
                try:
                    stop_service(
                        process,
                        socket_path,
                        timeout_seconds=budget.cleanup_timeout(),
                    )
                except SliceFailure as cleanup_error:
                    if phase_error is None:
                        phase_error = cleanup_error
                    else:
                        phase_error = SliceFailure(
                            f"{phase_error}; cleanup failed: {cleanup_error}"
                        )
                finally:
                    service_log.flush()
                    os.fsync(service_log.fileno())
                    _emit_and_retain_service_log(service_log_path, evidence_root)
            if phase_error is not None:
                raise phase_error
    budget.assert_within_deadline()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, help="Path to the checked-out DobbyVPN candidate.")
    parser.add_argument("--commit-sha", required=True, help="Exact lowercase 40-character candidate commit SHA.")
    parser.add_argument(
        "--allow-bootstrap",
        action="store_true",
        help="Allow desktop_build.py to install/download its documented dependencies.",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="Service readiness timeout in seconds.")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        run_slice(
            Path(args.candidate),
            expected_commit=args.commit_sha,
            skip_dependencies=not args.allow_bootstrap,
            timeout_seconds=args.timeout,
        )
    except SliceFailure as error:
        print(
            f"linux_slice status=failed code={type(error).__name__} "
            f"reason={safe_failure_reason(error)}",
            file=sys.stderr,
        )
        return 1
    print("Torturer Linux slice passed: build, Unix service readiness, safe CLI rejection, and cleanup verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
