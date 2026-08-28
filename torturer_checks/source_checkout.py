"""Exact-source checks shared by public candidate executors.

Git is an external preflight dependency, so every invocation is bounded,
supervised as a process tree, and retained as complete owner-only evidence.
Hosted output exposes only safe evidence metadata; the retained originals are
never replaced by a derived error message.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Sequence

from torturer_checks.public_output import emit_evidence


FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")

# Git preflight is only a small part of the hosted 30-minute lane. These
# bounds leave ample room for the canonical scenarios and the lane's cleanup
# reserve while preventing a stuck Git process from consuming the lane.
MAX_PREFLIGHT_SECONDS = 1800
GIT_COMMAND_TIMEOUT_SECONDS = 30
GIT_TERMINATION_GRACE_SECONDS = 10
# Short synthetic and diagnostic preflights need proportionally more time for
# process-tree proof and durable evidence writes than normal 30-second Git
# checks.  The ten-second cap keeps production observation budgets unchanged
# once they are large enough, while reserving half of very small bounds avoids
# scheduling-dependent deadline overruns during mandatory cleanup.
PREFLIGHT_CLEANUP_RESERVE_FRACTION = 0.5
MIN_PREFLIGHT_CLEANUP_RESERVE_SECONDS = 0.01


class SourceCheckoutError(RuntimeError):
    """The candidate checkout is not the exact clean revision requested."""


class EvidenceRetentionError(SourceCheckoutError):
    """An original evidence file could not be completely retained."""

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        super().__init__(message)
        self.path = path


@dataclass(frozen=True)
class PreflightResult:
    """Complete original output from one bounded preflight command."""

    command: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    evidence_directory: Path | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    metadata_path: Path | None = None
    evidence_complete: bool = True
    process_tree_proven: bool = True
    survivor_pids: tuple[int, ...] = ()
    cleanup_errors: tuple[str, ...] = ()
    elapsed_seconds: float = 0.0
    cleanup_reserve_seconds: float = 0.0
    deadline_exceeded: bool = False
    # Process-census output is a diagnostic stream in its own right.  Keep it
    # separate from the child-owned stderr bytes so retaining diagnostics does
    # not mutate either original command stream.
    tree_diagnostics: bytes = b""
    tree_diagnostics_path: Path | None = None


@dataclass(frozen=True)
class TreeCleanup:
    """Bounded process-tree cleanup result."""

    process_tree_proven: bool
    survivor_pids: tuple[int, ...] = ()
    error: str | None = None


def _safe_stem(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return stem or "preflight"


def _validate_evidence_path(
    directory: Path,
    *,
    allow_missing_final: bool = False,
    host_os: str | None = None,
) -> None:
    """Reject unsafe evidence paths with platform-correct permissions.

    The default evidence directory is created by ``tempfile.mkdtemp`` and
    resolved by ``_evidence_directory`` before validation, allowing an
    OS-managed alias such as macOS ``/var``. Explicit configured paths still
    receive the strict symlink checks below. Windows ACLs are not represented
    by POSIX mode bits, so Unix owner/mode checks are intentionally skipped on
    that platform while path-target checks remain enforced.
    """

    validation_os = host_os or os.name
    posix_permissions = validation_os == "posix"

    if not directory.is_absolute():
        raise SourceCheckoutError(f"preflight evidence directory must be absolute: {directory}")

    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            # The caller creates missing components with mode 0700, then
            # validates the complete path again.
            break
        if stat.S_ISLNK(info.st_mode):
            raise SourceCheckoutError(f"preflight evidence path contains a symlink: {current}")
        if not stat.S_ISDIR(info.st_mode):
            raise SourceCheckoutError(f"preflight evidence path is not a directory: {current}")
        if (
            posix_permissions
            and current != directory
            and (info.st_mode & stat.S_IWOTH)
            and not (info.st_mode & stat.S_ISVTX)
        ):
            raise SourceCheckoutError(f"preflight evidence ancestor is world-writable: {current}")

    try:
        info = os.lstat(directory)
    except FileNotFoundError as error:
        if allow_missing_final:
            return
        raise SourceCheckoutError(f"preflight evidence directory was not created: {directory}") from error
    if stat.S_ISLNK(info.st_mode):
        raise SourceCheckoutError(f"preflight evidence directory must not be a symlink: {directory}")
    if not stat.S_ISDIR(info.st_mode):
        raise SourceCheckoutError(f"preflight evidence path is not a directory: {directory}")
    if posix_permissions and hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise SourceCheckoutError(f"preflight evidence directory is not owner-controlled: {directory}")
    if posix_permissions and info.st_mode & 0o077:
        raise SourceCheckoutError(f"preflight evidence directory must be mode 0700: {directory}")


def _evidence_directory(requested: Path | None) -> Path:
    configured = requested or os.environ.get("TORTURER_PREFLIGHT_EVIDENCE_DIR")
    if configured:
        directory = Path(configured).expanduser()
    else:
        # Keep a local original even when a caller did not provide its normal
        # retained-results directory. It is owner-only and intentionally not
        # removed by this helper, so a failed run remains diagnosable.
        # macOS exposes its temporary root through /var -> /private/var. The
        # directory was just created by mkdtemp, so resolving only this
        # OS-managed path is safe and does not weaken explicit-path checks.
        directory = Path(tempfile.mkdtemp(prefix="torturer-preflight-evidence-")).resolve()
    if not directory.is_absolute():
        raise SourceCheckoutError(f"preflight evidence directory must be absolute: {directory}")
    _validate_evidence_path(directory, allow_missing_final=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_evidence_path(directory)
    return directory


def _retain_file(directory: Path, filename: str, payload: bytes) -> Path:
    path = directory / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise SourceCheckoutError(f"refusing to overwrite existing preflight evidence: {path}") from error
    except OSError as error:
        raise EvidenceRetentionError(
            f"could not create owner-only preflight evidence: {path}", path=path
        ) from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            _write_payload(output, payload)
            output.flush()
            os.fsync(output.fileno())
        path.chmod(0o600)
    except Exception as error:
        # Never remove a partial original. The metadata record written by the
        # caller marks this path evidence-incomplete and preserves its bytes.
        raise EvidenceRetentionError(
            f"could not completely retain original evidence; partial file preserved: {path}",
            path=path,
        ) from error
    return path


def _write_payload(output: object, payload: bytes) -> None:
    getattr(output, "write")(payload)


def _retain_stream(directory: Path, stem: str, suffix: str, payload: bytes) -> Path:
    return _retain_file(directory, f"{_safe_stem(stem)}.{suffix}.raw.log", payload)


def _emit_result(
    result: PreflightResult,
    evidence_directory: Path,
    evidence_stem: str,
    *,
    deadline: float | None = None,
    started_at: float | None = None,
) -> PreflightResult:
    retained: dict[str, Path | None] = {
        "stdout": None,
        "stderr": None,
        "tree_diagnostics": None,
    }
    retention_errors: list[str] = []
    for name, payload in (("stdout", result.stdout), ("stderr", result.stderr)):
        try:
            retained[name] = _retain_stream(evidence_directory, evidence_stem, name, payload)
        except SourceCheckoutError as error:
            path = getattr(error, "path", None)
            if path is not None:
                retained[name] = path
            retention_errors.append(str(error))

    if result.tree_diagnostics:
        try:
            retained["tree_diagnostics"] = _retain_stream(
                evidence_directory,
                evidence_stem,
                "process-tree-census",
                result.tree_diagnostics,
            )
        except SourceCheckoutError as error:
            path = getattr(error, "path", None)
            if path is not None:
                retained["tree_diagnostics"] = path
            retention_errors.append(str(error))

    evidence_complete = result.evidence_complete and not retention_errors
    elapsed_seconds = result.elapsed_seconds
    if started_at is not None:
        elapsed_seconds = max(elapsed_seconds, time.monotonic() - started_at)
    deadline_exceeded = result.deadline_exceeded or (
        deadline is not None and time.monotonic() > deadline
    )
    metadata = {
        "schema": "torturer.preflight.evidence.v1",
        "command": list(result.command),
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "evidence_directory": str(evidence_directory),
        "stdout_path": str(retained["stdout"]) if retained["stdout"] else None,
        "stderr_path": str(retained["stderr"]) if retained["stderr"] else None,
        "process_tree_census_path": (
            str(retained["tree_diagnostics"]) if retained["tree_diagnostics"] else None
        ),
        "process_tree_proven": result.process_tree_proven,
        "survivor_pids": list(result.survivor_pids),
        "cleanup_errors": list(result.cleanup_errors),
        "elapsed_seconds": elapsed_seconds,
        "cleanup_reserve_seconds": result.cleanup_reserve_seconds,
        "deadline_exceeded": deadline_exceeded,
        "evidence_complete": evidence_complete,
        "evidence_incomplete": not evidence_complete,
        "retention_errors": retention_errors,
    }
    metadata_path = evidence_directory / f"{_safe_stem(evidence_stem)}.metadata.raw.json"
    metadata_written = False
    try:
        _retain_file(
            evidence_directory,
            metadata_path.name,
            (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        metadata_written = True
    except SourceCheckoutError as error:
        retention_errors.append(str(error))
        evidence_complete = False

    emitted = replace(
        result,
        evidence_directory=evidence_directory,
        stdout_path=retained["stdout"],
        stderr_path=retained["stderr"],
        tree_diagnostics_path=retained["tree_diagnostics"],
        metadata_path=metadata_path if metadata_written else None,
        evidence_complete=evidence_complete,
        elapsed_seconds=elapsed_seconds,
        deadline_exceeded=deadline_exceeded,
    )
    emit_evidence(
        "source-preflight",
        status=("timed-out" if result.timed_out else ("failed" if result.returncode != 0 else "completed")),
        payloads={
            "stdout": emitted.stdout,
            "stderr": emitted.stderr,
            "process-tree-census": emitted.tree_diagnostics,
        },
    )
    if retention_errors:
        raise SourceCheckoutError("preflight evidence incomplete\n" + "\n".join(retention_errors))
    return emitted


def _preflight_cleanup_reserve(timeout_seconds: float) -> float:
    """Reserve part of the caller's total bound for cleanup and evidence."""

    return min(
        GIT_TERMINATION_GRACE_SECONDS,
        max(
            MIN_PREFLIGHT_CLEANUP_RESERVE_SECONDS,
            timeout_seconds * PREFLIGHT_CLEANUP_RESERVE_FRACTION,
        ),
    )


def _remaining_until(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, max(0.0, cap))


def _process_group_alive(process: subprocess.Popen[bytes]) -> bool:
    if os.name == "nt":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _proc_descendants(
    root_pid: int,
    *,
    process: subprocess.Popen[bytes] | None = None,
    deadline: float | None = None,
) -> set[int]:
    """Return a bounded recursive descendant snapshot for detached children.

    On Windows the process-group primitive does not contain descendants.  Use
    the Toolhelp census shared by the hosted Windows adapter when available;
    callers pass the launched process so an unavailable census remains an
    explicit, unprovable state instead of becoming a false clean result.
    """

    parent_by_pid: dict[int, int] = {}
    reliable = True
    census_diagnostics = bytearray()
    if os.name == "nt":
        try:
            from torturer_checks.hosted.cli import _process_snapshot

            snapshot = _process_snapshot(deadline=deadline)
        except (ImportError, OSError, TypeError, ValueError):
            snapshot = None
        if snapshot is None:
            reliable = False
        else:
            parent_by_pid = {pid: values[0] for pid, values in snapshot.items()}
    else:
        proc_root = Path("/proc")
        if proc_root.is_dir():
            try:
                for entry in proc_root.iterdir():
                    if deadline is not None and time.monotonic() >= deadline:
                        reliable = False
                        census_diagnostics.extend(b"procfs-census-deadline=1\n")
                        break
                    if not entry.name.isdigit():
                        continue
                    try:
                        stat_line = (entry / "stat").read_text(encoding="ascii")
                        close = stat_line.rfind(")")
                        fields = stat_line[close + 2 :].split()
                        parent_by_pid[int(entry.name)] = int(fields[1])
                    except FileNotFoundError:
                        continue
                    except (OSError, UnicodeError, ValueError, IndexError) as error:
                        reliable = False
                        census_diagnostics.extend(
                            f"procfs-census-entry={entry.name} error={error!r}\n".encode(
                                "utf-8", errors="replace"
                            )
                        )
                    if deadline is not None and time.monotonic() > deadline:
                        reliable = False
                        census_diagnostics.extend(b"procfs-census-deadline=1\n")
                        break
            except OSError as error:
                reliable = False
                census_diagnostics.extend(
                    f"procfs-census-iteration-error={error!r}\n".encode(
                        "utf-8", errors="replace"
                    )
                )
        else:
            try:
                ps_timeout = 2.0
                if deadline is not None:
                    ps_timeout = max(0.0, min(ps_timeout, deadline - time.monotonic()))
                if ps_timeout <= 0:
                    raise subprocess.TimeoutExpired(["ps"], 0.0)
                completed = subprocess.run(
                    ["ps", "-axo", "pid=,ppid="],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=ps_timeout,
                )
                if deadline is not None and time.monotonic() > deadline:
                    reliable = False
                    census_diagnostics.extend(b"ps-census-deadline=1\n")
                listing_bytes = getattr(completed, "stdout", b"") or b""
                listing = listing_bytes.decode("ascii", errors="ignore")
                ps_stderr = getattr(completed, "stderr", b"") or b""
                ps_returncode = getattr(completed, "returncode", 0)
                if ps_returncode != 0 or ps_stderr:
                    reliable = False
                    census_diagnostics.extend(
                        b"ps-census-returncode="
                        + str(ps_returncode).encode("ascii", errors="replace")
                        + b"\nps-census-stdout-start\n"
                        + listing_bytes
                        + b"\nps-census-stdout-finish\nps-census-stderr-start\n"
                        + (
                            ps_stderr
                            if isinstance(ps_stderr, bytes)
                            else str(ps_stderr).encode("utf-8", errors="replace")
                        )
                        + b"\nps-census-stderr-finish\n"
                    )
            except subprocess.TimeoutExpired as error:
                listing = ""
                reliable = False
                census_diagnostics.extend(
                    b"ps-census-timeout\nstdout-start\n"
                    + _timeout_bytes(error, "output")
                    + b"\nstdout-finish\nstderr-start\n"
                    + _timeout_bytes(error, "stderr")
                    + b"\nstderr-finish\n"
                )
            except OSError as error:
                listing = ""
                reliable = False
                census_diagnostics.extend(
                    f"ps-census-launch-error={error!r}\n".encode(
                        "utf-8", errors="replace"
                    )
                )
            for line in listing.splitlines():
                if deadline is not None and time.monotonic() >= deadline:
                    reliable = False
                    census_diagnostics.extend(b"ps-census-deadline=1\n")
                    break
                fields = line.split()
                if len(fields) == 2:
                    try:
                        parent_by_pid[int(fields[0])] = int(fields[1])
                    except ValueError:
                        reliable = False
                        census_diagnostics.extend(
                            f"ps-census-malformed-line={line!r}\n".encode(
                                "utf-8", errors="replace"
                            )
                        )
                elif line.strip():
                    reliable = False
                    census_diagnostics.extend(
                        f"ps-census-malformed-line={line!r}\n".encode(
                            "utf-8", errors="replace"
                        )
                    )
    descendants: set[int] = set()
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        children = [pid for pid, ppid in parent_by_pid.items() if ppid == parent]
        for child in children:
            if child not in descendants:
                descendants.add(child)
                frontier.append(child)
    if os.name == "nt" and snapshot is not None:
        unknown = {
            pid for pid, values in snapshot.items()
            if not values[2]
        }
        if root_pid in unknown or unknown.intersection(descendants):
            reliable = False
            identity_unavailable_pids = sorted(
                {root_pid} | unknown.intersection(descendants)
            )
            census_diagnostics.extend(
                b"windows-census-identity-unavailable="
                + ",".join(str(pid) for pid in identity_unavailable_pids).encode(
                    "ascii"
                )
                + b"\n"
            )
    if deadline is not None and time.monotonic() > deadline:
        reliable = False
        census_diagnostics.extend(b"process-census-deadline=1\n")
    if process is not None:
        # The reliability decision above includes a descendant identity that
        # could not be queried, not merely a failed top-level census.
        process._torturer_tree_census_observed = reliable  # type: ignore[attr-defined]
        if census_diagnostics:
            prior = getattr(process, "_torturer_tree_census_diagnostics", b"")
            process._torturer_tree_census_diagnostics = (  # type: ignore[attr-defined]
                prior + bytes(census_diagnostics)
            )
    return descendants


def _pid_alive(pid: int, *, deadline: float | None = None) -> bool:
    if deadline is not None and time.monotonic() >= deadline:
        # An unperformed deadline-bound probe cannot prove that the PID is
        # gone. Keep it in the survivor set so cleanup fails closed.
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Permission denial means that liveness is unproven. Treating it as
        # dead would falsely certify cleanup and lose the evidence gap.
        return True
    if deadline is not None and time.monotonic() > deadline:
        return True
    if os.name == "posix":
        try:
            stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            if deadline is not None and time.monotonic() > deadline:
                return True
            close = stat_line.rfind(")")
            return stat_line[close + 2 :].split()[0] != "Z"
        except (OSError, ValueError, IndexError):
            pass
    return True


def _wait_for_tree(
    process: subprocess.Popen[bytes],
    tracked: set[int],
    timeout: float | None = None,
    *,
    deadline: float | None = None,
) -> bool:
    if os.name == "nt" and not getattr(process, "_torturer_tree_census_observed", False):
        # CREATE_NEW_PROCESS_GROUP does not prove descendant disappearance on
        # Windows. Do not certify a leader-only result when no bounded census
        # was observed; callers fail closed and retain the evidence metadata.
        return False
    if deadline is None:
        if timeout is None:
            raise SourceCheckoutError("process-tree deadline is required")
        deadline = time.monotonic() + max(0.0, timeout)
    while True:
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=deadline)
        )
        if not getattr(process, "_torturer_tree_census_observed", True):
            return False
        if process.poll() is not None and not _process_group_alive(process):
            if not any(
                _pid_alive(pid, deadline=deadline)
                for pid in tracked
                if pid != process.pid
            ):
                return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            pass


def _tree_survivors(
    process: subprocess.Popen[bytes],
    tracked: set[int],
    *,
    deadline: float | None = None,
) -> tuple[int, ...]:
    tracked.update(_proc_descendants(process.pid, process=process, deadline=deadline))
    survivors = {
        pid for pid in tracked if _pid_alive(pid, deadline=deadline)
    }
    if _process_group_alive(process) and process.poll() is None:
        survivors.add(process.pid)
    return tuple(sorted(survivors))


def _terminate_tree(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float | None = None,
    force_immediately: bool = False,
    deadline: float | None = None,
) -> TreeCleanup:
    if deadline is None:
        if grace_seconds is None:
            raise SourceCheckoutError("process-tree cleanup deadline is required")
        cleanup_deadline = time.monotonic() + max(0.0, grace_seconds)
    else:
        cleanup_deadline = float(deadline)
    tracked = set(getattr(process, "_torturer_tracked", set()))
    tracked.update(
        {process.pid}
        | _proc_descendants(process.pid, process=process, deadline=cleanup_deadline)
    )
    termination_errors: list[str] = []
    leader_running = process.poll() is None
    if force_immediately:
        if os.name == "nt":
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError as error:
                termination_errors.append(
                    f"preflight forced leader kill error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                )
        else:
            if leader_running:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    termination_errors.append(
                        f"preflight forced group kill error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-group-kill-error"
                    )
            for pid in tracked:
                if pid != process.pid:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        termination_errors.append(
                            f"preflight forced descendant kill pid={pid} "
                            f"error={type(error).__name__}; "
                            "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                        )
        if _wait_for_tree(process, tracked, deadline=cleanup_deadline):
            return TreeCleanup(
                not termination_errors,
                (),
                "; ".join(termination_errors) if termination_errors else None,
            )
        return TreeCleanup(
            False,
            _tree_survivors(process, tracked, deadline=cleanup_deadline),
            "; ".join(
                termination_errors + ["preflight process tree survived forced termination"]
            ),
        )
    if os.name == "nt":
        # Ask taskkill for recursive tree cleanup while the leader still gives
        # Windows a stable root PID. Its complete diagnostics stay visible.
        try:
            remaining = _remaining_until(cleanup_deadline)
            if remaining > 0:
                subprocess.run(
                    ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    timeout=remaining,
                )
            else:
                process.kill()
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError as error:
                termination_errors.append(
                    f"preflight forced leader kill error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                )
    else:
        if leader_running:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as error:
                termination_errors.append(
                    f"preflight graceful group termination error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-group-term-error"
                )
        for pid in tracked:
            if pid != process.pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    termination_errors.append(
                        f"preflight graceful descendant termination pid={pid} "
                        f"error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-term-error"
                    )
    if _wait_for_tree(process, tracked, deadline=cleanup_deadline):
        return TreeCleanup(
            not termination_errors,
            (),
            "; ".join(termination_errors) if termination_errors else None,
        )
    if os.name == "nt":
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            termination_errors.append(
                f"preflight forced leader kill error={type(error).__name__}; "
                "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
            )
    else:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                termination_errors.append(
                    f"preflight forced group kill error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-group-kill-error"
                )
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=cleanup_deadline)
        )
        for pid in tracked:
            if pid != process.pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    termination_errors.append(
                        f"preflight forced descendant kill pid={pid} "
                        f"error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                    )
    if _wait_for_tree(process, tracked, deadline=cleanup_deadline):
        return TreeCleanup(
            not termination_errors,
            (),
            "; ".join(termination_errors) if termination_errors else None,
        )
    return TreeCleanup(
        False,
        _tree_survivors(process, tracked, deadline=cleanup_deadline),
        "; ".join(
            termination_errors + ["preflight process tree survived forced termination"]
        ),
    )


def _timeout_bytes(error: subprocess.TimeoutExpired, name: str) -> bytes:
    payload = getattr(error, name, None) or b""
    return payload if isinstance(payload, bytes) else str(payload).encode("utf-8", errors="replace")


def _output_bytes(value: bytes | str | None) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return b""


def _merge_output(previous: bytes, current: bytes) -> bytes:
    """Merge cumulative communicate output without duplicating a prefix."""

    if not previous:
        return current
    if not current or current.startswith(previous) or previous.startswith(current):
        return current if len(current) >= len(previous) else previous
    return previous + current


def _finalize_process(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    description: str,
) -> tuple[str, ...]:
    """Reap the leader and close both pipe objects inside the same deadline.

    ``Popen.communicate(timeout=...)`` deliberately leaves its pipe file
    objects open when the timeout expires.  A resistant descendant can keep
    those pipes open after the leader has been killed, so a later
    ``communicate`` attempt may also time out.  Closing the objects without a
    bounded final reap leaves ``ResourceWarning`` noise (and can leak file
    descriptors across repeated hosted runs).  The caller has already made
    every bounded drain attempt; this finalizer closes only after those
    attempts and records any inability to reap/close rather than suppressing
    it.  Bytes returned by ``communicate`` remain untouched in the result.
    """

    diagnostics: list[str] = []
    try:
        # Always make a bounded wait attempt, including when the absolute
        # deadline has already elapsed.  The old ``poll() is None`` branch
        # skipped reaping in that case; a leader killed by tree cleanup could
        # therefore remain owned by Popen and emit ResourceWarning when the
        # object was collected.  ``wait(timeout=0)`` is a non-blocking reap
        # attempt, not a grace period, and closes that race whenever the
        # leader has already exited.
        remaining = _remaining_until(deadline)
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            try:
                process.wait(timeout=0)
            except subprocess.TimeoutExpired:
                diagnostics.append(
                    f"{description} leader reap timed out; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-reap-timeout"
                )
            except (OSError, ValueError) as error:
                diagnostics.append(
                    f"{description} leader reap error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-reap-error"
                )
        except (OSError, ValueError) as error:
            diagnostics.append(
                f"{description} leader reap error={type(error).__name__}; "
                "EVIDENCE_INCOMPLETE=1 reason=process-reap-error"
            )
    except (OSError, ValueError) as error:
        diagnostics.append(
            f"{description} leader finalization error={type(error).__name__}; "
            "EVIDENCE_INCOMPLETE=1 reason=process-reap-error"
        )

    for stream_name in ("stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        if stream is None:
            continue
        try:
            stream.close()
        except (OSError, ValueError) as error:
            diagnostics.append(
                f"{description} {stream_name} pipe close error={type(error).__name__}; "
                "EVIDENCE_INCOMPLETE=1 reason=output-close-error"
            )
    return tuple(diagnostics)


def _communicate_with_tree(
    process: subprocess.Popen[bytes],
    deadline: float,
    tracked: set[int],
) -> tuple[bytes, bytes]:
    """Communicate in short bounded slices while tracking descendants."""

    timeout_seconds = max(0.0, deadline - time.monotonic())
    stdout = b""
    stderr = b""
    while True:
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=deadline)
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timeout = subprocess.TimeoutExpired(process.args, timeout_seconds)
            timeout.output = stdout
            timeout.stderr = stderr
            raise timeout
        try:
            stdout, stderr = process.communicate(timeout=min(0.1, remaining))
            tracked.update(
                _proc_descendants(process.pid, process=process, deadline=deadline)
            )
            return stdout, stderr
        except subprocess.TimeoutExpired as error:
            stdout = _timeout_bytes(error, "output") or stdout
            stderr = _timeout_bytes(error, "stderr") or stderr


def run_bounded_preflight(
    command: Sequence[str],
    *,
    timeout_seconds: float = GIT_COMMAND_TIMEOUT_SECONDS,
    evidence_directory: Path | None = None,
    evidence_stem: str = "preflight",
) -> PreflightResult:
    """Run one external preflight command inside one total wall-clock bound.

    ``timeout_seconds`` is the complete budget, not merely the child
    observation timeout.  A small internal reserve is held for termination,
    pipe draining, process-tree proof, and evidence retention; every later
    operation is clamped to the same absolute deadline.
    """

    if not command or any(not isinstance(item, str) or not item for item in command):
        raise SourceCheckoutError("preflight command must contain non-empty arguments")
    if timeout_seconds <= 0 or timeout_seconds > MAX_PREFLIGHT_SECONDS:
        raise SourceCheckoutError(
            f"preflight timeout must be between 1 and {MAX_PREFLIGHT_SECONDS} seconds"
        )
    started_at = time.monotonic()
    deadline = started_at + timeout_seconds
    cleanup_reserve = _preflight_cleanup_reserve(timeout_seconds)
    evidence_root = _evidence_directory(evidence_directory)
    try:
        process = subprocess.Popen(
            list(command),
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
    except OSError as error:
        raise SourceCheckoutError("could not launch preflight command") from error
    timed_out = False
    process_tree_proven = True
    survivor_pids: tuple[int, ...] = ()
    cleanup_errors: list[str] = []
    tracked = {process.pid}
    process._torturer_tracked = tracked  # type: ignore[attr-defined]
    process._torturer_tree_census_observed = False  # type: ignore[attr-defined]
    stdout = b""
    stderr = b""
    try:
        # Pass an absolute observation deadline.  Recomputing a relative
        # deadline inside the helper would silently extend this phase if the
        # process were descheduled between the two calls and could consume the
        # cleanup reserve held inside the caller's one total bound.
        observation_deadline = deadline - cleanup_reserve
        stdout, stderr = _communicate_with_tree(process, observation_deadline, tracked)
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=deadline)
        )
        normal_tree_check_deadline = min(
            deadline - cleanup_reserve,
            time.monotonic() + min(GIT_TERMINATION_GRACE_SECONDS, 1.0),
        )
        process_tree_proven = _wait_for_tree(
            process,
            tracked,
            deadline=normal_tree_check_deadline,
        )
        if not process_tree_proven:
            survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
            cleanup_errors.append(
                "preflight normal completion left an unproven or surviving process tree"
            )
            cleanup = _terminate_tree(
                process,
                force_immediately=True,
                deadline=deadline,
            )
            process_tree_proven = cleanup.process_tree_proven
            survivor_pids = cleanup.survivor_pids
            if cleanup.error:
                cleanup_errors.append(cleanup.error)
            try:
                stdout, stderr = process.communicate(timeout=_remaining_until(deadline))
            except subprocess.TimeoutExpired as error:
                stdout = _timeout_bytes(error, "output") or stdout
                stderr = _timeout_bytes(error, "stderr") or stderr
                cleanup_errors.append("preflight diagnostics did not drain after normal-completion cleanup")
            except OSError as error:
                stdout = _merge_output(
                    stdout, _output_bytes(getattr(error, "stdout", None))
                )
                stderr = _merge_output(
                    stderr, _output_bytes(getattr(error, "stderr", None))
                )
                cleanup_errors.append(
                    "preflight diagnostics drain error="
                    + type(error).__name__
                    + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
                )
            final_proof = _wait_for_tree(
                process,
                tracked,
                deadline=deadline,
            )
            process_tree_proven = process_tree_proven and final_proof
            if not final_proof:
                survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
                cleanup_errors.append(
                    "preflight process tree could not be proven gone after normal-completion cleanup"
                )
    except subprocess.TimeoutExpired as first_timeout:
        timed_out = True
        stdout = _timeout_bytes(first_timeout, "output")
        stderr = _timeout_bytes(first_timeout, "stderr")
        print(
            f"[torturer-preflight] timeout after {timeout_seconds:g}s; terminating process tree",
            file=sys.stderr,
        )
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=deadline)
        )
        cleanup = _terminate_tree(
            process,
            force_immediately=True,
            deadline=deadline,
        )
        process_tree_proven = cleanup.process_tree_proven
        survivor_pids = cleanup.survivor_pids
        if cleanup.error:
            cleanup_errors.append(cleanup.error)
            print(f"[torturer-preflight] cleanup-error={cleanup.error}", file=sys.stderr)

        try:
            drain_timeout = _remaining_until(deadline)
            stdout, stderr = process.communicate(timeout=drain_timeout)
            tracked.update(
                _proc_descendants(process.pid, process=process, deadline=deadline)
            )
            after_drain = _wait_for_tree(process, tracked, deadline=deadline)
            process_tree_proven = process_tree_proven and after_drain
            if not after_drain:
                survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
                cleanup_errors.append("preflight process tree could not be proven gone after timeout drain")
        except subprocess.TimeoutExpired as drain_timeout:
            # A pipe can remain open in a descendant even after the leader is
            # gone. Force a second bounded tree cleanup before the final drain.
            stdout = _timeout_bytes(drain_timeout, "output") or stdout
            stderr = _timeout_bytes(drain_timeout, "stderr") or stderr
            cleanup_errors.append("preflight diagnostics did not drain within the bounded cleanup window")
            final_cleanup = _terminate_tree(
                process,
                force_immediately=True,
                deadline=deadline,
            )
            process_tree_proven = process_tree_proven and final_cleanup.process_tree_proven
            survivor_pids = final_cleanup.survivor_pids
            if final_cleanup.error:
                cleanup_errors.append(final_cleanup.error)
            try:
                stdout, stderr = process.communicate(timeout=_remaining_until(deadline))
            except subprocess.TimeoutExpired as final_timeout:
                # Retain every byte available from the final bounded attempt,
                # then prove the tree state even though the pipe stayed open.
                stdout = _timeout_bytes(final_timeout, "output") or stdout
                stderr = _timeout_bytes(final_timeout, "stderr") or stderr
                final_proof = _wait_for_tree(process, tracked, deadline=deadline)
                process_tree_proven = process_tree_proven and final_proof
                if not final_proof:
                    survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
                    cleanup_errors.append("preflight process tree survived final bounded drain")
            except OSError as final_error:
                stdout = _merge_output(
                    stdout, _output_bytes(getattr(final_error, "stdout", None))
                )
                stderr = _merge_output(
                    stderr, _output_bytes(getattr(final_error, "stderr", None))
                )
                cleanup_errors.append(
                    "preflight final diagnostics drain error="
                    + type(final_error).__name__
                    + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
                )
                final_proof = _wait_for_tree(process, tracked, deadline=deadline)
                process_tree_proven = process_tree_proven and final_proof
                if not final_proof:
                    survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
                    cleanup_errors.append("preflight process tree survived final output-drain error")
            else:
                final_proof = _wait_for_tree(process, tracked, deadline=deadline)
                process_tree_proven = process_tree_proven and final_proof
            if not final_proof:
                survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
                cleanup_errors.append("preflight process tree could not be proven gone after final drain")
        except OSError as error:
            stdout = _merge_output(
                stdout, _output_bytes(getattr(error, "stdout", None))
            )
            stderr = _merge_output(
                stderr, _output_bytes(getattr(error, "stderr", None))
            )
            cleanup_errors.append(
                "preflight diagnostics drain error="
                + type(error).__name__
                + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
            )
            final_proof = _wait_for_tree(process, tracked, deadline=deadline)
            process_tree_proven = process_tree_proven and final_proof
            if not final_proof:
                survivor_pids = _tree_survivors(process, tracked, deadline=deadline)
                cleanup_errors.append("preflight process tree survived output-drain error")
    except OSError as error:
        # A pipe/read failure during the initial bounded communication must
        # still produce a result and retain the bytes collected so far. The
        # failed stream boundary is explicitly incomplete, never inferred
        # complete from process exit alone.
        cleanup_errors.append(
            "preflight diagnostics error="
            + type(error).__name__
            + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
        )
        stdout = _merge_output(
            stdout, _output_bytes(getattr(error, "stdout", None))
        )
        stderr = _merge_output(
            stderr, _output_bytes(getattr(error, "stderr", None))
        )
        cleanup = _terminate_tree(
            process,
            force_immediately=True,
            deadline=deadline,
        )
        process_tree_proven = process_tree_proven and cleanup.process_tree_proven
        survivor_pids = cleanup.survivor_pids
        if cleanup.error:
            cleanup_errors.append(cleanup.error)
    finally:
        finalization_errors = _finalize_process(
            process,
            deadline=deadline,
            description="preflight",
        )
        if finalization_errors:
            process_tree_proven = False
            cleanup_errors.extend(finalization_errors)
    tree_diagnostics = getattr(process, "_torturer_tree_census_diagnostics", b"")
    elapsed_seconds = time.monotonic() - started_at
    deadline_exceeded = elapsed_seconds > timeout_seconds
    if deadline_exceeded:
        cleanup_errors.append(
            f"preflight total bound exceeded ({elapsed_seconds:.3f}s > {timeout_seconds:.3f}s)"
        )
    result = PreflightResult(
        tuple(command),
        process.returncode if process.returncode is not None else -1,
        stdout,
        stderr,
        timed_out,
        evidence_complete=process_tree_proven,
        process_tree_proven=process_tree_proven,
        survivor_pids=survivor_pids,
        cleanup_errors=tuple(cleanup_errors),
        elapsed_seconds=elapsed_seconds,
        cleanup_reserve_seconds=cleanup_reserve,
        deadline_exceeded=deadline_exceeded,
        tree_diagnostics=tree_diagnostics,
    )
    try:
        emitted = _emit_result(
            result,
            evidence_root,
            evidence_stem,
            deadline=deadline,
            started_at=started_at,
        )
    except SourceCheckoutError as evidence_error:
        cleanup_errors.append(str(evidence_error))
        emitted = result
    post_elapsed_seconds = time.monotonic() - started_at
    if post_elapsed_seconds > timeout_seconds and not emitted.deadline_exceeded:
        cleanup_errors.append(
            f"preflight total bound exceeded during evidence retention "
            f"({post_elapsed_seconds:.3f}s > {timeout_seconds:.3f}s)"
        )
        emitted = replace(
            emitted,
            elapsed_seconds=post_elapsed_seconds,
            deadline_exceeded=True,
        )
    if cleanup_errors:
        messages = []
        if timed_out:
            messages.append(f"preflight command timed out after {timeout_seconds:g}s")
        messages.extend(cleanup_errors)
        raise SourceCheckoutError(
            f"{'; '.join(messages)}; complete diagnostics retained privately"
        )
    if timed_out:
        raise SourceCheckoutError(
            f"preflight command timed out after {timeout_seconds:g}s; "
            "complete diagnostics retained privately"
        )
    return emitted


def _git_result(
    command: Sequence[str],
    *,
    evidence_directory: Path | None,
    evidence_stem: str,
) -> PreflightResult:
    result = run_bounded_preflight(
        command,
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
        evidence_directory=evidence_directory,
        evidence_stem=evidence_stem,
    )
    if result.returncode != 0:
        raise SourceCheckoutError(
            f"Git preflight failed with exit code {result.returncode}; "
            "complete diagnostics retained privately"
        )
    return result


def verify_source_checkout(
    candidate: Path,
    expected_commit: str,
    *,
    evidence_directory: Path | None = None,
) -> None:
    """Reject refs, abbreviated SHAs, the wrong HEAD, and tracked modifications."""

    if FULL_SHA.fullmatch(expected_commit) is None:
        raise SourceCheckoutError("commit SHA must be exactly 40 lowercase hexadecimal characters")
    evidence_root = _evidence_directory(evidence_directory)
    actual_commit = _git_result(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"],
        evidence_directory=evidence_root,
        evidence_stem="source-rev-parse",
    ).stdout.decode("utf-8", errors="replace").strip()
    tracked_state = _git_result(
        [
            "git",
            "-C",
            str(candidate),
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
        ],
        evidence_directory=evidence_root,
        evidence_stem="source-status",
    ).stdout.decode("utf-8", errors="replace")
    if actual_commit != expected_commit:
        raise SourceCheckoutError("candidate HEAD does not match the requested commit")
    if tracked_state.strip():
        raise SourceCheckoutError("candidate checkout has modified tracked files")
