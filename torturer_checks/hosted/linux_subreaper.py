"""Command-scoped Linux descendant containment for hosted qualification."""

from __future__ import annotations

import ctypes
import os
import signal
import sys


_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_SETUP_FAILURE = 125
_EXEC_FAILURE = 127


def _write_status(descriptor: int, status: bytes) -> bool:
    """Write one atomic status record to the runner-only control pipe."""

    try:
        os.write(descriptor, status + b"\n")
        return True
    except OSError:
        os.write(2, b"DOBBYVPN_SUBREAPER_STATUS_FAILED\n")
        return False


def _enable_subreaper() -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        if prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            return False
        enabled = ctypes.c_int(0)
        if (
            prctl(
                _PR_GET_CHILD_SUBREAPER,
                ctypes.addressof(enabled),
                0,
                0,
                0,
            )
            != 0
        ):
            return False
        return enabled.value == 1
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _mirror_leader_status(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        signum = os.WTERMSIG(status)
        if signum not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
    return _SETUP_FAILURE


def main() -> int:
    if (
        os.name != "posix"
        or len(sys.argv) < 5
        or sys.argv[1] != "--status-fd"
        or sys.argv[3] != "--"
    ):
        return _SETUP_FAILURE
    try:
        status_descriptor = int(sys.argv[2])
        if status_descriptor < 0:
            raise ValueError
        # The forked candidate inherits this descriptor only until exec.
        # CLOEXEC prevents untrusted candidate code from writing trusted
        # helper state or keeping the control pipe open.
        os.set_inheritable(status_descriptor, False)
    except (OSError, ValueError):
        os.write(2, b"DOBBYVPN_SUBREAPER_SETUP_FAILED\n")
        return _SETUP_FAILURE
    if not _enable_subreaper():
        _write_status(status_descriptor, b"SETUP_FAILED")
        os.write(2, b"DOBBYVPN_SUBREAPER_SETUP_FAILED\n")
        return _SETUP_FAILURE
    if not _write_status(status_descriptor, b"READY"):
        return _SETUP_FAILURE

    command = sys.argv[4:]
    try:
        leader = os.fork()
    except OSError:
        _write_status(status_descriptor, b"FORK_FAILED")
        os.write(2, b"DOBBYVPN_SUBREAPER_FORK_FAILED\n")
        return _SETUP_FAILURE
    if leader == 0:
        try:
            os.execvpe(command[0], command, os.environ)
        except OSError:
            _write_status(status_descriptor, b"EXEC_FAILED")
            os.write(2, b"DOBBYVPN_SUBREAPER_EXEC_FAILED\n")
            os._exit(_EXEC_FAILURE)

    leader_status: int | None = None
    while True:
        try:
            pid, status = os.wait()
        except InterruptedError:
            continue
        except ChildProcessError:
            break
        if pid == leader:
            leader_status = status
    if leader_status is None:
        _write_status(status_descriptor, b"WAIT_FAILED")
        os.write(2, b"DOBBYVPN_SUBREAPER_WAIT_FAILED\n")
        return _SETUP_FAILURE
    if not _write_status(status_descriptor, b"COMPLETE"):
        return _SETUP_FAILURE
    return _mirror_leader_status(leader_status)


if __name__ == "__main__":
    raise SystemExit(main())
