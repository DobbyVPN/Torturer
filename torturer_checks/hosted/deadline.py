"""Run one hosted command with a cross-platform hard deadline.

The child inherits the caller's stdin, stdout, and stderr.  This wrapper never
captures, filters, truncates, or discards diagnostics.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time


_MAX_TIMEOUT_SECONDS = 30 * 60
_MAX_GRACE_SECONDS = 60


class DeadlineError(ValueError):
    """The requested command or deadline is unsafe."""


def _bounded(value: int, *, name: str, maximum: int) -> int:
    if not 1 <= value <= maximum:
        raise DeadlineError(f"{name} must be between 1 and {maximum} seconds")
    return value


def _group_alive(process: subprocess.Popen[bytes]) -> bool:
    """Return whether the POSIX process group still has a member."""
    if os.name == "nt":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # We cannot prove that a group we cannot inspect has gone away.
        return True
    return True


def _wait_for_group(process: subprocess.Popen[bytes], timeout: float) -> bool:
    """Wait until the leader and, on POSIX, its whole process group exit."""
    deadline = time.monotonic() + timeout
    while True:
        leader_gone = process.poll() is not None
        if leader_gone and not _group_alive(process):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def _terminate(process: subprocess.Popen[bytes], grace_seconds: int) -> None:
    if os.name == "nt":
        if process.poll() is None:
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError) as error:
                print(f"hosted-deadline graceful-stop-error={type(error).__name__}", file=sys.stderr)
        graceful = False
        try:
            graceful = _wait_for_group(process, grace_seconds)
        except (OSError, ValueError) as error:
            print(
                f"hosted-deadline graceful-stop-wait-error={type(error).__name__}",
                file=sys.stderr,
            )
        if not graceful:
            print("hosted-deadline graceful-stop-expired", file=sys.stderr)
        # The leader may have exited while descendants remain. Always ask
        # taskkill for recursive tree cleanup; its complete diagnostics remain
        # visible through inherited stdout/stderr.
        killed = None
        try:
            killed = subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                timeout=grace_seconds,
            )
        except subprocess.TimeoutExpired:
            print("hosted-deadline taskkill-expired", file=sys.stderr)
        if killed is None or (killed.returncode != 0 and process.poll() is None):
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            if _wait_for_group(process, grace_seconds):
                return
        except (OSError, ValueError) as error:
            print(
                f"hosted-deadline graceful-stop-wait-error={type(error).__name__}",
                file=sys.stderr,
            )
        print("hosted-deadline graceful-stop-expired", file=sys.stderr)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if _wait_for_group(process, 10):
        return
    print("hosted-deadline process-tree-still-present", file=sys.stderr)
    raise DeadlineError("command process tree survived forced termination")


def run(command: list[str], *, timeout_seconds: int, grace_seconds: int) -> int:
    timeout = _bounded(
        timeout_seconds,
        name="timeout",
        maximum=_MAX_TIMEOUT_SECONDS,
    )
    grace = _bounded(
        grace_seconds,
        name="kill grace",
        maximum=_MAX_GRACE_SECONDS,
    )
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise DeadlineError("command must contain non-empty argument strings")
    # Never echo argv: hosted commands may contain credentials, private URLs,
    # or profile material. The child still inherits the complete raw streams.
    print(f"hosted-deadline timeout_seconds={timeout} command_arg_count={len(command)}")
    process = subprocess.Popen(
        command,
        stdin=None,
        stdout=None,
        stderr=None,
        start_new_session=os.name != "nt",
        creationflags=(
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        ),
    )
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print("hosted-deadline expired", file=sys.stderr)
        _terminate(process, grace)
        return 124
    print(f"hosted-deadline return_code={return_code}")
    return return_code


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--timeout-seconds", type=int, required=True)
    result.add_argument("--kill-grace-seconds", type=int, default=30)
    result.add_argument("command", nargs=argparse.REMAINDER)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.command,
            timeout_seconds=args.timeout_seconds,
            grace_seconds=args.kill_grace_seconds,
        )
    except DeadlineError as error:
        print(f"hosted-deadline invalid-request={type(error).__name__}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"hosted-deadline launch-error={type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
