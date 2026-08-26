"""Run one hosted command with a cross-platform hard deadline.

The child streams are captured and retained in an owner-only runner-local
evidence directory.  Public Actions receives only an opaque evidence id, byte
count, digest, and stable status; raw diagnostics are never echoed.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile
import time

from .cli import HostedAdapterError, SubprocessRunner, _ensure_owner_only_directory


_MAX_TIMEOUT_SECONDS = 30 * 60
_MAX_GRACE_SECONDS = 60
_MIN_CLEANUP_SECONDS = 0.01


class DeadlineError(ValueError):
    """The requested command or deadline is unsafe."""


def _safe_reason(error: Exception) -> str:
    """Expose a bounded diagnostic code without echoing command/path data."""

    reason = str(error).strip()
    if not reason or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in reason):
        return type(error).__name__
    return reason[:128]


def _bounded(value: int, *, name: str, maximum: int) -> int:
    if not 1 <= value <= maximum:
        raise DeadlineError(f"{name} must be between 1 and {maximum} seconds")
    return value


def _remaining_until(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, max(0.0, cap))


def _evidence_directory() -> Path:
    configured = os.environ.get("TORTURER_HOSTED_DEADLINE_EVIDENCE_DIR")
    if configured:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            raise DeadlineError("deadline evidence directory must be absolute")
        _ensure_owner_only_directory(root)
        return root
    parent = os.environ.get("RUNNER_TEMP")
    if parent:
        parent_path = Path(parent).expanduser()
        if not parent_path.is_absolute():
            raise DeadlineError("runner temporary directory must be absolute")
        parent_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_path.chmod(0o700)
    else:
        parent_path = None
    directory = Path(tempfile.mkdtemp(prefix="torturer-hosted-deadline-", dir=parent_path))
    directory.chmod(0o700)
    _ensure_owner_only_directory(directory)
    return directory


def _publish_evidence(runner: SubprocessRunner, *, status: str) -> None:
    records = runner.safe_evidence()
    if not records:
        raise DeadlineError("deadline evidence metadata is empty")
    for record in records:
        identifier = record.get("evidence_id")
        size = record.get("evidence_bytes")
        digest = record.get("evidence_sha256")
        if (
            not isinstance(identifier, str)
            or len(identifier) != 32
            or identifier[0] != "e"
            or any(character not in "0123456789abcdef" for character in identifier[1:])
            or not isinstance(size, int)
            or not isinstance(digest, str)
            or len(digest) != 64
        ):
            raise DeadlineError("deadline evidence metadata is incomplete")
        print(
            f"hosted-deadline evidence status={status} id={identifier} "
            f"bytes={size} sha256={digest}"
        )


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
    cleanup_reserve = min(float(grace), max(_MIN_CLEANUP_SECONDS, timeout / 2.0))
    try:
        evidence_directory = _evidence_directory()
        runner = SubprocessRunner(
            evidence_directory,
            cleanup_reserve_seconds=cleanup_reserve,
        )
    except HostedAdapterError as error:
        raise DeadlineError(error.code) from error
    print(f"hosted-deadline status=started timeout_seconds={timeout} command_arg_count={len(command)}")
    try:
        result = runner.run(command, timeout_seconds=timeout)
    except HostedAdapterError as error:
        _publish_evidence(runner, status="failed")
        if error.code == "COMMAND_TIMEOUT":
            print("hosted-deadline status=timed-out")
            return 124
        raise DeadlineError(error.code) from error
    _publish_evidence(runner, status=("failed" if result.returncode else "completed"))
    print(f"hosted-deadline status=completed return_code={result.returncode}")
    return result.returncode


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
        print(
            f"hosted-deadline invalid-request={type(error).__name__} "
            f"reason={_safe_reason(error)}",
            file=sys.stderr,
        )
        return 2
    except OSError as error:
        print(f"hosted-deadline launch-error={type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
