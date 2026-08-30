"""Run one hosted command with a cross-platform hard deadline.

The child streams are captured and retained in an owner-only runner-local
evidence directory.  Public Actions receives only an opaque evidence id, byte
count, digest, and stable status; raw diagnostics are never echoed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import threading
import time

from .cli import (
    HostedAdapterError,
    SubprocessRunner,
    _evidence_metadata,
    _ensure_owner_only_directory,
    _opaque_evidence_id,
)


_MAX_TIMEOUT_SECONDS = 30 * 60
_MAX_GRACE_SECONDS = 60
_MIN_CLEANUP_SECONDS = 0.01
_MAX_SUMMARY_RECORDS = 256
_MAX_SUMMARY_BYTES = 1024 * 1024
_PROGRESS_PATH_ENV = "TORTURER_HOSTED_PROGRESS_PATH"
_SAFE_PROGRESS_LINE = re.compile(
    r"hosted-functional scenario-(?:"
    r"start id=[a-z][a-z0-9._-]{2,95} required_seconds=[0-9]+ "
    r"missing_capabilities=[0-9]+|"
    r"finish id=[a-z][a-z0-9._-]{2,95} "
    r"outcome=(?:passed|failed|unavailable|unknown) "
    r"duration_seconds=[0-9]+(?:\.[0-9]+)? reset_failures=[0-9]+|"
    r"error id=[a-z][a-z0-9._-]{2,95} "
    r"code=[A-Za-z][A-Za-z0-9_.-]* "
    r"duration_seconds=[0-9]+(?:\.[0-9]+)?)"
)


class DeadlineError(ValueError):
    """The requested command or deadline is unsafe."""


class _ProgressForwarder:
    """Forward only allow-listed hosted scenario markers from the child."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise DeadlineError("progress path must be absolute")
        try:
            _ensure_owner_only_directory(path.parent)
        except HostedAdapterError as error:
            raise DeadlineError("progress path is unsafe") from error
        self.path = path
        self.offset = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _drain(self) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            return
        if self.path.is_symlink() or not stat.S_ISREG(info.st_mode):
            return
        try:
            with self.path.open("rb") as source:
                source.seek(self.offset)
                data = source.read()
        except OSError:
            return
        if not data:
            return
        consumed = 0
        for raw_line in data.splitlines(keepends=True):
            if not raw_line.endswith(b"\n"):
                break
            consumed += len(raw_line)
            try:
                line = raw_line[:-1].decode("ascii")
            except UnicodeDecodeError:
                continue
            if _SAFE_PROGRESS_LINE.fullmatch(line):
                print(line, flush=True)
        self.offset += consumed

    def _watch(self) -> None:
        while not self._stop.wait(0.1):
            self._drain()
        self._drain()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._watch,
            name="hosted-progress-forwarder",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)


def _progress_forwarder() -> _ProgressForwarder | None:
    configured = os.environ.get(_PROGRESS_PATH_ENV)
    if not configured:
        return None
    return _ProgressForwarder(Path(configured).expanduser())


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
            f"bytes={size} sha256={digest}",
            flush=True,
        )


def _summary_path(path: Path | None) -> Path | None:
    configured = path
    if configured is None:
        value = os.environ.get("TORTURER_HOSTED_DEADLINE_SUMMARY_PATH")
        configured = Path(value).expanduser() if value else None
    if configured is None:
        return None
    if not configured.is_absolute():
        raise DeadlineError("deadline summary path must be absolute")
    _ensure_owner_only_directory(configured.parent)
    return configured


def _safe_evidence_records(runner: SubprocessRunner) -> list[dict[str, object]]:
    records = list(runner.safe_evidence())
    if not records:
        raise DeadlineError("deadline evidence metadata is empty")
    if len(records) > _MAX_SUMMARY_RECORDS:
        raise DeadlineError("deadline evidence metadata is too large")
    safe: list[dict[str, object]] = []
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
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise DeadlineError("deadline evidence metadata is incomplete")
        safe.append({
            "evidence_id": identifier,
            "evidence_bytes": size,
            "evidence_sha256": digest,
        })
    return safe


def opaque_file_evidence(path: Path, *, evidence_kind: str) -> dict[str, object]:
    """Return safe metadata for one owner-only file without exposing its path."""

    if not evidence_kind or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        for character in evidence_kind
    ):
        raise DeadlineError("evidence kind is invalid")
    if not path.is_absolute():
        raise DeadlineError("evidence path must be absolute")
    try:
        evidence_bytes, evidence_sha256 = _evidence_metadata(path)
    except OSError as error:
        if getattr(error, "errno", None) == 2:
            return {
                "evidence_id": _opaque_evidence_id(),
                "evidence_kind": evidence_kind,
                "state": "missing",
            }
        raise DeadlineError("evidence metadata unavailable") from error
    except HostedAdapterError as error:
        raise DeadlineError("evidence metadata unavailable") from error
    return {
        "evidence_id": _opaque_evidence_id(),
        "evidence_kind": evidence_kind,
        "evidence_bytes": evidence_bytes,
        "evidence_sha256": evidence_sha256,
    }


def write_opaque_manifest(
    path: Path,
    *,
    kind: str,
    status: str,
    return_code: int | None,
    records: list[dict[str, object]],
    fields: dict[str, object] | None = None,
) -> None:
    """Write a small owner-only manifest containing metadata only."""

    if not path.is_absolute():
        raise DeadlineError("opaque manifest path must be absolute")
    if not kind or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        for character in kind
    ):
        raise DeadlineError("opaque manifest kind is invalid")
    if status not in {"completed", "failed", "timed-out", "incomplete"}:
        raise DeadlineError("opaque manifest status is invalid")
    if return_code is not None and not isinstance(return_code, int):
        raise DeadlineError("opaque manifest return code is invalid")
    if len(records) > _MAX_SUMMARY_RECORDS:
        raise DeadlineError("opaque manifest evidence is too large")
    payload: dict[str, object] = {
        "schema": 1,
        "kind": kind,
        "status": status,
        "return_code": return_code,
        "evidence": records,
    }
    if fields:
        for key, value in fields.items():
            if not isinstance(key, str) or not key or key in payload:
                raise DeadlineError("opaque manifest field is invalid")
            if isinstance(value, (str, int, bool)) or value is None:
                payload[key] = value
            else:
                raise DeadlineError("opaque manifest field value is invalid")
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_SUMMARY_BYTES:
        raise DeadlineError("opaque manifest is too large")
    _ensure_owner_only_directory(path.parent)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise DeadlineError("opaque manifest unavailable") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise DeadlineError("opaque manifest fsync failed") from error


def _write_deadline_summary(
    path: Path | None,
    runner: SubprocessRunner,
    *,
    status: str,
    return_code: int | None,
) -> None:
    if path is None:
        return
    write_opaque_manifest(
        path,
        kind="dobbyvpn.hosted.deadline-summary",
        status=status,
        return_code=return_code,
        records=_safe_evidence_records(runner),
    )


def run(
    command: list[str],
    *,
    timeout_seconds: int,
    grace_seconds: int,
    summary_output: Path | None = None,
) -> int:
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
    summary = _summary_path(summary_output)
    progress = _progress_forwarder()
    if progress is not None:
        progress.start()
    print(
        f"hosted-deadline status=started timeout_seconds={timeout} "
        f"command_arg_count={len(command)}",
        flush=True,
    )
    try:
        result = runner.run(command, timeout_seconds=timeout)
        status = "failed" if result.returncode else "completed"
        _publish_evidence(runner, status=status)
        _write_deadline_summary(
            summary,
            runner,
            status=status,
            return_code=result.returncode,
        )
        print(
            f"hosted-deadline status=completed return_code={result.returncode}",
            flush=True,
        )
        return result.returncode
    except HostedAdapterError as error:
        if error.code == "COMMAND_TIMEOUT":
            _publish_evidence(runner, status="timed-out")
            _write_deadline_summary(
                summary,
                runner,
                status="timed-out",
                return_code=124,
            )
            print("hosted-deadline status=timed-out", flush=True)
            return 124
        _publish_evidence(runner, status="failed")
        _write_deadline_summary(
            summary,
            runner,
            status="failed",
            return_code=None,
        )
        raise DeadlineError(error.code) from error
    finally:
        if progress is not None:
            progress.stop()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--timeout-seconds", type=int, required=True)
    result.add_argument("--kill-grace-seconds", type=int, default=30)
    result.add_argument("--summary-output", type=Path)
    result.add_argument("command", nargs=argparse.REMAINDER)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.command,
            timeout_seconds=args.timeout_seconds,
            grace_seconds=args.kill_grace_seconds,
            summary_output=args.summary_output,
        )
    except DeadlineError as error:
        print(
            f"hosted-deadline invalid-request={type(error).__name__} "
            f"reason={_safe_reason(error)}",
            file=sys.stderr,
            flush=True,
        )
        return 2
    except OSError as error:
        print(
            f"hosted-deadline launch-error={type(error).__name__}",
            file=sys.stderr,
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
