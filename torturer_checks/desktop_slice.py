"""Secretless public Windows and macOS desktop lifecycle verification.

This source-build slice calls only DobbyVPN's public ``desktop_build.py`` and
the built native operator CLI.  It deliberately uses an invalid local TOML file;
no profile, endpoint, credential, routable URL, ``connect`` command, or
privileged tunnel start is involved.

Run on the matching hosted runner, for example::

    python3 -m torturer_checks.desktop_slice --candidate /path/to/DobbyVPN \
        --commit-sha 0123456789abcdef0123456789abcdef01234567 \
        --platform macos --arch arm64
    python3 -m torturer_checks.desktop_slice --candidate /path/to/DobbyVPN \
        --commit-sha 0123456789abcdef0123456789abcdef01234567 \
        --platform macos --arch amd64
    python3 -m torturer_checks.desktop_slice --candidate /path/to/DobbyVPN \
        --commit-sha 0123456789abcdef0123456789abcdef01234567 \
        --platform windows --arch amd64

``desktop_build.py`` may bootstrap its documented local dependencies only when
``--allow-bootstrap`` is passed.  The default is ``--skip-deps``.

macOS is checked through a private owner-only Unix control socket.  Windows is
checked through a private temporary ``PROGRAMDATA`` root: the service creates
its own local control token there and the product CLI consumes it.  This test
never supplies, reads, prints, or persists that token.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from dataclasses import dataclass, replace
import json
import hashlib
import os
from pathlib import Path
import platform as host_platform_module
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping, Sequence
import uuid

from torturer_checks.cli_status import CLIStatusError, parse_public_status
from torturer_checks.source_checkout import (
    SourceCheckoutError,
    _finalize_process,
    _pid_alive,
    _proc_descendants,
    verify_source_checkout,
)
from torturer_checks.public_output import emit_evidence
from torturer_checks.windows_job import (
    WindowsJobError,
    close_for as close_windows_job,
    job_for as windows_job_for,
    popen_with_windows_job,
    terminate_and_prove_empty as terminate_windows_job,
    wait_for_empty as wait_for_windows_job,
)


BUILD_SCRIPT_RELATIVE_PATH = Path(".github/scripts/desktop_build.py")
GRADLE_RELATIVE_PATH = Path("kmp_module/gradlew")
WINDOWS_GRADLE_RELATIVE_PATH = Path("kmp_module/gradlew.bat")
SERVICE_RELATIVE_PATHS = {
    "macos": Path("kmp_module/services/macos_grpcvpnserver"),
    "windows": Path("kmp_module/services/windows_grpcvpnserver.exe"),
}
CLI_RELATIVE_PATHS = {
    "macos": Path("kmp_module/services/dobby-cli"),
    "windows": Path("kmp_module/services/dobby-cli.exe"),
}
MACOS_ARCHITECTURES = frozenset(("arm64", "amd64"))
MALFORMED_CONFIG_NAME = "malformed-public-fixture.toml"
# This is intentionally neither valid TOML nor a profile container.
MALFORMED_CONFIG = "[\nthis cannot be parsed as TOML\n"

# Hosted desktop runs must finish before the workflow's 30-minute contract.
# Keep a fixed reserve for diagnostics and process-tree cleanup; no individual
# command may consume that reserve.
MAX_RUN_SECONDS = 30 * 60
CLEANUP_RESERVE_SECONDS = 120
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
COMMAND_TERMINATION_GRACE_SECONDS = 15
COMMAND_CLEANUP_RESERVE_FRACTION = 0.25
MIN_COMMAND_CLEANUP_RESERVE_SECONDS = 0.01


class SliceFailure(RuntimeError):
    """One required public-contract assertion did not hold."""


SERVICE_STARTUP_CONTROL_AUTH_IDENTITY_FAILED = "CONTROL_AUTH_IDENTITY_FAILED"
SERVICE_STARTUP_CONTROL_AUTH_TOKEN_IO_FAILED = "CONTROL_AUTH_TOKEN_IO_FAILED"
SERVICE_STARTUP_CONTROL_AUTH_ACL_APPLY_FAILED = "CONTROL_AUTH_ACL_APPLY_FAILED"
SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED = "CONTROL_AUTH_ACL_VERIFY_FAILED"
SERVICE_STARTUP_CONTROL_AUTH_INVALID_TOKEN = "CONTROL_AUTH_INVALID_TOKEN"
SERVICE_STARTUP_CONTROL_AUTH_OTHER = "CONTROL_AUTH_OTHER"
# Keep the previous name and value source-compatible.  New output uses the
# more precise OTHER bucket for the generic marker.
SERVICE_STARTUP_CONTROL_AUTH_FAILED = "CONTROL_AUTH_INIT_FAILED"
SERVICE_STARTUP_LOOPBACK_LISTEN_FAILED = "LOOPBACK_LISTEN_FAILED"
SERVICE_STARTUP_INTERRUPTED_STATE_RECOVERY_FAILED = "INTERRUPTED_STATE_RECOVERY_FAILED"
SERVICE_STARTUP_SECURE_LOCAL_LOGGING_FAILED = "SECURE_LOCAL_LOGGING_FAILED"
SERVICE_STARTUP_GRPC_SERVE_FAILED = "GRPC_SERVE_FAILED"
SERVICE_STARTUP_EMPTY = "EMPTY"
SERVICE_STARTUP_UNCLASSIFIED = "UNCLASSIFIED"

# These are exact, stable fragments emitted by DobbyVPN's public Go desktop
# startup paths.  The classifier returns only the fixed values above; it never
# returns a service-log fragment.  The nested control-auth markers come from
# controlplane/token*.go.  They must precede the outer panic marker because
# DobbyVPN wraps each one as "failed to prepare control authentication: %w".
# Keep this list fixed and explicit: an unknown or private error is always
# classified as CONTROL_AUTH_OTHER/UNCLASSIFIED, never echoed publicly.
_SERVICE_STARTUP_RULES = (
    (b"failed to initialize secure local logging", SERVICE_STARTUP_SECURE_LOCAL_LOGGING_FAILED),
    (b"failed to recover interrupted product state", SERVICE_STARTUP_INTERRUPTED_STATE_RECOVERY_FAILED),
    (b"failed to listen", SERVICE_STARTUP_LOOPBACK_LISTEN_FAILED),
    (b"failed to serve", SERVICE_STARTUP_GRPC_SERVE_FAILED),
)

_SERVICE_STARTUP_CONTROL_AUTH_RULES = (
    # Identity/current-user/SID resolution reachable from
    # LoadOrCreateControlToken -> controlTokenUser/LookupSID.
    (b"resolve installed-user sid", SERVICE_STARTUP_CONTROL_AUTH_IDENTITY_FAILED),
    (b"resolve current windows user", SERVICE_STARTUP_CONTROL_AUTH_IDENTITY_FAILED),
    (
        b"windows installed-user identity is unavailable for the control token acl",
        SERVICE_STARTUP_CONTROL_AUTH_IDENTITY_FAILED,
    ),
    # Token path or I/O.  Most raw os.File errors intentionally have no stable
    # product prefix and therefore remain in the fixed OTHER bucket.
    (
        b"programdata is required for the installation control token",
        SERVICE_STARTUP_CONTROL_AUTH_TOKEN_IO_FAILED,
    ),
    # Invalid token content is checked before ACL verification.
    (b"invalid desktop control token", SERVICE_STARTUP_CONTROL_AUTH_INVALID_TOKEN),
    # ACL construction/application.
    (b"build explicit runtime path acl", SERVICE_STARTUP_CONTROL_AUTH_ACL_APPLY_FAILED),
    (b"set explicit runtime path acl", SERVICE_STARTUP_CONTROL_AUTH_ACL_APPLY_FAILED),
    # ACL verification/owner/inheritance/entries.  The concrete descriptions
    # below are the values passed to verifyExactACL in token_windows.go; using
    # their stable wording avoids matching arbitrary private text.
    (b"read control token acl:", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token has no security descriptor", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token security descriptor is invalid", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"read control token security descriptor control:", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token owner is defaulted", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token dacl is defaulted", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token has no dacl", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"read control token owner:", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token owner is not the expected identity", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token acl inheritance is not disabled", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"read control token dacl:", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token acl contains", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token acl repeats an identity", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token acl grants access to an unexpected identity", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token acl is missing an expected identity", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"inspect control token type:", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    (b"control token is a reparse point", SERVICE_STARTUP_CONTROL_AUTH_ACL_VERIFY_FAILED),
    # The outer marker is intentionally last among control-auth rules.
    (b"failed to prepare control authentication", SERVICE_STARTUP_CONTROL_AUTH_OTHER),
)


def classify_service_startup_log(payload: bytes) -> str:
    """Map private service-startup bytes to one fixed public-safe class.

    The complete payload remains owner-only evidence.  This function must stay
    deliberately boring: it accepts bytes, performs only fixed substring
    checks, and returns an allow-listed value.  In particular, no candidate
    path, user name, endpoint, URL, credential, or other log text is returned.
    Callers that read a file should handle read failures and use
    ``SERVICE_STARTUP_UNCLASSIFIED`` while preserving the original failure.
    """

    if not isinstance(payload, bytes):
        return SERVICE_STARTUP_UNCLASSIFIED
    lowered = payload.lower()
    for needle, classification in _SERVICE_STARTUP_CONTROL_AUTH_RULES:
        if needle in lowered:
            return classification
    for needle, classification in _SERVICE_STARTUP_RULES:
        if needle in lowered:
            return classification
    return SERVICE_STARTUP_EMPTY if not lowered.strip(b"\x00\t\r\n ") else SERVICE_STARTUP_UNCLASSIFIED


def _service_startup_class_from_path(path: Path) -> str:
    """Read a private startup log for classification without masking a failure."""

    try:
        return classify_service_startup_log(path.read_bytes())
    except Exception:
        # The service failure and the original complete log-retention path are
        # still handled by the caller/finally block.  A diagnostic read issue
        # must never turn a real startup failure into an exception from this
        # best-effort classifier.
        return SERVICE_STARTUP_UNCLASSIFIED


def _is_service_exit_before_readiness(error: BaseException) -> bool:
    """Identify only the readiness early-exit assertion for startup decoding."""

    first_line = str(error).splitlines()[0].strip() if str(error) else ""
    return first_line.startswith("service exited before readiness (exit code ")


def _service_failure_summary(error: BaseException, service_log_path: Path) -> str:
    """Add a fixed startup class without exposing service bytes or masking error."""

    startup_detail = ""
    if _is_service_exit_before_readiness(error):
        startup_class = _service_startup_class_from_path(service_log_path)
        startup_detail = f"; startup_failure_class={startup_class}"
    return f"{error}{startup_detail}; complete service diagnostics retained privately"


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


def safe_failure_reason(error: BaseException) -> str:
    """Return useful failure detail while keeping hosted output secretless.

    The first line is the contract-level failure summary. Later lines may
    contain ``CommandResult.describe()`` output and therefore remain only in
    the retained evidence instead of crossing the public workflow boundary.
    Defensively remove URLs and common credential forms from the summary too.
    """

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
    evidence_directory: Path | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    cleanup_path: Path | None = None
    process_tree_proven: bool = True
    survivor_pids: tuple[int, ...] = ()
    cleanup_diagnostics: tuple[str, ...] = ()
    elapsed_seconds: float = 0.0
    cleanup_reserve_seconds: float = 0.0
    deadline_exceeded: bool = False
    # Process-census output is separate from the child-owned stderr stream;
    # adding it to stderr would mutate the exact bytes emitted by the command.
    process_tree_diagnostics_bytes: bytes = b""
    process_tree_diagnostics_path: Path | None = None

    def describe(self) -> str:
        return (
            f"command_result exit_code={self.returncode} "
            f"stdout_bytes={len(self.stdout_bytes)} "
            f"stdout_sha256={hashlib.sha256(self.stdout_bytes).hexdigest()} "
            f"stderr_bytes={len(self.stderr_bytes)} "
            f"stderr_sha256={hashlib.sha256(self.stderr_bytes).hexdigest()} "
            f"process_tree_proven={self.process_tree_proven}"
        )


@dataclass(frozen=True)
class RuntimePaths:
    root: Path
    fixture: Path
    socket_path: Path | None
    token_path: Path | None


@dataclass(frozen=True)
class ProcessTreeResult:
    """Bounded cleanup proof for one launched process tree."""

    process_tree_proven: bool
    survivor_pids: tuple[int, ...] = ()
    diagnostics: tuple[str, ...] = ()


class RunBudget:
    """Track one hosted desktop run's hard deadline and cleanup reserve."""

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
        """Return a timeout that cannot consume the diagnostic/cleanup reserve."""

        remaining = self.deadline - self.clock() - self.cleanup_reserve_seconds
        if remaining <= 0:
            raise SliceFailure("hosted desktop run exhausted its functional budget before cleanup reserve")
        if requested is None:
            return remaining
        if requested <= 0:
            raise SliceFailure("hosted desktop operation timeout must be positive")
        return min(float(requested), remaining)

    def cleanup_timeout(self) -> float:
        """Return the remaining bounded cleanup window."""

        return max(0.0, min(self.cleanup_reserve_seconds, self.deadline - self.clock()))

    def assert_within_deadline(self) -> None:
        if self.clock() > self.deadline:
            raise SliceFailure("hosted desktop run exceeded its strict 1800-second deadline")


def _command_cleanup_reserve(timeout_seconds: float) -> float:
    """Reserve part of one command's total bound for cleanup and evidence."""

    return min(
        COMMAND_TERMINATION_GRACE_SECONDS,
        max(
            MIN_COMMAND_CLEANUP_RESERVE_SECONDS,
            timeout_seconds * COMMAND_CLEANUP_RESERVE_FRACTION,
        ),
    )


def _remaining_until(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, max(0.0, cap))


def candidate_path(value: str) -> Path:
    """Return a complete public DobbyVPN checkout, rejecting partial trees."""

    root = Path(value).expanduser().resolve()
    required = (
        root / BUILD_SCRIPT_RELATIVE_PATH,
        root / GRADLE_RELATIVE_PATH,
        root / WINDOWS_GRADLE_RELATIVE_PATH,
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


def _normalize_machine(machine: str) -> str:
    normalized = machine.lower()
    if normalized in {"x86_64", "amd64"}:
        return "amd64"
    if normalized in {"arm64", "aarch64"}:
        return "arm64"
    return normalized


def validate_target(
    target_platform: str,
    architecture: str,
    *,
    host_os: str | None = None,
    host_machine: str | None = None,
) -> None:
    """Reject cross-platform/architecture execution before candidate code runs."""

    current_os = host_os or host_platform_module.system()
    current_arch = _normalize_machine(host_machine or host_platform_module.machine())
    if target_platform == "macos":
        if architecture not in MACOS_ARCHITECTURES:
            raise SliceFailure("macOS architecture must be arm64 or amd64")
        if current_os != "Darwin":
            raise SliceFailure("macOS slice must run on a macOS runner")
    elif target_platform == "windows":
        if architecture != "amd64":
            raise SliceFailure("Windows public slice currently supports amd64 only")
        if current_os != "Windows":
            raise SliceFailure("Windows slice must run on a Windows runner")
    else:
        raise SliceFailure("desktop slice platform must be macos or windows")
    if current_arch != architecture:
        raise SliceFailure(
            f"{target_platform} {architecture} slice must run on matching {architecture} hardware "
            f"(found {current_arch})"
        )


def service_build_command(root: Path, target_platform: str, architecture: str, *, skip_dependencies: bool) -> list[str]:
    """Build the native service through the candidate's documented entry point."""

    command = [
        sys.executable,
        str(root / BUILD_SCRIPT_RELATIVE_PATH),
        "libs",
        "--platform",
        target_platform,
        "--arch",
        architecture,
    ]
    if skip_dependencies:
        command.append("--skip-deps")
    return command


def app_build_command(
    root: Path,
    target_platform: str,
    architecture: str,
    *,
    skip_dependencies: bool,
) -> list[str]:
    """Build the desktop app and native CLI for the validated architecture."""

    command = [
        sys.executable,
        str(root / BUILD_SCRIPT_RELATIVE_PATH),
        "app",
        "--platform",
        target_platform,
        "--arch",
        architecture,
        "--skip-libs",
    ]
    if skip_dependencies:
        command.append("--skip-deps")
    return command


def cli_command(root: Path, target_platform: str, *arguments: str) -> list[str]:
    """Run the candidate's built native operator CLI directly."""

    return [str(root / CLI_RELATIVE_PATHS[target_platform]), *arguments]


def service_command(service: Path, target_platform: str, port: int | None) -> list[str]:
    """Return the service's public normal-mode command as an argument vector."""

    if target_platform == "windows":
        if port is None:
            raise SliceFailure("Windows service requires a loopback TCP port")
        return [str(service), "-port", str(port)]
    return [str(service)]


def emit_command_diagnostics(result: CommandResult) -> None:
    """Publish only metadata after the complete streams are retained."""

    emit_evidence(
        "desktop-command",
        status=("failed" if result.returncode != 0 else "completed"),
        payloads={
            "stdout": result.stdout_bytes,
            "stderr": result.stderr_bytes,
            "process-tree-census": result.process_tree_diagnostics_bytes,
        },
    )


def _safe_evidence_stem(label: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("._")
    return stem or "command"


def _validate_evidence_directory(
    directory: Path,
    *,
    allow_missing_final: bool = False,
    host_os: str | None = None,
) -> None:
    """Validate evidence without treating Windows mode bits as ACLs.

    The default directory is created by ``tempfile.mkdtemp`` and resolved by
    ``_prepare_evidence_directory`` before reaching this validator.  This
    accommodates OS-managed aliases such as macOS ``/var`` while preserving
    strict symlink checks for explicitly configured paths.
    """

    validation_os = host_os or os.name
    posix_permissions = validation_os == "posix"
    if not directory.is_absolute():
        raise SliceFailure(f"desktop evidence directory must be absolute: {directory}")
    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(details.st_mode):
            raise SliceFailure(f"desktop evidence path contains a symlink: {current}")
        if not stat.S_ISDIR(details.st_mode):
            raise SliceFailure(f"desktop evidence path is not a directory: {current}")
        if (
            posix_permissions
            and current != directory
            and (details.st_mode & stat.S_IWOTH)
            and not (details.st_mode & stat.S_ISVTX)
        ):
            raise SliceFailure(f"desktop evidence ancestor is world-writable: {current}")
    try:
        details = os.lstat(directory)
    except FileNotFoundError as error:
        if allow_missing_final:
            return
        raise SliceFailure(f"desktop evidence directory was not created: {directory}") from error
    if stat.S_ISLNK(details.st_mode):
        raise SliceFailure(f"desktop evidence directory must not be a symlink: {directory}")
    if not stat.S_ISDIR(details.st_mode):
        raise SliceFailure(f"desktop evidence path is not a directory: {directory}")
    if posix_permissions and hasattr(os, "geteuid") and details.st_uid != os.geteuid():
        raise SliceFailure(f"desktop evidence directory is not owner-controlled: {directory}")
    if posix_permissions and details.st_mode & 0o077:
        raise SliceFailure(f"desktop evidence directory must be mode 0700: {directory}")


def _prepare_evidence_directory(configured: Path | str | None) -> Path:
    if configured:
        directory = Path(configured).expanduser()
    else:
        # The OS owns the temp-root alias (for example macOS ``/var``).  The
        # directory itself was just created by mkdtemp, so resolving only this
        # generated path preserves strict checks for explicit caller paths.
        directory = Path(tempfile.mkdtemp(prefix="torturer-desktop-evidence-")).resolve()
    _validate_evidence_directory(directory, allow_missing_final=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_evidence_directory(directory)
    return directory


def _retain_exclusive_bytes(directory: Path, filename: str, payload: bytes) -> Path:
    path = directory / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise SliceFailure(f"refusing to overwrite existing desktop evidence: {path}") from error
    except OSError as error:
        raise SliceFailure(f"could not create owner-only desktop evidence: {path}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    except Exception as error:
        # Preserve partial original bytes for diagnosis; never unlink them.
        raise SliceFailure(f"desktop evidence write incomplete; partial file preserved: {path}") from error
    return path


def _retain_command_streams(
    evidence_directory: Path,
    label: str,
    stdout: bytes,
    stderr: bytes,
    process_tree_diagnostics: bytes = b"",
) -> dict[str, Path]:
    """Retain original command streams and cleanup metadata exclusively."""

    _validate_evidence_directory(evidence_directory)
    stem = _safe_evidence_stem(label)
    paths: dict[str, Path] = {}
    for suffix, payload in (("stdout", stdout), ("stderr", stderr)):
        paths[suffix] = _retain_exclusive_bytes(
            evidence_directory,
            f"{stem}.{suffix}.raw.log",
            payload,
        )
    if process_tree_diagnostics:
        paths["process_tree_diagnostics"] = _retain_exclusive_bytes(
            evidence_directory,
            f"{stem}.process-tree-census.raw.log",
            process_tree_diagnostics,
        )
    return paths


def _retain_cleanup_record(
    evidence_directory: Path,
    label: str,
    result: ProcessTreeResult,
    *,
    elapsed_seconds: float = 0.0,
    cleanup_reserve_seconds: float = 0.0,
    deadline_exceeded: bool = False,
    process_tree_diagnostics_path: Path | None = None,
) -> Path:
    metadata = {
        "schema": "torturer.desktop.command-cleanup.v1",
        "process_tree_proven": result.process_tree_proven,
        "survivor_pids": list(result.survivor_pids),
        "diagnostics": list(result.diagnostics),
        "elapsed_seconds": elapsed_seconds,
        "cleanup_reserve_seconds": cleanup_reserve_seconds,
        "deadline_exceeded": deadline_exceeded,
        "process_tree_census_path": (
            str(process_tree_diagnostics_path) if process_tree_diagnostics_path else None
        ),
    }
    return _retain_exclusive_bytes(
        evidence_directory,
        f"{_safe_evidence_stem(label)}.cleanup.raw.json",
        (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )


def _emit_and_retain_service_log(path: Path, evidence_directory: Path | None) -> None:
    """Retain the complete service log before publishing safe metadata."""

    if not path.is_file():
        return
    if evidence_directory is None:
        raise SliceFailure("desktop service diagnostics require an owner-only evidence directory")
    _validate_evidence_directory(evidence_directory)
    payload = path.read_bytes()
    _retain_exclusive_bytes(evidence_directory, "service.combined.raw.log", payload)
    emit_evidence("desktop-service", status="retained", payloads={"service": payload})


def _process_group_alive(process: subprocess.Popen[bytes]) -> bool:
    """Return whether the launched process group still has a member."""

    if os.name == "nt":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # A permission error means we cannot prove the cleanup succeeded.
        return True
    return True


def _wait_for_process_tree(
    process: subprocess.Popen[bytes],
    timeout_seconds: float | None = None,
    tracked: set[int] | None = None,
    *,
    deadline: float | None = None,
) -> bool:
    """Wait for both the leader and its process group, proving disappearance."""

    tracked = tracked if tracked is not None else set()
    if deadline is None:
        if timeout_seconds is None:
            raise SliceFailure("process-tree deadline is required")
        deadline = time.monotonic() + max(0.0, timeout_seconds)
    # Windows Job Object accounting is the authoritative containment proof.
    # The PID/parent census remains supplemental diagnostic evidence and may
    # not turn a native ActiveProcesses=0 observation into a false failure.
    if os.name == "nt":
        if windows_job_for(process) is not None:
            return wait_for_windows_job(process, deadline=deadline).process_tree_proven
        # A Windows process without a Job Object is an invalid production
        # launch. A PID census is supplemental evidence only and cannot
        # replace the mandatory native containment boundary.
        tracked.update(_proc_descendants(process.pid, process=process, deadline=deadline))
        return False
    while True:
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=deadline)
        )
        if not getattr(process, "_torturer_tree_census_observed", True):
            return False
        leader_gone = process.poll() is not None
        if leader_gone and not _process_group_alive(process) and not any(
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


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float | None = None,
    description: str,
    force_immediately: bool = False,
    evidence_directory: Path | None = None,
    deadline: float | None = None,
) -> ProcessTreeResult:
    """Terminate a command and prove its process group did not survive."""

    # Lightweight fakes in the helper tests model only the public Popen
    # lifecycle methods. Preserve that seam while real processes always use
    # the process-group path below.
    if deadline is None:
        if grace_seconds is None:
            raise SliceFailure("process-tree cleanup deadline is required")
        cleanup_deadline = time.monotonic() + max(0.0, grace_seconds)
    else:
        cleanup_deadline = float(deadline)
    process_id = getattr(process, "pid", None)
    if process_id is None:
        diagnostics: list[str] = []
        if process.poll() is None:
            try:
                process.terminate()
            except OSError as error:
                diagnostics.append(
                    f"{description} graceful-stop-error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-term-error"
                )
            try:
                process.wait(timeout=_remaining_until(cleanup_deadline))
            except subprocess.TimeoutExpired:
                diagnostics.append(f"{description} graceful-stop-expired")
                try:
                    process.kill()
                except OSError as error:
                    diagnostics.append(
                        f"{description} forced-stop-error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                    )
                try:
                    process.wait(timeout=_remaining_until(cleanup_deadline))
                except subprocess.TimeoutExpired:
                    diagnostics.append(f"{description} forced-stop-expired")
        if process.poll() is None:
            return ProcessTreeResult(False, (), tuple(diagnostics + [f"{description} process survived termination"]))
        return ProcessTreeResult(True, (), tuple(diagnostics))

    tracked = set(getattr(process, "_torturer_tracked", set()))
    tracked.update(
        _proc_descendants(process_id, process=process, deadline=cleanup_deadline)
    )
    diagnostics = []
    termination_errors: list[str] = []
    was_running = process.poll() is None
    if force_immediately:
        if os.name == "nt":
            job_attached = windows_job_for(process) is not None
            if job_attached:
                cleanup = terminate_windows_job(
                    process,
                    deadline=cleanup_deadline,
                    stage=f"{description}-forced",
                )
                if cleanup.process_tree_proven:
                    return ProcessTreeResult(True, (), cleanup.diagnostics)
                termination_errors.extend(cleanup.diagnostics)
            else:
                termination_errors.append(
                    f"stage={description} windows-job missing; "
                    "EVIDENCE_INCOMPLETE=1 reason=job-containment-missing"
                )
            if not job_attached:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError as error:
                    termination_errors.append(
                        f"{description} forced leader kill error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                    )
        else:
            if was_running:
                try:
                    os.killpg(process_id, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    termination_errors.append(
                        f"{description} forced group kill error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-group-kill-error"
                    )
            for pid in tracked:
                if pid != process_id:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        termination_errors.append(
                            f"{description} forced descendant kill pid={pid} "
                            f"error={type(error).__name__}; "
                            "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                        )
        if _wait_for_process_tree(process, tracked=tracked, deadline=cleanup_deadline):
            return ProcessTreeResult(
                not termination_errors,
                (),
                tuple(diagnostics + termination_errors),
            )
        return ProcessTreeResult(
            False,
            (
                ((process_id,) if process.poll() is None else ())
                if os.name == "nt" and windows_job_for(process) is None
                else tuple(
                    sorted(
                        pid for pid in tracked
                        if _pid_alive(pid, deadline=cleanup_deadline)
                    )
                )
            ),
            tuple(
                diagnostics
                + termination_errors
                + [f"{description} process group survived forced termination"]
            ),
        )
    if was_running:
        if os.name == "nt":
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError) as error:
                diagnostics.append(
                    f"{description} graceful-stop-error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-term-error"
                )
                print(
                    f"[torturer-process] {description} graceful-stop-error={type(error).__name__}",
                    file=sys.stderr,
                )
        else:
            try:
                os.killpg(process_id, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as error:
                termination_errors.append(
                    f"{description} graceful group termination error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-group-term-error"
                )
            for pid in tracked:
                if pid != process_id:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        termination_errors.append(
                            f"{description} graceful descendant termination pid={pid} "
                            f"error={type(error).__name__}; "
                            "EVIDENCE_INCOMPLETE=1 reason=process-term-error"
                        )

    tree_gone = _wait_for_process_tree(process, tracked=tracked, deadline=cleanup_deadline)
    if tree_gone and (os.name != "nt" or windows_job_for(process) is not None):
        return ProcessTreeResult(
            not termination_errors,
            (),
            tuple(diagnostics + termination_errors),
        )

    if not tree_gone and os.name != "nt":
        diagnostics.append(f"{description} graceful-stop-expired")
        print(f"[torturer-process] {description} graceful-stop-expired", file=sys.stderr)
    if os.name == "nt":
        if windows_job_for(process) is not None:
            cleanup = terminate_windows_job(
                process,
                deadline=cleanup_deadline,
                stage=description,
            )
            if cleanup.process_tree_proven:
                return ProcessTreeResult(True, (), cleanup.diagnostics)
            termination_errors.extend(cleanup.diagnostics)
        else:
            # A Windows process without a retained Job Object is not safe to
            # clean recursively. Kill only the identity-bound leader and fail
            # closed; never fall back to unsafe PID-based tree termination.
            termination_errors.append(
                f"stage={description} windows-job missing; "
                "EVIDENCE_INCOMPLETE=1 reason=job-containment-missing"
            )
            if process.poll() is None:
                try:
                    process.kill()
                except OSError as error:
                    termination_errors.append(
                        f"{description} forced leader kill error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                    )
    else:
        if process.poll() is None:
            try:
                os.killpg(process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                termination_errors.append(
                    f"{description} forced group kill error={type(error).__name__}; "
                    "EVIDENCE_INCOMPLETE=1 reason=process-group-kill-error"
                )
        for pid in tracked:
            if pid != process_id:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    termination_errors.append(
                        f"{description} forced descendant kill pid={pid} "
                        f"error={type(error).__name__}; "
                        "EVIDENCE_INCOMPLETE=1 reason=process-kill-error"
                    )

    if _wait_for_process_tree(process, tracked=tracked, deadline=cleanup_deadline):
        return ProcessTreeResult(
            not termination_errors,
            (),
            tuple(diagnostics + termination_errors),
        )
    if os.name == "nt" and windows_job_for(process) is None:
        survivors = {process_id} if process.poll() is None else set()
    else:
        survivors = {
            pid for pid in tracked if _pid_alive(pid, deadline=cleanup_deadline)
        }
    if _process_group_alive(process):
        survivors.add(process_id)
    diagnostics.extend(termination_errors)
    diagnostics.append(f"{description} process group survived forced termination")
    return ProcessTreeResult(False, tuple(sorted(survivors)), tuple(diagnostics))


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


def _communicate_with_tracking(
    process: subprocess.Popen[bytes],
    deadline: float,
    tracked: set[int],
) -> tuple[bytes, bytes]:
    """Communicate in bounded slices so short-lived descendants are observed."""

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
            current_stdout, current_stderr = process.communicate(
                timeout=min(0.1, remaining)
            )
            stdout = _merge_output(stdout, _output_bytes(current_stdout))
            stderr = _merge_output(stderr, _output_bytes(current_stderr))
            tracked.update(
                _proc_descendants(process.pid, process=process, deadline=deadline)
            )
            return stdout, stderr
        except subprocess.TimeoutExpired as error:
            stdout = _merge_output(stdout, _timeout_bytes(error, "output"))
            stderr = _merge_output(stderr, _timeout_bytes(error, "stderr"))


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    evidence_directory: Path | None = None,
    evidence_label: str = "command",
) -> CommandResult:
    """Execute an argument vector inside one total wall-clock bound.

    ``timeout_seconds`` covers child observation, process-tree proof,
    termination, pipe draining, and evidence retention.  A small reserve is
    withheld from normal observation so cleanup cannot be pushed beyond the
    caller's deadline.
    """

    if timeout_seconds <= 0:
        raise SliceFailure("command timeout must be positive")
    started_at = time.monotonic()
    deadline = started_at + timeout_seconds
    cleanup_reserve = _command_cleanup_reserve(timeout_seconds)
    evidence_root = _prepare_evidence_directory(evidence_directory)
    try:
        process = popen_with_windows_job(
            subprocess.Popen,
            list(command),
            cwd=cwd,
            env=env,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
            stage="desktop-command",
            deadline=deadline,
        )
    except WindowsJobError as error:
        if evidence_root is None:
            raise SliceFailure(
                f"{error}; EVIDENCE_INCOMPLETE=1 reason=setup-output-no-owner-evidence"
            ) from error
        setup_label = f"{evidence_label}-setup-{uuid.uuid4().hex}"
        try:
            paths = _retain_command_streams(
                evidence_root,
                setup_label,
                error.stdout,
                error.stderr,
            )
            _retain_cleanup_record(
                evidence_root,
                setup_label,
                ProcessTreeResult(
                    False,
                    diagnostics=(
                        str(error),
                        "EVIDENCE_INCOMPLETE=1 reason=windows-job-setup",
                    ),
                ),
                process_tree_diagnostics_path=paths.get("process_tree_diagnostics"),
            )
        except SliceFailure as retention_error:
            raise SliceFailure(
                f"{error}; setup-output-retention-failed: {retention_error}"
            ) from error
        raise SliceFailure(
            f"{error}; complete setup diagnostics retained privately"
        ) from error
    tracked = {process.pid}
    process._torturer_tracked = tracked  # type: ignore[attr-defined]
    timed_out = False
    cleanup_result = ProcessTreeResult(True)
    cleanup_diagnostics: list[str] = []
    process_tree_proven = True
    survivor_pids: tuple[int, ...] = ()
    evidence_error: SliceFailure | None = None
    stdout = b""
    stderr = b""
    try:
        # Keep this as one absolute deadline across the caller/helper boundary.
        # A fresh relative deadline here would consume the cleanup reserve if
        # the process were descheduled between computing and using it.
        observation_deadline = deadline - cleanup_reserve
        stdout, stderr = _communicate_with_tracking(process, observation_deadline, tracked)
        normal_tree_deadline = min(
            deadline - cleanup_reserve,
            time.monotonic() + min(COMMAND_TERMINATION_GRACE_SECONDS, 1.0),
        )
        process_tree_proven = _wait_for_process_tree(
            process,
            tracked=tracked,
            deadline=normal_tree_deadline,
        )
        if not process_tree_proven:
            cleanup_diagnostics.append("normal completion left an unproven or surviving process tree")
            cleanup_result = _terminate_process_tree(
                process,
                description="command",
                force_immediately=True,
                evidence_directory=evidence_root,
                deadline=deadline,
            )
            cleanup_diagnostics.extend(cleanup_result.diagnostics)
            process_tree_proven = cleanup_result.process_tree_proven
            survivor_pids = cleanup_result.survivor_pids
            try:
                drained_stdout, drained_stderr = process.communicate(
                    timeout=_remaining_until(deadline)
                )
                stdout = _merge_output(stdout, _output_bytes(drained_stdout))
                stderr = _merge_output(stderr, _output_bytes(drained_stderr))
            except subprocess.TimeoutExpired as error:
                stdout = _merge_output(stdout, _timeout_bytes(error, "output"))
                stderr = _merge_output(stderr, _timeout_bytes(error, "stderr"))
                cleanup_diagnostics.append("command diagnostics did not drain after normal-completion cleanup")
            except OSError as error:
                stdout = _merge_output(
                    stdout, _output_bytes(getattr(error, "stdout", None))
                )
                stderr = _merge_output(
                    stderr, _output_bytes(getattr(error, "stderr", None))
                )
                cleanup_diagnostics.append(
                    "command diagnostics drain error="
                    + type(error).__name__
                    + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
                )
            final_proof = _wait_for_process_tree(
                process,
                tracked=tracked,
                deadline=deadline,
            )
            process_tree_proven = process_tree_proven and final_proof
            if not final_proof:
                survivor_pids = tuple(
                    sorted(
                        pid for pid in tracked
                        if _pid_alive(pid, deadline=deadline)
                    )
                )
                cleanup_diagnostics.append(
                    "command process tree could not be proven gone after normal-completion cleanup"
                )
    except subprocess.TimeoutExpired as first_timeout:
        timed_out = True
        stdout = _timeout_bytes(first_timeout, "output")
        stderr = _timeout_bytes(first_timeout, "stderr")
        print(
            f"[torturer-command] timeout after {timeout_seconds:g}s; terminating process tree",
            file=sys.stderr,
        )
        tracked.update(
            _proc_descendants(process.pid, process=process, deadline=deadline)
        )
        cleanup_result = _terminate_process_tree(
            process,
            description="command",
            force_immediately=True,
            evidence_directory=evidence_root,
            deadline=deadline,
        )
        cleanup_diagnostics.extend(cleanup_result.diagnostics)
        process_tree_proven = cleanup_result.process_tree_proven
        survivor_pids = cleanup_result.survivor_pids
        if cleanup_result.diagnostics:
            print(
                f"[torturer-command] cleanup-diagnostics={'; '.join(cleanup_result.diagnostics)}",
                file=sys.stderr,
            )
        try:
            drain_timeout = _remaining_until(deadline)
            drained_stdout, drained_stderr = process.communicate(timeout=drain_timeout)
            stdout = _merge_output(stdout, _output_bytes(drained_stdout))
            stderr = _merge_output(stderr, _output_bytes(drained_stderr))
        except subprocess.TimeoutExpired as error:
            stdout = _merge_output(stdout, _timeout_bytes(error, "output"))
            stderr = _merge_output(stderr, _timeout_bytes(error, "stderr"))
            cleanup_diagnostics.append("command diagnostics did not drain after forced termination")
        except OSError as error:
            stdout = _merge_output(
                stdout, _output_bytes(getattr(error, "stdout", None))
            )
            stderr = _merge_output(
                stderr, _output_bytes(getattr(error, "stderr", None))
            )
            cleanup_diagnostics.append(
                "command diagnostics drain error="
                + type(error).__name__
                + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
            )
        final_proof = _wait_for_process_tree(
            process,
            tracked=tracked,
            deadline=deadline,
        )
        process_tree_proven = process_tree_proven and final_proof
        if not final_proof:
            final_cleanup = _terminate_process_tree(
                process,
                description="command-final",
                force_immediately=True,
                evidence_directory=evidence_root,
                deadline=deadline,
            )
            cleanup_diagnostics.extend(final_cleanup.diagnostics)
            process_tree_proven = process_tree_proven and final_cleanup.process_tree_proven
            survivor_pids = final_cleanup.survivor_pids
            try:
                drained_stdout, drained_stderr = process.communicate(
                    timeout=_remaining_until(deadline)
                )
                stdout = _merge_output(stdout, _output_bytes(drained_stdout))
                stderr = _merge_output(stderr, _output_bytes(drained_stderr))
            except subprocess.TimeoutExpired as error:
                stdout = _merge_output(stdout, _timeout_bytes(error, "output"))
                stderr = _merge_output(stderr, _timeout_bytes(error, "stderr"))
                cleanup_diagnostics.append("command diagnostics did not drain after final cleanup")
            except OSError as error:
                stdout = _merge_output(
                    stdout, _output_bytes(getattr(error, "stdout", None))
                )
                stderr = _merge_output(
                    stderr, _output_bytes(getattr(error, "stderr", None))
                )
                cleanup_diagnostics.append(
                    "command final diagnostics drain error="
                    + type(error).__name__
                    + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
                )
            final_proof = _wait_for_process_tree(
                process,
                tracked=tracked,
                deadline=deadline,
            )
            process_tree_proven = process_tree_proven and final_proof
            if not final_proof:
                survivor_pids = tuple(
                    sorted(
                        pid for pid in tracked
                        if _pid_alive(pid, deadline=deadline)
                    )
                )
                cleanup_diagnostics.append("command process tree survived final cleanup")
    except OSError as error:
        # Preserve any bytes collected before a pipe/read failure, perform the
        # same bounded tree cleanup, and retain an explicit incomplete-output
        # diagnostic instead of dropping the exception out of the runner.
        cleanup_diagnostics.append(
            "command diagnostics error="
            + type(error).__name__
            + "; output evidence is incomplete; EVIDENCE_INCOMPLETE=1 reason=output-drain-error"
        )
        stdout = _merge_output(
            stdout, _output_bytes(getattr(error, "stdout", None))
        )
        stderr = _merge_output(
            stderr, _output_bytes(getattr(error, "stderr", None))
        )
        cleanup_result = _terminate_process_tree(
            process,
            description="command-output-error",
            force_immediately=True,
            evidence_directory=evidence_root,
            deadline=deadline,
        )
        cleanup_diagnostics.extend(cleanup_result.diagnostics)
        process_tree_proven = process_tree_proven and cleanup_result.process_tree_proven
        survivor_pids = cleanup_result.survivor_pids
    finally:
        finalization_errors = _finalize_process(
            process,
            deadline=deadline,
            description="command",
        )
        if finalization_errors:
            process_tree_proven = False
            cleanup_diagnostics.extend(finalization_errors)
    tree_diagnostics = getattr(process, "_torturer_tree_census_diagnostics", b"")
    elapsed_seconds = time.monotonic() - started_at
    deadline_exceeded = elapsed_seconds > timeout_seconds
    if deadline_exceeded:
        cleanup_diagnostics.append(
            f"command total bound exceeded ({elapsed_seconds:.3f}s > {timeout_seconds:.3f}s)"
        )
    result = CommandResult(
        tuple(command),
        process.returncode if process.returncode is not None else -1,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
        stdout,
        stderr,
        evidence_directory=evidence_root,
        process_tree_proven=process_tree_proven,
        survivor_pids=survivor_pids,
        cleanup_diagnostics=tuple(cleanup_diagnostics),
        elapsed_seconds=elapsed_seconds,
        cleanup_reserve_seconds=cleanup_reserve,
        deadline_exceeded=deadline_exceeded,
        process_tree_diagnostics_bytes=tree_diagnostics,
        process_tree_diagnostics_path=None,
    )
    try:
        paths = _retain_command_streams(
            evidence_root,
            evidence_label,
            stdout,
            stderr,
            tree_diagnostics,
        )
        cleanup_path = _retain_cleanup_record(
            evidence_root,
            evidence_label,
            ProcessTreeResult(process_tree_proven, survivor_pids, tuple(cleanup_diagnostics)),
            elapsed_seconds=elapsed_seconds,
            cleanup_reserve_seconds=cleanup_reserve,
            deadline_exceeded=deadline_exceeded,
            process_tree_diagnostics_path=paths.get("process_tree_diagnostics"),
        )
        result = replace(
            result,
            stdout_path=paths["stdout"],
            stderr_path=paths["stderr"],
            cleanup_path=cleanup_path,
            process_tree_diagnostics_path=paths.get("process_tree_diagnostics"),
        )
    except SliceFailure as error:
        evidence_error = error
    post_elapsed_seconds = time.monotonic() - started_at
    if post_elapsed_seconds > timeout_seconds and not deadline_exceeded:
        cleanup_diagnostics.append(
            f"command total bound exceeded during evidence retention "
            f"({post_elapsed_seconds:.3f}s > {timeout_seconds:.3f}s)"
        )
        result = replace(
            result,
            elapsed_seconds=post_elapsed_seconds,
            deadline_exceeded=True,
            cleanup_diagnostics=tuple(cleanup_diagnostics),
        )
    emit_command_diagnostics(result)
    if evidence_error is not None:
        raise SliceFailure(f"{evidence_error}\n{result.describe()}") from evidence_error
    # Preserve the primary timeout classification even when the same absolute
    # deadline also made a cleanup/census proof inconclusive.  The detail
    # remains attached so a caller cannot mistake this for a clean timeout.
    if timed_out:
        details = "; ".join(cleanup_diagnostics)
        suffix = f"; {details}" if details else ""
        raise SliceFailure(
            f"command timed out after {timeout_seconds:g}s{suffix}\n{result.describe()}"
        )
    if not process_tree_proven or cleanup_diagnostics:
        raise SliceFailure(f"{'; '.join(cleanup_diagnostics)}\n{result.describe()}")
    return result


def require_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        raise SliceFailure(f"{description} failed\n{result.describe()}")


def require_nonzero(result: CommandResult, description: str) -> None:
    if result.returncode == 0:
        raise SliceFailure(f"{description} unexpectedly succeeded\n{result.describe()}")


def reserve_loopback_port() -> int:
    """Choose a currently free IPv4 loopback port for the Windows service."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_tcp(
    port: int,
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
    *,
    connector: Callable[[tuple[str, int], float], object] = socket.create_connection,
) -> None:
    """Wait for the Windows loopback listener while detecting an early exit."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SliceFailure(f"service exited before readiness (exit code {process.returncode})")
        try:
            connection = connector(("127.0.0.1", port), 1)
        except OSError:
            time.sleep(0.1)
            continue
        close = getattr(connection, "close", None)
        if callable(close):
            close()
        return
    raise SliceFailure(f"service did not listen on loopback TCP port {port} within {timeout_seconds:g}s")


def wait_for_unix_socket(
    path: Path,
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Wait for the macOS owner-only Unix control socket.

    The service creates the socket before tightening its mode to ``0600``.
    Keep polling through that brief creation-to-chmod transition, but never
    treat it as ready until the final owner-only mode is visible.
    """

    deadline = clock() + timeout_seconds
    last_observed_mode: int | None = None
    while clock() < deadline:
        if process.poll() is not None:
            raise SliceFailure(f"service exited before readiness (exit code {process.returncode})")
        try:
            details = path.stat()
        except FileNotFoundError:
            sleeper(0.1)
            continue
        if not stat.S_ISSOCK(details.st_mode):
            raise SliceFailure(f"control path exists but is not a Unix socket: {path}")
        mode = stat.S_IMODE(details.st_mode)
        if mode == 0o600:
            return
        last_observed_mode = mode
        sleeper(0.1)
    if last_observed_mode is not None:
        raise SliceFailure(
            "control socket permissions did not become 600 before readiness timeout "
            f"({timeout_seconds:g}s; last observed mode {last_observed_mode:o})"
        )
    raise SliceFailure(f"service did not create its Unix control socket within {timeout_seconds:g}s: {path}")


def build_runtime_paths(root: Path, target_platform: str) -> RuntimePaths:
    """Return platform-specific private paths rooted in one temporary directory."""

    fixture = root / MALFORMED_CONFIG_NAME
    if target_platform == "macos":
        return RuntimePaths(root, fixture, root / "control.sock", None)
    return RuntimePaths(root, fixture, None, root / "ProgramData" / "DobbyVPN" / "control.token")


_WINDOWS_ACCOUNT_FORBIDDEN = frozenset('\\/:*?"<>|@')


def derive_windows_control_token_user(environment: Mapping[str, str]) -> str:
    """Derive the installed-user account without exposing its value on error.

    DobbyVPN's Windows token ACL must resolve the same account that launched
    the hosted service.  The runner-provided ``USERNAME`` is required and the
    optional ``USERDOMAIN`` is prepended in the canonical ``DOMAIN\\USER``
    form.  Values are validated before they cross the subprocess boundary;
    inherited control-token overrides never participate in this decision.
    """

    def valid_component(value: object) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise SliceFailure("Windows control-token identity is unavailable or unsafe")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise SliceFailure("Windows control-token identity is unavailable or unsafe")
        if any(character in _WINDOWS_ACCOUNT_FORBIDDEN for character in value):
            raise SliceFailure("Windows control-token identity is unavailable or unsafe")
        return value

    username = valid_component(environment.get("USERNAME"))
    raw_domain = environment.get("USERDOMAIN")
    if raw_domain is None:
        account = username
    else:
        domain = valid_component(raw_domain)
        account = f"{domain}\\{username}"
    if account.upper() in {"SYSTEM", "NT AUTHORITY\\SYSTEM"}:
        raise SliceFailure("Windows control-token identity is unavailable or unsafe")
    return account


def service_environment(target_platform: str, runtime: RuntimePaths, port: int | None) -> dict[str, str]:
    """Constrain public control transport state to the per-run temporary root."""

    environment = os.environ.copy()
    # Do not let an inherited override turn this secretless fixture into a test
    # against an operator-provided token or a different local identity.
    environment.pop("DOBBYVPN_CONTROL_TOKEN_PATH", None)
    environment.pop("DOBBYVPN_CONTROL_TOKEN_USER", None)
    if target_platform == "macos":
        if runtime.socket_path is None:
            raise SliceFailure("macOS runtime has no control socket path")
        environment["DOBBYVPN_CONTROL_SOCKET"] = str(runtime.socket_path)
        environment["DOBBYVPN_CONTROL_PEER_UID"] = str(os.getuid())
        return environment
    if port is None:
        raise SliceFailure("Windows runtime has no loopback TCP port")
    environment["PROGRAMDATA"] = str(runtime.root / "ProgramData")
    environment["PORT"] = str(port)
    # The public Windows service must not fall back to an account lookup that
    # can differ across hosted launch contexts.  Derive it from the copied
    # runner environment only after removing any inherited override.
    environment["DOBBYVPN_CONTROL_TOKEN_USER"] = derive_windows_control_token_user(environment)
    return environment


def assert_windows_token_path(runtime: RuntimePaths) -> None:
    """Require only the token's generated location, never its secret contents."""

    path = runtime.token_path
    if path is None or not path.is_file() or path.is_symlink():
        raise SliceFailure("Windows service did not create a regular PROGRAMDATA/DobbyVPN control token")


def stop_service(
    process: subprocess.Popen[bytes],
    socket_path: Path | None,
    *,
    timeout_seconds: float = 15.0,
    evidence_directory: Path | None = None,
) -> None:
    """Stop the service tree, prove it is gone, and remove only our socket."""

    cleanup_deadline = time.monotonic() + max(0.0, timeout_seconds)
    failures: list[str] = []
    try:
        cleanup = _terminate_process_tree(
            process,
            description="service",
            evidence_directory=evidence_directory,
            deadline=cleanup_deadline,
        )
        if not cleanup.process_tree_proven or cleanup.diagnostics:
            failures.append(
                "service process tree cleanup could not be proven: "
                + "; ".join(cleanup.diagnostics)
            )
        if not failures:
            if socket_path is not None:
                if socket_path.exists() or socket_path.is_socket():
                    details = socket_path.lstat()
                    if not stat.S_ISSOCK(details.st_mode):
                        failures.append(
                            f"refusing to remove non-socket cleanup path: {socket_path}"
                        )
                    else:
                        socket_path.unlink()
                if socket_path.exists() or socket_path.is_socket():
                    failures.append(f"control socket remained after cleanup: {socket_path}")
    except (OSError, ValueError) as error:
        failures.append(f"service cleanup error={type(error).__name__}")
    finally:
        try:
            process.wait(timeout=_remaining_until(cleanup_deadline))
        except subprocess.TimeoutExpired:
            failures.append("service leader reap timed out; EVIDENCE_INCOMPLETE=1 reason=process-reap-timeout")
        except (OSError, ValueError) as error:
            failures.append(
                f"service leader reap error={type(error).__name__}; "
                "EVIDENCE_INCOMPLETE=1 reason=process-reap-error"
            )
        close_diagnostics = close_windows_job(
            process,
            stage="service",
            deadline=cleanup_deadline,
        )
        # A first CloseHandle failure is retained but is not fatal when the
        # shared same-deadline retry closed the Job.  Keep those bytes in a
        # small owner-only cleanup record (or visible local diagnostics when
        # no evidence directory was requested) so the successful retry never
        # suppresses the original native observation.
        close_failed = False
        if len(close_diagnostics):
            close_failed = getattr(close_diagnostics, "failed", bool(close_diagnostics))
            if evidence_directory is not None:
                try:
                    _retain_cleanup_record(
                        evidence_directory,
                        "service",
                        ProcessTreeResult(
                            not close_failed,
                            diagnostics=tuple(close_diagnostics),
                        ),
                        deadline_exceeded=time.monotonic() > cleanup_deadline,
                    )
                except SliceFailure as error:
                    failures.append(str(error))
            else:
                print(
                    "[torturer-process] service close diagnostics="
                    + "; ".join(close_diagnostics),
                    file=sys.stderr,
                )
        if close_failed:
            failures.extend(close_diagnostics)
    if failures:
        raise SliceFailure("; ".join(failures))


def assert_cli_contract(
    root: Path,
    target_platform: str,
    environment: dict[str, str],
    fixture: Path,
    *,
    budget: RunBudget,
    evidence_directory: Path | None,
) -> None:
    """Exercise only non-connecting product CLI operations against the service."""

    help_result = run_command(
        cli_command(root, target_platform, "--help"),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(),
        evidence_directory=evidence_directory,
        evidence_label="cli-help",
    )
    require_success(help_result, "CLI help")
    if "check-config" not in help_result.stdout or "disconnect" not in help_result.stdout:
        raise SliceFailure(f"CLI help did not expose the documented command surface\n{help_result.describe()}")

    status_result = run_command(
        cli_command(root, target_platform, "status", "--json"),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(),
        evidence_directory=evidence_directory,
        evidence_label="cli-status",
    )
    require_success(status_result, "CLI status")
    try:
        status = parse_public_status(status_result.stdout)
    except CLIStatusError as error:
        raise SliceFailure(
            f"CLI status JSON was invalid: {error}\n{status_result.describe()}"
        ) from error
    if status.state != "Disconnected":
        raise SliceFailure(
            f"CLI did not report the initial disconnected state\n{status_result.describe()}"
        )

    malformed_result = run_command(
        cli_command(root, target_platform, "check-config", str(fixture)),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(),
        evidence_directory=evidence_directory,
        evidence_label="cli-check-config",
    )
    require_nonzero(malformed_result, "CLI malformed local configuration rejection")

    disconnect_result = run_command(
        cli_command(root, target_platform, "disconnect"),
        cwd=root,
        env=environment,
        timeout_seconds=budget.operation_timeout(),
        evidence_directory=evidence_directory,
        evidence_label="cli-disconnect",
    )
    require_success(disconnect_result, "CLI disconnect after malformed input")


def run_slice(
    candidate: Path,
    *,
    expected_commit: str,
    target_platform: str,
    architecture: str,
    skip_dependencies: bool,
    timeout_seconds: float,
) -> None:
    """Build, launch, verify, and clean up one matching desktop candidate."""

    budget = RunBudget()
    validate_target(target_platform, architecture)
    root = candidate_path(str(candidate))
    try:
        verify_source_checkout(root, expected_commit)
    except SourceCheckoutError as error:
        raise SliceFailure(str(error)) from error
    configured_evidence = os.environ.get("TORTURER_EVIDENCE_DIR")
    runtime_root: Path | None = None
    with nullcontext(_prepare_evidence_directory(configured_evidence)) as evidence_root:
        build_environment = os.environ.copy()
        require_success(
            run_command(
                service_build_command(root, target_platform, architecture, skip_dependencies=skip_dependencies),
                cwd=root,
                env=build_environment,
                timeout_seconds=budget.operation_timeout(),
                evidence_directory=evidence_root,
                evidence_label="service-build",
            ),
            f"public {target_platform} {architecture} service build",
        )
        require_success(
            run_command(
                app_build_command(
                    root,
                    target_platform,
                    architecture,
                    skip_dependencies=skip_dependencies,
                ),
                cwd=root,
                env=build_environment,
                timeout_seconds=budget.operation_timeout(),
                evidence_directory=evidence_root,
                evidence_label="app-build",
            ),
            f"public {target_platform} desktop application and native CLI build",
        )

        service = root / SERVICE_RELATIVE_PATHS[target_platform]
        if not service.is_file() or (target_platform == "macos" and not os.access(service, os.X_OK)):
            raise SliceFailure(f"public build did not produce an executable {target_platform} service: {service}")
        cli = root / CLI_RELATIVE_PATHS[target_platform]
        if not cli.is_file() or (target_platform == "macos" and not os.access(cli, os.X_OK)):
            raise SliceFailure(f"public build did not produce an executable {target_platform} operator CLI: {cli}")

        with tempfile.TemporaryDirectory(prefix=f"torturer-{target_platform}-") as temporary:
            runtime_root = Path(temporary)
            runtime_root.chmod(0o700)
            runtime = build_runtime_paths(runtime_root, target_platform)
            runtime.fixture.write_text(MALFORMED_CONFIG, encoding="utf-8")
            runtime.fixture.chmod(0o600)
            port = reserve_loopback_port() if target_platform == "windows" else None
            environment = service_environment(target_platform, runtime, port)
            service_log_path = runtime.root / "service.combined.log"
            try:
                # Close the parent's copy immediately after launch.  The child
                # retains its redirected handle, while Windows evidence reads
                # and temporary-directory cleanup are no longer exposed to a
                # parent-held sharing violation.
                with service_log_path.open("wb", buffering=0) as service_log:
                    process = popen_with_windows_job(
                        subprocess.Popen,
                        service_command(service, target_platform, port),
                        cwd=root,
                        env=environment,
                        stdin=None,
                        stdout=service_log,
                        stderr=subprocess.STDOUT,
                        start_new_session=os.name != "nt",
                        creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
                        stage=f"desktop-service-{target_platform}",
                        deadline=budget.deadline,
                    )
            except WindowsJobError as error:
                if evidence_root is not None:
                    _emit_and_retain_service_log(service_log_path, evidence_root)
                raise SliceFailure(str(error)) from error
            process._torturer_tracked = {process.pid}  # type: ignore[attr-defined]
            try:
                if target_platform == "macos":
                    if runtime.socket_path is None:  # Defensive narrowing for type checkers.
                        raise SliceFailure("macOS runtime has no control socket path")
                    wait_for_unix_socket(runtime.socket_path, process, budget.operation_timeout(timeout_seconds))
                else:
                    if port is None:
                        raise SliceFailure("Windows runtime has no loopback TCP port")
                    wait_for_tcp(port, process, budget.operation_timeout(timeout_seconds))
                    assert_windows_token_path(runtime)
                assert_cli_contract(
                    root,
                    target_platform,
                    environment,
                    runtime.fixture,
                    budget=budget,
                    evidence_directory=evidence_root,
                )
            except SliceFailure as error:
                raise SliceFailure(
                    _service_failure_summary(error, service_log_path)
                ) from error
            finally:
                try:
                    stop_service(
                        process,
                        runtime.socket_path,
                        timeout_seconds=budget.cleanup_timeout(),
                        evidence_directory=evidence_root,
                    )
                finally:
                    _emit_and_retain_service_log(service_log_path, evidence_root)
    if runtime_root is not None and runtime_root.exists():
        raise SliceFailure(f"private {target_platform} runtime resources remained after cleanup: {runtime_root}")
    budget.assert_within_deadline()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, help="Path to the checked-out DobbyVPN candidate.")
    parser.add_argument("--commit-sha", required=True, help="Exact lowercase 40-character candidate commit SHA.")
    parser.add_argument("--platform", required=True, choices=("macos", "windows"))
    parser.add_argument("--arch", required=True, help="macOS: arm64 or amd64; Windows: amd64.")
    parser.add_argument(
        "--allow-bootstrap",
        action="store_true",
        help="Allow desktop_build.py to install/download its documented local dependencies.",
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
            target_platform=args.platform,
            architecture=args.arch,
            skip_dependencies=not args.allow_bootstrap,
            timeout_seconds=args.timeout,
        )
    except SliceFailure as error:
        print(
            "desktop_slice status=failed "
            f"code={type(error).__name__} reason={safe_failure_reason(error)}",
            file=sys.stderr,
        )
        return 1
    print(
        "Torturer desktop slice passed: source builds, native CLI lifecycle, "
        "and private service cleanup verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
