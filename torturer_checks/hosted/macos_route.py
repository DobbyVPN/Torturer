"""Fail-closed macOS default-route inspection and restoration.

The macOS ``route -n get default`` command has been observed to print
``not in table`` while returning success.  This module keeps that state
distinct from a malformed or foreign route and only restores a captured
baseline after the candidate service is proven dead.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from typing import Sequence

from .cli import _ensure_owner_only_directory
from .macos import _MACOS_PROCESS_IDENTITY_SCRIPT, _parse_macos_process_identity


_ABSENT_MARKER = re.compile(r"\bnot in table\b", re.IGNORECASE)
_GATEWAY = re.compile(r"^[A-Za-z0-9.:#_-]+$")
_INTERFACE = re.compile(r"^[A-Za-z0-9._-]+$")
_FLAGS = re.compile(r"^[A-Za-z0-9_,<> \t\r\n-]*$")
_PID = re.compile(r"^[1-9][0-9]{0,9}$")
_ROUTE_TIMEOUT_SECONDS = 30


class MacOSRouteError(RuntimeError):
    """A bounded route operation refused to continue."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class MacOSDefaultRoute:
    gateway: str
    interface: str
    flags: str

    def validate(self) -> "MacOSDefaultRoute":
        if not _GATEWAY.fullmatch(self.gateway):
            raise MacOSRouteError("DEFAULT_ROUTE_BASELINE_INVALID")
        if not _INTERFACE.fullmatch(self.interface):
            raise MacOSRouteError("DEFAULT_ROUTE_BASELINE_INVALID")
        if not _FLAGS.fullmatch(self.flags):
            raise MacOSRouteError("DEFAULT_ROUTE_BASELINE_INVALID")
        return self


@dataclass(frozen=True)
class MacOSRouteProbe:
    """One complete route probe, including its command status."""

    returncode: int
    route: MacOSDefaultRoute | None
    absent: bool


@dataclass(frozen=True)
class RestoreDecision:
    """The only route mutation the guarded workflow is allowed to make."""

    action: str
    command: tuple[str, ...] | None


def _field_values(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip()
        if key in {"gateway", "interface", "flags"}:
            fields[key] = value.strip()
    return fields


def parse_default_route(output: str, *, returncode: int = 0) -> MacOSRouteProbe:
    """Classify one route probe without trusting its exit code alone."""

    fields = _field_values(output)
    absent = bool(_ABSENT_MARKER.search(output))
    has_route_fields = any(fields.values())
    if absent and has_route_fields:
        raise MacOSRouteError("DEFAULT_ROUTE_STATE_AMBIGUOUS")
    if absent:
        # ``route`` may return either zero or non-zero for this state.  The
        # marker is authoritative only when no contradictory route exists.
        return MacOSRouteProbe(returncode=returncode, route=None, absent=True)
    if returncode != 0:
        raise MacOSRouteError("DEFAULT_ROUTE_PROBE_FAILED")
    if set(fields) != {"gateway", "interface", "flags"}:
        raise MacOSRouteError("DEFAULT_ROUTE_STATE_AMBIGUOUS")
    route = MacOSDefaultRoute(
        gateway=fields["gateway"],
        interface=fields["interface"],
        flags=fields["flags"],
    ).validate()
    return MacOSRouteProbe(returncode=returncode, route=route, absent=False)


def parse_baseline(path: Path) -> MacOSDefaultRoute:
    """Read and validate the captured baseline route."""

    try:
        output = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise MacOSRouteError("DEFAULT_ROUTE_BASELINE_MISSING") from error
    probe = parse_default_route(output)
    if probe.absent or probe.route is None:
        raise MacOSRouteError("DEFAULT_ROUTE_BASELINE_MISSING")
    return probe.route


def _restore_command(
    route: MacOSDefaultRoute,
    *,
    action: str,
) -> tuple[str, ...]:
    if action not in {"add", "change"}:
        raise MacOSRouteError("DEFAULT_ROUTE_ACTION_INVALID")
    if route.gateway.startswith("link#"):
        return ("sudo", "-n", "route", "-n", action, "default", "-interface", route.interface)
    if "IFSCOPE" in route.flags:
        return (
            "sudo", "-n", "route", "-n", action, "default", route.gateway,
            "-ifscope", route.interface,
        )
    return ("sudo", "-n", "route", "-n", action, "default", route.gateway)


def decide_restore(
    baseline: MacOSDefaultRoute | None,
    current: MacOSRouteProbe,
    *,
    service_dead: bool,
) -> RestoreDecision:
    """Choose a guarded no-op, add, or change; reject every other state."""

    if baseline is None:
        raise MacOSRouteError("DEFAULT_ROUTE_BASELINE_MISSING")
    baseline.validate()
    if not service_dead:
        raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_LIVE")
    if current.absent:
        return RestoreDecision("add", _restore_command(baseline, action="add"))
    if current.route is None:
        raise MacOSRouteError("DEFAULT_ROUTE_STATE_AMBIGUOUS")
    if (
        current.route.interface == baseline.interface
        and current.route.gateway == baseline.gateway
    ):
        return RestoreDecision("not-needed", None)
    if re.fullmatch(r"utun[0-9]+", current.route.interface):
        return RestoreDecision("change", _restore_command(baseline, action="change"))
    raise MacOSRouteError("DEFAULT_ROUTE_STATE_AMBIGUOUS")


def verify_baseline(baseline: MacOSDefaultRoute, current: MacOSRouteProbe) -> None:
    """Require a present route with the exact captured gateway/interface."""

    baseline.validate()
    if current.absent or current.route is None:
        raise MacOSRouteError("DEFAULT_ROUTE_VERIFY_FAILED")
    if (
        current.route.interface != baseline.interface
        or current.route.gateway != baseline.gateway
    ):
        raise MacOSRouteError("DEFAULT_ROUTE_VERIFY_FAILED")


def _validate_output_path(path: Path) -> None:
    if not path.is_absolute():
        raise MacOSRouteError("DEFAULT_ROUTE_OUTPUT_UNSAFE")
    _ensure_owner_only_directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise MacOSRouteError("DEFAULT_ROUTE_OUTPUT_UNSAFE") from error
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise MacOSRouteError("DEFAULT_ROUTE_OUTPUT_UNSAFE")
    if info.st_mode & 0o077:
        raise MacOSRouteError("DEFAULT_ROUTE_OUTPUT_UNSAFE")
    raise MacOSRouteError("DEFAULT_ROUTE_OUTPUT_EXISTS")


def _capture(command: Sequence[str], path: Path, timeout_seconds: float) -> int:
    """Run one route command with complete unsuppressed output on disk."""

    if timeout_seconds <= 0:
        raise MacOSRouteError("DEFAULT_ROUTE_TIMEOUT_INVALID")
    timeout_seconds = min(float(timeout_seconds), float(_ROUTE_TIMEOUT_SECONDS))
    _validate_output_path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            process = subprocess.Popen(
                tuple(command),
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=min(1.0, timeout_seconds))
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=min(1.0, timeout_seconds))
                    except subprocess.TimeoutExpired as error:
                        raise MacOSRouteError(
                            "DEFAULT_ROUTE_COMMAND_SURVIVOR"
                        ) from error
                output.write(b"DEFAULT_ROUTE_COMMAND_TIMEOUT=1\n")
                output.flush()
                os.fsync(output.fileno())
                raise MacOSRouteError("DEFAULT_ROUTE_COMMAND_TIMEOUT")
            output.flush()
            os.fsync(output.fileno())
            return int(returncode)
    except OSError as error:
        raise MacOSRouteError("DEFAULT_ROUTE_COMMAND_UNAVAILABLE") from error


def _service_is_dead(
    pid: int,
    timeout_seconds: float,
    evidence_file: Path,
    identity_file: Path | None = None,
) -> bool:
    if not _PID.fullmatch(str(pid)):
        raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_PID_INVALID")
    timeout_seconds = min(float(timeout_seconds), float(_ROUTE_TIMEOUT_SECONDS))
    expected_identity: dict[str, object] | None = None
    if identity_file is not None:
        try:
            value = json.loads(identity_file.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("identity is not an object")
            if set(value) != {"command", "native_start", "pid", "start"}:
                raise ValueError("native identity fields are incomplete")
            expected_identity = value
            if (
                isinstance(value.get("pid"), bool)
                or not isinstance(value.get("pid"), int)
                or value["pid"] != pid
            ):
                raise ValueError("identity PID does not match service PID")
            if (
                not isinstance(value["command"], str)
                or not Path(value["command"]).is_absolute()
                or not isinstance(value["start"], str)
                or not isinstance(value["native_start"], str)
                or re.fullmatch(r"[1-9][0-9]*\.[0-9]{6}", value["native_start"]) is None
                or int(value["native_start"].split(".", 1)[1]) >= 1_000_000
                or value["start"] != value["native_start"]
            ):
                raise ValueError("identity fields are incomplete")
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_IDENTITY_INVALID") from error
    try:
        native_start = expected_identity["native_start"] if expected_identity is not None else None
        if expected_identity is not None:
            returncode = _capture(
                (
                    "sudo", "-n", "python3", "-c",
                    _MACOS_PROCESS_IDENTITY_SCRIPT, str(pid),
                ),
                evidence_file,
                timeout_seconds,
            )
        else:
            returncode = _capture(
                (
                    "sudo", "-n", "ps", "-p", str(pid), "-o",
                    "pid=",
                ),
                evidence_file,
                timeout_seconds,
            )
        output = evidence_file.read_text(encoding="utf-8", errors="replace")
    except MacOSRouteError as error:
        if error.code == "DEFAULT_ROUTE_COMMAND_TIMEOUT":
            raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_PROBE_TIMEOUT") from error
        raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_PROBE_UNAVAILABLE") from error
    except OSError as error:
        raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_PROBE_UNAVAILABLE") from error
    if returncode == 1 and expected_identity is None and not output.strip():
        return True
    if returncode == 0 and expected_identity is None and output.strip() == str(pid):
        return False
    if returncode == 2 and native_start is not None and output.strip() == "service_probe_absent":
        return True
    if returncode == 0 and native_start is not None:
        try:
            identity, command = _parse_macos_process_identity(output, pid)
        except ValueError as error:
            raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_IDENTITY_MISMATCH") from error
        expected = f"{pid}|{native_start}"
        expected_command = str(expected_identity["command"])
        if identity == expected and command == expected_command:
            return False
        raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_IDENTITY_MISMATCH")
    raise MacOSRouteError("DEFAULT_ROUTE_SERVICE_PROBE_FAILED")


def restore(
    *,
    baseline_file: Path,
    service_probe_file: Path,
    current_file: Path,
    confirmation_file: Path,
    restore_file: Path,
    verified_file: Path,
    service_pid: int,
    timeout_seconds: float,
    service_identity_file: Path | None = None,
) -> str:
    """Inspect, restore, and verify the default route using bounded probes."""

    if timeout_seconds <= 0:
        raise MacOSRouteError("DEFAULT_ROUTE_TIMEOUT_INVALID")
    baseline = parse_baseline(baseline_file)
    service_dead = _service_is_dead(
        service_pid,
        timeout_seconds,
        service_probe_file,
        service_identity_file,
    )
    current_status = _capture(
        ("sudo", "-n", "route", "-n", "get", "default"),
        current_file,
        timeout_seconds,
    )
    current = parse_default_route(
        current_file.read_text(encoding="utf-8", errors="replace"),
        returncode=current_status,
    )
    if current.absent:
        confirmation_status = _capture(
            ("sudo", "-n", "route", "-n", "get", "default"),
            confirmation_file,
            timeout_seconds,
        )
        confirmation = parse_default_route(
            confirmation_file.read_text(encoding="utf-8", errors="replace"),
            returncode=confirmation_status,
        )
        if not confirmation.absent:
            raise MacOSRouteError("DEFAULT_ROUTE_ABSENCE_NOT_CONFIRMED")
    decision = decide_restore(baseline, current, service_dead=service_dead)
    if decision.command is not None:
        restore_status = _capture(decision.command, restore_file, timeout_seconds)
        if restore_status != 0:
            raise MacOSRouteError("DEFAULT_ROUTE_RESTORE_FAILED")
    verified_status = _capture(
        ("sudo", "-n", "route", "-n", "get", "default"),
        verified_file,
        timeout_seconds,
    )
    verified = parse_default_route(
        verified_file.read_text(encoding="utf-8", errors="replace"),
        returncode=verified_status,
    )
    verify_baseline(baseline, verified)
    return decision.action


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-file", type=Path, required=True)
    parser.add_argument("--service-probe-file", type=Path, required=True)
    parser.add_argument("--current-file", type=Path, required=True)
    parser.add_argument("--confirmation-file", type=Path, required=True)
    parser.add_argument("--restore-file", type=Path, required=True)
    parser.add_argument("--verified-file", type=Path, required=True)
    parser.add_argument("--service-pid", type=int, required=True)
    parser.add_argument("--service-identity-file", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        action = restore(
            baseline_file=args.baseline_file,
            service_probe_file=args.service_probe_file,
            current_file=args.current_file,
            confirmation_file=args.confirmation_file,
            restore_file=args.restore_file,
            verified_file=args.verified_file,
            service_pid=args.service_pid,
            timeout_seconds=args.timeout_seconds,
            service_identity_file=args.service_identity_file,
        )
    except MacOSRouteError as error:
        print(f"macos_default_route_restore=failed code={error.code}", file=sys.stderr)
        return 1
    print(f"macos_default_route_restore={action}")
    print("macos_default_route_restore=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
