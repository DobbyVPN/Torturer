"""Secretless public Linux desktop verification for one DobbyVPN checkout.

This is deliberately a black-box slice.  It only calls the candidate's public
desktop build entry point and its JVM command-line application.  The fixture is
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
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Sequence

from torturer_checks.source_checkout import SourceCheckoutError, verify_source_checkout


SERVICE_RELATIVE_PATH = Path("kmp_module/services/ubuntu_grpcvpnserver")
BUILD_SCRIPT_RELATIVE_PATH = Path(".github/scripts/desktop_build.py")
GRADLE_RELATIVE_PATH = Path("kmp_module/gradlew")
MALFORMED_CONFIG_NAME = "malformed-public-fixture.toml"
# No valid TOML profile table, endpoint, credential, hostname, or routable URL.
MALFORMED_CONFIG = "[\nthis cannot be parsed as TOML\n"


class SliceFailure(RuntimeError):
    """One required public-contract assertion did not hold."""


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def describe(self) -> str:
        rendered = " ".join(self.command)
        return (
            f"command: {rendered}\nexit code: {self.returncode}\n"
            f"stdout:\n{self.stdout}\nstderr:\n{self.stderr}"
        )


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
    """Build the JVM application without rebuilding the service just built."""

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
    """Run the candidate's public JVM CLI using its Gradle application target."""

    return [
        str(root / GRADLE_RELATIVE_PATH),
        "--no-daemon",
        ":app:run",
        "--args=" + " ".join(arguments),
    ]


def run_command(command: Sequence[str], *, cwd: Path, env: dict[str, str]) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return CommandResult(tuple(command), completed.returncode, completed.stdout, completed.stderr)


def require_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        raise SliceFailure(f"{description} failed\n{result.describe()}")


def require_nonzero(result: CommandResult, description: str) -> None:
    if result.returncode == 0:
        raise SliceFailure(f"{description} unexpectedly succeeded\n{result.describe()}")


def wait_for_socket(path: Path, process: subprocess.Popen[str], timeout_seconds: float) -> None:
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


def stop_service(process: subprocess.Popen[str], socket_path: Path) -> None:
    """Terminate the ephemeral process and remove any stale Unix socket it leaves."""

    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.poll() is None:
        raise SliceFailure("service process survived termination")

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


def assert_cli_contract(root: Path, environment: dict[str, str], fixture: Path) -> None:
    """Exercise safe CLI surfaces against the ready service, never a tunnel."""

    gradle_dir = root / "kmp_module"
    help_result = run_command(cli_command(root, "--help"), cwd=gradle_dir, env=environment)
    require_success(help_result, "CLI help")
    if "check-config" not in help_result.stdout or "verify-session" not in help_result.stdout:
        raise SliceFailure(f"CLI help did not expose the documented command surface\n{help_result.describe()}")

    status_result = run_command(cli_command(root, "status", "--json"), cwd=gradle_dir, env=environment)
    require_success(status_result, "CLI status")
    if '"state": "Disconnected"' not in status_result.stdout:
        raise SliceFailure(f"CLI did not report the initial disconnected state\n{status_result.describe()}")

    malformed_result = run_command(
        cli_command(root, "check-config", str(fixture)), cwd=gradle_dir, env=environment
    )
    require_nonzero(malformed_result, "CLI malformed local configuration rejection")

    disconnect_result = run_command(cli_command(root, "disconnect"), cwd=gradle_dir, env=environment)
    require_success(disconnect_result, "CLI disconnect after malformed input")


def run_slice(
    candidate: Path,
    *,
    expected_commit: str,
    skip_dependencies: bool,
    timeout_seconds: float,
) -> None:
    """Build, launch, verify and clean up one candidate.  Any missing phase fails."""

    root = candidate_path(str(candidate))
    try:
        verify_source_checkout(root, expected_commit)
    except SourceCheckoutError as error:
        raise SliceFailure(str(error)) from error
    build_environment = os.environ.copy()
    require_success(
        run_command(build_command(root, skip_dependencies=skip_dependencies), cwd=root, env=build_environment),
        "public Linux service build",
    )
    require_success(
        run_command(app_build_command(root, skip_dependencies=skip_dependencies), cwd=root, env=build_environment),
        "public desktop application build",
    )

    service = root / SERVICE_RELATIVE_PATH
    if not service.is_file() or not os.access(service, os.X_OK):
        raise SliceFailure(f"public build did not produce an executable Linux service: {service}")

    with tempfile.TemporaryDirectory(prefix="torturer-linux-") as temporary:
        runtime = Path(temporary)
        runtime.chmod(0o700)
        socket_path = runtime / "control.sock"
        fixture = runtime / MALFORMED_CONFIG_NAME
        fixture.write_text(MALFORMED_CONFIG, encoding="utf-8")
        fixture.chmod(0o600)
        environment = service_environment(service.parent, socket_path)
        service_log_path = runtime / "service.log"
        with service_log_path.open("w", encoding="utf-8") as service_log:
            process = subprocess.Popen(
                [str(service)],
                cwd=root,
                env=environment,
                text=True,
                stdout=service_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                wait_for_socket(socket_path, process, timeout_seconds)
                assert_cli_contract(root, environment, fixture)
            except SliceFailure as error:
                service_log.flush()
                logs = service_log_path.read_text(encoding="utf-8", errors="replace")
                raise SliceFailure(f"{error}\nservice log:\n{logs}") from error
            finally:
                stop_service(process, socket_path)


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
        print(f"Torturer Linux slice failed: {error}", file=sys.stderr)
        return 1
    print("Torturer Linux slice passed: build, Unix service readiness, safe CLI rejection, and cleanup verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
