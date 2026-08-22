"""Secretless public Windows and macOS desktop lifecycle verification.

This source-build slice calls only DobbyVPN's public ``desktop_build.py`` and
the product JVM CLI target.  It deliberately uses an invalid local TOML file;
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
from dataclasses import dataclass
import os
from pathlib import Path
import platform as host_platform_module
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Sequence

from torturer_checks.source_checkout import SourceCheckoutError, verify_source_checkout


BUILD_SCRIPT_RELATIVE_PATH = Path(".github/scripts/desktop_build.py")
GRADLE_RELATIVE_PATH = Path("kmp_module/gradlew")
WINDOWS_GRADLE_RELATIVE_PATH = Path("kmp_module/gradlew.bat")
SERVICE_RELATIVE_PATHS = {
    "macos": Path("kmp_module/services/macos_grpcvpnserver"),
    "windows": Path("kmp_module/services/windows_grpcvpnserver.exe"),
}
MACOS_ARCHITECTURES = frozenset(("arm64", "amd64"))
MALFORMED_CONFIG_NAME = "malformed-public-fixture.toml"
# This is intentionally neither valid TOML nor a profile container.
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
        return (
            f"command: {' '.join(self.command)}\nexit code: {self.returncode}\n"
            f"stdout:\n{self.stdout}\nstderr:\n{self.stderr}"
        )


@dataclass(frozen=True)
class RuntimePaths:
    root: Path
    fixture: Path
    socket_path: Path | None
    token_path: Path | None


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


def app_build_command(root: Path, target_platform: str, *, skip_dependencies: bool) -> list[str]:
    """Build the JVM app after the service build without rebuilding that service."""

    command = [
        sys.executable,
        str(root / BUILD_SCRIPT_RELATIVE_PATH),
        "app",
        "--platform",
        target_platform,
        "--skip-libs",
    ]
    if skip_dependencies:
        command.append("--skip-deps")
    return command


def cli_command(root: Path, target_platform: str, *arguments: str) -> list[str]:
    """Run the product JVM CLI through the candidate's Gradle application target."""

    gradle = WINDOWS_GRADLE_RELATIVE_PATH if target_platform == "windows" else GRADLE_RELATIVE_PATH
    return [
        str(root / gradle),
        "--no-daemon",
        ":app:run",
        "--args=" + " ".join(arguments),
    ]


def service_command(service: Path, target_platform: str, port: int | None) -> list[str]:
    """Return the service's public normal-mode command as an argument vector."""

    if target_platform == "windows":
        if port is None:
            raise SliceFailure("Windows service requires a loopback TCP port")
        return [str(service), "-port", str(port)]
    return [str(service)]


def emit_command_diagnostics(result: CommandResult) -> None:
    """Expose every captured child stream while retaining it for assertions.

    The slices need the captured text for machine-readable checks, but a
    successful command must not become diagnostically silent in hosted CI.
    Labels go to stderr; child stdout and stderr are written unchanged to their
    corresponding parent streams.
    """

    rendered = " ".join(result.command)
    print(
        f"[torturer-command] argv={rendered} returncode={result.returncode} stdout-begin",
        file=sys.stderr,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
        sys.stdout.flush()
    print("[torturer-command] stdout-end stderr-begin", file=sys.stderr)
    if result.stderr:
        sys.stderr.write(result.stderr)
        sys.stderr.flush()
    print("[torturer-command] stderr-end", file=sys.stderr)


def run_command(command: Sequence[str], *, cwd: Path, env: dict[str, str]) -> CommandResult:
    """Execute an argument vector without invoking a shell."""

    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result = CommandResult(tuple(command), completed.returncode, completed.stdout, completed.stderr)
    emit_command_diagnostics(result)
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
    process: subprocess.Popen[str],
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
    process: subprocess.Popen[str],
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
    return environment


def assert_windows_token_path(runtime: RuntimePaths) -> None:
    """Require only the token's generated location, never its secret contents."""

    path = runtime.token_path
    if path is None or not path.is_file() or path.is_symlink():
        raise SliceFailure("Windows service did not create a regular PROGRAMDATA/DobbyVPN control token")


def stop_service(process: subprocess.Popen[str], socket_path: Path | None) -> None:
    """Stop the unprivileged service and remove only our private Unix socket."""

    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.poll() is None:
        raise SliceFailure("service process survived termination")
    if socket_path is None:
        return
    if socket_path.exists() or socket_path.is_socket():
        details = socket_path.lstat()
        if not stat.S_ISSOCK(details.st_mode):
            raise SliceFailure(f"refusing to remove non-socket cleanup path: {socket_path}")
        socket_path.unlink()
    if socket_path.exists() or socket_path.is_socket():
        raise SliceFailure(f"control socket remained after cleanup: {socket_path}")


def assert_cli_contract(root: Path, target_platform: str, environment: dict[str, str], fixture: Path) -> None:
    """Exercise only non-connecting product CLI operations against the service."""

    gradle_dir = root / "kmp_module"
    help_result = run_command(cli_command(root, target_platform, "--help"), cwd=gradle_dir, env=environment)
    require_success(help_result, "CLI help")
    if "check-config" not in help_result.stdout or "disconnect" not in help_result.stdout:
        raise SliceFailure(f"CLI help did not expose the documented command surface\n{help_result.describe()}")

    status_result = run_command(
        cli_command(root, target_platform, "status", "--json"), cwd=gradle_dir, env=environment
    )
    require_success(status_result, "CLI status")
    if '"state": "Disconnected"' not in status_result.stdout:
        raise SliceFailure(f"CLI did not report the initial disconnected state\n{status_result.describe()}")

    malformed_result = run_command(
        cli_command(root, target_platform, "check-config", str(fixture)), cwd=gradle_dir, env=environment
    )
    require_nonzero(malformed_result, "CLI malformed local configuration rejection")

    disconnect_result = run_command(
        cli_command(root, target_platform, "disconnect"), cwd=gradle_dir, env=environment
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

    validate_target(target_platform, architecture)
    root = candidate_path(str(candidate))
    try:
        verify_source_checkout(root, expected_commit)
    except SourceCheckoutError as error:
        raise SliceFailure(str(error)) from error
    build_environment = os.environ.copy()
    require_success(
        run_command(
            service_build_command(root, target_platform, architecture, skip_dependencies=skip_dependencies),
            cwd=root,
            env=build_environment,
        ),
        f"public {target_platform} {architecture} service build",
    )
    require_success(
        run_command(
            app_build_command(root, target_platform, skip_dependencies=skip_dependencies),
            cwd=root,
            env=build_environment,
        ),
        f"public {target_platform} JVM application build",
    )

    service = root / SERVICE_RELATIVE_PATHS[target_platform]
    if not service.is_file() or (target_platform == "macos" and not os.access(service, os.X_OK)):
        raise SliceFailure(f"public build did not produce an executable {target_platform} service: {service}")

    with tempfile.TemporaryDirectory(prefix=f"torturer-{target_platform}-") as temporary:
        runtime_root = Path(temporary)
        runtime_root.chmod(0o700)
        runtime = build_runtime_paths(runtime_root, target_platform)
        runtime.fixture.write_text(MALFORMED_CONFIG, encoding="utf-8")
        runtime.fixture.chmod(0o600)
        port = reserve_loopback_port() if target_platform == "windows" else None
        environment = service_environment(target_platform, runtime, port)
        service_log_path = runtime.root / "service.log"
        with service_log_path.open("w", encoding="utf-8") as service_log:
            process = subprocess.Popen(
                service_command(service, target_platform, port),
                cwd=root,
                env=environment,
                text=True,
                stdout=service_log,
                stderr=subprocess.STDOUT,
            )
            try:
                if target_platform == "macos":
                    if runtime.socket_path is None:  # Defensive narrowing for type checkers.
                        raise SliceFailure("macOS runtime has no control socket path")
                    wait_for_unix_socket(runtime.socket_path, process, timeout_seconds)
                else:
                    if port is None:
                        raise SliceFailure("Windows runtime has no loopback TCP port")
                    wait_for_tcp(port, process, timeout_seconds)
                    assert_windows_token_path(runtime)
                assert_cli_contract(root, target_platform, environment, runtime.fixture)
            except SliceFailure as error:
                service_log.flush()
                logs = service_log_path.read_text(encoding="utf-8", errors="replace")
                raise SliceFailure(f"{error}\nservice log:\n{logs}") from error
            finally:
                stop_service(process, runtime.socket_path)
    if runtime_root.exists():
        raise SliceFailure(f"private {target_platform} runtime resources remained after cleanup: {runtime_root}")


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
        print(f"Torturer desktop slice failed: {error}", file=sys.stderr)
        return 1
    print(
        "Torturer desktop slice passed: source builds, safe CLI lifecycle, "
        "and private service cleanup verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
