"""Select one explicit hosted platform adapter."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .android import AndroidHostedAdapter
from .cli import CommandRunner
from .linux import LinuxHostedAdapter
from .macos import MacOSHostedAdapter
from .windows import WindowsHostedAdapter

_ADAPTERS: dict[str, type] = {
    "linux": LinuxHostedAdapter,
    "windows": WindowsHostedAdapter,
    "macos": MacOSHostedAdapter,
    "android": AndroidHostedAdapter,
}


def adapter_for_platform(
    platform: str,
    *,
    cli: Path | None = None,
    profile: Path,
    runner: CommandRunner,
    download_url: str | None = None,
    upload_url: str | None = None,
    adb: Path | None = None,
    source_sha: str | None = None,
    identity_url: str | None = None,
    latency_url: str | None = None,
    service_pid: int | None = None,
    service_binary: Path | None = None,
    service_socket: Path | None = None,
    service_library_path: Path | None = None,
    service_pid_file: Path | None = None,
    network_interface: str | None = None,
) -> Any:
    try:
        adapter_class = _ADAPTERS[platform]
    except KeyError as error:
        raise ValueError("unsupported hosted platform") from error
    kwargs: dict[str, object] = {
        "profile": profile,
        "runner": runner,
        "download_url": download_url,
        "upload_url": upload_url,
    }
    if platform == "android":
        for name, value in (
            ("cli", cli),
            ("service_pid", service_pid),
            ("service_binary", service_binary),
            ("service_socket", service_socket),
            ("service_library_path", service_library_path),
            ("service_pid_file", service_pid_file),
            ("network_interface", network_interface),
        ):
            if value is not None:
                raise ValueError(f"android adapter received unexpected {name}")
        kwargs.update({
            "adb": adb,
            "source_sha": source_sha,
            "identity_url": identity_url,
            "latency_url": latency_url,
        })
    else:
        if cli is None:
            raise ValueError("hosted desktop adapter requires --cli")
        kwargs["cli"] = cli
        if platform == "linux":
            kwargs.update({
                "service_pid": service_pid,
                "service_binary": service_binary,
                "service_socket": service_socket,
                "service_library_path": service_library_path,
                "service_pid_file": service_pid_file,
                "network_interface": network_interface,
            })
        elif platform in {"windows", "macos"}:
            kwargs.update({
                "service_pid": service_pid,
                "service_binary": service_binary,
                "service_pid_file": service_pid_file,
                "service_socket": service_socket,
            })
    return adapter_class(**kwargs)


__all__ = ["adapter_for_platform"]
