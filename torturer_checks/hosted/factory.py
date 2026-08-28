"""Select one explicit hosted platform adapter."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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

_DISPOSABLE_UPLOAD_PATH = re.compile(r"^/upload/([0-9a-f]{32})$")


@dataclass(frozen=True)
class DisposableMeasurementEndpoints:
    """Token-bound endpoints exposed by the disposable Render sink."""

    identity_url: str
    latency_url: str
    download_url: str
    upload_url: str


def disposable_measurement_endpoints(upload_url: str) -> DisposableMeasurementEndpoints:
    """Derive the other test-owned probes from one encrypted upload URL."""

    if not isinstance(upload_url, str) or not 12 <= len(upload_url) <= 512:
        raise ValueError("disposable upload URL is invalid")
    try:
        parsed = urlsplit(upload_url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("disposable upload URL is invalid") from error
    match = _DISPOSABLE_UPLOAD_PATH.fullmatch(parsed.path)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or match is None
    ):
        raise ValueError("disposable upload URL is invalid")
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")
    token = match.group(1)
    download_url = f"{origin}/download/{token}"
    return DisposableMeasurementEndpoints(
        identity_url=f"{origin}/identity/{token}",
        latency_url=download_url,
        download_url=download_url,
        upload_url=upload_url,
    )


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
    service_identity_file: Path | None = None,
    network_interface: str | None = None,
) -> Any:
    try:
        adapter_class = _ADAPTERS[platform]
    except KeyError as error:
        raise ValueError("unsupported hosted platform") from error
    if (
        upload_url is not None
        and identity_url is None
        and latency_url is None
        and download_url is None
    ):
        endpoints = disposable_measurement_endpoints(upload_url)
        identity_url = endpoints.identity_url
        latency_url = endpoints.latency_url
        download_url = endpoints.download_url

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
            ("service_identity_file", service_identity_file),
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
        kwargs["identity_url"] = identity_url
        if platform == "linux":
            kwargs.update({
                "service_pid": service_pid,
                "service_binary": service_binary,
                "service_socket": service_socket,
                "service_library_path": service_library_path,
                "service_pid_file": service_pid_file,
                "service_identity_file": service_identity_file,
                "network_interface": network_interface,
            })
        elif platform in {"windows", "macos"}:
            kwargs.update({
                "service_pid": service_pid,
                "service_binary": service_binary,
                "service_pid_file": service_pid_file,
                "service_identity_file": service_identity_file,
                "service_socket": service_socket,
            })
    return adapter_class(**kwargs)


__all__ = [
    "DisposableMeasurementEndpoints",
    "adapter_for_platform",
    "disposable_measurement_endpoints",
]
