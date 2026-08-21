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
    cli: Path,
    profile: Path,
    runner: CommandRunner,
    download_url: str | None = None,
    upload_url: str | None = None,
) -> Any:
    try:
        adapter_class = _ADAPTERS[platform]
    except KeyError as error:
        raise ValueError("unsupported hosted platform") from error
    return adapter_class(
        cli=cli,
        profile=profile,
        runner=runner,
        download_url=download_url,
        upload_url=upload_url,
    )


__all__ = ["adapter_for_platform"]
