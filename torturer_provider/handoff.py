"""Argument-vector helpers for the trusted encrypted profile handoff.

The platform job creates an ephemeral RSA recipient certificate and keeps its
private key owner-only.  The trusted lease job uses OpenSSL CMS with the public
certificate to encrypt a short-lived profile artifact.  This module only
constructs validated argument vectors and checks private-file boundaries; it
never places plaintext profile material in a command argument or a log.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Final


_HEX32: Final = re.compile(r"^[0-9a-f]{32}$")
_PLATFORM: Final = re.compile(r"^[a-z][a-z0-9-]{0,13}$")
_OPENSSL: Final = "openssl"


class HandoffContractError(ValueError):
    """Raised when an encrypted handoff input or boundary is unsafe."""


def _file_argument(value: object, name: str) -> str:
    if not isinstance(value, Path):
        raise HandoffContractError(f"{name} must be a pathlib.Path")
    text = str(value)
    if not text or "\x00" in text or text.startswith("-"):
        raise HandoffContractError(f"{name} is not a safe file argument")
    return text


def require_owner_only(path: Path) -> None:
    """Reject missing, symlinked, non-regular, or group-readable handoff files."""

    try:
        info = path.lstat()
    except OSError as error:
        raise HandoffContractError("handoff file is unavailable") from error
    if not path.is_file() or path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise HandoffContractError("handoff file must be a regular owner-only file")


def artifact_name(origin_run_id: str, platform: str) -> str:
    """Return an opaque artifact name without endpoint/profile material."""

    if not isinstance(origin_run_id, str) or not _HEX32.fullmatch(origin_run_id):
        raise HandoffContractError("origin run id is invalid")
    if not isinstance(platform, str) or not _PLATFORM.fullmatch(platform):
        raise HandoffContractError("platform is invalid")
    return f"render-lease-{origin_run_id}-{platform}"


def cms_encrypt_command(plaintext: Path, recipient_certificate: Path, ciphertext: Path) -> tuple[str, ...]:
    """Build an OpenSSL CMS AES-GCM encryption argv; no shell interpolation."""

    source = _file_argument(plaintext, "plaintext")
    recipient = _file_argument(recipient_certificate, "recipient certificate")
    target = _file_argument(ciphertext, "ciphertext")
    if source == target or recipient == target:
        raise HandoffContractError("handoff input and output files must differ")
    return (
        _OPENSSL,
        "cms",
        "-encrypt",
        "-binary",
        "-aes-256-gcm",
        "-in",
        source,
        "-out",
        target,
        "-outform",
        "DER",
        recipient,
    )


def cms_decrypt_command(ciphertext: Path, recipient_certificate: Path, private_key: Path, plaintext: Path) -> tuple[str, ...]:
    """Build an OpenSSL CMS decryption argv; key contents never enter argv."""

    source = _file_argument(ciphertext, "ciphertext")
    recipient = _file_argument(recipient_certificate, "recipient certificate")
    key = _file_argument(private_key, "private key")
    target = _file_argument(plaintext, "plaintext")
    if source == target or key == target or recipient == target:
        raise HandoffContractError("handoff input and output files must differ")
    return (
        _OPENSSL,
        "cms",
        "-decrypt",
        "-binary",
        "-inform",
        "DER",
        "-in",
        source,
        "-recip",
        recipient,
        "-inkey",
        key,
        "-out",
        target,
    )
