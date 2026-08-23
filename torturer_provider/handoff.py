"""Argument-vector helpers for the trusted encrypted profile handoff.

The platform job creates an ephemeral RSA recipient certificate and keeps its
private key owner-only.  The trusted lease job uses OpenSSL CMS with the public
certificate to encrypt a short-lived profile artifact.  This module only
constructs validated argument vectors and checks private-file boundaries; it
never places plaintext profile material in a command argument or a log.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
from typing import Final


_HEX32: Final = re.compile(r"^[0-9a-f]{32}$")
_SOURCE_SHA: Final = re.compile(r"^[0-9a-f]{40}$")
_PLATFORM: Final = frozenset(("linux", "windows", "macos", "android"))
_OPENSSL: Final = "openssl"


class HandoffContractError(ValueError):
    """Raised when an encrypted handoff input or boundary is unsafe."""


def require_source_sha(value: object) -> str:
    """Validate the full, non-zero Git SHA of the DobbyVPN candidate.

    A short SHA, an omitted value, an uppercase value, and the all-zero
    sentinel are not identities.  Keeping this check in the handoff module
    gives every request/lease producer the same fail-closed rule before any
    profile is decrypted.
    """

    if not isinstance(value, str) or _SOURCE_SHA.fullmatch(value) is None or value == "0" * 40:
        raise HandoffContractError("source SHA is invalid")
    return value


def _require_run_and_platform(origin_run_id: object, platform: object) -> tuple[str, str]:
    if not isinstance(origin_run_id, str) or not _HEX32.fullmatch(origin_run_id):
        raise HandoffContractError("origin run id is invalid")
    if not isinstance(platform, str) or platform not in _PLATFORM:
        raise HandoffContractError("platform is invalid")
    return origin_run_id, platform


def lease_correlation_id(origin_run_id: object, platform: object, source_sha: object) -> str:
    """Return the opaque deterministic identity for one candidate lease.

    The source SHA is part of the hash domain, so replaying a request under a
    different DobbyVPN commit cannot address the same handoff identity.  The
    source itself is not exposed in the artifact name.
    """

    run_id, normalized_platform = _require_run_and_platform(origin_run_id, platform)
    normalized_source = require_source_sha(source_sha)
    material = f"dobbyvpn.render-lease.v1\0{run_id}\0{normalized_platform}\0{normalized_source}".encode(
        "ascii"
    )
    return hashlib.sha256(material).hexdigest()[:32]


def validate_lease_correlation(
    *,
    expected_run_id: object,
    expected_platform: object,
    expected_source_sha: object,
    request_run_id: object,
    request_platform: object,
    request_source_sha: object,
) -> str:
    """Validate a request against trusted run/platform/source provenance.

    This is intentionally a pre-decryption check.  It rejects omission and
    mismatch of the candidate source before the caller can use the profile,
    and returns the only identity that may be used for lease correlation.
    """

    expected_id = lease_correlation_id(expected_run_id, expected_platform, expected_source_sha)
    request_id = lease_correlation_id(request_run_id, request_platform, request_source_sha)
    if request_id != expected_id:
        raise HandoffContractError("lease correlation identity mismatch")
    return expected_id


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


def artifact_name(origin_run_id: object, platform: object, source_sha: object) -> str:
    """Return a source-bound opaque artifact name."""

    _, normalized_platform = _require_run_and_platform(origin_run_id, platform)
    return f"render-lease-{lease_correlation_id(origin_run_id, normalized_platform, source_sha)}-{normalized_platform}"


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
