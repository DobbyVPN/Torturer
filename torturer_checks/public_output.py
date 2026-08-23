"""Small public-output boundary for hosted verification helpers.

Original command/service bytes remain in the owner-controlled runner evidence
directory. Public Actions receives only a stable kind/status and an
unpredictable correlation identifier with byte count and SHA-256.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Mapping


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def emit_evidence(
    kind: str,
    *,
    status: str,
    payloads: Mapping[str, bytes],
) -> str:
    """Print only bounded evidence metadata and return its opaque identifier."""

    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
    if not kind or any(character not in allowed for character in kind):
        raise ValueError("evidence kind is invalid")
    if not status or any(character not in allowed for character in status):
        raise ValueError("evidence status is invalid")
    identifier = secrets.token_hex(16)
    fields = [f"kind={kind}", f"status={status}", f"id={identifier}"]
    for name, payload in payloads.items():
        if not name or any(character not in allowed for character in name):
            raise ValueError("evidence stream name is invalid")
        if not isinstance(payload, bytes):
            raise TypeError("evidence payload must be bytes")
        fields.extend((f"{name}_bytes={len(payload)}", f"{name}_sha256={_digest(payload)}"))
    print("diagnostic_evidence " + " ".join(fields))
    return identifier
