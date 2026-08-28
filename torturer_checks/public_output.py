"""Small public-output boundary for hosted verification helpers.

Original command/service bytes remain in the owner-controlled runner evidence
directory. Public Actions receives only a stable kind/status and an
unpredictable correlation identifier with byte count and SHA-256.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Mapping


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ABSOLUTE_PATH = re.compile(
    r"(?:/(?:Users|home|private/var|var/folders|tmp)/|[A-Za-z]:[\\/])[^\s:'\"]+"
)
_DIAGNOSTIC_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s]+")
_DIAGNOSTIC_SECRET = re.compile(
    r"(?ix)(?P<label>\b(?:token|password|secret|credential|authorization|cookie)\b\s*[:=]\s*)"
    r"(?:bearer\s+|basic\s+)?[^\s,;]+"
)
_DIAGNOSTIC_MARKERS = (
    "error:",
    "fatal error",
    "build failed",
    "the following build commands failed",
    "undefined symbols",
    "ld:",
    "clang:",
    "swiftcompile",
    "compileswift",
    "no such module",
    "framework not found",
    "codesign",
)
_MAX_DIAGNOSTIC_LINES = 24
_MAX_DIAGNOSTIC_BYTES = 8 * 1024


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _redact_diagnostic_line(line: str) -> str:
    """Remove runner paths, URLs, and credential-shaped values from one line."""

    line = _ANSI_ESCAPE.sub("", line)
    line = _ABSOLUTE_PATH.sub("<path>", line)
    line = _DIAGNOSTIC_URL.sub("<redacted-url>", line)
    return _DIAGNOSTIC_SECRET.sub(r"\g<label><redacted>", line)


def safe_diagnostic_excerpt(raw_output: str) -> str:
    """Return a bounded, scrubbed compiler/linker excerpt for public failures.

    Callers retain the complete original command bytes separately.  This
    derived view is intentionally limited to stable diagnostic markers and is
    safe to include in a hosted workflow's failure line.
    """

    if not isinstance(raw_output, str):
        return ""
    selected: list[str] = []
    total = 0
    for raw_line in raw_output.splitlines():
        line = _redact_diagnostic_line(raw_line).strip()
        if not line:
            continue
        lowered = line.lower()
        if not any(marker in lowered for marker in _DIAGNOSTIC_MARKERS):
            continue
        encoded_size = len(line.encode("utf-8", errors="replace"))
        if encoded_size > _MAX_DIAGNOSTIC_BYTES or total + encoded_size + 1 > _MAX_DIAGNOSTIC_BYTES:
            break
        selected.append(line)
        total += encoded_size + 1
        if len(selected) >= _MAX_DIAGNOSTIC_LINES:
            break
    return "\n".join(selected)


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
