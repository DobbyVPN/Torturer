"""Validated, non-secret request exchanged with the trusted lease workflow."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Mapping


_RUN_ID = re.compile(r"^[a-f0-9]{32}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLATFORM = frozenset(("linux", "windows", "macos", "android"))


class LeaseRequestError(ValueError):
    """A lease request is malformed or contains an unsafe field."""


@dataclass(frozen=True)
class RenderLeaseRequest:
    """Only opaque correlation and immutable image identity cross the boundary."""

    run_id: str
    platform: str
    image_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or _RUN_ID.fullmatch(self.run_id) is None:
            raise LeaseRequestError("run_id is invalid")
        if self.platform not in _PLATFORM:
            raise LeaseRequestError("platform is invalid")
        if not isinstance(self.image_digest, str) or _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise LeaseRequestError("image_digest is invalid")

    @classmethod
    def parse(cls, value: Mapping[str, object]) -> "RenderLeaseRequest":
        if not isinstance(value, Mapping) or set(value) != {"schema", "kind", "run_id", "platform", "image_digest"}:
            raise LeaseRequestError("request has an unexpected shape")
        if value.get("schema") != 1 or value.get("kind") != "dobbyvpn.render-lease-request":
            raise LeaseRequestError("request identity is invalid")
        return cls(
            run_id=value.get("run_id", ""),
            platform=value.get("platform", ""),
            image_digest=value.get("image_digest", ""),
        )

    @classmethod
    def from_file(cls, path: Path) -> "RenderLeaseRequest":
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            raise LeaseRequestError("request file is unavailable")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise LeaseRequestError("request file is invalid JSON") from error
        if not isinstance(value, Mapping):
            raise LeaseRequestError("request must be an object")
        return cls.parse(value)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": 1,
            "kind": "dobbyvpn.render-lease-request",
            "run_id": self.run_id,
            "platform": self.platform,
            "image_digest": self.image_digest,
        }
