"""Stateful, secret-free lifecycle wrapper for one disposable Render lease.

The Render API client owns provider control-plane calls.  This module owns the
trusted lease state machine and its local journal.  It deliberately does not
generate, store, serialize, or return an Outline key or client profile.  Those
values belong to the server-image/profile handoff protocol and must cross a
trusted workflow boundary separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time
from typing import Callable

from .render import (
    DisposableRenderController,
    RenderAPI,
    RenderAPIError,
    RenderReaper,
    RenderServiceHandle,
    RenderServiceReady,
    RenderServiceSpec,
)


_RUN_ID = re.compile(r"^[a-f0-9]{32}$")
_PLATFORM = re.compile(r"^[a-z][a-z0-9-]{0,13}$")
_SERVICE_NAME = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SERVICE_ID = re.compile(r"^srv-[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_CLEANUP_RESULT = re.compile(r"^[a-z0-9_-]{1,64}$")
_JOURNAL_SCHEMA = 1
_JOURNAL_KIND = "dobbyvpn.render-lease-journal"


class LeaseState(str, Enum):
    ABSENT = "absent"
    CREATING = "creating"
    HEALTHY = "healthy"
    ISSUED = "issued"
    TESTING = "testing"
    DELETING = "deleting"


class LeaseStateError(RuntimeError):
    """A requested transition is not valid for the current lease state."""


class LeaseCleanupError(RuntimeError):
    """Cleanup could not be independently proven."""


def _require(value: object, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{name} has an invalid format")
    return value


def _utc_timestamp(epoch_seconds: float) -> str:
    if not isinstance(epoch_seconds, (int, float)) or isinstance(epoch_seconds, bool):
        raise ValueError("lease clock returned an invalid value")
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class RenderLeaseDescriptor:
    """Opaque run identity and the dedicated Render service namespace."""

    run_id: str
    platform: str
    service_name: str
    image_digest: str

    def __post_init__(self) -> None:
        _require(self.run_id, _RUN_ID, "run_id")
        _require(self.platform, _PLATFORM, "platform")
        _require(self.service_name, _SERVICE_NAME, "service_name")
        _require(self.image_digest, _IMAGE_DIGEST, "image_digest")
        expected = f"dobby-torturer-{self.run_id}-{self.platform}"
        if self.service_name != expected:
            raise ValueError("service_name does not match the lease namespace")

    @property
    def service_prefix(self) -> str:
        """The dedicated, random namespace used by the independent reaper."""

        return f"dobby-torturer-{self.run_id}-"

    @classmethod
    def create(
        cls,
        platform: str,
        image_digest: str,
        *,
        token_bytes: int = 16,
    ) -> "RenderLeaseDescriptor":
        _require(platform, _PLATFORM, "platform")
        _require(image_digest, _IMAGE_DIGEST, "image_digest")
        if token_bytes < 16 or token_bytes > 32:
            raise ValueError("lease run-id entropy must be between 16 and 32 bytes")
        run_id = secrets.token_hex(token_bytes)
        return cls(run_id, platform, f"dobby-torturer-{run_id}-{platform}", image_digest)


@dataclass(frozen=True)
class LeaseJournalRecord:
    """One safe journal entry; no profile, key, endpoint, or credential field."""

    run_id: str
    service_id: str | None
    image_digest: str
    state: LeaseState
    timestamp: str
    cleanup_result: str | None = None

    def __post_init__(self) -> None:
        _require(self.run_id, _RUN_ID, "run_id")
        if self.service_id is not None:
            _require(self.service_id, _SERVICE_ID, "service_id")
        _require(self.image_digest, _IMAGE_DIGEST, "image_digest")
        if not isinstance(self.state, LeaseState):
            raise ValueError("journal state is invalid")
        if not isinstance(self.timestamp, str) or not self.timestamp:
            raise ValueError("journal timestamp is invalid")
        if self.cleanup_result is not None:
            _require(self.cleanup_result, _CLEANUP_RESULT, "cleanup_result")

    def to_json_object(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "service_id": self.service_id,
            "image_digest": self.image_digest,
            "state": self.state.value,
            "timestamp": self.timestamp,
            "cleanup_result": self.cleanup_result,
        }


class RenderLeaseJournal:
    """Atomic owner-only journal for trusted lease state transitions."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        if self.path.exists() and not self.path.is_file():
            raise ValueError("lease journal path is not a regular file")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = stat.S_IMODE(self.path.parent.stat().st_mode)
        if mode & 0o077:
            raise PermissionError("lease journal directory is not owner-only")

    def records(self) -> tuple[LeaseJournalRecord, ...]:
        if not self.path.exists():
            return ()
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            raise PermissionError("lease journal is not owner-only")
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("lease journal is unreadable") from error
        if not isinstance(document, dict) or document.get("schema") != _JOURNAL_SCHEMA or document.get("kind") != _JOURNAL_KIND:
            raise ValueError("lease journal has an invalid header")
        entries = document.get("records")
        if not isinstance(entries, list):
            raise ValueError("lease journal records are invalid")
        records: list[LeaseJournalRecord] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "run_id", "service_id", "image_digest", "state", "timestamp", "cleanup_result"
            }:
                raise ValueError("lease journal entry has unsafe fields")
            try:
                records.append(
                    LeaseJournalRecord(
                        run_id=entry["run_id"],
                        service_id=entry["service_id"],
                        image_digest=entry["image_digest"],
                        state=LeaseState(entry["state"]),
                        timestamp=entry["timestamp"],
                        cleanup_result=entry["cleanup_result"],
                    )
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("lease journal entry is invalid") from error
        return tuple(records)

    def append(self, record: LeaseJournalRecord) -> None:
        if not isinstance(record, LeaseJournalRecord):
            raise TypeError("journal append requires a LeaseJournalRecord")
        existing = list(self.records())
        existing.append(record)
        document = {
            "schema": _JOURNAL_SCHEMA,
            "kind": _JOURNAL_KIND,
            "records": [entry.to_json_object() for entry in existing],
        }
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                os.chmod(temporary_name, 0o600)
                json.dump(document, temporary, sort_keys=True, separators=(",", ":"))
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, self.path)
            os.chmod(self.path, 0o600)
        except Exception:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass
            raise


_ALLOWED_TRANSITIONS: dict[LeaseState, frozenset[LeaseState]] = {
    LeaseState.ABSENT: frozenset({LeaseState.CREATING}),
    LeaseState.CREATING: frozenset({LeaseState.HEALTHY, LeaseState.DELETING}),
    LeaseState.HEALTHY: frozenset({LeaseState.ISSUED, LeaseState.DELETING}),
    LeaseState.ISSUED: frozenset({LeaseState.TESTING, LeaseState.DELETING}),
    LeaseState.TESTING: frozenset({LeaseState.DELETING}),
    LeaseState.DELETING: frozenset({LeaseState.ABSENT}),
}


class RenderLease:
    """One bounded Render service lease with fail-closed cleanup."""

    def __init__(
        self,
        api: RenderAPI,
        spec: RenderServiceSpec,
        descriptor: RenderLeaseDescriptor,
        journal: RenderLeaseJournal,
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if spec.name != descriptor.service_name or spec.image_digest != descriptor.image_digest:
            raise ValueError("service specification does not match lease descriptor")
        self.api = api
        self.spec = spec
        self.descriptor = descriptor
        self.journal = journal
        self._wall_clock = wall_clock
        self._controller = DisposableRenderController(api, clock=monotonic_clock, sleeper=sleeper)
        self.state = LeaseState.ABSENT
        self.handle: RenderServiceHandle | None = None
        self.ready: RenderServiceReady | None = None
        self._append(None)

    def _append(self, cleanup_result: str | None) -> None:
        self.journal.append(
            LeaseJournalRecord(
                run_id=self.descriptor.run_id,
                service_id=None if self.handle is None else self.handle.service_id,
                image_digest=self.descriptor.image_digest,
                state=self.state,
                timestamp=_utc_timestamp(self._wall_clock()),
                cleanup_result=cleanup_result,
            )
        )

    def _transition(self, target: LeaseState, cleanup_result: str | None = None) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise LeaseStateError(f"invalid lease transition {self.state.value}->{target.value}")
        self.state = target
        self._append(cleanup_result)

    def acquire(self, *, timeout_seconds: float = 600.0, poll_seconds: float = 5.0) -> RenderServiceReady:
        if self.state is not LeaseState.ABSENT:
            raise LeaseStateError("lease can only be acquired from absent")
        self._transition(LeaseState.CREATING)
        try:
            self.handle = self.api.create_service(self.spec)
            self._append(None)
            self.ready = self._controller._wait_until_ready(self.handle, timeout_seconds, poll_seconds)
            self._transition(LeaseState.HEALTHY)
            return self.ready
        except Exception as error:
            try:
                self._cleanup_after_failure()
            except Exception as cleanup_error:
                raise LeaseCleanupError("lease creation cleanup was not verified") from cleanup_error
            raise error

    def mark_issued(self) -> None:
        if self.state is not LeaseState.HEALTHY:
            raise LeaseStateError("profile can only be issued from healthy")
        self._transition(LeaseState.ISSUED)

    def begin_testing(self) -> None:
        if self.state is not LeaseState.ISSUED:
            raise LeaseStateError("testing can only begin after profile issuance")
        self._transition(LeaseState.TESTING)

    def _cleanup_after_failure(self) -> None:
        if self.handle is None:
            if self.state is LeaseState.DELETING:
                self._append("unverified-no-service-id")
            else:
                self._transition(LeaseState.DELETING, "unverified-no-service-id")
            raise LeaseCleanupError("no exact service ID was returned")
        if self.state is not LeaseState.DELETING:
            self._transition(LeaseState.DELETING)
        self.api.delete_service(self.handle.service_id)
        if self.api.exists(self.handle.service_id):
            raise LeaseCleanupError("service deletion was not verified")
        self._transition(LeaseState.ABSENT, "verified")

    def cleanup(self) -> None:
        if self.state is LeaseState.ABSENT:
            return
        self._cleanup_after_failure()

    def reap_orphans(self, *, active_service_ids: tuple[str, ...] = (), older_than_seconds: float = 900.0) -> tuple[str, ...]:
        """Reap only this descriptor's random namespace, never a broad prefix."""

        reaper = RenderReaper(self.api)
        return reaper.reap_tagged(
            self.spec.owner_id,
            self.descriptor.service_prefix,
            active_service_ids=active_service_ids,
            older_than_seconds=older_than_seconds,
        )


__all__ = [
    "LeaseCleanupError",
    "LeaseJournalRecord",
    "LeaseState",
    "LeaseStateError",
    "RenderLease",
    "RenderLeaseDescriptor",
    "RenderLeaseJournal",
]
