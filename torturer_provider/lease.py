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
_BUNDLE_JOURNAL_SCHEMA = 2
_JOURNAL_KIND = "dobbyvpn.render-lease-journal"
_ROLES = frozenset(("outline", "upload-sink"))


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
    role: str = "outline"

    def __post_init__(self) -> None:
        _require(self.run_id, _RUN_ID, "run_id")
        _require(self.platform, _PLATFORM, "platform")
        _require(self.service_name, _SERVICE_NAME, "service_name")
        _require(self.image_digest, _IMAGE_DIGEST, "image_digest")
        if self.role not in _ROLES:
            raise ValueError("role is invalid")
        suffix = self.platform if self.role == "outline" else "upload-sink"
        expected = f"dobby-torturer-{self.run_id}-{suffix}"
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
    role: str = "outline"

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
        if self.role not in _ROLES:
            raise ValueError("journal role is invalid")

    def to_json_object(self, *, include_role: bool = False) -> dict[str, object]:
        value = {
            "run_id": self.run_id,
            "service_id": self.service_id,
            "image_digest": self.image_digest,
            "state": self.state.value,
            "timestamp": self.timestamp,
            "cleanup_result": self.cleanup_result,
        }
        if include_role:
            value["role"] = self.role
        return value


class RenderLeaseJournal:
    """Atomic owner-only journal for trusted lease state transitions."""

    def __init__(self, path: str | os.PathLike[str], *, schema: int | None = None) -> None:
        self.path = Path(path)
        if self.path.exists() and not self.path.is_file():
            raise ValueError("lease journal path is not a regular file")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = stat.S_IMODE(self.path.parent.stat().st_mode)
        if mode & 0o077:
            raise PermissionError("lease journal directory is not owner-only")
        if schema not in (None, _JOURNAL_SCHEMA, _BUNDLE_JOURNAL_SCHEMA):
            raise ValueError("lease journal schema is invalid")
        self.schema = self._existing_schema() if self.path.exists() else (schema or _JOURNAL_SCHEMA)
        if schema is not None and self.path.exists() and self.schema != schema:
            raise ValueError("lease journal schema does not match requested schema")

    def _existing_schema(self) -> int:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("lease journal is unreadable") from error
        schema = document.get("schema") if isinstance(document, dict) else None
        if schema not in (_JOURNAL_SCHEMA, _BUNDLE_JOURNAL_SCHEMA):
            raise ValueError("lease journal has an invalid header")
        return int(schema)

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
        if not isinstance(document, dict) or document.get("schema") != self.schema or document.get("kind") != _JOURNAL_KIND:
            raise ValueError("lease journal has an invalid header")
        entries = document.get("records")
        if not isinstance(entries, list):
            raise ValueError("lease journal records are invalid")
        records: list[LeaseJournalRecord] = []
        for entry in entries:
            expected_keys = {
                "run_id", "service_id", "image_digest", "state", "timestamp", "cleanup_result"
            }
            if self.schema == _BUNDLE_JOURNAL_SCHEMA:
                expected_keys.add("role")
            if not isinstance(entry, dict) or set(entry) != expected_keys:
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
                        role=entry.get("role", "outline"),
                    )
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("lease journal entry is invalid") from error
        return tuple(records)

    def append(self, record: LeaseJournalRecord) -> None:
        if not isinstance(record, LeaseJournalRecord):
            raise TypeError("journal append requires a LeaseJournalRecord")
        if self.schema == _JOURNAL_SCHEMA and record.role != "outline":
            raise ValueError("legacy lease journal cannot contain a non-outline role")
        existing = list(self.records())
        existing.append(record)
        document = {
            "schema": self.schema,
            "kind": _JOURNAL_KIND,
            "records": [entry.to_json_object(include_role=self.schema == _BUNDLE_JOURNAL_SCHEMA) for entry in existing],
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
        cleanup_api: RenderAPI | None = None,
    ) -> None:
        if spec.name != descriptor.service_name or spec.image_digest != descriptor.image_digest:
            raise ValueError("service specification does not match lease descriptor")
        self.api = api
        self.spec = spec
        self.descriptor = descriptor
        self.journal = journal
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        # Acquisition and cleanup have different operational budgets. Keep
        # the readiness controller on the acquisition client, while every
        # cleanup/recovery operation uses the explicitly bounded client when
        # one is supplied.
        self.cleanup_api = api if cleanup_api is None else cleanup_api
        self._controller = DisposableRenderController(
            api,
            clock=monotonic_clock,
            sleeper=sleeper,
            cleanup_api=self.cleanup_api,
        )
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
                role=self.descriptor.role,
            )
        )

    def _transition(self, target: LeaseState, cleanup_result: str | None = None) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise LeaseStateError(f"invalid lease transition {self.state.value}->{target.value}")
        self.state = target
        self._append(cleanup_result)

    def acquire(
        self,
        *,
        timeout_seconds: float = 600.0,
        poll_seconds: float = 5.0,
        active_service_ids: tuple[str, ...] = (),
        deadline: float | None = None,
    ) -> RenderServiceReady:
        if self.state is not LeaseState.ABSENT:
            raise LeaseStateError("lease can only be acquired from absent")
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("lease readiness bounds must be positive")
        if deadline is not None and (
            isinstance(deadline, bool) or not isinstance(deadline, (int, float))
        ):
            raise ValueError("lease acquisition deadline is invalid")
        self._transition(LeaseState.CREATING)
        try:
            self.handle = self.api.create_service(self.spec)
            self._append(None)
            wait_seconds = timeout_seconds
            if deadline is not None:
                wait_seconds = deadline - self._monotonic_clock()
                if wait_seconds <= 0:
                    raise LeaseStateError("lease acquisition deadline expired")
            self.ready = self._controller._wait_until_ready(self.handle, wait_seconds, poll_seconds)
            self._transition(LeaseState.HEALTHY)
            return self.ready
        except BaseException:
            try:
                self._cleanup_after_failure(active_service_ids=active_service_ids)
            except BaseException as cleanup_error:
                raise LeaseCleanupError("lease creation cleanup was not verified") from cleanup_error
            raise

    def mark_issued(self) -> None:
        if self.state is not LeaseState.HEALTHY:
            raise LeaseStateError("profile can only be issued from healthy")
        self._transition(LeaseState.ISSUED)

    def begin_testing(self) -> None:
        if self.state is not LeaseState.ISSUED:
            raise LeaseStateError("testing can only begin after profile issuance")
        self._transition(LeaseState.TESTING)

    def _cleanup_after_failure(self, *, active_service_ids: tuple[str, ...] = ()) -> None:
        if self.handle is None:
            if self.state is not LeaseState.DELETING:
                self._transition(LeaseState.DELETING)
            try:
                # A create response can be lost after Render has accepted the
                # request. The run-scoped random namespace is the only safe
                # fallback selector when no exact service ID exists.
                # One create request can produce at most one service whose
                # response was lost.  Refuse an ambiguous namespace before
                # deleting anything; a second candidate is stale state, not
                # evidence that this request created two services.
                self.reap_orphans(
                    active_service_ids=active_service_ids,
                    older_than_seconds=0,
                    max_candidates=1,
                )
                RenderReaper(self.cleanup_api).assert_tagged_absent(
                    self.spec.owner_id,
                    self.descriptor.service_prefix,
                    active_service_ids=active_service_ids,
                )
            except BaseException as error:
                self._append("unverified-no-service-id")
                raise LeaseCleanupError("namespace cleanup was not verified") from error
            self._transition(LeaseState.ABSENT, "verified-namespace")
            return
        if self.state is not LeaseState.DELETING:
            self._transition(LeaseState.DELETING)
        self.cleanup_api.delete_service(self.handle.service_id)
        if self.cleanup_api.exists(self.handle.service_id):
            raise LeaseCleanupError("service deletion was not verified")
        self._transition(LeaseState.ABSENT, "verified")

    def cleanup(self, *, active_service_ids: tuple[str, ...] = ()) -> None:
        if self.state is LeaseState.ABSENT:
            return
        self._cleanup_after_failure(active_service_ids=active_service_ids)

    def reap_orphans(
        self,
        *,
        active_service_ids: tuple[str, ...] = (),
        older_than_seconds: float = 900.0,
        max_candidates: int | None = None,
    ) -> tuple[str, ...]:
        """Reap only this descriptor's random namespace, never a broad prefix."""

        reaper = RenderReaper(self.cleanup_api)
        return reaper.reap_tagged(
            self.spec.owner_id,
            self.descriptor.service_prefix,
            active_service_ids=active_service_ids,
            older_than_seconds=older_than_seconds,
            max_candidates=max_candidates,
        )


class RenderLeaseBundle:
    """Fail-closed lifecycle for one platform's Outline and upload-sink services."""

    def __init__(
        self,
        outline: RenderLease,
        upload_sink: RenderLease,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if outline.descriptor.role != "outline" or upload_sink.descriptor.role != "upload-sink":
            raise ValueError("lease bundle roles are invalid")
        if outline.descriptor.run_id != upload_sink.descriptor.run_id:
            raise ValueError("lease bundle run IDs differ")
        if outline.descriptor.platform != upload_sink.descriptor.platform:
            raise ValueError("lease bundle platforms differ")
        if outline.spec.owner_id != upload_sink.spec.owner_id:
            raise ValueError("lease bundle owners differ")
        if outline.journal.path != upload_sink.journal.path:
            raise ValueError("lease bundle journals differ")
        if outline.journal.schema != _BUNDLE_JOURNAL_SCHEMA or upload_sink.journal.schema != _BUNDLE_JOURNAL_SCHEMA:
            raise ValueError("lease bundle requires journal schema 2")
        self.outline = outline
        self.upload_sink = upload_sink
        self._monotonic_clock = monotonic_clock

    @property
    def leases(self) -> tuple[RenderLease, RenderLease]:
        return (self.outline, self.upload_sink)

    def acquire(self, *, timeout_seconds: float = 600.0, poll_seconds: float = 5.0) -> tuple[RenderServiceReady, RenderServiceReady]:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("lease bundle readiness bounds must be positive")
        deadline = self._monotonic_clock() + timeout_seconds

        def ensure_remaining() -> float:
            remaining = deadline - self._monotonic_clock()
            if remaining <= 0:
                raise LeaseStateError("lease bundle acquisition deadline expired")
            return remaining

        try:
            self.outline.acquire(
                poll_seconds=poll_seconds,
                deadline=deadline,
            )
            if self.outline.handle is None:
                raise LeaseStateError("Outline lease handle is missing after acquisition")
            outline_id = self.outline.handle.service_id
            ensure_remaining()
            self.upload_sink.acquire(
                poll_seconds=poll_seconds,
                active_service_ids=(outline_id,),
                deadline=deadline,
            )
            if self.outline.ready is None or self.upload_sink.ready is None:
                raise LeaseStateError("lease bundle readiness is incomplete")
            if self.outline.handle.service_id == self.upload_sink.handle.service_id:
                raise LeaseStateError("lease bundle service IDs must be distinct")
            return self.outline.ready, self.upload_sink.ready
        except BaseException:
            try:
                self.cleanup()
            except BaseException as cleanup_error:
                raise LeaseCleanupError("lease bundle acquisition cleanup was not verified") from cleanup_error
            raise

    def mark_issued(self) -> None:
        self.outline.mark_issued()
        try:
            self.upload_sink.mark_issued()
        except BaseException:
            self.cleanup()
            raise

    def begin_testing(self) -> None:
        self.outline.begin_testing()
        try:
            self.upload_sink.begin_testing()
        except BaseException:
            self.cleanup()
            raise

    def cleanup(self) -> None:
        failures: list[BaseException] = []
        for lease in reversed(self.leases):
            active = tuple(
                other.handle.service_id
                for other in self.leases
                if other is not lease and other.handle is not None
            )
            try:
                lease.cleanup(active_service_ids=active)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise LeaseCleanupError("lease bundle cleanup was not verified") from failures[0]
        # Exact-ID deletion above is necessary but insufficient for a schema-2
        # bundle: a lost create response or stale provider state can leave a
        # second service in this run/platform namespace. Reuse the bounded,
        # fail-closed reaper contract used by lease_cli. With no active IDs,
        # any matching candidate is unexpected; max_candidates=0 therefore
        # refuses to delete or silently ignore it.
        reaper = RenderReaper(self.outline.cleanup_api)
        try:
            reaper.reap_tagged(
                self.outline.spec.owner_id,
                self.outline.descriptor.service_prefix,
                older_than_seconds=0,
                max_candidates=0,
            )
            reaper.assert_tagged_absent(
                self.outline.spec.owner_id,
                self.outline.descriptor.service_prefix,
            )
        except BaseException as error:
            raise LeaseCleanupError("lease bundle namespace cleanup was not verified") from error


__all__ = [
    "LeaseCleanupError",
    "LeaseJournalRecord",
    "LeaseState",
    "LeaseStateError",
    "RenderLeaseBundle",
    "RenderLease",
    "RenderLeaseDescriptor",
    "RenderLeaseJournal",
]
