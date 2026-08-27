#!/usr/bin/env python3
"""Trusted Render lease command boundary.

This command is intended for a protected workflow only. It accepts an opaque
request and protected provider/image settings, creates one lease, writes the
plaintext client profile to an owner-only file for immediate CMS encryption,
and emits only a safe lease record. It never prints a profile, URL, key, or
provider token.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from urllib.parse import urlsplit

from .lease import (
    LeaseJournalRecord,
    LeaseState,
    RenderLease,
    RenderLeaseBundle,
    RenderLeaseDescriptor,
    RenderLeaseJournal,
)
from .lease_request import LeaseRequestError, RenderLeaseRequest
from .outline import OutlineWSSProfile
from .render import RenderAPI, RenderAPIError, RenderReaper, RenderServiceSpec


_IMAGE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{2,255}$")
_SERVICE_ID = re.compile(r"^srv-[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UPLOAD_PATH = re.compile(r"^/upload/[0-9a-f]{32}$")
_OUTLINE_CONFIG_COMMAND = "/outline-ss-server -config=/etc/secrets/config.yml"
_UPLOAD_SINK_COMMAND = "/upload-sink --path-file=/etc/secrets/upload-path"
_UPLOAD_SINK_ROLE = "upload-sink"


def _owner_output(path: Path, payload: dict[str, object]) -> None:
    _owner_text(path, json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _ensure_owner_directory(path: Path) -> None:
    """Create one private directory path without following symlinks."""

    path = Path(path)
    if path.is_absolute() and path == Path(path.anchor):
        raise ValueError("owner output directory must not be the filesystem root")
    if path.is_absolute():
        current = Path(path.anchor)
        parts = path.parts[1:]
    else:
        current = Path(".")
        parts = path.parts
    for part in parts:
        if part in ("", "."):
            continue
        candidate = current / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                # A concurrent creator is acceptable only if it produced a
                # real directory; a symlink is never an output root.
                pass
            info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("owner output directory is not a regular directory")
        current = candidate

    info = current.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("owner output directory is not a regular directory")
    # The workflow's final output directory is disposable and must not be
    # readable by another local user. Do not chmod a caller's broad shared
    # directory; reject it instead. The directory fd is re-checked below
    # with O_NOFOLLOW before any secret bytes are written.
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("owner output directory is not owner-only")


def _owner_text(path: Path, text: str) -> None:
    path = Path(path)
    if not path.name or path.name in {".", ".."}:
        raise ValueError("owner output filename is invalid")
    _ensure_owner_directory(path.parent)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path.parent, directory_flags)
    temporary_name: str | None = None
    temporary_fd: int | None = None
    temporary_created = False
    replaced = False
    try:
        directory_info = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_info.st_mode):
            raise ValueError("owner output parent is not a directory")
        os.fchmod(directory_fd, 0o700)

        try:
            existing = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
                raise ValueError("owner output path is not a regular file")

        temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
        temporary_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(temporary_name, temporary_flags, 0o600, dir_fd=directory_fd)
        temporary_created = True
        with os.fdopen(temporary_fd, "wb", closefd=True) as output:
            temporary_fd = None
            output.write(text.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        replaced = True
        os.fsync(directory_fd)
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_name is not None and temporary_created and not replaced:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _require_owner_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_mode & 0o077:
        raise ValueError("lease file is not owner-only")


def _safe_lease_payload(
    request: RenderLeaseRequest,
    service_id: str,
    generation: str,
    state: str,
    cleanup: str | None = None,
) -> dict[str, object]:
    if _SERVICE_ID.fullmatch(service_id) is None:
        raise ValueError("service ID is invalid")
    payload: dict[str, object] = {
        "schema": 1,
        "kind": "dobbyvpn.render-lease",
        "run_id": request.run_id,
        "platform": request.platform,
        "source_sha": request.source_sha,
        "service_id": service_id,
        "image_digest": request.image_digest,
        "provider_generation": generation,
        "state": state,
    }
    if cleanup is not None:
        payload["cleanup"] = cleanup
    return payload


def _safe_bundle_payload(
    request: RenderLeaseRequest,
    outline: RenderLease,
    upload_sink: RenderLease,
    state: str,
    cleanup: str | None = None,
) -> dict[str, object]:
    services: list[dict[str, object]] = []
    for lease in (outline, upload_sink):
        if lease.handle is None or lease.ready is None:
            raise ValueError("lease bundle service is not ready")
        services.append({
            "role": lease.descriptor.role,
            "service_id": lease.handle.service_id,
            "image_digest": lease.descriptor.image_digest,
            "provider_generation": lease.ready.provider_generation,
        })
    payload: dict[str, object] = {
        "schema": 2,
        "kind": "dobbyvpn.render-lease",
        "run_id": request.run_id,
        "platform": request.platform,
        "source_sha": request.source_sha,
        "services": services,
        "state": state,
    }
    if cleanup is not None:
        payload["cleanup"] = cleanup
    return payload


def _upload_path() -> str:
    path = f"/upload/{secrets.token_hex(16)}"
    if _UPLOAD_PATH.fullmatch(path) is None:
        raise ValueError("generated upload path is invalid")
    return path


def _upload_url(service_url: str, path: str) -> str:
    if _UPLOAD_PATH.fullmatch(path) is None:
        raise ValueError("upload path is invalid")
    parsed = urlsplit(service_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise ValueError("upload service URL is invalid")
    return service_url.rstrip("/") + path

def _cleanup_journal(
    path: Path,
    request: RenderLeaseRequest,
    services: tuple[dict[str, object], ...] | None,
) -> tuple[RenderLeaseJournal, dict[str, LeaseJournalRecord]]:
    _require_owner_file(path)
    journal = RenderLeaseJournal(path)
    records = journal.records()
    if not records:
        raise ValueError("lease cleanup journal is empty")
    if services is None:
        grouped: dict[str, dict[str, set[str]]] = {}
        for record in records:
            item = grouped.setdefault(record.role, {"service_ids": set(), "digests": set()})
            if record.service_id is not None:
                item["service_ids"].add(record.service_id)
            item["digests"].add(record.image_digest)
        services = tuple(
            {
                "role": role,
                "service_id": next(iter(item["service_ids"]), None),
                "image_digest": next(iter(item["digests"])),
                "provider_generation": "recovered",
            }
            for role, item in grouped.items()
            if len(item["service_ids"]) <= 1 and len(item["digests"]) == 1
        )
        if not services or len(services) != len(grouped):
            raise ValueError("lease cleanup journal identity is ambiguous")
        if journal.schema == 2 and set(grouped) != {"outline", _UPLOAD_SINK_ROLE}:
            raise ValueError("lease cleanup journal must contain both service roles")
    expected = {
        str(service["role"]): (service["service_id"], str(service["image_digest"]))
        for service in services
    }
    if journal.schema == 1 and set(expected) != {"outline"}:
        raise ValueError("legacy lease journal cannot represent a service bundle")
    if journal.schema == 2 and set(expected) != {"outline", _UPLOAD_SINK_ROLE}:
        raise ValueError("lease cleanup requires exactly both service roles")
    if len(expected) != len(services):
        raise ValueError("lease cleanup service roles are duplicated")
    service_ids = [service_id for service_id, _ in expected.values() if service_id is not None]
    if len(set(service_ids)) != len(service_ids):
        raise ValueError("lease cleanup service IDs must be distinct")
    latest: dict[str, LeaseJournalRecord] = {}
    for record in records:
        if record.run_id != request.run_id:
            raise ValueError("lease cleanup journal history identity mismatch")
        role = record.role
        if role not in expected:
            raise ValueError("lease cleanup journal role mismatch")
        service_id, image_digest = expected[role]
        if record.image_digest != image_digest:
            raise ValueError("lease cleanup journal image identity mismatch")
        if role == "outline" and image_digest != request.image_digest:
            raise ValueError("lease cleanup journal request image identity mismatch")
        if service_id is not None and record.service_id not in {None, service_id}:
            raise ValueError("lease cleanup journal service identity mismatch")
        if record.state not in set(LeaseState):
            raise ValueError("lease cleanup journal state is invalid")
        latest[role] = record
    if set(latest) != set(expected):
        raise ValueError("lease cleanup journal is missing a service role")
    return journal, latest


def _append_cleanup_state(
    journal: RenderLeaseJournal,
    request: RenderLeaseRequest,
    service_id: str | None,
    state: LeaseState,
    cleanup_result: str | None = None,
    *,
    image_digest: str | None = None,
    role: str = "outline",
) -> None:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    journal.append(
        LeaseJournalRecord(
            run_id=request.run_id,
            service_id=service_id,
            image_digest=request.image_digest if image_digest is None else image_digest,
            state=state,
            timestamp=timestamp,
            cleanup_result=cleanup_result,
            role=role,
        )
    )


def _reverify_recorded_absence(
    api: RenderAPI,
    journal: RenderLeaseJournal,
    request: RenderLeaseRequest,
    last_records: dict[str, LeaseJournalRecord],
    *,
    owner_id: str | None = None,
    descriptor: RenderLeaseDescriptor | None = None,
) -> None:
    """Freshly prove an old absent result and repair anything that returned."""

    failures: list[BaseException] = []
    known_ids = tuple(
        record.service_id
        for record in last_records.values()
        if record.service_id is not None
    )
    for role, record in last_records.items():
        if record.service_id is None:
            continue
        try:
            if not api.exists(record.service_id):
                if record.state is not LeaseState.ABSENT or record.cleanup_result != "verified":
                    _append_cleanup_state(
                        journal,
                        request,
                        record.service_id,
                        LeaseState.ABSENT,
                        "verified",
                        image_digest=record.image_digest,
                        role=role,
                    )
                continue
            _append_cleanup_state(
                journal,
                request,
                record.service_id,
                LeaseState.DELETING,
                image_digest=record.image_digest,
                role=role,
            )
            api.delete_service(record.service_id)
            if api.exists(record.service_id):
                raise RenderAPIError("DELETE_NOT_VERIFIED")
            _append_cleanup_state(
                journal,
                request,
                record.service_id,
                LeaseState.ABSENT,
                "verified",
                image_digest=record.image_digest,
                role=role,
            )
        except BaseException as error:
            failures.append(error)
            try:
                _append_cleanup_state(
                    journal,
                    request,
                    record.service_id,
                    LeaseState.DELETING,
                    "delete-unverified",
                    image_digest=record.image_digest,
                    role=role,
                )
            except BaseException as journal_error:
                failures.append(journal_error)

    unknown_roles = tuple(
        role for role, record in last_records.items() if record.service_id is None
    )
    if unknown_roles:
        if not isinstance(owner_id, str) or descriptor is None:
            failures.append(ValueError("namespace identity is unavailable"))
        else:
            try:
                reaper = RenderReaper(api)
                reaper.reap_tagged(
                    owner_id,
                    descriptor.service_prefix,
                    active_service_ids=known_ids,
                    older_than_seconds=0,
                )
                reaper.assert_tagged_absent(owner_id, descriptor.service_prefix)
                for role in unknown_roles:
                    record = last_records[role]
                    _append_cleanup_state(
                        journal,
                        request,
                        None,
                        LeaseState.ABSENT,
                        "verified-namespace",
                        image_digest=record.image_digest,
                        role=role,
                    )
            except BaseException as error:
                failures.append(error)
    if failures:
        raise RenderAPIError("DELETE_NOT_VERIFIED") from failures[0]



def acquire(args: argparse.Namespace) -> int:
    request = RenderLeaseRequest.from_file(args.request)
    if request.image_digest != args.expected_image_digest:
        raise ValueError("request image digest differs from the trusted workflow setting")
    if not _IMAGE_PATH.fullmatch(args.image_path):
        raise ValueError("image path is invalid")
    if not 1 <= args.listen_port <= 65535:
        raise ValueError("listen port is invalid")
    if not 0 < args.timeout_seconds <= 900 or not 0 < args.poll_seconds <= 60:
        raise ValueError("lease readiness bounds are invalid")
    api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
    descriptor = RenderLeaseDescriptor(
        run_id=request.run_id,
        platform=request.platform,
        service_name=f"dobby-torturer-{request.run_id}-{request.platform}",
        image_digest=request.image_digest,
    )
    profile = OutlineWSSProfile.random()
    outline_spec = RenderServiceSpec(
        owner_id=args.owner_id,
        name=descriptor.service_name,
        image_owner_id=args.image_owner_id,
        image_path=args.image_path,
        image_digest=request.image_digest,
        region=args.region,
        secret_files=profile.render_secret_files(args.listen_port),
        docker_command=_OUTLINE_CONFIG_COMMAND,
    )
    sink_image_owner_id = getattr(args, "sink_image_owner_id", None)
    sink_image_path = getattr(args, "sink_image_path", None)
    expected_sink_digest = getattr(args, "expected_sink_image_digest", None)
    upload_url_output = getattr(args, "upload_url_output", None)
    if not all(isinstance(value, str) and value for value in (sink_image_owner_id, sink_image_path, expected_sink_digest)):
        raise ValueError("lease requires upload sink image settings")
    if not _DIGEST.fullmatch(expected_sink_digest):
        raise ValueError("upload sink image digest is not immutable")
    if not _IMAGE_PATH.fullmatch(sink_image_path) or not sink_image_path.endswith("@" + expected_sink_digest):
        raise ValueError("upload sink image path must use the declared immutable digest")
    if not isinstance(upload_url_output, Path):
        raise ValueError("lease requires an upload URL output")

    sink_descriptor = RenderLeaseDescriptor(
        run_id=request.run_id,
        platform=request.platform,
        service_name=f"dobby-torturer-{request.run_id}-upload-sink",
        image_digest=expected_sink_digest,
        role=_UPLOAD_SINK_ROLE,
    )
    upload_path = _upload_path()
    sink_spec = RenderServiceSpec(
        owner_id=args.owner_id,
        name=sink_descriptor.service_name,
        image_owner_id=sink_image_owner_id,
        image_path=sink_image_path,
        image_digest=expected_sink_digest,
        region=args.region,
        health_check_path="/healthz",
        secret_files=(("upload-path", upload_path),),
        docker_command=_UPLOAD_SINK_COMMAND,
    )
    journal = RenderLeaseJournal(args.journal, schema=2)
    outline = RenderLease(api, outline_spec, descriptor, journal)
    upload_sink = RenderLease(api, sink_spec, sink_descriptor, journal)
    bundle = RenderLeaseBundle(outline, upload_sink)
    bundle.acquire(timeout_seconds=args.timeout_seconds, poll_seconds=args.poll_seconds)
    try:
        if outline.ready is None or upload_sink.ready is None:
            raise ValueError("lease bundle is not ready")
        _owner_text(args.profile_output, profile.client_toml(outline.ready.url))
        _owner_text(args.upload_url_output, _upload_url(upload_sink.ready.url, upload_path) + "\n")
        bundle.mark_issued()
        _owner_output(args.lease_output, _safe_bundle_payload(request, outline, upload_sink, "issued"))
    except Exception:
        bundle.cleanup()
        raise
    print(json.dumps(_safe_bundle_payload(request, outline, upload_sink, "issued"), sort_keys=True))
    return 0


def _lease_record(path: Path) -> tuple[dict[str, object], RenderLeaseRequest, tuple[dict[str, object], ...]]:
    _require_owner_file(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("lease record has an unsafe shape")
    if value.get("kind") != "dobbyvpn.render-lease":
        raise ValueError("lease record identity is invalid")
    schema = value.get("schema")
    if schema == 1:
        base_keys = {
            "schema", "kind", "run_id", "platform", "service_id",
            "source_sha", "image_digest", "provider_generation", "state",
        }
        if set(value) not in (base_keys, base_keys | {"cleanup"}):
            raise ValueError("lease record has an unsafe shape")
        service_id = value["service_id"]
        if not isinstance(service_id, str) or _SERVICE_ID.fullmatch(service_id) is None:
            raise ValueError("lease service ID is invalid")
        services: tuple[dict[str, object], ...] = ({
            "role": "outline",
            "service_id": service_id,
            "image_digest": value["image_digest"],
            "provider_generation": value["provider_generation"],
        },)
    elif schema == 2:
        base_keys = {"schema", "kind", "run_id", "platform", "source_sha", "services", "state"}
        if set(value) not in (base_keys, base_keys | {"cleanup"}):
            raise ValueError("lease record has an unsafe shape")
        if not isinstance(value.get("services"), list):
            raise ValueError("lease bundle record is invalid")
        if len(value["services"]) != 2:
            raise ValueError("lease bundle must contain exactly two services")
        parsed: list[dict[str, object]] = []
        for service in value["services"]:
            if not isinstance(service, dict) or set(service) != {
                "role", "service_id", "image_digest", "provider_generation"
            }:
                raise ValueError("lease bundle service has an unsafe shape")
            if service["role"] not in {"outline", _UPLOAD_SINK_ROLE}:
                raise ValueError("lease bundle service role is invalid")
            if not isinstance(service["service_id"], str) or _SERVICE_ID.fullmatch(service["service_id"]) is None:
                raise ValueError("lease bundle service ID is invalid")
            if not isinstance(service["image_digest"], str) or _DIGEST.fullmatch(service["image_digest"]) is None:
                raise ValueError("lease bundle image digest is invalid")
            if not isinstance(service["provider_generation"], str) or not service["provider_generation"]:
                raise ValueError("lease bundle provider generation is invalid")
            parsed.append(service)
        if {str(service["role"]) for service in parsed} != {"outline", _UPLOAD_SINK_ROLE}:
            raise ValueError("lease bundle roles are incomplete or duplicated")
        service_ids = [str(service["service_id"]) for service in parsed]
        if len(set(service_ids)) != len(service_ids):
            raise ValueError("lease bundle service IDs must be distinct")
        services = tuple(parsed)
    else:
        raise ValueError("lease record identity is invalid")
    outline_image_digest = next(
        str(service["image_digest"])
        for service in services
        if service["role"] == "outline"
    )
    try:
        request = RenderLeaseRequest(value["run_id"], value["platform"], value["source_sha"], outline_image_digest)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("lease record request identity is invalid") from error
    if value.get("state") not in {"issued", "testing", "absent"}:
        raise ValueError("lease record state is invalid")
    return value, request, services


def begin_testing(args: argparse.Namespace) -> int:
    value, request, services = _lease_record(args.lease)
    journal, last_records = _cleanup_journal(args.journal, request, services)
    if value["schema"] == 1:
        raise ValueError("legacy schema-1 leases support cleanup only")
    if value["schema"] == 2:
        if value["state"] == "testing":
            if any(record.state is not LeaseState.TESTING for record in last_records.values()):
                raise ValueError("testing lease bundle conflicts with cleanup journal")
            print(json.dumps({"state": "testing", "service_ids": sorted(str(service["service_id"]) for service in services)}, sort_keys=True))
            return 0
        if value["state"] != "issued" or any(record.state is not LeaseState.ISSUED for record in last_records.values()):
            raise ValueError("lease bundle is not ready to begin testing")
        for service in services:
            _append_cleanup_state(
                journal,
                request,
                str(service["service_id"]),
                LeaseState.TESTING,
                image_digest=str(service["image_digest"]),
                role=str(service["role"]),
            )
        updated = dict(value)
        updated["state"] = "testing"
        _owner_output(args.lease, updated)
        print(json.dumps({"state": "testing", "service_ids": sorted(str(service["service_id"]) for service in services)}, sort_keys=True))
        return 0

    service = services[0]
    service_id = str(service["service_id"])
    last_record = last_records["outline"]
    if value["state"] == "testing":
        if last_record.state is not LeaseState.TESTING:
            raise ValueError("testing lease record conflicts with cleanup journal")
        print(json.dumps({"service_id": service_id, "state": "testing"}, sort_keys=True))
        return 0
    if value["state"] != "issued" or last_record.state is not LeaseState.ISSUED:
        raise ValueError("lease is not ready to begin testing")
    _append_cleanup_state(journal, request, service_id, LeaseState.TESTING)
    _owner_output(
        args.lease,
        _safe_lease_payload(
            request,
            service_id,
            str(value["provider_generation"]),
            "testing",
        ),
    )
    print(json.dumps({"service_id": service_id, "state": "testing"}, sort_keys=True))
    return 0


def _recover_from_journal(args: argparse.Namespace) -> int:
    request_path = getattr(args, "request", None)
    owner_id = getattr(args, "owner_id", None)
    if not isinstance(request_path, Path) or not isinstance(owner_id, str) or not owner_id:
        raise ValueError("journal-only cleanup requires request and owner identity")
    request = RenderLeaseRequest.from_file(request_path)
    journal, last_records = _cleanup_journal(args.journal, request, None)
    api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
    descriptor = RenderLeaseDescriptor(
        run_id=request.run_id,
        platform=request.platform,
        service_name=f"dobby-torturer-{request.run_id}-{request.platform}",
        image_digest=request.image_digest,
    )
    if last_records and all(
        record.state is LeaseState.ABSENT and record.cleanup_result in {"verified", "verified-namespace"}
        for record in last_records.values()
    ):
        _reverify_recorded_absence(
            api,
            journal,
            request,
            last_records,
            owner_id=owner_id,
            descriptor=descriptor,
        )
        cleanup_results = {record.cleanup_result for record in last_records.values()}
        cleanup = "verified" if cleanup_results == {"verified"} else "verified-namespace"
        print(json.dumps({"state": "absent", "cleanup": cleanup}, sort_keys=True))
        return 0

    failures: list[BaseException] = []
    known_ids = tuple(
        record.service_id
        for record in last_records.values()
        if record.service_id is not None
    )
    for role, record in last_records.items():
        if record.state is not LeaseState.DELETING:
            _append_cleanup_state(
                journal,
                request,
                record.service_id,
                LeaseState.DELETING,
                image_digest=record.image_digest,
                role=role,
            )
    for role, record in last_records.items():
        if record.service_id is None:
            continue
        try:
            api.delete_service(record.service_id)
            if api.exists(record.service_id):
                raise RenderAPIError("DELETE_NOT_VERIFIED")
            _append_cleanup_state(
                journal,
                request,
                record.service_id,
                LeaseState.ABSENT,
                "verified",
                image_digest=record.image_digest,
                role=role,
            )
        except BaseException as error:
            failures.append(error)
            _append_cleanup_state(
                journal,
                request,
                record.service_id,
                LeaseState.DELETING,
                "delete-unverified",
                image_digest=record.image_digest,
                role=role,
            )
    if not failures:
        try:
            RenderReaper(api).reap_tagged(
                owner_id,
                descriptor.service_prefix,
                active_service_ids=known_ids,
                older_than_seconds=0,
            )
            RenderReaper(api).assert_tagged_absent(owner_id, descriptor.service_prefix)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise RenderAPIError("DELETE_NOT_VERIFIED") from failures[0]
    for role, record in last_records.items():
        if record.service_id is None:
            _append_cleanup_state(
                journal,
                request,
                None,
                LeaseState.ABSENT,
                "verified-namespace",
                image_digest=record.image_digest,
                role=role,
            )
    print(json.dumps({"state": "absent", "cleanup": "verified-namespace"}, sort_keys=True))
    return 0


def cleanup(args: argparse.Namespace) -> int:
    lease_path = getattr(args, "lease", None)
    if lease_path is None or not lease_path.exists():
        return _recover_from_journal(args)
    value, request, services = _lease_record(lease_path)
    journal, last_records = _cleanup_journal(args.journal, request, services)
    if value["schema"] == 2:
        if value["state"] == "absent":
            if value.get("cleanup") != "verified" or any(
                record.state not in {LeaseState.ABSENT, LeaseState.DELETING}
                or (
                    record.state is LeaseState.ABSENT
                    and record.cleanup_result != "verified"
                )
                for record in last_records.values()
            ):
                raise ValueError("absent lease bundle cleanup is not journaled")
            api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
            _reverify_recorded_absence(api, journal, request, last_records)
            print(json.dumps({"state": "absent", "cleanup": "verified"}, sort_keys=True))
            return 0
        if value["state"] not in {"issued", "testing"}:
            raise ValueError("lease bundle record identity is invalid")
        if any(record.state not in {LeaseState.ISSUED, LeaseState.TESTING, LeaseState.DELETING, LeaseState.ABSENT} for record in last_records.values()):
            raise ValueError("active lease bundle conflicts with cleanup journal")
        for service in services:
            role = str(service["role"])
            record = last_records[role]
            if record.state not in {LeaseState.DELETING, LeaseState.ABSENT}:
                _append_cleanup_state(
                    journal,
                    request,
                    str(service["service_id"]),
                    LeaseState.DELETING,
                    image_digest=str(service["image_digest"]),
                    role=role,
                )
        api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
        failures: list[BaseException] = []
        for service in services:
            role = str(service["role"])
            record = last_records[role]
            service_id = str(service["service_id"])
            if record.state is LeaseState.ABSENT and record.cleanup_result == "verified":
                continue
            try:
                api.delete_service(service_id)
                if api.exists(service_id):
                    raise RenderAPIError("DELETE_NOT_VERIFIED")
                _append_cleanup_state(
                    journal,
                    request,
                    service_id,
                    LeaseState.ABSENT,
                    "verified",
                    image_digest=str(service["image_digest"]),
                    role=role,
                )
            except BaseException as error:
                failures.append(error)
                _append_cleanup_state(
                    journal,
                    request,
                    service_id,
                    LeaseState.DELETING,
                    "delete-unverified",
                    image_digest=str(service["image_digest"]),
                    role=role,
                )
        if failures:
            raise RenderAPIError("DELETE_NOT_VERIFIED") from failures[0]
        updated = dict(value)
        updated["state"] = "absent"
        updated["cleanup"] = "verified"
        _owner_output(lease_path, updated)
        print(json.dumps({"state": "absent", "cleanup": "verified"}, sort_keys=True))
        return 0

    service = services[0]
    service_id = str(service["service_id"])
    last_record = last_records["outline"]
    if value["state"] == "absent":
        if value.get("cleanup") != "verified":
            raise ValueError("absent lease record is not verified")
        if last_record.state not in {LeaseState.ABSENT, LeaseState.DELETING} or (
            last_record.state is LeaseState.ABSENT
            and last_record.cleanup_result != "verified"
        ):
            raise ValueError("absent lease cleanup is not journaled")
        api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
        _reverify_recorded_absence(api, journal, request, last_records)
        print(json.dumps({"service_id": service_id, "state": "absent", "cleanup": "verified"}, sort_keys=True))
        return 0
    if value["state"] not in {"issued", "testing"}:
        raise ValueError("lease record identity is invalid")
    if last_record.state not in {LeaseState.ISSUED, LeaseState.TESTING, LeaseState.DELETING}:
        raise ValueError("active lease record conflicts with cleanup journal")
    if last_record.state is not LeaseState.DELETING:
        _append_cleanup_state(journal, request, service_id, LeaseState.DELETING)
    api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
    api.delete_service(service_id)
    if api.exists(service_id):
        _append_cleanup_state(journal, request, service_id, LeaseState.DELETING, "delete-unverified")
        raise RenderAPIError("DELETE_NOT_VERIFIED")
    _append_cleanup_state(journal, request, service_id, LeaseState.ABSENT, "verified")
    _owner_output(lease_path, _safe_lease_payload(request, service_id, value["provider_generation"], "absent", "verified"))
    print(json.dumps({"service_id": service_id, "state": "absent", "cleanup": "verified"}, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    acquire_parser = commands.add_parser("acquire")
    acquire_parser.add_argument("--request", type=Path, required=True)
    acquire_parser.add_argument("--owner-id", required=True)
    acquire_parser.add_argument("--image-owner-id", required=True)
    acquire_parser.add_argument("--image-path", required=True)
    acquire_parser.add_argument("--expected-image-digest", required=True)
    acquire_parser.add_argument("--sink-image-owner-id")
    acquire_parser.add_argument("--sink-image-path")
    acquire_parser.add_argument("--expected-sink-image-digest")
    acquire_parser.add_argument("--profile-output", type=Path, required=True)
    acquire_parser.add_argument("--lease-output", type=Path, required=True)
    acquire_parser.add_argument("--upload-url-output", type=Path)
    acquire_parser.add_argument("--journal", type=Path, required=True)
    acquire_parser.add_argument("--listen-port", type=int, default=10000)
    acquire_parser.add_argument("--region", default="oregon")
    acquire_parser.add_argument("--timeout-seconds", type=float, default=600.0)
    acquire_parser.add_argument("--poll-seconds", type=float, default=5.0)
    acquire_parser.set_defaults(handler=acquire)
    cleanup_parser = commands.add_parser("cleanup")
    cleanup_parser.add_argument("--lease", type=Path)
    cleanup_parser.add_argument("--journal", type=Path, required=True)
    cleanup_parser.add_argument("--request", type=Path)
    cleanup_parser.add_argument("--owner-id")
    cleanup_parser.set_defaults(handler=cleanup)
    testing_parser = commands.add_parser("begin-testing")
    testing_parser.add_argument("--lease", type=Path, required=True)
    testing_parser.add_argument("--journal", type=Path, required=True)
    testing_parser.set_defaults(handler=begin_testing)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (LeaseRequestError, RenderAPIError, OSError, ValueError, json.JSONDecodeError) as error:
        code = getattr(error, "code", type(error).__name__.upper())
        print(f"render-lease failed code={code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
