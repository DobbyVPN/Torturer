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
import stat
import sys

from .lease import (
    LeaseJournalRecord,
    LeaseState,
    RenderLease,
    RenderLeaseDescriptor,
    RenderLeaseJournal,
)
from .lease_request import LeaseRequestError, RenderLeaseRequest
from .outline import OutlineWSSProfile
from .render import RenderAPI, RenderAPIError, RenderReaper, RenderServiceSpec


_IMAGE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{2,255}$")
_SERVICE_ID = re.compile(r"^srv-[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_OUTLINE_CONFIG_COMMAND = "/outline-ss-server -config=/etc/secrets/config.yml"


def _owner_output(path: Path, payload: dict[str, object]) -> None:
    _owner_text(path, json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _owner_text(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


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
        "service_id": service_id,
        "image_digest": request.image_digest,
        "provider_generation": generation,
        "state": state,
    }
    if cleanup is not None:
        payload["cleanup"] = cleanup
    return payload

def _cleanup_journal(
    path: Path,
    request: RenderLeaseRequest,
    service_id: str | None,
) -> tuple[RenderLeaseJournal, LeaseJournalRecord]:
    _require_owner_file(path)
    journal = RenderLeaseJournal(path)
    records = journal.records()
    if not records:
        raise ValueError("lease cleanup journal is empty")
    last = records[-1]
    if (
        last.run_id != request.run_id
        or last.image_digest != request.image_digest
        or (service_id is not None and last.service_id != service_id)
    ):
        raise ValueError("lease cleanup journal identity mismatch")
    if any(
        record.run_id != request.run_id
        or record.image_digest != request.image_digest
        or (service_id is not None and record.service_id not in {None, service_id})
        for record in records
    ):
        raise ValueError("lease cleanup journal history identity mismatch")
    if last.state not in set(LeaseState):
        raise ValueError("lease cleanup journal state is invalid")
    return journal, last


def _append_cleanup_state(
    journal: RenderLeaseJournal,
    request: RenderLeaseRequest,
    service_id: str | None,
    state: LeaseState,
    cleanup_result: str | None = None,
) -> None:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    journal.append(
        LeaseJournalRecord(
            run_id=request.run_id,
            service_id=service_id,
            image_digest=request.image_digest,
            state=state,
            timestamp=timestamp,
            cleanup_result=cleanup_result,
        )
    )



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
    spec = RenderServiceSpec(
        owner_id=args.owner_id,
        name=descriptor.service_name,
        image_owner_id=args.image_owner_id,
        image_path=args.image_path,
        image_digest=request.image_digest,
        region=args.region,
        secret_files=profile.render_secret_files(args.listen_port),
        docker_command=_OUTLINE_CONFIG_COMMAND,
    )
    journal = RenderLeaseJournal(args.journal)
    lease = RenderLease(api, spec, descriptor, journal)
    ready = lease.acquire(timeout_seconds=args.timeout_seconds, poll_seconds=args.poll_seconds)
    try:
        _owner_text(args.profile_output, profile.client_toml(ready.url))
        lease.mark_issued()
        _owner_output(
            args.lease_output,
            _safe_lease_payload(request, ready.handle.service_id, ready.provider_generation, "issued"),
        )
    except Exception:
        lease.cleanup()
        raise
    print(json.dumps(_safe_lease_payload(request, ready.handle.service_id, ready.provider_generation, "issued"), sort_keys=True))
    return 0


def _lease_record(path: Path) -> tuple[dict[str, object], RenderLeaseRequest, str]:
    _require_owner_file(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("lease record has an unsafe shape")
    base_keys = {
        "schema", "kind", "run_id", "platform", "service_id",
        "image_digest", "provider_generation", "state",
    }
    if set(value) not in (base_keys, base_keys | {"cleanup"}):
        raise ValueError("lease record has an unsafe shape")
    request = RenderLeaseRequest(value["run_id"], value["platform"], value["image_digest"])
    if value["kind"] != "dobbyvpn.render-lease" or value["schema"] != 1:
        raise ValueError("lease record identity is invalid")
    service_id = value["service_id"]
    if not isinstance(service_id, str) or _SERVICE_ID.fullmatch(service_id) is None:
        raise ValueError("lease service ID is invalid")
    return value, request, service_id


def begin_testing(args: argparse.Namespace) -> int:
    value, request, service_id = _lease_record(args.lease)
    journal, last_record = _cleanup_journal(args.journal, request, service_id)
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
    journal, last_record = _cleanup_journal(args.journal, request, None)
    records = journal.records()
    service_ids = {record.service_id for record in records if record.service_id is not None}
    if len(service_ids) > 1:
        raise ValueError("lease cleanup journal contains conflicting service IDs")
    if last_record.state is LeaseState.ABSENT and last_record.cleanup_result in {
        "verified", "verified-namespace"
    }:
        print(json.dumps({"state": "absent", "cleanup": last_record.cleanup_result}, sort_keys=True))
        return 0

    api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
    service_id = next(iter(service_ids), None)
    if last_record.state is not LeaseState.DELETING:
        _append_cleanup_state(journal, request, service_id, LeaseState.DELETING)
    if service_id is not None:
        api.delete_service(service_id)
        if api.exists(service_id):
            _append_cleanup_state(journal, request, service_id, LeaseState.DELETING, "delete-unverified")
            raise RenderAPIError("DELETE_NOT_VERIFIED")
        _append_cleanup_state(journal, request, service_id, LeaseState.ABSENT, "verified")
        print(json.dumps({"service_id": service_id, "state": "absent", "cleanup": "verified"}, sort_keys=True))
        return 0

    descriptor = RenderLeaseDescriptor(
        run_id=request.run_id,
        platform=request.platform,
        service_name=f"dobby-torturer-{request.run_id}-{request.platform}",
        image_digest=request.image_digest,
    )
    RenderReaper(api).reap_tagged(owner_id, descriptor.service_prefix, older_than_seconds=0)
    remaining = tuple(
        record.service_id
        for record in api.list_services(owner_id)
        if record.owner_id == owner_id and record.name.startswith(descriptor.service_prefix)
    )
    if remaining:
        _append_cleanup_state(journal, request, None, LeaseState.DELETING, "delete-unverified")
        raise RenderAPIError("DELETE_NOT_VERIFIED")
    _append_cleanup_state(journal, request, None, LeaseState.ABSENT, "verified-namespace")
    print(json.dumps({"state": "absent", "cleanup": "verified-namespace"}, sort_keys=True))
    return 0


def cleanup(args: argparse.Namespace) -> int:
    lease_path = getattr(args, "lease", None)
    if lease_path is None or not lease_path.exists():
        return _recover_from_journal(args)
    value, request, service_id = _lease_record(lease_path)
    journal, last_record = _cleanup_journal(args.journal, request, service_id)
    if value["state"] == "absent":
        if value.get("cleanup") != "verified":
            raise ValueError("absent lease record is not verified")
        if last_record.state is not LeaseState.ABSENT or last_record.cleanup_result != "verified":
            raise ValueError("absent lease cleanup is not journaled")
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
    acquire_parser.add_argument("--profile-output", type=Path, required=True)
    acquire_parser.add_argument("--lease-output", type=Path, required=True)
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
