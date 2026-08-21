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
import json
import os
from pathlib import Path
import re
import stat
import sys

from .lease import RenderLease, RenderLeaseDescriptor, RenderLeaseJournal
from .lease_request import LeaseRequestError, RenderLeaseRequest
from .outline import OutlineWSSProfile
from .render import RenderAPI, RenderAPIError, RenderServiceSpec


_IMAGE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{2,255}$")
_SERVICE_ID = re.compile(r"^srv-[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_OUTLINE_CONFIG_COMMAND = "-config=/etc/secrets/config.yml"


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


def cleanup(args: argparse.Namespace) -> int:
    _require_owner_file(args.lease)
    value = json.loads(args.lease.read_text(encoding="utf-8"))
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
    if value["state"] == "absent":
        if value.get("cleanup") != "verified":
            raise ValueError("absent lease record is not verified")
        print(json.dumps({"service_id": value["service_id"], "state": "absent", "cleanup": "verified"}, sort_keys=True))
        return 0
    if value["state"] != "issued":
        raise ValueError("lease record identity is invalid")
    service_id = value["service_id"]
    if not isinstance(service_id, str) or _SERVICE_ID.fullmatch(service_id) is None:
        raise ValueError("lease service ID is invalid")
    api = RenderAPI(os.environ.get("RENDER_API_TOKEN", ""))
    api.delete_service(service_id)
    if api.exists(service_id):
        raise RenderAPIError("DELETE_NOT_VERIFIED")
    _owner_output(args.lease, _safe_lease_payload(request, service_id, value["provider_generation"], "absent", "verified"))
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
    cleanup_parser.add_argument("--lease", type=Path, required=True)
    cleanup_parser.set_defaults(handler=cleanup)
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
