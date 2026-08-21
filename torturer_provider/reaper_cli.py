"""Trusted, secret-safe command line entry point for the Render reaper.

This command is intended for a protected/manual workflow.  It never accepts a
profile, access key, endpoint, or provider response on its command line and
prints only stable cleanup status plus opaque service IDs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from .render import RenderAPI, RenderAPIError, RenderReaper


_OWNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_NAMESPACE = re.compile(r"^dobby-torturer-[a-f0-9]{32}-$")
_SERVICE_ID = re.compile(r"^srv-[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-id", default=os.environ.get("RENDER_OWNER_ID", ""))
    parser.add_argument("--name-prefix", required=True)
    parser.add_argument("--older-than-seconds", type=float, default=900.0)
    parser.add_argument("--active-service-id", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    token = os.environ.get("RENDER_API_TOKEN", "")
    if not token:
        print("error=RENDER_API_TOKEN_MISSING", file=sys.stderr)
        return 2
    if not _OWNER_ID.fullmatch(args.owner_id):
        print("error=RENDER_OWNER_ID_INVALID", file=sys.stderr)
        return 2
    if not _NAMESPACE.fullmatch(args.name_prefix):
        print("error=RENDER_NAMESPACE_INVALID", file=sys.stderr)
        return 2
    if args.older_than_seconds < 0:
        print("error=RENDER_REAPER_AGE_INVALID", file=sys.stderr)
        return 2
    if any(not _SERVICE_ID.fullmatch(value) for value in args.active_service_id):
        print("error=RENDER_ACTIVE_SERVICE_ID_INVALID", file=sys.stderr)
        return 2
    try:
        deleted = RenderReaper(RenderAPI(token)).reap_tagged(
            args.owner_id,
            args.name_prefix,
            active_service_ids=tuple(args.active_service_id),
            older_than_seconds=args.older_than_seconds,
        )
    except (RenderAPIError, ValueError) as error:
        if isinstance(error, RenderAPIError):
            print(f"error={error.code}", file=sys.stderr)
        else:
            print("error=RENDER_REAPER_INPUT_INVALID", file=sys.stderr)
        return 1
    print(json.dumps({"deleted_service_ids": list(deleted)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
