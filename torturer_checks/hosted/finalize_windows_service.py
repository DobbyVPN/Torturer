"""Finalize the workflow-owned initial Windows service process."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import re
import sys
import time

from .cli import SubprocessRunner, _ensure_owner_only_directory
from .windows import WindowsServiceProcessController, read_windows_service_identity


_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-identity-file", type=Path, required=True)
    parser.add_argument("--service-binary", type=Path, required=True)
    parser.add_argument("--raw-log-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    return parser


def _identity_value(path: Path) -> str:
    """Read one owner-private, regular, non-symlink identity file safely."""

    return read_windows_service_identity(path)


def _safe_reason(error: Exception) -> str:
    for attribute in ("reason_code", "code"):
        reason = getattr(error, attribute, None)
        if isinstance(reason, str) and _REASON.fullmatch(reason) is not None:
            return reason
    fallback = type(error).__name__
    return fallback if _REASON.fullmatch(fallback) is not None else "FINALIZE_FAILED"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        print("windows_service_finalizer=failed code=INVALID_FINALIZE_TIMEOUT", file=sys.stderr)
        return 1
    deadline = time.monotonic() + args.timeout_seconds

    runner: SubprocessRunner | None = None
    try:
        _ensure_owner_only_directory(args.raw_log_dir)
        identity = _identity_value(args.service_identity_file)
        pid = int(identity.split("|", 1)[0])
        runner = SubprocessRunner(args.raw_log_dir)
        controller = WindowsServiceProcessController(
            pid=pid,
            binary=args.service_binary,
            pid_file=None,
            identity_file=args.service_identity_file,
            runner=runner,
            raw_directory=args.raw_log_dir,
            control_address="127.0.0.1:50051",
            expected_initial_identity=identity,
            initialization_deadline=deadline,
        )
        controller.finalize_initial_service(
            args.timeout_seconds,
            deadline=deadline,
        )
        print("windows_service_finalizer=controller tree=proven")
        status = 0
    except Exception as error:
        code = _safe_reason(error)
        print(f"windows_service_finalizer=failed code={code}", file=sys.stderr)
        status = 1

    if runner is not None:
        try:
            evidence = runner.safe_evidence()
            for item in evidence:
                if not isinstance(item, dict):
                    raise ValueError("evidence metadata is not a mapping")
                print(f"windows_service_finalizer_evidence={item}")
        except Exception as error:
            print(
                f"windows_service_finalizer=failed code={_safe_reason(error)}",
                file=sys.stderr,
            )
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
