"""Exact-source checks shared by public candidate executors."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess


FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")


class SourceCheckoutError(RuntimeError):
    """The candidate checkout is not the exact clean revision requested."""


def verify_source_checkout(candidate: Path, expected_commit: str) -> None:
    """Reject refs, abbreviated SHAs, the wrong HEAD, and tracked modifications."""

    if FULL_SHA.fullmatch(expected_commit) is None:
        raise SourceCheckoutError("commit SHA must be exactly 40 lowercase hexadecimal characters")
    try:
        actual_commit = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=None,
        ).stdout.strip()
        tracked_state = subprocess.run(
            [
                "git",
                "-C",
                str(candidate),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=None,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise SourceCheckoutError("candidate is not a readable Git checkout") from error
    if actual_commit != expected_commit:
        raise SourceCheckoutError("candidate HEAD does not match the requested commit")
    if tracked_state.strip():
        raise SourceCheckoutError("candidate checkout has modified tracked files")
