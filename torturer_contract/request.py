"""Validation for the untrusted identity passed to Torturer.

The DobbyVPN caller owns the values, but keeping validation in a small module
makes the trust boundary explicit and testable. Validated values still must be
passed through environment variables rather than interpolated into shell code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re


_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
    r"/[A-Za-z0-9_.-]{1,100}"
)
_COMMIT = re.compile(r"[0-9a-f]{40}")


class ValidationError(ValueError):
    """A caller supplied an invalid or ambiguous candidate identity."""


@dataclass(frozen=True)
class VerificationRequest:
    """Immutable identity of one candidate verification request."""

    source_repository: str
    commit_sha: str
    pr_number: int

    @classmethod
    def parse(
        cls,
        *,
        source_repository: str,
        commit_sha: str,
        pr_number: str | int,
    ) -> "VerificationRequest":
        if not _REPOSITORY.fullmatch(source_repository):
            raise ValidationError(
                "source_repository must be one GitHub owner/repository slug"
            )

        owner, repository = source_repository.split("/", maxsplit=1)
        if owner in {".", ".."} or repository in {".", ".."}:
            raise ValidationError(
                "source_repository must not contain path-navigation segments"
            )

        if not _COMMIT.fullmatch(commit_sha):
            raise ValidationError(
                "commit_sha must be a lowercase full 40-character hexadecimal SHA"
            )

        if isinstance(pr_number, bool):
            raise ValidationError("pr_number must be a positive integer")

        try:
            parsed_pr = int(pr_number)
        except (TypeError, ValueError) as error:
            raise ValidationError("pr_number must be a positive integer") from error

        if str(parsed_pr) != str(pr_number) or parsed_pr <= 0:
            raise ValidationError("pr_number must be a positive canonical integer")

        return cls(
            source_repository=source_repository,
            commit_sha=commit_sha,
            pr_number=parsed_pr,
        )

    def to_json(self) -> str:
        """Return stable JSON suitable for a diagnostic request record."""

        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
