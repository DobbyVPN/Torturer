from __future__ import annotations

import unittest

from torturer_contract.request import VerificationRequest, ValidationError


class VerificationRequestTest(unittest.TestCase):
    def test_accepts_upstream_candidate(self) -> None:
        request = VerificationRequest.parse(
            source_repository="DobbyVPN/DobbyVPN",
            commit_sha="a" * 40,
            pr_number="42",
        )

        self.assertEqual(request.source_repository, "DobbyVPN/DobbyVPN")
        self.assertEqual(request.commit_sha, "a" * 40)
        self.assertEqual(request.pr_number, 42)
        self.assertEqual(
            request.to_json(),
            '{"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            '"pr_number":42,"source_repository":"DobbyVPN/DobbyVPN"}',
        )

    def test_accepts_public_fork_slug(self) -> None:
        request = VerificationRequest.parse(
            source_repository="contributor-name/dobbyvpn.fork",
            commit_sha="0123456789abcdef" * 2 + "01234567",
            pr_number=7,
        )

        self.assertEqual(request.pr_number, 7)

    def test_rejects_shell_metacharacters_in_repository(self) -> None:
        invalid = (
            "DobbyVPN/DobbyVPN;echo-owned",
            "DobbyVPN/DobbyVPN\nother/thing",
            "DobbyVPN/${HOME}",
            "../DobbyVPN",
            "DobbyVPN/..",
            "_owner/DobbyVPN",
            "-owner/DobbyVPN",
            "owner-/DobbyVPN",
            "missing-repository",
        )

        for repository in invalid:
            with self.subTest(repository=repository):
                with self.assertRaises(ValidationError):
                    VerificationRequest.parse(
                        source_repository=repository,
                        commit_sha="a" * 40,
                        pr_number=1,
                    )

    def test_rejects_mutable_or_ambiguous_refs(self) -> None:
        invalid = (
            "main",
            "refs/pull/1/head",
            "A" * 40,
            "a" * 39,
            "a" * 41,
            "g" * 40,
            "a" * 40 + "\n",
        )

        for commit in invalid:
            with self.subTest(commit=commit):
                with self.assertRaises(ValidationError):
                    VerificationRequest.parse(
                        source_repository="DobbyVPN/DobbyVPN",
                        commit_sha=commit,
                        pr_number=1,
                    )

    def test_rejects_noncanonical_pr_numbers(self) -> None:
        invalid: tuple[object, ...] = (
            0,
            -1,
            True,
            "0",
            "-1",
            "01",
            "1.0",
            "one",
            "",
            None,
        )

        for pr_number in invalid:
            with self.subTest(pr_number=pr_number):
                with self.assertRaises(ValidationError):
                    VerificationRequest.parse(
                        source_repository="DobbyVPN/DobbyVPN",
                        commit_sha="a" * 40,
                        pr_number=pr_number,  # type: ignore[arg-type]
                    )


if __name__ == "__main__":
    unittest.main()
