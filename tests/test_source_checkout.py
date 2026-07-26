from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from torturer_checks.source_checkout import SourceCheckoutError, verify_source_checkout


class SourceCheckoutTest(unittest.TestCase):
    def test_accepts_exact_clean_commit_and_rejects_tracked_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Torturer"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "torturer@example.invalid"],
                check=True,
            )
            tracked = root / "tracked.txt"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
            commit = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()

            verify_source_checkout(root, commit)
            (root / "untracked.txt").write_text("allowed\n", encoding="utf-8")
            verify_source_checkout(root, commit)
            tracked.write_text("modified\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceCheckoutError, "modified tracked"):
                verify_source_checkout(root, commit)

    def test_rejects_abbreviated_or_wrong_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(SourceCheckoutError, "exactly 40"):
                verify_source_checkout(root, "abc123")


if __name__ == "__main__":
    unittest.main()
