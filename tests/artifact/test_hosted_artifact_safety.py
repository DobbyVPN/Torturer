from __future__ import annotations

import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from torturer_checks.hosted.artifacts import ArtifactDownloadError, _extract, download_artifact


def _zip(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        for name, value, mode in entries:
            item = zipfile.ZipInfo(name)
            if mode is not None:
                item.external_attr = mode << 16
            bundle.writestr(item, value)
    return output.getvalue()


class HostedArtifactSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.listing = json.dumps({"artifacts": [{
            "id": 42, "name": "candidate", "expired": False,
            "workflow_run": {"id": 77},
            "archive_download_url": "https://api.github.com/repos/o/r/actions/artifacts/42/zip",
        }]}).encode()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _download(self, archive: bytes, *, output: Path | None = None, expected: tuple[str, ...] = ("manifest.json",)) -> None:
        with patch("torturer_checks.hosted.artifacts._get", side_effect=[self.listing, archive]):
            download_artifact(
                repository="o/r", artifact_name="candidate", run_id=77,
                output_dir=output or self.root / "out", expected_files=expected,
                metadata_path=self.root / "listing.json", archive_path=self.root / "archive.zip",
            )

    def test_allowed_extraction_is_owner_only(self) -> None:
        self._download(_zip([("manifest.json", b"{}", stat.S_IFREG)]))
        self.assertEqual((self.root / "out/manifest.json").read_bytes(), b"{}")
        self.assertEqual((self.root / "out/manifest.json").stat().st_mode & 0o077, 0)
        self.assertEqual((self.root / "out").stat().st_mode & 0o077, 0)

    def test_existing_destination_is_never_overwritten(self) -> None:
        retained = self.root / "listing.json"
        retained.write_bytes(b"retained")
        with patch("torturer_checks.hosted.artifacts._get", return_value=self.listing) as get:
            with self.assertRaisesRegex(ArtifactDownloadError, "already exists"):
                self._download(_zip([("manifest.json", b"{}", stat.S_IFREG)]))
        self.assertEqual(retained.read_bytes(), b"retained")
        get.assert_not_called()

    def test_existing_temporary_symlink_is_rejected(self) -> None:
        target = self.root / "outside"
        target.write_bytes(b"retained")
        temporary = self.root / ".listing.json.tmp"
        try:
            temporary.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with patch("torturer_checks.hosted.artifacts._get", return_value=self.listing):
            with self.assertRaisesRegex(ArtifactDownloadError, "already exists"):
                self._download(_zip([("manifest.json", b"{}", stat.S_IFREG)]))
        self.assertEqual(target.read_bytes(), b"retained")

    def test_existing_destination_symlink_is_rejected(self) -> None:
        target = self.root / "outside"
        target.write_bytes(b"retained")
        destination = self.root / "listing.json"
        try:
            destination.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with patch("torturer_checks.hosted.artifacts._get", return_value=self.listing) as get:
            with self.assertRaisesRegex(ArtifactDownloadError, "already exists"):
                self._download(_zip([("manifest.json", b"{}", stat.S_IFREG)]))
        self.assertEqual(target.read_bytes(), b"retained")
        get.assert_not_called()

    def test_existing_output_directory_symlink_is_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        output = self.root / "out"
        try:
            output.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with patch("torturer_checks.hosted.artifacts._get", side_effect=[self.listing, _zip([("manifest.json", b"{}", stat.S_IFREG)])]):
            with self.assertRaisesRegex(ArtifactDownloadError, "real directory"):
                self._download(_zip([("manifest.json", b"{}", stat.S_IFREG)]), output=output)
        self.assertFalse((outside / "manifest.json").exists())

    def test_traversal_and_zip_symlink_members_are_rejected(self) -> None:
        traversal = _zip([("../escape", b"bad", stat.S_IFREG)])
        traversal_path = self.root / "traversal.zip"
        traversal_path.write_bytes(traversal)
        with self.assertRaisesRegex(ArtifactDownloadError, "member path is unsafe"):
            _extract(traversal_path, self.root / "traversal-out", {"../escape"})
        link = _zip([("link", b"target", stat.S_IFLNK | 0o777)])
        link_path = self.root / "link.zip"
        link_path.write_bytes(link)
        with self.assertRaisesRegex(ArtifactDownloadError, "unsafe member"):
            _extract(link_path, self.root / "link-out", {"link"})
        mixed = _zip([("manifest.json", b"ok", stat.S_IFREG), ("link", b"target", stat.S_IFLNK | 0o777)])
        mixed_path = self.root / "mixed.zip"
        mixed_path.write_bytes(mixed)
        mixed_output = self.root / "mixed-out"
        with self.assertRaisesRegex(ArtifactDownloadError, "unsafe member"):
            _extract(mixed_path, mixed_output, {"manifest.json", "link"})
        self.assertFalse((mixed_output / "manifest.json").exists())

    def test_duplicate_zip_members_are_rejected_before_writes(self) -> None:
        duplicate = _zip([("manifest.json", b"one", stat.S_IFREG), ("manifest.json", b"two", stat.S_IFREG)])
        with patch("torturer_checks.hosted.artifacts._get", side_effect=[self.listing, duplicate]):
            with self.assertRaisesRegex(ArtifactDownloadError, "duplicate members"):
                self._download(duplicate)
        self.assertFalse((self.root / "out/manifest.json").exists())

    def test_duplicate_expected_names_are_rejected(self) -> None:
        with patch("torturer_checks.hosted.artifacts._get") as get:
            with self.assertRaisesRegex(ArtifactDownloadError, "allow-list is invalid"):
                self._download(b"unused", expected=("manifest.json", "manifest.json"))
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
