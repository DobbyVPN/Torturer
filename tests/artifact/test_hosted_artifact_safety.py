from __future__ import annotations

import io
import json
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.request import Request
import zipfile

import torturer_checks.hosted.artifacts as artifacts
from torturer_checks.hosted.artifacts import (
    ArtifactDownloadError,
    _CredentialSafeRedirectHandler,
    _extract,
    download_artifact,
)


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

    def test_get_has_true_total_deadline_for_slow_chunk(self) -> None:
        class SlowChunkResponse:
            def __init__(self) -> None:
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                self.close()

            def read(self, _size: int) -> bytes:
                while not self.closed:
                    time.sleep(0.01)
                return b""

            def close(self) -> None:
                self.closed = True

        response = SlowChunkResponse()
        started = time.monotonic()
        with patch.dict("os.environ", {"GH_TOKEN": "synthetic-token"}), patch(
            "torturer_checks.hosted.artifacts._OPENER.open", return_value=response
        ) as opener:
            with self.assertRaisesRegex(ArtifactDownloadError, "ARTIFACT_TRANSFER_TIMEOUT"):
                artifacts._get("https://api.github.com/synthetic", timeout_seconds=0.05)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.5)
        self.assertTrue(response.closed)
        self.assertLessEqual(opener.call_args.kwargs["timeout"], 0.05)

    def test_download_has_one_aggregate_deadline_for_list_download_extract(self) -> None:
        archive = _zip([("manifest.json", b"{}", stat.S_IFREG)])
        deadlines: list[float] = []
        calls = 0

        def slow_get(_url: str, *, deadline: float | None = None, **_kwargs: object) -> bytes:
            nonlocal calls
            calls += 1
            self.assertIsNotNone(deadline)
            assert deadline is not None
            deadlines.append(deadline)
            time.sleep(0.02)
            if time.monotonic() >= deadline:
                raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
            return self.listing if calls == 1 else archive

        def slow_extract(*_args: object, **_kwargs: object) -> None:
            time.sleep(0.5)

        started = time.monotonic()
        with patch("torturer_checks.hosted.artifacts._get", side_effect=slow_get), patch(
            "torturer_checks.hosted.artifacts._extract", side_effect=slow_extract
        ):
            with self.assertRaisesRegex(ArtifactDownloadError, "ARTIFACT_TRANSFER_TIMEOUT"):
                download_artifact(
                    repository="o/r", artifact_name="candidate", run_id=77,
                    output_dir=self.root / "out", expected_files=("manifest.json",),
                    metadata_path=self.root / "listing.json", archive_path=self.root / "archive.zip",
                    timeout_seconds=0.3,
                )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.5)
        self.assertEqual(calls, 2)
        self.assertEqual(len(set(deadlines)), 1)

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
        with self.assertWarnsRegex(UserWarning, "Duplicate name"):
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

    def test_cross_origin_redirect_drops_github_authorization(self) -> None:
        request = Request(
            "https://api.github.com/repos/o/r/actions/artifacts/42/zip",
            headers={
                "Authorization": "Bearer secret",
                "X-GitHub-Api-Version": "2022-11-28",
                "Accept": "application/vnd.github+json",
            },
        )
        redirected = _CredentialSafeRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://artifactcache.example.invalid/archive.zip?signature=opaque",
        )
        self.assertIsNotNone(redirected)
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertIsNone(redirected.get_header("X-Github-Api-Version"))
        self.assertEqual(redirected.get_header("Accept"), "application/vnd.github+json")

    def test_cli_public_output_contains_only_opaque_archive_metadata(self) -> None:
        archive = self.root / "archive.zip"
        archive.write_bytes(b"private archive bytes")
        with patch(
            "torturer_checks.hosted.artifacts.download_artifact",
            return_value={
                "name": "private-artifact-name",
                "run_id": 987654,
                "files": ["private-member.json"],
            },
        ), patch("sys.stdout", new_callable=io.StringIO) as output:
            result = artifacts.main(
                [
                    "--repository", "o/r",
                    "--artifact-name", "private-artifact-name",
                    "--run-id", "987654",
                    "--output-dir", str(self.root / "out"),
                    "--metadata", str(self.root / "metadata.json"),
                    "--archive", str(archive),
                    "--expect-file", "private-member.json",
                ]
            )
        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("artifact-download", rendered)
        self.assertRegex(rendered, r"id=[0-9a-f]{32}")
        self.assertRegex(rendered, r"archive_bytes=21")
        self.assertNotIn("private-artifact-name", rendered)
        self.assertNotIn("987654", rendered)
        self.assertNotIn("private-member.json", rendered)

    def test_redirect_refuses_https_downgrade(self) -> None:
        request = Request(
            "https://api.github.com/repos/o/r/actions/artifacts/42/zip",
            headers={"Authorization": "Bearer secret"},
        )
        with self.assertRaisesRegex(ArtifactDownloadError, "not HTTPS"):
            _CredentialSafeRedirectHandler().redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://artifactcache.example.invalid/archive.zip",
            )


if __name__ == "__main__":
    unittest.main()
