from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from torturer_checks.hosted.candidate import CandidateClosureError, stage, verify


SHA = "a" * 40


class HostedCandidateClosureTests(unittest.TestCase):
    def _source(self, root: Path, platform: str) -> None:
        files = {
            "linux": (
                "kmp_module/services/ubuntu_grpcvpnserver",
                "kmp_module/services/dobby-cli",
                "kmp_module/services/libdobby_bridge.so",
                "kmp_module/services/libc++.so.1",
                "kmp_module/services/libc++abi.so.1",
            ),
            "windows": (
                "kmp_module/services/windows_grpcvpnserver.exe",
                "kmp_module/services/dobby-cli.exe",
                "kmp_module/services/wintun.dll",
                "kmp_module/services/dobby_bridge.dll",
            ),
            "macos": (
                "kmp_module/services/macos_grpcvpnserver",
                "kmp_module/services/dobby-cli",
            ),
            "android": (
                "kmp_module/app/build/outputs/apk/debug/app-debug.apk",
                "kmp_module/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk",
            ),
        }[platform]
        for index, relative in enumerate(files):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture-{index}".encode())
            path.chmod(0o700)

    def test_every_platform_round_trips_exact_allow_list(self) -> None:
        architectures = {
            "linux": "amd64",
            "windows": "amd64",
            "macos": "arm64",
            "android": "x86_64",
        }
        for platform, architecture in architectures.items():
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source"
                output = root / "output"
                self._source(source, platform)
                manifest = stage(
                    source,
                    output,
                    platform=platform,
                    architecture=architecture,
                    source_sha=SHA,
                )
                self.assertEqual(
                    verify(
                        output,
                        platform=platform,
                        architecture=architecture,
                        source_sha=SHA,
                    ),
                    manifest,
                )
                self.assertEqual(
                    {path.name for path in output.iterdir()},
                    set(manifest["files"]) | {"manifest.json"},
                )
                self.assertEqual(output.stat().st_mode & 0o077, 0)

    def test_tamper_and_extra_member_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "output"
            self._source(source, "macos")
            stage(source, output, platform="macos", architecture="arm64", source_sha=SHA)
            (output / "dobby-cli").write_bytes(b"tampered")
            with self.assertRaisesRegex(CandidateClosureError, "digest or size mismatch"):
                verify(output, platform="macos", architecture="arm64", source_sha=SHA)
            stage_root = root / "second"
            stage(source, stage_root, platform="macos", architecture="arm64", source_sha=SHA)
            (stage_root / "unexpected").write_bytes(b"unexpected")
            with self.assertRaisesRegex(CandidateClosureError, "member allow-list mismatch"):
                verify(stage_root, platform="macos", architecture="arm64", source_sha=SHA)

    def test_symlink_and_stale_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            self._source(source, "linux")
            target = source / "kmp_module/services/dobby-cli"
            target.unlink()
            target.symlink_to(source / "kmp_module/services/ubuntu_grpcvpnserver")
            with self.assertRaisesRegex(CandidateClosureError, "not a regular file"):
                stage(source, root / "output", platform="linux", architecture="amd64", source_sha=SHA)
            with self.assertRaisesRegex(CandidateClosureError, "source SHA is invalid"):
                stage(source, root / "other", platform="linux", architecture="amd64", source_sha="short")

    def test_symlinked_parents_and_preexisting_outputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            self._source(source, "macos")

            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(CandidateClosureError, "path contains a symlink component"):
                stage(source, linked_parent / "output", platform="macos", architecture="arm64", source_sha=SHA)

            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(CandidateClosureError, "must not already exist"):
                stage(source, existing, platform="macos", architecture="arm64", source_sha=SHA)

            output = root / "output"
            stage(source, output, platform="macos", architecture="arm64", source_sha=SHA)
            root_link = root / "root-link"
            root_link.symlink_to(output, target_is_directory=True)
            with self.assertRaisesRegex(CandidateClosureError, "path contains a symlink component"):
                verify(root_link, platform="macos", architecture="arm64", source_sha=SHA)

    def test_source_intermediate_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            self._source(source, "macos")
            module_target = root / "module-target"
            (source / "kmp_module").rename(module_target)
            (source / "kmp_module").symlink_to(module_target, target_is_directory=True)
            with self.assertRaisesRegex(CandidateClosureError, "path contains a symlink component"):
                stage(source, root / "output", platform="macos", architecture="arm64", source_sha=SHA)

    def test_manifest_shape_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "output"
            self._source(source, "android")
            stage(source, output, platform="android", architecture="x86_64", source_sha=SHA)
            manifest_path = output / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["profile"] = "forbidden"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            os.chmod(manifest_path, 0o600)
            with self.assertRaisesRegex(CandidateClosureError, "unsafe shape"):
                verify(output, platform="android", architecture="x86_64", source_sha=SHA)

    def test_manifest_rejects_ambiguous_scalar_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "output"
            self._source(source, "macos")
            stage(source, output, platform="macos", architecture="arm64", source_sha=SHA)
            manifest_path = output / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(CandidateClosureError, "schema mismatch"):
                verify(output, platform="macos", architecture="arm64", source_sha=SHA)
            manifest["schema"] = 1
            manifest["files"]["dobby-cli"]["size"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(CandidateClosureError, "size is invalid"):
                verify(output, platform="macos", architecture="arm64", source_sha=SHA)


if __name__ == "__main__":
    unittest.main()
