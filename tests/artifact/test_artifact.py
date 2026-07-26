from __future__ import annotations

import hashlib
import json
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile

from torturer_checks.artifact import (
    ArchiveLimits,
    ArtifactContractError,
    SourceIdentity,
    inspect_macos_zip,
    inspect_windows_zip,
    source_identity_from_checkout,
)


SOURCE = SourceIdentity.create(repository="DobbyVPN/DobbyVPN", commit="a" * 40)
WINDOWS_EXECUTABLE = "dobbyVPN-windows/bin/Dobby Vpn.exe"
MAC_APP = "Dobby Vpn.app"
MAC_EXECUTABLE = f"{MAC_APP}/Contents/MacOS/Dobby Vpn"


def fake_pe(machine: int = 0x8664, payload: bytes = b"") -> bytes:
    data = bytearray(0x90)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    return bytes(data) + payload


def fake_macho(cpu: int = 0x0100000C, payload: bytes = b"") -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + b"\0" * 24 + payload


def write_zip(path: Path, files: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, data in files.items():
            archive.writestr(name, data)


def mac_files(*, executable: bytes | None = None, plist: bytes | None = None) -> dict[str, bytes]:
    return {
        f"{MAC_APP}/Contents/Info.plist": plist
        if plist is not None
        else plistlib.dumps({"CFBundleExecutable": "Dobby Vpn", "CFBundlePackageType": "APPL"}),
        MAC_EXECUTABLE: executable if executable is not None else fake_macho(),
        f"{MAC_APP}/Contents/Resources/icon.icns": b"icon",
    }


class ArtifactContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_windows_contract_hashes_exact_artifact_and_emits_stable_manifest(self) -> None:
        artifact = self.directory / "dobbyVPN-windows.zip"
        executable = fake_pe(payload=b"normal public payload")
        write_zip(artifact, {WINDOWS_EXECUTABLE: executable, "dobbyVPN-windows/app/app.ico": b"icon"})

        expected_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        result = inspect_windows_zip(
            artifact,
            source=SOURCE,
            expected_sha256=expected_digest,
            expected_size_bytes=artifact.stat().st_size,
        )
        manifest = result.manifest_v1(
            workflow_revision="b" * 40, runner_os="windows", runner_arch="x86_64"
        )

        self.assertEqual(result.artifact_sha256, expected_digest)
        self.assertEqual(result.artifact_size_bytes, artifact.stat().st_size)
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["source"], {"repository": "DobbyVPN/DobbyVPN", "commit": "a" * 40})
        self.assertEqual(manifest["components"][0]["path"], WINDOWS_EXECUTABLE)  # type: ignore[index]
        self.assertEqual(result.manifest_json_v1(), result.manifest_json_v1())
        self.assertEqual(json.loads(result.manifest_json_v1())["artifact"]["format"], "zip")
        with self.assertRaisesRegex(ArtifactContractError, "SHA-256 differs"):
            inspect_windows_zip(artifact, source=SOURCE, expected_sha256="0" * 64)

    def test_windows_architecture_and_layout_are_exact(self) -> None:
        artifact = self.directory / "wrong.zip"
        write_zip(artifact, {WINDOWS_EXECUTABLE: fake_pe(0xAA64)})
        with self.assertRaisesRegex(ArtifactContractError, "architecture"):
            inspect_windows_zip(artifact, source=SOURCE, architecture="amd64")

        write_zip(artifact, {"another-root/bin/Dobby Vpn.exe": fake_pe()})
        with self.assertRaisesRegex(ArtifactContractError, "expected package root"):
            inspect_windows_zip(artifact, source=SOURCE)

    def test_macos_contract_requires_bundle_plist_and_target_macho_slice(self) -> None:
        artifact = self.directory / "dobbyVPN-macos-aarch64.zip"
        write_zip(artifact, mac_files())

        result = inspect_macos_zip(artifact, source=SOURCE, architecture="aarch64")

        self.assertEqual(result.architecture, "arm64")
        self.assertEqual(result.components[0]["path"], MAC_EXECUTABLE)

        write_zip(artifact, mac_files(plist=plistlib.dumps({"CFBundleExecutable": "Wrong"})))
        with self.assertRaisesRegex(ArtifactContractError, "Info.plist"):
            inspect_macos_zip(artifact, source=SOURCE, architecture="arm64")

        write_zip(artifact, mac_files(executable=fake_macho(0x01000007)))
        with self.assertRaisesRegex(ArtifactContractError, "architecture"):
            inspect_macos_zip(artifact, source=SOURCE, architecture="arm64")

    def test_rejects_path_traversal_and_windows_case_collisions(self) -> None:
        artifact = self.directory / "unsafe.zip"
        write_zip(artifact, {WINDOWS_EXECUTABLE: fake_pe(), "dobbyVPN-windows/../outside": b"x"})
        with self.assertRaisesRegex(ArtifactContractError, "unsafe path"):
            inspect_windows_zip(artifact, source=SOURCE)

        write_zip(
            artifact,
            {WINDOWS_EXECUTABLE: fake_pe(), "DobbyVPN-windows/bin/Dobby Vpn.exe": fake_pe()},
        )
        with self.assertRaisesRegex(ArtifactContractError, "colliding"):
            inspect_windows_zip(artifact, source=SOURCE)

    def test_rejects_zip_symlink_and_symlink_artifact(self) -> None:
        artifact = self.directory / "symlink-member.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(WINDOWS_EXECUTABLE, fake_pe())
            link = zipfile.ZipInfo("dobbyVPN-windows/link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"target")
        with self.assertRaisesRegex(ArtifactContractError, "symbolic links"):
            inspect_windows_zip(artifact, source=SOURCE)

        linked = self.directory / "linked.zip"
        try:
            linked.symlink_to(artifact)
        except OSError as error:  # pragma: no cover - unusual Windows developer setup
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaisesRegex(ArtifactContractError, "non-symlink"):
            inspect_windows_zip(linked, source=SOURCE)

    def test_rejects_archive_bomb_before_member_reading(self) -> None:
        artifact = self.directory / "bomb.zip"
        write_zip(
            artifact,
            {WINDOWS_EXECUTABLE: fake_pe(), "dobbyVPN-windows/app/repeated": b"A" * 50_000},
        )
        with self.assertRaisesRegex(ArtifactContractError, "compression ratio"):
            inspect_windows_zip(artifact, source=SOURCE, limits=ArchiveLimits(max_compression_ratio=2))

    def test_obvious_credential_marker_is_not_echoed(self) -> None:
        artifact = self.directory / "credential.zip"
        secret = b"ghp_this_must_not_appear_in_diagnostics"
        write_zip(artifact, {WINDOWS_EXECUTABLE: fake_pe(payload=secret)})

        with self.assertRaises(ArtifactContractError) as raised:
            inspect_windows_zip(artifact, source=SOURCE)

        self.assertIn("credential marker", str(raised.exception))
        self.assertNotIn(secret.decode(), str(raised.exception))

    def test_common_binary_xox_bytes_are_not_treated_as_a_slack_token(self) -> None:
        artifact = self.directory / "ordinary-binary.zip"
        write_zip(
            artifact,
            {WINDOWS_EXECUTABLE: fake_pe(payload=b"ordinary-xox-binary-bytes")},
        )

        inspect_windows_zip(artifact, source=SOURCE)

        write_zip(
            artifact,
            {WINDOWS_EXECUTABLE: fake_pe(payload=b"xoxb-not-a-real-token")},
        )
        with self.assertRaisesRegex(ArtifactContractError, "credential marker"):
            inspect_windows_zip(artifact, source=SOURCE)

    def test_source_identity_requires_exact_resolved_sha(self) -> None:
        repository = self.directory / "source"
        repository.mkdir()
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "Test"], check=True)
        (repository / "source.txt").write_text("public source", encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", "source.txt"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "source"], check=True)
        resolved = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()

        identity = source_identity_from_checkout(
            repository, repository="DobbyVPN/DobbyVPN", expected_commit=resolved
        )
        self.assertEqual(identity.commit, resolved)
        with self.assertRaisesRegex(ArtifactContractError, "differs"):
            source_identity_from_checkout(
                repository, repository="DobbyVPN/DobbyVPN", expected_commit="a" * 40
            )

        (repository / "source.txt").write_text("modified source", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactContractError, "modified tracked files"):
            source_identity_from_checkout(
                repository, repository="DobbyVPN/DobbyVPN", expected_commit=resolved
            )

    def test_identity_rejects_noncanonical_source_values(self) -> None:
        with self.assertRaises(ArtifactContractError):
            SourceIdentity.create(repository="DobbyVPN/../DobbyVPN", commit="a" * 40)
        with self.assertRaises(ArtifactContractError):
            SourceIdentity.create(repository="DobbyVPN/..", commit="a" * 40)
        with self.assertRaises(ArtifactContractError):
            SourceIdentity.create(repository="DobbyVPN/DobbyVPN", commit="A" * 40)


if __name__ == "__main__":
    unittest.main()
