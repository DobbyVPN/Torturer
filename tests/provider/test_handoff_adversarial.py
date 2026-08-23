"""Adversarial tests for the encrypted profile transport boundary."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from torturer_provider.handoff import (
    HandoffContractError,
    artifact_name,
    cms_decrypt_command,
    cms_encrypt_command,
    require_owner_only,
    validate_lease_correlation,
)


class EncryptedHandoffAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl is required by the hosted handoff contract")

    @staticmethod
    def _make_recipient(root: Path, stem: str) -> tuple[Path, Path]:
        key = root / f"{stem}.key"
        cert = root / f"{stem}.crt"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                "-subj", f"/CN={stem}", "-keyout", str(key), "-out", str(cert),
                "-days", "1",
            ],
            check=True,
        )
        key.chmod(0o600)
        cert.chmod(0o600)
        return key, cert

    def test_wrong_recipient_tampering_and_replay_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="torturer-handoff-adversarial-") as directory:
            root = Path(directory)
            plaintext = root / "profile.toml"
            ciphertext = root / "profile.cms"
            decrypted = root / "decrypted.toml"
            tampered = root / "tampered.cms"
            plaintext.write_bytes(b'[[Outline]]\nPassword = "synthetic-canary"\n')
            plaintext.chmod(0o600)
            first_key, first_cert = self._make_recipient(root, "first")
            second_key, second_cert = self._make_recipient(root, "second")

            subprocess.run(
                cms_encrypt_command(plaintext, first_cert, ciphertext), check=True
            )
            ciphertext.chmod(0o600)
            subprocess.run(
                cms_decrypt_command(ciphertext, first_cert, first_key, decrypted),
                check=True,
            )
            decrypted.chmod(0o600)
            self.assertEqual(decrypted.read_bytes(), plaintext.read_bytes())

            wrong_recipient = subprocess.run(
                cms_decrypt_command(ciphertext, second_cert, second_key, root / "wrong.toml"),
                check=False,
            )
            self.assertNotEqual(wrong_recipient.returncode, 0)

            tampered.write_bytes(
                ciphertext.read_bytes()[:-1]
                + bytes([ciphertext.read_bytes()[-1] ^ 1])
            )
            tampered.chmod(0o600)
            tampered_result = subprocess.run(
                cms_decrypt_command(tampered, first_cert, first_key, root / "tampered.toml"),
                check=False,
            )
            self.assertNotEqual(tampered_result.returncode, 0)

            # A ciphertext from another run cannot be identified by the
            # opaque artifact name of this run; the fresh recipient key also
            # makes replay into this job fail closed.
            self.assertNotEqual(artifact_name("a" * 32, "linux", "b" * 40), artifact_name("b" * 32, "linux", "b" * 40))
            self.assertNotEqual(artifact_name("a" * 32, "linux", "b" * 40), artifact_name("a" * 32, "android", "b" * 40))
            self.assertNotEqual(artifact_name("a" * 32, "linux", "b" * 40), artifact_name("a" * 32, "linux", "c" * 40))

    def test_private_key_and_profile_material_never_enter_argv_or_ciphertext(self) -> None:
        marker = "PROFILE_BYTES bearer=synthetic endpoint=https://private.example"
        plaintext = Path("/tmp/profile-marker.toml")
        certificate = Path("/tmp/recipient-marker.crt")
        private_key = Path("/tmp/recipient-marker.key")
        ciphertext = Path("/tmp/profile-marker.cms")
        encrypt = cms_encrypt_command(plaintext, certificate, ciphertext)
        decrypt = cms_decrypt_command(ciphertext, certificate, private_key, plaintext)
        self.assertNotIn(marker, " ".join(encrypt))
        self.assertNotIn(marker, " ".join(decrypt))
        self.assertNotIn(marker.encode(), " ".join(encrypt).encode())
        self.assertNotIn(marker.encode(), " ".join(decrypt).encode())
        self.assertNotIn(private_key.name, " ".join(encrypt))
        self.assertIn(str(private_key), decrypt)

    def test_all_handoff_inputs_must_be_owner_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="torturer-handoff-permissions-") as directory:
            root = Path(directory)
            for name in ("profile.toml", "recipient.key", "recipient.crt", "profile.cms"):
                path = root / name
                path.write_bytes(b"synthetic")
                path.chmod(0o600)
                require_owner_only(path)
                path.chmod(0o640)
                with self.assertRaises(HandoffContractError):
                    require_owner_only(path)

    def test_artifact_identity_rejects_cross_platform_and_malformed_replay_names(self) -> None:
        source = "b" * 40
        self.assertTrue(artifact_name("a" * 32, "linux", source).startswith("render-lease-"))
        for run_id, platform, candidate_source in (
            ("A" * 32, "linux", source),
            ("a" * 31, "linux", source),
            ("a" * 32, "freebsd", source),
            ("a" * 32, "linux/evil", source),
            ("a" * 32, "linux", "0" * 40),
            ("a" * 32, "linux", "b" * 39),
        ):
            with self.subTest(run_id=run_id, platform=platform), self.assertRaises(HandoffContractError):
                artifact_name(run_id, platform, candidate_source)

    def test_omitted_or_mismatched_source_is_rejected_before_decryption(self) -> None:
        common = {
            "expected_run_id": "a" * 32,
            "expected_platform": "linux",
            "expected_source_sha": "b" * 40,
            "request_run_id": "a" * 32,
            "request_platform": "linux",
        }
        for candidate in (None, "c" * 40):
            with self.subTest(candidate=candidate), self.assertRaises(HandoffContractError):
                validate_lease_correlation(**common, request_source_sha=candidate)


if __name__ == "__main__":
    unittest.main()
