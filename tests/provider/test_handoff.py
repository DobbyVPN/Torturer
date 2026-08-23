"""Tests for the standard-tool encrypted profile handoff boundary."""

from __future__ import annotations

import os
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
    lease_correlation_id,
    require_owner_only,
    require_source_sha,
    validate_lease_correlation,
)


class EncryptedHandoffTests(unittest.TestCase):
    def test_artifact_name_is_opaque_and_validated(self) -> None:
        source = "b" * 40
        name = artifact_name("a" * 32, "linux", source)
        self.assertEqual(name, f"render-lease-{lease_correlation_id('a' * 32, 'linux', source)}-linux")
        self.assertNotIn(source, name)
        with self.assertRaises(HandoffContractError):
            artifact_name("short", "linux", source)
        with self.assertRaises(HandoffContractError):
            artifact_name("a" * 32, "linux;cat", source)

    def test_source_sha_is_full_nonzero_and_correlation_is_pre_decrypt_check(self) -> None:
        run_id = "a" * 32
        source = "b" * 40
        self.assertEqual(require_source_sha(source), source)
        for invalid in (None, "", "b" * 39, "B" * 40, "0" * 40):
            with self.subTest(invalid=invalid), self.assertRaises(HandoffContractError):
                require_source_sha(invalid)
        expected = validate_lease_correlation(
            expected_run_id=run_id,
            expected_platform="linux",
            expected_source_sha=source,
            request_run_id=run_id,
            request_platform="linux",
            request_source_sha=source,
        )
        self.assertEqual(expected, lease_correlation_id(run_id, "linux", source))
        for request_source in (None, "c" * 40):
            with self.subTest(request_source=request_source), self.assertRaises(HandoffContractError):
                validate_lease_correlation(
                    expected_run_id=run_id,
                    expected_platform="linux",
                    expected_source_sha=source,
                    request_run_id=run_id,
                    request_platform="linux",
                    request_source_sha=request_source,
                )

    def test_commands_are_argument_vectors_and_reject_collisions(self) -> None:
        source = Path("/tmp/profile input.json")
        cert = Path("/tmp/recipient.pem")
        target = Path("/tmp/profile.cms")
        command = cms_encrypt_command(source, cert, target)
        self.assertEqual(command[0:5], ("openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm"))
        self.assertIn(str(source), command)
        self.assertNotIn(";", " ".join(command))
        with self.assertRaises(HandoffContractError):
            cms_encrypt_command(source, cert, source)
        decrypt = cms_decrypt_command(target, cert, Path("/tmp/private.pem"), source)
        self.assertIn("-inkey", decrypt)
        with self.assertRaises(HandoffContractError):
            cms_decrypt_command(target, cert, Path("-private.pem"), source)

    def test_cms_round_trip_keeps_plaintext_out_of_ciphertext(self) -> None:
        self.assertIsNotNone(shutil.which("openssl"), "openssl is required by the hosted runner contract")
        with tempfile.TemporaryDirectory(prefix="torturer-handoff-") as directory:
            root = Path(directory)
            key = root / "recipient-key.pem"
            cert = root / "recipient-cert.pem"
            plaintext = root / "profile.json"
            ciphertext = root / "profile.cms"
            decrypted = root / "decrypted.json"
            canary = b'{"password":"synthetic-handoff-canary"}\n'
            plaintext.write_bytes(canary)
            os.chmod(plaintext, 0o600)
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                    "-subj", "/CN=torturer-handoff-test", "-keyout", str(key),
                    "-out", str(cert), "-days", "1",
                ],
                check=True,
            )
            os.chmod(key, 0o600)
            os.chmod(cert, 0o600)
            require_owner_only(plaintext)
            require_owner_only(key)
            subprocess.run(cms_encrypt_command(plaintext, cert, ciphertext), check=True)
            os.chmod(ciphertext, 0o600)
            require_owner_only(ciphertext)
            self.assertNotIn(canary, ciphertext.read_bytes())
            subprocess.run(cms_decrypt_command(ciphertext, cert, key, decrypted), check=True)
            os.chmod(decrypted, 0o600)
            self.assertEqual(decrypted.read_bytes(), canary)

    def test_owner_only_check_rejects_group_readable_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="torturer-handoff-mode-") as directory:
            path = Path(directory) / "handoff"
            path.write_text("synthetic")
            os.chmod(path, 0o640)
            with self.assertRaises(HandoffContractError):
                require_owner_only(path)


if __name__ == "__main__":
    unittest.main()
