"""Cross-workflow policy tests for the encrypted profile transport boundary."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLIENT_WORKFLOWS = tuple(
    ROOT / ".github" / "workflows" / name
    for name in (
        "functional.yml",
        "functional-windows.yml",
        "functional-macos.yml",
        "functional-android.yml",
    )
)
LEASE_WORKFLOW = ROOT / ".github" / "workflows" / "server-lease.yml"


class ProfileHandoffBoundaryPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.clients = {path.name: path.read_text(encoding="utf-8") for path in CLIENT_WORKFLOWS}
        cls.lease = LEASE_WORKFLOW.read_text(encoding="utf-8")

    @staticmethod
    def _step(text: str, title: str) -> str:
        start = text.index(f"- name: {title}")
        next_step = text.find("\n      - name:", start + 1)
        return text[start:] if next_step < 0 else text[start:next_step]

    def test_each_client_exposes_only_request_certificate_and_result(self) -> None:
        for name, text in self.clients.items():
            request = self._step(text, "Upload public certificate")
            self.assertIn("request.json", request, name)
            self.assertIn("recipient.crt", request, name)
            for forbidden in ("recipient.key", "profile.toml", "profile.cms", "raw-log", "SERVICE_DIR"):
                self.assertNotIn(forbidden, request, f"{name}: {forbidden}")

            result_title = next(
                title for title in (
                    "Upload safe functional result",
                    "Upload safe Android functional result",
                    "Upload safe macOS functional result",
                    "Upload safe Windows functional result",
                ) if f"- name: {title}" in text
            )
            result = self._step(text, result_title)
            self.assertIn("path: ${{ env.RESULT_PATH }}", result, name)
            for forbidden in ("profile.toml", "profile.cms", "recipient.key", "raw-log", "SERVICE_DIR"):
                self.assertNotIn(forbidden, result, f"{name}: {forbidden}")
            self.assertIn("retention-days: 1", result, name)

    def test_each_client_decrypts_only_with_local_key_and_always_removes_plaintext(self) -> None:
        for name, text in self.clients.items():
            self.assertIn('"$HANDOFF_DIR/recipient.key"', text, name)
            remove = self._step(text, "Remove plaintext handoff material")
            self.assertIn("if: always()", remove, name)
            self.assertIn('rm -f "$HANDOFF_DIR/profile.toml" "$HANDOFF_DIR/recipient.key"', remove, name)
            self.assertNotIn("recipient.key", self._step(text, "Upload public certificate"), name)
            self.assertIn("profile.cms", text, name)
            self.assertIn("openssl cms -decrypt", text, name)

    def test_lease_job_uploads_only_ciphertext_and_safe_record(self) -> None:
        upload = self._step(self.lease, "Upload encrypted profile and safe lease record")
        self.assertIn("profile.cms", upload)
        self.assertIn("lease.json", upload)
        self.assertNotIn("profile.toml", upload)
        self.assertNotIn("recipient.key", upload)
        self.assertNotIn("recipient.crt", upload)
        self.assertNotIn("raw", upload.lower())
        self.assertIn("retention-days: 1", upload)

        journal = self._step(self.lease, "Upload safe lease journal")
        self.assertIn("lease.json", journal)
        self.assertIn("journal.json", journal)
        self.assertNotIn("profile.cms", journal)
        self.assertNotIn("profile.toml", journal)
        self.assertNotIn("recipient.key", journal)
        self.assertNotIn("recipient.crt", journal)
        self.assertIn("retention-days: 1", journal)

    def test_lease_encrypts_before_upload_and_deletes_plaintext_unconditionally(self) -> None:
        encrypt = self.lease.index("openssl cms -encrypt")
        upload = self.lease.index("- name: Upload encrypted profile and safe lease record")
        cleanup = self.lease.index("- name: Remove plaintext lease material")
        self.assertLess(encrypt, upload)
        self.assertIn('rm -f "$lease_dir/profile.toml" "$lease_dir/request/unpacked/recipient.crt"', self.lease[cleanup:])
        self.assertIn("if: always()", self.lease[self.lease.index("- name: Remove plaintext lease material") - 30:])
        self.assertIn('rm -f "$LEASE_DIR/profile.toml"', self.lease)
        self.assertNotIn("recipient.key", self.lease)

    def test_no_profile_or_key_paths_are_uploaded_as_result_evidence(self) -> None:
        all_text = "\n".join(self.clients.values()) + "\n" + self.lease
        for upload in re.findall(r"(?ms)- name: Upload .*?\n(?:      .*\n)*?", all_text):
            if "functional result" in upload.lower() or "completion marker" in upload.lower():
                self.assertNotIn("profile.cms", upload)
                self.assertNotIn("profile.toml", upload)
                self.assertNotIn("recipient.key", upload)


if __name__ == "__main__":
    unittest.main()
