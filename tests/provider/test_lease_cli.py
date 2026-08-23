from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest

from torturer_provider import lease_cli
from torturer_provider.lease import LeaseJournalRecord, LeaseState, RenderLeaseJournal
from torturer_provider.render import RenderServiceHandle


class FakeAPI:
    deleted: list[str] = []

    def __init__(self, token: str) -> None:
        self.token = token

    def delete_service(self, service_id: str) -> bool:
        self.deleted.append(service_id)
        return True

    def exists(self, service_id: str) -> bool:
        return False

    def list_services(self, owner_id: str):
        return ()




class FakeAcquireAPI:
    specs: list[object] = []

    def __init__(self, token: str) -> None:
        self.token = token
        self.deleted: list[str] = []

    def create_service(self, spec):
        self.specs.append(spec)
        return RenderServiceHandle("srv-acquire123", "dep-acquire123", spec.image_digest)

    def service(self, service_id):
        return {"suspended": "not_suspended", "serviceDetails": {"numInstances": 1, "url": "https://lease.example.onrender.com"}}

    def deploy(self, service_id, deploy_id):
        return {"status": "live"}

    def delete_service(self, service_id):
        self.deleted.append(service_id)
        return True

    def exists(self, service_id):
        return False


class LeaseCLIContractTests(unittest.TestCase):
    @staticmethod
    def _write_issued_journal(path: Path, value: dict[str, object]) -> None:
        journal = RenderLeaseJournal(path)
        journal.append(
            LeaseJournalRecord(
                run_id=str(value["run_id"]),
                service_id=str(value["service_id"]),
                image_digest=str(value["image_digest"]),
                state=LeaseState.ISSUED,
                timestamp="2026-08-23T00:00:00Z",
            )
        )

    def test_acquire_writes_owner_only_profile_and_safe_lease_record(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAcquireAPI
        FakeAcquireAPI.specs = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-acquire-") as directory:
                root = Path(directory)
                digest = "sha256:" + "c" * 64
                request = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": "d" * 32,
                    "platform": "linux",
                    "source_sha": "e" * 40,
                    "image_digest": digest,
                }
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request), encoding="utf-8")
                os.chmod(request_path, 0o600)
                args = argparse.Namespace(
                    request=request_path, owner_id="tea-owner123", image_owner_id="tea-owner123",
                    image_path="ghcr.io/dobbyvpn/outline@" + digest, expected_image_digest=digest,
                    profile_output=root / "profile.toml", lease_output=root / "lease.json",
                    journal=root / "journal.json", listen_port=10000, region="oregon",
                    timeout_seconds=5.0, poll_seconds=1.0,
                )
                self.assertEqual(lease_cli.acquire(args), 0)
                self.assertEqual((root / "profile.toml").stat().st_mode & 0o777, 0o600)
                profile = (root / "profile.toml").read_text(encoding="utf-8")
                self.assertIn("[[Outline]]", profile)
                self.assertIn("lease.example.onrender.com", profile)
                lease = json.loads((root / "lease.json").read_text(encoding="utf-8"))
                self.assertEqual(lease["state"], "issued")
                self.assertNotIn("lease.example.onrender.com", json.dumps(lease))
                self.assertEqual(
                    FakeAcquireAPI.specs[0].docker_command,
                    "/outline-ss-server -config=/etc/secrets/config.yml",
                )
        finally:
            lease_cli.RenderAPI = original

    def test_cleanup_is_idempotent_and_keeps_safe_shape(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAPI
        FakeAPI.deleted = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-") as directory:
                path = Path(directory) / "lease.json"
                value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "a" * 32,
                    "platform": "linux",
                    "source_sha": "c" * 40,
                    "service_id": "srv-test123",
                    "image_digest": "sha256:" + "b" * 64,
                    "provider_generation": "dep-test123",
                    "state": "issued",
                }
                path.write_text(json.dumps(value), encoding="utf-8")
                os.chmod(path, 0o600)
                journal_path = Path(directory) / "journal.json"
                self._write_issued_journal(journal_path, value)
                args = argparse.Namespace(lease=path, journal=journal_path, request=None, owner_id=None)
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(FakeAPI.deleted, ["srv-test123"])
                result = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(result["state"], "absent")
                self.assertEqual(result["cleanup"], "verified")
                self.assertNotIn("profile", json.dumps(result).lower())
                records = RenderLeaseJournal(journal_path).records()
                self.assertEqual(
                    [record.state for record in records],
                    [LeaseState.ISSUED, LeaseState.DELETING, LeaseState.ABSENT],
                )
                self.assertEqual(records[-1].cleanup_result, "verified")
        finally:
            lease_cli.RenderAPI = original

    def test_begin_testing_is_idempotent_and_journaled(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-testing-") as directory:
            root = Path(directory)
            value = {
                "schema": 1,
                "kind": "dobbyvpn.render-lease",
                "run_id": "b" * 32,
                "platform": "macos",
                "source_sha": "d" * 40,
                "service_id": "srv-testing123",
                "image_digest": "sha256:" + "c" * 64,
                "provider_generation": "dep-testing123",
                "state": "issued",
            }
            lease_path = root / "lease.json"
            lease_path.write_text(json.dumps(value), encoding="utf-8")
            lease_path.chmod(0o600)
            journal_path = root / "journal.json"
            self._write_issued_journal(journal_path, value)
            args = argparse.Namespace(lease=lease_path, journal=journal_path)
            self.assertEqual(lease_cli.begin_testing(args), 0)
            self.assertEqual(lease_cli.begin_testing(args), 0)
            self.assertEqual(
                [record.state for record in RenderLeaseJournal(journal_path).records()],
                [LeaseState.ISSUED, LeaseState.TESTING],
            )
            testing = json.loads(lease_path.read_text(encoding="utf-8"))
            self.assertEqual(testing["state"], "testing")
            self.assertNotIn("profile", json.dumps(testing).lower())

    def test_cleanup_from_testing_records_deleting_before_absent(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAPI
        FakeAPI.deleted = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-testing-cleanup-") as directory:
                root = Path(directory)
                value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "7" * 32,
                    "platform": "android",
                    "source_sha": "8" * 40,
                    "service_id": "srv-testingcleanup123",
                    "image_digest": "sha256:" + "8" * 64,
                    "provider_generation": "dep-testingcleanup123",
                    "state": "issued",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                self._write_issued_journal(journal_path, value)
                lease_cli.begin_testing(
                    argparse.Namespace(lease=lease_path, journal=journal_path)
                )
                self.assertEqual(
                    lease_cli.cleanup(
                        argparse.Namespace(
                            lease=lease_path,
                            journal=journal_path,
                            request=None,
                            owner_id=None,
                        )
                    ),
                    0,
                )
                self.assertEqual(FakeAPI.deleted, ["srv-testingcleanup123"])
                self.assertEqual(
                    [record.state for record in RenderLeaseJournal(journal_path).records()],
                    [
                        LeaseState.ISSUED,
                        LeaseState.TESTING,
                        LeaseState.DELETING,
                        LeaseState.ABSENT,
                    ],
                )
        finally:
            lease_cli.RenderAPI = original

    def test_cleanup_rejects_conflicting_service_identity_in_journal_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-conflicting-service-") as directory:
            root = Path(directory)
            value = {
                "schema": 1,
                "kind": "dobbyvpn.render-lease",
                "run_id": "9" * 32,
                "platform": "windows",
                "source_sha": "b" * 40,
                "service_id": "srv-current123",
                "image_digest": "sha256:" + "a" * 64,
                "provider_generation": "dep-current123",
                "state": "issued",
            }
            lease_path = root / "lease.json"
            lease_path.write_text(json.dumps(value), encoding="utf-8")
            lease_path.chmod(0o600)
            journal_path = root / "journal.json"
            journal = RenderLeaseJournal(journal_path)
            for service_id in ("srv-conflict123", "srv-current123"):
                journal.append(LeaseJournalRecord(
                    run_id=str(value["run_id"]),
                    service_id=service_id,
                    image_digest=str(value["image_digest"]),
                    state=LeaseState.ISSUED,
                    timestamp="2026-08-23T00:00:00Z",
                ))
            with self.assertRaisesRegex(ValueError, "journal history identity mismatch"):
                lease_cli.cleanup(
                    argparse.Namespace(
                        lease=lease_path,
                        journal=journal_path,
                        request=None,
                        owner_id=None,
                    )
                )

    def test_cleanup_recovers_exact_service_from_journal_without_lease_record(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAPI
        FakeAPI.deleted = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-recovery-") as directory:
                root = Path(directory)
                request_value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": "e" * 32,
                    "platform": "windows",
                    "source_sha": "a" * 40,
                    "image_digest": "sha256:" + "f" * 64,
                }
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request_value), encoding="utf-8")
                request_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path)
                journal.append(LeaseJournalRecord(
                    run_id=request_value["run_id"],
                    service_id="srv-recover123",
                    image_digest=request_value["image_digest"],
                    state=LeaseState.CREATING,
                    timestamp="2026-08-23T00:00:00Z",
                ))
                args = argparse.Namespace(
                    lease=None,
                    journal=journal_path,
                    request=request_path,
                    owner_id="tea-owner123",
                )
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(FakeAPI.deleted, ["srv-recover123"])
                self.assertEqual(
                    [record.state for record in journal.records()],
                    [LeaseState.CREATING, LeaseState.DELETING, LeaseState.ABSENT],
                )
                self.assertEqual(journal.records()[-1].cleanup_result, "verified")
        finally:
            lease_cli.RenderAPI = original


if __name__ == "__main__":
    unittest.main()
