from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest

from torturer_provider import lease_cli
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




class FakeAcquireAPI:
    def __init__(self, token: str) -> None:
        self.token = token
        self.deleted: list[str] = []

    def create_service(self, spec):
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
    def test_acquire_writes_owner_only_profile_and_safe_lease_record(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAcquireAPI
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-acquire-") as directory:
                root = Path(directory)
                digest = "sha256:" + "c" * 64
                request = {"schema": 1, "kind": "dobbyvpn.render-lease-request", "run_id": "d" * 32, "platform": "linux", "image_digest": digest}
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
                    "service_id": "srv-test123",
                    "image_digest": "sha256:" + "b" * 64,
                    "provider_generation": "dep-test123",
                    "state": "issued",
                }
                path.write_text(json.dumps(value), encoding="utf-8")
                os.chmod(path, 0o600)
                args = argparse.Namespace(lease=path)
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(FakeAPI.deleted, ["srv-test123"])
                result = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(result["state"], "absent")
                self.assertEqual(result["cleanup"], "verified")
                self.assertNotIn("profile", json.dumps(result).lower())
        finally:
            lease_cli.RenderAPI = original


if __name__ == "__main__":
    unittest.main()
