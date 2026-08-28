from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from torturer_provider import lease_cli
from torturer_provider.lease import LeaseCleanupError, LeaseJournalRecord, LeaseState, RenderLeaseJournal
from torturer_provider.render import HTTPResponse, RenderAPIError, RenderServiceHandle, RenderServiceRecord


class FakeAPI:
    deleted: list[str] = []
    options: list[dict[str, object]] = []

    def __init__(self, token: str, **options: object) -> None:
        self.token = token
        type(self).options.append(dict(options))

    def delete_service(self, service_id: str) -> bool:
        self.deleted.append(service_id)
        return True

    def exists(self, service_id: str) -> bool:
        return False

    def list_services(self, owner_id: str):
        return ()




class StaleAbsentAPI(FakeAPI):
    present: set[str] = set()

    def exists(self, service_id: str) -> bool:
        return service_id in self.present

    def delete_service(self, service_id: str) -> bool:
        self.deleted.append(service_id)
        self.present.discard(service_id)
        return True


class DeleteFailsOnceAPI(StaleAbsentAPI):
    delete_attempts = 0

    def delete_service(self, service_id: str) -> bool:
        self.deleted.append(service_id)
        if type(self).delete_attempts == 0:
            type(self).delete_attempts += 1
            raise RuntimeError("transient delete failure")
        self.present.discard(service_id)
        return True


class NamespaceStaleAPI(FakeAPI):
    records: list[RenderServiceRecord] = []

    def list_services(self, owner_id: str):
        return tuple(self.records)

    def delete_service(self, service_id: str) -> bool:
        self.deleted.append(service_id)
        self.records[:] = [record for record in self.records if record.service_id != service_id]
        return True

    def exists(self, service_id: str) -> bool:
        return any(record.service_id == service_id for record in self.records)


class FakeAcquireAPI:
    specs: list[object] = []
    options: list[dict[str, object]] = []

    def __init__(self, token: str, **options: object) -> None:
        self.token = token
        type(self).options.append(dict(options))
        self.deleted: list[str] = []

    def create_service(self, spec):
        self.specs.append(spec)
        if spec.name.endswith("-upload-sink"):
            return RenderServiceHandle("srv-sink123", "dep-sink123", spec.image_digest)
        return RenderServiceHandle("srv-acquire123", "dep-acquire123", spec.image_digest)

    def service(self, service_id):
        host = "sink.example.onrender.com" if service_id == "srv-sink123" else "lease.example.onrender.com"
        return {"suspended": "not_suspended", "serviceDetails": {"numInstances": 1, "url": "https://" + host}}

    def deploy(self, service_id, deploy_id):
        return {"status": "live"}

    def delete_service(self, service_id):
        self.deleted.append(service_id)
        return True

    def exists(self, service_id):
        return False

    def list_services(self, owner_id):
        return ()


class LostCreateTransport:
    def __init__(self, *, full_page: bool) -> None:
        self.full_page = full_page
        self.calls: list[tuple[str, str]] = []
        self.deleted: list[str] = []

    def request(self, method, path, payload, headers):
        self.calls.append((method, path))
        if method == "POST" and path == "/services":
            # Render accepted the request, but the acquisition client lost
            # the response before it received a service ID.
            raise RenderAPIError("TRANSPORT_ERROR")
        if method == "GET" and path.startswith("/services?"):
            record = {
                "id": "srv-orphan123",
                "name": "dobby-torturer-" + "d" * 32 + "-linux",
                "ownerId": "tea-owner123",
                "type": "web_service",
                "createdAt": "2026-08-23T00:00:00Z",
            }
            records = [record]
            if not self.full_page:
                records.append({**record, "id": "srv-stale123", "name": record["name"] + "-stale"})
            if self.full_page:
                return HTTPResponse(
                    200,
                    [{"service": record, "cursor": f"cursor-{index}"} for index in range(100)],
                )
            return HTTPResponse(200, [{"service": value} for value in records])
        if method == "DELETE":
            self.deleted.append(path)
            return HTTPResponse(204, {})
        raise AssertionError((method, path, payload))


def acquire_args(root: Path, *, platform: str = "linux") -> argparse.Namespace:
    digest = "sha256:" + "c" * 64
    sink_digest = "sha256:" + "d" * 64
    request_path = root / "request.json"
    request_path.write_text(json.dumps({
        "schema": 1,
        "kind": "dobbyvpn.render-lease-request",
        "run_id": "d" * 32,
        "platform": platform,
        "source_sha": "e" * 40,
        "image_digest": digest,
    }), encoding="utf-8")
    request_path.chmod(0o600)
    return argparse.Namespace(
        request=request_path,
        owner_id="tea-owner123",
        image_owner_id="tea-owner123",
        image_path="ghcr.io/dobbyvpn/outline@" + digest,
        expected_image_digest=digest,
        sink_image_owner_id="tea-owner123",
        sink_image_path="ghcr.io/dobbyvpn/sink@" + sink_digest,
        expected_sink_image_digest=sink_digest,
        profile_output=root / "profile.toml",
        upload_url_output=root / "upload-url.txt",
        lease_output=root / "lease.json",
        journal=root / "journal.json",
        listen_port=10000,
        region="oregon",
        timeout_seconds=5.0,
        poll_seconds=1.0,
        available_until_epoch=2_000_000_000,
    )


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

    def test_cleanup_api_uses_the_workflow_bounded_retry_contract(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAPI
        FakeAPI.options = []
        try:
            lease_cli._cleanup_api(argparse.Namespace(
                api_timeout_seconds=5,
                api_retry_attempts=2,
                api_retry_backoff_seconds=0.5,
            ))
        finally:
            lease_cli.RenderAPI = original
        self.assertEqual(FakeAPI.options, [{
            "timeout_seconds": 5.0,
            "retry_attempts": 2,
            "retry_backoff_seconds": 0.5,
            "service_list_max_pages": 1,
        }])

    def test_acquire_lost_create_recovery_uses_one_page_cleanup_api(self) -> None:
        original = lease_cli.RenderAPI
        transports: list[LostCreateTransport] = []
        options: list[dict[str, object]] = []

        def provider(token: str, **kwargs: object):
            options.append(dict(kwargs))
            transport = LostCreateTransport(full_page=True)
            transports.append(transport)
            return original(token or "fixture-token", transport=transport, **kwargs)

        lease_cli.RenderAPI = provider
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-lost-create-page-bound-") as directory:
                with self.assertRaises(LeaseCleanupError):
                    lease_cli.acquire(acquire_args(Path(directory)))
        finally:
            lease_cli.RenderAPI = original

        self.assertEqual(options, [{}, {
            "timeout_seconds": 5.0,
            "retry_attempts": 2,
            "retry_backoff_seconds": 0.5,
            "service_list_max_pages": 1,
        }])
        self.assertEqual(transports[0].calls, [("POST", "/services")])
        cleanup_transport = transports[1]
        list_paths = [path for method, path in cleanup_transport.calls if method == "GET"]
        self.assertEqual(len(list_paths), 2)
        self.assertTrue(all("cursor=" not in path for path in list_paths))
        self.assertEqual(cleanup_transport.deleted, [])

    def test_acquire_lost_create_recovery_refuses_ambiguous_candidates_without_delete(self) -> None:
        original = lease_cli.RenderAPI
        transports: list[LostCreateTransport] = []

        def provider(token: str, **kwargs: object):
            transport = LostCreateTransport(full_page=False)
            transports.append(transport)
            return original(token or "fixture-token", transport=transport, **kwargs)

        lease_cli.RenderAPI = provider
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-lost-create-ambiguous-") as directory:
                with self.assertRaises(LeaseCleanupError):
                    lease_cli.acquire(acquire_args(Path(directory)))
        finally:
            lease_cli.RenderAPI = original

        cleanup_transport = transports[1]
        self.assertGreaterEqual(
            sum(method == "GET" for method, _path in cleanup_transport.calls),
            2,
        )
        self.assertEqual(cleanup_transport.deleted, [])
        self.assertTrue(all(method != "DELETE" for method, _path in cleanup_transport.calls))

    def test_acquire_writes_owner_only_profile_and_safe_bundle(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAcquireAPI
        FakeAcquireAPI.specs = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-acquire-") as directory:
                root = Path(directory)
                digest = "sha256:" + "c" * 64
                sink_digest = "sha256:" + "d" * 64
                request = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": "d" * 32,
                    "platform": "macos",
                    "source_sha": "e" * 40,
                    "image_digest": digest,
                }
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request), encoding="utf-8")
                os.chmod(request_path, 0o600)
                args = argparse.Namespace(
                    request=request_path, owner_id="tea-owner123", image_owner_id="tea-owner123",
                    image_path="ghcr.io/dobbyvpn/outline@" + digest, expected_image_digest=digest,
                    sink_image_owner_id="tea-owner123",
                    sink_image_path="ghcr.io/dobbyvpn/sink@" + sink_digest,
                    expected_sink_image_digest=sink_digest,
                    profile_output=root / "profile.toml", lease_output=root / "lease.json",
                    upload_url_output=root / "upload-url.txt", journal=root / "journal.json",
                    listen_port=10000, region="oregon",
                    timeout_seconds=5.0, poll_seconds=1.0,
                    available_until_epoch=2_000_000_000,
                )
                self.assertEqual(lease_cli.acquire(args), 0)
                self.assertEqual((root / "profile.toml").stat().st_mode & 0o777, 0o600)
                profile = (root / "profile.toml").read_text(encoding="utf-8")
                self.assertIn("[[Outline]]", profile)
                self.assertIn("lease.example.onrender.com", profile)
                lease = json.loads((root / "lease.json").read_text(encoding="utf-8"))
                self.assertEqual(lease["schema"], 2)
                self.assertEqual(lease["state"], "issued")
                self.assertEqual(lease["available_until_epoch"], 2_000_000_000)
                self.assertEqual(
                    {service["role"] for service in lease["services"]},
                    {"outline", "upload-sink"},
                )
                self.assertNotIn("lease.example.onrender.com", json.dumps(lease))
                self.assertFalse(hasattr(FakeAcquireAPI.specs[0], "docker_command"))
                self.assertRegex(
                    (root / "upload-url.txt").read_text(encoding="utf-8").strip(),
                    r"^https://sink\.example\.onrender\.com/upload/[0-9a-f]{32}$",
                )
        finally:
            lease_cli.RenderAPI = original

    def test_acquire_emits_schema2_bundle_for_every_hosted_platform(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAcquireAPI
        FakeAcquireAPI.specs = []
        try:
            for platform in ("linux", "windows", "macos", "android"):
                with self.subTest(platform=platform), tempfile.TemporaryDirectory(
                    prefix=f"lease-cli-{platform}-bundle-"
                ) as directory:
                    root = Path(directory)
                    outline_digest = "sha256:" + "c" * 64
                    sink_digest = "sha256:" + "d" * 64
                    request_path = root / "request.json"
                    request_path.write_text(json.dumps({
                        "schema": 1,
                        "kind": "dobbyvpn.render-lease-request",
                        "run_id": "d" * 32,
                        "platform": platform,
                        "source_sha": "e" * 40,
                        "image_digest": outline_digest,
                    }), encoding="utf-8")
                    request_path.chmod(0o600)
                    args = argparse.Namespace(
                        request=request_path, owner_id="tea-owner123",
                        image_owner_id="tea-owner123",
                        image_path="ghcr.io/dobbyvpn/outline@" + outline_digest,
                        expected_image_digest=outline_digest,
                        sink_image_owner_id="tea-owner123",
                        sink_image_path="ghcr.io/dobbyvpn/sink@" + sink_digest,
                        expected_sink_image_digest=sink_digest,
                        profile_output=root / "profile.toml",
                        upload_url_output=root / "upload-url.txt",
                        lease_output=root / "lease.json",
                        journal=root / "journal.json", listen_port=10000,
                        region="oregon", timeout_seconds=5.0, poll_seconds=1.0,
                        available_until_epoch=2_000_000_000,
                    )
                    self.assertEqual(lease_cli.acquire(args), 0)
                    lease = json.loads((root / "lease.json").read_text(encoding="utf-8"))
                    self.assertEqual(lease["platform"], platform)
                    self.assertEqual(lease["schema"], 2)
                    self.assertEqual(lease["available_until_epoch"], 2_000_000_000)
                    self.assertEqual(
                        {service["role"] for service in lease["services"]},
                        {"outline", "upload-sink"},
                    )
        finally:
            lease_cli.RenderAPI = original

    def test_owner_output_rejects_symlinked_parent_and_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-owner-output-") as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            outside_file = outside / "secret.txt"
            outside_file.write_text("unchanged", encoding="utf-8")
            symlink_parent = root / "symlink-parent"
            symlink_parent.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "owner output directory"):
                lease_cli._owner_text(symlink_parent / "output.txt", "not written")
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged")

            destination = root / "destination.txt"
            destination.symlink_to(outside_file)
            with self.assertRaisesRegex(ValueError, "owner output path"):
                lease_cli._owner_text(destination, "not written")
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged")

    def test_owner_output_uses_exclusive_random_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-owner-temp-") as directory:
            root = Path(directory)
            outside = root / "outside.txt"
            outside.write_text("unchanged", encoding="utf-8")
            temporary_name = ".output." + "a" * 32 + ".tmp"
            (root / temporary_name).symlink_to(outside)
            with mock.patch.object(lease_cli.secrets, "token_hex", return_value="a" * 32):
                with self.assertRaises(FileExistsError):
                    lease_cli._owner_text(root / "output", "not written")
            self.assertTrue((root / temporary_name).is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    def test_owner_output_is_atomic_owner_only_and_durable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-owner-durable-") as directory:
            path = Path(directory) / "output"
            lease_cli._owner_text(path, "secret\n")
            self.assertEqual(path.read_text(encoding="utf-8"), "secret\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(any(path.parent.glob(".output.*.tmp")))

    def test_linux_acquire_writes_two_safe_service_identities_and_private_upload_url(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAcquireAPI
        FakeAcquireAPI.specs = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-linux-bundle-") as directory:
                root = Path(directory)
                outline_digest = "sha256:" + "c" * 64
                sink_digest = "sha256:" + "d" * 64
                request_path = root / "request.json"
                request_path.write_text(json.dumps({
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": "d" * 32,
                    "platform": "linux",
                    "source_sha": "e" * 40,
                    "image_digest": outline_digest,
                }), encoding="utf-8")
                request_path.chmod(0o600)
                args = argparse.Namespace(
                    request=request_path,
                    owner_id="tea-owner123",
                    image_owner_id="tea-owner123",
                    image_path="ghcr.io/dobbyvpn/outline@" + outline_digest,
                    expected_image_digest=outline_digest,
                    sink_image_owner_id="tea-owner123",
                    sink_image_path="ghcr.io/dobbyvpn/sink@" + sink_digest,
                    expected_sink_image_digest=sink_digest,
                    profile_output=root / "profile.toml",
                    upload_url_output=root / "upload-url.txt",
                    lease_output=root / "lease.json",
                    journal=root / "journal.json",
                    listen_port=10000,
                    region="oregon",
                    timeout_seconds=5.0,
                    poll_seconds=1.0,
                    available_until_epoch=2_000_000_000,
                )
                self.assertEqual(lease_cli.acquire(args), 0)
                lease = json.loads((root / "lease.json").read_text(encoding="utf-8"))
                self.assertEqual(lease["schema"], 2)
                self.assertEqual({service["role"] for service in lease["services"]}, {"outline", "upload-sink"})
                self.assertEqual(
                    {service["image_digest"] for service in lease["services"]},
                    {outline_digest, sink_digest},
                )
                self.assertNotIn("onrender.com", json.dumps(lease))
                upload_url = (root / "upload-url.txt").read_text(encoding="utf-8").strip()
                self.assertRegex(upload_url, r"^https://sink\.example\.onrender\.com/upload/[0-9a-f]{32}$")
                self.assertEqual((root / "upload-url.txt").stat().st_mode & 0o777, 0o600)
                self.assertEqual(FakeAcquireAPI.specs[1].health_check_path, "/healthz")
                self.assertFalse(hasattr(FakeAcquireAPI.specs[1], "docker_command"))
                self.assertRegex(FakeAcquireAPI.specs[1].secret_files[0][1], r"^/upload/[0-9a-f]{32}$")
        finally:
            lease_cli.RenderAPI = original

    def test_upload_url_rejects_non_origin_service_urls(self) -> None:
        path = "/upload/" + "a" * 32
        self.assertEqual(
            lease_cli._upload_url("https://sink.example.onrender.com/", path),
            "https://sink.example.onrender.com" + path,
        )
        for service_url in (
            "http://sink.example.onrender.com",
            "https://user:password@sink.example.onrender.com",
            "https://sink.example.onrender.com/base",
            "https://sink.example.onrender.com?token=private",
            "https://sink.example.onrender.com/#fragment",
        ):
            with self.assertRaisesRegex(ValueError, "upload service URL"):
                lease_cli._upload_url(service_url, path)

    def test_cleanup_repairs_stale_absent_schema1_lease(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = StaleAbsentAPI
        StaleAbsentAPI.deleted = []
        StaleAbsentAPI.present = {"srv-stale123"}
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-stale-schema1-") as directory:
                root = Path(directory)
                value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "a" * 32,
                    "platform": "linux",
                    "source_sha": "b" * 40,
                    "service_id": "srv-stale123",
                    "image_digest": "sha256:" + "c" * 64,
                    "provider_generation": "dep-stale123",
                    "state": "absent",
                    "cleanup": "verified",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path)
                journal.append(LeaseJournalRecord(
                    run_id=value["run_id"],
                    service_id=value["service_id"],
                    image_digest=value["image_digest"],
                    state=LeaseState.ABSENT,
                    timestamp="2026-08-23T00:00:00Z",
                    cleanup_result="verified",
                ))
                args = argparse.Namespace(
                    lease=lease_path, journal=journal_path, request=None, owner_id="tea-owner123",
                )
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(StaleAbsentAPI.deleted, ["srv-stale123"])
                self.assertFalse(StaleAbsentAPI.present)
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(StaleAbsentAPI.deleted, ["srv-stale123"])
                latest = RenderLeaseJournal(journal_path).records()[-1]
                self.assertEqual(latest.state, LeaseState.ABSENT)
                self.assertEqual(latest.cleanup_result, "verified")
        finally:
            lease_cli.RenderAPI = original

    def test_cleanup_retries_after_stale_absence_repair_failure(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = DeleteFailsOnceAPI
        DeleteFailsOnceAPI.deleted = []
        DeleteFailsOnceAPI.present = {"srv-retry123"}
        DeleteFailsOnceAPI.delete_attempts = 0
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-stale-retry-") as directory:
                root = Path(directory)
                value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "c" * 32,
                    "platform": "linux",
                    "source_sha": "d" * 40,
                    "service_id": "srv-retry123",
                    "image_digest": "sha256:" + "e" * 64,
                    "provider_generation": "dep-retry123",
                    "state": "absent",
                    "cleanup": "verified",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path)
                journal.append(LeaseJournalRecord(
                    run_id=value["run_id"],
                    service_id=value["service_id"],
                    image_digest=value["image_digest"],
                    state=LeaseState.ABSENT,
                    timestamp="2026-08-23T00:00:00Z",
                    cleanup_result="verified",
                ))
                args = argparse.Namespace(
                    lease=lease_path, journal=journal_path, request=None, owner_id="tea-owner123",
                )
                with self.assertRaises(RenderAPIError):
                    lease_cli.cleanup(args)
                self.assertEqual(
                    RenderLeaseJournal(journal_path).records()[-1].state,
                    LeaseState.DELETING,
                )
                self.assertEqual(lease_cli.cleanup(args), 0)
                latest = RenderLeaseJournal(journal_path).records()[-1]
                self.assertEqual(latest.state, LeaseState.ABSENT)
                self.assertEqual(latest.cleanup_result, "verified")
        finally:
            lease_cli.RenderAPI = original

    def test_cleanup_repairs_stale_absent_schema2_bundle(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = StaleAbsentAPI
        StaleAbsentAPI.deleted = []
        StaleAbsentAPI.present = {"srv-stale-sink123"}
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-stale-schema2-") as directory:
                root = Path(directory)
                outline_digest = "sha256:" + "c" * 64
                sink_digest = "sha256:" + "d" * 64
                services = [
                    {
                        "role": "outline",
                        "service_id": "srv-stale-outline123",
                        "image_digest": outline_digest,
                        "provider_generation": "dep-stale-outline123",
                    },
                    {
                        "role": "upload-sink",
                        "service_id": "srv-stale-sink123",
                        "image_digest": sink_digest,
                        "provider_generation": "dep-stale-sink123",
                    },
                ]
                value = {
                    "schema": 2,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "e" * 32,
                    "platform": "android",
                    "source_sha": "f" * 40,
                    "available_until_epoch": 2_000_000_000,
                    "services": services,
                    "state": "absent",
                    "cleanup": "verified",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path, schema=2)
                for service in services:
                    journal.append(LeaseJournalRecord(
                        run_id=value["run_id"],
                        service_id=service["service_id"],
                        image_digest=service["image_digest"],
                        state=LeaseState.ABSENT,
                        timestamp="2026-08-23T00:00:00Z",
                        cleanup_result="verified",
                        role=service["role"],
                    ))
                args = argparse.Namespace(
                    lease=lease_path, journal=journal_path, request=None, owner_id="tea-owner123",
                )
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(StaleAbsentAPI.deleted, ["srv-stale-sink123"])
                self.assertFalse(StaleAbsentAPI.present)
                latest = {record.role: record for record in RenderLeaseJournal(journal_path).records()}
                self.assertEqual(set(latest), {"outline", "upload-sink"})
                self.assertTrue(all(record.state is LeaseState.ABSENT for record in latest.values()))
                self.assertTrue(all(record.cleanup_result == "verified" for record in latest.values()))
        finally:
            lease_cli.RenderAPI = original

    def test_journal_only_cleanup_repairs_stale_absent_record(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = StaleAbsentAPI
        StaleAbsentAPI.deleted = []
        StaleAbsentAPI.present = {"srv-journal-stale123"}
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-stale-journal-") as directory:
                root = Path(directory)
                request_value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": "1" * 32,
                    "platform": "macos",
                    "source_sha": "2" * 40,
                    "image_digest": "sha256:" + "3" * 64,
                }
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request_value), encoding="utf-8")
                request_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path)
                journal.append(LeaseJournalRecord(
                    run_id=request_value["run_id"],
                    service_id="srv-journal-stale123",
                    image_digest=request_value["image_digest"],
                    state=LeaseState.ABSENT,
                    timestamp="2026-08-23T00:00:00Z",
                    cleanup_result="verified",
                ))
                args = argparse.Namespace(
                    lease=None,
                    journal=journal_path,
                    request=request_path,
                    owner_id="tea-owner123",
                )
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(StaleAbsentAPI.deleted, ["srv-journal-stale123"])
                self.assertFalse(StaleAbsentAPI.present)
        finally:
            lease_cli.RenderAPI = original

    def test_journal_only_cleanup_repairs_stale_absent_namespace(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = NamespaceStaleAPI
        NamespaceStaleAPI.deleted = []
        run_id = "2" * 32
        NamespaceStaleAPI.records = [
            RenderServiceRecord(
                service_id="srv-namespace-stale123",
                name=f"dobby-torturer-{run_id}-linux",
                owner_id="tea-owner123",
                service_type="web_service",
                created_at="2026-08-23T00:00:00Z",
            )
        ]
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-stale-namespace-") as directory:
                root = Path(directory)
                request_value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": run_id,
                    "platform": "linux",
                    "source_sha": "3" * 40,
                    "image_digest": "sha256:" + "4" * 64,
                }
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request_value), encoding="utf-8")
                request_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path, schema=2)
                for role, digest in (
                    ("outline", request_value["image_digest"]),
                    ("upload-sink", "sha256:" + "5" * 64),
                ):
                    journal.append(LeaseJournalRecord(
                        run_id=run_id,
                        service_id=None,
                        image_digest=digest,
                        state=LeaseState.ABSENT,
                        timestamp="2026-08-23T00:00:00Z",
                        cleanup_result="verified-namespace",
                        role=role,
                    ))
                args = argparse.Namespace(
                    lease=None,
                    journal=journal_path,
                    request=request_path,
                    owner_id="tea-owner123",
                )
                candidate_bounds: list[int | None] = []
                original_reap = lease_cli.RenderReaper.reap_tagged

                def bounded_reap(reaper, *reap_args, **reap_kwargs):
                    candidate_bounds.append(reap_kwargs.get("max_candidates"))
                    return original_reap(reaper, *reap_args, **reap_kwargs)

                with mock.patch.object(
                    lease_cli.RenderReaper,
                    "reap_tagged",
                    new=bounded_reap,
                ):
                    self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(candidate_bounds, [2])
                self.assertEqual(NamespaceStaleAPI.deleted, ["srv-namespace-stale123"])
                self.assertEqual(NamespaceStaleAPI.records, [])
        finally:
            lease_cli.RenderAPI = original

    def test_journal_only_absent_retry_rejects_an_extra_tagged_service(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = NamespaceStaleAPI
        NamespaceStaleAPI.deleted = []
        run_id = "3" * 32
        NamespaceStaleAPI.records = [
            RenderServiceRecord(
                service_id="srv-extra123",
                name=f"dobby-torturer-{run_id}-linux",
                owner_id="tea-owner123",
                service_type="web_service",
                created_at="2026-08-23T00:00:00Z",
            )
        ]
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-retry-extra-namespace-") as directory:
                root = Path(directory)
                request_value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease-request",
                    "run_id": run_id,
                    "platform": "linux",
                    "source_sha": "4" * 40,
                    "image_digest": "sha256:" + "5" * 64,
                }
                request_path = root / "request.json"
                request_path.write_text(json.dumps(request_value), encoding="utf-8")
                request_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path)
                journal.append(LeaseJournalRecord(
                    run_id=run_id,
                    service_id="srv-known123",
                    image_digest=request_value["image_digest"],
                    state=LeaseState.ABSENT,
                    timestamp="2026-08-23T00:00:00Z",
                    cleanup_result="verified",
                ))
                args = argparse.Namespace(
                    lease=None,
                    journal=journal_path,
                    request=request_path,
                    owner_id="tea-owner123",
                )
                with self.assertRaisesRegex(RenderAPIError, "DELETE_NOT_VERIFIED"):
                    lease_cli.cleanup(args)
                self.assertEqual(NamespaceStaleAPI.deleted, [])
                self.assertEqual(
                    [record.service_id for record in NamespaceStaleAPI.records],
                    ["srv-extra123"],
                )
        finally:
            lease_cli.RenderAPI = original

    def test_schema2_lease_record_rejects_duplicate_service_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-duplicate-record-") as directory:
            path = Path(directory) / "lease.json"
            digest = "sha256:" + "a" * 64
            value = {
                "schema": 2,
                "kind": "dobbyvpn.render-lease",
                "run_id": "7" * 32,
                "platform": "linux",
                "source_sha": "8" * 40,
                "available_until_epoch": 2_000_000_000,
                "services": [
                    {
                        "role": "outline",
                        "service_id": "srv-duplicate123",
                        "image_digest": digest,
                        "provider_generation": "dep-outline123",
                    },
                    {
                        "role": "upload-sink",
                        "service_id": "srv-duplicate123",
                        "image_digest": "sha256:" + "b" * 64,
                        "provider_generation": "dep-sink123",
                    },
                ],
                "state": "issued",
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "service IDs must be distinct"):
                lease_cli._lease_record(path)

    def test_schema2_journal_rejects_duplicate_service_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-duplicate-journal-") as directory:
            root = Path(directory)
            request_value = {
                "schema": 1,
                "kind": "dobbyvpn.render-lease-request",
                "run_id": "9" * 32,
                "platform": "android",
                "source_sha": "a" * 40,
                "image_digest": "sha256:" + "b" * 64,
            }
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request_value), encoding="utf-8")
            request_path.chmod(0o600)
            journal_path = root / "journal.json"
            journal = RenderLeaseJournal(journal_path, schema=2)
            for role, digest in (
                ("outline", request_value["image_digest"]),
                ("upload-sink", "sha256:" + "c" * 64),
            ):
                journal.append(LeaseJournalRecord(
                    run_id=request_value["run_id"],
                    service_id="srv-duplicate123",
                    image_digest=digest,
                    state=LeaseState.ABSENT,
                    timestamp="2026-08-23T00:00:00Z",
                    cleanup_result="verified",
                    role=role,
                ))
            with self.assertRaisesRegex(ValueError, "service IDs must be distinct"):
                lease_cli._cleanup_journal(journal_path, lease_cli.RenderLeaseRequest.from_file(request_path), None)

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
                args = argparse.Namespace(lease=path, journal=journal_path, request=None, owner_id="tea-owner123")
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

    def test_linux_bundle_cleanup_deletes_and_verifies_both_bound_service_ids(self) -> None:
        original = lease_cli.RenderAPI
        lease_cli.RenderAPI = FakeAPI
        FakeAPI.deleted = []
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-linux-cleanup-") as directory:
                root = Path(directory)
                outline_digest = "sha256:" + "b" * 64
                sink_digest = "sha256:" + "c" * 64
                value = {
                    "schema": 2,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "a" * 32,
                    "platform": "linux",
                    "source_sha": "d" * 40,
                    "available_until_epoch": 2_000_000_000,
                    "services": [
                        {"role": "outline", "service_id": "srv-outline123", "image_digest": outline_digest, "provider_generation": "dep-outline123"},
                        {"role": "upload-sink", "service_id": "srv-sink123", "image_digest": sink_digest, "provider_generation": "dep-sink123"},
                    ],
                    "state": "testing",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path, schema=2)
                for service in value["services"]:
                    journal.append(LeaseJournalRecord(
                        run_id=value["run_id"],
                        service_id=service["service_id"],
                        image_digest=service["image_digest"],
                        state=LeaseState.TESTING,
                        timestamp="2026-08-23T00:00:00Z",
                        role=service["role"],
                    ))
                args = argparse.Namespace(lease=lease_path, journal=journal_path, request=None, owner_id="tea-owner123")
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(lease_cli.cleanup(args), 0)
                self.assertEqual(FakeAPI.deleted, ["srv-outline123", "srv-sink123"])
                result = json.loads(lease_path.read_text(encoding="utf-8"))
                self.assertEqual(result["state"], "absent")
                self.assertEqual(result["cleanup"], "verified")
                records = RenderLeaseJournal(journal_path).records()
                latest = {record.role: record for record in records}
                self.assertEqual(set(latest), {"outline", "upload-sink"})
                self.assertTrue(all(record.state is LeaseState.ABSENT for record in latest.values()))
                self.assertTrue(all(record.cleanup_result == "verified" for record in latest.values()))
                self.assertEqual({record.image_digest for record in latest.values()}, {outline_digest, sink_digest})
        finally:
            lease_cli.RenderAPI = original

    def test_begin_testing_rejects_legacy_schema1_lease(self) -> None:
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
            with self.assertRaisesRegex(ValueError, "cleanup only"):
                lease_cli.begin_testing(args)
            self.assertEqual(
                [record.state for record in RenderLeaseJournal(journal_path).records()],
                [LeaseState.ISSUED],
            )
            issued = json.loads(lease_path.read_text(encoding="utf-8"))
            self.assertEqual(issued["state"], "issued")
            self.assertNotIn("profile", json.dumps(issued).lower())

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
                    "state": "testing",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                journal = RenderLeaseJournal(journal_path)
                journal.append(LeaseJournalRecord(
                    run_id=str(value["run_id"]),
                    service_id=str(value["service_id"]),
                    image_digest=str(value["image_digest"]),
                    state=LeaseState.TESTING,
                    timestamp="2026-08-23T00:00:00Z",
                ))
                self.assertEqual(
                    lease_cli.cleanup(
                        argparse.Namespace(
                            lease=lease_path,
                            journal=journal_path,
                            request=None,
                            owner_id="tea-owner123",
                        )
                    ),
                    0,
                )
                self.assertEqual(FakeAPI.deleted, ["srv-testingcleanup123"])
                self.assertEqual(
                    [record.state for record in RenderLeaseJournal(journal_path).records()],
                    [
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
            with self.assertRaisesRegex(ValueError, "service identity mismatch"):
                lease_cli.cleanup(
                    argparse.Namespace(
                        lease=lease_path,
                        journal=journal_path,
                        request=None,
                        owner_id=None,
                    )
                )

    def test_linux_cleanup_rejects_journal_missing_the_sink_role(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-linux-missing-role-") as directory:
            root = Path(directory)
            outline_digest = "sha256:" + "a" * 64
            sink_digest = "sha256:" + "b" * 64
            value = {
                "schema": 2,
                "kind": "dobbyvpn.render-lease",
                "run_id": "8" * 32,
                "platform": "linux",
                "source_sha": "9" * 40,
                "available_until_epoch": 2_000_000_000,
                "services": [
                    {
                        "role": "outline",
                        "service_id": "srv-outline123",
                        "image_digest": outline_digest,
                        "provider_generation": "dep-outline123",
                    },
                    {
                        "role": "upload-sink",
                        "service_id": "srv-sink123",
                        "image_digest": sink_digest,
                        "provider_generation": "dep-sink123",
                    },
                ],
                "state": "testing",
            }
            lease_path = root / "lease.json"
            lease_path.write_text(json.dumps(value), encoding="utf-8")
            lease_path.chmod(0o600)
            journal_path = root / "journal.json"
            journal = RenderLeaseJournal(journal_path, schema=2)
            journal.append(LeaseJournalRecord(
                run_id=value["run_id"],
                service_id="srv-outline123",
                image_digest=outline_digest,
                state=LeaseState.TESTING,
                timestamp="2026-08-23T00:00:00Z",
                role="outline",
            ))
            with self.assertRaisesRegex(ValueError, "missing a service role"):
                lease_cli.cleanup(argparse.Namespace(
                    lease=lease_path,
                    journal=journal_path,
                    request=None,
                    owner_id=None,
                ))

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

    def test_cleanup_recovery_rejects_outline_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-recovery-digest-") as directory:
            root = Path(directory)
            request_value = {
                "schema": 1,
                "kind": "dobbyvpn.render-lease-request",
                "run_id": "f" * 32,
                "platform": "linux",
                "source_sha": "a" * 40,
                "image_digest": "sha256:" + "a" * 64,
            }
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request_value), encoding="utf-8")
            request_path.chmod(0o600)
            journal_path = root / "journal.json"
            journal = RenderLeaseJournal(journal_path, schema=2)
            journal.append(LeaseJournalRecord(
                run_id=request_value["run_id"],
                service_id="srv-outline123",
                image_digest="sha256:" + "b" * 64,
                state=LeaseState.CREATING,
                timestamp="2026-08-23T00:00:00Z",
                role="outline",
            ))
            journal.append(LeaseJournalRecord(
                run_id=request_value["run_id"],
                service_id="srv-sink123",
                image_digest="sha256:" + "c" * 64,
                state=LeaseState.CREATING,
                timestamp="2026-08-23T00:00:00Z",
                role="upload-sink",
            ))
            with self.assertRaisesRegex(ValueError, "request image identity mismatch"):
                lease_cli.cleanup(argparse.Namespace(
                    lease=None,
                    journal=journal_path,
                    request=request_path,
                    owner_id="tea-owner123",
                ))

    def test_cli_hides_secret_text_from_generic_transport_failure(self) -> None:
        original = lease_cli.RenderAPI
        secret = "token=render-secret profile=private-profile endpoint=https://private.example"

        class SecretTransport:
            def request(self, method, path, payload, headers):
                raise RuntimeError(secret)

        def provider(token: str, **_options: object):
            return original("fixture-token", transport=SecretTransport())

        lease_cli.RenderAPI = provider
        try:
            with tempfile.TemporaryDirectory(prefix="lease-cli-secret-transport-") as directory:
                root = Path(directory)
                value = {
                    "schema": 1,
                    "kind": "dobbyvpn.render-lease",
                    "run_id": "4" * 32,
                    "platform": "linux",
                    "source_sha": "5" * 40,
                    "service_id": "srv-secrettransport123",
                    "image_digest": "sha256:" + "6" * 64,
                    "provider_generation": "dep-secrettransport123",
                    "state": "issued",
                }
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                lease_path.chmod(0o600)
                journal_path = root / "journal.json"
                self._write_issued_journal(journal_path, value)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = lease_cli.main([
                        "cleanup",
                        "--lease", str(lease_path),
                        "--journal", str(journal_path),
                    ])
                self.assertEqual(result, 1)
                self.assertIn("render-lease failed code=TRANSPORT_ERROR", stderr.getvalue())
                self.assertNotIn(secret, stderr.getvalue())
        finally:
            lease_cli.RenderAPI = original

    def test_acquire_cli_persists_a_strict_safe_failure_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lease-cli-safe-result-") as directory:
            root = Path(directory)
            safe_result = root / "acquire-result.json"
            stderr = io.StringIO()
            with mock.patch.object(
                lease_cli,
                "acquire",
                side_effect=RenderAPIError("DEPLOY_FAILED"),
            ), contextlib.redirect_stderr(stderr):
                result = lease_cli.main([
                    "acquire",
                    "--request", str(root / "request.json"),
                    "--owner-id", "tea-owner123",
                    "--image-owner-id", "tea-owner123",
                    "--image-path", "ghcr.io/dobbyvpn/outline@sha256:" + "a" * 64,
                    "--expected-image-digest", "sha256:" + "a" * 64,
                    "--profile-output", str(root / "profile.toml"),
                    "--lease-output", str(root / "lease.json"),
                    "--journal", str(root / "journal.json"),
                    "--available-until-epoch", "2000000000",
                    "--safe-result-output", str(safe_result),
                ])
            self.assertEqual(result, 1)
            self.assertIn("render-lease failed code=DEPLOY_FAILED", stderr.getvalue())
            value = json.loads(safe_result.read_text(encoding="utf-8"))
            self.assertEqual(value, {
                "schema": 1,
                "kind": "dobbyvpn.render-lease-command-result",
                "command": "acquire",
                "status": "failed",
                "code": "DEPLOY_FAILED",
            })
            self.assertEqual(safe_result.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
