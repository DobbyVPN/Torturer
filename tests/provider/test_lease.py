from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from torturer_provider.lease import (  # noqa: E402
    LeaseState,
    LeaseStateError,
    RenderLease,
    RenderLeaseDescriptor,
    RenderLeaseJournal,
)
from torturer_provider.render import (  # noqa: E402
    RenderAPIError,
    RenderServiceHandle,
    RenderServiceRecord,
    RenderServiceSpec,
)


IMAGE_DIGEST = "sha256:" + "a" * 64
RUN_ID = "a" * 32


class FakeLeaseAPI:
    def __init__(self, *, failed_deploy: bool = False, fail_create: bool = False) -> None:
        self.failed_deploy = failed_deploy
        self.fail_create = fail_create
        self.created = False
        self.deleted = False
        self.delete_calls: list[str] = []
        self.records: tuple[RenderServiceRecord, ...] = ()

    def create_service(self, spec: RenderServiceSpec) -> RenderServiceHandle:
        if self.fail_create:
            raise RenderAPIError("INVALID_SERVICE_ID")
        self.created = True
        return RenderServiceHandle("srv-lease123", "dep-lease123", spec.image_digest)

    def service(self, service_id: str) -> dict[str, object]:
        if self.deleted:
            raise RenderAPIError("UNEXPECTED_STATUS", 404)
        return {
            "suspended": "not_suspended",
            "serviceDetails": {"numInstances": 1, "url": "https://dobby-test.onrender.com"},
        }

    def deploy(self, service_id: str, deploy_id: str) -> dict[str, object]:
        return {"status": "build_failed" if self.failed_deploy else "live"}

    def delete_service(self, service_id: str) -> bool:
        self.delete_calls.append(service_id)
        self.deleted = True
        return True

    def exists(self, service_id: str) -> bool:
        return not self.deleted

    def list_services(self, owner_id: str) -> tuple[RenderServiceRecord, ...]:
        return self.records


def make_lease(api: FakeLeaseAPI, temporary: tempfile.TemporaryDirectory) -> RenderLease:
    descriptor = RenderLeaseDescriptor(
        run_id=RUN_ID,
        platform="linux",
        service_name=f"dobby-torturer-{RUN_ID}-linux",
        image_digest=IMAGE_DIGEST,
    )
    spec = RenderServiceSpec(
        owner_id="tea-test123",
        name=descriptor.service_name,
        image_owner_id="tea-test123",
        image_path="ghcr.io/dobbyvpn/outline-ss-server@" + IMAGE_DIGEST,
        image_digest=IMAGE_DIGEST,
    )
    journal = RenderLeaseJournal(Path(temporary.name) / "lease.json")
    return RenderLease(
        api,
        spec,
        descriptor,
        journal,
        wall_clock=lambda: 1_700_000_000.0,
    )


class RenderLeaseTests(unittest.TestCase):
    def test_full_lifecycle_is_journaled_without_profile_or_endpoint_data(self) -> None:
        api = FakeLeaseAPI()
        with tempfile.TemporaryDirectory(prefix="render-lease-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                ready = lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertEqual(ready.url, "https://dobby-test.onrender.com")
                self.assertIs(lease.state, LeaseState.HEALTHY)
                lease.mark_issued()
                lease.begin_testing()
                lease.cleanup()
                self.assertIs(lease.state, LeaseState.ABSENT)
                self.assertEqual(api.delete_calls, ["srv-lease123"])

                records = lease.journal.records()
                self.assertEqual(
                    [record.state for record in records],
                    [
                        LeaseState.ABSENT,
                        LeaseState.CREATING,
                        LeaseState.CREATING,
                        LeaseState.HEALTHY,
                        LeaseState.ISSUED,
                        LeaseState.TESTING,
                        LeaseState.DELETING,
                        LeaseState.ABSENT,
                    ],
                )
                document = json.dumps([record.to_json_object() for record in records], sort_keys=True)
                self.assertNotIn("dobby-test.onrender.com", document)
                self.assertNotIn("fixture-token", document)
                self.assertNotIn("profile", document.lower())
                self.assertEqual(lease.journal.path.stat().st_mode & 0o777, 0o600)
            finally:
                holder.cleanup()

    def test_failed_deploy_is_cleaned_and_verified_before_error_returns(self) -> None:
        api = FakeLeaseAPI(failed_deploy=True)
        with tempfile.TemporaryDirectory(prefix="render-lease-failure-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaisesRegex(RenderAPIError, "DEPLOY_FAILED"):
                    lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertIs(lease.state, LeaseState.ABSENT)
                self.assertEqual(api.delete_calls, ["srv-lease123"])
                self.assertEqual(lease.journal.records()[-1].cleanup_result, "verified")
            finally:
                holder.cleanup()

    def test_create_without_an_exact_service_id_fails_closed(self) -> None:
        api = FakeLeaseAPI(fail_create=True)
        with tempfile.TemporaryDirectory(prefix="render-lease-no-id-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaisesRegex(RenderAPIError, "INVALID_SERVICE_ID"):
                    lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertIs(lease.state, LeaseState.ABSENT)
                self.assertEqual(lease.journal.records()[-1].cleanup_result, "verified-namespace")
            finally:
                holder.cleanup()

    def test_lost_create_response_reaps_only_this_run_namespace(self) -> None:
        api = FakeLeaseAPI(fail_create=True)
        old = datetime.fromtimestamp(time.time() - 5, timezone.utc).isoformat().replace("+00:00", "Z")
        api.records = (
            RenderServiceRecord(
                "srv-orphan123",
                f"dobby-torturer-{RUN_ID}-linux",
                "tea-test123",
                "web_service",
                old,
            ),
            RenderServiceRecord(
                "srv-other123",
                "dobby-torturer-" + "b" * 32 + "-linux",
                "tea-test123",
                "web_service",
                old,
            ),
        )
        with tempfile.TemporaryDirectory(prefix="render-lease-lost-response-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaisesRegex(RenderAPIError, "INVALID_SERVICE_ID"):
                    lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertEqual(api.delete_calls, ["srv-orphan123"])
                self.assertIs(lease.state, LeaseState.ABSENT)
                self.assertEqual(lease.journal.records()[-1].cleanup_result, "verified-namespace")
            finally:
                holder.cleanup()

    def test_invalid_transitions_and_absent_cleanup_are_rejected_or_noop(self) -> None:
        api = FakeLeaseAPI()
        with tempfile.TemporaryDirectory(prefix="render-lease-state-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaises(LeaseStateError):
                    lease.mark_issued()
                with self.assertRaises(LeaseStateError):
                    lease.begin_testing()
                lease.cleanup()
                self.assertEqual(api.delete_calls, [])
                self.assertIs(lease.state, LeaseState.ABSENT)
            finally:
                holder.cleanup()

    def test_reaper_selects_only_aged_tagged_services_and_excludes_active_id(self) -> None:
        api = FakeLeaseAPI()
        old = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat().replace("+00:00", "Z")
        recent = datetime.fromtimestamp(time.time() - 10, timezone.utc).isoformat().replace("+00:00", "Z")
        prefix = f"dobby-torturer-{RUN_ID}-"
        api.records = (
            RenderServiceRecord("srv-old123", prefix + "linux", "tea-test123", "web_service", old),
            RenderServiceRecord("srv-active123", prefix + "android", "tea-test123", "web_service", old),
            RenderServiceRecord("srv-recent1", prefix + "macos", "tea-test123", "web_service", recent),
            RenderServiceRecord("srv-other123", "unrelated-service", "tea-test123", "web_service", old),
        )
        with tempfile.TemporaryDirectory(prefix="render-lease-reaper-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                deleted = lease.reap_orphans(active_service_ids=("srv-active123",), older_than_seconds=900)
                self.assertEqual(deleted, ("srv-old123",))
                self.assertEqual(api.delete_calls, ["srv-old123"])
            finally:
                holder.cleanup()


if __name__ == "__main__":
    unittest.main()
