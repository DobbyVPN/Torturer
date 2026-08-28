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
    LeaseCleanupError,
    LeaseJournalRecord,
    LeaseState,
    LeaseStateError,
    RenderLease,
    RenderLeaseBundle,
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
    def __init__(
        self,
        *,
        failed_deploy: bool = False,
        fail_create: bool = False,
        retain_deleted_records: bool = False,
    ) -> None:
        self.failed_deploy = failed_deploy
        self.fail_create = fail_create
        self.retain_deleted_records = retain_deleted_records
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
        if not self.retain_deleted_records:
            self.records = tuple(record for record in self.records if record.service_id != service_id)
        return True

    def exists(self, service_id: str) -> bool:
        return self.retain_deleted_records or not self.deleted

    def list_services(self, owner_id: str) -> tuple[RenderServiceRecord, ...]:
        return self.records


class FakeBundleAPI:
    def __init__(self, *, retain_sink: bool = False) -> None:
        self.retain_sink = retain_sink
        self.fail_listing = False
        self.created: list[RenderServiceSpec] = []
        self.active: set[str] = set()
        self.delete_calls: list[str] = []

    def create_service(self, spec: RenderServiceSpec) -> RenderServiceHandle:
        self.created.append(spec)
        service_id = "srv-sink123" if spec.name.endswith("-upload-sink") else "srv-outline123"
        self.active.add(service_id)
        return RenderServiceHandle(service_id, "dep-" + service_id.removeprefix("srv-"), spec.image_digest)

    def service(self, service_id: str) -> dict[str, object]:
        if service_id not in self.active:
            raise RenderAPIError("UNEXPECTED_STATUS", 404)
        host = "sink.example.onrender.com" if service_id == "srv-sink123" else "outline.example.onrender.com"
        return {"suspended": "not_suspended", "serviceDetails": {"numInstances": 1, "url": "https://" + host}}

    def deploy(self, service_id: str, deploy_id: str) -> dict[str, object]:
        return {"status": "live"}

    def delete_service(self, service_id: str) -> bool:
        self.delete_calls.append(service_id)
        if not (self.retain_sink and service_id == "srv-sink123"):
            self.active.discard(service_id)
        return True

    def exists(self, service_id: str) -> bool:
        return service_id in self.active

    def list_services(self, owner_id: str) -> tuple[RenderServiceRecord, ...]:
        if self.fail_listing:
            raise RenderAPIError("TRANSPORT_ERROR")
        now = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat().replace("+00:00", "Z")
        return tuple(
            RenderServiceRecord(
                service_id,
                "dobby-torturer-" + RUN_ID + ("-upload-sink" if service_id == "srv-sink123" else "-linux"),
                "tea-test123",
                "web_service",
                now,
            )
            for service_id in sorted(self.active)
        )


def make_bundle(api: FakeBundleAPI, directory: str | Path) -> RenderLeaseBundle:
    journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
    sink_digest = "sha256:" + "b" * 64
    outline_descriptor = RenderLeaseDescriptor(
        RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-linux", IMAGE_DIGEST
    )
    sink_descriptor = RenderLeaseDescriptor(
        RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-upload-sink", sink_digest, "upload-sink"
    )
    outline = RenderLease(
        api,
        RenderServiceSpec(
            "tea-test123", outline_descriptor.service_name, "tea-test123",
            "ghcr.io/dobbyvpn/outline@" + IMAGE_DIGEST, IMAGE_DIGEST,
        ),
        outline_descriptor,
        journal,
    )
    sink = RenderLease(
        api,
        RenderServiceSpec(
            "tea-test123", sink_descriptor.service_name, "tea-test123",
            "ghcr.io/dobbyvpn/sink@" + sink_digest, sink_digest,
        ),
        sink_descriptor,
        journal,
    )
    return RenderLeaseBundle(outline, sink)


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

    def test_lost_create_response_fails_closed_on_an_ambiguous_namespace(self) -> None:
        api = FakeLeaseAPI(fail_create=True)
        old = datetime.fromtimestamp(time.time() - 5, timezone.utc).isoformat().replace("+00:00", "Z")
        prefix = f"dobby-torturer-{RUN_ID}-"
        api.records = (
            RenderServiceRecord(
                "srv-orphan123",
                prefix + "linux",
                "tea-test123",
                "web_service",
                old,
            ),
            RenderServiceRecord(
                "srv-stale123",
                prefix + "android",
                "tea-test123",
                "web_service",
                old,
            ),
        )
        with tempfile.TemporaryDirectory(prefix="render-lease-ambiguous-lost-response-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaises(LeaseCleanupError):
                    lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertIs(lease.state, LeaseState.DELETING)
                self.assertEqual(api.delete_calls, [])
                self.assertEqual(
                    lease.journal.records()[-1].cleanup_result,
                    "unverified-no-service-id",
                )
            finally:
                holder.cleanup()

    def test_lost_create_response_fails_closed_when_fresh_namespace_absence_is_not_proven(self) -> None:
        api = FakeLeaseAPI(fail_create=True, retain_deleted_records=True)
        old = datetime.fromtimestamp(time.time() - 5, timezone.utc).isoformat().replace("+00:00", "Z")
        prefix = f"dobby-torturer-{RUN_ID}-"
        api.records = (
            RenderServiceRecord(
                "srv-stuck123",
                prefix + "linux",
                "tea-test123",
                "web_service",
                old,
            ),
        )
        with tempfile.TemporaryDirectory(prefix="render-lease-unverified-namespace-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaises(LeaseCleanupError):
                    lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertEqual(lease.state, LeaseState.DELETING)
                self.assertEqual(lease.journal.records()[-1].cleanup_result, "unverified-no-service-id")
            finally:
                holder.cleanup()

    def test_cancellation_during_readiness_cleans_service_and_reraises(self) -> None:
        class Cancelled(BaseException):
            pass

        class CancellableAPI(FakeLeaseAPI):
            def service(self, service_id: str) -> dict[str, object]:
                raise Cancelled()

        api = CancellableAPI()
        with tempfile.TemporaryDirectory(prefix="render-lease-cancel-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaises(Cancelled):
                    lease.acquire(timeout_seconds=5, poll_seconds=1)
                self.assertEqual(api.delete_calls, ["srv-lease123"])
                self.assertEqual(lease.state, LeaseState.ABSENT)
            finally:
                holder.cleanup()

    def test_exact_service_cleanup_fails_closed_when_absence_is_not_verified(self) -> None:
        api = FakeLeaseAPI(retain_deleted_records=True)
        with tempfile.TemporaryDirectory(prefix="render-lease-sticky-delete-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                lease.acquire(timeout_seconds=5, poll_seconds=1)
                lease.mark_issued()
                with self.assertRaises(LeaseCleanupError):
                    lease.cleanup()
                self.assertEqual(lease.state, LeaseState.DELETING)
                self.assertEqual(api.delete_calls, ["srv-lease123"])
            finally:
                holder.cleanup()

    def test_reaper_rejects_malformed_timestamp_in_its_dedicated_namespace(self) -> None:
        class MalformedRecord:
            service_id = "srv-malformed123"
            name = f"dobby-torturer-{RUN_ID}-linux"
            owner_id = "tea-test123"
            created_at = "not-a-timestamp"

        api = FakeLeaseAPI()
        api.records = (MalformedRecord(),)
        with tempfile.TemporaryDirectory(prefix="render-lease-malformed-reaper-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                with self.assertRaisesRegex(RenderAPIError, "INVALID_SERVICE_TIMESTAMP"):
                    lease.reap_orphans(older_than_seconds=0)
                self.assertEqual(api.delete_calls, [])
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
            RenderServiceRecord("srv-active-sink123", prefix + "upload-sink", "tea-test123", "web_service", old),
            RenderServiceRecord("srv-recent1", prefix + "macos", "tea-test123", "web_service", recent),
            RenderServiceRecord("srv-other123", "unrelated-service", "tea-test123", "web_service", old),
        )
        with tempfile.TemporaryDirectory(prefix="render-lease-reaper-test.") as directory:
            holder = tempfile.TemporaryDirectory(dir=directory)
            try:
                lease = make_lease(api, holder)
                deleted = lease.reap_orphans(
                    active_service_ids=("srv-active123", "srv-active-sink123"),
                    older_than_seconds=900,
                )
                self.assertEqual(deleted, ("srv-old123",))
                self.assertEqual(api.delete_calls, ["srv-old123"])
            finally:
                holder.cleanup()

    def test_linux_bundle_binds_roles_and_digests_and_cleans_both_services(self) -> None:
        api = FakeBundleAPI()
        sink_digest = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-test.") as directory:
            journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
            outline_descriptor = RenderLeaseDescriptor(
                run_id=RUN_ID,
                platform="linux",
                service_name=f"dobby-torturer-{RUN_ID}-linux",
                image_digest=IMAGE_DIGEST,
            )
            sink_descriptor = RenderLeaseDescriptor(
                run_id=RUN_ID,
                platform="linux",
                service_name=f"dobby-torturer-{RUN_ID}-upload-sink",
                image_digest=sink_digest,
                role="upload-sink",
            )
            outline = RenderLease(
                api,
                RenderServiceSpec(
                    owner_id="tea-test123",
                    name=outline_descriptor.service_name,
                    image_owner_id="tea-test123",
                    image_path="ghcr.io/dobbyvpn/outline-ss-server@" + IMAGE_DIGEST,
                    image_digest=IMAGE_DIGEST,
                ),
                outline_descriptor,
                journal,
            )
            sink = RenderLease(
                api,
                RenderServiceSpec(
                    owner_id="tea-test123",
                    name=sink_descriptor.service_name,
                    image_owner_id="tea-test123",
                    image_path="ghcr.io/dobbyvpn/torturer-throughput-sink@" + sink_digest,
                    image_digest=sink_digest,
                    health_check_path="/healthz",
                ),
                sink_descriptor,
                journal,
            )
            bundle = RenderLeaseBundle(outline, sink)
            bundle.acquire(timeout_seconds=5, poll_seconds=1)
            bundle.mark_issued()
            bundle.begin_testing()
            bundle.cleanup()
            self.assertEqual(api.delete_calls, ["srv-sink123", "srv-outline123"])
            records = journal.records()
            self.assertEqual(journal.schema, 2)
            self.assertEqual({record.role for record in records}, {"outline", "upload-sink"})
            self.assertEqual(
                {record.image_digest for record in records},
                {IMAGE_DIGEST, sink_digest},
            )
            document = json.dumps([record.to_json_object(include_role=True) for record in records])
            self.assertNotIn("onrender.com", document)

    def test_linux_bundle_fails_closed_on_an_extra_same_namespace_service(self) -> None:
        api = FakeBundleAPI()
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-extra-service-test.") as directory:
            bundle = make_bundle(api, directory)
            bundle.acquire(timeout_seconds=5, poll_seconds=1)
            api.active.add("srv-extra123")
            with self.assertRaises(LeaseCleanupError):
                bundle.cleanup()
            self.assertEqual(api.delete_calls, ["srv-sink123", "srv-outline123"])
            self.assertEqual(api.active, {"srv-extra123"})

    def test_linux_bundle_fails_closed_when_namespace_probe_fails(self) -> None:
        api = FakeBundleAPI()
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-probe-failure-test.") as directory:
            bundle = make_bundle(api, directory)
            bundle.acquire(timeout_seconds=5, poll_seconds=1)
            api.fail_listing = True
            with self.assertRaises(LeaseCleanupError):
                bundle.cleanup()
            self.assertEqual(api.delete_calls, ["srv-sink123", "srv-outline123"])
            self.assertEqual(api.active, set())
            api.fail_listing = False
            bundle.cleanup()

    def test_schema2_bundle_accepts_all_hosted_platforms(self) -> None:
        for platform in ("linux", "windows", "macos", "android"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory(
                prefix=f"render-lease-{platform}-bundle-shape-test."
            ) as directory:
                journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
                sink_digest = "sha256:" + "b" * 64
                outline_descriptor = RenderLeaseDescriptor(
                    RUN_ID, platform, f"dobby-torturer-{RUN_ID}-{platform}", IMAGE_DIGEST
                )
                sink_descriptor = RenderLeaseDescriptor(
                    RUN_ID, platform, f"dobby-torturer-{RUN_ID}-upload-sink",
                    sink_digest, "upload-sink"
                )
                outline = RenderLease(
                    FakeBundleAPI(),
                    RenderServiceSpec(
                        "tea-test123", outline_descriptor.service_name, "tea-test123",
                        "ghcr.io/dobbyvpn/outline@" + IMAGE_DIGEST, IMAGE_DIGEST,
                    ),
                    outline_descriptor, journal,
                )
                sink = RenderLease(
                    FakeBundleAPI(),
                    RenderServiceSpec(
                        "tea-test123", sink_descriptor.service_name, "tea-test123",
                        "ghcr.io/dobbyvpn/sink@" + sink_digest, sink_digest,
                    ),
                    sink_descriptor, journal,
                )
                self.assertIsInstance(RenderLeaseBundle(outline, sink), RenderLeaseBundle)

    def test_linux_bundle_uses_one_absolute_deadline_and_cleans_on_exhaustion(self) -> None:
        class FakeClock:
            def __init__(self) -> None:
                self.value = 0.0

            def __call__(self) -> float:
                return self.value

            def sleep(self, seconds: float) -> None:
                self.value += seconds

        class ExpiringAPI(FakeBundleAPI):
            def __init__(self, clock: FakeClock) -> None:
                super().__init__()
                self.clock = clock

            def create_service(self, spec: RenderServiceSpec) -> RenderServiceHandle:
                handle = super().create_service(spec)
                if spec.name.endswith("-upload-sink"):
                    # The first service succeeded, but the second service's
                    # control-plane call consumed the shared bundle budget.
                    self.clock.value += 6
                return handle

        clock = FakeClock()
        api = ExpiringAPI(clock)
        sink_digest = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-deadline-test.") as directory:
            journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
            outline_descriptor = RenderLeaseDescriptor(
                RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-linux", IMAGE_DIGEST
            )
            sink_descriptor = RenderLeaseDescriptor(
                RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-upload-sink", sink_digest, "upload-sink"
            )
            outline = RenderLease(
                api,
                RenderServiceSpec(
                    "tea-test123", outline_descriptor.service_name, "tea-test123",
                    "ghcr.io/dobbyvpn/outline@" + IMAGE_DIGEST, IMAGE_DIGEST,
                ),
                outline_descriptor,
                journal,
                monotonic_clock=clock,
                sleeper=clock.sleep,
            )
            sink = RenderLease(
                api,
                RenderServiceSpec(
                    "tea-test123", sink_descriptor.service_name, "tea-test123",
                    "ghcr.io/dobbyvpn/sink@" + sink_digest, sink_digest,
                ),
                sink_descriptor,
                journal,
                monotonic_clock=clock,
                sleeper=clock.sleep,
            )
            bundle = RenderLeaseBundle(outline, sink, monotonic_clock=clock)
            with self.assertRaisesRegex(LeaseStateError, "deadline expired"):
                bundle.acquire(timeout_seconds=5, poll_seconds=1)
            self.assertEqual(api.delete_calls, ["srv-sink123", "srv-outline123"])
            self.assertEqual(api.active, set())
            latest = {record.role: record for record in journal.records()}
            self.assertEqual(
                {role: (record.state, record.cleanup_result) for role, record in latest.items()},
                {
                    "outline": (LeaseState.ABSENT, "verified"),
                    "upload-sink": (LeaseState.ABSENT, "verified"),
                },
            )

    def test_linux_bundle_failure_reaps_only_unknown_sink_and_then_outline(self) -> None:
        class SinkCreateFailureAPI(FakeBundleAPI):
            def create_service(self, spec: RenderServiceSpec) -> RenderServiceHandle:
                if spec.name.endswith("-upload-sink"):
                    self.active.add("srv-sink123")
                    raise RenderAPIError("CREATE_FAILED")
                return super().create_service(spec)

        api = SinkCreateFailureAPI()
        sink_digest = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-failure-test.") as directory:
            journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
            outline_descriptor = RenderLeaseDescriptor(RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-linux", IMAGE_DIGEST)
            sink_descriptor = RenderLeaseDescriptor(RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-upload-sink", sink_digest, "upload-sink")
            outline = RenderLease(
                api,
                RenderServiceSpec("tea-test123", outline_descriptor.service_name, "tea-test123", "ghcr.io/dobbyvpn/outline@" + IMAGE_DIGEST, IMAGE_DIGEST),
                outline_descriptor,
                journal,
            )
            sink = RenderLease(
                api,
                RenderServiceSpec("tea-test123", sink_descriptor.service_name, "tea-test123", "ghcr.io/dobbyvpn/sink@" + sink_digest, sink_digest),
                sink_descriptor,
                journal,
            )
            bundle = RenderLeaseBundle(outline, sink)
            with self.assertRaises(RenderAPIError):
                bundle.acquire(timeout_seconds=5, poll_seconds=1)
            self.assertEqual(api.delete_calls, ["srv-sink123", "srv-outline123"])
            self.assertEqual(api.active, set())

    def test_linux_bundle_rejects_duplicate_provider_service_id(self) -> None:
        class DuplicateIDAPI(FakeBundleAPI):
            def create_service(self, spec: RenderServiceSpec) -> RenderServiceHandle:
                self.created.append(spec)
                self.active.add("srv-outline123")
                return RenderServiceHandle("srv-outline123", "dep-outline123", spec.image_digest)

        api = DuplicateIDAPI()
        sink_digest = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-duplicate-id-test.") as directory:
            journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
            outline_descriptor = RenderLeaseDescriptor(RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-linux", IMAGE_DIGEST)
            sink_descriptor = RenderLeaseDescriptor(RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-upload-sink", sink_digest, "upload-sink")
            outline = RenderLease(
                api,
                RenderServiceSpec("tea-test123", outline_descriptor.service_name, "tea-test123", "ghcr.io/dobbyvpn/outline@" + IMAGE_DIGEST, IMAGE_DIGEST),
                outline_descriptor,
                journal,
            )
            sink = RenderLease(
                api,
                RenderServiceSpec("tea-test123", sink_descriptor.service_name, "tea-test123", "ghcr.io/dobbyvpn/sink@" + sink_digest, sink_digest),
                sink_descriptor,
                journal,
            )
            with self.assertRaises(LeaseStateError):
                RenderLeaseBundle(outline, sink).acquire(timeout_seconds=5, poll_seconds=1)

    def test_linux_bundle_fails_closed_when_sink_absence_is_unverified(self) -> None:
        api = FakeBundleAPI(retain_sink=True)
        sink_digest = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory(prefix="render-lease-bundle-sticky-sink-test.") as directory:
            journal = RenderLeaseJournal(Path(directory) / "journal.json", schema=2)
            outline_descriptor = RenderLeaseDescriptor(RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-linux", IMAGE_DIGEST)
            sink_descriptor = RenderLeaseDescriptor(RUN_ID, "linux", f"dobby-torturer-{RUN_ID}-upload-sink", sink_digest, "upload-sink")
            outline = RenderLease(
                api,
                RenderServiceSpec("tea-test123", outline_descriptor.service_name, "tea-test123", "ghcr.io/dobbyvpn/outline@" + IMAGE_DIGEST, IMAGE_DIGEST),
                outline_descriptor,
                journal,
            )
            sink = RenderLease(
                api,
                RenderServiceSpec("tea-test123", sink_descriptor.service_name, "tea-test123", "ghcr.io/dobbyvpn/sink@" + sink_digest, sink_digest),
                sink_descriptor,
                journal,
            )
            bundle = RenderLeaseBundle(outline, sink)
            bundle.acquire(timeout_seconds=5, poll_seconds=1)
            bundle.mark_issued()
            with self.assertRaises(LeaseCleanupError):
                bundle.cleanup()
            self.assertEqual(api.delete_calls, ["srv-sink123", "srv-outline123"])
            self.assertIn("srv-sink123", api.active)
            self.assertNotIn("srv-outline123", api.active)

    def test_legacy_journal_rejects_upload_sink_role(self) -> None:
        with tempfile.TemporaryDirectory(prefix="render-lease-legacy-role-test.") as directory:
            journal = RenderLeaseJournal(Path(directory) / "journal.json")
            with self.assertRaisesRegex(ValueError, "non-outline role"):
                journal.append(
                    LeaseJournalRecord(
                        run_id=RUN_ID,
                        service_id=None,
                        image_digest=IMAGE_DIGEST,
                        state=LeaseState.ABSENT,
                        timestamp="2026-08-23T00:00:00Z",
                        role="upload-sink",
                    )
                )


if __name__ == "__main__":
    unittest.main()
