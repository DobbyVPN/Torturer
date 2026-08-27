from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "torturer_provider" / "render.py"
SPEC = importlib.util.spec_from_file_location("render_provider_under_test", MODULE_PATH)
assert SPEC and SPEC.loader
RENDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RENDER
SPEC.loader.exec_module(RENDER)


IMAGE_DIGEST = "sha256:" + "a" * 64


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeTransport:
    def __init__(self, *, failed: bool = False) -> None:
        self.failed = failed
        self.calls: list[tuple[str, str, object, dict[str, str]]] = []
        self.polls = 0
        self.deleted = False

    def request(self, method, path, payload, headers):
        self.calls.append((method, path, payload, dict(headers)))
        if method == "POST" and path == "/services":
            return RENDER.HTTPResponse(201, {"service": {"id": "srv-test123"}, "deployId": "dep-test123"})
        if method == "GET" and path == "/services/srv-test123":
            if self.deleted:
                raise RENDER.RenderAPIError("UNEXPECTED_STATUS", 404)
            return RENDER.HTTPResponse(200, {
                "suspended": "not_suspended",
                "serviceDetails": {
                    "numInstances": 1,
                    "url": "https://dobby-test.onrender.com" if self.polls else None,
                },
            })
        if method == "GET" and path == "/services/srv-test123/deploys/dep-test123":
            self.polls += 1
            return RENDER.HTTPResponse(200, {"status": "build_failed" if self.failed else ("live" if self.polls > 1 else "build_in_progress")})
        if method == "DELETE" and path == "/services/srv-test123":
            self.deleted = True
            return RENDER.HTTPResponse(204, {})
        raise AssertionError((method, path, payload))


class RetryTransport:
    def __init__(self, responses: list[RENDER.HTTPResponse | RENDER.RenderAPIError]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def request(self, method, path, payload, headers):
        self.calls.append((method, path))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class PartialCreateTransport:
    def __init__(self) -> None:
        self.records = [{
            "id": "srv-partial123",
            "name": "dobby-test-123",
            "ownerId": "tea-test123",
            "type": "web_service",
            "createdAt": "2026-08-23T00:00:00Z",
        }]
        self.calls: list[tuple[str, str]] = []

    def request(self, method, path, payload, headers):
        self.calls.append((method, path))
        if method == "POST" and path == "/services":
            # Render accepted the service but returned a malformed body.
            return RENDER.HTTPResponse(201, {"service": {"id": "invalid"}})
        if method == "GET" and path.startswith("/services?"):
            return RENDER.HTTPResponse(200, [{"service": record} for record in self.records])
        if method == "DELETE" and path == "/services/srv-partial123":
            self.records.clear()
            return RENDER.HTTPResponse(204, {})
        if method == "GET" and path == "/services/srv-partial123":
            if self.records:
                return RENDER.HTTPResponse(200, {"id": "srv-partial123"})
            raise RENDER.RenderAPIError("UNEXPECTED_STATUS", 404)
        raise AssertionError((method, path, payload))


class PendingTransport(FakeTransport):
    def request(self, method, path, payload, headers):
        if method == "GET" and path == "/services/srv-test123":
            self.calls.append((method, path, payload, dict(headers)))
            if self.deleted:
                raise RENDER.RenderAPIError("UNEXPECTED_STATUS", 404)
            return RENDER.HTTPResponse(200, {
                "suspended": "not_suspended",
                "serviceDetails": {"numInstances": 1, "url": None},
            })
        if method == "GET" and path == "/services/srv-test123/deploys/dep-test123":
            self.calls.append((method, path, payload, dict(headers)))
            return RENDER.HTTPResponse(200, {"status": "build_in_progress"})
        return super().request(method, path, payload, headers)


class MalformedReadinessTransport(FakeTransport):
    def request(self, method, path, payload, headers):
        if method == "GET" and path == "/services/srv-test123":
            self.calls.append((method, path, payload, dict(headers)))
            if self.deleted:
                raise RENDER.RenderAPIError("UNEXPECTED_STATUS", 404)
            return RENDER.HTTPResponse(200, ["malformed"])
        return super().request(method, path, payload, headers)


class StickyDeleteTransport(MalformedReadinessTransport):
    def request(self, method, path, payload, headers):
        if method == "DELETE" and path == "/services/srv-test123":
            self.calls.append((method, path, payload, dict(headers)))
            return RENDER.HTTPResponse(204, {})
        return super().request(method, path, payload, headers)


def spec() -> object:
    return RENDER.RenderServiceSpec(
        owner_id="tea-test123",
        name="dobby-test-123",
        image_owner_id="tea-test123",
        image_path="docker.io/dobbyvpn/outline-wss@" + IMAGE_DIGEST,
        image_digest=IMAGE_DIGEST,
    )


def image_spec_with_runtime_config() -> object:
    return RENDER.RenderServiceSpec(
        owner_id="tea-test123",
        name="dobby-test-123",
        image_owner_id="tea-test123",
        image_path="ghcr.io/dobbyvpn/outline-ss-server@" + IMAGE_DIGEST,
        image_digest=IMAGE_DIGEST,
        health_check_path="/probe/tcp",
        secret_files=(("config.yml", "web:\n  servers: []\n"),),
    )


class RenderControllerTests(unittest.TestCase):
    def test_payload_is_one_free_image_service_without_secrets(self) -> None:
        value = spec().payload()
        self.assertEqual(value["type"], "web_service")
        self.assertEqual(value["autoDeploy"], "no")
        self.assertEqual(value["serviceDetails"]["numInstances"], 1)
        self.assertEqual(value["serviceDetails"]["runtime"], "image")
        self.assertNotIn("token", repr(value).lower())

    def test_payload_can_bind_immutable_image_runtime_config_without_echoing_content(self) -> None:
        value = image_spec_with_runtime_config().payload()
        self.assertEqual(value["image"]["imagePath"], "ghcr.io/dobbyvpn/outline-ss-server@" + IMAGE_DIGEST)
        self.assertEqual(value["secretFiles"], [{"name": "config.yml", "content": "web:\n  servers: []\n"}])
        self.assertNotIn("envSpecificDetails", value["serviceDetails"])

    def test_outline_wss_spec_can_omit_fake_http_health_path(self) -> None:
        value = image_spec_with_runtime_config().__dict__
        value["health_check_path"] = None
        payload = RENDER.RenderServiceSpec(**value).payload()
        self.assertNotIn("healthCheckPath", payload["serviceDetails"])

    def test_mutable_image_reference_is_rejected_even_with_a_digest_field(self) -> None:
        fields = image_spec_with_runtime_config().__dict__
        with self.assertRaisesRegex(ValueError, "immutable digest"):
            RENDER.RenderServiceSpec(**{**fields, "image_path": "ghcr.io/dobbyvpn/outline-ss-server:latest"})
        with self.assertRaisesRegex(ValueError, "immutable digest"):
            RENDER.RenderServiceSpec(
                **{**fields, "image_path": "ghcr.io/dobbyvpn/outline-ss-server@sha256:" + "b" * 64}
            )

    def test_secret_file_validation_is_fail_closed(self) -> None:
        fields = image_spec_with_runtime_config().__dict__
        with self.assertRaises(ValueError):
            RENDER.RenderServiceSpec(**{**fields, "secret_files": (("../config", "x"),)})

    def test_acquire_waits_for_live_https_service_and_release_verifies_deletion(self) -> None:
        transport = FakeTransport()
        clock = FakeClock()
        api = RENDER.RenderAPI("fixture-token", base_url="https://api.render.test/v1", transport=transport)
        controller = RENDER.DisposableRenderController(api, clock=clock, sleeper=clock.sleep)
        ready = controller.acquire(spec(), timeout_seconds=20, poll_seconds=1)
        self.assertEqual(ready.url, "https://dobby-test.onrender.com")
        controller.release(ready)
        self.assertTrue(transport.deleted)
        self.assertTrue(all("fixture-token" not in repr(call[:3]) for call in transport.calls))

    def test_read_retries_rate_limit_with_bounded_backoff_but_create_does_not_retry(self) -> None:
        backoffs: list[float] = []
        transport = RetryTransport([
            RENDER.HTTPResponse(429, {"error": "rate limited"}),
            RENDER.HTTPResponse(200, {"suspended": "not_suspended"}),
        ])
        api = RENDER.RenderAPI(
            "fixture-token",
            transport=transport,
            retry_backoff_seconds=0.25,
            sleeper=backoffs.append,
        )
        self.assertEqual(api.service("srv-test123"), {"suspended": "not_suspended"})
        self.assertEqual(transport.calls, [
            ("GET", "/services/srv-test123"),
            ("GET", "/services/srv-test123"),
        ])
        self.assertEqual(backoffs, [0.25])

        create_transport = RetryTransport([
            RENDER.HTTPResponse(429, {"error": "rate limited"}),
            RENDER.HTTPResponse(201, {"service": {"id": "srv-test123"}}),
        ])
        create_api = RENDER.RenderAPI("fixture-token", transport=create_transport, retry_backoff_seconds=0)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "UNEXPECTED_STATUS:429"):
            create_api.create_service(spec())
        self.assertEqual(create_transport.calls, [("POST", "/services")])

    def test_malformed_service_list_is_rejected_instead_of_being_treated_as_empty(self) -> None:
        transport = RetryTransport([RENDER.HTTPResponse(200, [{"service": {"id": "invalid"}}])])
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "INVALID_SERVICE_LIST"):
            api.list_services("tea-test123")

    def test_malformed_create_response_triggers_exact_name_cleanup_and_absence_proof(self) -> None:
        transport = PartialCreateTransport()
        api = RENDER.RenderAPI("fixture-token", transport=transport, retry_backoff_seconds=0)
        controller = RENDER.DisposableRenderController(api)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "INVALID_SERVICE_ID"):
            controller.acquire(spec(), timeout_seconds=5, poll_seconds=1)
        self.assertEqual(transport.records, [])
        self.assertIn(("DELETE", "/services/srv-partial123"), transport.calls)
        self.assertGreaterEqual(
            sum(method == "GET" and path.startswith("/services?") for method, path in transport.calls),
            2,
        )

    def test_cancellation_during_readiness_still_deletes_service(self) -> None:
        class Cancelled(BaseException):
            pass

        transport = FakeTransport()
        clock = FakeClock()

        def cancel(_seconds: float) -> None:
            raise Cancelled()

        api = RENDER.RenderAPI("fixture-token", transport=transport)
        controller = RENDER.DisposableRenderController(api, clock=clock, sleeper=cancel)
        with self.assertRaises(Cancelled):
            controller.acquire(spec(), timeout_seconds=20, poll_seconds=1)
        self.assertTrue(transport.deleted)

    def test_failed_deploy_is_deleted_before_failure_is_returned(self) -> None:
        transport = FakeTransport(failed=True)
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        controller = RENDER.DisposableRenderController(api)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "DEPLOY_FAILED"):
            controller.acquire(spec(), timeout_seconds=20)
        self.assertTrue(transport.deleted)

    def test_readiness_timeout_is_bounded_and_deletes_service(self) -> None:
        transport = PendingTransport()
        clock = FakeClock()
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        controller = RENDER.DisposableRenderController(api, clock=clock, sleeper=clock.sleep)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "READINESS_TIMEOUT"):
            controller.acquire(spec(), timeout_seconds=2, poll_seconds=1)
        self.assertTrue(transport.deleted)

    def test_malformed_readiness_response_is_not_treated_as_ready(self) -> None:
        transport = MalformedReadinessTransport()
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        controller = RENDER.DisposableRenderController(api)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "INVALID_RESPONSE"):
            controller.acquire(spec(), timeout_seconds=5, poll_seconds=1)
        self.assertTrue(transport.deleted)

    def test_readiness_failure_rejects_unverified_delete(self) -> None:
        transport = StickyDeleteTransport()
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        controller = RENDER.DisposableRenderController(api)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "CREATE_CLEANUP_FAILED"):
            controller.acquire(spec(), timeout_seconds=5, poll_seconds=1)
        self.assertTrue(any(method == "DELETE" and path == "/services/srv-test123" for method, path, *_ in transport.calls))

    def test_reaper_accepts_already_deleted_service(self) -> None:
        transport = FakeTransport()
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        reaper = RENDER.RenderReaper(api)
        reaper.reap(("srv-test123",))
        reaper.reap(("srv-test123",))
        self.assertTrue(transport.deleted)

    def test_provider_errors_never_echo_api_token_or_response_body(self) -> None:
        class ErrorTransport:
            def request(self, method, path, payload, headers):
                raise RENDER.RenderAPIError("HTTP_ERROR", 401)

        api = RENDER.RenderAPI("fixture-token", transport=ErrorTransport())
        with self.assertRaises(RENDER.RenderAPIError) as raised:
            api.service("srv-test123")
        self.assertNotIn("fixture-token", str(raised.exception))
        self.assertNotIn("Authorization", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
