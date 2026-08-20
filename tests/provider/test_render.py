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


def spec() -> object:
    return RENDER.RenderServiceSpec(
        owner_id="tea-test123",
        name="dobby-test-123",
        image_owner_id="tea-test123",
        image_path="docker.io/dobbyvpn/outline-wss@" + IMAGE_DIGEST,
        image_digest=IMAGE_DIGEST,
    )


class RenderControllerTests(unittest.TestCase):
    def test_payload_is_one_free_image_service_without_secrets(self) -> None:
        value = spec().payload()
        self.assertEqual(value["type"], "web_service")
        self.assertEqual(value["autoDeploy"], "no")
        self.assertEqual(value["serviceDetails"]["numInstances"], 1)
        self.assertEqual(value["serviceDetails"]["runtime"], "image")
        self.assertNotIn("token", repr(value).lower())

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

    def test_failed_deploy_is_deleted_before_failure_is_returned(self) -> None:
        transport = FakeTransport(failed=True)
        api = RENDER.RenderAPI("fixture-token", transport=transport)
        controller = RENDER.DisposableRenderController(api)
        with self.assertRaisesRegex(RENDER.RenderAPIError, "DEPLOY_FAILED"):
            controller.acquire(spec(), timeout_seconds=20)
        self.assertTrue(transport.deleted)

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
