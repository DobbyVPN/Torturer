from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from torturer_checks.hosted.android import AndroidHostedAdapter
from torturer_checks.hosted.cli import CommandResult, HostedAdapterError
from torturer_checks.hosted.factory import adapter_for_platform
from torturer_contract.functional.engine import FunctionalEngine
from torturer_contract.functional.results import RunProvenance
from torturer_contract.functional.scenarios import get_scenario


_SOURCE_SHA = "a" * 40


def _observation(error_code: str | None = None) -> bytes:
    value: dict[str, object] = {
        "schema": 1,
        "kind": "dobbyvpn.android.profile-observation",
        "platform": "android",
        "source_sha": _SOURCE_SHA,
        "configured": True,
        "connected": True,
        "tunnel_interface": True,
        "routing_identity_changed": True,
        "stability_verified": True,
        "latency_ms": 12.5,
        "download_mbps": 20.0,
        "upload_mbps": 10.0,
        "disconnect_clean": True,
        "restart_verified": True,
        "reconnect_bounded": True,
        "second_tunnel_interface": True,
        "second_routing_identity_changed": True,
        "final_disconnect_clean": True,
        "cleanup_verified": True,
    }
    if error_code is not None:
        value["error_code"] = error_code
    return (json.dumps(value) + "\n").encode("utf-8")


class FakeAndroidRunner:
    def __init__(self, raw_directory: Path) -> None:
        self.raw_directory = raw_directory
        self.raw_directory.mkdir(parents=True)
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[float] = []
        self.command_payload: dict[str, object] | None = None
        self.observation = _observation()

    def run(self, command, *, timeout_seconds):
        argv = tuple(command)
        self.calls.append(argv)
        self.timeouts.append(float(timeout_seconds))
        if argv[1:2] == ("push",) and argv[2].endswith(".command.json"):
            self.command_payload = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        if argv[1:2] == ("exec-out",):
            return CommandResult(argv, 0, self.observation, b"")
        return CommandResult(argv, 0, b"adb stdout diagnostic\n", b"adb stderr diagnostic\n")


def _provenance(adapter: AndroidHostedAdapter) -> RunProvenance:
    return RunProvenance(
        source_repository="DobbyVPN/DobbyVPN",
        source_sha=_SOURCE_SHA,
        torturer_sha="b" * 40,
        artifact_sha256="c" * 64,
        server_image_digest="sha256:" + "d" * 64,
        platform="android",
        adapter_id=adapter.adapter_id,
        adapter_version=adapter.adapter_version,
        capabilities=frozenset(item.value for item in adapter.capabilities),
    )


class HostedAndroidAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="hosted-android-adapter-")
        root = Path(self.directory.name)
        self.adb = root / "adb"
        self.adb.write_bytes(b"synthetic adb executable\n")
        self.adb.chmod(0o700)
        self.profile = root / "profile.conf"
        self.profile.write_bytes(b"synthetic profile bytes\n")
        os.chmod(self.profile, 0o600)
        self.runner = FakeAndroidRunner(root / "raw")
        self.adapter = AndroidHostedAdapter(
            runner=self.runner,
            profile=self.profile,
            adb=self.adb,
            source_sha=_SOURCE_SHA,
            identity_url="https://identity.example.test/ip",
            latency_url="https://latency.example.test/blob",
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        self.addCleanup(self.directory.cleanup)

    def test_bulk_adapter_uses_one_product_session_and_canonical_engine(self) -> None:
        scenario = get_scenario("functional.core-connection")
        result = FunctionalEngine("e" * 64).run(
            scenario, self.adapter, _provenance(self.adapter)
        )
        self.assertEqual(result.outcome, "passed")
        self.assertEqual(
            [item["operation"] for item in self.runner.command_payload["operations"]],
            [step.operation for step in scenario.steps],
        )
        instrumentation = [
            call for call in self.runner.calls if "instrument" in call
        ]
        self.assertEqual(len(instrumentation), 1)
        self.assertIn("dobby.real_profile", instrumentation[0])
        self.assertIn("dobby.hosted_command_file", instrumentation[0])
        self.assertTrue(any(call[1] == "logcat" for call in self.runner.calls))
        self.assertTrue(
            all(timeout <= scenario.max_duration_seconds for timeout in self.runner.timeouts)
        )

    def test_product_error_is_failed_and_cleanup_commands_are_still_attempted(self) -> None:
        self.runner.observation = _observation("DRIVER_ERROR")
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.core-connection"),
            self.adapter,
            _provenance(self.adapter),
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "ANDROID_OBSERVATION_ERROR")
        self.assertTrue(
            any(
                "am" in call and "force-stop" in call
                for call in self.runner.calls
            )
        )

    def test_missing_seam_inputs_fail_closed_and_headless_contract_is_explicit(self) -> None:
        adapter = AndroidHostedAdapter(
            runner=self.runner,
            profile=self.profile,
        )
        self.assertEqual(adapter.capabilities, frozenset())
        self.assertLessEqual(
            get_scenario("functional.start-stop-start").max_duration_seconds,
            30 * 60,
        )

    def test_factory_wires_android_without_a_desktop_cli(self) -> None:
        adapter = adapter_for_platform(
            "android",
            cli=None,
            profile=self.profile,
            runner=self.runner,
            adb=self.adb,
            source_sha=_SOURCE_SHA,
            identity_url="https://identity.example.test/ip",
            latency_url="https://latency.example.test/blob",
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        self.assertIsInstance(adapter, AndroidHostedAdapter)
        self.assertEqual(adapter.capabilities, self.adapter.capabilities)

    def test_missing_or_non_executable_adb_fails_closed(self) -> None:
        with self.assertRaisesRegex(HostedAdapterError, "ANDROID_ADB_UNAVAILABLE"):
            AndroidHostedAdapter(
                runner=self.runner,
                profile=self.profile,
                adb=Path(self.directory.name) / "missing-adb",
            )
        non_executable = Path(self.directory.name) / "non-executable-adb"
        non_executable.write_bytes(b"not executable\n")
        non_executable.chmod(0o600)
        with self.assertRaisesRegex(HostedAdapterError, "ANDROID_ADB_UNAVAILABLE"):
            AndroidHostedAdapter(
                runner=self.runner,
                profile=self.profile,
                adb=non_executable,
            )

    def test_android_endpoints_reject_query_fragment_and_userinfo(self) -> None:
        for invalid in (
            "https://identity.example.test/ip?token=x",
            "https://identity.example.test/ip#fragment",
            "https://user:password@identity.example.test/ip",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(HostedAdapterError, "IDENTITY_URL_INVALID"):
                    AndroidHostedAdapter(
                        runner=self.runner,
                        profile=self.profile,
                        adb=self.adb,
                        identity_url=invalid,
                        latency_url="https://latency.example.test/blob",
                        download_url="https://download.example.test/blob",
                        upload_url="https://upload.example.test/blob",
                    )

    def test_android_adapter_rejects_unexpected_constructor_arguments(self) -> None:
        with self.assertRaisesRegex(HostedAdapterError, "ANDROID_ARGUMENT_UNEXPECTED"):
            AndroidHostedAdapter(
                runner=self.runner,
                profile=self.profile,
                network_interface="eth0",
            )

    def test_factory_rejects_android_desktop_arguments(self) -> None:
        values: dict[str, object] = {
            "cli": Path("/unexpected"),
            "service_pid": 1,
            "service_binary": Path("/unexpected"),
            "service_socket": Path("/unexpected"),
            "service_library_path": Path("/unexpected"),
            "service_pid_file": Path("/unexpected"),
            "network_interface": "eth0",
        }
        for argument, value in values.items():
            with self.subTest(argument=argument):
                with self.assertRaisesRegex(ValueError, f"unexpected {argument}"):
                    adapter_for_platform(
                        "android",
                        profile=self.profile,
                        runner=self.runner,
                        adb=self.adb,
                        **{argument: value},
                    )

    def test_factory_rejects_a_desktop_lane_without_a_cli(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires --cli"):
            adapter_for_platform(
                "linux",
                cli=None,
                profile=self.profile,
                runner=self.runner,
                download_url="https://download.example.test/blob",
                upload_url="https://upload.example.test/blob",
            )

    def test_parser_accepts_android_specific_inputs_without_a_cli(self) -> None:
        from torturer_checks.hosted.run import build_parser

        parsed = build_parser().parse_args([
            "--platform", "android", "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN", "--source-sha", _SOURCE_SHA,
            "--candidate-manifest", __file__, "--server-image-digest", "sha256:" + "b" * 64,
            "--output", str(Path(self.directory.name) / "result.json"),
            "--adb", "/synthetic/adb", "--identity-url", "https://identity.example.test/ip",
            "--latency-url", "https://latency.example.test/blob",
        ])
        self.assertIsNone(parsed.cli)

if __name__ == "__main__":
    unittest.main()
