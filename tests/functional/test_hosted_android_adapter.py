from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from torturer_checks.hosted.android import (
    AndroidHostedAdapter,
    _finalization_error,
    _scenario_deadlines,
)
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
        self.raw_directory.mkdir(mode=0o700, parents=True)
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[float] = []
        self.command_payload: dict[str, object] | None = None
        self.observation = _observation()
        self.fail_diagnostics = False
        self.fail_cleanup = False

    def run(self, command, *, timeout_seconds):
        argv = tuple(command)
        self.calls.append(argv)
        self.timeouts.append(float(timeout_seconds))
        if argv[1:2] == ("push",) and argv[2].endswith(".command.json"):
            self.command_payload = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        if argv[1:2] == ("exec-out",):
            return CommandResult(argv, 0, self.observation, b"")
        if argv[1:3] == ("shell", "pidof"):
            return CommandResult(argv, 1, b"", b"adb pidof: no matching process\n")
        if self.fail_diagnostics and (
            argv[1:2] == ("logcat",) or argv[1:3] == ("shell", "dumpsys") or argv[1:3] == ("shell", "ps")
        ):
            return CommandResult(argv, 1, b"adb diagnostics stdout diagnostic\n", b"adb diagnostics stderr diagnostic\n")
        if self.fail_cleanup and (
            argv[1:3] == ("shell", "rm")
            or argv[1:4] == ("shell", "am", "force-stop")
            or (argv[1:4] == ("shell", "run-as", "com.dobby.vpn") and "rm" in argv)
        ):
            return CommandResult(argv, 1, b"adb cleanup stdout diagnostic\n", b"adb cleanup stderr diagnostic\n")
        return CommandResult(argv, 0, b"adb stdout diagnostic\n", b"adb stderr diagnostic\n")


class InputAndroidRunner(FakeAndroidRunner):
    """Synthetic runner that exercises the real stdin staging path."""

    def run_with_input(self, command, *, timeout_seconds, input_bytes):
        del input_bytes
        return self.run(command, timeout_seconds=timeout_seconds)


class PartialLogcatRunner(FakeAndroidRunner):
    """Synthetic runner for a bounded, non-empty logcat timeout."""

    def run(self, command, *, timeout_seconds):
        result = super().run(command, timeout_seconds=timeout_seconds)
        if tuple(command)[1:2] == ("logcat",):
            return CommandResult(tuple(command), 124, b"partial logcat bytes\n", b"", timed_out=True)
        return result


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
        self.assertTrue(all(timeout <= 5.0 for timeout in self.runner.timeouts[-7:]))

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

    def test_finalization_deadlines_are_reserved_inside_the_lane(self) -> None:
        work, diagnostics, cleanup = _scenario_deadlines(100.0, 141.0)
        self.assertLess(work, diagnostics)
        self.assertLess(diagnostics, cleanup)
        self.assertLessEqual(cleanup, 100.0 + 1_800.0)
        self.assertAlmostEqual(cleanup - work, 35.25)

    def test_command_evidence_uses_exclusive_names_when_raw_directory_is_reused(self) -> None:
        scenario = get_scenario("functional.core-connection")
        first, _profile_one, _output_one = self.adapter._write_command(scenario)
        first_bytes = first.read_bytes()
        second, _profile_two, _output_two = self.adapter._write_command(scenario)
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), first_bytes)
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)
        self.assertEqual(second.stat().st_mode & 0o777, 0o600)

    def test_finalization_failure_remains_visible_after_product_failure(self) -> None:
        self.runner.observation = _observation("DRIVER_ERROR")
        self.runner.fail_cleanup = True
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.core-connection"),
            self.adapter,
            _provenance(self.adapter),
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "ANDROID_CLEANUP_FAILED")
        self.assertTrue(any(call[1] == "logcat" for call in self.runner.calls))

    def test_diagnostic_failure_remains_visible_after_product_failure(self) -> None:
        self.runner.observation = _observation("DRIVER_ERROR")
        self.runner.fail_diagnostics = True
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.core-connection"),
            self.adapter,
            _provenance(self.adapter),
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "ANDROID_DIAGNOSTICS_FAILED")

    def test_finalization_error_codes_are_stable(self) -> None:
        from torturer_contract.functional.engine import ScenarioExecutionError

        self.assertEqual(
            _finalization_error(
                ScenarioExecutionError("ANDROID_DIAGNOSTICS_FAILED"),
                ScenarioExecutionError("ANDROID_CLEANUP_FAILED"),
            ).reason_code,
            "ANDROID_FINALIZATION_FAILED",
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

    def test_binary_staging_disables_pty_allocation(self) -> None:
        runner = InputAndroidRunner(Path(self.directory.name) / "input-raw")
        adapter = AndroidHostedAdapter(
            runner=runner,
            profile=self.profile,
            adb=self.adb,
            source_sha=_SOURCE_SHA,
            identity_url="https://identity.example.test/ip",
            latency_url="https://latency.example.test/blob",
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.configure"), adapter, _provenance(adapter)
        )
        self.assertEqual(result.outcome, "passed")
        staged = [
            call for call in runner.calls
            if len(call) > 5 and call[1:4] == ("shell", "-T", "run-as")
        ]
        self.assertGreaterEqual(len(staged), 2)
        self.assertTrue(all(call[2] == "-T" for call in staged))
        self.assertIn("mkdir -p files && cat > files/", staged[0][-1])

    def test_nonempty_logcat_timeout_is_retained_without_masking_product_result(self) -> None:
        runner = PartialLogcatRunner(Path(self.directory.name) / "partial-logcat-raw")
        adapter = AndroidHostedAdapter(
            runner=runner,
            profile=self.profile,
            adb=self.adb,
            source_sha=_SOURCE_SHA,
            identity_url="https://identity.example.test/ip",
            latency_url="https://latency.example.test/blob",
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.configure"), adapter, _provenance(adapter)
        )
        self.assertEqual(result.outcome, "passed")

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
            "--platform-version", "35",
            "--candidate-manifest", __file__, "--server-image-digest", "sha256:" + "b" * 64,
            "--output", str(Path(self.directory.name) / "result.json"),
            "--adb", "/synthetic/adb", "--identity-url", "https://identity.example.test/ip",
            "--latency-url", "https://latency.example.test/blob",
        ])
        self.assertIsNone(parsed.cli)

if __name__ == "__main__":
    unittest.main()
