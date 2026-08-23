from __future__ import annotations

import os
import socket
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from torturer_checks.hosted.android import AndroidHostedAdapter
from torturer_checks.hosted.cli import CommandResult, HostedAdapterError, HostedCLIAdapter, SubprocessRunner
from torturer_checks.hosted.linux import (
    LinuxHostedAdapter,
    LinuxServiceProcessController,
    _SERVICE_LAUNCH_SCRIPT,
)
from torturer_checks.hosted.macos import MacOSHostedAdapter
from torturer_checks.hosted.windows import WindowsHostedAdapter
from torturer_checks.hosted.run import (
    _partition_applicable,
    _run_scenarios,
    _select_scenarios,
    build_parser,
)
from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import FunctionalEngine, ScenarioExecutionError
from torturer_contract.functional.scenarios import ScenarioStep, get_scenario, scenario_catalog


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[float] = []
        self.connected = False
        self.external_calls = 0
        self.restore_identity = True
        self.baseline_ip = b"198.51.100.10\n"
        self.disconnected_ip = b"198.51.100.10\n"

    def run(self, command, *, timeout_seconds):
        argv = tuple(command)
        self.calls.append(argv)
        self.timeouts.append(float(timeout_seconds))
        if argv[0] == "curl":
            return CommandResult(argv, 0, b"0.25\t1000000\n", b"curl diagnostic\n")
        if argv[0] == "sudo":
            return CommandResult(argv, 0, b"sudo diagnostic\n", b"")
        operation = argv[1]
        if operation == "check-config":
            return CommandResult(argv, 0, b"profiles=1 source=file\n", b"")
        if operation == "connect-profile":
            self.connected = True
            return CommandResult(argv, 0, b"CONNECTED\n", b"")
        if operation == "status":
            state = b"Connected" if self.connected else b"Disconnected"
            return CommandResult(argv, 0, b'{"code":%d,"state":"%s"}\n' % (2 if self.connected else 0, state), b"")
        if operation == "external-ip":
            self.external_calls += 1
            if self.external_calls == 1:
                value = self.baseline_ip
            elif not self.connected and self.restore_identity:
                value = self.disconnected_ip
            else:
                value = b"203.0.113.10\n"
            return CommandResult(argv, 0, value, b"")
        if operation == "disconnect":
            self.connected = False
            return CommandResult(argv, 0, b"DISCONNECTED\n", b"")
        raise AssertionError(argv)


class HostedCLIAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="hosted-cli-adapter-")
        root = Path(self.directory.name)
        self.cli = root / "dobby-cli"
        self.cli.write_bytes(b"synthetic executable")
        os.chmod(self.cli, 0o700)
        self.profile = root / "profile.toml"
        self.profile.write_text("[[Outline]]\nPassword = \"synthetic\"\n", encoding="utf-8")
        os.chmod(self.profile, 0o600)
        self.runner = FakeRunner()
        self.runner.raw_directory = root / "runner-raw"
        self.adapter = HostedCLIAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        self.addCleanup(self.directory.cleanup)

    def test_common_operations_are_observations_not_assertions(self) -> None:
        self.assertTrue({Capability.CONFIGURE, Capability.CONNECT, Capability.TUNNEL_INTERFACE,
                         Capability.ROUTING_IDENTITY, Capability.DISCONNECT,
                         Capability.RESOURCE_CLEANUP} <= self.adapter.capabilities)
        scenario = get_scenario("functional.connect-route-identity")
        engine = FunctionalEngine(scenario_set_digest="a" * 64)
        result = engine.run(scenario, self.adapter, _provenance(self.adapter))
        self.assertEqual(result.outcome, "passed")
        self.assertTrue(any(call[1] == "connect-profile" for call in self.runner.calls))
        self.adapter.reset()
        self.assertFalse(self.runner.connected)

    def test_windows_and_macos_use_the_same_canonical_cli_scenarios(self) -> None:
        scenario = get_scenario("functional.connect-route-identity")
        for adapter_class, expected_id in (
            (WindowsHostedAdapter, "hosted-windows-cli"),
            (MacOSHostedAdapter, "hosted-macos-cli"),
        ):
            runner = FakeRunner()
            adapter = adapter_class(cli=self.cli, profile=self.profile, runner=runner)
            self.assertEqual(adapter.adapter_id, expected_id)
            result = FunctionalEngine("f" * 64).run(scenario, adapter, _provenance(adapter))
            self.assertEqual(result.outcome, "passed")

    def test_reconnect_reuses_public_cli_and_leaves_clean_baseline(self) -> None:
        self.assertIn(Capability.RECONNECT, self.adapter.capabilities)
        result = FunctionalEngine("d" * 64).run(
            get_scenario("functional.start-stop-start"),
            self.adapter,
            _provenance(self.adapter),
        )
        self.assertEqual(result.outcome, "passed")
        self.assertTrue(result.cleanup["verified"])
        reconnect_index = next(
            index for index, call in enumerate(self.runner.calls)
            if call[1] == "connect-profile" and index > 4
        )
        disconnects = [
            index for index, call in enumerate(self.runner.calls) if call[1] == "disconnect"
        ]
        self.assertEqual(len(disconnects), 2)
        self.assertLess(disconnects[0], reconnect_index)
        self.assertGreater(disconnects[1], reconnect_index)
        self.assertFalse(self.runner.connected)

    def test_reconnect_operation_is_bounded_and_returns_safe_observations(self) -> None:
        observations = self.adapter.execute(
            ScenarioStep(id="reconnect", operation="reconnect", timeout_seconds=5)
        )
        self.assertEqual(observations, {"restart_verified": True, "reconnect_bounded": True})
        self.assertTrue(self.runner.connected)

    def test_cleanup_scenario_proves_disconnect_and_cleanup(self) -> None:
        scenario = get_scenario("functional.disconnect-cleanup")
        engine = FunctionalEngine(scenario_set_digest="b" * 64)
        result = engine.run(scenario, self.adapter, _provenance(self.adapter))
        self.assertEqual(result.outcome, "passed")
        self.assertTrue(result.cleanup["verified"])

    def test_disconnect_accepts_a_rotated_non_tunnel_host_identity(self) -> None:
        self.runner.disconnected_ip = b"198.51.100.11\n"
        scenario = get_scenario("functional.disconnect-cleanup")
        result = FunctionalEngine(scenario_set_digest="a" * 64).run(
            scenario, self.adapter, _provenance(self.adapter)
        )
        self.assertEqual(result.outcome, "passed")
        self.assertTrue(result.cleanup["verified"])
        self.assertNotEqual(self.runner.baseline_ip, self.runner.disconnected_ip)

    def test_disconnect_fails_when_status_is_clean_but_identity_is_not_restored(self) -> None:
        self.runner.restore_identity = False
        scenario = get_scenario("functional.disconnect-cleanup")
        result = FunctionalEngine(scenario_set_digest="a" * 64).run(
            scenario, self.adapter, _provenance(self.adapter)
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "ASSERTION_FAILED")
        self.assertFalse(
            any(
                assertion.id == "disconnect.clean" and assertion.passed
                for assertion in result.assertions
            )
        )

    def test_linux_network_transition_requires_and_uses_explicit_interface(self) -> None:
        adapter = LinuxHostedAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner, network_interface="eth0"
        )
        self.assertIn(Capability.NETWORK_TRANSITION, adapter.capabilities)
        adapter.execute(ScenarioStep(id="connect", operation="connect", timeout_seconds=5))
        adapter.execute(ScenarioStep(id="tunnel", operation="observe_tunnel", timeout_seconds=5))
        adapter.execute(ScenarioStep(id="routing", operation="observe_routing_identity", timeout_seconds=5))
        result = adapter.execute(ScenarioStep(id="network", operation="network_transition", timeout_seconds=5))
        self.assertEqual(result, {"network_transition_verified": True})

    def test_linux_endurance_is_url_gated_and_bounded(self) -> None:
        adapter = LinuxHostedAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        self.assertIn(Capability.ENDURANCE, adapter.capabilities)
        adapter.execute(ScenarioStep(id="connect", operation="connect", timeout_seconds=5))
        result = adapter.execute(ScenarioStep(id="endurance", operation="measure_endurance", timeout_seconds=1))
        self.assertTrue(result["endurance_verified"])
        self.assertGreater(float(result["download_mbps"]), 0)
        self.assertGreater(float(result["upload_mbps"]), 0)

    def test_linux_endurance_does_not_start_a_partial_tail_transfer(self) -> None:
        adapter = LinuxHostedAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        metrics = {"latency_ms": 1.0, "download_mbps": 2.0, "upload_mbps": 3.0}
        with (
            mock.patch.object(adapter, "_connected", return_value=True),
            mock.patch.object(adapter, "_routing_identity_changed", return_value=True),
            mock.patch.object(adapter, "_throughput", return_value=metrics) as throughput,
            mock.patch(
                "torturer_checks.hosted.linux.time.monotonic",
                side_effect=[100.0, 100.0, 101.0, 159.0, 159.5],
            ),
            mock.patch("torturer_checks.hosted.linux.time.sleep") as sleep,
        ):
            result = adapter._endurance(60.0)

        self.assertEqual(result, {"endurance_verified": True, **metrics})
        throughput.assert_called_once_with(30.0)
        self.assertEqual(sleep.call_args_list, [mock.call(1.0), mock.call(0.5)])

    def test_linux_endurance_rejects_zero_complete_samples(self) -> None:
        adapter = LinuxHostedAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        with mock.patch("torturer_checks.hosted.linux.time.monotonic", side_effect=[100.0, 100.0]):
            with self.assertRaisesRegex(ScenarioExecutionError, "ENDURANCE_NO_COMPLETE_SAMPLE"):
                adapter._endurance(0.0)

    def test_hosted_runner_can_select_a_bounded_canonical_subset(self) -> None:
        parsed = build_parser().parse_args([
            "--platform", "linux", "--cli", str(self.cli), "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN", "--source-sha", "a" * 40,
            "--artifact", str(self.cli), "--server-image-digest", "sha256:" + "b" * 64,
            "--output", str(self.directory.name + "/result.json"), "--scenario-id",
            "functional.configure", "--scenario-id", "functional.disconnect-cleanup",
        ])
        self.assertEqual(parsed.scenario_ids, ["functional.configure", "functional.disconnect-cleanup"])

    def test_hosted_runner_accounts_for_one_reset_after_every_selected_scenario(self) -> None:
        scenarios = _select_scenarios([
            "functional.core-connection",
            "functional.start-stop-start",
        ])
        results, reset_failures, reset_count = _run_scenarios(
            FunctionalEngine("1" * 64), scenarios, self.adapter, _provenance(self.adapter)
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(reset_count, 2)
        self.assertEqual(reset_failures, [])

    def test_hosted_runner_runs_the_complete_catalog_inside_the_lane_bound(self) -> None:
        selected = _select_scenarios(None)
        self.assertEqual(selected, scenario_catalog())
        total_seconds = sum(item.max_duration_seconds for item in selected) + 5 * len(selected)
        self.assertEqual(total_seconds, 1190)

    def test_default_lane_partitions_all_applicable_and_unsupported_scenarios(self) -> None:
        selected = _select_scenarios(None)
        applicable, unsupported = _partition_applicable(selected, self.adapter.capabilities)
        self.assertEqual(
            len(applicable) + len(unsupported),
            len(selected),
        )
        self.assertIn(
            "functional.connect-route-identity",
            {scenario.id for scenario in applicable},
        )
        unsupported_ids = {item["scenario_id"] for item in unsupported}
        self.assertIn("functional.sleep-wake", unsupported_ids)
        self.assertIn("functional.network-transition", unsupported_ids)
        self.assertIn("functional.bounded-endurance", unsupported_ids)

    def test_hosted_runner_accepts_all_feasible_cli_scenarios_in_one_lane(self) -> None:
        selected = _select_scenarios([
            "functional.core-connection",
            "functional.start-stop-start",
        ])
        self.assertEqual(len(selected), 2)

    def test_android_entrypoint_is_fail_closed_without_profile_session_api(self) -> None:
        adapter = AndroidHostedAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        self.assertEqual(adapter.capabilities, frozenset())
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.configure"), adapter, _provenance(adapter)
        )
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(result.reason_code, "CAPABILITY_UNAVAILABLE")

    def test_unsupported_capabilities_are_explicitly_unavailable(self) -> None:
        scenario = get_scenario("functional.sleep-wake")
        engine = FunctionalEngine(scenario_set_digest="c" * 64)
        result = engine.run(scenario, self.adapter, _provenance(self.adapter))
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(result.reason_code, "CAPABILITY_UNAVAILABLE")

    def test_throughput_probe_keeps_curl_diagnostics_visible(self) -> None:
        adapter = HostedCLIAdapter(
            cli=self.cli,
            profile=self.profile,
            runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        metrics = adapter._throughput(5)
        self.assertEqual(metrics["latency_ms"], 250.0)
        curl_calls = [call for call in self.runner.calls if call[0] == "curl"]
        self.assertEqual(len(curl_calls), 2)
        self.assertNotIn("--silent", curl_calls[0])
        self.assertIn("--show-error", curl_calls[0])
        self.assertIn("--output", curl_calls[0])
        self.assertEqual(curl_calls[0][curl_calls[0].index("--output") + 1], os.devnull)
        self.assertIn("--upload-file", curl_calls[1])
        self.assertIn("--request", curl_calls[1])
        self.assertEqual(curl_calls[1][curl_calls[1].index("--request") + 1], "POST")

    def test_connect_commands_share_one_step_deadline(self) -> None:
        with mock.patch(
            "torturer_checks.hosted.cli.time.monotonic",
            side_effect=[100.0, 101.0, 102.0],
        ):
            self.adapter.execute(
                ScenarioStep(id="connect", operation="connect", timeout_seconds=10)
            )
        self.assertEqual(self.runner.timeouts, [9.0, 8.0])

    def test_throughput_commands_share_one_step_deadline(self) -> None:
        adapter = HostedCLIAdapter(
            cli=self.cli,
            profile=self.profile,
            runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        with mock.patch(
            "torturer_checks.hosted.cli.time.monotonic",
            side_effect=[100.0, 101.0, 102.0],
        ):
            adapter._throughput(10)
        self.assertEqual(self.runner.timeouts, [9.0, 8.0])

    def test_linux_process_loss_commands_share_one_step_deadline(self) -> None:
        class FakeService:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def restart_after_loss(self, timeout: float) -> None:
                self.timeouts.append(timeout)

        adapter = LinuxHostedAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        service = FakeService()
        adapter.service = service  # type: ignore[assignment]
        adapter._baseline_ip = "198.51.100.10"
        self.runner.external_calls = 1
        with mock.patch(
            "torturer_checks.hosted.linux.time.monotonic",
            side_effect=[100.0, 101.0, 102.0, 103.0, 104.0],
        ):
            result = adapter._process_loss(10)
        self.assertEqual(result, {"process_loss_verified": True})
        self.assertEqual(service.timeouts, [9.0])
        self.assertEqual(self.runner.timeouts, [8.0, 7.0, 6.0])

    def test_linux_restart_launcher_tracks_exact_child_pid(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        library = root / "library"
        library.mkdir()
        socket_path = root / "control.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        self.addCleanup(listener.close)
        pid_file = root / "service.pid"
        raw_directory = root / "service-raw"

        class ServiceRunner:
            def __init__(self) -> None:
                self.calls: list[tuple[str, ...]] = []

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                self.calls.append(argv)
                if len(argv) >= 5 and argv[2:5] == ("sh", "-c", _SERVICE_LAUNCH_SCRIPT):
                    return CommandResult(argv, 0, b"456\n", b"")
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(
                        argv,
                        0,
                        (str(binary.resolve()) + "\n").encode(),
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0, b"", b"")
                raise AssertionError(argv)

        runner = ServiceRunner()
        controller = LinuxServiceProcessController(
            pid=123,
            binary=binary,
            socket=socket_path,
            library_path=library,
            pid_file=pid_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        with mock.patch(
            "torturer_checks.hosted.linux.time.monotonic",
            side_effect=[100.0, 101.0, 102.0, 103.0],
        ):
            controller._start(10.0)

        self.assertEqual(controller.pid, 456)
        self.assertEqual(pid_file.read_text(encoding="ascii"), "456\n")
        launcher = next(
            call
            for call in runner.calls
            if len(call) >= 5 and call[2:5] == ("sh", "-c", _SERVICE_LAUNCH_SCRIPT)
        )
        self.assertEqual(
            launcher[:5],
            ("sudo", "-n", "sh", "-c", _SERVICE_LAUNCH_SCRIPT),
        )
        self.assertEqual(launcher[5], "dobbyvpn-service")
        self.assertEqual(launcher[6], str(binary))
        self.assertEqual(launcher[7], str(socket_path))
        self.assertEqual(launcher[9], str(library))

    def test_subprocess_runner_retains_complete_stdout_and_stderr_bytes(self) -> None:
        raw = Path(self.directory.name) / "raw"
        runner = SubprocessRunner(raw)
        result = runner.run(
            ("python3", "-c", "import sys; sys.stdout.buffer.write(b'198.51.100.10\\n'); sys.stderr.buffer.write(b'err\\n')"),
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        retained = (raw / "command-001.raw.log").read_bytes()
        self.assertIn(b"198.51.100.10\n", retained)
        self.assertIn(b"err\n", retained)
        evidence = runner.safe_evidence()
        self.assertEqual(evidence[0]["returncode"], 0)
        self.assertEqual(evidence[0]["stdout_bytes"], 14)
        self.assertNotIn("198.51.100.10", repr(evidence[0]))
        self.assertNotIn("stdout_sha256", evidence[0])
        self.assertNotIn("stderr_sha256", evidence[0])
        self.assertNotIn("python3", repr(evidence[0]))

    def test_profile_must_be_owner_only(self) -> None:
        os.chmod(self.profile, 0o640)
        with self.assertRaisesRegex(HostedAdapterError, "PROFILE_NOT_OWNER_ONLY"):
            HostedCLIAdapter(cli=self.cli, profile=self.profile, runner=self.runner)


def _provenance(adapter: HostedCLIAdapter):
    from torturer_contract.functional.results import RunProvenance
    return RunProvenance(
        source_repository="DobbyVPN/DobbyVPN",
        source_sha="1" * 40,
        torturer_sha="2" * 40,
        artifact_sha256="3" * 64,
        server_image_digest="sha256:" + "4" * 64,
        platform="linux",
        adapter_id=adapter.adapter_id,
        adapter_version=adapter.adapter_version,
        capabilities=frozenset(item.value for item in adapter.capabilities),
    )


if __name__ == "__main__":
    unittest.main()
