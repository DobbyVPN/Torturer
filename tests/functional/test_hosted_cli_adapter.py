from __future__ import annotations

import contextlib
import copy
import gc
import hashlib
import io
import os
import signal
import socket
from pathlib import Path
import subprocess
import tempfile
import sys
import time
import unittest
import warnings
from unittest import mock

import torturer_checks.hosted.run as hosted_run
from torturer_checks.hosted.android import AndroidHostedAdapter
from torturer_checks.hosted.cli import (
    CommandResult,
    HostedAdapterError,
    HostedCLIAdapter,
    SubprocessRunner,
    _ProcessSnapshotProvider,
    _ProcessIdentity,
    _ProcessProbeError,
    _direct_tree_status,
    _identity_live,
    _linux_child_pids,
    _tree_status,
    _bounded_reap_process,
    _bounded_capture,
    _consume_subreaper_status,
    _parse_macos_process_snapshot,
)
from torturer_checks.hosted.linux import (
    LinuxHostedAdapter,
    LinuxServiceProcessController,
    _SERVICE_LAUNCH_SCRIPT,
    _parse_linux_process_census,
)
from torturer_checks.hosted.factory import (
    adapter_for_platform,
    disposable_measurement_endpoints,
)
from torturer_checks.hosted.macos import MacOSHostedAdapter
from torturer_checks.hosted.windows import WindowsHostedAdapter
from torturer_checks.hosted.run import (
    EXPECTED_UNAVAILABLE_BY_PLATFORM,
    _coverage_contract,
    _diagnostic_code,
    _expected_unavailable,
    _finalize_adapter,
    _partition_applicable,
    _qualification_exit_code,
    _run_scenarios,
    _select_scenarios,
    build_parser,
)
from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import (
    CapabilityUnavailable,
    FunctionalEngine,
    ScenarioExecutionError,
)
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


class SequencedIdentityRunner(FakeRunner):
    """Return exact external identities in order, then repeat the last one."""

    def __init__(
        self, identities: list[bytes], *, disconnected_status_delay: int = 0
    ) -> None:
        super().__init__()
        if not identities:
            raise ValueError("identity sequence must not be empty")
        self.identities = identities
        self.disconnected_status_delay = disconnected_status_delay

    def run(self, command, *, timeout_seconds):
        argv = tuple(command)
        if (
            len(argv) > 1
            and argv[1] == "status"
            and not self.connected
            and self.disconnected_status_delay > 0
        ):
            self.calls.append(argv)
            self.timeouts.append(float(timeout_seconds))
            self.disconnected_status_delay -= 1
            return CommandResult(argv, 0, b'{"code":2,"state":"Connected"}\n', b"")
        if len(argv) > 1 and argv[1] == "external-ip":
            self.calls.append(argv)
            self.timeouts.append(float(timeout_seconds))
            index = min(self.external_calls, len(self.identities) - 1)
            self.external_calls += 1
            return CommandResult(argv, 0, self.identities[index], b"")
        return super().run(command, timeout_seconds=timeout_seconds)


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

    def test_disposable_upload_url_derives_all_test_owned_probe_endpoints(self) -> None:
        token = "a" * 32
        endpoints = disposable_measurement_endpoints(
            f"https://sink.example.onrender.com/upload/{token}"
        )
        self.assertEqual(
            endpoints.identity_url,
            f"https://sink.example.onrender.com/identity/{token}",
        )
        self.assertEqual(
            endpoints.latency_url,
            f"https://sink.example.onrender.com/download/{token}",
        )
        self.assertEqual(endpoints.download_url, endpoints.latency_url)

    def test_disposable_endpoint_derivation_rejects_noncanonical_urls(self) -> None:
        for invalid in (
            "http://sink.example.onrender.com/upload/" + "a" * 32,
            "https://sink.example.onrender.com/upload/" + "a" * 31,
            "https://sink.example.onrender.com/upload/" + "A" * 32,
            "https://sink.example.onrender.com/upload/" + "a" * 32 + "?x=1",
            "https://user@sink.example.onrender.com/upload/" + "a" * 32,
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "disposable upload URL is invalid"):
                    disposable_measurement_endpoints(invalid)

    def test_desktop_identity_probe_can_use_disposable_test_endpoint(self) -> None:
        token = "a" * 32

        class IdentityRunner(FakeRunner):
            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                if argv[0] == "curl":
                    self.calls.append(argv)
                    self.timeouts.append(float(timeout_seconds))
                    return CommandResult(argv, 0, b"203.0.113.42\n", b"identity diagnostic\n")
                return super().run(command, timeout_seconds=timeout_seconds)

        runner = IdentityRunner()
        adapter = HostedCLIAdapter(
            cli=self.cli,
            profile=self.profile,
            runner=runner,
            identity_url=f"https://sink.example.onrender.com/identity/{token}",
        )
        self.assertEqual(adapter._external_ip(5), "203.0.113.42")
        self.assertEqual(runner.calls[0][0], "curl")
        self.assertIn("--show-error", runner.calls[0])
        self.assertNotIn("--silent", runner.calls[0])

    def test_routing_identity_waits_for_convergence_without_classifying_baseline_as_tunnel(self) -> None:
        baseline = b"198.51.100.10\n"
        tunneled = b"203.0.113.10\n"
        runner = SequencedIdentityRunner([baseline, baseline, tunneled])
        adapter = HostedCLIAdapter(cli=self.cli, profile=self.profile, runner=runner)

        adapter.execute(ScenarioStep(id="connect", operation="connect", timeout_seconds=5))
        with mock.patch("torturer_checks.hosted.cli.time.sleep") as sleep:
            result = adapter.execute(
                ScenarioStep(
                    id="routing",
                    operation="observe_routing_identity",
                    timeout_seconds=5,
                )
            )

        self.assertEqual(result, {"routing_identity_changed": True})
        self.assertEqual(adapter._tunneled_ips, {"203.0.113.10"})
        self.assertEqual(runner.external_calls, 3)
        sleep.assert_called_once()

    def test_disconnect_waits_for_status_and_route_restoration(self) -> None:
        baseline = b"198.51.100.10\n"
        tunneled = b"203.0.113.10\n"
        runner = SequencedIdentityRunner(
            [baseline, tunneled, tunneled, baseline],
            disconnected_status_delay=1,
        )
        adapter = HostedCLIAdapter(cli=self.cli, profile=self.profile, runner=runner)

        adapter.execute(ScenarioStep(id="connect", operation="connect", timeout_seconds=5))
        adapter.execute(
            ScenarioStep(
                id="routing",
                operation="observe_routing_identity",
                timeout_seconds=5,
            )
        )
        with mock.patch("torturer_checks.hosted.cli.time.sleep") as sleep:
            result = adapter.execute(
                ScenarioStep(id="disconnect", operation="disconnect", timeout_seconds=5)
            )

        self.assertEqual(result, {"disconnect_clean": True})
        self.assertEqual(runner.external_calls, 4)
        self.assertEqual(sum(call[1] == "status" for call in runner.calls), 3)
        self.assertEqual(sleep.call_count, 2)

    def test_routing_convergence_returns_false_at_exact_deadline(self) -> None:
        runner = SequencedIdentityRunner([b"198.51.100.10\n"])
        adapter = HostedCLIAdapter(cli=self.cli, profile=self.profile, runner=runner)
        adapter._baseline_ip = "198.51.100.10"

        with (
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic",
                side_effect=[100.0, 100.1, 105.0],
            ),
            mock.patch("torturer_checks.hosted.cli.time.sleep") as sleep,
        ):
            self.assertFalse(adapter._wait_for_routing_identity_changed(5.0))

        self.assertEqual(adapter._tunneled_ips, set())
        self.assertEqual(runner.external_calls, 1)
        sleep.assert_not_called()

    def test_factory_derives_test_owned_endpoints_for_every_desktop(self) -> None:
        token = "a" * 32
        upload_url = f"https://sink.example.onrender.com/upload/{token}"
        for platform, expected_type in (
            ("linux", LinuxHostedAdapter),
            ("windows", WindowsHostedAdapter),
            ("macos", MacOSHostedAdapter),
        ):
            with self.subTest(platform=platform):
                adapter = adapter_for_platform(
                    platform,
                    cli=self.cli,
                    profile=self.profile,
                    runner=FakeRunner(),
                    upload_url=upload_url,
                )
                self.assertIsInstance(adapter, expected_type)
                self.assertEqual(
                    adapter.identity_url,
                    f"https://sink.example.onrender.com/identity/{token}",
                )
                self.assertEqual(
                    adapter.download_url,
                    f"https://sink.example.onrender.com/download/{token}",
                )

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

    def test_hosted_desktop_unsafe_gaps_have_platform_reason_codes(self) -> None:
        windows = WindowsHostedAdapter(cli=self.cli, profile=self.profile, runner=FakeRunner())
        macos = MacOSHostedAdapter(cli=self.cli, profile=self.profile, runner=FakeRunner())
        linux = LinuxHostedAdapter(cli=self.cli, profile=self.profile, runner=FakeRunner())
        self.assertEqual(
            windows.capability_unavailable_reasons[Capability.NETWORK_TRANSITION],
            "HOSTED_WINDOWS_UPLINK_TOGGLE_UNSUPPORTED",
        )
        self.assertEqual(
            macos.capability_unavailable_reasons[Capability.NETWORK_TRANSITION],
            "HOSTED_MACOS_UPLINK_TOGGLE_UNSUPPORTED",
        )
        self.assertEqual(
            linux.capability_unavailable_reasons[Capability.NETWORK_TRANSITION],
            "HOSTED_LINUX_INTERFACE_REQUIRED",
        )

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

        class Clock:
            now = 100.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, seconds: float) -> None:
                self.now += seconds

        clock = Clock()
        with (
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic", side_effect=clock.monotonic
            ),
            mock.patch("torturer_checks.hosted.cli.time.sleep", side_effect=clock.sleep),
        ):
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

    def test_linux_network_transition_is_unavailable_without_exact_interface(self) -> None:
        adapter = LinuxHostedAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        self.assertNotIn(Capability.NETWORK_TRANSITION, adapter.capabilities)
        with self.assertRaises(CapabilityUnavailable):
            adapter.execute(
                ScenarioStep(id="network", operation="network_transition", timeout_seconds=5)
            )

    def test_linux_explicit_interface_keeps_all_ten_catalog_ids_and_applies_network_transition(self) -> None:
        adapter = LinuxHostedAdapter(
            cli=self.cli,
            profile=self.profile,
            runner=self.runner,
            network_interface="eth0",
        )
        selected = _select_scenarios(None)
        self.assertEqual(len(selected), 10)
        self.assertEqual(
            {scenario.id for scenario in selected},
            {scenario.id for scenario in scenario_catalog()},
        )
        applicable, unsupported = _partition_applicable(selected, adapter.capabilities)
        self.assertIn("functional.network-transition", {scenario.id for scenario in applicable})
        self.assertNotIn(
            "functional.network-transition",
            {item["scenario_id"] for item in unsupported},
        )
        network_result = FunctionalEngine("1" * 64).run(
            get_scenario("functional.network-transition"),
            adapter,
            _provenance(adapter),
        )
        self.assertEqual(network_result.outcome, "passed")

    def test_linux_sleep_wake_is_explicitly_unavailable_with_stable_reason(self) -> None:
        adapter = LinuxHostedAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        scenario = get_scenario("functional.sleep-wake")
        self.assertNotIn(Capability.SLEEP_WAKE, adapter.capabilities)
        self.assertEqual(
            adapter.capability_unavailable_reasons,
            {
                Capability.NETWORK_TRANSITION: "HOSTED_LINUX_INTERFACE_REQUIRED",
                Capability.SLEEP_WAKE: "HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
                Capability.PROCESS_LOSS: "HOSTED_SERVICE_CONTROL_UNAVAILABLE",
            },
        )
        result = FunctionalEngine("1" * 64).run(
            scenario,
            adapter,
            _provenance(adapter),
        )
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(result.reason_code, "HOSTED_RUNNER_SUSPEND_UNSUPPORTED")

    def test_linux_partition_uses_capability_reason_without_string_key_mismatch(self) -> None:
        adapter = LinuxHostedAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        _, unsupported = _partition_applicable(
            (get_scenario("functional.sleep-wake"),),
            adapter.capabilities,
            adapter.capability_unavailable_reasons,
        )
        self.assertEqual(
            unsupported,
            [{
                "scenario_id": "functional.sleep-wake",
                "missing_capabilities": ["sleep_wake"],
                "reason_code": "HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
            }],
        )

    def test_engine_keeps_runtime_unavailability_generic_when_capability_was_advertised(self) -> None:
        scenario = get_scenario("functional.sleep-wake")

        class RuntimeUnavailableAdapter:
            adapter_id = "runtime-unavailable"
            adapter_version = "v1"
            capabilities = scenario.required_capabilities
            capability_unavailable_reasons = {
                Capability.SLEEP_WAKE: "HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
            }

            def execute(self, step):
                raise CapabilityUnavailable()

        adapter = RuntimeUnavailableAdapter()
        result = FunctionalEngine("1" * 64).run(
            scenario,
            adapter,
            _provenance(adapter),
        )
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(result.reason_code, "CAPABILITY_UNAVAILABLE")

    def test_shared_desktop_endurance_is_url_gated_and_bounded(self) -> None:
        adapter = HostedCLIAdapter(
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
        for adapter_class in (LinuxHostedAdapter, WindowsHostedAdapter, MacOSHostedAdapter):
            with self.subTest(adapter=adapter_class.__name__):
                desktop = adapter_class(
                    cli=self.cli, profile=self.profile, runner=FakeRunner(),
                    download_url="https://download.example.test/blob",
                    upload_url="https://upload.example.test/blob",
                )
                self.assertIn(Capability.ENDURANCE, desktop.capabilities)

    def test_shared_desktop_endurance_does_not_start_a_partial_tail_transfer(self) -> None:
        adapter = HostedCLIAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        metrics = {"latency_ms": 1.0, "download_mbps": 2.0, "upload_mbps": 3.0}
        with (
            mock.patch.object(adapter, "_connected", return_value=True),
            mock.patch.object(
                adapter, "_wait_for_routing_identity_changed", return_value=True
            ),
            mock.patch.object(adapter, "_throughput", return_value=metrics) as throughput,
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic",
                side_effect=[100.0, 100.0, 101.0, 102.0, 159.0, 159.5],
            ),
            mock.patch("torturer_checks.hosted.linux.time.sleep") as sleep,
        ):
            result = adapter._endurance(60.0)

        self.assertEqual(result, {"endurance_verified": True, **metrics})
        throughput.assert_called_once_with(30.0)
        self.assertEqual(sleep.call_args_list, [mock.call(1.0), mock.call(0.5)])

    def test_shared_desktop_endurance_rejects_zero_complete_samples(self) -> None:
        adapter = HostedCLIAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        with mock.patch("torturer_checks.hosted.cli.time.monotonic", side_effect=[100.0, 100.0]):
            with self.assertRaisesRegex(ScenarioExecutionError, "ENDURANCE_NO_COMPLETE_SAMPLE"):
                adapter._endurance(0.0)

    def test_shared_desktop_endurance_retries_one_transient_transfer_failure(self) -> None:
        adapter = HostedCLIAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        metrics = {"latency_ms": 1.0, "download_mbps": 2.0, "upload_mbps": 3.0}
        with (
            mock.patch.object(adapter, "_connected", return_value=True),
            mock.patch.object(
                adapter, "_wait_for_routing_identity_changed", return_value=True
            ),
            mock.patch.object(
                adapter,
                "_throughput",
                side_effect=[ScenarioExecutionError("THROUGHPUT_FAILED"), metrics],
            ) as throughput,
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic",
                side_effect=[100.0, 100.0, 100.5, 101.0, 102.0, 159.5, 159.75, 160.0],
            ),
            mock.patch("torturer_checks.hosted.cli.time.sleep") as sleep,
        ):
            result = adapter._endurance(60.0)

        self.assertEqual(result, {"endurance_verified": True, **metrics})
        self.assertEqual(throughput.call_args_list, [mock.call(30.0), mock.call(30.0)])
        self.assertEqual(sleep.call_args_list, [mock.call(1.0), mock.call(0.25)])

    def test_shared_desktop_endurance_fails_after_two_transfer_failures(self) -> None:
        adapter = HostedCLIAdapter(
            cli=self.cli, profile=self.profile, runner=self.runner,
            download_url="https://download.example.test/blob",
            upload_url="https://upload.example.test/blob",
        )
        with (
            mock.patch.object(adapter, "_connected", return_value=True),
            mock.patch.object(
                adapter, "_wait_for_routing_identity_changed", return_value=True
            ),
            mock.patch.object(
                adapter,
                "_throughput",
                side_effect=ScenarioExecutionError("THROUGHPUT_FAILED"),
            ) as throughput,
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic",
                side_effect=[100.0, 100.0, 100.5, 101.0, 102.0],
            ),
            mock.patch("torturer_checks.hosted.cli.time.sleep"),
        ):
            with self.assertRaisesRegex(ScenarioExecutionError, "THROUGHPUT_FAILED"):
                adapter._endurance(60.0)

        self.assertEqual(throughput.call_count, 2)

    def test_hosted_runner_can_select_a_bounded_canonical_subset(self) -> None:
        parsed = build_parser().parse_args([
            "--platform", "linux", "--cli", str(self.cli), "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN", "--source-sha", "a" * 40,
            "--platform-version", "24.04",
            "--candidate-manifest", str(self.cli), "--server-image-digest", "sha256:" + "b" * 64,
            "--lane-timeout-seconds", "1800",
            "--output", str(self.directory.name + "/result.json"), "--scenario-id",
            "functional.configure", "--scenario-id", "functional.disconnect-cleanup",
            "--expected-unavailable",
            "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
        ])
        self.assertEqual(parsed.scenario_ids, ["functional.configure", "functional.disconnect-cleanup"])
        self.assertEqual(
            parsed.expected_unavailable,
            ["functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED"],
        )

    def test_hosted_lane_timeout_is_required_and_strict(self) -> None:
        arguments = [
            "--platform", "linux",
            "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN",
            "--source-sha", "a" * 40,
            "--platform-version", "24.04",
            "--candidate-manifest", str(self.cli),
            "--server-image-digest", "sha256:" + "b" * 64,
            "--output", str(self.directory.name + "/result.json"),
        ]
        with self.assertRaises(SystemExit):
            build_parser().parse_args(arguments)
        for value in ("0", "-1", "1800.1", "nan", "inf"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                build_parser().parse_args(arguments + ["--lane-timeout-seconds", value])
        parsed = build_parser().parse_args(
            arguments + ["--lane-timeout-seconds", "1800"]
        )
        self.assertEqual(parsed.lane_timeout_seconds, 1800.0)

    def test_hosted_lane_timeout_accounts_for_reset_and_finalization_tail(self) -> None:
        with self.assertRaisesRegex(ValueError, "requested lane bound"):
            _select_scenarios(["functional.configure"], lane_timeout_seconds=54)
        self.assertEqual(
            len(_select_scenarios(["functional.configure"], lane_timeout_seconds=55)),
            1,
        )
        with self.assertRaisesRegex(ValueError, "requested lane bound"):
            _select_scenarios(None, lane_timeout_seconds=1231)
        self.assertEqual(
            _select_scenarios(None, lane_timeout_seconds=1232),
            scenario_catalog(),
        )

    def test_hosted_lane_budget_uses_platform_capabilities_and_declared_minimum(self) -> None:
        all_capabilities = frozenset(Capability)
        self.assertEqual(
            _select_scenarios(
                None,
                lane_timeout_seconds=1232,
                capabilities=all_capabilities,
                platform="linux",
            ),
            scenario_catalog(),
        )
        with self.assertRaisesRegex(ValueError, "requested lane bound"):
            _select_scenarios(
                None,
                lane_timeout_seconds=1231,
                capabilities=all_capabilities,
                platform="linux",
            )

        desktop_capabilities = all_capabilities - {
            Capability.NETWORK_TRANSITION,
            Capability.SLEEP_WAKE,
        }
        android_capabilities = all_capabilities - {
            Capability.NETWORK_TRANSITION,
            Capability.ENDURANCE,
        }
        for platform, capabilities, minimum in (
            ("linux", desktop_capabilities, 1010),
            ("windows", desktop_capabilities, 1010),
            ("macos", desktop_capabilities, 1010),
            ("android", android_capabilities, 980),
        ):
            with self.subTest(platform=platform):
                self.assertEqual(
                    len(
                        _select_scenarios(
                            None,
                            lane_timeout_seconds=minimum,
                            capabilities=capabilities,
                            platform=platform,
                        )
                    ),
                    10,
                )
                with self.assertRaisesRegex(ValueError, "requested lane bound"):
                    _select_scenarios(
                        None,
                        lane_timeout_seconds=minimum - 1,
                        capabilities=capabilities,
                        platform=platform,
                    )

    def test_linux_candidate_identity_probes_share_one_absolute_deadline(self) -> None:
        class ProbeRunner:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                self.timeouts.append(float(timeout_seconds))
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(argv, 0, b"/synthetic/service\n", b"")
                if argv[2:4] == ("sh", "-c") and argv[-1] == "731":
                    return CommandResult(
                        argv,
                        0,
                        b"731 (service) S 1 306 306 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345\n",
                        b"",
                    )
                raise AssertionError(argv)

        controller = object.__new__(LinuxServiceProcessController)
        controller.pid = 731
        controller.binary = Path("/synthetic/service")
        controller.runner = ProbeRunner()
        controller._initial_identity = ("12345", 306)
        controller._replacement_identity = None
        with mock.patch(
            "torturer_checks.hosted.linux.time.monotonic",
            side_effect=[100.0, 100.0, 101.0],
        ):
            controller._verify_candidate_pid(5.0)
        self.assertEqual(controller.runner.timeouts, [5.0, 4.0])

    def test_linux_restart_recomputes_timeout_between_verify_and_kill(self) -> None:
        controller = object.__new__(LinuxServiceProcessController)
        controller.pid = 731
        controller._verify_candidate_pid = mock.Mock()
        controller._sudo = mock.Mock(
            return_value=CommandResult(("sudo",), 0, b"", b"")
        )
        controller._wait_dead = mock.Mock()
        controller._start = mock.Mock()
        with mock.patch(
            "torturer_checks.hosted.linux.time.monotonic",
            side_effect=[100.0, 100.0, 101.0, 102.0, 103.0, 104.0],
        ):
            controller.restart_after_loss(5.0)
        self.assertEqual(
            controller._verify_candidate_pid.call_args_list,
            [mock.call(5.0), mock.call(4.0)],
        )
        self.assertEqual(controller._sudo.call_args.args[1], 3.0)
        self.assertEqual(controller._wait_dead.call_args.args[0], 2.0)
        self.assertEqual(controller._start.call_args.args[0], 1.0)

    def test_linux_process_census_rejects_duplicate_or_extra_fields(self) -> None:
        valid = "731 1 731 S\n"
        self.assertEqual(len(_parse_linux_process_census(valid)), 1)
        with self.assertRaises(ValueError):
            _parse_linux_process_census(valid + valid)
        with self.assertRaises(ValueError):
            _parse_linux_process_census("731 1 731 S unexpected\n")
        with self.assertRaises(ValueError):
            _parse_linux_process_census("731 1 731 R+\n")

    def test_linux_liveness_does_not_turn_a_ps_probe_error_into_absence(self) -> None:
        controller = object.__new__(LinuxServiceProcessController)
        controller.pid = 731
        controller._sudo = mock.Mock(
            side_effect=(
                CommandResult(("sudo",), 0, b"", b""),
                CommandResult(("sudo",), 1, b"", b""),
            )
        )
        with self.assertRaisesRegex(ScenarioExecutionError, "SERVICE_PROBE_FAILED"):
            controller._alive(1.0)
        controller._sudo = mock.Mock(
            side_effect=(
                CommandResult(("sudo",), 1, b"", b"permission denied\n"),
                CommandResult(("sudo",), 1, b"", b""),
            )
        )
        with self.assertRaisesRegex(ScenarioExecutionError, "SERVICE_PROBE_FAILED"):
            controller._alive(1.0)

    def test_linux_partial_restart_commits_identity_before_readiness(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-partial"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        raw_directory = root / "service-partial-raw"
        raw_directory.mkdir(mode=0o700)

        class Launcher:
            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                if argv[2:5] == ("sh", "-c", _SERVICE_LAUNCH_SCRIPT):
                    return CommandResult(argv, 0, b"794\n", b"")
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(
                        argv, 0, (str(binary.resolve()) + "\n").encode(), b""
                    )
                raise AssertionError(argv)

        controller = object.__new__(LinuxServiceProcessController)
        controller.pid = 793
        controller.binary = binary
        controller.socket = root / "partial.sock"
        controller.library_path = None
        controller.pid_file = root / "partial.pid"
        controller.runner = Launcher()
        controller.raw_directory = raw_directory
        controller._restart_number = 0
        controller._initial_identity = None
        controller._replacement_identity = None
        controller._replacement_tree = ()
        events: list[str] = []
        controller._candidate_process_identity = mock.Mock(
            return_value=("12399", 794)
        )
        controller._verify_candidate_pid = mock.Mock(
            side_effect=lambda _timeout: (events.append("verify"), ("12399", 794))[1]
        )
        controller._write_pid = mock.Mock(side_effect=lambda _pid: events.append("write"))
        controller._alive = mock.Mock(return_value=False)
        with self.assertRaisesRegex(ScenarioExecutionError, "SERVICE_RESTART_EXITED"):
            controller._start(5.0)
        controller._verify_candidate_pid.assert_called_once()
        self.assertEqual(controller._replacement_identity, ("12399", 794))
        self.assertEqual(events, ["verify", "write"])

    def test_linux_process_identity_probe_requires_explicit_absence_marker(self) -> None:
        controller = object.__new__(LinuxServiceProcessController)
        controller.runner = mock.Mock()
        controller.runner.run.return_value = CommandResult(
            ("sudo",), 1, b"", b""
        )
        with self.assertRaisesRegex(ScenarioExecutionError, "SERVICE_TREE_PROBE_FAILED"):
            controller._read_process_stat(731, 1.0)
        controller.runner.run.return_value = CommandResult(
            ("sudo",), 2, b"service_probe_absent\n", b""
        )
        self.assertIsNone(controller._read_process_stat(731, 1.0))

    def test_linux_initial_identity_sidecar_rejects_same_binary_pid_reuse(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-initial-identity"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        raw_directory = root / "service-initial-identity-raw"
        raw_directory.mkdir(mode=0o700)
        identity_file = root / "service.identity"
        identity_file.write_text("731|12345|306\n", encoding="ascii")
        identity_file.chmod(0o600)

        class ReusedPIDRunner:
            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(argv, 0, (str(binary) + "\n").encode(), b"")
                if argv[2:4] == ("sh", "-c"):
                    return CommandResult(
                        argv,
                        0,
                        b"731 (service) S 1 306 306 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99999\n",
                        b"",
                    )
                raise AssertionError(argv)

        with self.assertRaisesRegex(HostedAdapterError, "SERVICE_PID_NOT_CANDIDATE"):
            LinuxServiceProcessController(
                pid=731,
                binary=binary,
                socket=root / "service-initial-identity.sock",
                library_path=None,
                pid_file=root / "service-initial-identity.pid",
                identity_file=identity_file,
                runner=ReusedPIDRunner(),
                raw_directory=raw_directory,
            )

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
        self.assertEqual(total_seconds, 1202)
        self.assertEqual(
            total_seconds + hosted_run._FINALIZE_TIMEOUT_SECONDS,
            1232,
        )

    def test_default_lane_partitions_all_applicable_and_unsupported_scenarios(self) -> None:
        selected = _select_scenarios(None)
        applicable, unsupported = _partition_applicable(
            selected,
            self.adapter.capabilities,
            self.adapter.capability_unavailable_reasons,
        )
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
        self.assertEqual(
            next(item["reason_code"] for item in unsupported
                 if item["scenario_id"] == "functional.sleep-wake"),
            "HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
        )
        self.assertEqual(
            next(item["reason_code"] for item in unsupported
                 if item["scenario_id"] == "functional.network-transition"),
            "HOSTED_RUNNER_UPLINK_TOGGLE_UNSUPPORTED",
        )

    def _linux_coverage_fixture(self):
        selected = scenario_catalog()
        expected = EXPECTED_UNAVAILABLE_BY_PLATFORM["linux"]
        results = [
            {"scenario_id": scenario.id, "outcome": "passed"}
            for scenario in selected
        ]
        missing_capability = {
            "functional.network-transition": "network_transition",
            "functional.sleep-wake": "sleep_wake",
        }
        unsupported = []
        for scenario_id, reason_code in expected:
            result = next(item for item in results if item["scenario_id"] == scenario_id)
            result.update({"outcome": "unavailable", "reason_code": reason_code})
            unsupported.append({
                "scenario_id": scenario_id,
                "missing_capabilities": [missing_capability[scenario_id]],
                "reason_code": reason_code,
            })
        coverage = _coverage_contract(
            "linux",
            selected,
            results,
            unsupported,
            expected,
            reset_count=len(selected),
            reset_failures=0,
        )
        return selected, results, unsupported, expected, coverage

    def test_expected_unavailable_scenario_is_an_explicit_supported_subset(self) -> None:
        scenario = get_scenario("functional.sleep-wake")
        subset_results, reset_failures, reset_count = _run_scenarios(
            FunctionalEngine("1" * 64), (scenario,), self.adapter, _provenance(self.adapter)
        )
        self.assertEqual(reset_count, 1)
        self.assertEqual(reset_failures, [])
        self.assertEqual(subset_results[0]["scenario_id"], scenario.id)
        self.assertEqual(subset_results[0]["outcome"], "unavailable")
        self.assertEqual(subset_results[0]["reason_code"], "HOSTED_RUNNER_SUSPEND_UNSUPPORTED")
        _, results, unsupported, _, coverage = self._linux_coverage_fixture()
        self.assertEqual(
            _qualification_exit_code(
                results,
                unsupported,
                [],
                coverage=coverage,
            ),
            0,
        )

    def test_unavailable_allowlist_rejects_new_changed_and_stale_pairs(self) -> None:
        selected, results, unsupported, _, _ = self._linux_coverage_fixture()
        for expected in (
            frozenset(),
            frozenset({("functional.sleep-wake", "CHANGED_REASON")}),
            frozenset({("functional.sleep-wake", "HOSTED_RUNNER_SUSPEND_UNSUPPORTED"), ("functional.network-transition", "NEW_GAP")}),
        ):
            with self.subTest(expected=expected):
                coverage = _coverage_contract(
                    "linux",
                    selected,
                    results,
                    unsupported,
                    expected,
                    reset_count=len(selected),
                    reset_failures=0,
                )
                self.assertEqual(coverage["status"], "coverage-contract-failed")
                self.assertEqual(
                    _qualification_exit_code(results, unsupported, [], coverage=coverage),
                    2,
                )

    def test_unexpected_missing_capability_cannot_become_a_coverage_pass(self) -> None:
        selected, results, unsupported, expected, _ = self._linux_coverage_fixture()
        unexpected = next(
            item for item in results
            if item["scenario_id"] == "functional.core-connection"
        )
        unexpected.update({"outcome": "unavailable", "reason_code": "UNEXPECTED_GAP"})
        unsupported.append({
            "scenario_id": "functional.core-connection",
            "missing_capabilities": ["connect"],
            "reason_code": "UNEXPECTED_GAP",
        })
        coverage = _coverage_contract(
            "linux",
            selected,
            results,
            unsupported,
            expected,
            reset_count=len(selected),
            reset_failures=0,
        )
        self.assertEqual(coverage["status"], "coverage-contract-failed")
        self.assertEqual(
            _qualification_exit_code(results, unsupported, [], coverage=coverage),
            2,
        )

    def test_coverage_result_is_explicitly_incomplete_and_records_exact_pairs(self) -> None:
        _, _, _, _, coverage = self._linux_coverage_fixture()
        self.assertEqual(coverage["status"], "supported-subset-with-expected-limitations")
        self.assertFalse(coverage["complete"])
        self.assertTrue(coverage["selected_catalog_match"])
        self.assertEqual(coverage["actual_unavailable"], [
            {"scenario_id": "functional.network-transition", "reason_code": "HOSTED_LINUX_INTERFACE_REQUIRED"},
            {"scenario_id": "functional.sleep-wake", "reason_code": "HOSTED_RUNNER_SUSPEND_UNSUPPORTED"},
        ])

    def test_expected_unavailable_cli_values_are_strict_and_unique(self) -> None:
        self.assertEqual(
            _expected_unavailable(["functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED"]),
            frozenset({("functional.sleep-wake", "HOSTED_RUNNER_SUSPEND_UNSUPPORTED")}),
        )
        with self.assertRaises(ValueError):
            _expected_unavailable(["functional.sleep-wake"])
        with self.assertRaises(ValueError):
            _expected_unavailable([
                "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
                "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
            ])

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
        self.assertEqual(result.reason_code, "HOSTED_RUNNER_SUSPEND_UNSUPPORTED")

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
        with (
            mock.patch(
                "torturer_checks.hosted.linux.time.monotonic",
                side_effect=[100.0, 101.0, 102.0, 103.0, 104.0],
            ),
            mock.patch.object(
                adapter, "_wait_for_routing_identity_changed", return_value=True
            ) as wait_for_routing,
        ):
            result = adapter._process_loss(10)
        self.assertEqual(result, {"process_loss_verified": True})
        self.assertEqual(service.timeouts, [9.0])
        self.assertEqual(self.runner.timeouts, [8.0, 7.0])
        wait_for_routing.assert_called_once_with(6.0)

    def test_linux_process_loss_rejects_expired_deadline_instead_of_using_minimum(self) -> None:
        class FakeService:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def restart_after_loss(self, timeout: float) -> None:
                self.timeouts.append(timeout)

        adapter = LinuxHostedAdapter(cli=self.cli, profile=self.profile, runner=self.runner)
        service = FakeService()
        adapter.service = service  # type: ignore[assignment]
        with mock.patch(
            "torturer_checks.hosted.linux.time.monotonic",
            side_effect=[100.0, 100.02],
        ):
            with self.assertRaisesRegex(ScenarioExecutionError, "PROCESS_LOSS_TIMEOUT"):
                adapter._process_loss(0.01)
        self.assertEqual(service.timeouts, [])
        self.assertEqual(self.runner.calls, [])

    def test_linux_adapter_finalization_stops_the_deliberately_restarted_service(self) -> None:
        class FakeService:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def stop_restarted_service(self, timeout: float) -> None:
                self.timeouts.append(timeout)

        adapter = LinuxHostedAdapter(
            cli=self.cli,
            profile=self.profile,
            runner=self.runner,
        )
        service = FakeService()
        adapter.service = service  # type: ignore[assignment]
        adapter.finalize(12.5)
        self.assertEqual(service.timeouts, [12.5])

    def test_hosted_run_finalization_uses_the_remaining_lane_budget(self) -> None:
        class FakeAdapter:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def finalize(self, *, timeout_seconds: float) -> None:
                self.timeouts.append(timeout_seconds)

        adapter = FakeAdapter()
        with mock.patch(
            "torturer_checks.hosted.run.time.monotonic",
            return_value=100.0,
        ):
            _finalize_adapter(adapter, 112.5)
        self.assertEqual(adapter.timeouts, [12.5])

    def test_hosted_run_passes_the_canonical_absolute_deadline_to_finalizer(self) -> None:
        class DeadlineAdapter:
            def __init__(self) -> None:
                self.deadlines: list[float | None] = []

            def finalize(self, *, timeout_seconds: float, deadline: float | None) -> None:
                self.deadlines.append(deadline)

        adapter = DeadlineAdapter()
        with mock.patch(
            "torturer_checks.hosted.run.time.monotonic",
            return_value=100.0,
        ):
            _finalize_adapter(adapter, 112.5)
        self.assertEqual(adapter.deadlines, [112.5])

    def test_hosted_run_rejects_an_adapter_without_a_finalizer(self) -> None:
        with self.assertRaisesRegex(ValueError, "ADAPTER_FINALIZER_UNAVAILABLE"):
            _finalize_adapter(object(), None)

    def test_hosted_run_diagnostics_keep_only_stable_reason_codes(self) -> None:
        self.assertEqual(
            _diagnostic_code(ScenarioExecutionError("SERVICE_FINALIZE_TIMEOUT")),
            "SERVICE_FINALIZE_TIMEOUT",
        )
        self.assertEqual(
            _diagnostic_code(HostedAdapterError("SERVICE_PID_NOT_CANDIDATE")),
            "SERVICE_PID_NOT_CANDIDATE",
        )
        self.assertEqual(
            _diagnostic_code(ValueError("path/to/private-profile")),
            "ValueError",
        )
        self.assertEqual(
            _diagnostic_code(ValueError("THISISASECRETVALUE")),
            "ValueError",
        )
        self.assertEqual(
            _diagnostic_code(ValueError("HOSTED_LANE_DEADLINE_EXCEEDED before finalization")),
            "HOSTED_LANE_DEADLINE_EXCEEDED",
        )

        class TypedFailure(Exception):
            reason_code = "SCENARIO_FAILED private=credential-value"

        self.assertEqual(_diagnostic_code(TypedFailure()), "SCENARIO_FAILED")
        self.assertEqual(
            _diagnostic_code(ValueError("PRIVATE_SECRET upper-case detail")),
            "ValueError",
        )

    def test_hosted_run_main_finalizes_adapter_before_returning(self) -> None:
        root = Path(self.directory.name)
        raw_directory = root / "main-finalize-raw"
        raw_directory.mkdir(mode=0o700)
        output = root / "main-finalize-result.json"

        class MainRunner:
            def safe_evidence(self):
                return ()

        class MainAdapter:
            adapter_id = "hosted-linux-cli"
            adapter_version = "v2"
            capabilities = frozenset({Capability.CONFIGURE})
            capability_unavailable_reasons = {}

            def __init__(self) -> None:
                self.runner = MainRunner()
                self.finalized: list[float] = []

            def finalize(self, *, timeout_seconds: float) -> None:
                self.finalized.append(timeout_seconds)

        adapter = MainAdapter()
        manifest = {"kind": "source-build-closure", "architecture": "amd64"}
        arguments = [
            "--platform", "linux",
            "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN",
            "--source-sha", "a" * 40,
            "--platform-version", "24.04",
            "--candidate-manifest", str(root / "manifest.json"),
            "--server-image-digest", "sha256:" + "b" * 64,
            "--lane-timeout-seconds", "60",
            "--output", str(output),
            "--raw-log-dir", str(raw_directory),
            "--scenario-id", "functional.configure",
        ]
        with (
            mock.patch.object(hosted_run, "_git_head", return_value="c" * 40),
            mock.patch.object(hosted_run, "verify_candidate", return_value=manifest),
            mock.patch.object(hosted_run, "_sha256", return_value="d" * 64),
            mock.patch.object(hosted_run, "closure_sha256", return_value="e" * 64),
            mock.patch.object(hosted_run, "adapter_for_platform", return_value=adapter),
            mock.patch.object(hosted_run, "_run_scenarios", return_value=([], [], 0)),
            mock.patch.object(
                hosted_run,
                "_coverage_contract",
                return_value={"status": "supported-subset-with-expected-limitations"},
            ),
            mock.patch.object(hosted_run, "_qualification_exit_code", return_value=0),
        ):
            code = hosted_run.main(arguments)

        self.assertEqual(code, 0)
        self.assertEqual(len(adapter.finalized), 1)
        self.assertGreater(adapter.finalized[0], 0)
        self.assertTrue(output.is_file())

    def test_hosted_run_success_path_finalizer_failure_cannot_pass(self) -> None:
        root = Path(self.directory.name)
        raw_directory = root / "main-finalizer-failure-raw"
        raw_directory.mkdir(mode=0o700)
        output = root / "main-finalizer-failure-result.json"

        class MainRunner:
            def safe_evidence(self):
                return ()

        class MainAdapter:
            adapter_id = "hosted-linux-cli"
            adapter_version = "v2"
            capabilities = frozenset({Capability.CONFIGURE})
            capability_unavailable_reasons = {}
            runner = MainRunner()

            def finalize(self, *, timeout_seconds: float, deadline: float | None) -> None:
                raise ValueError("PRIVATE_SECRET=must-not-escape")

        manifest = {"kind": "source-build-closure", "architecture": "amd64"}
        arguments = [
            "--platform", "linux", "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN", "--source-sha", "a" * 40,
            "--platform-version", "24.04", "--candidate-manifest", str(root / "manifest.json"),
            "--server-image-digest", "sha256:" + "b" * 64, "--lane-timeout-seconds", "60",
            "--output", str(output), "--raw-log-dir", str(raw_directory),
            "--scenario-id", "functional.configure",
        ]
        diagnostics = io.StringIO()
        with (
            mock.patch.object(hosted_run, "_git_head", return_value="c" * 40),
            mock.patch.object(hosted_run, "verify_candidate", return_value=manifest),
            mock.patch.object(hosted_run, "_sha256", return_value="d" * 64),
            mock.patch.object(hosted_run, "closure_sha256", return_value="e" * 64),
            mock.patch.object(hosted_run, "adapter_for_platform", return_value=MainAdapter()),
            mock.patch.object(hosted_run, "_run_scenarios", return_value=([], [], 0)),
            mock.patch.object(
                hosted_run, "_coverage_contract",
                return_value={"status": "supported-subset-with-expected-limitations"},
            ),
            mock.patch.object(hosted_run, "_qualification_exit_code", return_value=0),
            contextlib.redirect_stderr(diagnostics),
        ):
            code = hosted_run.main(arguments)

        self.assertEqual(code, 1)
        self.assertIn("hosted-functional failed code=ValueError", diagnostics.getvalue())
        self.assertNotIn("PRIVATE_SECRET", diagnostics.getvalue())

    def test_hosted_run_lane_clock_starts_before_slow_preflight(self) -> None:
        root = Path(self.directory.name)
        raw_directory = root / "main-preflight-raw"
        raw_directory.mkdir(mode=0o700)
        output = root / "main-preflight-result.json"

        class MainRunner:
            def safe_evidence(self):
                return ()

        class MainAdapter:
            adapter_id = "hosted-linux-cli"
            adapter_version = "v2"
            capabilities = frozenset({Capability.CONFIGURE})
            capability_unavailable_reasons = {}

            def __init__(self) -> None:
                self.runner = MainRunner()
                self.finalized: list[float] = []

            def finalize(self, *, timeout_seconds: float) -> None:
                self.finalized.append(timeout_seconds)

        adapter = MainAdapter()
        scenario_deadlines: list[float] = []

        def run_scenarios(*_args, deadline: float | None = None, **_kwargs):
            scenario_deadlines.append(float(deadline))
            return [], [], 0

        clock = [100.0]

        def monotonic() -> float:
            return clock[0]

        def slow_preflight(*_args, **_kwargs) -> str:
            clock[0] = 130.0
            return "c" * 40

        manifest = {"kind": "source-build-closure", "architecture": "amd64"}
        arguments = [
            "--platform", "linux",
            "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN",
            "--source-sha", "a" * 40,
            "--platform-version", "24.04",
            "--candidate-manifest", str(root / "manifest.json"),
            "--server-image-digest", "sha256:" + "b" * 64,
            "--lane-timeout-seconds", "60",
            "--output", str(output),
            "--raw-log-dir", str(raw_directory),
            "--scenario-id", "functional.configure",
        ]
        with (
            mock.patch.object(hosted_run.time, "monotonic", side_effect=monotonic),
            mock.patch.object(hosted_run, "_git_head", side_effect=slow_preflight),
            mock.patch.object(hosted_run, "verify_candidate", return_value=manifest),
            mock.patch.object(hosted_run, "_sha256", return_value="d" * 64),
            mock.patch.object(hosted_run, "closure_sha256", return_value="e" * 64),
            mock.patch.object(hosted_run, "adapter_for_platform", return_value=adapter),
            mock.patch.object(hosted_run, "_run_scenarios", side_effect=run_scenarios),
            mock.patch.object(
                hosted_run,
                "_coverage_contract",
                return_value={"status": "supported-subset-with-expected-limitations"},
            ),
            mock.patch.object(hosted_run, "_qualification_exit_code", return_value=0),
        ):
            code = hosted_run.main(arguments)

        self.assertEqual(code, 0)
        self.assertEqual(scenario_deadlines, [130.0])
        self.assertEqual(adapter.finalized, [30.0])

    def test_hosted_run_main_catch_path_finalizes_and_redacts_finalizer_failure(self) -> None:
        root = Path(self.directory.name)
        raw_directory = root / "main-catch-raw"
        raw_directory.mkdir(mode=0o700)
        output = root / "main-catch-result.json"

        class MainRunner:
            def safe_evidence(self):
                return ()

        class MainAdapter:
            adapter_id = "hosted-linux-cli"
            adapter_version = "v2"
            capabilities = frozenset({Capability.CONFIGURE})
            capability_unavailable_reasons = {}

            def __init__(self) -> None:
                self.runner = MainRunner()
                self.finalized: list[float] = []

            def finalize(self, *, timeout_seconds: float) -> None:
                self.finalized.append(timeout_seconds)
                raise ValueError("private-profile=/owner/secret/profile.toml")

        adapter = MainAdapter()
        scenario_deadlines: list[float] = []

        def fail_scenarios(*_args, deadline: float | None = None, **_kwargs):
            scenario_deadlines.append(float(deadline))
            raise ScenarioExecutionError("SCENARIO_FAILED private detail")

        manifest = {"kind": "source-build-closure", "architecture": "amd64"}
        arguments = [
            "--platform", "linux",
            "--profile", str(self.profile),
            "--source-repository", "DobbyVPN/DobbyVPN",
            "--source-sha", "a" * 40,
            "--platform-version", "24.04",
            "--candidate-manifest", str(root / "manifest.json"),
            "--server-image-digest", "sha256:" + "b" * 64,
            "--lane-timeout-seconds", "60",
            "--output", str(output),
            "--raw-log-dir", str(raw_directory),
            "--scenario-id", "functional.configure",
        ]
        diagnostics = io.StringIO()
        with (
            mock.patch.object(hosted_run, "_git_head", return_value="c" * 40),
            mock.patch.object(hosted_run, "verify_candidate", return_value=manifest),
            mock.patch.object(hosted_run, "_sha256", return_value="d" * 64),
            mock.patch.object(hosted_run, "closure_sha256", return_value="e" * 64),
            mock.patch.object(hosted_run, "adapter_for_platform", return_value=adapter),
            mock.patch.object(hosted_run, "_run_scenarios", side_effect=fail_scenarios),
            mock.patch.object(hosted_run, "_MAX_LANE_SECONDS", 60),
            contextlib.redirect_stderr(diagnostics),
        ):
            code = hosted_run.main(arguments)

        self.assertEqual(code, 1)
        self.assertEqual(len(adapter.finalized), 1)
        self.assertEqual(len(scenario_deadlines), 1)
        self.assertAlmostEqual(adapter.finalized[0], 30.0, delta=0.5)
        self.assertIn("adapter-finalization-failed code=ValueError", diagnostics.getvalue())
        self.assertIn("hosted-functional failed code=SCENARIO_FAILED", diagnostics.getvalue())
        self.assertNotIn("private-profile", diagnostics.getvalue())
        self.assertNotIn("/owner/secret/profile.toml", diagnostics.getvalue())

    def test_linux_service_finalization_verifies_and_stops_the_exact_restart(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-finalize"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        pid_file = root / "service-finalize.pid"
        raw_directory = root / "service-finalize-raw"
        raw_directory.mkdir(mode=0o700)

        class ServiceRunner:
            def __init__(self) -> None:
                self.alive = True
                self.calls: list[tuple[str, ...]] = []

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                self.calls.append(argv)
                if argv[2:4] == ("sh", "-c") and argv[-1] == "789":
                    return CommandResult(
                        argv,
                        0 if self.alive else 2,
                        b"789 (service) S 1 300 300 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345\n" if self.alive else b"service_probe_absent\n",
                        b"",
                    )
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(
                        argv,
                        0 if self.alive else 1,
                        (str(binary.resolve()) + "\n").encode() if self.alive else b"",
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0 if self.alive else 1, b"", b"")
                if argv[2:4] == ("ps", "-o"):
                    return CommandResult(
                        argv,
                        0 if self.alive else 1,
                        b"S\n" if self.alive else b"",
                        b"",
                    )
                if argv[2:4] == ("ps", "-axo"):
                    return CommandResult(
                        argv,
                        0,
                        b"789 1 300 S\n" if self.alive else b"",
                        b"",
                    )
                if argv[2:4] == ("kill", "-TERM"):
                    self.alive = False
                    return CommandResult(argv, 0, b"", b"")
                raise AssertionError(argv)

        runner = ServiceRunner()
        controller = LinuxServiceProcessController(
            pid=789,
            binary=binary,
            socket=root / "service-finalize.sock",
            library_path=None,
            pid_file=pid_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        controller._restart_number = 1
        controller._replacement_identity = ("12345", 300)
        controller.stop_restarted_service(10.0)

        self.assertFalse(runner.alive)
        self.assertIn(("sudo", "-n", "kill", "-TERM", "--", "-300"), runner.calls)
        self.assertNotIn(("sudo", "-n", "kill", "-KILL", "--", "-300"), runner.calls)

    def test_linux_service_finalization_escalates_a_resistant_restart_to_kill(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-finalize-resistant"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        raw_directory = root / "service-finalize-resistant-raw"
        raw_directory.mkdir(mode=0o700)

        class ServiceRunner:
            def __init__(self) -> None:
                self.alive = True
                self.calls: list[tuple[str, ...]] = []

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                self.calls.append(argv)
                if argv[2:4] == ("sh", "-c") and argv[-1] == "790":
                    return CommandResult(
                        argv,
                        0 if self.alive else 2,
                        b"790 (service) S 1 301 301 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12346\n" if self.alive else b"service_probe_absent\n",
                        b"",
                    )
                if argv[2:4] == ("sh", "-c") and argv[-1] == "7910":
                    return CommandResult(
                        argv,
                        0 if self.alive else 2,
                        b"7910 (worker) S 790 301 301 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12347\n" if self.alive else b"service_probe_absent\n",
                        b"",
                    )
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(
                        argv,
                        0,
                        (str(binary.resolve()) + "\n").encode(),
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0 if self.alive else 1, b"", b"")
                if argv[2:4] == ("ps", "-o"):
                    return CommandResult(argv, 0 if self.alive else 1, b"S\n" if self.alive else b"", b"")
                if argv[2:4] == ("ps", "-axo"):
                    return CommandResult(
                        argv,
                        0,
                        b"790 1 301 S\n7910 790 301 S\n" if self.alive else b"",
                        b"",
                    )
                if argv[2:4] == ("kill", "-TERM"):
                    return CommandResult(argv, 0, b"", b"")
                if argv[2:4] == ("kill", "-KILL"):
                    self.alive = False
                    return CommandResult(argv, 0, b"", b"")
                raise AssertionError(argv)

        runner = ServiceRunner()
        controller = LinuxServiceProcessController(
            pid=790,
            binary=binary,
            socket=root / "service-finalize-resistant.sock",
            library_path=None,
            pid_file=root / "service-finalize-resistant.pid",
            runner=runner,
            raw_directory=raw_directory,
        )
        controller._restart_number = 1
        controller._replacement_identity = ("12346", 301)
        with mock.patch.object(
            controller,
            "_wait_replacement_tree",
            side_effect=[HostedAdapterError("SERVICE_FINALIZE_TIMEOUT"), ()],
        ):
            controller.stop_restarted_service(10.0)

        self.assertFalse(runner.alive)
        self.assertIn(("sudo", "-n", "kill", "-TERM", "--", "-301"), runner.calls)
        self.assertIn(("sudo", "-n", "kill", "-KILL", "--", "-301"), runner.calls)

    def test_linux_service_finalization_refuses_a_reused_pid(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-finalize-identity"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        raw_directory = root / "service-finalize-identity-raw"
        raw_directory.mkdir(mode=0o700)

        class ServiceRunner:
            def __init__(self) -> None:
                self.readlinks = 0
                self.calls: list[tuple[str, ...]] = []

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                self.calls.append(argv)
                if argv[2:4] == ("readlink", "-f"):
                    self.readlinks += 1
                    return CommandResult(
                        argv,
                        0,
                        (str(binary.resolve()) + "\n").encode(),
                        b"",
                    )
                if argv[2:4] == ("sh", "-c") and argv[-1] == "791":
                    return CommandResult(
                        argv,
                        0,
                        b"791 (service) S 1 302 302 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99999\n",
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0, b"", b"")
                if argv[2:4] == ("ps", "-o"):
                    return CommandResult(argv, 0, b"S\n", b"")
                raise AssertionError(argv)

        runner = ServiceRunner()
        controller = LinuxServiceProcessController(
            pid=791,
            binary=binary,
            socket=root / "service-finalize-identity.sock",
            library_path=None,
            pid_file=root / "service-finalize-identity.pid",
            runner=runner,
            raw_directory=raw_directory,
        )
        controller._restart_number = 1
        controller._replacement_identity = ("12345", 302)
        with self.assertRaisesRegex(HostedAdapterError, "SERVICE_PID_NOT_CANDIDATE"):
            controller.stop_restarted_service(10.0)

        self.assertFalse(any(call[2:4] in {("kill", "-TERM"), ("kill", "-KILL")} for call in runner.calls))

    def test_linux_service_finalization_does_not_pass_on_root_disappearance(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-finalize-root-gone"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        raw_directory = root / "service-finalize-root-gone-raw"
        raw_directory.mkdir(mode=0o700)

        class ServiceRunner:
            def __init__(self) -> None:
                self.alive = True

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(argv, 0, (str(binary.resolve()) + "\n").encode(), b"")
                if argv[2:4] == ("sh", "-c") and argv[-1] == "793":
                    return CommandResult(
                        argv,
                        0 if self.alive else 2,
                        b"793 (service) S 1 306 306 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12351\n"
                        if self.alive else b"service_probe_absent\n",
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0 if self.alive else 1, b"", b"")
                if argv[2:4] == ("ps", "-o"):
                    return CommandResult(
                        argv,
                        0 if self.alive else 1,
                        b"S\n" if self.alive else b"",
                        b"",
                    )
                raise AssertionError(argv)

        runner = ServiceRunner()
        controller = LinuxServiceProcessController(
            pid=793,
            binary=binary,
            socket=root / "service-finalize-root-gone.sock",
            library_path=None,
            pid_file=root / "service-finalize-root-gone.pid",
            runner=runner,
            raw_directory=raw_directory,
        )
        controller._restart_number = 1
        controller._replacement_identity = ("12351", 306)
        runner.alive = False
        with self.assertRaisesRegex(HostedAdapterError, "SERVICE_TREE_PROBE_FAILED"):
            controller.stop_restarted_service(10.0)

    def test_linux_service_finalization_fails_closed_on_timed_out_liveness_probe(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-finalize-timeout"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        raw_directory = root / "service-finalize-timeout-raw"
        raw_directory.mkdir(mode=0o700)

        class ServiceRunner:
            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(argv, 0, (str(binary.resolve()) + "\n").encode(), b"")
                if argv[2:4] == ("sh", "-c") and argv[-1] == "792":
                    return CommandResult(
                        argv,
                        0,
                        b"792 (service) S 1 303 303 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12347\n",
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0, b"", b"", timed_out=True)
                raise AssertionError(argv)

        controller = LinuxServiceProcessController(
            pid=792,
            binary=binary,
            socket=root / "service-finalize-timeout.sock",
            library_path=None,
            pid_file=root / "service-finalize-timeout.pid",
            runner=ServiceRunner(),
            raw_directory=raw_directory,
        )
        controller._restart_number = 1
        controller._replacement_identity = ("12347", 303)
        with self.assertRaisesRegex(ScenarioExecutionError, "SERVICE_PROBE_FAILED"):
            controller.stop_restarted_service(10.0)

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
        reused_log = raw_directory / "service-restart-001.raw.log"
        raw_directory.mkdir(mode=0o700)
        reused_log.write_bytes(b"previous service evidence\n")
        reused_log.chmod(0o600)

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
                if argv[2:4] == ("sh", "-c") and argv[-1] == "123":
                    return CommandResult(
                        argv,
                        0,
                        b"123 (service) S 1 303 303 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12348\n",
                        b"",
                    )
                if argv[2:4] == ("sh", "-c") and argv[-1] == "456":
                    return CommandResult(
                        argv,
                        0,
                        b"456 (service) S 1 304 304 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12349\n",
                        b"",
                    )
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0, b"", b"")
                if argv[2:4] == ("ps", "-o"):
                    return CommandResult(argv, 0, b"S\n", b"")
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
            return_value=100.0,
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
        launched_log = Path(launcher[10])
        self.assertNotEqual(launched_log, reused_log)
        self.assertEqual(reused_log.read_bytes(), b"previous service evidence\n")
        self.assertEqual(launched_log.stat().st_mode & 0o777, 0o600)

    def test_linux_restart_uses_detached_launcher_when_runner_provides_one(self) -> None:
        root = Path(self.directory.name)
        binary = root / "service-detached"
        binary.write_bytes(b"synthetic service")
        binary.chmod(0o700)
        socket_path = root / "detached-control.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        self.addCleanup(listener.close)
        pid_file = root / "detached-service.pid"
        raw_directory = root / "detached-service-raw"
        raw_directory.mkdir(mode=0o700)

        class DetachedServiceRunner:
            def __init__(self) -> None:
                self.detached_calls: list[tuple[str, ...]] = []
                self.probe_calls: list[tuple[str, ...]] = []

            def run_detached(self, command, *, timeout_seconds):
                self.detached_calls.append(tuple(command))
                return CommandResult(tuple(command), 0, b"789\n", b"")

            def run(self, command, *, timeout_seconds):
                argv = tuple(command)
                self.probe_calls.append(argv)
                if argv[2:4] == ("kill", "-0"):
                    return CommandResult(argv, 0, b"", b"")
                if argv[2:4] == ("ps", "-o"):
                    return CommandResult(argv, 0, b"S\n", b"")
                if argv[2:4] == ("readlink", "-f"):
                    return CommandResult(argv, 0, (str(binary.resolve()) + "\n").encode(), b"")
                if argv[2:4] == ("sh", "-c") and argv[-1] == "123":
                    return CommandResult(
                        argv,
                        0,
                        b"123 (service) S 1 304 304 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12348\n",
                        b"",
                    )
                if argv[2:4] == ("sh", "-c") and argv[-1] == "789":
                    return CommandResult(
                        argv,
                        0,
                        b"789 (service) S 1 305 305 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12350\n",
                        b"",
                    )
                raise AssertionError(argv)

        runner = DetachedServiceRunner()
        controller = LinuxServiceProcessController(
            pid=123,
            binary=binary,
            socket=socket_path,
            library_path=None,
            pid_file=pid_file,
            runner=runner,
            raw_directory=raw_directory,
        )
        controller._start(10.0)

        self.assertEqual(controller.pid, 789)
        self.assertEqual(len(runner.detached_calls), 1)
        self.assertEqual(runner.detached_calls[0][2:5], ("sh", "-c", _SERVICE_LAUNCH_SCRIPT))

    def test_subprocess_runner_retains_complete_stdout_and_stderr_bytes(self) -> None:
        raw = Path(self.directory.name) / "raw"
        runner = SubprocessRunner(raw)
        result = runner.run(
            ("python3", "-c", "import sys; sys.stdout.buffer.write(b'198.51.100.10\\n'); sys.stderr.buffer.write(b'err\\n')"),
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        retained_path = next(raw.glob("command-001*.raw.log"))
        retained = retained_path.read_bytes()
        self.assertIn(b"198.51.100.10\n", retained)
        self.assertIn(b"err\n", retained)
        evidence = runner.safe_evidence()
        self.assertEqual(evidence[0]["returncode"], 0)
        self.assertEqual(len(evidence[0]["evidence_id"]), 32)
        self.assertTrue(all(character in "0123456789abcdef" for character in evidence[0]["evidence_id"]))
        self.assertEqual(evidence[0]["stdout_bytes"], 14)
        original_length = len(retained)
        self.assertEqual(evidence[0]["evidence_bytes"], original_length)
        self.assertEqual(
            evidence[0]["evidence_sha256"],
            hashlib.sha256(retained).hexdigest(),
        )
        self.assertNotIn("198.51.100.10", repr(evidence[0]))
        self.assertNotIn("stdout_sha256", evidence[0])
        self.assertNotIn("stderr_sha256", evidence[0])
        self.assertNotIn("python3", repr(evidence[0]))
        retained_path.write_bytes(b"mutated-after-retention\n")
        self.assertEqual(evidence[0]["evidence_bytes"], original_length)
        self.assertNotEqual(
            evidence[0]["evidence_sha256"], hashlib.sha256(retained_path.read_bytes()).hexdigest()
        )

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "Linux subreaper assertion requires procfs",
    )
    def test_subprocess_runner_preserves_stdin_and_nonzero_status(self) -> None:
        raw = Path(self.directory.name) / "stdin-status-raw"
        runner = SubprocessRunner(raw)
        result = runner.run_with_input(
            (
                sys.executable,
                "-c",
                "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); raise SystemExit(23)",
            ),
            timeout_seconds=5,
            input_bytes=b"private-stdin-marker\n",
        )
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout, b"private-stdin-marker\n")
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"returncode=23", retained)
        self.assertNotIn(b"linux_subreaper.py", retained)

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "Linux subreaper assertion requires procfs",
    )
    def test_subprocess_runner_preserves_sigkill_status(self) -> None:
        raw = Path(self.directory.name) / "sigkill-status-raw"
        runner = SubprocessRunner(raw)
        result = runner.run(
            (
                sys.executable,
                "-c",
                "import os,signal; os.kill(os.getpid(), signal.SIGKILL)",
            ),
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, -signal.SIGKILL)
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"returncode=-9", retained)

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "Linux subreaper assertion requires procfs",
    )
    def test_subprocess_runner_missing_command_fails_closed_after_retention(self) -> None:
        raw = Path(self.directory.name) / "missing-command-raw"
        runner = SubprocessRunner(raw)
        missing = "/dobbyvpn/synthetic-command-does-not-exist"
        with self.assertRaisesRegex(HostedAdapterError, "COMMAND_UNAVAILABLE"):
            runner.run((missing,), timeout_seconds=5)
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(f"argv={missing}".encode(), retained)
        self.assertIn(b"DOBBYVPN_SUBREAPER_EXEC_FAILED", retained)
        self.assertEqual(runner.safe_evidence()[0]["returncode"], 127)

    def test_subprocess_runner_subreaper_control_failure_is_retained(self) -> None:
        raw = Path(self.directory.name) / "subreaper-control-raw"
        runner = SubprocessRunner(raw)
        command = (sys.executable, "-c", "raise SystemExit(0)")

        def failing_wrapper(_command, *, status_fd):
            return (
                sys.executable,
                "-c",
                "import os,sys; os.write(int(sys.argv[1]), b'SETUP_FAILED\\n')",
                str(status_fd),
            )

        with (
            mock.patch(
                "torturer_checks.hosted.cli._linux_contained_argv",
                side_effect=failing_wrapper,
            ),
            self.assertRaisesRegex(HostedAdapterError, "SUBREAPER_UNAVAILABLE"),
        ):
            runner.run(command, timeout_seconds=5)
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"SUBREAPER_STATUS_BEGIN\nSETUP_FAILED\n", retained)
        self.assertIn(b"argv=" + " ".join(command).encode(), retained)

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "Linux subreaper assertion requires procfs",
    )
    def test_candidate_cannot_spoof_subreaper_failure_via_stderr(self) -> None:
        raw = Path(self.directory.name) / "subreaper-spoof-raw"
        runner = SubprocessRunner(raw)
        result = runner.run(
            (
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('DOBBYVPN_SUBREAPER_SETUP_FAILED\\n')",
            ),
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.stderr,
            b"DOBBYVPN_SUBREAPER_SETUP_FAILED\n",
        )
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"SUBREAPER_STATUS_BEGIN\nREADY\nCOMPLETE\n", retained)

    def test_subprocess_runner_setup_failure_retains_original_command(self) -> None:
        raw = Path(self.directory.name) / "subreaper-setup-raw"
        runner = SubprocessRunner(raw)
        command = ("synthetic-command", "synthetic-argument")
        with (
            mock.patch(
                "torturer_checks.hosted.cli._linux_contained_argv",
                side_effect=HostedAdapterError("SUBREAPER_UNAVAILABLE"),
            ),
            self.assertRaisesRegex(HostedAdapterError, "SUBREAPER_UNAVAILABLE"),
        ):
            runner.run(command, timeout_seconds=5)
        retained = next(raw.glob("command-001*.runner-error.raw.log")).read_bytes()
        self.assertEqual(
            retained,
            b"argv=synthetic-command synthetic-argument\n"
            b"runner_error=SUBREAPER_UNAVAILABLE\n",
        )
        evidence = runner.safe_evidence()[0]
        self.assertEqual(evidence["runner_error"], "SUBREAPER_UNAVAILABLE")
        self.assertEqual(evidence["returncode"], None)

    @unittest.skipUnless(os.name == "posix", "descriptor assertion requires POSIX")
    def test_subreaper_status_read_cannot_cross_absolute_deadline(self) -> None:
        reader, writer = os.pipe()
        started = time.monotonic()
        try:
            diagnostics, failure = _consume_subreaper_status(
                reader,
                required=True,
                deadline=started + 0.05,
            )
            reader = -1
        finally:
            if reader >= 0:
                os.close(reader)
            os.close(writer)
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertEqual(failure, "SUBREAPER_UNAVAILABLE")
        self.assertIn(b"SUBREAPER_STATUS_READ_TIMEOUT=1", diagnostics)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1", diagnostics)

    @unittest.skipUnless(os.name == "posix", "detached launcher assertion requires POSIX")
    def test_subprocess_runner_detached_launcher_allows_intended_child_and_retains_leader(self) -> None:
        raw = Path(self.directory.name) / "detached-launch-raw"
        runner = SubprocessRunner(raw)
        script = "sleep 60 >/dev/null 2>&1 & printf '%s\\n' \"$!\""
        result = runner.run_detached(("sh", "-c", script), timeout_seconds=5)
        self.assertEqual(result.returncode, 0)
        child_pid = int(result.stdout.decode("ascii").strip())
        try:
            os.kill(child_pid, 0)
            retained = next(raw.glob("command-001*.raw.log")).read_bytes()
            self.assertIn(b"DETACHED_LAUNCH_LEADER_STATUS=gone", retained)
            self.assertNotIn(b"PROCESS_TREE_UNPROVEN", retained)
        finally:
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass

    def test_macos_process_census_is_bounded_and_retained(self) -> None:
        completed = subprocess.CompletedProcess(
            ("ps",),
            0,
            b"123 1 123 Mon Aug 23 10:00:00 2026\n",
            b"ps diagnostic\n",
        )
        with (
            mock.patch.object(Path, "is_dir", return_value=False),
            mock.patch("torturer_checks.hosted.cli.subprocess.run", return_value=completed) as run,
        ):
            provider = _ProcessSnapshotProvider()
            snapshot = provider()
        self.assertEqual(snapshot, _parse_macos_process_snapshot(completed.stdout))
        self.assertEqual(run.call_args.kwargs["timeout"], 0.25)
        self.assertIn(b"ps diagnostic\n", provider.diagnostics)

    def test_macos_process_census_can_be_invalidated_at_proof_boundary(self) -> None:
        first = subprocess.CompletedProcess(
            ("ps",),
            0,
            b"123 1 123 Mon Aug 23 10:00:00 2026\n",
            b"",
        )
        second = subprocess.CompletedProcess(("ps",), 0, b"", b"")
        with (
            mock.patch.object(Path, "is_dir", return_value=False),
            mock.patch(
                "torturer_checks.hosted.cli.subprocess.run",
                side_effect=[first, second],
            ) as run,
        ):
            provider = _ProcessSnapshotProvider()
            self.assertEqual(len(provider()), 1)
            # The monitor's short cache is intentional, but must not cross a
            # completion/cleanup proof boundary.
            self.assertEqual(len(provider()), 1)
            provider.invalidate()
            self.assertEqual(provider(), {})
        self.assertEqual(run.call_count, 2)

    def test_macos_malformed_process_census_is_not_used_for_cleanup_proof(self) -> None:
        completed = subprocess.CompletedProcess(
            ("ps",),
            0,
            b"123 1 123 Mon Aug 23 10:00:00 2026\nnot-a-process-row\n",
            b"",
        )
        with (
            mock.patch.object(Path, "is_dir", return_value=False),
            mock.patch("torturer_checks.hosted.cli.subprocess.run", return_value=completed),
        ):
            provider = _ProcessSnapshotProvider()
            self.assertIsNone(provider())
        self.assertIn(b"MAC_PROCESS_CENSUS_PARSE_ERROR=1", provider.diagnostics)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1", provider.diagnostics)

    def test_subprocess_runner_never_overwrites_another_runner_sequence(self) -> None:
        raw = Path(self.directory.name) / "shared-raw"
        first = SubprocessRunner(raw)
        second = SubprocessRunner(raw)
        first.run(
            (sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'first\\n')"),
            timeout_seconds=5,
        )
        second.run(
            (sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'second\\n')"),
            timeout_seconds=5,
        )
        retained = sorted(raw.glob("command-001*.raw.log"))
        self.assertEqual(len(retained), 2)
        contents = {path.read_bytes() for path in retained}
        self.assertEqual(sum(b"first\\n" in item for item in contents), 1)
        self.assertEqual(sum(b"second\\n" in item for item in contents), 1)
        self.assertEqual(
            {first.safe_evidence()[0]["evidence_id"], second.safe_evidence()[0]["evidence_id"]},
            {first.safe_evidence()[0]["evidence_id"], second.safe_evidence()[0]["evidence_id"]},
        )
        self.assertNotEqual(first.safe_evidence()[0]["evidence_id"], second.safe_evidence()[0]["evidence_id"])
        self.assertTrue(all((path.stat().st_mode & 0o777) == 0o600 for path in retained))

    @unittest.skipUnless(os.name == "posix", "process-group assertion requires POSIX")
    def test_subprocess_runner_kills_child_process_group_on_timeout(self) -> None:
        raw = Path(self.directory.name) / "timeout-raw"
        runner = SubprocessRunner(raw)
        child_script = "import time; time.sleep(60)"
        parent_script = (
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable, '-c', sys.argv[1]]); "
            "print(child.pid, flush=True); time.sleep(60)"
        )
        with self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"):
            runner.run(
                (sys.executable, "-c", parent_script, child_script),
                timeout_seconds=0.5,
            )

        retained = next(raw.glob("command-001*.raw.log"))
        child_pid = int(
            retained.read_text().split("stdout-begin\n", 1)[1].split("\nstdout-end", 1)[0].strip()
        )
        for _ in range(40):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            stat_path = Path(f"/proc/{child_pid}/stat")
            if stat_path.exists() and stat_path.read_text(encoding="ascii").split(") ", 1)[1].split()[0] == "Z":
                break
            time.sleep(0.05)
        else:
            self.fail(f"timed-out child process {child_pid} survived the process-group kill")

    @unittest.skipUnless(os.name == "posix", "process-tree timing assertion requires POSIX")
    def test_subprocess_runner_timeout_is_one_total_wall_clock_budget(self) -> None:
        raw = Path(self.directory.name) / "total-bound-raw"
        runner = SubprocessRunner(raw)
        started = time.monotonic()
        with self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"):
            runner.run(
                (sys.executable, "-c", "import time; time.sleep(60)"),
                timeout_seconds=0.4,
            )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.2)
        evidence = runner.safe_evidence()
        self.assertEqual(len(evidence), 1)
        self.assertIn("timed_out", evidence[0])

    @unittest.skipUnless(os.name == "posix", "process-tree reaping assertion requires POSIX")
    def test_subprocess_runner_reaps_leader_when_cleanup_tail_is_tiny(self) -> None:
        raw = Path(self.directory.name) / "tiny-reap-raw"
        runner = SubprocessRunner(raw)
        with warnings.catch_warnings(record=True) as observed:
            warnings.simplefilter("always", ResourceWarning)
            with self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"):
                runner.run(
                    (sys.executable, "-c", "import time; time.sleep(60)"),
                    timeout_seconds=0.2,
                )
            gc.collect()
        self.assertFalse(
            [warning for warning in observed if issubclass(warning.category, ResourceWarning)],
            "timeout cleanup must reap the leader before returning",
        )

    @unittest.skipUnless(os.name == "posix", "non-blocking pipe EOF proof requires POSIX")
    def test_bounded_reap_distinguishes_reaped_leader_from_complete_pipe_eof(self) -> None:
        process = subprocess.Popen(
            (sys.executable, "-c", "import sys; print('stdout-marker'); print('stderr-marker', file=sys.stderr)"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.wait(timeout=2.0)

        reaped, output_complete, stdout, stderr, diagnostics = _bounded_reap_process(
            process, 0.0
        )

        self.assertTrue(reaped)
        self.assertTrue(output_complete)
        self.assertEqual(stdout, b"stdout-marker\n")
        self.assertEqual(stderr, b"stderr-marker\n")
        self.assertEqual(diagnostics, b"")

    def test_windows_bounded_reap_drains_reader_output_while_polling(self) -> None:
        class WindowsProcess:
            stdout = None
            stderr = None

            def __init__(self) -> None:
                self.calls = 0
                self.polls = 0
                self.returncode: int | None = None

            def poll(self) -> int | None:
                self.polls += 1
                return self.returncode

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(
                        ("fake",), timeout, output=b"first-out", stderr=b"first-err"
                    )
                self.returncode = 0
                return b"first-out", b"first-err"

        process = WindowsProcess()
        with mock.patch("torturer_checks.hosted.cli.os.name", "nt"):
            reaped, output_complete, stdout, stderr, diagnostics = _bounded_reap_process(
                process, deadline=time.monotonic() + 0.2  # type: ignore[arg-type]
            )

        self.assertTrue(reaped)
        self.assertTrue(output_complete)
        self.assertEqual(stdout, b"first-out")
        self.assertEqual(stderr, b"first-err")
        self.assertEqual(diagnostics, b"")
        self.assertGreaterEqual(process.calls, 2)
        self.assertGreaterEqual(process.polls, 2)

    def test_windows_failed_start_time_lookup_is_not_proven_gone(self) -> None:
        identity = _ProcessIdentity(42, "creation-time")
        census = {42: (1, 0, "", "R")}
        with (
            mock.patch("torturer_checks.hosted.cli.os.name", "nt"),
            mock.patch("torturer_checks.hosted.cli._process_snapshot", return_value=census),
        ):
            self.assertIsNone(_identity_live(identity))
            self.assertEqual(_tree_status(42, (identity,)), "unknown")

    @unittest.skipUnless(os.name == "posix", "direct process probe fallback is POSIX-only")
    def test_tree_status_uses_direct_probe_only_after_complete_census(self) -> None:
        vanished = (_ProcessIdentity(999999, "vanished", 999999),)
        with mock.patch(
            "torturer_checks.hosted.cli._process_snapshot", return_value=None
        ):
            self.assertEqual(
                _tree_status(
                    999999,
                    vanished,
                    allow_direct_fallback=True,
                    census_complete=True,
                ),
                "gone",
            )
            # A failed/incomplete census cannot use the same disappearance
            # race fallback; it must remain unknown and fail closed.
            self.assertEqual(
                _tree_status(
                    999999,
                    vanished,
                    allow_direct_fallback=True,
                    census_complete=False,
                ),
                "unknown",
            )

    @unittest.skipUnless(os.name == "posix", "direct process probe fallback is POSIX-only")
    def test_tree_status_direct_probe_precedes_slow_final_census(self) -> None:
        identity = (_ProcessIdentity(999999, "vanished", 999999),)
        with (
            mock.patch(
                "torturer_checks.hosted.cli._direct_tree_status",
                return_value="gone",
            ) as direct_probe,
            mock.patch(
                "torturer_checks.hosted.cli._process_snapshot",
                side_effect=AssertionError("slow full census must not run first"),
            ),
        ):
            self.assertEqual(
                _tree_status(
                    999999,
                    identity,
                    allow_direct_fallback=True,
                    census_complete=True,
                ),
                "gone",
            )
        direct_probe.assert_called_once()

    @unittest.skipUnless(os.name == "posix", "direct process probe is POSIX-only")
    def test_direct_tree_proof_cannot_cross_its_absolute_deadline(self) -> None:
        identity = (_ProcessIdentity(42, "start", 42),)

        class Clock:
            now = 0.0

            def monotonic(self) -> float:
                return self.now

        clock = Clock()

        def late_identity(*_args, **_kwargs) -> bool:
            clock.now = 2.0
            return False

        with (
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic",
                side_effect=clock.monotonic,
            ),
            mock.patch(
                "torturer_checks.hosted.cli._identity_live",
                side_effect=late_identity,
            ),
            mock.patch("torturer_checks.hosted.cli.os.killpg") as killpg,
        ):
            self.assertEqual(
                _direct_tree_status(42, identity, deadline=1.0), "unknown"
            )
        killpg.assert_not_called()

        clock.now = 0.0

        def late_group_probe(*_args, **_kwargs) -> None:
            clock.now = 2.0
            raise ProcessLookupError

        with (
            mock.patch(
                "torturer_checks.hosted.cli.time.monotonic",
                side_effect=clock.monotonic,
            ),
            mock.patch(
                "torturer_checks.hosted.cli._identity_live", return_value=False
            ),
            mock.patch(
                "torturer_checks.hosted.cli.os.killpg",
                side_effect=late_group_probe,
            ),
        ):
            self.assertEqual(
                _direct_tree_status(42, identity, deadline=1.0), "unknown"
            )

    @unittest.skipUnless(os.name == "posix", "process identity probe is POSIX-only")
    def test_posix_identity_probe_error_is_not_proven_gone(self) -> None:
        identity = _ProcessIdentity(42, "creation-time")
        with mock.patch(
            "torturer_checks.hosted.cli._proc_stat",
            side_effect=_ProcessProbeError("identity probe failed"),
        ):
            self.assertIsNone(_identity_live(identity))

    @unittest.skipUnless(os.name == "posix", "procfs child traversal is POSIX-only")
    def test_linux_child_walk_reads_every_task_and_fails_closed_on_malformed_state(self) -> None:
        proc_root = Path(self.directory.name) / "proc"
        task_root = proc_root / "42" / "task"
        for task, children in (("42", "100 101\n"), ("43", "102\n")):
            directory = task_root / task
            directory.mkdir(parents=True)
            (directory / "children").write_text(children, encoding="ascii")

        real_path = Path

        def mapped_path(value: str) -> Path:
            if value == "/proc/42/task":
                return task_root
            return real_path(value)

        with mock.patch("torturer_checks.hosted.cli.Path", side_effect=mapped_path):
            self.assertEqual(_linux_child_pids(42), (100, 101, 102))
            (task_root / "43" / "children").write_text(
                "not-a-pid\n", encoding="ascii"
            )
            with self.assertRaises(_ProcessProbeError):
                _linux_child_pids(42)

    def test_timeout_output_oserror_retains_partial_bytes_and_marks_incomplete(self) -> None:
        raw = Path(self.directory.name) / "timeout-oserror-raw"

        class FakeMonitor:
            identities = ()

            def start(self) -> None:
                return None

            def stop(self, timeout: float) -> bool:
                return True

        class FakeProcess:
            pid = 12345
            returncode = 0
            stdout = None
            stderr = None

            def __init__(self) -> None:
                self.calls = 0

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(
                        ("fake",), timeout, output=b"before-", stderr=b"before-err"
                    )
                error = OSError("injected pipe failure")
                error.stdout = b"after-"  # type: ignore[attr-defined]
                error.stderr = b"after-err"  # type: ignore[attr-defined]
                raise error

            def poll(self) -> int | None:
                return self.returncode

        with (
            mock.patch("torturer_checks.hosted.cli.subprocess.Popen", return_value=FakeProcess()),
            mock.patch("torturer_checks.hosted.cli._ProcessTreeMonitor", return_value=FakeMonitor()),
            mock.patch(
                "torturer_checks.hosted.cli._kill_process_tree",
                return_value=b"PROCESS_TREE_STATUS=gone\n",
            ),
            self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"),
        ):
            SubprocessRunner(raw).run(("fake",), timeout_seconds=0.2)

        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"before-after-", retained)
        self.assertIn(b"before-errafter-err", retained)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1 reason=output-drain-error", retained)

    def test_bounded_capture_post_timeout_oserror_keeps_bytes_and_kill_error(self) -> None:
        class FakeHelper:
            stdout = None
            stderr = None
            returncode = None

            def __init__(self) -> None:
                self.calls = 0

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(
                        ("fake",), timeout, output=b"before-", stderr=b"before-err"
                    )
                error = OSError("injected helper pipe failure")
                error.stdout = b"after-"  # type: ignore[attr-defined]
                error.stderr = b"after-err"  # type: ignore[attr-defined]
                raise error

            def kill(self) -> None:
                raise OSError("injected kill failure")

        helper = FakeHelper()
        with (
            mock.patch("torturer_checks.hosted.cli.subprocess.Popen", return_value=helper),
            mock.patch(
                "torturer_checks.hosted.cli._bounded_reap_process",
                return_value=(True, False, b"drained-", b"drained-err", b""),
            ),
        ):
            code, stdout, stderr, timed_out = _bounded_capture(
                ("fake",), timeout=0.2
            )

        self.assertIsNone(code)
        self.assertTrue(timed_out)
        self.assertIn(b"before-after-", stdout)
        self.assertIn(b"before-errafter-err", stderr)
        self.assertIn(b"PROCESS_KILL_ERROR=", stderr)
        self.assertIn(b"OUTPUT_DRAIN_ERROR=", stderr)
        self.assertIn(b"EVIDENCE_INCOMPLETE=1", stderr)

    @unittest.skipUnless(os.name == "posix", "process-group reaping assertion requires POSIX")
    def test_subprocess_runner_reserves_reap_tail_after_tree_cleanup(self) -> None:
        raw = Path(self.directory.name) / "reap-reserve-raw"
        runner = SubprocessRunner(raw)
        communicate_timeouts: list[float] = []
        reap_timeouts: list[float] = []

        class FakeMonitor:
            identities = ()

            def start(self) -> None:
                return None

            def stop(self, timeout: float) -> bool:
                return True

        class FakeProcess:
            pid = 12345
            returncode = None
            stdout = None
            stderr = None

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                communicate_timeouts.append(timeout)
                raise subprocess.TimeoutExpired(("fake",), timeout, output=b"partial-out", stderr=b"partial-err")

            def poll(self) -> None:
                return None

            def kill(self) -> None:
                return None

        process = FakeProcess()

        def reap(
            _process: FakeProcess,
            timeout: float | None = None,
            *,
            deadline: float | None = None,
        ) -> tuple[bool, bool, bytes, bytes, bytes]:
            if deadline is not None:
                timeout = max(0.0, deadline - time.monotonic())
            assert timeout is not None
            reap_timeouts.append(timeout)
            return True, True, b"drained-out", b"drained-err", b""

        def tree_cleanup(*_args, **_kwargs) -> bytes:
            time.sleep(0.1)
            return b"PROCESS_TREE_STATUS=gone\n"

        with (
            mock.patch("torturer_checks.hosted.cli.subprocess.Popen", return_value=process),
            mock.patch("torturer_checks.hosted.cli._ProcessTreeMonitor", return_value=FakeMonitor()),
            mock.patch("torturer_checks.hosted.cli._kill_process_tree", side_effect=tree_cleanup),
            mock.patch("torturer_checks.hosted.cli._tree_status", return_value="gone"),
            mock.patch("torturer_checks.hosted.cli._tracked_processes", return_value=()),
            mock.patch("torturer_checks.hosted.cli._kill_process", return_value=b""),
            mock.patch("torturer_checks.hosted.cli._bounded_reap_process", side_effect=reap),
            self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"),
        ):
            runner.run(("fake",), timeout_seconds=0.2)

        self.assertEqual(len(communicate_timeouts), 2)
        self.assertGreaterEqual(len(reap_timeouts), 1)
        # A 0.2-second budget has a 0.1-second cleanup reserve and must leave
        # the explicit 0.05-second reaping tail after the drain attempt.
        self.assertLessEqual(communicate_timeouts[1], 0.08)
        self.assertTrue(all(timeout <= 0.05 for timeout in reap_timeouts))
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"drained-out", retained)
        self.assertIn(b"drained-err", retained)

    @unittest.skipUnless(os.name == "posix", "process-proof deadline assertion requires POSIX")
    def test_final_tree_proof_has_reserved_interval_before_reap_tail(self) -> None:
        raw = Path(self.directory.name) / "proof-deadline-raw"
        runner = SubprocessRunner(raw)

        class Clock:
            now = 100.0

            def monotonic(self) -> float:
                return self.now

        clock = Clock()
        proof_observations: list[tuple[float, float]] = []

        class FakeMonitor:
            identities = ()

            def start(self) -> None:
                return None

            def stop(self, timeout: float) -> bool:
                return True

        class FakeProcess:
            pid = 12345
            returncode = 0
            stdout = None
            stderr = None

            def __init__(self) -> None:
                self.calls = 0

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(
                        ("fake",), timeout, output=b"partial-out", stderr=b"partial-err"
                    )
                return b"drained-out", b"drained-err"

            def poll(self) -> int:
                return self.returncode

        def tree_cleanup(*_args, **kwargs) -> bytes:
            old_cleanup_deadline = float(kwargs["deadline"])
            # Put the proof call after the old cleanup-work boundary while it
            # is still strictly inside the caller's absolute deadline.
            clock.now = old_cleanup_deadline + 0.01
            return b"PROCESS_TREE_STATUS=unknown\n"

        def tree_status(*_args, **kwargs) -> str:
            proof_observations.append((clock.now, float(kwargs["deadline"])))
            return "gone"

        def reap(*_args, **_kwargs):
            return True, True, b"", b"", b""

        with (
            mock.patch("torturer_checks.hosted.cli.time.monotonic", side_effect=clock.monotonic),
            mock.patch("torturer_checks.hosted.cli.subprocess.Popen", return_value=FakeProcess()),
            mock.patch("torturer_checks.hosted.cli._ProcessTreeMonitor", return_value=FakeMonitor()),
            mock.patch("torturer_checks.hosted.cli._kill_process_tree", side_effect=tree_cleanup),
            mock.patch("torturer_checks.hosted.cli._tree_status", side_effect=tree_status),
            mock.patch("torturer_checks.hosted.cli._bounded_reap_process", side_effect=reap),
            self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"),
        ):
            runner.run(("fake",), timeout_seconds=0.5)

        self.assertGreaterEqual(len(proof_observations), 2)
        pre_reap_now, pre_reap_deadline = proof_observations[0]
        self.assertGreaterEqual(pre_reap_now, 100.4)
        self.assertLess(pre_reap_now, 100.5)
        self.assertAlmostEqual(pre_reap_deadline, 100.45)
        self.assertAlmostEqual(proof_observations[-1][1], 100.5)
        retained = next(raw.glob("command-001*.raw.log")).read_bytes()
        self.assertIn(b"partial-out", retained)
        self.assertIn(b"drained-out", retained)
        self.assertIn(b"PROCESS_TREE_STATUS=gone", retained)

    @unittest.skipUnless(os.name == "posix", "detached process-tree assertion requires POSIX")
    def test_subprocess_runner_kills_detached_resistant_descendant_and_retains_markers(self) -> None:
        raw = Path(self.directory.name) / "detached-timeout-raw"
        runner = SubprocessRunner(raw)
        child_script = (
            "import os,signal,time,sys; os.setsid(); signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('detached descendant stdout', flush=True); "
            "print('detached descendant stderr', file=sys.stderr, flush=True); time.sleep(60)"
        )
        parent_script = (
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable, '-c', sys.argv[1]]); "
            "print(child.pid, flush=True); time.sleep(60)"
        )
        with (
            mock.patch(
                "torturer_checks.hosted.cli._process_snapshot",
                side_effect=AssertionError(
                    "Linux command monitoring must not scan unrelated host processes"
                ),
            ),
            self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"),
        ):
            runner.run(
                (sys.executable, "-c", parent_script, child_script),
                timeout_seconds=0.6,
            )

        retained = next(raw.glob("command-001*.raw.log"))
        content = retained.read_bytes()
        self.assertIn(b"detached descendant stdout", content)
        self.assertIn(b"detached descendant stderr", content)
        self.assertIn(b"PROCESS_TREE_TRACKED=", content)
        self.assertIn(b"PROCESS_TREE_STATUS=gone", content)
        self.assertNotIn(b"EVIDENCE_INCOMPLETE=1", content)

    @unittest.skipUnless(os.name == "posix", "process-group assertion requires POSIX")
    def test_subprocess_runner_rejects_zero_exit_leader_with_detached_descendant(self) -> None:
        raw = Path(self.directory.name) / "zero-exit-detached-raw"
        runner = SubprocessRunner(raw)
        child_script = (
            "import os,signal,time; os.setsid(); signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "os.close(1); os.close(2); time.sleep(60)"
        )
        parent_script = (
            "import os,subprocess,sys; child=subprocess.Popen([sys.executable, '-c', sys.argv[1]]); "
            "print(child.pid, flush=True); os._exit(0)"
        )
        child_pid: int | None = None
        try:
            with self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"):
                runner.run(
                    (sys.executable, "-c", parent_script, child_script),
                    timeout_seconds=0.8,
                )
            retained = next(raw.glob("command-001*.raw.log"))
            content = retained.read_bytes()
            child_pid = int(
                content.split(b"stdout-begin\n", 1)[1]
                .split(b"\nstdout-end", 1)[0]
                .strip()
            )
            self.assertIn(b"PROCESS_TREE_STATUS=gone", content)
            self.assertNotIn(b"EVIDENCE_INCOMPLETE=1", content)
            self.assertNotIn(b"ResourceWarning", content)
            for _ in range(40):
                stat_path = Path(f"/proc/{child_pid}/stat")
                try:
                    state = stat_path.read_text(encoding="ascii").split(") ", 1)[1][0]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail(f"detached child process {child_pid} survived cleanup")
        finally:
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "process-tree drain assertion requires POSIX")
    def test_subprocess_runner_marks_evidence_incomplete_after_drain_timeout(self) -> None:
        raw = Path(self.directory.name) / "drain-timeout-raw"
        runner = SubprocessRunner(raw)
        parent_script = (
            "import pathlib,subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            "print(child.pid, flush=True); time.sleep(60)"
        )
        try:
            with mock.patch(
                "torturer_checks.hosted.cli._kill_process_tree",
                return_value=b"PROCESS_TREE_STATUS=gone\n",
            ):
                with mock.patch(
                    "torturer_checks.hosted.cli._signal_tracked",
                    return_value=b"",
                ):
                    with self.assertRaisesRegex(HostedAdapterError, "COMMAND_TIMEOUT"):
                        runner.run(
                            (sys.executable, "-c", parent_script),
                            timeout_seconds=0.6,
                        )
            retained = next(raw.glob("command-001*.raw.log"))
            content = retained.read_bytes()
            self.assertIn(b"OUTPUT_DRAIN_TIMEOUT=1", content)
            self.assertRegex(content, rb"PROCESS_TREE_FINAL_STATUS=(alive|unknown)")
            self.assertIn(b"EVIDENCE_INCOMPLETE=1", content)
        finally:
            try:
                child_pid = int(
                    next(raw.glob("command-001*.raw.log"))
                    .read_text(encoding="utf-8")
                    .split("stdout-begin\n", 1)[1]
                    .split("\nstdout-end", 1)[0]
                    .strip()
                )
                os.kill(child_pid, 9)
            except (FileNotFoundError, IndexError, ValueError, ProcessLookupError):
                pass

    def test_throughput_urls_reject_query_fragment_and_userinfo(self) -> None:
        for invalid in (
            "https://download.example.test/blob?token=x",
            "https://download.example.test/blob#fragment",
            "https://user:password@download.example.test/blob",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(HostedAdapterError, "THROUGHPUT_URL_INVALID"):
                    HostedCLIAdapter(
                        cli=self.cli,
                        profile=self.profile,
                        runner=self.runner,
                        download_url=invalid,
                        upload_url="https://upload.example.test/blob",
                    )
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
