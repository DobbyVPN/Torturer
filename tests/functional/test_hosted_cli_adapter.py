from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from torturer_checks.hosted.cli import CommandResult, HostedAdapterError, HostedCLIAdapter, SubprocessRunner
from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import FunctionalEngine
from torturer_contract.functional.scenarios import get_scenario


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.connected = False
        self.external_calls = 0

    def run(self, command, *, timeout_seconds):
        del timeout_seconds
        argv = tuple(command)
        self.calls.append(argv)
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
            value = b"198.51.100.10\n" if self.external_calls == 1 else b"203.0.113.10\n"
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

    def test_cleanup_scenario_proves_disconnect_and_cleanup(self) -> None:
        scenario = get_scenario("functional.disconnect-cleanup")
        engine = FunctionalEngine(scenario_set_digest="b" * 64)
        result = engine.run(scenario, self.adapter, _provenance(self.adapter))
        self.assertEqual(result.outcome, "passed")
        self.assertTrue(result.cleanup["verified"])

    def test_unsupported_capabilities_are_explicitly_unavailable(self) -> None:
        scenario = get_scenario("functional.sleep-wake")
        engine = FunctionalEngine(scenario_set_digest="c" * 64)
        result = engine.run(scenario, self.adapter, _provenance(self.adapter))
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(result.reason_code, "CAPABILITY_UNAVAILABLE")

    def test_subprocess_runner_retains_complete_stdout_and_stderr_bytes(self) -> None:
        raw = Path(self.directory.name) / "raw"
        runner = SubprocessRunner(raw)
        result = runner.run(
            ("python3", "-c", "import sys; sys.stdout.buffer.write(b'out\\n'); sys.stderr.buffer.write(b'err\\n')"),
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        retained = (raw / "command-001.raw.log").read_bytes()
        self.assertIn(b"out\n", retained)
        self.assertIn(b"err\n", retained)

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
