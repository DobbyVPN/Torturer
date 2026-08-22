from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from torturer_contract.functional import (
    Capability,
    FunctionalEngine,
    ResultValidationError,
    ScenarioAdapter,
    evaluate_assertion,
    get_scenario,
    scenario_catalog,
)
from torturer_contract.functional.results import RunProvenance, ScenarioResult, validate_result_payload
from torturer_contract.functional.scenarios import catalog_document


class FakeAdapter:
    def __init__(self, *, capabilities: frozenset[Capability] | None = None, failure: Exception | None = None):
        self._capabilities = capabilities if capabilities is not None else frozenset(Capability)
        self.failure = failure
        self.calls: list[str] = []

    @property
    def capabilities(self) -> frozenset[Capability]:
        return self._capabilities

    def execute(self, step):
        self.calls.append(step.operation)
        if self.failure is not None:
            raise self.failure
        result = {
            "configured": True,
            "tunnel_interface": True,
            "routing_identity_changed": True,
            "stability_verified": True,
            "disconnect_clean": True,
            "cleanup_verified": True,
            "restart_verified": True,
            "reconnect_bounded": True,
            "network_transition_verified": True,
            "sleep_wake_verified": True,
            "process_loss_verified": True,
            "endurance_verified": True,
            "latency_ms": 12.5,
            "download_mbps": 10.0,
            "upload_mbps": 5.0,
        }
        if step.id == "second-tunnel":
            result["second_tunnel_interface"] = True
        if step.id == "second-routing":
            result["second_routing_identity_changed"] = True
        if step.id == "final-disconnect":
            result["final_disconnect_clean"] = True
        return result


def provenance() -> RunProvenance:
    return RunProvenance(
        source_repository="DobbyVPN/DobbyVPN",
        source_sha="a" * 40,
        torturer_sha="b" * 40,
        artifact_sha256="c" * 64,
        server_image_digest="sha256:" + "d" * 64,
        platform="linux",
        adapter_id="fake-linux",
        adapter_version="v1",
        capabilities=frozenset(capability.value for capability in Capability),
    )


class FunctionalContractTests(unittest.TestCase):
    def test_catalog_is_complete_unique_and_bounded(self):
        scenarios = scenario_catalog()
        ids = [scenario.id for scenario in scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            set(ids),
            {
                "functional.core-connection",
                "functional.configure",
                "functional.connect-route-identity",
                "functional.stability-throughput",
                "functional.disconnect-cleanup",
                "functional.start-stop-start",
                "functional.network-transition",
                "functional.sleep-wake",
                "functional.product-process-loss",
                "functional.bounded-endurance",
            },
        )
        for scenario in scenarios:
            self.assertEqual(scenario.version, 1)
            self.assertGreater(scenario.max_duration_seconds, 0)
            self.assertLessEqual(
                sum(step.timeout_seconds for step in scenario.steps),
                scenario.max_duration_seconds,
            )

    def test_catalog_document_matches_schema_fixture_shape(self):
        document = catalog_document()
        schema_path = Path(__file__).parents[2] / "torturer_contract/functional/schema/scenario-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], schema["properties"]["schema"]["const"])
        self.assertEqual(document["kind"], schema["properties"]["kind"]["const"])
        self.assertEqual(len(document["scenarios"]), len(scenario_catalog()))

    def test_assertions_have_stable_semantics(self):
        observations = {
            "configured": True,
            "tunnel_interface": True,
            "routing_identity_changed": True,
            "latency_ms": 1,
            "download_mbps": 2,
            "upload_mbps": 3,
        }
        self.assertTrue(evaluate_assertion("configure.accepted", observations).passed)
        self.assertTrue(evaluate_assertion("traffic.metrics_positive", observations).passed)
        observations["upload_mbps"] = 0
        self.assertFalse(evaluate_assertion("traffic.metrics_positive", observations).passed)

    def test_engine_runs_semantic_steps_and_returns_pass(self):
        adapter = FakeAdapter()
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.start-stop-start"), adapter, provenance()
        )
        self.assertEqual(result.outcome, "passed")
        self.assertEqual(
            adapter.calls,
            ["configure", "connect", "observe_tunnel", "observe_routing_identity", "disconnect", "reconnect", "observe_tunnel", "observe_routing_identity", "disconnect", "inspect_cleanup"],
        )
        self.assertTrue(result.cleanup["verified"])
        self.assertEqual(result.to_dict()["schema"], 1)

    def test_restart_second_cycle_failure_cannot_be_masked(self):
        class SecondCycleFailureAdapter(FakeAdapter):
            def execute(self, step):
                result = super().execute(step)
                if step.id == "second-tunnel":
                    result["second_tunnel_interface"] = False
                if step.id == "second-routing":
                    result["second_routing_identity_changed"] = True
                if step.id == "final-disconnect":
                    result["final_disconnect_clean"] = True
                return result

        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.start-stop-start"),
            SecondCycleFailureAdapter(),
            provenance(),
        )
        self.assertEqual(result.outcome, "failed")
        self.assertIn(
            {"id": "tunnel.second_established", "passed": False},
            result.to_dict()["assertions"],
        )

    def test_non_throughput_result_does_not_require_metrics(self):
        class NoMetricAdapter(FakeAdapter):
            def execute(self, step):
                value = super().execute(step)
                for key in ("latency_ms", "download_mbps", "upload_mbps"):
                    value.pop(key, None)
                return value

        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.disconnect-cleanup"), NoMetricAdapter(), provenance()
        )
        self.assertEqual(result.outcome, "passed")
        self.assertEqual(result.metrics, {})
        validate_result_payload(result.to_dict())

    def test_private_provenance_can_omit_render_image_digest(self):
        private = RunProvenance(
            source_repository="DobbyVPN/DobbyVPN",
            source_sha="a" * 40,
            torturer_sha="b" * 40,
            artifact_sha256="c" * 64,
            server_image_digest=None,
            platform="linux",
            adapter_id="private-harness-linux",
            adapter_version="v1",
            capabilities=frozenset({"configure"}),
            provider_kind="private",
        )
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.configure"),
            FakeAdapter(capabilities=frozenset({Capability.CONFIGURE})),
            private,
        )
        self.assertEqual(result.outcome, "passed")
        payload = result.to_dict()
        self.assertEqual(payload["provenance"]["provider_kind"], "private")
        self.assertNotIn("server_image_digest", payload["provenance"])
        validate_result_payload(payload)

    def test_render_provenance_without_image_digest_is_rejected(self):
        with self.assertRaises(ResultValidationError):
            RunProvenance(
                source_repository="DobbyVPN/DobbyVPN",
                source_sha="a" * 40,
                torturer_sha="b" * 40,
                artifact_sha256="c" * 64,
                server_image_digest=None,
                platform="linux",
                adapter_id="fake-linux",
                adapter_version="v1",
                capabilities=frozenset({"configure"}),
            )

    def test_engine_reports_missing_capability_as_unavailable(self):
        adapter = FakeAdapter(capabilities=frozenset({Capability.CONFIGURE}))
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.connect-route-identity"), adapter, provenance()
        )
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(result.reason_code, "CAPABILITY_UNAVAILABLE")
        self.assertEqual(adapter.calls, [])

    def test_engine_reports_adapter_failure_without_echoing_exception(self):
        adapter = FakeAdapter(failure=RuntimeError("synthetic private detail"))
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.configure"), adapter, provenance()
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "ADAPTER_ERROR")
        self.assertNotIn("synthetic", result.to_json())

    def test_result_validator_rejects_unsafe_or_incomplete_payloads(self):
        adapter = FakeAdapter()
        result = FunctionalEngine("e" * 64).run(
            get_scenario("functional.stability-throughput"), adapter, provenance()
        )
        payload = result.to_dict()
        validate_result_payload(payload)

        unsafe = copy.deepcopy(payload)
        unsafe["profile"] = "synthetic-secret"
        with self.assertRaises(ResultValidationError):
            validate_result_payload(unsafe)

        invalid_metrics = copy.deepcopy(payload)
        invalid_metrics["metrics"]["download_mbps"] = 0
        with self.assertRaises(ResultValidationError):
            validate_result_payload(invalid_metrics)

        missing_metrics = copy.deepcopy(payload)
        missing_metrics["metrics"] = {}
        with self.assertRaises(ResultValidationError):
            validate_result_payload(missing_metrics)

        missing_reason = copy.deepcopy(payload)
        missing_reason["outcome"] = "failed"
        missing_reason.pop("reason_code", None)
        with self.assertRaises(ResultValidationError):
            validate_result_payload(missing_reason)


if __name__ == "__main__":
    unittest.main()
