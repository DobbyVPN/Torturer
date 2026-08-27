from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import time
import unittest

from torturer_contract.functional import (
    AssertionOutcome,
    Capability,
    EvidenceReference,
    FunctionalEngine,
    ResultValidationError,
    ScenarioResult,
    evaluate_assertion,
    get_scenario,
    scenario_catalog,
)
from torturer_contract.functional.results import RunProvenance, validate_result_payload
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
        platform_version="24.04",
        architecture="amd64",
        artifact_kind="package",
        artifact_manifest_sha256="d" * 64,
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

        endurance = get_scenario("functional.bounded-endurance")
        self.assertIn(
            "traffic.metrics_positive",
            endurance.assertion_ids,
        )

    def test_cleanup_assertions_have_an_explicit_disconnect_step(self):
        for scenario in scenario_catalog():
            if "cleanup.restored" not in scenario.assertion_ids:
                continue
            operations = [step.operation for step in scenario.steps]
            cleanup_index = operations.index("inspect_cleanup")
            self.assertGreater(cleanup_index, 0, scenario.id)
            self.assertEqual(operations[cleanup_index - 1], "disconnect", scenario.id)
            self.assertIn(Capability.DISCONNECT, scenario.required_capabilities, scenario.id)
            self.assertTrue(
                {"disconnect.clean", "disconnect.final_clean"} & set(scenario.assertion_ids),
                scenario.id,
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

    def test_result_contains_identity_timing_and_evidence_metadata(self):
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        provider_calls = []

        def evidence_provider():
            provider_calls.append(True)
            return (reference,)

        result = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            FakeAdapter(),
            provenance(),
            evidence_provider=evidence_provider,
        )
        payload = result.to_dict()
        self.assertEqual(provider_calls, [True])
        self.assertEqual(payload["schema"], 2)
        self.assertEqual(payload["provenance"]["platform_version"], "24.04")
        self.assertEqual(payload["provenance"]["architecture"], "amd64")
        self.assertEqual(payload["provenance"]["artifact_kind"], "package")
        self.assertEqual(payload["provenance"]["artifact_sha256"], "c" * 64)
        self.assertEqual(payload["provenance"]["artifact_manifest_sha256"], "d" * 64)
        self.assertLessEqual(payload["monotonic_start_ns"], payload["monotonic_end_ns"])
        self.assertIn("execution", payload["phase_durations_ms"])
        self.assertEqual(payload["evidence_refs"], [{"id": "command-001", "bytes": 17, "sha256": "f" * 64}])
        validate_result_payload(payload)

    def test_result_validator_rejects_missing_contract_metadata(self):
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        payload = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            FakeAdapter(),
            provenance(),
            evidence_provider=lambda: (reference,),
        ).to_dict()
        for key in ("monotonic_start_ns", "monotonic_end_ns", "phase_durations_ms", "evidence_refs"):
            invalid = copy.deepcopy(payload)
            invalid.pop(key)
            with self.subTest(key=key), self.assertRaises(ResultValidationError):
                validate_result_payload(invalid)

    def test_v1_contract_remains_unchanged_and_does_not_accept_v2_fields(self):
        payload = FunctionalEngine("e" * 64).run(
            get_scenario("functional.configure"), FakeAdapter(), provenance()
        ).to_dict()
        self.assertEqual(payload["schema"], 1)
        self.assertTrue(all(isinstance(item, str) for item in payload["evidence_refs"]))
        validate_result_payload(payload)
        payload["monotonic_start_ns"] = 1
        with self.assertRaises(ResultValidationError):
            validate_result_payload(payload)

    def test_v1_golden_payload_preserves_shape_and_default_omissions(self):
        result = ScenarioResult(
            scenario_id="functional.configure",
            scenario_version=1,
            scenario_set_digest="e" * 64,
            provenance=RunProvenance(
                source_repository="DobbyVPN/DobbyVPN",
                source_sha="a" * 40,
                torturer_sha="b" * 40,
                artifact_sha256="c" * 64,
                server_image_digest="sha256:" + "d" * 64,
                platform="linux",
                adapter_id="fake-linux",
                adapter_version="v1",
                capabilities=frozenset({"configure"}),
            ),
            outcome="passed",
            assertions=(AssertionOutcome("configure.accepted", True),),
            cleanup={"required": False, "verified": True},
            metrics={},
            duration_ms=17,
            evidence_refs=("command-001",),
        )
        expected = {
            "schema": 1,
            "scenario_id": "functional.configure",
            "scenario_version": 1,
            "scenario_set_digest": "e" * 64,
            "provenance": {
                "source_repository": "DobbyVPN/DobbyVPN",
                "source_sha": "a" * 40,
                "torturer_sha": "b" * 40,
                "artifact_sha256": "c" * 64,
                "server_image_digest": "sha256:" + "d" * 64,
                "platform": "linux",
                "adapter_id": "fake-linux",
                "adapter_version": "v1",
                "capabilities": ["configure"],
            },
            "outcome": "passed",
            "assertions": [{"id": "configure.accepted", "passed": True}],
            "cleanup": {"required": False, "verified": True},
            "metrics": {},
            "duration_ms": 17,
            "evidence_refs": ["command-001"],
        }
        self.assertEqual(result.to_dict(), expected)
        self.assertEqual(
            result.to_json(),
            json.dumps(expected, sort_keys=True, separators=(",", ":")),
        )
        self.assertNotIn("reason_code", result.to_dict())
        self.assertNotIn("monotonic_start_ns", result.to_dict())
        validate_result_payload(expected)

    def test_v2_evidence_provider_runs_for_unavailable_and_failed_paths(self):
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        calls = []

        def evidence_provider():
            calls.append(True)
            return (reference,)

        unavailable = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.connect-route-identity"),
            FakeAdapter(capabilities=frozenset({Capability.CONFIGURE})),
            provenance(),
            evidence_provider=evidence_provider,
        )
        failed = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            FakeAdapter(failure=RuntimeError("synthetic")),
            provenance(),
            evidence_provider=evidence_provider,
        )
        self.assertEqual((unavailable.outcome, failed.outcome), ("unavailable", "failed"))
        self.assertEqual(calls, [True, True])
        validate_result_payload(unavailable.to_dict())
        validate_result_payload(failed.to_dict())

    def test_v2_secret_markers_never_enter_success_failure_unavailable_or_exception_results(self):
        secret_marker = (
            "SECRET_MARKER profile-bytes bearer=credential endpoint=https://"
            "user:pass@private.example 198.51.100.77"
        )
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)

        class SecretObservationAdapter(FakeAdapter):
            def __init__(self, *, configured: bool = True, **kwargs):
                super().__init__(**kwargs)
                self.configured = configured

            def execute(self, step):
                observations = super().execute(step)
                observations["private_diagnostic"] = secret_marker
                if step.operation == "configure":
                    observations["configured"] = self.configured
                return observations

        def evidence_provider():
            return (reference,)

        success = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            SecretObservationAdapter(),
            provenance(),
            evidence_provider=evidence_provider,
        )
        failure = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            SecretObservationAdapter(configured=False),
            provenance(),
            evidence_provider=evidence_provider,
        )
        unavailable = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.connect-route-identity"),
            SecretObservationAdapter(capabilities=frozenset({Capability.CONFIGURE})),
            provenance(),
            evidence_provider=evidence_provider,
        )
        adapter_exception = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            FakeAdapter(failure=RuntimeError(secret_marker)),
            provenance(),
            evidence_provider=evidence_provider,
        )

        self.assertEqual(
            (success.outcome, failure.outcome, unavailable.outcome, adapter_exception.outcome),
            ("passed", "failed", "unavailable", "failed"),
        )
        for result in (success, failure, unavailable, adapter_exception):
            serialized = result.to_json()
            self.assertNotIn(secret_marker, serialized)
            self.assertNotIn("private_diagnostic", serialized)
            validate_result_payload(result.to_dict())

    def test_v2_timing_includes_blocking_evidence_finalization(self):
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)

        def blocking_provider():
            time.sleep(0.01)
            return (reference,)

        result = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            FakeAdapter(),
            provenance(),
            evidence_provider=blocking_provider,
        )
        payload = result.to_dict()
        self.assertGreaterEqual(payload["phase_durations_ms"]["evidence"], 5)
        self.assertGreaterEqual(
            payload["duration_ms"],
            sum(payload["phase_durations_ms"].values()),
        )
        validate_result_payload(payload)

    def test_v2_evidence_overrun_fails_closed_and_retains_references(self):
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        base = get_scenario("functional.configure")
        bounded = replace(
            base,
            steps=(replace(base.steps[0], timeout_seconds=1),),
            max_duration_seconds=1,
        )

        def overrun_provider():
            time.sleep(1.05)
            return (reference,)

        result = FunctionalEngine("e" * 64, schema_version=2).run(
            bounded,
            FakeAdapter(),
            provenance(),
            evidence_provider=overrun_provider,
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "SCENARIO_TIMEOUT")
        self.assertEqual(result.evidence_refs, (reference,))
        validate_result_payload(result.to_dict())

    def test_v2_rejects_static_evidence_default_without_a_sink_provider(self):
        with self.assertRaises(ResultValidationError):
            FunctionalEngine("e" * 64, schema_version=2).run(
                get_scenario("functional.configure"),
                FakeAdapter(),
                provenance(),
            )

    def test_v2_rejects_manifest_digest_reused_as_artifact_digest(self):
        duplicate = RunProvenance(
            source_repository="DobbyVPN/DobbyVPN",
            source_sha="a" * 40,
            torturer_sha="b" * 40,
            artifact_sha256="c" * 64,
            artifact_manifest_sha256="c" * 64,
            artifact_kind="package",
            server_image_digest="sha256:" + "d" * 64,
            platform="linux",
            platform_version="24.04",
            architecture="amd64",
            adapter_id="fake-linux",
            adapter_version="v1",
            capabilities=frozenset(capability.value for capability in Capability),
        )
        with self.assertRaisesRegex(
            ResultValidationError, "artifact and artifact-manifest digests must be distinct"
        ):
            FunctionalEngine("e" * 64, schema_version=2).run(
                get_scenario("functional.configure"),
                FakeAdapter(),
                duplicate,
                evidence_provider=lambda: (
                    EvidenceReference("command-001", 17, "f" * 64),
                ),
            )

    def test_private_provenance_rejects_render_image_digest(self):
        with self.assertRaisesRegex(
            ResultValidationError, "private provenance must not contain server_image_digest"
        ):
            RunProvenance(
                source_repository="DobbyVPN/DobbyVPN",
                source_sha="a" * 40,
                torturer_sha="b" * 40,
                artifact_sha256="c" * 64,
                artifact_manifest_sha256="d" * 64,
                server_image_digest="sha256:" + "e" * 64,
                platform="linux",
                adapter_id="private-harness-linux",
                adapter_version="v1",
                capabilities=frozenset({"configure"}),
                provider_kind="private",
                platform_version="private",
                architecture="amd64",
                artifact_kind="manifest",
            )

    def test_v2_phase_durations_cannot_exceed_total_duration(self):
        with self.assertRaisesRegex(
            ResultValidationError, "phase durations cannot exceed duration_ms"
        ):
            ScenarioResult(
                scenario_id="functional.configure",
                scenario_version=1,
                scenario_set_digest="e" * 64,
                provenance=provenance(),
                outcome="passed",
                assertions=(AssertionOutcome("configure.accepted", True),),
                cleanup={"required": False, "verified": True},
                metrics={},
                duration_ms=10,
                evidence_refs=(EvidenceReference("command-001", 17, "f" * 64),),
                schema_version=2,
                monotonic_start_ns=1,
                monotonic_end_ns=11,
                phase_durations_ms={"execution": 7, "evidence": 4},
            )

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

    def test_non_throughput_zero_metrics_are_omitted_from_v2_result(self):
        class ZeroMetricAdapter(FakeAdapter):
            def execute(self, step):
                value = super().execute(step)
                for key in ("latency_ms", "download_mbps", "upload_mbps"):
                    value[key] = 0.0
                return value

        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        result = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.configure"),
            ZeroMetricAdapter(),
            provenance(),
            evidence_provider=lambda: (reference,),
        )
        self.assertEqual(result.outcome, "passed")
        self.assertEqual(result.metrics, {})
        validate_result_payload(result.to_dict())

    def test_throughput_failure_retains_zero_metrics_for_diagnostics(self):
        class ZeroMetricAdapter(FakeAdapter):
            def execute(self, step):
                value = super().execute(step)
                for key in ("latency_ms", "download_mbps", "upload_mbps"):
                    value[key] = 0.0
                return value

        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        result = FunctionalEngine("e" * 64, schema_version=2).run(
            get_scenario("functional.stability-throughput"),
            ZeroMetricAdapter(),
            provenance(),
            evidence_provider=lambda: (reference,),
        )
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.reason_code, "ASSERTION_FAILED")
        self.assertEqual(
            result.metrics,
            {"latency_ms": 0.0, "download_mbps": 0.0, "upload_mbps": 0.0},
        )
        validate_result_payload(result.to_dict())

    def test_non_throughput_invalid_metrics_fail_closed(self):
        reference = EvidenceReference(id="command-001", bytes=17, sha256="f" * 64)
        for invalid in (-1.0, float("nan")):
            with self.subTest(invalid=invalid):
                class InvalidMetricAdapter(FakeAdapter):
                    def execute(self, step):
                        value = super().execute(step)
                        value["latency_ms"] = invalid
                        return value

                with self.assertRaisesRegex(
                    ResultValidationError, "metrics.latency_ms"
                ):
                    FunctionalEngine("e" * 64, schema_version=2).run(
                        get_scenario("functional.configure"),
                        InvalidMetricAdapter(),
                        provenance(),
                        evidence_provider=lambda: (reference,),
                    )

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
            platform_version="private",
            architecture="amd64",
            artifact_kind="manifest",
            artifact_manifest_sha256="d" * 64,
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
                platform_version="24.04",
                architecture="amd64",
                artifact_kind="package",
                artifact_manifest_sha256="d" * 64,
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
