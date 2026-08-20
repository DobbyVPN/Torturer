"""Small semantic scenario engine shared by hosted and local adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import time
from typing import Protocol

from .assertions import evaluate_assertions
from .capabilities import Capability
from .results import RunProvenance, ScenarioResult
from .scenarios import ScenarioDefinition, ScenarioStep


class CapabilityUnavailable(Exception):
    """Raised by an adapter when a required environment feature is absent."""


class ScenarioExecutionError(Exception):
    """Raised by an adapter for a stable, expected execution failure."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ScenarioAdapter(Protocol):
    """Semantic operations implemented by one hosted or local adapter."""

    @property
    def capabilities(self) -> frozenset[Capability]: ...

    def execute(self, step: ScenarioStep) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class FunctionalEngine:
    """Execute a definition without owning platform commands or evidence."""

    scenario_set_digest: str

    def run(
        self,
        scenario: ScenarioDefinition,
        adapter: ScenarioAdapter,
        provenance: RunProvenance,
    ) -> ScenarioResult:
        missing = scenario.required_capabilities - adapter.capabilities
        if missing:
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_version=scenario.version,
                scenario_set_digest=self.scenario_set_digest,
                provenance=provenance,
                outcome="unavailable",
                reason_code="CAPABILITY_UNAVAILABLE",
                assertions=(),
                cleanup={"required": False, "verified": True},
                metrics={},
                duration_ms=0,
            )

        started = time.monotonic()
        observations: dict[str, object] = {}
        try:
            for step in scenario.steps:
                if time.monotonic() - started > scenario.max_duration_seconds:
                    return self._failure(
                        scenario, provenance, "SCENARIO_TIMEOUT", observations, started
                    )
                result = adapter.execute(step)
                if not isinstance(result, Mapping):
                    return self._failure(
                        scenario, provenance, "ADAPTER_RESULT_INVALID", observations, started
                    )
                observations.update(result)
            if time.monotonic() - started > scenario.max_duration_seconds:
                return self._failure(
                    scenario, provenance, "SCENARIO_TIMEOUT", observations, started
                )
        except CapabilityUnavailable:
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_version=scenario.version,
                scenario_set_digest=self.scenario_set_digest,
                provenance=provenance,
                outcome="unavailable",
                reason_code="CAPABILITY_UNAVAILABLE",
                assertions=(),
                cleanup={"required": False, "verified": True},
                metrics={},
                duration_ms=self._duration_ms(started),
            )
        except ScenarioExecutionError as error:
            return self._failure(
                scenario, provenance, error.reason_code, observations, started
            )
        except Exception:
            # Adapter exception details stay in the adapter/evidence sink. The
            # public result carries only a stable non-sensitive reason code.
            return self._failure(
                scenario, provenance, "ADAPTER_ERROR", observations, started
            )

        assertions = evaluate_assertions(scenario.assertion_ids, observations)
        cleanup_required = "cleanup.restored" in scenario.assertion_ids
        cleanup_verified = observations.get("cleanup_verified") is True
        metrics = self._metrics(observations)
        if not all(assertion.passed for assertion in assertions):
            outcome = "failed"
            reason_code = "ASSERTION_FAILED"
        else:
            outcome = "passed"
            reason_code = None
        return ScenarioResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            scenario_set_digest=self.scenario_set_digest,
            provenance=provenance,
            outcome=outcome,
            reason_code=reason_code,
            assertions=assertions,
            cleanup={"required": cleanup_required, "verified": cleanup_verified},
            metrics=metrics,
            duration_ms=self._duration_ms(started),
        )

    def _failure(
        self,
        scenario: ScenarioDefinition,
        provenance: RunProvenance,
        reason_code: str,
        observations: Mapping[str, object],
        started: float,
    ) -> ScenarioResult:
        assertions = evaluate_assertions(scenario.assertion_ids, observations)
        return ScenarioResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            scenario_set_digest=self.scenario_set_digest,
            provenance=provenance,
            outcome="failed",
            reason_code=reason_code,
            assertions=assertions,
            cleanup={
                "required": "cleanup.restored" in scenario.assertion_ids,
                "verified": observations.get("cleanup_verified") is True,
            },
            metrics=self._metrics(observations),
            duration_ms=self._duration_ms(started),
        )

    @staticmethod
    def _duration_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))

    @staticmethod
    def _metrics(observations: Mapping[str, object]) -> dict[str, float | int]:
        result: dict[str, float | int] = {}
        for key in ("latency_ms", "download_mbps", "upload_mbps"):
            value = observations.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                result[key] = value
        return result
