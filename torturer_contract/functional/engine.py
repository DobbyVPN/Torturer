"""Small semantic scenario engine shared by hosted and local adapters."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import time
from typing import Protocol

from .assertions import evaluate_assertions
from .capabilities import Capability
from .results import EvidenceReference, ResultValidationError, RunProvenance, ScenarioResult
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


class BulkScenarioAdapter(Protocol):
    """Optional one-session canonical scenario boundary."""

    def execute_scenario(self, scenario: ScenarioDefinition) -> Mapping[str, object]: ...


def _unavailable_reason(adapter: ScenarioAdapter, missing: frozenset[Capability]) -> str:
    """Return an adapter-owned reason for a proved hosted capability gap.

    The canonical engine still owns the unavailable outcome.  Adapters may
    explain why a platform cannot perform one of the shared operations, but
    they cannot turn that gap into a pass or remove the scenario from the
    selected catalog.
    """

    reasons = getattr(adapter, "capability_unavailable_reasons", {})
    if isinstance(reasons, Mapping):
        for capability in sorted(missing, key=lambda value: value.value):
            reason = reasons.get(capability)
            if isinstance(reason, str) and reason:
                return reason
    return "CAPABILITY_UNAVAILABLE"


EvidenceProvider = Callable[[], Sequence[EvidenceReference]]


@dataclass(frozen=True)
class FunctionalEngine:
    """Execute a definition without owning platform commands or evidence."""

    scenario_set_digest: str
    schema_version: int = 1
    evidence_refs: tuple[EvidenceReference, ...] = ()

    def run(
        self,
        scenario: ScenarioDefinition,
        adapter: ScenarioAdapter,
        provenance: RunProvenance,
        *,
        evidence_provider: EvidenceProvider | None = None,
    ) -> ScenarioResult:
        started_ns = time.monotonic_ns()
        missing = scenario.required_capabilities - adapter.capabilities
        if missing:
            ended_ns = time.monotonic_ns()
            return self._result(
                scenario,
                provenance,
                outcome="unavailable",
                reason_code=_unavailable_reason(adapter, missing),
                assertions=(),
                cleanup={"required": False, "verified": True},
                metrics={},
                started_ns=started_ns,
                ended_ns=ended_ns,
                phase_durations_ms={"availability": self._duration_ms(started_ns, ended_ns)},
                evidence_provider=evidence_provider,
            )

        observations: dict[str, object] = {}
        try:
            bulk_execute = getattr(adapter, "execute_scenario", None)
            if callable(bulk_execute):
                if self._expired(started_ns, scenario.max_duration_seconds):
                    return self._failure(
                        scenario, provenance, "SCENARIO_TIMEOUT", observations, started_ns, evidence_provider
                    )
                result = bulk_execute(scenario)
                if not isinstance(result, Mapping):
                    return self._failure(
                        scenario, provenance, "ADAPTER_RESULT_INVALID", observations, started_ns, evidence_provider
                    )
                observations.update(result)
            else:
                for step in scenario.steps:
                    if self._expired(started_ns, scenario.max_duration_seconds):
                        return self._failure(
                            scenario, provenance, "SCENARIO_TIMEOUT", observations, started_ns, evidence_provider
                        )
                    result = adapter.execute(step)
                    if not isinstance(result, Mapping):
                        return self._failure(
                            scenario, provenance, "ADAPTER_RESULT_INVALID", observations, started_ns, evidence_provider
                        )
                    observations.update(result)
            if self._expired(started_ns, scenario.max_duration_seconds):
                return self._failure(
                    scenario, provenance, "SCENARIO_TIMEOUT", observations, started_ns, evidence_provider
                )
        except CapabilityUnavailable:
            ended_ns = time.monotonic_ns()
            return self._result(
                scenario,
                provenance,
                outcome="unavailable",
                reason_code=_unavailable_reason(
                    adapter, scenario.required_capabilities - adapter.capabilities
                ),
                assertions=(),
                cleanup={"required": False, "verified": True},
                metrics={},
                started_ns=started_ns,
                ended_ns=ended_ns,
                phase_durations_ms={"execution": self._duration_ms(started_ns, ended_ns)},
                evidence_provider=evidence_provider,
            )
        except ScenarioExecutionError as error:
            return self._failure(
                scenario, provenance, error.reason_code, observations, started_ns, evidence_provider
            )
        except Exception:
            # Adapter exception details stay in the adapter/evidence sink. The
            # public result carries only a stable non-sensitive reason code.
            return self._failure(
                scenario, provenance, "ADAPTER_ERROR", observations, started_ns, evidence_provider
            )

        execution_ended_ns = time.monotonic_ns()
        assertions_started_ns = execution_ended_ns
        assertions = evaluate_assertions(scenario.assertion_ids, observations)
        ended_ns = time.monotonic_ns()
        cleanup_required = "cleanup.restored" in scenario.assertion_ids
        cleanup_verified = observations.get("cleanup_verified") is True
        metrics = self._metrics(observations)
        if not all(assertion.passed for assertion in assertions):
            outcome = "failed"
            reason_code = "ASSERTION_FAILED"
        else:
            outcome = "passed"
            reason_code = None
        return self._result(
            scenario,
            provenance,
            outcome=outcome,
            reason_code=reason_code,
            assertions=assertions,
            cleanup={"required": cleanup_required, "verified": cleanup_verified},
            metrics=metrics,
            started_ns=started_ns,
            ended_ns=ended_ns,
            phase_durations_ms={
                "execution": self._duration_ms(started_ns, execution_ended_ns),
                "assertions": self._duration_ms(assertions_started_ns, ended_ns),
            },
            evidence_provider=evidence_provider,
        )

    def _failure(
        self,
        scenario: ScenarioDefinition,
        provenance: RunProvenance,
        reason_code: str,
        observations: Mapping[str, object],
        started_ns: int,
        evidence_provider: EvidenceProvider | None = None,
    ) -> ScenarioResult:
        execution_ended_ns = time.monotonic_ns()
        assertions_started_ns = execution_ended_ns
        assertions = evaluate_assertions(scenario.assertion_ids, observations)
        ended_ns = time.monotonic_ns()
        return self._result(
            scenario,
            provenance,
            outcome="failed",
            reason_code=reason_code,
            assertions=assertions,
            cleanup={
                "required": "cleanup.restored" in scenario.assertion_ids,
                "verified": observations.get("cleanup_verified") is True,
            },
            metrics=self._metrics(observations),
            started_ns=started_ns,
            ended_ns=ended_ns,
            phase_durations_ms={
                "execution": self._duration_ms(started_ns, execution_ended_ns),
                "assertions": self._duration_ms(assertions_started_ns, ended_ns),
            },
            evidence_provider=evidence_provider,
        )

    @staticmethod
    def _duration_ms(started_ns: int, ended_ns: int) -> int:
        return max(0, (ended_ns - started_ns) // 1_000_000)

    @staticmethod
    def _expired(started_ns: int, max_duration_seconds: int) -> bool:
        return time.monotonic_ns() - started_ns > max_duration_seconds * 1_000_000_000

    def _result(
        self,
        scenario: ScenarioDefinition,
        provenance: RunProvenance,
        *,
        outcome: str,
        reason_code: str | None,
        assertions,
        cleanup: Mapping[str, bool],
        metrics: Mapping[str, float | int],
        started_ns: int,
        ended_ns: int,
        phase_durations_ms: Mapping[str, int],
        evidence_provider: EvidenceProvider | None,
    ) -> ScenarioResult:
        if self.schema_version == 2 and evidence_provider is None:
            raise ResultValidationError("v2 evidence provider is required")
        evidence_started_ns = ended_ns
        evidence_refs = tuple(evidence_provider()) if evidence_provider is not None else self.evidence_refs
        final_ended_ns = time.monotonic_ns()
        finalized_phases = dict(phase_durations_ms)
        if self.schema_version == 2:
            # Evidence metadata is finalized only after the adapter and sink
            # have completed. Include that finalization window in the
            # monotonic duration rather than reporting a shorter run.
            finalized_phases["evidence"] = self._duration_ms(
                evidence_started_ns, final_ended_ns
            )
        final_outcome = outcome
        final_reason_code = reason_code
        if (
            self.schema_version == 2
            and final_ended_ns - started_ns > scenario.max_duration_seconds * 1_000_000_000
            and outcome == "passed"
        ):
            # Evidence finalization is part of the scenario's observed wall
            # clock. A sink that blocks past the declared bound cannot leave
            # a scenario looking like a pass merely because execution itself
            # finished in time; the references are still retained below.
            final_outcome = "failed"
            final_reason_code = "SCENARIO_TIMEOUT"
        return ScenarioResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            scenario_set_digest=self.scenario_set_digest,
            provenance=provenance,
            outcome=final_outcome,
            reason_code=final_reason_code,
            assertions=assertions,
            cleanup=cleanup,
            metrics=metrics,
            duration_ms=self._duration_ms(started_ns, final_ended_ns),
            schema_version=self.schema_version,
            monotonic_start_ns=started_ns,
            monotonic_end_ns=final_ended_ns,
            phase_durations_ms=finalized_phases,
            evidence_refs=evidence_refs,
        )

    @staticmethod
    def _metrics(observations: Mapping[str, object]) -> dict[str, float | int]:
        result: dict[str, float | int] = {}
        for key in ("latency_ms", "download_mbps", "upload_mbps"):
            value = observations.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                result[key] = value
        return result
