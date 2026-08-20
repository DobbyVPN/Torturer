"""Canonical cross-platform functional-test contract.

This package contains only public scenario semantics and safe result
validation. Platform commands, credentials, and evidence storage belong to
the adapters and callers that execute it.
"""

from .assertions import (
    AssertionOutcome,
    evaluate_assertion,
    evaluate_assertions,
)
from .capabilities import Capability
from .engine import (
    CapabilityUnavailable,
    FunctionalEngine,
    ScenarioAdapter,
    ScenarioExecutionError,
)
from .results import (
    ResultValidationError,
    RunProvenance,
    ScenarioResult,
    validate_result_payload,
)
from .scenarios import (
    ScenarioDefinition,
    ScenarioStep,
    catalog_document,
    get_scenario,
    scenario_catalog,
)

__all__ = [
    "AssertionOutcome",
    "CapabilityUnavailable",
    "Capability",
    "FunctionalEngine",
    "ResultValidationError",
    "RunProvenance",
    "ScenarioAdapter",
    "ScenarioDefinition",
    "ScenarioExecutionError",
    "ScenarioResult",
    "ScenarioStep",
    "evaluate_assertion",
    "evaluate_assertions",
    "catalog_document",
    "get_scenario",
    "scenario_catalog",
    "validate_result_payload",
]
