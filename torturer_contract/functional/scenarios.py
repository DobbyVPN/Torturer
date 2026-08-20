"""Versioned, platform-neutral scenario definitions.

Definitions contain semantic operations only. They intentionally do not carry
shell commands, profile values, endpoints, or platform-specific setup.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .capabilities import Capability


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{2,95}$")


@dataclass(frozen=True)
class ScenarioStep:
    """One semantic adapter operation in a scenario."""

    id: str
    operation: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ValueError(f"invalid scenario step id: {self.id!r}")
        if not _IDENTIFIER.fullmatch(self.operation):
            raise ValueError(f"invalid scenario operation: {self.operation!r}")
        if self.timeout_seconds <= 0:
            raise ValueError("scenario step timeout must be positive")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "operation": self.operation,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class ScenarioDefinition:
    """A versioned scenario and its canonical pass criteria."""

    id: str
    version: int
    steps: tuple[ScenarioStep, ...]
    required_capabilities: frozenset[Capability]
    assertion_ids: tuple[str, ...]
    max_duration_seconds: int

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ValueError(f"invalid scenario id: {self.id!r}")
        if self.version != 1:
            raise ValueError("only scenario version 1 is currently supported")
        if not self.steps:
            raise ValueError("scenario must contain at least one step")
        step_ids = [step.id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError(f"scenario has duplicate step ids: {self.id}")
        if not self.assertion_ids:
            raise ValueError("scenario must contain at least one assertion")
        if len(self.assertion_ids) != len(set(self.assertion_ids)):
            raise ValueError(f"scenario has duplicate assertions: {self.id}")
        if self.max_duration_seconds <= 0:
            raise ValueError("scenario maximum duration must be positive")
        if sum(step.timeout_seconds for step in self.steps) > self.max_duration_seconds:
            raise ValueError(f"scenario step bounds exceed scenario bound: {self.id}")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "version": self.version,
            "steps": [step.to_dict() for step in self.steps],
            "required_capabilities": sorted(
                capability.value for capability in self.required_capabilities
            ),
            "assertion_ids": list(self.assertion_ids),
            "max_duration_seconds": self.max_duration_seconds,
        }


def _step(id: str, operation: str, timeout: int = 30) -> ScenarioStep:
    return ScenarioStep(id=id, operation=operation, timeout_seconds=timeout)


_COMMON_CONNECT = (
    _step("configure", "configure"),
    _step("connect", "connect", 60),
    _step("tunnel", "observe_tunnel"),
    _step("routing", "observe_routing_identity"),
)


SCENARIO_CATALOG: tuple[ScenarioDefinition, ...] = (
    ScenarioDefinition(
        id="functional.configure",
        version=1,
        steps=(_step("configure", "configure"),),
        required_capabilities=frozenset({Capability.CONFIGURE}),
        assertion_ids=("configure.accepted",),
        max_duration_seconds=120,
    ),
    ScenarioDefinition(
        id="functional.connect-route-identity",
        version=1,
        steps=_COMMON_CONNECT,
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
        ),
        max_duration_seconds=240,
    ),
    ScenarioDefinition(
        id="functional.stability-throughput",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("stability", "measure_stability", 180),
            _step("throughput", "measure_throughput", 180),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.TRAFFIC_MEASUREMENT,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "traffic.stable",
            "traffic.metrics_positive",
        ),
        max_duration_seconds=600,
    ),
    ScenarioDefinition(
        id="functional.disconnect-cleanup",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("disconnect", "disconnect"),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.DISCONNECT,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "disconnect.clean",
            "cleanup.restored",
        ),
        max_duration_seconds=360,
    ),
    ScenarioDefinition(
        id="functional.start-stop-start",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("disconnect", "disconnect"),
            _step("reconnect", "reconnect", 90),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.DISCONNECT,
                Capability.RECONNECT,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "lifecycle.restart",
            "cleanup.restored",
        ),
        max_duration_seconds=480,
    ),
    ScenarioDefinition(
        id="functional.failed-repeated-reconnect",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("reconnect", "reconnect", 120),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.RECONNECT,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "reconnect.bounded",
            "cleanup.restored",
        ),
        max_duration_seconds=480,
    ),
    ScenarioDefinition(
        id="functional.network-transition",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("network", "network_transition", 120),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.NETWORK_TRANSITION,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "network.transition",
            "cleanup.restored",
        ),
        max_duration_seconds=480,
    ),
    ScenarioDefinition(
        id="functional.sleep-wake",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("sleep_wake", "sleep_wake", 180),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.SLEEP_WAKE,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "sleep_wake.transition",
            "cleanup.restored",
        ),
        max_duration_seconds=540,
    ),
    ScenarioDefinition(
        id="functional.product-process-loss",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("process_loss", "process_loss", 120),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.PROCESS_LOSS,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "process_loss.recovered",
            "cleanup.restored",
        ),
        max_duration_seconds=480,
    ),
    ScenarioDefinition(
        id="functional.bounded-endurance",
        version=1,
        steps=_COMMON_CONNECT
        + (
            _step("endurance", "measure_endurance", 900),
            _step("disconnect", "disconnect"),
            _step("cleanup", "inspect_cleanup"),
        ),
        required_capabilities=frozenset(
            {
                Capability.CONFIGURE,
                Capability.CONNECT,
                Capability.TUNNEL_INTERFACE,
                Capability.ROUTING_IDENTITY,
                Capability.TRAFFIC_MEASUREMENT,
                Capability.ENDURANCE,
                Capability.DISCONNECT,
                Capability.RESOURCE_CLEANUP,
            }
        ),
        assertion_ids=(
            "configure.accepted",
            "tunnel.established",
            "routing.identity_changed",
            "endurance.bounded",
            "disconnect.clean",
            "cleanup.restored",
        ),
        max_duration_seconds=1500,
    ),
)


def scenario_catalog() -> tuple[ScenarioDefinition, ...]:
    """Return the immutable canonical scenario catalog."""

    return SCENARIO_CATALOG


def get_scenario(scenario_id: str, *, version: int = 1) -> ScenarioDefinition:
    """Return one scenario or raise ``KeyError`` for an unknown version."""

    for scenario in SCENARIO_CATALOG:
        if scenario.id == scenario_id and scenario.version == version:
            return scenario
    raise KeyError(f"unknown scenario: {scenario_id!r} v{version}")


def catalog_document() -> dict[str, object]:
    """Return the JSON-safe catalog representation used by fixtures."""

    return {
        "schema": 1,
        "kind": "dobbyvpn.functional.scenario-catalog",
        "scenarios": [scenario.to_dict() for scenario in SCENARIO_CATALOG],
    }
