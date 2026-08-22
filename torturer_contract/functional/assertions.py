"""Canonical functional assertions.

Assertions consume adapter observations, never platform commands or profile
values. They are intentionally small and deterministic so local and hosted
adapters cannot quietly define different pass criteria.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Mapping


class AssertionDefinitionError(ValueError):
    """Raised when an unknown or malformed canonical assertion is requested."""


@dataclass(frozen=True)
class AssertionOutcome:
    """One canonical assertion decision."""

    id: str
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "passed": self.passed}


def _true(observations: Mapping[str, object], key: str) -> bool:
    return observations.get(key) is True


def _positive(observations: Mapping[str, object], key: str) -> bool:
    value = observations.get(key)
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) > 0
    )


_ASSERTION_KEYS: dict[str, str] = {
    "configure.accepted": "configured",
    "tunnel.established": "tunnel_interface",
    "tunnel.second_established": "second_tunnel_interface",
    "routing.identity_changed": "routing_identity_changed",
    "routing.second_identity_changed": "second_routing_identity_changed",
    "traffic.stable": "stability_verified",
    "disconnect.clean": "disconnect_clean",
    "disconnect.final_clean": "final_disconnect_clean",
    "cleanup.restored": "cleanup_verified",
    "lifecycle.restart": "restart_verified",
    "reconnect.bounded": "reconnect_bounded",
    "network.transition": "network_transition_verified",
    "sleep_wake.transition": "sleep_wake_verified",
    "process_loss.recovered": "process_loss_verified",
    "endurance.bounded": "endurance_verified",
}

_METRIC_ASSERTIONS = {
    "traffic.metrics_positive": (
        "latency_ms",
        "download_mbps",
        "upload_mbps",
    )
}


def evaluate_assertion(
    assertion_id: str, observations: Mapping[str, object]
) -> AssertionOutcome:
    """Evaluate one known assertion against safe adapter observations."""

    if assertion_id in _ASSERTION_KEYS:
        return AssertionOutcome(assertion_id, _true(observations, _ASSERTION_KEYS[assertion_id]))
    if assertion_id in _METRIC_ASSERTIONS:
        return AssertionOutcome(
            assertion_id,
            all(_positive(observations, key) for key in _METRIC_ASSERTIONS[assertion_id]),
        )
    raise AssertionDefinitionError(f"unknown canonical assertion: {assertion_id!r}")


def evaluate_assertions(
    assertion_ids: tuple[str, ...], observations: Mapping[str, object]
) -> tuple[AssertionOutcome, ...]:
    """Evaluate assertions in their definition order."""

    return tuple(evaluate_assertion(assertion_id, observations) for assertion_id in assertion_ids)
