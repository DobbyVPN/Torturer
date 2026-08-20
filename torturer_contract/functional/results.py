"""Safe canonical functional result model and validation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
from typing import Mapping, Sequence

from .assertions import AssertionOutcome


class ResultValidationError(ValueError):
    """Raised when a result cannot safely satisfy the public contract."""


_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{2,95}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,95}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _require_string(value: object, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ResultValidationError(f"{name} has an invalid format")
    return value


def _require_digest(value: object, name: str) -> str:
    digest = _require_string(value, name, _DIGEST)
    if set(digest) == {"0"}:
        raise ResultValidationError(f"{name} must not be all zeroes")
    return digest


def _positive_number(value: object, name: str) -> float | int:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ResultValidationError(f"{name} must be a number")
    if not math.isfinite(float(value)) or float(value) <= 0:
        raise ResultValidationError(f"{name} must be finite and positive")
    return value


def _safe_key_set(value: Mapping[str, object], allowed: set[str], name: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ResultValidationError(f"{name} contains unsupported fields: {sorted(unknown)}")


@dataclass(frozen=True)
class RunProvenance:
    """Immutable source and adapter identity attached to every result."""

    source_repository: str
    source_sha: str
    torturer_sha: str
    artifact_sha256: str
    server_image_digest: str
    platform: str
    adapter_id: str
    adapter_version: str
    capabilities: frozenset[str]
    harness_sha: str | None = None
    provider_generation: str | None = None

    def __post_init__(self) -> None:
        _require_string(self.source_repository, "source_repository", _REPOSITORY)
        _require_string(self.source_sha, "source_sha", _SHA)
        _require_string(self.torturer_sha, "torturer_sha", _SHA)
        _require_digest(self.artifact_sha256, "artifact_sha256")
        _require_string(self.server_image_digest, "server_image_digest", _IMAGE_DIGEST)
        _require_string(self.platform, "platform", _IDENTIFIER)
        _require_string(self.adapter_id, "adapter_id", _IDENTIFIER)
        _require_string(self.adapter_version, "adapter_version", _VERSION)
        if self.harness_sha is not None:
            _require_string(self.harness_sha, "harness_sha", _SHA)
        if self.provider_generation is not None:
            _require_string(self.provider_generation, "provider_generation", _IDENTIFIER)
        if not all(isinstance(item, str) and _IDENTIFIER.fullmatch(item) for item in self.capabilities):
            raise ResultValidationError("capabilities must contain stable identifiers")


@dataclass(frozen=True)
class ScenarioResult:
    """Canonical safe result for one scenario execution."""

    scenario_id: str
    scenario_version: int
    scenario_set_digest: str
    provenance: RunProvenance
    outcome: str
    assertions: tuple[AssertionOutcome, ...]
    cleanup: Mapping[str, bool]
    metrics: Mapping[str, float | int]
    duration_ms: int
    evidence_refs: tuple[str, ...] = ()
    reason_code: str | None = None

    def __post_init__(self) -> None:
        _require_string(self.scenario_id, "scenario_id", _IDENTIFIER)
        if self.scenario_version != 1:
            raise ResultValidationError("unsupported scenario version")
        _require_digest(self.scenario_set_digest, "scenario_set_digest")
        if self.outcome not in {"passed", "failed", "unavailable"}:
            raise ResultValidationError("outcome must be passed, failed, or unavailable")
        if self.duration_ms < 0:
            raise ResultValidationError("duration_ms must not be negative")
        if self.outcome in {"failed", "unavailable"}:
            if self.reason_code is None or not _REASON.fullmatch(self.reason_code):
                raise ResultValidationError("failed/unavailable results require reason_code")
        elif self.reason_code is not None:
            raise ResultValidationError("passed results must not contain reason_code")
        _safe_key_set(self.cleanup, {"required", "verified"}, "cleanup")
        if set(self.cleanup) != {"required", "verified"} or not all(
            isinstance(value, bool) for value in self.cleanup.values()
        ):
            raise ResultValidationError("cleanup must contain Boolean required and verified")
        allowed_metrics = {"latency_ms", "download_mbps", "upload_mbps"}
        _safe_key_set(self.metrics, allowed_metrics, "metrics")
        if self.outcome == "passed":
            requires_metrics = any(
                assertion.id == "traffic.metrics_positive" for assertion in self.assertions
            )
            if requires_metrics and set(self.metrics) != allowed_metrics:
                raise ResultValidationError("throughput results require all bounded metrics")
            for key, value in self.metrics.items():
                _positive_number(value, f"metrics.{key}")
            if not all(assertion.passed for assertion in self.assertions):
                raise ResultValidationError("passed results cannot contain a failed assertion")
            if self.cleanup["required"] and not self.cleanup["verified"]:
                raise ResultValidationError("passed results require verified cleanup")
        for assertion in self.assertions:
            _require_string(assertion.id, "assertion.id", _IDENTIFIER)
            if not isinstance(assertion.passed, bool):
                raise ResultValidationError("assertion.passed must be Boolean")
        if not all(isinstance(ref, str) and _IDENTIFIER.fullmatch(ref) for ref in self.evidence_refs):
            raise ResultValidationError("evidence_refs must contain opaque identifiers")

    def to_dict(self) -> dict[str, object]:
        provenance: dict[str, object] = {
            "source_repository": self.provenance.source_repository,
            "source_sha": self.provenance.source_sha,
            "torturer_sha": self.provenance.torturer_sha,
            "artifact_sha256": self.provenance.artifact_sha256,
            "server_image_digest": self.provenance.server_image_digest,
            "platform": self.provenance.platform,
            "adapter_id": self.provenance.adapter_id,
            "adapter_version": self.provenance.adapter_version,
            "capabilities": sorted(self.provenance.capabilities),
        }
        if self.provenance.harness_sha is not None:
            provenance["harness_sha"] = self.provenance.harness_sha
        if self.provenance.provider_generation is not None:
            provenance["provider_generation"] = self.provenance.provider_generation
        payload: dict[str, object] = {
            "schema": 1,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "scenario_set_digest": self.scenario_set_digest,
            "provenance": provenance,
            "outcome": self.outcome,
            "assertions": [assertion.to_dict() for assertion in self.assertions],
            "cleanup": dict(self.cleanup),
            "metrics": dict(self.metrics),
            "duration_ms": self.duration_ms,
            "evidence_refs": list(self.evidence_refs),
        }
        if self.reason_code is not None:
            payload["reason_code"] = self.reason_code
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def validate_result_payload(payload: Mapping[str, object]) -> None:
    """Validate a decoded public result without accepting unknown data."""

    _safe_key_set(
        payload,
        {
            "schema",
            "scenario_id",
            "scenario_version",
            "scenario_set_digest",
            "provenance",
            "outcome",
            "assertions",
            "cleanup",
            "metrics",
            "duration_ms",
            "evidence_refs",
            "reason_code",
        },
        "result",
    )
    if payload.get("schema") != 1:
        raise ResultValidationError("unsupported result schema")
    provenance_value = payload.get("provenance")
    if not isinstance(provenance_value, Mapping):
        raise ResultValidationError("provenance must be an object")
    _safe_key_set(
        provenance_value,
        {
            "source_repository",
            "source_sha",
            "torturer_sha",
            "harness_sha",
            "artifact_sha256",
            "server_image_digest",
            "provider_generation",
            "platform",
            "adapter_id",
            "adapter_version",
            "capabilities",
        },
        "provenance",
    )
    required_provenance = {
        "source_repository",
        "source_sha",
        "torturer_sha",
        "artifact_sha256",
        "server_image_digest",
        "platform",
        "adapter_id",
        "adapter_version",
        "capabilities",
    }
    if not required_provenance.issubset(provenance_value):
        raise ResultValidationError("provenance is incomplete")
    assertions_value = payload.get("assertions")
    if not isinstance(assertions_value, Sequence) or isinstance(assertions_value, (str, bytes)):
        raise ResultValidationError("assertions must be an array")
    assertion_objects: list[AssertionOutcome] = []
    for value in assertions_value:
        if not isinstance(value, Mapping):
            raise ResultValidationError("assertion must be an object")
        _safe_key_set(value, {"id", "passed"}, "assertion")
        if not isinstance(value.get("passed"), bool):
            raise ResultValidationError("assertion.passed must be Boolean")
        assertion_objects.append(AssertionOutcome(str(value.get("id")), value["passed"]))
    cleanup_value = payload.get("cleanup")
    metrics_value = payload.get("metrics")
    if not isinstance(cleanup_value, Mapping) or not isinstance(metrics_value, Mapping):
        raise ResultValidationError("cleanup and metrics must be objects")
    try:
        provenance = RunProvenance(
            source_repository=str(provenance_value["source_repository"]),
            source_sha=str(provenance_value["source_sha"]),
            torturer_sha=str(provenance_value["torturer_sha"]),
            harness_sha=(str(provenance_value["harness_sha"]) if "harness_sha" in provenance_value else None),
            artifact_sha256=str(provenance_value["artifact_sha256"]),
            server_image_digest=str(provenance_value["server_image_digest"]),
            provider_generation=(str(provenance_value["provider_generation"]) if "provider_generation" in provenance_value else None),
            platform=str(provenance_value["platform"]),
            adapter_id=str(provenance_value["adapter_id"]),
            adapter_version=str(provenance_value["adapter_version"]),
            capabilities=frozenset(str(item) for item in provenance_value["capabilities"]),
        )
        ScenarioResult(
            scenario_id=str(payload.get("scenario_id")),
            scenario_version=int(payload.get("scenario_version", -1)),
            scenario_set_digest=str(payload.get("scenario_set_digest")),
            provenance=provenance,
            outcome=str(payload.get("outcome")),
            assertions=tuple(assertion_objects),
            cleanup=cleanup_value,
            metrics=metrics_value,
            duration_ms=int(payload.get("duration_ms", -1)),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs", [])),
            reason_code=(str(payload["reason_code"]) if "reason_code" in payload else None),
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ResultValidationError):
            raise
        raise ResultValidationError("malformed result payload") from error
