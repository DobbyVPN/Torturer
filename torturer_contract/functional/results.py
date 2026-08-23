"""Versioned safe canonical functional result models and validation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
from typing import Mapping, Sequence

from .assertions import AssertionOutcome


class ResultValidationError(ValueError):
    """Raised when a result cannot safely satisfy its public contract."""


_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{2,95}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,95}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_PROVIDER_KIND = re.compile(r"^(?:render|private)$")


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
    server_image_digest: str | None
    platform: str
    adapter_id: str
    adapter_version: str
    capabilities: frozenset[str]
    harness_sha: str | None = None
    provider_generation: str | None = None
    provider_kind: str = "render"
    # v2-only provenance. None is intentional: it prevents a v1 producer from
    # silently claiming an artifact/platform identity it did not observe.
    platform_version: str | None = None
    architecture: str | None = None
    artifact_kind: str | None = None
    artifact_manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        _require_string(self.source_repository, "source_repository", _REPOSITORY)
        _require_string(self.source_sha, "source_sha", _SHA)
        _require_string(self.torturer_sha, "torturer_sha", _SHA)
        _require_digest(self.artifact_sha256, "artifact_sha256")
        if self.artifact_manifest_sha256 is not None:
            _require_digest(self.artifact_manifest_sha256, "artifact_manifest_sha256")
        if self.server_image_digest is not None:
            _require_string(self.server_image_digest, "server_image_digest", _IMAGE_DIGEST)
        if not isinstance(self.provider_kind, str) or not _PROVIDER_KIND.fullmatch(self.provider_kind):
            raise ResultValidationError("provider_kind is invalid")
        if self.provider_kind == "render" and self.server_image_digest is None:
            raise ResultValidationError("Render provenance requires server_image_digest")
        _require_string(self.platform, "platform", _IDENTIFIER)
        _require_string(self.adapter_id, "adapter_id", _IDENTIFIER)
        _require_string(self.adapter_version, "adapter_version", _VERSION)
        if self.harness_sha is not None:
            _require_string(self.harness_sha, "harness_sha", _SHA)
        if self.provider_generation is not None:
            _require_string(self.provider_generation, "provider_generation", _IDENTIFIER)
        if not all(isinstance(item, str) and _IDENTIFIER.fullmatch(item) for item in self.capabilities):
            raise ResultValidationError("capabilities must contain stable identifiers")
        for value, name, pattern in (
            (self.platform_version, "platform_version", _VERSION),
            (self.architecture, "architecture", _VERSION),
            (self.artifact_kind, "artifact_kind", _IDENTIFIER),
        ):
            if value is not None:
                _require_string(value, name, pattern)


@dataclass(frozen=True)
class EvidenceReference:
    """Safe metadata for one opaque, durably retained evidence object."""

    id: str
    bytes: int
    sha256: str

    def __post_init__(self) -> None:
        _require_string(self.id, "evidence.id", _IDENTIFIER)
        if not isinstance(self.bytes, int) or isinstance(self.bytes, bool) or self.bytes < 0:
            raise ResultValidationError("evidence.bytes must be a non-negative integer")
        _require_digest(self.sha256, "evidence.sha256")

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "bytes": self.bytes, "sha256": self.sha256}


@dataclass(frozen=True)
class ScenarioResult:
    """Canonical result supporting the published v1 and metadata-complete v2 contracts."""

    scenario_id: str
    scenario_version: int
    scenario_set_digest: str
    provenance: RunProvenance
    outcome: str
    assertions: tuple[AssertionOutcome, ...]
    cleanup: Mapping[str, bool]
    metrics: Mapping[str, float | int]
    duration_ms: int
    evidence_refs: tuple[str | EvidenceReference, ...] = ()
    reason_code: str | None = None
    schema_version: int = 1
    monotonic_start_ns: int | None = None
    monotonic_end_ns: int | None = None
    phase_durations_ms: Mapping[str, int] | None = None

    def __post_init__(self) -> None:
        _require_string(self.scenario_id, "scenario_id", _IDENTIFIER)
        if self.scenario_version != 1:
            raise ResultValidationError("unsupported scenario version")
        if self.schema_version not in {1, 2}:
            raise ResultValidationError("unsupported result schema")
        _require_digest(self.scenario_set_digest, "scenario_set_digest")
        if self.outcome not in {"passed", "failed", "unavailable"}:
            raise ResultValidationError("outcome must be passed, failed, or unavailable")
        if self.schema_version == 1:
            if self.duration_ms < 0:
                raise ResultValidationError("duration_ms must not be negative")
        elif (
            not isinstance(self.duration_ms, int)
            or isinstance(self.duration_ms, bool)
            or self.duration_ms < 0
        ):
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
        if self.schema_version == 1:
            if not all(isinstance(ref, str) and _IDENTIFIER.fullmatch(ref) for ref in self.evidence_refs):
                raise ResultValidationError("evidence_refs must contain opaque identifiers")
            return
        if any(
            value is None
            for value in (
                self.provenance.platform_version,
                self.provenance.architecture,
                self.provenance.artifact_kind,
                self.provenance.artifact_manifest_sha256,
            )
        ):
            raise ResultValidationError("v2 provenance is incomplete")
        if self.provenance.artifact_sha256 == self.provenance.artifact_manifest_sha256:
            raise ResultValidationError(
                "v2 artifact and artifact-manifest digests must be distinct"
            )
        if (
            not isinstance(self.monotonic_start_ns, int)
            or isinstance(self.monotonic_start_ns, bool)
            or self.monotonic_start_ns < 0
            or not isinstance(self.monotonic_end_ns, int)
            or isinstance(self.monotonic_end_ns, bool)
            or self.monotonic_end_ns < self.monotonic_start_ns
        ):
            raise ResultValidationError("v2 monotonic start/end timestamps are invalid")
        if not isinstance(self.phase_durations_ms, Mapping) or not self.phase_durations_ms:
            raise ResultValidationError("v2 phase_durations_ms is incomplete")
        if not all(
            isinstance(key, str)
            and _IDENTIFIER.fullmatch(key)
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
            for key, value in self.phase_durations_ms.items()
        ):
            raise ResultValidationError("v2 phase durations must be non-negative integers")
        if sum(self.phase_durations_ms.values()) > self.duration_ms:
            raise ResultValidationError("v2 phase durations cannot exceed duration_ms")
        if not all(isinstance(ref, EvidenceReference) for ref in self.evidence_refs):
            raise ResultValidationError("v2 evidence_refs must contain metadata objects")

    def to_dict(self) -> dict[str, object]:
        provenance: dict[str, object] = {
            "source_repository": self.provenance.source_repository,
            "source_sha": self.provenance.source_sha,
            "torturer_sha": self.provenance.torturer_sha,
            "artifact_sha256": self.provenance.artifact_sha256,
            "platform": self.provenance.platform,
            "adapter_id": self.provenance.adapter_id,
            "adapter_version": self.provenance.adapter_version,
            "capabilities": sorted(self.provenance.capabilities),
        }
        if self.provenance.server_image_digest is not None:
            provenance["server_image_digest"] = self.provenance.server_image_digest
        if self.provenance.provider_kind != "render":
            provenance["provider_kind"] = self.provenance.provider_kind
        if self.provenance.harness_sha is not None:
            provenance["harness_sha"] = self.provenance.harness_sha
        if self.provenance.provider_generation is not None:
            provenance["provider_generation"] = self.provenance.provider_generation
        if self.schema_version == 2:
            provenance.update(
                {
                    "artifact_manifest_sha256": self.provenance.artifact_manifest_sha256,
                    "artifact_kind": self.provenance.artifact_kind,
                    "platform_version": self.provenance.platform_version,
                    "architecture": self.provenance.architecture,
                }
            )
        payload: dict[str, object] = {
            "schema": self.schema_version,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "scenario_set_digest": self.scenario_set_digest,
            "provenance": provenance,
            "outcome": self.outcome,
            "assertions": [assertion.to_dict() for assertion in self.assertions],
            "cleanup": dict(self.cleanup),
            "metrics": dict(self.metrics),
            "duration_ms": self.duration_ms,
            "evidence_refs": (
                [reference.to_dict() for reference in self.evidence_refs]
                if self.schema_version == 2
                else list(self.evidence_refs)
            ),
        }
        if self.schema_version == 2:
            payload["monotonic_start_ns"] = self.monotonic_start_ns
            payload["monotonic_end_ns"] = self.monotonic_end_ns
            payload["phase_durations_ms"] = dict(self.phase_durations_ms or {})
        if self.reason_code is not None:
            payload["reason_code"] = self.reason_code
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _provenance_from_payload(value: Mapping[str, object], *, schema_version: int) -> RunProvenance:
    old_allowed = {
        "source_repository", "source_sha", "torturer_sha", "harness_sha", "artifact_sha256",
        "server_image_digest", "provider_kind", "provider_generation", "platform", "adapter_id",
        "adapter_version", "capabilities",
    }
    v2_allowed = old_allowed | {"artifact_manifest_sha256", "artifact_kind", "platform_version", "architecture"}
    _safe_key_set(value, v2_allowed if schema_version == 2 else old_allowed, "provenance")
    required = old_allowed - {"harness_sha", "server_image_digest", "provider_kind", "provider_generation"}
    if schema_version == 2:
        required |= {"artifact_manifest_sha256", "artifact_kind", "platform_version", "architecture"}
    if not required.issubset(value):
        raise ResultValidationError("provenance is incomplete")
    capabilities_value = value["capabilities"]
    if not isinstance(capabilities_value, Sequence) or isinstance(capabilities_value, (str, bytes)):
        raise ResultValidationError("capabilities must be an array")
    provider_kind = value.get("provider_kind", "render")
    if provider_kind != "private" and "server_image_digest" not in value:
        raise ResultValidationError("Render provenance is missing server_image_digest")
    return RunProvenance(
        source_repository=value["source_repository"],  # type: ignore[arg-type]
        source_sha=value["source_sha"],  # type: ignore[arg-type]
        torturer_sha=value["torturer_sha"],  # type: ignore[arg-type]
        harness_sha=value.get("harness_sha"),  # type: ignore[arg-type]
        artifact_sha256=value["artifact_sha256"],  # type: ignore[arg-type]
        artifact_manifest_sha256=value.get("artifact_manifest_sha256"),  # type: ignore[arg-type]
        artifact_kind=value.get("artifact_kind"),  # type: ignore[arg-type]
        server_image_digest=value.get("server_image_digest"),  # type: ignore[arg-type]
        provider_generation=value.get("provider_generation"),  # type: ignore[arg-type]
        platform=value["platform"],  # type: ignore[arg-type]
        platform_version=value.get("platform_version"),  # type: ignore[arg-type]
        architecture=value.get("architecture"),  # type: ignore[arg-type]
        adapter_id=value["adapter_id"],  # type: ignore[arg-type]
        adapter_version=value["adapter_version"],  # type: ignore[arg-type]
        capabilities=frozenset(capabilities_value),  # type: ignore[arg-type]
        provider_kind=provider_kind,  # type: ignore[arg-type]
    )


def _assertions_from_payload(value: object) -> tuple[AssertionOutcome, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ResultValidationError("assertions must be an array")
    assertions: list[AssertionOutcome] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ResultValidationError("assertion must be an object")
        _safe_key_set(item, {"id", "passed"}, "assertion")
        if not isinstance(item.get("passed"), bool):
            raise ResultValidationError("assertion.passed must be Boolean")
        assertions.append(AssertionOutcome(item.get("id"), item["passed"]))  # type: ignore[arg-type]
    return tuple(assertions)


def _evidence_from_payload(value: object) -> tuple[EvidenceReference, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ResultValidationError("v2 evidence_refs must be an array")
    references: list[EvidenceReference] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ResultValidationError("evidence reference must be an object")
        _safe_key_set(item, {"id", "bytes", "sha256"}, "evidence reference")
        if not {"id", "bytes", "sha256"}.issubset(item):
            raise ResultValidationError("evidence reference is incomplete")
        references.append(EvidenceReference(item["id"], item["bytes"], item["sha256"]))  # type: ignore[arg-type]
    return tuple(references)


def _validate_v1_result_payload(payload: Mapping[str, object]) -> None:
    """Preserve the published schema-1 validator's exact behavior."""

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
            "provider_kind",
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
        "platform",
        "adapter_id",
        "adapter_version",
        "capabilities",
    }
    if not required_provenance.issubset(provenance_value):
        raise ResultValidationError("provenance is incomplete")
    provider_kind = provenance_value.get("provider_kind", "render")
    if provider_kind != "private" and "server_image_digest" not in provenance_value:
        raise ResultValidationError("Render provenance is missing server_image_digest")
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
            server_image_digest=(
                str(provenance_value["server_image_digest"])
                if "server_image_digest" in provenance_value else None
            ),
            provider_generation=(str(provenance_value["provider_generation"]) if "provider_generation" in provenance_value else None),
            platform=str(provenance_value["platform"]),
            adapter_id=str(provenance_value["adapter_id"]),
            adapter_version=str(provenance_value["adapter_version"]),
            capabilities=frozenset(str(item) for item in provenance_value["capabilities"]),
            provider_kind=str(provenance_value.get("provider_kind", "render")),
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


def validate_result_payload(payload: Mapping[str, object]) -> None:
    """Validate the published v1 payload or metadata-complete v2 payload."""

    schema = payload.get("schema")
    if schema == 1:
        _validate_v1_result_payload(payload)
        return
    if schema == 2:
        allowed = {
            "schema", "scenario_id", "scenario_version", "scenario_set_digest", "provenance", "outcome",
            "assertions", "cleanup", "metrics", "duration_ms", "evidence_refs", "reason_code",
            "monotonic_start_ns", "monotonic_end_ns", "phase_durations_ms",
        }
        schema_version = 2
    else:
        raise ResultValidationError("unsupported result schema")
    _safe_key_set(payload, allowed, "result")
    provenance_value = payload.get("provenance")
    if not isinstance(provenance_value, Mapping):
        raise ResultValidationError("provenance must be an object")
    provenance = _provenance_from_payload(provenance_value, schema_version=schema_version)
    cleanup = payload.get("cleanup")
    metrics = payload.get("metrics")
    if not isinstance(cleanup, Mapping) or not isinstance(metrics, Mapping):
        raise ResultValidationError("cleanup and metrics must be objects")
    if schema_version == 1:
        evidence_refs_value = payload.get("evidence_refs")
        if not isinstance(evidence_refs_value, Sequence) or isinstance(evidence_refs_value, (str, bytes)):
            raise ResultValidationError("evidence_refs must be an array")
        evidence_refs: tuple[str | EvidenceReference, ...] = tuple(evidence_refs_value)  # type: ignore[assignment]
        phase_durations = None
        start_ns = end_ns = None
    else:
        if not {"monotonic_start_ns", "monotonic_end_ns", "phase_durations_ms"}.issubset(payload):
            raise ResultValidationError("v2 timing metadata is incomplete")
        evidence_refs = _evidence_from_payload(payload.get("evidence_refs"))
        phase_durations = payload["phase_durations_ms"]
        start_ns = payload["monotonic_start_ns"]
        end_ns = payload["monotonic_end_ns"]
    try:
        ScenarioResult(
            scenario_id=payload.get("scenario_id"),  # type: ignore[arg-type]
            scenario_version=payload.get("scenario_version", -1),  # type: ignore[arg-type]
            scenario_set_digest=payload.get("scenario_set_digest"),  # type: ignore[arg-type]
            provenance=provenance,
            outcome=payload.get("outcome"),  # type: ignore[arg-type]
            assertions=_assertions_from_payload(payload.get("assertions")),
            cleanup=cleanup,
            metrics=metrics,
            duration_ms=payload.get("duration_ms", -1),  # type: ignore[arg-type]
            evidence_refs=evidence_refs,
            reason_code=payload.get("reason_code"),  # type: ignore[arg-type]
            schema_version=schema_version,
            monotonic_start_ns=start_ns,  # type: ignore[arg-type]
            monotonic_end_ns=end_ns,  # type: ignore[arg-type]
            phase_durations_ms=phase_durations,  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ResultValidationError):
            raise
        raise ResultValidationError("malformed result payload") from error
