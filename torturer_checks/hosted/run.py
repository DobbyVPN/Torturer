#!/usr/bin/env python3
"""Run the canonical scenarios through one trusted hosted CLI adapter."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from torturer_contract.functional.engine import (
    FunctionalEngine,
    capability_unavailable_reason,
)
from torturer_contract.functional.results import (
    EvidenceReference,
    RunProvenance,
    validate_result_payload,
)
from torturer_contract.functional.scenarios import catalog_document, get_scenario, scenario_catalog

from ..source_checkout import run_bounded_preflight
from .candidate import closure_sha256, expected_architecture, verify as verify_candidate
from .cli import SubprocessRunner, _ensure_owner_only_directory
from .factory import adapter_for_platform


ROOT = Path(__file__).resolve().parents[2]
_SHA40 = set("0123456789abcdef")
# The hosted engine's own ceiling matches the public 30-minute functional
# lane contract.  Workflows may reserve part of that window for provisioning
# and cleanup, but the engine must not impose a contradictory 20-minute cap.
_MAX_LANE_SECONDS = 1_800
_RESET_TIMEOUT_SECONDS = 5
_OPAQUE_EVIDENCE_ID = re.compile(r"[a-z][0-9a-f]{31}\Z")
_SCENARIO_ID = re.compile(r"[a-z][a-z0-9._-]{2,95}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")

# This is intentionally Linux-only for this change. Other hosted lanes keep
# their existing fail-closed behavior until their own reviewed capabilities
# and workflow contracts are updated.
EXPECTED_UNAVAILABLE_BY_PLATFORM: dict[str, frozenset[tuple[str, str]]] = {
    "linux": frozenset({
        ("functional.sleep-wake", "HOSTED_RUNNER_SUSPEND_UNSUPPORTED"),
    }),
}
# Android's first instrumentation process is cold-started on a freshly booted
# emulator.  Keep a small, explicit command-cleanup reserve for that one
# platform so the canonical configure window is spent on the product command;
# process-tree cleanup remains bounded and still fails closed when it cannot
# be proven.  Desktop lanes retain the ordinary five-second reserve.
_ANDROID_COMMAND_CLEANUP_RESERVE_SECONDS = 1.0


def _full_sha(value: str, name: str) -> str:
    if len(value) != 40 or any(ch not in _SHA40 for ch in value):
        raise ValueError(f"{name} must be a full lowercase SHA")
    return value


def _git_head(*, evidence_directory: Path | None = None) -> str:
    result = run_bounded_preflight(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        evidence_directory=evidence_directory,
        evidence_stem="torturer-rev-parse",
    )
    if result.returncode != 0:
        raise ValueError("Torturer checkout could not resolve HEAD")
    status = run_bounded_preflight(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=all"],
        evidence_directory=evidence_directory,
        evidence_stem="torturer-status",
    )
    if status.returncode != 0:
        raise ValueError("Torturer checkout status could not be read")
    if status.stdout.decode("utf-8", errors="replace").strip():
        raise ValueError("Torturer checkout is dirty")
    return _full_sha(result.stdout.decode("utf-8", errors="replace").strip(), "Torturer SHA")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_references(records: object) -> tuple[EvidenceReference, ...]:
    """Convert only sink-produced metadata into canonical v2 references."""
    if not isinstance(records, (tuple, list)):
        raise ValueError("EVIDENCE_METADATA_INVALID")
    references: list[EvidenceReference] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("EVIDENCE_METADATA_INVALID")
        try:
            evidence_id = record["evidence_id"]
            if not isinstance(evidence_id, str) or _OPAQUE_EVIDENCE_ID.fullmatch(evidence_id) is None:
                raise ValueError("opaque evidence id is invalid")
            references.append(
                EvidenceReference(
                    id=evidence_id,
                    bytes=record["evidence_bytes"],
                    sha256=record["evidence_sha256"],
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("EVIDENCE_METADATA_INVALID") from error
    return tuple(references)


def _public_evidence(records: object) -> list[dict[str, object]]:
    """Project private sink metadata to opaque public evidence references only."""

    return [reference.to_dict() for reference in _evidence_references(records)]


def _select_scenarios(scenario_ids: list[str] | None) -> tuple:
    scenarios = scenario_catalog() if not scenario_ids else tuple(get_scenario(value) for value in scenario_ids)
    if len({scenario.id for scenario in scenarios}) != len(scenarios):
        raise ValueError("scenario-id values must be unique")
    worst_case_seconds = sum(scenario.max_duration_seconds for scenario in scenarios)
    worst_case_seconds += len(scenarios) * _RESET_TIMEOUT_SECONDS
    if worst_case_seconds > _MAX_LANE_SECONDS:
        raise ValueError("selected scenarios exceed the 30-minute lane bound")
    return scenarios


def _partition_applicable(
    scenarios,
    capabilities,
    unavailable_reasons: object = None,
) -> tuple[tuple, list[dict[str, object]]]:
    available = frozenset(capabilities)
    applicable = []
    unsupported = []
    for scenario in scenarios:
        missing_capabilities = frozenset(scenario.required_capabilities - available)
        missing = sorted(capability.value for capability in missing_capabilities)
        if missing_capabilities:
            unsupported.append(
                {
                    "scenario_id": scenario.id,
                    "missing_capabilities": missing,
                    "reason_code": capability_unavailable_reason(
                        missing_capabilities,
                        unavailable_reasons,
                    ),
                }
            )
        else:
            applicable.append(scenario)
    return tuple(applicable), unsupported


def _expected_unavailable(values: list[str] | None) -> frozenset[tuple[str, str]]:
    """Parse the workflow's explicit scenario-id=reason-code allowlist."""

    pairs: set[tuple[str, str]] = set()
    for value in values or []:
        scenario_id, separator, reason_code = value.partition("=")
        if (
            not separator
            or _SCENARIO_ID.fullmatch(scenario_id) is None
            or _REASON_CODE.fullmatch(reason_code) is None
        ):
            raise ValueError(
                "expected-unavailable values must be scenario-id=REASON_CODE"
            )
        pair = (scenario_id, reason_code)
        if pair in pairs:
            raise ValueError("expected-unavailable values must be unique")
        pairs.add(pair)
    return frozenset(pairs)


def _unavailable_pair_records(
    values: list[dict[str, object]],
    *,
    result_values: bool = False,
) -> tuple[list[tuple[str, str]], bool]:
    """Return pairs and whether every record has a valid pair shape."""

    pairs: list[tuple[str, str]] = []
    valid = True
    for value in values:
        if not isinstance(value, dict):
            valid = False
            pairs.append(("<invalid-scenario>", "<invalid-reason>"))
            continue
        if result_values and value.get("outcome") != "unavailable":
            continue
        scenario_id = value.get("scenario_id")
        reason_code = value.get("reason_code")
        if (
            not isinstance(scenario_id, str)
            or _SCENARIO_ID.fullmatch(scenario_id) is None
            or not isinstance(reason_code, str)
            or _REASON_CODE.fullmatch(reason_code) is None
        ):
            valid = False
            pairs.append(("<invalid-scenario>", "<invalid-reason>"))
        else:
            pairs.append((scenario_id, reason_code))
    return pairs, valid


def _pair_documents(pairs: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [
        {"scenario_id": scenario_id, "reason_code": reason_code}
        for scenario_id, reason_code in sorted(pairs)
    ]


def _coverage_contract(
    platform: str,
    selected_scenarios,
    results: list[dict[str, object]],
    unsupported_scenarios: list[dict[str, object]],
    expected_unavailable: frozenset[tuple[str, str]],
    *,
    reset_count: int,
    reset_failures: int,
) -> dict[str, object]:
    """Validate complete hosted coverage and return its release-report view."""

    catalog_ids = [scenario.id for scenario in scenario_catalog()]
    catalog_set = set(catalog_ids)
    selected_ids = [scenario.id for scenario in selected_scenarios]
    result_ids = [
        item.get("scenario_id") if isinstance(item, dict) else None
        for item in results
    ]
    selected_catalog_match = (
        len(selected_ids) == len(catalog_ids)
        and len(set(selected_ids)) == len(catalog_ids)
        and set(selected_ids) == catalog_set
    )
    valid_result_ids = [value for value in result_ids if isinstance(value, str)]
    result_catalog_match = (
        len(result_ids) == len(catalog_ids)
        and len(valid_result_ids) == len(result_ids)
        and len(set(valid_result_ids)) == len(catalog_ids)
        and set(valid_result_ids) == catalog_set
    )
    result_outcomes_valid = all(
        isinstance(item, dict)
        and item.get("outcome") in {"passed", "unavailable"}
        for item in results
    )
    failed_results = [
        item for item in results
        if isinstance(item, dict) and item.get("outcome") == "failed"
    ]
    declared_pairs, declared_valid = _unavailable_pair_records(unsupported_scenarios)
    observed_pairs, observed_valid = _unavailable_pair_records(
        results,
        result_values=True,
    )
    declared_ids = [scenario_id for scenario_id, _ in declared_pairs]
    observed_ids = [scenario_id for scenario_id, _ in observed_pairs]
    expected_pairs = sorted(expected_unavailable)
    declared_results_match = (
        declared_valid
        and observed_valid
        and Counter(declared_pairs) == Counter(observed_pairs)
        and Counter(declared_ids) == Counter(observed_ids)
    )
    actual_matches_allowlist = (
        observed_valid
        and Counter(observed_pairs) == Counter(expected_pairs)
    )
    configured = (
        platform in EXPECTED_UNAVAILABLE_BY_PLATFORM
        and expected_unavailable == EXPECTED_UNAVAILABLE_BY_PLATFORM[platform]
    )
    status = (
        "supported-subset-with-expected-limitations"
        if (
            configured
            and selected_catalog_match
            and result_catalog_match
            and result_outcomes_valid
            and not failed_results
            and declared_results_match
            and actual_matches_allowlist
            and reset_count == len(catalog_ids)
            and reset_failures == 0
        )
        else "coverage-contract-failed"
    )
    return {
        "status": status,
        "complete": False,
        "catalog_scenario_count": len(catalog_ids),
        "selected_scenario_count": len(selected_ids),
        "result_scenario_count": len(result_ids),
        "selected_catalog_match": selected_catalog_match,
        "result_catalog_match": result_catalog_match,
        "expected_unavailable": _pair_documents(expected_pairs),
        "declared_unavailable": _pair_documents(declared_pairs),
        "actual_unavailable": _pair_documents(observed_pairs),
        "configured_allowlist_matches_platform": configured,
        "declared_results_match": declared_results_match,
        "actual_matches_allowlist": actual_matches_allowlist,
        "reset_count": reset_count,
        "reset_failures": reset_failures,
    }


def _lane_remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def _require_lane_time(
    deadline: float | None,
    *,
    required_seconds: float,
    operation: str,
) -> float | None:
    """Reserve one operation and its cleanup inside one absolute lane clock."""

    remaining = _lane_remaining(deadline)
    if remaining is not None and remaining <= required_seconds:
        raise ValueError(
            f"HOSTED_LANE_DEADLINE_EXCEEDED before {operation} "
            f"remaining={remaining:.3f}s required={required_seconds:.3f}s"
        )
    return remaining


def _run_scenarios(
    engine,
    scenarios,
    adapter,
    provenance,
    *,
    deadline: float | None = None,
) -> tuple[list[dict[str, object]], list[str], int]:
    results: list[dict[str, object]] = []
    reset_failures: list[str] = []
    reset_count = 0
    runner = getattr(adapter, "runner", None)
    safe_evidence = getattr(runner, "safe_evidence", None)
    if engine.schema_version == 2 and not callable(safe_evidence):
        raise ValueError("EVIDENCE_SINK_UNAVAILABLE")
    for scenario in scenarios:
        missing = scenario.required_capabilities - adapter.capabilities
        # A missing-capability result is immediate, but its mandatory reset is
        # still part of this lane's bounded cleanup. An applicable scenario
        # reserves its declared worst-case execution plus that same cleanup.
        required_seconds = _RESET_TIMEOUT_SECONDS + (
            0 if missing else scenario.max_duration_seconds
        )
        _require_lane_time(
            deadline,
            required_seconds=required_seconds,
            operation=f"scenario {scenario.id}",
        )
        if engine.schema_version == 1:
            # Historical v1 carries opaque IDs only; do not feed structured
            # v2 evidence metadata into a v1 result object.
            result = engine.run(scenario, adapter, provenance)
        else:
            before = len(safe_evidence())
            reset_error: Exception | None = None
            reset_called = False

            def finalize_evidence(
                *, before: int = before
            ) -> tuple[EvidenceReference, ...]:
                nonlocal reset_called, reset_error
                if not reset_called:
                    reset_called = True
                    try:
                        reset_timeout = _lane_remaining(deadline)
                        if reset_timeout is not None:
                            if reset_timeout <= 0:
                                raise ValueError(
                                    "HOSTED_LANE_DEADLINE_EXCEEDED before scenario reset"
                                )
                            reset_timeout = min(
                                float(_RESET_TIMEOUT_SECONDS), reset_timeout
                            )
                        else:
                            reset_timeout = float(_RESET_TIMEOUT_SECONDS)
                        adapter.reset(timeout_seconds=reset_timeout)
                    except Exception as error:
                        reset_error = error
                return _evidence_references(safe_evidence()[before:])

            result = engine.run(
                scenario,
                adapter,
                provenance,
                evidence_provider=finalize_evidence,
            )
        payload = result.to_dict()
        validate_result_payload(payload)
        results.append(payload)
        reset_count += 1
        if engine.schema_version == 2:
            if reset_error is not None:
                reset_failures.append(type(reset_error).__name__)
        else:
            try:
                reset_timeout = _lane_remaining(deadline)
                if reset_timeout is not None:
                    if reset_timeout <= 0:
                        raise ValueError(
                            "HOSTED_LANE_DEADLINE_EXCEEDED before scenario reset"
                        )
                    reset_timeout = min(float(_RESET_TIMEOUT_SECONDS), reset_timeout)
                else:
                    reset_timeout = float(_RESET_TIMEOUT_SECONDS)
                adapter.reset(timeout_seconds=reset_timeout)
            except Exception as error:
                reset_failures.append(type(error).__name__)
        remaining = _lane_remaining(deadline)
        if remaining is not None and remaining <= 0:
            raise ValueError(
                f"HOSTED_LANE_DEADLINE_EXCEEDED after scenario {scenario.id} cleanup"
            )
    return results, reset_failures, reset_count


def _qualification_exit_code(
    results: list[dict[str, object]],
    unsupported_scenarios: list[dict[str, object]],
    reset_failures: list[str],
    *,
    coverage: dict[str, object] | None = None,
) -> int:
    """Fail qualification unless the reviewed Linux coverage contract matches."""
    failed = [
        item for item in results
        if isinstance(item, dict) and item.get("outcome") == "failed"
    ]
    unavailable = [
        item for item in results
        if isinstance(item, dict) and item.get("outcome") == "unavailable"
    ]
    if failed or reset_failures:
        return 2
    if coverage is None:
        # All platforms without an explicit reviewed exception retain the
        # historical fail-closed behavior.
        return 2 if unavailable or unsupported_scenarios else 0
    return 0 if coverage.get("status") == "supported-subset-with-expected-limitations" else 2


def _write_json(path: Path, payload: dict[str, object]) -> None:
    """Create one private result without replacing an existing artifact.

    A result is owner evidence, so an existing path (including a symlink) is
    never replaced.  The temporary inode is deliberately retained on every
    failure, including a short write or destination race, so a failed result
    remains diagnosable rather than being silently discarded.
    """

    _ensure_owner_only_directory(path.parent)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ValueError("RESULT_EVIDENCE_UNAVAILABLE") from error
    else:
        raise ValueError("RESULT_EVIDENCE_EXISTS")

    temporary: Path | None = None
    descriptor: int | None = None
    for _ in range(100):
        candidate = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            continue
        temporary = candidate
        os.fchmod(descriptor, 0o600)
        break
    if temporary is None or descriptor is None:
        raise ValueError("RESULT_EVIDENCE_UNAVAILABLE")

    installed = False
    try:
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        # A hard link gives non-overwriting install semantics: if the output
        # appeared after the preflight check, link(2) fails and the partial
        # temporary remains available for diagnosis.
        os.link(temporary, path, follow_symlinks=False)
        installed = True
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as error:
        raise ValueError(
            f"RESULT_EVIDENCE_INCOMPLETE partial={temporary.name}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if installed and temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                # The installed result is intact; leaving the same-inode
                # temporary is safer than deleting evidence on cleanup error.
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("linux", "windows", "macos", "android"), required=True)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument(
        "--platform-version",
        required=True,
        help="Observed target OS/emulator version; never inferred as unknown",
    )
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--server-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-log-dir", type=Path)
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--identity-url")
    parser.add_argument("--latency-url")
    parser.add_argument("--download-url")
    parser.add_argument("--upload-url")
    parser.add_argument("--scenario-id", action="append", dest="scenario_ids", help="Run one canonical scenario; repeat to select a bounded subset.")
    parser.add_argument("--service-pid", type=int)
    parser.add_argument("--service-binary", type=Path)
    parser.add_argument("--service-socket", type=Path)
    parser.add_argument("--service-library-path", type=Path)
    parser.add_argument("--service-pid-file", type=Path)
    parser.add_argument("--network-interface")
    parser.add_argument(
        "--expected-unavailable",
        action="append",
        default=[],
        dest="expected_unavailable",
        metavar="SCENARIO_ID=REASON_CODE",
        help="Reviewed hosted exception in SCENARIO_ID=REASON_CODE form (Linux only).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        expected_unavailable = _expected_unavailable(args.expected_unavailable)
        if args.platform != "linux" and expected_unavailable:
            raise ValueError(
                "expected-unavailable is only supported for the reviewed Linux lane"
            )
        source_sha = _full_sha(args.source_sha, "source SHA")
        raw_dir = args.raw_log_dir or args.output.parent / "hosted-command-raw"
        _ensure_owner_only_directory(raw_dir)
        torturer_sha = _git_head(evidence_directory=raw_dir)
        if args.candidate_manifest.name != "manifest.json":
            raise ValueError("candidate manifest must be named manifest.json")
        candidate_manifest = verify_candidate(
            args.candidate_manifest.parent,
            platform=args.platform,
            architecture=expected_architecture(args.platform),
            source_sha=source_sha,
        )
        candidate_manifest_sha = _sha256(args.candidate_manifest)
        candidate_closure_sha = closure_sha256(candidate_manifest)
        if candidate_closure_sha == candidate_manifest_sha:
            raise ValueError("candidate closure and manifest digests unexpectedly collide")
        command_cleanup_reserve = (
            _ANDROID_COMMAND_CLEANUP_RESERVE_SECONDS
            if args.platform == "android"
            else None
        )
        runner = (
            SubprocessRunner(raw_dir, cleanup_reserve_seconds=command_cleanup_reserve)
            if command_cleanup_reserve is not None
            else SubprocessRunner(raw_dir)
        )
        adapter = adapter_for_platform(
            args.platform,
            cli=args.cli,
            profile=args.profile,
            runner=runner,
            adb=args.adb,
            source_sha=source_sha,
            identity_url=args.identity_url,
            latency_url=args.latency_url,
            download_url=args.download_url,
            upload_url=args.upload_url,
            service_pid=args.service_pid,
            service_binary=args.service_binary,
            service_socket=args.service_socket,
            service_library_path=args.service_library_path,
            service_pid_file=args.service_pid_file,
            network_interface=args.network_interface,
        )
        provenance = RunProvenance(
            source_repository=args.source_repository,
            source_sha=source_sha,
            torturer_sha=torturer_sha,
            artifact_sha256=candidate_closure_sha,
            artifact_manifest_sha256=candidate_manifest_sha,
            artifact_kind=candidate_manifest["kind"],
            server_image_digest=args.server_image_digest,
            platform=args.platform,
            platform_version=args.platform_version,
            architecture=candidate_manifest["architecture"],
            adapter_id=adapter.adapter_id,
            adapter_version=adapter.adapter_version,
            capabilities=frozenset(item.value for item in adapter.capabilities),
        )
        scenario_set_digest = hashlib.sha256(
            json.dumps(catalog_document(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        engine = FunctionalEngine(scenario_set_digest=scenario_set_digest, schema_version=2)
        selected_scenarios = _select_scenarios(args.scenario_ids)
        # Keep every selected canonical scenario in the engine run. The engine
        # emits a versioned unavailable result for missing capabilities; merely
        # removing those scenarios would make an all-applicable pass look like
        # complete coverage.
        _, unsupported_scenarios = _partition_applicable(
            selected_scenarios,
            adapter.capabilities,
            getattr(adapter, "capability_unavailable_reasons", None),
        )
        scenarios = selected_scenarios
        # The canonical lane clock starts only after source/candidate
        # preflight. The outer workflow still bounds this whole process; this
        # clock specifically covers scenario execution, reset/cleanup, result
        # serialization, and both result fsyncs.
        lane_deadline = time.monotonic() + _MAX_LANE_SECONDS
        results, reset_failures, reset_count = _run_scenarios(
            engine,
            scenarios,
            adapter,
            provenance,
            deadline=lane_deadline,
        )
        coverage = None
        if args.platform == "linux":
            coverage = _coverage_contract(
                args.platform,
                selected_scenarios,
                results,
                unsupported_scenarios,
                expected_unavailable,
                reset_count=reset_count,
                reset_failures=len(reset_failures),
            )
        document = {
            "schema": 2,
            "kind": "dobbyvpn.functional.hosted-run",
            "platform": args.platform,
            "source_sha": source_sha,
            "torturer_sha": torturer_sha,
            "artifact_sha256": candidate_closure_sha,
            "candidate_manifest_sha256": candidate_manifest_sha,
            "artifact_manifest_sha256": candidate_manifest_sha,
            "artifact_kind": candidate_manifest["kind"],
            "platform_version": args.platform_version,
            "architecture": candidate_manifest["architecture"],
            "server_image_digest": args.server_image_digest,
            "adapter_id": adapter.adapter_id,
            "adapter_version": adapter.adapter_version,
            "scenario_set_digest": engine.scenario_set_digest,
            "selected_scenario_ids": [scenario.id for scenario in selected_scenarios],
            "scenario_ids": [scenario.id for scenario in scenarios],
            "unsupported_scenarios": unsupported_scenarios,
            "reset_count": reset_count,
            "reset_failures": len(reset_failures),
            "results": results,
            # The runner retains complete command diagnostics privately.  The
            # public envelope gets only opaque evidence identity/size/digest;
            # command vectors, streams, URLs, and other sink metadata never
            # cross this boundary.
            "safe_command_evidence": _public_evidence(
                getattr(adapter.runner, "safe_evidence", lambda: ())()
            ),
        }
        if coverage is not None:
            document["coverage"] = coverage
        _require_lane_time(
            lane_deadline,
            required_seconds=0.0,
            operation="result serialization",
        )
        _write_json(args.output, document)
        # _write_json fsyncs the result inode and its containing directory. A
        # slow filesystem may cross the lane boundary during those operations;
        # retain the result and fail closed rather than reporting a late pass.
        if time.monotonic() > lane_deadline:
            raise ValueError("HOSTED_LANE_DEADLINE_EXCEEDED during result fsync")
        failed = [item for item in results if item["outcome"] == "failed"]
        unavailable = [item for item in results if item["outcome"] == "unavailable"]
        print(
            f"hosted-functional platform={args.platform} scenarios={len(results)} "
            f"unsupported={len(unsupported_scenarios)} failed={len(failed)} "
            f"unavailable={len(unavailable)} reset_failures={len(reset_failures)} "
            f"coverage={coverage['status'] if coverage is not None else 'strict'}"
        )
        return _qualification_exit_code(
            results,
            unsupported_scenarios,
            reset_failures,
            coverage=coverage,
        )
    except Exception as error:
        print(f"hosted-functional failed code={type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
