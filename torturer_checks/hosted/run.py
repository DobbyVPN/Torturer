#!/usr/bin/env python3
"""Run the canonical scenarios through one trusted hosted CLI adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from torturer_contract.functional.engine import FunctionalEngine
from torturer_contract.functional.results import RunProvenance, validate_result_payload
from torturer_contract.functional.scenarios import catalog_document, get_scenario, scenario_catalog

from .cli import SubprocessRunner
from .factory import adapter_for_platform


ROOT = Path(__file__).resolve().parents[2]
_SHA40 = set("0123456789abcdef")
_MAX_LANE_SECONDS = 1200
_RESET_TIMEOUT_SECONDS = 5


def _full_sha(value: str, name: str) -> str:
    if len(value) != 40 or any(ch not in _SHA40 for ch in value):
        raise ValueError(f"{name} must be a full lowercase SHA")
    return value


def _git_head() -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
    )
    if status.stdout.strip():
        raise ValueError("Torturer checkout is dirty")
    return _full_sha(result.stdout.strip(), "Torturer SHA")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select_scenarios(scenario_ids: list[str] | None) -> tuple:
    scenarios = scenario_catalog() if not scenario_ids else tuple(get_scenario(value) for value in scenario_ids)
    if len({scenario.id for scenario in scenarios}) != len(scenarios):
        raise ValueError("scenario-id values must be unique")
    worst_case_seconds = sum(scenario.max_duration_seconds for scenario in scenarios)
    worst_case_seconds += len(scenarios) * _RESET_TIMEOUT_SECONDS
    if worst_case_seconds > _MAX_LANE_SECONDS:
        raise ValueError("selected scenarios exceed the 30-minute lane bound")
    return scenarios


def _partition_applicable(scenarios, capabilities) -> tuple[tuple, list[dict[str, object]]]:
    available = frozenset(capabilities)
    applicable = []
    unsupported = []
    for scenario in scenarios:
        missing = sorted(
            capability.value
            for capability in scenario.required_capabilities - available
        )
        if missing:
            unsupported.append({"scenario_id": scenario.id, "missing_capabilities": missing})
        else:
            applicable.append(scenario)
    return tuple(applicable), unsupported


def _run_scenarios(engine, scenarios, adapter, provenance) -> tuple[list[dict[str, object]], list[str], int]:
    results: list[dict[str, object]] = []
    reset_failures: list[str] = []
    reset_count = 0
    for scenario in scenarios:
        result = engine.run(scenario, adapter, provenance)
        payload = result.to_dict()
        validate_result_payload(payload)
        results.append(payload)
        reset_count += 1
        try:
            adapter.reset(timeout_seconds=_RESET_TIMEOUT_SECONDS)
        except Exception as error:
            reset_failures.append(type(error).__name__)
    return results, reset_failures, reset_count


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("linux", "windows", "macos", "android"), required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--server-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-log-dir", type=Path)
    parser.add_argument("--download-url")
    parser.add_argument("--upload-url")
    parser.add_argument("--scenario-id", action="append", dest="scenario_ids", help="Run one canonical scenario; repeat to select a bounded subset.")
    parser.add_argument("--service-pid", type=int)
    parser.add_argument("--service-binary", type=Path)
    parser.add_argument("--service-socket", type=Path)
    parser.add_argument("--service-library-path", type=Path)
    parser.add_argument("--service-pid-file", type=Path)
    parser.add_argument("--network-interface")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        source_sha = _full_sha(args.source_sha, "source SHA")
        torturer_sha = _git_head()
        artifact_sha = _sha256(args.artifact)
        raw_dir = args.raw_log_dir or args.output.parent / "hosted-command-raw"
        adapter = adapter_for_platform(
            args.platform,
            cli=args.cli,
            profile=args.profile,
            runner=SubprocessRunner(raw_dir),
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
            artifact_sha256=artifact_sha,
            server_image_digest=args.server_image_digest,
            platform=args.platform,
            adapter_id=adapter.adapter_id,
            adapter_version=adapter.adapter_version,
            capabilities=frozenset(item.value for item in adapter.capabilities),
        )
        scenario_set_digest = hashlib.sha256(
            json.dumps(catalog_document(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        engine = FunctionalEngine(scenario_set_digest=scenario_set_digest)
        selected_scenarios = _select_scenarios(args.scenario_ids)
        if args.scenario_ids:
            scenarios = selected_scenarios
            unsupported_scenarios: list[dict[str, object]] = []
        else:
            scenarios, unsupported_scenarios = _partition_applicable(
                selected_scenarios, adapter.capabilities
            )
        if not scenarios:
            raise ValueError("hosted adapter has no applicable canonical scenarios")
        results, reset_failures, reset_count = _run_scenarios(
            engine, scenarios, adapter, provenance
        )
        document = {
            "schema": 1,
            "kind": "dobbyvpn.functional.hosted-run",
            "platform": args.platform,
            "source_sha": source_sha,
            "torturer_sha": torturer_sha,
            "artifact_sha256": artifact_sha,
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
            "safe_command_evidence": list(getattr(adapter.runner, "safe_evidence", lambda: ())()),
        }
        _write_json(args.output, document)
        failed = [item for item in results if item["outcome"] == "failed"]
        unavailable = [item for item in results if item["outcome"] == "unavailable"]
        print(
            f"hosted-functional platform={args.platform} scenarios={len(results)} "
            f"unsupported={len(unsupported_scenarios)} failed={len(failed)} "
            f"unavailable={len(unavailable)} reset_failures={len(reset_failures)}"
        )
        return 0 if not failed and not unavailable and not reset_failures else 2
    except Exception as error:
        print(f"hosted-functional failed code={type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
