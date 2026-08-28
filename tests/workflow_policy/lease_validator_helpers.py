"""Exercise the lease validators embedded in the hosted client workflows."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


_RUN_ID = "a" * 32
_SOURCE_SHA = "b" * 40
_SERVER_DIGEST = "sha256:" + "c" * 64
_SINK_DIGEST = "sha256:" + "d" * 64


def valid_lease(platform: str) -> dict[str, object]:
    """Return a synthetic valid schema-2 lease for a client validator."""

    return {
        "schema": 2,
        "kind": "dobbyvpn.render-lease",
        "run_id": _RUN_ID,
        "platform": platform,
        "source_sha": _SOURCE_SHA,
        "state": "issued",
        "available_until_epoch": 2_000_000_000,
        "services": [
            {
                "role": "outline",
                "service_id": "srv-outline-abc123",
                "image_digest": _SERVER_DIGEST,
                "provider_generation": "gen-20260827-abc123",
            },
            {
                "role": "upload-sink",
                "service_id": "srv-upload-abc123",
                "image_digest": _SINK_DIGEST,
                "provider_generation": "gen-20260827-abc123",
            },
        ],
    }


def _validator_script(workflow_text: str) -> str:
    marker = '          value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))'
    value_at = -1
    search_from = 0
    while True:
        candidate = workflow_text.find(marker, search_from)
        if candidate < 0:
            break
        if '"schema": 2' in workflow_text[candidate : candidate + 1200] and "services" in workflow_text[candidate : candidate + 2400]:
            value_at = candidate
            break
        search_from = candidate + 1
    if value_at < 0:
        raise ValueError("schema-2 lease validator was not found")
    start = workflow_text.rfind("          import json", 0, value_at)
    end = workflow_text.index("\n          PY", value_at)
    return textwrap.dedent(workflow_text[start:end])


def run_validator(workflow_text: str, lease: dict[str, object]) -> subprocess.CompletedProcess[str]:
    """Run an embedded validator against a synthetic lease record."""

    environment = os.environ.copy()
    environment.update(
        {
            "LEASE_RUN_ID": _RUN_ID,
            "SOURCE_SHA": _SOURCE_SHA,
            "SERVER_IMAGE_DIGEST": _SERVER_DIGEST,
            "SERVER_SINK_IMAGE_DIGEST": _SINK_DIGEST,
        }
    )
    with tempfile.TemporaryDirectory(prefix="workflow-lease-validator-") as directory:
        lease_path = Path(directory) / "lease.json"
        lease_path.write_text(json.dumps(lease), encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-c", _validator_script(workflow_text), str(lease_path)],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )


def adversarial_leases(platform: str) -> dict[str, dict[str, object]]:
    """Build records that must fail closed for identity and binding violations."""

    cases: dict[str, dict[str, object]] = {}
    swapped = valid_lease(platform)
    services = swapped["services"]
    assert isinstance(services, list)
    services[0]["image_digest"], services[1]["image_digest"] = (
        services[1]["image_digest"],
        services[0]["image_digest"],
    )
    cases["swapped service digests"] = swapped

    duplicate_ids = valid_lease(platform)
    duplicate_services = duplicate_ids["services"]
    assert isinstance(duplicate_services, list)
    duplicate_services[1]["service_id"] = duplicate_services[0]["service_id"]
    cases["duplicate service IDs"] = duplicate_ids

    empty_generation = valid_lease(platform)
    generation_services = empty_generation["services"]
    assert isinstance(generation_services, list)
    generation_services[0]["provider_generation"] = ""
    cases["empty provider generation"] = empty_generation

    extra_field = valid_lease(platform)
    extra_field["private_endpoint"] = "https://private.invalid"
    cases["extra top-level field"] = extra_field

    for field, value in (
        ("run_id", "f" * 32),
        ("platform", "other-platform"),
        ("source_sha", "e" * 40),
        ("state", "expired"),
    ):
        identity = valid_lease(platform)
        identity[field] = value
        cases[f"identity mismatch: {field}"] = identity

    return {name: copy.deepcopy(lease) for name, lease in cases.items()}
