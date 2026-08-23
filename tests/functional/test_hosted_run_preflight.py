from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from torturer_checks.hosted.cli import HostedAdapterError, SubprocessRunner
from torturer_checks.hosted import run as hosted_run
from torturer_contract.functional.capabilities import Capability
from torturer_contract.functional.engine import FunctionalEngine
from torturer_contract.functional.results import RunProvenance
from torturer_contract.functional.scenarios import get_scenario


class _EvidenceSink:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def safe_evidence(self) -> tuple[dict[str, object], ...]:
        return tuple(self.records)


class _V2Adapter:
    capabilities = frozenset({Capability.CONFIGURE})

    def __init__(self) -> None:
        self.runner = _EvidenceSink()

    def execute(self, step):
        self.runner.records.append({
            "evidence_id": "a" * 32,
            "evidence_bytes": 23,
            "evidence_sha256": "f" * 64,
        })
        return {"configured": True}

    def reset(self, *, timeout_seconds: float = 5) -> None:
        self.runner.records.append({
            "evidence_id": "b" * 32,
            "evidence_bytes": 19,
            "evidence_sha256": "e" * 64,
        })


def _v2_provenance(adapter: _V2Adapter) -> RunProvenance:
    return RunProvenance(
        source_repository="DobbyVPN/DobbyVPN",
        source_sha="a" * 40,
        torturer_sha="b" * 40,
        artifact_sha256="c" * 64,
        artifact_manifest_sha256="d" * 64,
        artifact_kind="source-build-closure",
        server_image_digest="sha256:" + "e" * 64,
        platform="linux",
        platform_version="24.04",
        architecture="amd64",
        adapter_id="hosted-linux-cli",
        adapter_version="v2",
        capabilities=frozenset(item.value for item in adapter.capabilities),
    )


class HostedRunPreflightTests(unittest.TestCase):
    def test_v2_run_binds_evidence_after_adapter_commands(self) -> None:
        adapter = _V2Adapter()
        results, reset_failures, reset_count = hosted_run._run_scenarios(
            FunctionalEngine("a" * 64, schema_version=2),
            (get_scenario("functional.configure"),),
            adapter,
            _v2_provenance(adapter),
        )
        self.assertEqual(reset_failures, [])
        self.assertEqual(reset_count, 1)
        self.assertEqual(results[0]["schema"], 2)
        self.assertEqual(
            results[0]["evidence_refs"],
            [
                {"id": "a" * 32, "bytes": 23, "sha256": "f" * 64},
                {"id": "b" * 32, "bytes": 19, "sha256": "e" * 64},
            ],
        )

    def test_v2_reset_failure_is_retained_without_dropping_reset_evidence(self) -> None:
        secret_marker = (
            "SECRET_MARKER profile-bytes bearer=credential endpoint=https://"
            "user:pass@private.example 198.51.100.77"
        )

        class FailingResetAdapter(_V2Adapter):
            def reset(self, *, timeout_seconds: float = 5) -> None:
                super().reset(timeout_seconds=timeout_seconds)
                raise RuntimeError(secret_marker)

        adapter = FailingResetAdapter()
        results, reset_failures, reset_count = hosted_run._run_scenarios(
            FunctionalEngine("a" * 64, schema_version=2),
            (get_scenario("functional.configure"),),
            adapter,
            _v2_provenance(adapter),
        )
        self.assertEqual(reset_count, 1)
        self.assertEqual(reset_failures, ["RuntimeError"])
        self.assertEqual(results[0]["evidence_refs"][-1]["id"], "b" * 32)
        self.assertNotIn(secret_marker, json.dumps(results, sort_keys=True))
        self.assertNotIn(secret_marker, json.dumps(reset_failures, sort_keys=True))

    def test_public_evidence_projection_discards_private_sink_metadata(self) -> None:
        secret_marker = (
            "SECRET_MARKER profile-bytes bearer=credential endpoint=https://"
            "user:pass@private.example 198.51.100.77"
        )
        records = ({
            "sequence": 1,
            "evidence_id": "a" * 32,
            "evidence_bytes": 23,
            "evidence_sha256": "f" * 64,
            "command": ["dobby-cli", "connect-profile", secret_marker],
            "stdout": secret_marker,
            "stderr": secret_marker,
            "profile": secret_marker,
            "endpoint": secret_marker,
            "observed_ip": "198.51.100.77",
        },)
        public = hosted_run._public_evidence(records)
        self.assertEqual(
            public,
            [{"id": "a" * 32, "bytes": 23, "sha256": "f" * 64}],
        )
        self.assertNotIn(secret_marker, json.dumps(public, sort_keys=True))
        self.assertEqual(set(public[0]), {"id", "bytes", "sha256"})

    def test_lane_refuses_scenario_without_execution_and_cleanup_reserve(self) -> None:
        adapter = _V2Adapter()
        with self.assertRaisesRegex(ValueError, "HOSTED_LANE_DEADLINE_EXCEEDED"):
            hosted_run._run_scenarios(
                FunctionalEngine("a" * 64, schema_version=2),
                (get_scenario("functional.configure"),),
                adapter,
                _v2_provenance(adapter),
                deadline=time.monotonic() + 0.05,
            )
        self.assertEqual(adapter.runner.records, [])

    def test_git_head_retains_both_bounded_preflight_streams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hosted-run-git-preflight-") as temporary:
            root = Path(temporary)
            evidence = root.parent / f"{root.name}-evidence"
            subprocess.run(["git", "init", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Torturer"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "torturer@example.invalid"],
                check=True,
            )
            (root / "tracked.txt").write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "fixture"], check=True)
            expected = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            previous_root = hosted_run.ROOT
            hosted_run.ROOT = root
            try:
                self.assertEqual(
                    hosted_run._git_head(evidence_directory=evidence),
                    expected,
                )
            finally:
                hosted_run.ROOT = previous_root
            try:
                self.assertEqual(
                    (evidence / "torturer-rev-parse.stdout.raw.log").read_bytes(),
                    f"{expected}\n".encode("ascii"),
                )
                self.assertEqual(
                    (evidence / "torturer-status.stdout.raw.log").read_bytes(),
                    b"",
                )
                self.assertEqual(
                    (evidence / "torturer-rev-parse.stderr.raw.log").read_bytes(),
                    b"",
                )
                self.assertEqual(
                    (evidence / "torturer-status.stderr.raw.log").read_bytes(),
                    b"",
                )
            finally:
                shutil.rmtree(evidence, ignore_errors=True)

    def test_result_writer_is_exclusive_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hosted-run-result-") as temporary:
            root = Path(temporary)
            output = root / "result.json"
            hosted_run._write_json(output, {"schema": 1, "value": "first"})
            original = output.read_bytes()
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, "RESULT_EVIDENCE_EXISTS"):
                hosted_run._write_json(output, {"schema": 1, "value": "second"})
            self.assertEqual(output.read_bytes(), original)

    def test_result_writer_retains_partial_on_serialization_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hosted-run-partial-") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "RESULT_EVIDENCE_INCOMPLETE"):
                hosted_run._write_json(root / "result.json", {"invalid": object()})
            partials = tuple(root.glob(".result.json.*.tmp"))
            self.assertEqual(len(partials), 1)
            self.assertEqual(os.stat(partials[0]).st_mode & 0o777, 0o600)

    def test_raw_evidence_directory_rejects_symlink_and_shared_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hosted-run-raw-") as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(HostedAdapterError, "EVIDENCE_PATH_UNSAFE"):
                SubprocessRunner(link / "raw")

            os.chmod(root, 0o755)
            try:
                with self.assertRaisesRegex(HostedAdapterError, "EVIDENCE_PATH_UNSAFE"):
                    SubprocessRunner(root / "raw")
            finally:
                os.chmod(root, 0o700)

    def test_parser_registers_download_url_once(self) -> None:
        parser = hosted_run.build_parser()
        matches = [
            action
            for action in parser._actions
            if "--download-url" in action.option_strings
        ]
        self.assertEqual(len(matches), 1)


if __name__ == "__main__":
    unittest.main()
