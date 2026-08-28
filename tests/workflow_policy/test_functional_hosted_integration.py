"""Cross-platform policy checks for the bounded hosted functional lanes."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from torturer_checks.hosted.run import EXPECTED_UNAVAILABLE_BY_PLATFORM
from torturer_contract.functional.scenarios import scenario_catalog

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = {
    "linux": ROOT / ".github" / "workflows" / "functional.yml",
    "windows": ROOT / ".github" / "workflows" / "functional-windows.yml",
    "macos": ROOT / ".github" / "workflows" / "functional-macos.yml",
    "android": ROOT / ".github" / "workflows" / "functional-android.yml",
}
EXPECTED_UNAVAILABLE = {
    "linux": (
        "functional.network-transition=HOSTED_LINUX_INTERFACE_REQUIRED",
        "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
    ),
    "windows": (
        "functional.network-transition=HOSTED_WINDOWS_UPLINK_TOGGLE_UNSUPPORTED",
        "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
    ),
    "macos": (
        "functional.network-transition=HOSTED_MACOS_UPLINK_TOGGLE_UNSUPPORTED",
        "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED",
    ),
    "android": (
        "functional.network-transition=ANDROID_UPLINK_TOGGLE_UNSUPPORTED",
        "functional.bounded-endurance=ANDROID_ENDURANCE_SEAM_UNSUPPORTED",
    ),
}
MIN_CANONICAL_TIMEOUT = {
    "linux": 1010,
    "windows": 1010,
    "macos": 1010,
    "android": 980,
}
POST_LANE_RESERVE_SECONDS = {
    "linux": 300,
    "windows": 300,
    "macos": 300,
    "android": 300,
}
DECLARED_LANE_SECONDS = {"linux": 950, "windows": 950, "macos": 950, "android": 920}

def _job(text: str, name: str, next_name: str | None = None) -> str:
    start = text.index(f"  {name}:")
    if next_name is None:
        return text[start:]
    return text[start:text.index(f"\n\n  {next_name}:", start)]

class FunctionalHostedIntegrationPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.texts = {platform: path.read_text(encoding="utf-8") for platform, path in WORKFLOWS.items()}

    def test_every_functional_job_is_at_most_thirty_minutes(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                values = [int(value) for value in re.findall(r"(?m)^    timeout-minutes:\s*(\d+)\s*$", text)]
                self.assertTrue(values)
                self.assertLessEqual(max(values), 30)
                client = _job(text, "client", "controller")
                if platform == "android":
                    build = _job(text, "build", "client")
                    build_timeout = int(re.search(r"(?m)^    timeout-minutes:\s*(\d+)\s*$", build).group(1))
                    client_timeout = int(re.search(r"(?m)^    timeout-minutes:\s*(\d+)\s*$", client).group(1))
                    self.assertEqual(build_timeout, 10)
                    self.assertEqual(client_timeout, 30)
                    self.assertIn("RUN_DEADLINE_EPOCH - $(date +%s) - 300", client)
                else:
                    self.assertIn("    timeout-minutes: 30", client)
                self.assertIn("    timeout-minutes: 30", _job(text, "controller"))

    def test_client_and_controller_have_absolute_deadlines_and_reserve(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                controller = _job(text, "controller")
                self.assertIn("RUN_DEADLINE_EPOCH", client)
                self.assertIn("RUN_DEADLINE_EPOCH - $(date +%s) - 300", client)
                self.assertIn("torturer_checks.hosted.deadline", client)
                self.assertIn("--kill-grace-seconds 30", client)
                self.assertIn('--lane-timeout-seconds "$remaining"', client)
                self.assertIn(f'-lt {MIN_CANONICAL_TIMEOUT[platform]}', client)
                self.assertIn('remaining=1200', client)
                self.assertNotIn('remaining=1260', client)
                self.assertIn('"available_until_epoch"', client)
                self.assertIn('server_remaining=$((available_until_epoch - $(date +%s)))', client)
                self.assertIn(
                    f'client_post_lane_reserve_seconds={POST_LANE_RESERVE_SECONDS[platform]}',
                    client,
                )
                self.assertIn('server_lane_remaining=$((server_remaining - client_post_lane_reserve_seconds - lane_start_margin_seconds))', client)
                self.assertIn('lane_start_margin_seconds=5', client)
                self.assertIn('POST_LANE_DEADLINE_EPOCH', client)
                self.assertIn('POST_LANE_STEP_TIMEOUT_SECONDS=60', client)
                self.assertIn('POST_LANE_MARKER_RESERVE_SECONDS=180', client)
                self.assertLess(
                    client.index("Establish validated post-lane provider deadline"),
                    client.index("- name: Run canonical"),
                )
                self.assertIn('insufficient Render lease lifetime before functional lane', client)
                self.assertIn("CONTROLLER_DEADLINE_EPOCH", controller)
                self.assertIn("CONTROLLER_DEADLINE_EPOCH - $(date +%s) - 120", controller)
                self.assertIn("api_timeout=30", controller)
                self.assertIn("dispatch_timeout=30", controller)
                self.assertIn("private-gh-api.sh", controller)
                self.assertIn("SOURCE_SHA: ${{ inputs.commit_sha }}", controller)
                self.assertIn("inputs[origin_source_sha]=${SOURCE_SHA}", controller)
                self.assertIn("deadline = int(started.timestamp()) + 30 * 60", controller)
                self.assertLess(controller.index("CONTROLLER_DEADLINE_EPOCH"), controller.index("found=false"))
                self.assertLess(controller.index("found=false"), controller.index("Dispatch exactly one trusted"))

    def test_marker_follows_essential_cleanup_and_aggregate_reserve_is_explicit(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                post_lane = client[client.index("- name: Run canonical"):]
                upload_blocks = re.split(r"(?m)^      - name: ", post_lane)[1:]
                artifact_uploads = [
                    block for block in upload_blocks
                    if "uses: actions/upload-artifact@" in block
                ]
                expected_uploads = {
                    "linux": 2,
                    "windows": 2,
                    "macos": 3,
                    "android": 4,
                }
                self.assertEqual(len(artifact_uploads), expected_uploads[platform])
                for block in artifact_uploads:
                    self.assertIn("timeout-minutes: 1", block)
                    self.assertIn("if: always()", block)
                canonical = post_lane.index("- name: Run canonical")
                marker_prepare = post_lane.index("id: post_lane_marker_prepare")
                marker_upload = post_lane.index("- name: Upload opaque")
                essential = {
                    "linux": "- name: Stop candidate service and verify process cleanup",
                    "windows": "- name: Stop exact Windows service and verify cleanup",
                    "macos": "- name: Restore macOS default route before evidence upload",
                    "android": "- name: Stop Android emulator and verify cleanup",
                }[platform]

                def step_block(step_name: str) -> str:
                    start = post_lane.index(step_name)
                    next_step = post_lane.find("\n      - name: ", start + len(step_name))
                    return post_lane[start:] if next_step < 0 else post_lane[start:next_step]

                essential_index = post_lane.index(essential)
                self.assertLess(canonical, essential_index)
                self.assertLess(essential_index, marker_prepare)
                essential_timeout = {"linux": 1, "windows": 1, "macos": 1, "android": 2}[platform]
                self.assertRegex(
                    step_block(essential),
                    rf"(?m)^        timeout-minutes:\s*{essential_timeout}\s*$",
                )
                if platform == "macos":
                    service_cleanup = "- name: Stop exact macOS service and verify cleanup"
                    service_index = post_lane.index(service_cleanup)
                    self.assertLess(canonical, service_index)
                    self.assertLess(service_index, essential_index)
                    self.assertLess(service_index, marker_prepare)
                    self.assertRegex(
                        step_block(service_cleanup),
                        r"(?m)^        timeout-minutes:\s*1\s*$",
                    )
                self.assertLess(marker_prepare, marker_upload)
                if platform == "android":
                    diagnostics = post_lane.index("- name: Report safe Android command diagnostics")
                    diagnostics_upload = post_lane.index("- name: Upload safe Android command diagnostics")
                    self.assertLess(marker_upload, diagnostics)
                    self.assertLess(diagnostics, diagnostics_upload)
                self.assertEqual(
                    post_lane.count("id: post_lane_marker_prepare"),
                    1,
                )
                marker_block = post_lane[post_lane.index("- name: Remove plaintext handoff material", canonical):marker_upload]
                self.assertIn('POST_LANE_MARKER_RESERVE_SECONDS:-', marker_block)
                self.assertIn('post_lane_marker_reserve="${POST_LANE_MARKER_RESERVE_SECONDS:-}"', marker_block)
                self.assertIn('if [ "$post_remaining" -lt "$post_lane_marker_reserve" ]', marker_block)
                remove_index = marker_block.index("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/upload-url.txt\" \"$HANDOFF_DIR/recipient.key\"")
                self.assertLess(remove_index, marker_block.index('run_deadline="${RUN_DEADLINE_EPOCH:-}"'))
                self.assertLess(remove_index, marker_block.index('provider_deadline="${POST_LANE_DEADLINE_EPOCH:-}"'))
                self.assertIn('if [ "$run_deadline" -le "$provider_deadline" ]; then', marker_block)
                self.assertIn('post_deadline="$run_deadline"', marker_block)
                self.assertIn('post_deadline="$provider_deadline"', marker_block)
                self.assertIn("post-lane marker preparation cannot fit before origin/provider deadline", marker_block)
                self.assertIn("functional lane did not establish valid origin/provider deadlines", marker_block)
                marker_upload_block = next(block for block in artifact_uploads if "completion marker" in block.lower())
                self.assertIn("steps.post_lane_marker_prepare.outcome == 'success'", marker_upload_block)
                if platform == "macos":
                    self.assertIn("steps.service_cleanup.outcome == 'success'", marker_upload_block)
                    self.assertIn("steps.route_cleanup.outcome == 'success'", marker_upload_block)
                else:
                    self.assertIn("steps.essential_cleanup.outcome == 'success'", marker_upload_block)
                self.assertIn("POST_LANE_MARKER_RESERVE_SECONDS", client)
                self.assertIn("POST_LANE_MARKER_RESERVE_SECONDS=180", client)
                self.assertIn("timeout-minutes: 1", marker_block)
                self.assertIn("timeout-minutes: 1", marker_upload_block)
                if platform == "android":
                    self.assertIn("timeout-minutes: 2", post_lane)
                for safe_upload in {
                    "linux": ("- name: Upload safe functional result",),
                    "windows": ("- name: Upload safe Windows functional result",),
                    "macos": ("- name: Upload safe macOS failure evidence", "- name: Upload safe macOS functional result"),
                    "android": ("- name: Upload safe Android command diagnostics", "- name: Upload safe Android emulator and transport summary", "- name: Upload safe Android functional result"),
                }[platform]:
                    self.assertGreater(post_lane.index(safe_upload), marker_upload)
                essential_seconds = {"linux": 60, "windows": 60, "macos": 120, "android": 65}[platform]
                if platform == "android":
                    # Android cleanup is proven at 65s; its 180s marker tail
                    # leaves a further 55s scheduling margin in the common
                    # 300s provider-release reserve.
                    self.assertEqual(65 + 180 + 55, POST_LANE_RESERVE_SECONDS[platform])
                else:
                    self.assertLessEqual(essential_seconds + 60 + 60 + 60, POST_LANE_RESERVE_SECONDS[platform])
                    self.assertEqual(120 + 60 + 60 + 60, POST_LANE_RESERVE_SECONDS[platform])
                self.assertNotIn("post_lane_.*_guard", post_lane)
                self.assertNotIn("post-lane service cleanup cannot fit before provider availability", post_lane)
                self.assertNotIn("post-lane evidence retention cannot fit before provider availability", post_lane)
                self.assertNotIn("post-lane route restore cannot fit before provider availability", post_lane)
                self.assertNotIn("post-lane Android emulator cleanup cannot fit before provider availability", post_lane)

    def test_missing_validated_lease_deadline_fails_closed_without_unset_variable_errors(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                paths = client[client.index("- name: Establish runner-local paths"):client.index("- name: Validate trusted functional inputs")]
                self.assertIn("POST_LANE_DEADLINE_EPOCH=unvalidated", paths)
                self.assertIn("POST_LANE_STEP_TIMEOUT_SECONDS=60", paths)
                self.assertIn("POST_LANE_MARKER_RESERVE_SECONDS=180", paths)
                deadline = client.index("- name: Establish validated post-lane provider deadline")
                canonical = client.index("- name: Run canonical")
                self.assertLess(deadline, canonical)
                deadline_block = client[deadline:canonical]
                self.assertIn("no validated lease exists; server hard cleanup remains authoritative", deadline_block)
                self.assertIn("POST_LANE_DEADLINE_EPOCH=%s", deadline_block)
                marker = client.index("id: post_lane_marker_prepare")
                marker_block = client[marker:client.index("- name: Upload opaque", marker)]
                self.assertIn('run_deadline="${RUN_DEADLINE_EPOCH:-}"', marker_block)
                self.assertIn('provider_deadline="${POST_LANE_DEADLINE_EPOCH:-}"', marker_block)
                self.assertIn('post_deadline="$run_deadline"', marker_block)
                self.assertIn('post_deadline="$provider_deadline"', marker_block)
                self.assertIn('post_lane_marker_reserve="${POST_LANE_MARKER_RESERVE_SECONDS:-}"', marker_block)
                self.assertIn("functional lane did not establish valid origin/provider deadlines", marker_block)

    def test_platform_lane_minima_match_catalog_and_capability_arithmetic(self) -> None:
        scenarios = scenario_catalog()
        scenario_by_id = {scenario.id: scenario for scenario in scenarios}
        for platform, expected_pairs in EXPECTED_UNAVAILABLE.items():
            unavailable_ids = {pair.split("=", 1)[0] for pair in expected_pairs}
            applicable_seconds = sum(
                scenario.max_duration_seconds
                for scenario_id, scenario in scenario_by_id.items()
                if scenario_id not in unavailable_ids
            )
            declared = applicable_seconds + len(scenarios) * 5
            with self.subTest(platform=platform):
                self.assertEqual(declared, DECLARED_LANE_SECONDS[platform])
                self.assertEqual(MIN_CANONICAL_TIMEOUT[platform], declared + 60)
                self.assertLessEqual(MIN_CANONICAL_TIMEOUT[platform], 1200)

    def test_source_sha_binds_request_lease_and_pre_decrypt_validation(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                self.assertIn("source_sha", client)
                self.assertIn("inputs[origin_source_sha]=${SOURCE_SHA}", _job(text, "controller"))
                self.assertIn("source_sha", text[text.index("request.json"):])
                self.assertIn("source_sha", text[text.index("openssl cms -decrypt"):])

    def test_each_workflow_declares_exact_reviewed_unavailable_allowlist(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                run = client[client.index("- name: Run canonical") :]
                actual = re.findall(r"--expected-unavailable\s+([^\s\\]+)", run)
                self.assertCountEqual(actual, EXPECTED_UNAVAILABLE[platform])
                self.assertEqual(
                    set(EXPECTED_UNAVAILABLE[platform]),
                    set("%s=%s" % pair for pair in EXPECTED_UNAVAILABLE_BY_PLATFORM[platform]),
                )
                self.assertNotIn("--scenario-id", run)

    def test_deadline_arithmetic_keeps_api_grace_inside_finalization_reserve(self) -> None:
        lane_seconds = 30 * 60
        finalization_reserve = 120
        api_grace_and_reserve = 181
        self.assertGreater(lane_seconds, finalization_reserve)
        self.assertGreater(api_grace_and_reserve, finalization_reserve)
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                self.assertRegex(client, r"api_remaining=\$\(\(RUN_DEADLINE_EPOCH - \$\(date \+%s\) - 181\)\)")
                self.assertNotIn('--kill-after=30s "${remaining}s"', client)
                self.assertNotIn('--kill-after=10s "${remaining}s"', client)

    def test_every_github_api_call_is_explicitly_bounded(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                self.assertNotIn("gh api", text)
                self.assertIn(".github/scripts/private-gh-api.sh", text)

    def test_non_android_openssl_calls_are_bounded(self) -> None:
        for platform, text in self.texts.items():
            if platform == "android":
                continue
            lines = text.splitlines()
            for index, line in enumerate(lines):
                if not re.search(r"openssl (?:req|cms -decrypt)", line):
                    continue
                context = "\n".join(lines[max(0, index - 3):index + 1])
                with self.subTest(platform=platform, line=index + 1):
                    self.assertIn("timeout", context)

    def test_trusted_helper_revision_is_proven_before_candidate_staging(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                build = _job(text, "build", "client")
                for required in (
                    "TORTURER_SHA: ${{ github.sha }}",
                    "git -C torturer rev-parse HEAD",
                    "test -z \"$(git -C torturer status --porcelain=v1 --untracked-files=all)\"",
                ):
                    self.assertIn(required, build)
                proof = build.index("git -C torturer rev-parse HEAD")
                stage_marker = "torturer_checks.hosted.candidate stage" if platform == "linux" else "candidate.py stage"
                stage = build.index(stage_marker)
                self.assertLess(proof, stage)

    def test_public_workflows_never_echo_raw_diagnostics(self) -> None:
        workflow_root = ROOT / ".github" / "workflows"
        forbidden = (
            "| tee",
            "stdout-begin",
            "stderr-begin",
            "combined-output-begin",
            "cat $SERVICE_DIR",
            "cat \"$EMULATOR_LOG\"",
            "Get-Content $SERVICE_DIR",
        )
        for path in sorted(workflow_root.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                for marker in forbidden:
                    self.assertNotIn(marker, text)
        for path in tuple((workflow_root / name) for name in (
            "functional.yml",
            "functional-android.yml",
            "functional-macos.yml",
            "functional-windows.yml",
            "server-lease.yml",
        )):
            self.assertIn("private-gh-api.sh", path.read_text(encoding="utf-8"))

    def test_public_output_helpers_are_safe_by_construction(self) -> None:
        source_root = ROOT / "torturer_checks"
        for relative in (
            "linux_slice.py",
            "desktop_slice.py",
            "source_checkout.py",
            "android.py",
            "hosted/deadline.py",
        ):
            source = (source_root / relative).read_text(encoding="utf-8")
            with self.subTest(source=relative):
                self.assertNotIn("stdout-begin", source)
                self.assertNotIn("stderr-begin", source)
                self.assertNotIn("combined-output-begin", source)
                self.assertNotIn("sys.stdout.buffer.write", source)
                self.assertNotIn("sys.stderr.buffer.write", source)
        deadline = (source_root / "hosted/deadline.py").read_text(encoding="utf-8")
        self.assertIn("SubprocessRunner", deadline)
        self.assertNotIn("stdout=None", deadline)
        self.assertNotIn("stderr=None", deadline)
        candidate = (source_root / "hosted/candidate.py").read_text(encoding="utf-8")
        self.assertNotIn("print(json.dumps(manifest", candidate)
        self.assertIn("candidate_closure status=", candidate)


if __name__ == "__main__":
    unittest.main()
