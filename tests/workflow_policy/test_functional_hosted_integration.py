"""Cross-platform policy checks for the bounded hosted functional lanes."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = {
    "linux": ROOT / ".github" / "workflows" / "functional.yml",
    "windows": ROOT / ".github" / "workflows" / "functional-windows.yml",
    "macos": ROOT / ".github" / "workflows" / "functional-macos.yml",
    "android": ROOT / ".github" / "workflows" / "functional-android.yml",
}

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
                    self.assertEqual(client_timeout, 20)
                    self.assertLessEqual(build_timeout + client_timeout, 30)
                else:
                    self.assertIn("    timeout-minutes: 30", client)
                self.assertIn("    timeout-minutes: 30", _job(text, "controller"))

    def test_client_and_controller_have_absolute_deadlines_and_reserve(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                controller = _job(text, "controller")
                self.assertIn("RUN_DEADLINE_EPOCH", client)
                self.assertIn("RUN_DEADLINE_EPOCH - $(date +%s) - 120", client)
                self.assertIn("torturer_checks.hosted.deadline", client)
                self.assertIn("--kill-grace-seconds 30", client)
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

    def test_source_sha_binds_request_lease_and_pre_decrypt_validation(self) -> None:
        for platform, text in self.texts.items():
            with self.subTest(platform=platform):
                client = _job(text, "client", "controller")
                self.assertIn("source_sha", client)
                self.assertIn("inputs[origin_source_sha]=${SOURCE_SHA}", _job(text, "controller"))
                self.assertIn("source_sha", text[text.index("request.json"):])
                self.assertIn("source_sha", text[text.index("openssl cms -decrypt"):])

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

    def test_linux_only_declares_the_reviewed_expected_unavailable_pair(self) -> None:
        expected = '--expected-unavailable "functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED"'
        self.assertEqual(self.texts["linux"].count(expected), 1)
        for platform in ("windows", "macos", "android"):
            with self.subTest(platform=platform):
                self.assertNotIn("--expected-unavailable", self.texts[platform])

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
