"""Policy tests for the secretless side of the trusted functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "functional.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class FunctionalWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_is_manual_only_and_has_a_hard_thirty_minute_deadline(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertIn("deadline = int(started.timestamp()) + 30 * 60", self.text)
        self.assertIn("RUN_DEADLINE_EPOCH", self.text)
        self.assertIn("RUN_DEADLINE_EPOCH - $(date +%s) - 120", self.text)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=30s "${remaining}s"', self.text)
        self.assertIn("PLATFORM: linux", self.text)

    def test_linux_lane_runs_every_applicable_canonical_scenario(self) -> None:
        start = self.text.index("- name: Run canonical Linux functional scenarios")
        end = self.text.index("- name: Stop candidate service", start)
        block = self.text[start:end]
        self.assertNotIn("--scenario-id", block)
        for option in (
            "--download-url", "--upload-url", "--service-pid",
            "--service-binary", "--service-socket", "--service-library-path",
            "--service-pid-file",
        ):
            self.assertIn(option, block)
        self.assertNotIn("--network-interface", block)
        self.assertIn('--download-url "https://proof.ovh.net/files/1Mb.dat"', block)
        self.assertNotRegex(block, r'--(?:download|upload)-url\s+"[^"\n]*[?#]')
        self.assertNotIn("speed.cloudflare.com/__down?", block)

    def test_runner_local_paths_are_initialized_from_runner_environment(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertNotIn("${{ runner.temp }}", client)
        self.assertRegex(client, r"(?m)^      - name: Establish runner-local paths$")
        self.assertIn("printf 'HANDOFF_DIR=%s\\n' \"$RUNNER_TEMP/dobbyvpn-render-handoff\"", client)
        self.assertIn("printf 'SERVICE_DIR=%s\\n' \"$RUNNER_TEMP/dobbyvpn-service\"", client)
        self.assertIn("printf 'DOBBYVPN_CONTROL_SOCKET=%s\\n' \"$control_socket\"", client)
        self.assertIn("printf 'RESULT_PATH=%s\\n' \"$RUNNER_TEMP/dobbyvpn-render-handoff/functional-result.json\"", client)
        self.assertGreaterEqual(client.count('} >> "$GITHUB_ENV"'), 2)

    def test_permissions_and_external_actions_are_minimal_and_immutable(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")
        build = self.text[self.text.index("  build:"):self.text.index("\n\n  client:")]
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        controller = self.text[self.text.index("\n\n  controller:"):]
        self.assertRegex(build, r"(?m)^    permissions:\n      contents: read$")
        self.assertRegex(client, r"(?m)^    permissions:\n      contents: read\n      actions: read$")
        self.assertRegex(controller, r"(?m)^    permissions:\n      contents: read\n      actions: write$")
        self.assertEqual(set(self.uses), EXPECTED_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("actions/cache", self.text)

    def test_untrusted_build_is_secretless_and_ends_at_an_allow_listed_artifact(self) -> None:
        build = self.text[self.text.index("  build:"):self.text.index("\n\n  client:")]
        self.assertNotIn("GH_TOKEN", build)
        self.assertNotIn("github.token", build)
        self.assertNotIn("secrets.", build)
        self.assertNotIn("environment:", build)
        self.assertNotIn("RENDER_", build)
        self.assertIn("submodules: recursive", build)
        self.assertIn("Stage an allow-listed candidate runtime closure", build)
        self.assertIn("Upload isolated candidate runtime", build)
        self.assertIn("torturer_checks.hosted.candidate stage", build)
        self.assertIn("--platform linux --architecture amd64", build)
        self.assertIn("torturer_checks.hosted.candidate verify", self.text)
        self.assertIn("Check out exact trusted Torturer helper revision", build)

    def test_tokens_end_before_any_candidate_execution(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        runtime = client[client.index("- name: Start the candidate Linux service"):]
        self.assertIn("GH_TOKEN", client[:client.index("- name: Start the candidate Linux service")])
        self.assertNotIn("GH_TOKEN", runtime)
        self.assertNotIn("github.token", runtime)
        controller = self.text[self.text.index("\n\n  controller:"):]
        self.assertIn("actions: write", controller)
        self.assertNotIn("actions/checkout", controller)
        self.assertNotIn("desktop_build.py", controller)
        self.assertIn("Dispatch exactly one trusted Render lease", controller)

    def test_render_provisioning_starts_only_after_verified_client_readiness(self) -> None:
        verify = self.text.index("- name: Verify trusted Torturer and exact candidate runtime closure")
        deadline = self.text.index("- name: Establish the hard thirty-minute workflow deadline")
        request = self.text.index("- name: Upload public certificate and opaque request after verified client readiness")
        wait = self.text.index("- name: Wait for and download the exact encrypted lease response")
        start = self.text.index("- name: Start the candidate Linux service")
        functional = self.text.index("- name: Run canonical Linux functional scenarios")
        self.assertLess(verify, deadline)
        self.assertLess(deadline, request)
        self.assertLess(request, wait)
        self.assertLess(wait, start)
        self.assertLess(start, functional)
        self.assertNotIn("GH_TOKEN", self.text[start:functional])

    def test_only_public_request_and_ciphertext_cross_job_boundaries(self) -> None:
        request = self.text.index("- name: Upload public certificate and opaque request")
        request_end = self.text.index("\n\n      - name:", request)
        request_block = self.text[request:request_end]
        self.assertIn("recipient.crt", request_block)
        self.assertIn("request.json", request_block)
        self.assertNotIn("recipient.key", request_block)
        self.assertNotIn("profile.toml", request_block)
        self.assertNotIn("PROFILE_HANDOFF_NOT_IMPLEMENTED", self.text)
        self.assertIn("torturer_checks.hosted.artifacts", self.text)
        self.assertIn("--expect-file lease.json", self.text)
        self.assertIn("--expect-file profile.cms", self.text)
        self.assertIn('--run-id "$lease_workflow_run_id"', self.text)
        self.assertNotIn('--run-id "$GITHUB_RUN_ID"', self.text)
        self.assertIn('"path": ".github/workflows/server-lease.yml"', self.text)
        self.assertIn('"display_title": sys.argv[3]', self.text)
        self.assertIn('"head_sha": os.environ["TORTURER_SHA"]', self.text)
        self.assertIn("--raw-log-dir", self.text)
        self.assertIn("--server-image-digest", self.text)
        self.assertIn('--candidate-manifest "$GITHUB_WORKSPACE/candidate/manifest.json"', self.text)
        self.assertIn("render-complete-${{ env.LEASE_RUN_ID }}-linux", self.text)
        self.assertIn("actual_exe=", self.text)
        self.assertIn("candidate service left child processes", self.text)


    def test_service_pid_is_exact_and_cleanup_tracks_restarts(self) -> None:
        start = self.text.index("- name: Start the candidate Linux service")
        run = self.text.index("- name: Run canonical Linux functional scenarios")
        start_block = self.text[start:run]
        self.assertIn("sudo -n sh -c", start_block)
        self.assertIn('printf "%s\\n" "$!"', start_block)
        self.assertNotIn("service_pid=$!", start_block)
        self.assertIn("SERVICE_PID_FILE", start_block)
        self.assertIn('sudo -n readlink -f "/proc/$service_pid/exe"', start_block)
        stop = self.text.index("- name: Stop candidate service and verify process cleanup")
        result = self.text.index("- name: Upload safe functional result")
        cleanup = self.text[stop:result]
        self.assertIn('service_pid="$(cat "$SERVICE_PID_FILE")"', cleanup)
        self.assertIn('sudo -n kill -TERM "$service_pid"', cleanup)
        self.assertNotIn('sudo -n kill -TERM "$SERVICE_PID"', cleanup)
    def test_cleanup_marker_and_plaintext_removal_are_unconditional(self) -> None:
        stop = self.text.index("- name: Stop candidate service and verify process cleanup")
        result = self.text.index("- name: Upload safe functional result")
        marker = self.text.index("- name: Publish opaque completion marker")
        remove = self.text.index("- name: Remove plaintext handoff material")
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:marker])
        self.assertIn("if: always()", self.text[marker:remove])
        self.assertIn('rm -f "$HANDOFF_DIR/profile.toml" "$HANDOFF_DIR/recipient.key"', self.text)

    def test_diagnostic_suppression_is_not_added(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)")


if __name__ == "__main__":
    unittest.main()
