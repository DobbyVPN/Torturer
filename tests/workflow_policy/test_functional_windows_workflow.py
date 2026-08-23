"""Policy tests for the isolated trusted Windows functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "functional-windows.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class FunctionalWindowsWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_manual_windows_lane_has_hard_thirty_minute_client_bound(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^    runs-on: windows-2022$")
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 30$")
        self.assertIn('value["run_started_at"]', self.text)
        self.assertIn("deadline = int(started.timestamp()) + 30 * 60", self.text)
        self.assertNotIn("deadline = lane_started + 30 * 60", self.text)
        self.assertIn("workflow_started_epoch=", self.text)
        self.assertIn("unset GH_TOKEN", self.text)
        self.assertIn("hosted.deadline", self.text)
        self.assertIn("--kill-grace-seconds 30", self.text)
        self.assertIn("for attempt in $(seq 1 360); do", self.text)
        self.assertIn("timeout-minutes: 30", self.text)

    def test_actions_are_immutable_and_minimal(self) -> None:
        self.assertEqual(set(self.uses), EXPECTED_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("actions/cache", self.text)

    def test_build_is_secretless_and_stages_exact_closure(self) -> None:
        build = self.text[self.text.index("  build:"):self.text.index("\n\n  client:")]
        self.assertNotIn("GH_TOKEN", build)
        self.assertNotIn("github.token", build)
        self.assertNotIn("secrets.", build)
        self.assertIn("Prove Windows runner architecture and elevation", build)
        self.assertIn("desktop_build.py libs --platform windows --arch amd64", build)
        self.assertIn("desktop_build.py app --platform windows --skip-libs", build)
        self.assertIn("candidate.py stage", build)
        self.assertIn("--platform windows --architecture amd64", build)
        self.assertIn("candidate-windows-${{ inputs.commit_sha }}", build)

    def test_client_verifies_provenance_before_candidate_execution(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn("candidate.py verify", client)
        self.assertLess(
            client.index("- name: Verify trusted Torturer checkout and candidate closure"),
            client.index("- name: Create ephemeral recipient and opaque Render lease request"),
        )
        self.assertLess(
            client.index("- name: Upload public certificate and opaque request"),
            client.index("- name: Wait for and download exact encrypted Render lease response"),
        )
        self.assertLess(
            client.index("- name: Validate and decrypt encrypted profile"),
            client.index("- name: Start exact Windows service candidate"),
        )
        self.assertIn("Prove Windows client runner architecture and elevation", client)
        self.assertIn("--source-sha \"$SOURCE_SHA\"", client)
        start = client.index("- name: Start exact Windows service candidate")
        runtime = client[start:]
        before_candidate = client[:client.index("- name: Start exact Windows service candidate")]
        self.assertIn("GH_TOKEN", before_candidate)
        self.assertIn("github.token", before_candidate)
        self.assertNotIn("GH_TOKEN", runtime)
        self.assertNotIn("github.token", runtime)
        self.assertIn("hosted.deadline", runtime)
        self.assertIn("--platform windows", runtime)
        self.assertIn("--service-socket", runtime)
        self.assertIn("control_token_ready=1", runtime)
        self.assertIn('dobby-cli.exe\" status', runtime)
        self.assertIn("--candidate-manifest \"$GITHUB_WORKSPACE/candidate/manifest.json\"", runtime)
        self.assertNotRegex(runtime, r"--artifact(?:\s|=)")
        self.assertIn("--download-url \"https://proof.ovh.net/files/1Mb.dat\"", runtime)
        self.assertNotIn("speed.cloudflare.com/__down?", runtime)

    def test_render_handoff_is_opaque_and_bound_to_windows_origin(self) -> None:
        self.assertIn("render-request-${lease_run_id}-${PLATFORM}", self.text)
        self.assertIn("render-lease-${LEASE_RUN_ID}-${PLATFORM}", self.text)
        self.assertIn("render-complete-${{ env.LEASE_RUN_ID }}-windows", self.text)
        self.assertIn("inputs[origin_workflow_path]=.github/workflows/functional-windows.yml", self.text)
        self.assertIn("profile.cms", self.text)
        self.assertIn("recipient.crt", self.text)
        self.assertIn("recipient.key", self.text)
        self.assertIn("profile.toml", self.text)
        self.assertIn("openssl cms -decrypt", self.text)

    def test_cleanup_and_completion_are_unconditional(self) -> None:
        stop = self.text.index("- name: Stop exact Windows service")
        result = self.text.index("- name: Upload safe Windows functional result")
        marker = self.text.index("- name: Publish opaque Windows completion marker")
        remove = self.text.index("- name: Remove plaintext handoff material")
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:marker])
        self.assertIn("if: always()", self.text[marker:remove])
        self.assertIn("taskkill.exe /PID", self.text[stop:result])
        self.assertIn("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/recipient.key\"", self.text)

    def test_no_diagnostic_suppression(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)|SilentlyContinue")
        self.assertNotIn("-InformationLevel Quiet", self.text)
        self.assertIn("Prove Windows runner architecture and elevation", self.text)
        self.assertIn("is_administrator=", self.text)
        self.assertIn("control_token_ready=1", self.text)


if __name__ == "__main__":
    unittest.main()
