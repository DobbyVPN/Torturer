"""Policy tests for the secretless side of the trusted functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "functional.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class FunctionalWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_is_manual_only_and_bounded_to_thirty_minutes(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 30$")
        self.assertIn("timeout --foreground --signal=TERM --kill-after=30s 1120s", self.text)
        self.assertIn("PLATFORM: linux", self.text)

    def test_linux_lane_selects_only_the_feasible_canonical_subset(self) -> None:
        expected = (
            "functional.core-connection",
            "functional.start-stop-start",
        )
        for scenario_id in expected:
            self.assertIn(f"--scenario-id {scenario_id}", self.text)
        self.assertNotIn("--scenario-id functional.bounded-endurance", self.text)
        self.assertNotIn("--scenario-id functional.network-transition", self.text)
        self.assertNotIn("--scenario-id functional.sleep-wake", self.text)
        self.assertNotIn("--scenario-id functional.product-process-loss", self.text)

    def test_runner_local_paths_are_initialized_from_runner_environment(self) -> None:
        self.assertNotIn("${{ runner.temp }}", self.text)
        self.assertRegex(self.text, r"(?m)^      - name: Establish runner-local paths$")
        self.assertIn("printf 'HANDOFF_DIR=%s\\n' \"$RUNNER_TEMP/dobbyvpn-render-handoff\" >> \"$GITHUB_ENV\"", self.text)
        self.assertIn("printf 'SERVICE_DIR=%s\\n' \"$RUNNER_TEMP/dobbyvpn-service\" >> \"$GITHUB_ENV\"", self.text)
        self.assertIn("printf 'DOBBYVPN_CONTROL_SOCKET=%s\\n' \"$control_socket\" >> \"$GITHUB_ENV\"", self.text)
        self.assertIn("printf 'RESULT_PATH=%s\\n' \"$RUNNER_TEMP/dobbyvpn-render-handoff/functional-result.json\" >> \"$GITHUB_ENV\"", self.text)

    def test_permissions_and_external_actions_are_minimal_and_immutable(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        controller = self.text[self.text.index("\n\n  controller:"):]
        self.assertRegex(client, r"(?m)^    permissions:\n      contents: read\n      actions: read$")
        self.assertRegex(controller, r"(?m)^    permissions:\n      contents: read\n      actions: write$")
        self.assertEqual(set(self.uses), EXPECTED_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("actions/cache", self.text)

    def test_candidate_side_is_secretless(self) -> None:
        self.assertNotIn("RENDER_API_TOKEN", self.text)
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("environment:", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("submodules: recursive", self.text)

    def test_candidate_job_has_no_controller_token_and_controller_isolated(self) -> None:
        client = self.text[: self.text.index("\n\n  controller:")]
        controller = self.text[self.text.index("\n\n  controller:"):]
        self.assertNotIn("actions: write", client)
        self.assertNotIn("GH_TOKEN", client)
        self.assertNotIn("github.token", client)
        self.assertIn("actions: write", controller)
        self.assertNotIn("actions/checkout", controller)
        self.assertNotIn("candidate", controller.lower())
        self.assertNotIn("desktop_build.py", controller)
        self.assertIn("Dispatch exactly one trusted Render lease", controller)

    def test_only_ciphertext_crosses_the_job_boundary(self) -> None:
        request = self.text.index("- name: Upload public certificate and opaque request")
        request_end = self.text.index("\n\n      - name:", request)
        request_block = self.text[request:request_end]
        self.assertIn("recipient.crt", request_block)
        self.assertIn("request.json", request_block)
        self.assertNotIn("recipient.key", request_block)
        self.assertNotIn("profile.toml", request_block)
        self.assertIn("PROFILE_HANDOFF_NOT_IMPLEMENTED", self.text)
        self.assertIn("--raw-log-dir", self.text)
        self.assertIn("--server-image-digest", self.text)
        self.assertIn("render-complete-${{ env.LEASE_RUN_ID }}-linux", self.text)
        self.assertIn("actual_exe=", self.text)
        self.assertIn("candidate service left child processes", self.text)

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
