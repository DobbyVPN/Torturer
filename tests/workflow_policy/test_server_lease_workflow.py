"""Policy tests for the trusted Render lease workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "server-lease.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class ServerLeaseWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_is_manual_only_and_has_a_bounded_lease_job(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 40$")
        self.assertRegex(self.text, r"(?m)^    environment: render-functional$")

    def test_runner_local_lease_path_is_initialized_from_runner_environment(self) -> None:
        self.assertNotIn("${{ runner.temp }}", self.text)
        self.assertRegex(self.text, r"(?m)^      - name: Establish runner-local paths$")
        self.assertIn("printf 'LEASE_DIR=%s\\n' \"$RUNNER_TEMP/dobbyvpn-render-lease\" >> \"$GITHUB_ENV\"", self.text)

    def test_permissions_and_external_actions_are_immutable(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n  actions: write$")
        self.assertEqual(set(self.uses), EXPECTED_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("actions/cache", self.text)

    def test_no_candidate_checkout_or_candidate_execution_enters_provider_job(self) -> None:
        self.assertEqual(self.text.count("repository: DobbyVPN/Torturer"), 1)
        self.assertNotIn("source_repository", self.text)
        self.assertNotIn("candidate", self.text.lower())
        self.assertIn("torturer_provider.lease_cli acquire", self.text)
        self.assertIn("torturer_provider.lease_cli cleanup", self.text)

    def test_provider_input_is_trusted_and_image_is_immutable(self) -> None:
        self.assertIn('test "$MODE" = acquire', self.text)
        self.assertIn("RENDER_IMAGE_PATH must end in configured digest", self.text.replace("the configured", "configured"))
        self.assertIn('if not image_path.endswith("@" + digest):', self.text)
        self.assertRegex(self.text, r"render-request-\[0-9a-f\]\{32\}-linux")
        self.assertNotRegex(self.text, r"(?m)^      (?:image_path|image_digest):")

    def test_origin_and_request_artifacts_are_bound_to_the_same_run(self) -> None:
        self.assertIn("origin_torturer_sha:", self.text)
        self.assertIn("ORIGIN_TORTURER_SHA: ${{ inputs.origin_torturer_sha }}", self.text)
        self.assertIn('value.get("head_sha") != os.environ["ORIGIN_TORTURER_SHA"]', self.text)
        self.assertIn('value.get("head_sha") != os.environ["TORTURER_SHA"]', self.text)
        self.assertIn('value.get("path") != ".github/workflows/functional.yml"', self.text)
        self.assertIn('workflow_run.get("id") != wanted_run', self.text)
        self.assertIn('files != {"request.json", "recipient.crt"}', self.text)
        self.assertIn('"kind": "dobbyvpn.render-lease-request"', self.text)

    def test_plaintext_never_enters_an_uploaded_artifact(self) -> None:
        upload = self.text.index("- name: Upload encrypted profile and safe lease record")
        wait = self.text.index("- name: Wait for opaque functional completion marker")
        block = self.text[upload:wait]
        self.assertIn("profile.cms", block)
        self.assertIn("lease.json", block)
        self.assertNotIn("profile.toml", block)
        self.assertIn("openssl cms -encrypt -binary -aes-256-gcm", self.text)
        self.assertIn('rm -f "$LEASE_DIR/profile.toml"', self.text)

    def test_cleanup_is_unconditional_and_independently_verified(self) -> None:
        cleanup = self.text.index("- name: Delete the exact Render service and verify absence")
        journal = self.text.index("- name: Upload safe lease journal")
        self.assertIn("if: always()", self.text[cleanup:journal])
        self.assertIn("torturer_provider.lease_cli cleanup", self.text[cleanup:journal])
        self.assertIn("if api.exists(service_id)", (ROOT / "torturer_provider" / "lease_cli.py").read_text(encoding="utf-8"))
        self.assertIn("for attempt in $(seq 1 180)", self.text)
        self.assertIn("completion marker deadline expired", self.text)

    def test_render_token_is_confined_to_provider_steps(self) -> None:
        self.assertEqual(self.text.count("RENDER_API_TOKEN: ${{ secrets.RENDER_API_TOKEN }}"), 2)
        self.assertNotIn("RENDER_API_TOKEN", self.text.split("- name: Acquire one disposable Render service and profile", 1)[0])

    def test_diagnostic_suppression_is_not_added(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)")


if __name__ == "__main__":
    unittest.main()
