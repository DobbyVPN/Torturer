"""Keep the Render reaper inside the trusted provider boundary."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "render-reaper.yml"


class RenderReaperWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_is_manual_only_and_read_only(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")
        self.assertNotIn("actions/cache", self.text)

    def test_checkout_is_immutable_and_does_not_persist_credentials(self) -> None:
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)$", self.text, flags=re.MULTILINE)
        self.assertEqual(actions, ["actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"])
        self.assertIn("ref: ${{ github.sha }}", self.text)
        self.assertIn("persist-credentials: false", self.text)

    def test_provider_secret_is_confined_to_the_reaper_process(self) -> None:
        self.assertEqual(self.text.count("RENDER_API_TOKEN: ${{ secrets.RENDER_API_TOKEN }}"), 1)
        self.assertIn("environment: render-functional", self.text)
        self.assertNotIn("source_repository", self.text)
        self.assertNotIn("commit_sha", self.text)
        self.assertNotIn("candidate", self.text.lower())
        self.assertEqual(self.text.count("RENDER_OWNER_ID: ${{ vars.RENDER_OWNER_ID }}"), 1)
        self.assertNotIn("RENDER_OWNER_ID: ${{ secrets.RENDER_OWNER_ID }}", self.text)
        self.assertNotIn("profile", self.text.lower())

    def test_command_accepts_only_opaque_namespace_and_service_ids(self) -> None:
        self.assertIn('--name-prefix "$NAME_PREFIX"', self.text)
        self.assertIn('--active-service-id "$service_id"', self.text)
        self.assertNotIn("--token", self.text)
        self.assertNotIn("--profile", self.text)
        self.assertNotIn("--endpoint", self.text)
        self.assertIn("dobbyvpn-render-reaper", self.text)

    def test_reaper_is_short_and_has_an_explicit_age_bound(self) -> None:
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 10$")
        self.assertIn('default: "900"', self.text)
        self.assertIn('--older-than-seconds "$OLDER_THAN_SECONDS"', self.text)


if __name__ == "__main__":
    unittest.main()
