"""Keep the reusable verifier inside its secretless public trust boundary."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from torturer_contract.workflow_policy import (
    FORBIDDEN_WORKFLOW_TOKENS,
    HOSTED_RUNNERS,
    PINNED_EXTERNAL_ACTIONS,
    STABLE_CHECK_NAMES,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "verify.yml"

class VerifyWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_is_reusable_only_with_the_documented_inputs(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_call:")
        self.assertNotRegex(self.text, r"(?m)^  (?:pull_request|push|workflow_dispatch|schedule):")
        for name in ("source_repository", "commit_sha", "pr_number"):
            self.assertRegex(self.text, rf"(?m)^      {name}:\n")

    def test_has_only_read_only_contents_permission(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")
        self.assertNotRegex(self.text, r"(?im):\s*(?:write|admin)\s*(?:#.*)?$")

    def test_forbids_privileged_triggers_secrets_environments_and_caches(self) -> None:
        for token in FORBIDDEN_WORKFLOW_TOKENS:
            self.assertNotIn(token, self.text, token)

    def test_every_external_action_is_immutably_pinned(self) -> None:
        self.assertTrue(self.uses)
        self.assertEqual(set(self.uses), PINNED_EXTERNAL_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")

    def test_runs_untrusted_candidate_only_on_ephemeral_hosted_labels(self) -> None:
        runners = re.findall(r"(?m)^    runs-on: ([^\s#]+)$", self.text)
        self.assertCountEqual(
            runners,
            ["ubuntu-24.04", "windows-2022", "macos-15", "macos-15-intel", "ubuntu-24.04"],
        )
        self.assertTrue(set(runners).issubset(HOSTED_RUNNERS))
        self.assertNotIn("self-hosted", self.text)

    def test_checks_out_pinned_helpers_and_exact_candidate_without_credentials(self) -> None:
        helper_refs = re.findall(r"(?m)^          ref: ([0-9a-f]{40})$", self.text)
        self.assertEqual(helper_refs, ["5980b453cadf00391ea733dc5169f8e5ae9fa04b"] * 5)
        candidate_checkout = re.search(
            r"- name: Check out exact candidate\n.*?(?=\n      - name:)",
            self.text,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(candidate_checkout)
        assert candidate_checkout is not None
        self.assertIn("repository: ${{ inputs.source_repository }}", candidate_checkout.group())
        self.assertIn("ref: ${{ inputs.commit_sha }}", candidate_checkout.group())
        self.assertIn("persist-credentials: false", candidate_checkout.group())
        self.assertIn("submodules: recursive", candidate_checkout.group())

    def test_stable_job_names_and_helper_clis_are_present(self) -> None:
        for name in STABLE_CHECK_NAMES:
            self.assertIn(f"name: {name}", self.text)
        self.assertIn("python3 -m torturer_checks.linux_slice", self.text)
        self.assertIn("python -m torturer_checks.desktop_slice", self.text)
        self.assertIn("python3 -m torturer_checks.desktop_slice", self.text)
        self.assertIn("python3 tests/android/run_contract.py", self.text)
        self.assertGreaterEqual(self.text.count("--commit-sha"), 5)

    def test_android_bootstrap_is_explicit_and_version_is_validated_first(self) -> None:
        validate_position = self.text.index("name: Validate candidate Go version")
        setup_position = self.text.index("name: Set up candidate Go version")
        self.assertLess(validate_position, setup_position)
        self.assertIn("ANDROID_NDK_HOME", self.text)
        self.assertIn(
            "golang.org/x/mobile/cmd/gomobile@v0.0.0-20260520154334-0e4426e1883d",
            self.text,
        )
        self.assertIn("/dev/kvm", self.text)
        self.assertIn('"ndk;27.2.12479018"', self.text)
        self.assertIn('"build-tools;36.0.0"', self.text)
        self.assertRegex(
            self.text,
            r"actions/setup-go@[0-9a-f]{40}\n        with:\n"
            r"          go-version: .+\n          cache: false",
        )


if __name__ == "__main__":
    unittest.main()
