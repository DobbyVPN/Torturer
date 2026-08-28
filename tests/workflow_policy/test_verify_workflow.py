"""Keep the reusable verifier inside its secretless public trust boundary."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from torturer_contract.workflow_policy import (
    FORBIDDEN_WORKFLOW_TOKENS,
    HOSTED_RUNNERS,
    NODE24_EXTERNAL_ACTIONS,
    PINNED_EXTERNAL_ACTIONS,
    STABLE_CHECK_NAMES,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "verify.yml"
SELF_TEST_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PINNED_TORTURER_COMMIT = "869304306be83649f3bd9845fb561d191758efff"

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

    def test_self_test_discovers_the_package_test_tree(self) -> None:
        self.assertIn(
            "run: PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py' -v",
            SELF_TEST_WORKFLOW.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "run: python3 -m compileall torturer_checks torturer_contract tests",
            SELF_TEST_WORKFLOW.read_text(encoding="utf-8"),
        )

    def test_all_public_workflow_actions_are_reviewed_node24_pins(self) -> None:
        """Reject a Node-16/20 action before a public runner warns about it.

        The immutable constants are reviewed from upstream ``action.yml``
        manifests when changed; testing every public workflow here prevents a
        later self-test-only action from bypassing that review.
        """
        for workflow in (WORKFLOW, SELF_TEST_WORKFLOW):
            uses = re.findall(
                r"^\s*uses:\s*([^\s#]+)",
                workflow.read_text(encoding="utf-8"),
                flags=re.MULTILINE,
            )
            self.assertTrue(uses, workflow.name)
            for action in uses:
                self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
                self.assertIn(action, NODE24_EXTERNAL_ACTIONS, workflow.name)

    def test_runs_untrusted_candidate_only_on_ephemeral_hosted_labels(self) -> None:
        runners = re.findall(r"(?m)^    runs-on: ([^\s#]+)$", self.text)
        self.assertCountEqual(
            runners,
            [
                "ubuntu-24.04",
                "windows-2022",
                "macos-15",
                "macos-15-intel",
                "macos-15",
                "ubuntu-24.04",
            ],
        )
        self.assertTrue(set(runners).issubset(HOSTED_RUNNERS))
        self.assertNotIn("self-hosted", self.text)

    def test_checks_out_pinned_helpers_and_exact_candidate_without_credentials(self) -> None:
        helper_refs = re.findall(r"(?m)^          ref: ([0-9a-f]{40})$", self.text)
        self.assertEqual(
            helper_refs,
            [PINNED_TORTURER_COMMIT] * 6,
        )
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

    def test_functional_platform_lanes_have_the_documented_30_minute_bound(self) -> None:
        for job in ("linux", "windows", "macos_arm64", "macos_intel", "ios_simulator", "android"):
            section = re.search(
                rf"(?ms)^  {job}:\n.*?(?=^  [a-zA-Z0-9_]+:|\Z)",
                self.text,
            )
            self.assertIsNotNone(section, job)
            assert section is not None
            self.assertRegex(section.group(), r"(?m)^    timeout-minutes: 30$")

    def test_stable_job_names_and_helper_clis_are_present(self) -> None:
        for name in STABLE_CHECK_NAMES:
            self.assertIn(f"name: {name}", self.text)
        self.assertIn("python3 -m torturer_checks.linux_slice", self.text)
        self.assertIn("python -m torturer_checks.desktop_slice", self.text)
        self.assertIn("python3 -m torturer_checks.desktop_slice", self.text)
        self.assertIn("source_identity_from_simulator_checkout", self.text)
        self.assertIn(":app:iosSimulatorArm64Test", self.text)
        self.assertIn("swift test --enable-code-coverage", self.text)
        self.assertIn("python3 tests/ios/run_app_contract.py", self.text)
        self.assertIn("build_ios_xcframework.sh", self.text)
        self.assertIn("--work-dir \"$TORTURER_IOS_WORK_DIR\"", self.text)
        self.assertIn("TORTURER_IOS_SIMULATOR_ARCH: arm64", self.text)
        self.assertIn("--architecture \"$TORTURER_IOS_SIMULATOR_ARCH\"", self.text)
        self.assertIn("python3 tests/android/run_contract.py", self.text)
        self.assertGreaterEqual(self.text.count("--commit-sha"), 5)

    def test_ios_uses_candidate_session_v2_runtime_and_no_cloak_dependency(self) -> None:
        self.assertIn('test -f "$CANDIDATE_DIR/go_module/sessionapi/v2/api.go"', self.text)
        self.assertIn('test -f "$CANDIDATE_DIR/go_module/sessionapi/runtime/lifecycle.go"', self.text)
        self.assertIn('test ! -e "$CANDIDATE_DIR/go_module/modules/Cloak"', self.text)
        self.assertNotIn('Cloak/internal', self.text)

    def test_android_bootstrap_is_explicit_and_version_is_validated_first(self) -> None:
        validate_position = self.text.index("name: Validate candidate Go version")
        setup_position = self.text.index("name: Set up candidate Go version")
        self.assertLess(validate_position, setup_position)
        self.assertIn("ANDROID_NDK_HOME", self.text)
        self.assertIn(
            "golang.org/x/mobile/cmd/gomobile@v0.0.0-20260520154334-0e4426e1883d",
            self.text,
        )
        self.assertIn(
            "golang.org/x/mobile/cmd/gobind@v0.0.0-20260520154334-0e4426e1883d",
            self.text,
        )
        self.assertIn("go mod download", self.text)
        self.assertIn("go mod tidy", self.text)
        self.assertIn("go version -m", self.text)
        self.assertIn('grep -F "$mobile_version"', self.text)
        self.assertNotIn("gomobile init", self.text)
        self.assertIn("/dev/kvm", self.text)
        self.assertIn("TORTURER_ANDROID_RAW_LOG_DIR:", self.text)
        self.assertIn('"ndk;27.2.12479018"', self.text)
        self.assertIn('"build-tools;36.0.0"', self.text)
        self.assertRegex(
            self.text,
            r"actions/setup-go@[0-9a-f]{40}\n        with:\n"
            r"          go-version: .+\n          cache: false",
        )

    def test_ios_bootstrap_is_pinned_and_raw_diagnostics_are_retained_privately(self) -> None:
        self.assertIn("TORTURER_IOS_RAW_LOG_DIR:", self.text)
        self.assertIn(
            "go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260520154334-0e4426e1883d",
            self.text,
        )
        self.assertIn(
            "go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260520154334-0e4426e1883d",
            self.text,
        )
        self.assertIn("go version -m", self.text)
        self.assertIn('export PATH="$tool_dir:$PATH"', self.text)
        self.assertIn("build_ios_xcframework.sh", self.text)
        self.assertGreaterEqual(
            self.text.count('git -C "$CANDIDATE_DIR" diff --quiet --no-ext-diff --'),
            2,
        )
        self.assertIn("candidate source mutated during pinned mobile preparation", self.text)
        self.assertNotIn("gomobile init", self.text)

    def test_mobile_bootstrap_mutation_probe_fails_closed_and_retains_full_diff(self) -> None:
        mutation_probe = 'if ! git -C "$CANDIDATE_DIR" diff --quiet --no-ext-diff --; then'
        full_diff = 'git -C "$CANDIDATE_DIR" diff --no-ext-diff -- >&2'
        self.assertEqual(self.text.count(mutation_probe), 2)
        self.assertEqual(self.text.count(full_diff), 2)
        self.assertNotIn(
            'if ! git -C "$CANDIDATE_DIR" diff --no-ext-diff --; then',
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
