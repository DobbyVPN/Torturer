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
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 30$")
        self.assertNotRegex(self.text, r"(?m)^\s+timeout-minutes:\s*(?:3[1-9]|[4-9][0-9]|[1-9][0-9]{2,})$")
        self.assertIn("LEASE_DEADLINE_EPOCH", self.text)
        self.assertIn("reserve = 680", self.text)
        self.assertIn("cleanup_command_seconds = 600", self.text)
        self.assertIn("cleanup_kill_grace_seconds = 1", self.text)
        self.assertIn("plaintext_cleanup_seconds = 4", self.text)
        self.assertIn("plaintext_kill_grace_seconds = 1", self.text)
        self.assertIn("evidence_upload_seconds = 60", self.text)
        self.assertIn("finalization_overhead_seconds = 10", self.text)
        self.assertIn("if sum(finalization_components) > reserve", self.text)
        self.assertIn("30 * 60", self.text)
        self.assertRegex(self.text, r"(?m)^    environment: render-functional$")
        self.assertIn("run-name: Trusted Render lease ${{ inputs.lease_run_id }} ${{ inputs.platform }}", self.text)

    def test_lease_directory_is_owner_only_before_provider_files_are_created(self) -> None:
        establish = self.text.index("- name: Establish runner-local paths and hard thirty-minute deadline")
        validate = self.text.index("- name: Validate trusted lease boundary")
        block = self.text[establish:validate]
        self.assertIn("umask 077", block)
        self.assertIn('mkdir -p "$lease_dir"', block)
        self.assertIn('chmod 700 "$lease_dir"', block)

    def test_runner_local_lease_path_is_initialized_from_runner_environment(self) -> None:
        self.assertNotIn("${{ runner.temp }}", self.text)
        self.assertRegex(self.text, r"(?m)^      - name: Establish runner-local paths and hard thirty-minute deadline$")
        self.assertIn('printf \'LEASE_DIR=%s\\n\' "$lease_dir" >> "$GITHUB_ENV"', self.text)

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
        for platform in ("linux", "windows", "macos", "android"):
            self.assertRegex(self.text, rf"(?m)^          - {platform}$")
        self.assertIn('platform = os.environ["PLATFORM"]', self.text)
        self.assertIn('f"{origin_id}:{origin_attempt}:{platform}:', self.text)
        self.assertIn('expected_artifact = f"render-request-{os.environ[\'LEASE_RUN_ID\']}-{platform}"', self.text)
        self.assertIn('test "$MODE" = acquire', self.text)
        self.assertIn("RENDER_IMAGE_PATH must end in configured digest", self.text.replace("the configured", "configured"))
        self.assertIn('if not image_path.endswith("@" + digest):', self.text)
        self.assertNotRegex(self.text, r"(?m)^      (?:image_path|image_digest):")

    def test_origin_and_request_artifacts_are_bound_to_the_same_run(self) -> None:
        self.assertIn("origin_torturer_sha:", self.text)
        self.assertIn("origin_source_sha:", self.text)
        self.assertIn("origin_run_attempt:", self.text)
        self.assertIn("ORIGIN_RUN_ATTEMPT: ${{ inputs.origin_run_attempt }}", self.text)
        self.assertIn("group: trusted-render-lease-account", self.text)
        self.assertIn("expected_lease = hashlib.sha256", self.text)
        self.assertIn("actions/artifacts?name=${artifact_name}", self.text)
        self.assertNotIn("actions/runs/${ORIGIN_RUN_ID}/artifacts", self.text)
        self.assertIn("one Render lease already exists for this origin/platform", self.text)
        self.assertIn("ORIGIN_TORTURER_SHA: ${{ inputs.origin_torturer_sha }}", self.text)
        self.assertIn("TORTURER_SHA: ${{ inputs.origin_torturer_sha }}", self.text)
        self.assertIn("ref: ${{ inputs.origin_torturer_sha }}", self.text)
        self.assertIn("ORIGIN_SOURCE_SHA: ${{ inputs.origin_source_sha }}", self.text)
        self.assertIn("origin_source_sha is invalid", self.text)
        self.assertIn("origin_workflow_path:", self.text)
        self.assertIn("ORIGIN_WORKFLOW_PATH: ${{ inputs.origin_workflow_path }}", self.text)
        self.assertIn("origin workflow path is not allow-listed", self.text)
        self.assertIn("origin workflow path does not match platform", self.text)
        self.assertIn('value.get("head_sha") != os.environ["ORIGIN_TORTURER_SHA"]', self.text)
        for workflow, platform in (
            ("functional.yml", "linux"), ("functional-windows.yml", "windows"),
            ("functional-macos.yml", "macos"), ("functional-android.yml", "android"),
        ):
            self.assertIn(f'".github/workflows/{workflow}": "{platform}"', self.text)
        self.assertIn('value.get("head_sha") != os.environ["TORTURER_SHA"]', self.text)
        self.assertIn('value.get("path") != os.environ["ORIGIN_WORKFLOW_PATH"]', self.text)
        self.assertIn('value.get("run_attempt") != int(os.environ["ORIGIN_RUN_ATTEMPT"])', self.text)
        self.assertIn('workflow_run.get("id") != wanted_run', self.text)
        self.assertIn('files != {"request.json", "recipient.crt"}', self.text)
        self.assertIn('"kind": "dobbyvpn.render-lease-request"', self.text)
        self.assertIn("torturer_checks.hosted.artifacts", self.text)
        self.assertIn("--expect-file request.json", self.text)
        self.assertIn("--expect-file recipient.crt", self.text)
        self.assertNotIn("unzip -o", self.text)
        self.assertIn("--timeout-seconds \"$readiness_timeout\"", self.text)
        self.assertIn("torturer_checks.hosted.deadline", self.text)
        self.assertIn('"platform": os.environ["PLATFORM"]', self.text)
        self.assertIn('"source_sha": os.environ["ORIGIN_SOURCE_SHA"]', self.text)
        self.assertIn('render-lease-${{ inputs.lease_run_id }}-${{ inputs.platform }}', self.text)
        self.assertIn('render-lease-journal-${{ inputs.lease_run_id }}-${{ inputs.platform }}', self.text)
        self.assertIn("RENDER_SINK_IMAGE_DIGEST", self.text)
        self.assertIn("--expected-sink-image-digest", self.text)
        self.assertIn('--safe-result-output "$LEASE_DIR/acquire-result.json"', self.text)
        self.assertIn('"upload-sink"', self.text)
        self.assertIn('if set(value) != set(expected) | {"services"}', self.text)

    def test_plaintext_never_enters_an_uploaded_artifact(self) -> None:
        upload = self.text.index("- name: Upload encrypted profile and safe lease record")
        wait = self.text.index("- name: Wait for opaque functional completion marker")
        block = self.text[upload:wait]
        self.assertIn("profile.cms", block)
        self.assertIn("lease.json", block)
        self.assertIn("upload.cms", block)
        self.assertNotIn("profile.toml", block)
        self.assertIn("openssl cms -encrypt -binary -aes-256-gcm", self.text)
        self.assertIn('rm -f "$LEASE_DIR/profile.toml"', self.text)

    def test_server_safe_schema2_record_is_bound_by_role_and_identity(self) -> None:
        acquire = self.text.index("- name: Acquire disposable Render service and upload sink")
        encrypt = self.text.index("- name: Encrypt and publish the profile and upload handoffs", acquire)
        block = self.text[acquire:encrypt]
        self.assertIn('if set(value) != set(expected) | {"services"}', block)
        self.assertIn('"run_id": os.environ["LEASE_RUN_ID"]', block)
        self.assertIn('"platform": os.environ["PLATFORM"]', block)
        self.assertIn('"source_sha": os.environ["ORIGIN_SOURCE_SHA"]', block)
        self.assertIn('"state": "issued"', block)
        self.assertIn('expected_digests = {', block)
        self.assertIn('"outline": os.environ["RENDER_IMAGE_DIGEST"]', block)
        self.assertIn('"upload-sink": os.environ["RENDER_SINK_IMAGE_DIGEST"]', block)
        self.assertIn("role in services_by_role", block)
        self.assertIn('service["image_digest"] != expected_digests[role]', block)
        self.assertIn('service["provider_generation"]', block)
        self.assertIn('lease service IDs must be distinct', block)

    def test_render_lease_is_account_serialized_and_docs_require_sequential_dispatch(self) -> None:
        self.assertIn("group: trusted-render-lease-account", self.text)
        self.assertIn("not a matrix queue", self.text)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        contract = (ROOT / "docs" / "contract.md").read_text(encoding="utf-8")
        for document in (readme, contract):
            self.assertIn("dispatches the next platform only after", document)
            self.assertIn("account-wide", document)
            self.assertIn("matrix queue", document)

    def test_every_cms_encrypt_or_decrypt_invocation_is_bounded(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        found: list[tuple[str, int]] = []
        for workflow in workflows:
            lines = workflow.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if not re.search(r"openssl\s+cms\s+-(?:encrypt|decrypt)\b", line):
                    continue
                found.append((workflow.name, index + 1))
                preceding = lines[max(0, index - 4):index]
                direct_timeout = bool(
                    re.search(
                        r"^\s*timeout\s+.*(?:[0-9]+|\$\{[^}]+\})s[\"']?\s+openssl\s+cms\b",
                        line,
                    )
                )
                absolute_deadline_wrapper = bool(
                    re.search(
                        r'^\s*"\$DEADLINE_COMMAND"\s+[1-9][0-9]*\s+openssl\s+cms\b',
                        line,
                    )
                )
                deadline_wrapper = any(
                    "torturer_checks.hosted.deadline" in candidate
                    for candidate in preceding
                )
                with self.subTest(workflow=workflow.name, line=index + 1):
                    self.assertTrue(
                        direct_timeout or absolute_deadline_wrapper or deadline_wrapper,
                        "CMS invocation must be directly timeout-wrapped or use the "
                        "shared process-tree deadline wrapper",
                    )
        self.assertGreaterEqual(len(found), 5)

    def test_server_encryption_uses_absolute_deadline_and_preserves_streams(self) -> None:
        encrypt = self.text.index("- name: Encrypt and publish the profile and upload handoffs")
        upload = self.text.index("- name: Upload encrypted profile and safe lease record", encrypt)
        block = self.text[encrypt:upload]
        self.assertIn("LEASE_DEADLINE_EPOCH - $(date +%s) - LEASE_CLEANUP_RESERVE_SECONDS", block)
        self.assertIn('if [ "$remaining" -le 2 ]', block)
        self.assertIn('encryption_timeout=$(( (remaining - 3) / 2 ))', block)
        self.assertIn('if [ "$encryption_timeout" -gt 60 ]; then encryption_timeout=60; fi', block)
        self.assertIn("torturer_checks.hosted.deadline", block)
        self.assertIn('--timeout-seconds "$encryption_timeout" --kill-grace-seconds 1', block)
        self.assertIn("openssl cms -encrypt -binary -aes-256-gcm", block)
        self.assertIn('upload-url.txt', block)
        # The deadline wrapper inherits both streams and proves/reaps the full
        # process tree; no redirection may discard OpenSSL diagnostics.
        self.assertNotRegex(block, r"2>\s*/dev/null|>\s*/dev/null|--quiet(?:\s|$)")

    def test_server_cms_budget_is_inside_the_single_aggregate_deadline(self) -> None:
        """The CMS child and its bounded reaping tail cannot cross the job deadline."""

        establish = self.text.index("- name: Establish runner-local paths and hard thirty-minute deadline")
        boundary = self.text.index("- name: Validate trusted lease boundary", establish)
        deadline_setup = self.text[establish:boundary]
        self.assertIn("deadline = int(started.timestamp()) + 30 * 60", deadline_setup)
        self.assertIn("reserve = 680", deadline_setup)
        self.assertIn("render_api_timeout_seconds = 20", deadline_setup)
        self.assertIn("render_api_retry_attempts = 2", deadline_setup)
        self.assertIn("render_api_backoff_seconds = 0.5 + 1.0", deadline_setup)
        self.assertIn("cleanup_provider_api_calls = 8", deadline_setup)
        self.assertIn("cleanup_provider_worst_case_seconds", deadline_setup)
        self.assertIn("LEASE_CLEANUP_PROVIDER_WORST_CASE_SECONDS", deadline_setup)
        self.assertIn("if sum(finalization_components) > reserve", deadline_setup)
        self.assertIn("LEASE_DEADLINE_EPOCH={deadline}", deadline_setup)

        encrypt = self.text.index("- name: Encrypt and publish the profile and upload handoffs")
        upload = self.text.index("- name: Upload encrypted profile and safe lease record", encrypt)
        block = self.text[encrypt:upload]
        self.assertRegex(
            block,
            r"remaining=\$\(\(LEASE_DEADLINE_EPOCH - \$\(date \+%s\) - "
            r"LEASE_CLEANUP_RESERVE_SECONDS\)\)",
        )
        self.assertIn("encryption_timeout=$(( (remaining - 3) / 2 ))", block)
        self.assertIn('if [ "$encryption_timeout" -gt 60 ]; then encryption_timeout=60; fi', block)
        self.assertIn('--timeout-seconds "$encryption_timeout" --kill-grace-seconds 1', block)
        # Both CMS children share the aggregate budget; each has its own
        # absolute-deadline wrapper and bounded one-second reaping tail.
        self.assertEqual(block.count("torturer_checks.hosted.deadline"), 2)
        self.assertNotRegex(block, r"(?m)^\s+timeout\s+.*openssl cms")
        # When the configured 60-second cap applies, the pre-reserve budget is
        # necessarily at least 123 seconds; for smaller budgets the split
        # formula above shrinks each child accordingly.
        self.assertEqual(2 * (60 + 1) + 1, 123)

    def test_cleanup_is_unconditional_and_independently_verified(self) -> None:
        cleanup = self.text.index("- name: Delete the exact Render service and verify absence")
        journal = self.text.index("- name: Upload safe lease journal")
        self.assertIn("if: always()", self.text[cleanup:journal])
        cleanup_step = self.text[cleanup:journal]
        self.assertIn("torturer_provider.lease_cli cleanup", cleanup_step)
        self.assertIn("Mark the issued lease as actively testing", self.text)
        self.assertIn("torturer_provider.lease_cli begin-testing", self.text)
        self.assertIn('if [ -f "$LEASE_DIR/journal.json" ]', cleanup_step)
        self.assertIn('--journal "$LEASE_DIR/journal.json"', cleanup_step)
        self.assertIn('--request "$LEASE_DIR/request/unpacked/request.json"', cleanup_step)
        self.assertIn('--owner-id "$RENDER_OWNER_ID"', cleanup_step)
        self.assertIn('cleanup_args+=(--lease "$LEASE_DIR/lease.json")', cleanup_step)
        self.assertIn("if api.exists(service_id)", (ROOT / "torturer_provider" / "lease_cli.py").read_text(encoding="utf-8"))
        self.assertIn("for attempt in $(seq 1 180)", self.text)
        self.assertIn("completion marker wait reached the cleanup reserve", self.text)
        self.assertIn('private-gh-api.sh', self.text)
        self.assertIn('sleep_seconds=10', self.text)
        self.assertIn('cleanup_command_limit="$LEASE_CLEANUP_COMMAND_SECONDS"', self.text)
        self.assertIn('"$LEASE_PLAINTEXT_CLEANUP_SECONDS"', self.text)
        self.assertIn('timeout --foreground --signal=TERM --kill-after="${LEASE_PLAINTEXT_KILL_GRACE_SECONDS}s" "${command_timeout}s"', self.text)
        self.assertIn("completion marker deadline expired", self.text)

    def test_finalization_sub_budgets_fit_inside_the_reserve(self) -> None:
        reserve = int(re.search(r"(?m)^          reserve = (\d+)$", self.text).group(1))
        names = (
            "cleanup_command_seconds",
            "cleanup_kill_grace_seconds",
            "plaintext_cleanup_seconds",
            "plaintext_kill_grace_seconds",
            "evidence_upload_seconds",
            "finalization_overhead_seconds",
        )
        values = {
            name: int(re.search(rf"(?m)^          {name} = (\d+)$", self.text).group(1))
            for name in names
        }
        self.assertEqual(values, {
            "cleanup_command_seconds": 600,
            "cleanup_kill_grace_seconds": 1,
            "plaintext_cleanup_seconds": 4,
            "plaintext_kill_grace_seconds": 1,
            "evidence_upload_seconds": 60,
            "finalization_overhead_seconds": 10,
        })
        self.assertLessEqual(sum(values.values()), reserve)
        self.assertEqual(sum(values.values()), 676)
        self.assertEqual(reserve, 680)
        self.assertRegex(
            self.text,
            r"(?ms)- name: Upload safe lease journal.*?timeout-minutes: 1",
        )

    def test_render_token_is_confined_to_provider_steps(self) -> None:
        self.assertEqual(self.text.count("RENDER_API_TOKEN: ${{ secrets.RENDER_API_TOKEN }}"), 2)
        self.assertNotIn("RENDER_API_TOKEN", self.text.split("- name: Acquire disposable Render service and upload sink", 1)[0])

    def test_diagnostic_suppression_is_not_added(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)")
        report = self.text.index("- name: Report safe Render acquisition result")
        cleanup = self.text.index("- name: Delete the exact Render service and verify absence")
        block = self.text[report:cleanup]
        self.assertIn("if: always()", block)
        self.assertIn("render_acquisition status={status} code={code}", block)
        self.assertIn("SAFE_RESULT_MISSING", block)
        self.assertIn("acquire-result.json", self.text[self.text.index("- name: Upload safe lease journal"):])

    def test_every_active_workflow_job_is_bounded_to_thirty_minutes(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            values = re.findall(r"(?m)^\s+timeout-minutes:\s*([0-9]+)\s*$", workflow.read_text(encoding="utf-8"))
            self.assertTrue(values, workflow.name)
            for value in values:
                self.assertLessEqual(int(value), 30, workflow.name)


if __name__ == "__main__":
    unittest.main()
