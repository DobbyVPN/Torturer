"""Policy tests for the isolated trusted Windows functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from .lease_validator_helpers import adversarial_leases, run_validator, valid_lease


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
        self.assertIn('--lane-timeout-seconds "$remaining"', self.text)
        self.assertIn("for attempt in $(seq 1 360); do", self.text)
        self.assertIn("if int(datetime.datetime.now(datetime.timezone.utc).timestamp()) >= deadline:", self.text)
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
        verify = client.index("- name: Verify trusted Torturer checkout and candidate closure")
        prepare = client.index("- name: Create ephemeral recipient and opaque Render lease request")
        preflight_start = client.index("- name: Start exact Windows preflight candidate")
        preflight_stop = client.index("- name: Stop Windows preflight candidate before Render handoff")
        upload = client.index("- name: Upload public certificate and opaque request")
        wait = client.index("- name: Wait for and download exact encrypted Render lease response")
        decrypt = client.index("- name: Validate and decrypt encrypted profile")
        functional_start = client.index("- name: Start exact Windows functional candidate")
        run = client.index("- name: Run canonical Windows functional scenarios")
        cleanup = client.index("- name: Stop exact Windows service and verify cleanup")
        self.assertLess(verify, prepare)
        self.assertLess(prepare, preflight_start)
        self.assertLess(preflight_start, preflight_stop)
        self.assertLess(preflight_stop, upload)
        self.assertLess(upload, wait)
        self.assertLess(wait, decrypt)
        self.assertLess(decrypt, functional_start)
        self.assertLess(functional_start, run)
        self.assertLess(run, cleanup)

        self.assertIn("Prove Windows client runner architecture and elevation", client)
        self.assertIn("--source-sha \"$SOURCE_SHA\"", client)
        before_candidate = client[:preflight_start]
        preflight_execution = client[preflight_start:preflight_stop]
        preflight_handoff = client[preflight_stop:upload]
        token_region = client[upload:decrypt]
        functional = client[functional_start:cleanup]
        after_decrypt = client[decrypt:]
        self.assertIn("GH_TOKEN", before_candidate)
        self.assertIn("github.token", before_candidate)
        self.assertNotIn("GH_TOKEN", preflight_execution)
        self.assertNotIn("github.token", preflight_execution)
        self.assertNotIn("GH_TOKEN", preflight_handoff)
        self.assertNotIn("github.token", preflight_handoff)
        self.assertIn("if: always()", preflight_handoff)
        self.assertIn("preflight_service_stop_verified=true", preflight_handoff)
        self.assertIn(
            "python -m torturer_checks.hosted.finalize_windows_service",
            preflight_handoff,
        )
        self.assertNotIn('python - "$service_identity_file"', preflight_handoff)
        self.assertIn("preflight-controller-fallback", preflight_handoff)
        self.assertNotIn("taskkill", preflight_handoff.lower())
        self.assertIn("PREFLIGHT_SERVICE_IDENTITY_FILE", preflight_handoff)
        self.assertIn("GH_TOKEN", token_region)
        self.assertIn("github.token", token_region)
        for forbidden in ("windows_grpcvpnserver.exe", "macos_grpcvpnserver", "dobby-cli.exe", "Start-Process", "taskkill.exe", "PREFLIGHT_SERVICE_PID"):
            self.assertNotIn(forbidden, token_region)
        self.assertNotIn("GH_TOKEN", functional)
        self.assertNotIn("github.token", functional)
        self.assertNotIn("GH_TOKEN", after_decrypt)
        self.assertNotIn("github.token", after_decrypt)
        self.assertIn("hosted.deadline", functional)
        self.assertIn("--platform windows", functional)
        self.assertIn("--service-socket", functional)
        self.assertIn('--service-identity-file "$SERVICE_IDENTITY_FILE"', functional)
        self.assertIn("--candidate-manifest \"$GITHUB_WORKSPACE/candidate/manifest.json\"", functional)
        self.assertNotRegex(functional, r"--artifact(?:\s|=)")
        self.assertNotIn("--download-url", functional)
        self.assertNotIn("proof.ovh.net", functional)
        self.assertNotIn("speed.cloudflare.com/__down?", functional)
        self.assertIn('upload_url="$(cat "$HANDOFF_DIR/upload-url.txt")"', functional)
        self.assertIn('--upload-url "$upload_url"', functional)
        self.assertIn("SERVER_SINK_IMAGE_DIGEST", client)
        self.assertIn("--expect-file upload.cms", client)
        self.assertIn('test -f "$LEASE_RESPONSE_DIR/upload.cms"', client)
        self.assertIn('"schema": 2', client)
        self.assertIn('{"outline", "upload-sink"}', client)
        self.assertIn('"provider_generation"', client)
        self.assertIn('"url", "path", "password", "secret"', client)

    def test_preflight_startup_bounds_every_candidate_probe_and_preserves_cleanup(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        start = client.index("- name: Start exact Windows preflight candidate")
        stop = client.index("- name: Stop Windows preflight candidate before Render handoff")
        preflight = client[start:stop]

        self.assertIn("PREFLIGHT_MAX_SECONDS=300", preflight)
        self.assertIn("PREFLIGHT_CLEANUP_RESERVE_SECONDS=180", preflight)
        self.assertIn("PREFLIGHT_PROBE_TIMEOUT_SECONDS=10", preflight)
        self.assertIn("preflight_deadline_epoch", preflight)
        self.assertIn("run_preflight_probe()", preflight)
        self.assertGreaterEqual(
            preflight.count("timeout --foreground --signal=TERM --kill-after=1s"),
            2,
        )
        self.assertRegex(
            preflight,
            r'run_preflight_probe "service-process-\$\{attempt\}" "\$probe_log" \\\n'
            r'\s+powershell\.exe .*Get-Process',
        )
        self.assertRegex(
            preflight,
            r'run_preflight_probe "control-port-\$\{attempt\}" "\$network_probe_log" \\\n'
            r'\s+powershell\.exe .*Test-NetConnection',
        )
        self.assertRegex(
            preflight,
            r'run_preflight_probe control-status "\$status_log" \\\n'
            r'\s+"\$GITHUB_WORKSPACE/candidate/dobby-cli\.exe" status',
        )
        self.assertIn(
            "preflight_service_readiness=failed code=SERVICE_PROBE_TIMEOUT",
            preflight,
        )
        self.assertIn(
            "preflight_service_readiness=failed code=CONTROL_PORT_PROBE_TIMEOUT",
            preflight,
        )
        self.assertIn(
            "preflight_control_status=failed code=CLI_STATUS_TIMEOUT",
            preflight,
        )
        self.assertIn("PREFLIGHT_SERVICE_PID_FILE", preflight)
        self.assertIn(
            "WriteAllText($env:DOBBYVPN_WINDOWS_SERVICE_PID_FILE",
            preflight,
        )
        self.assertIn("emit_private_evidence preflight-launch", preflight)

    def test_native_launch_uses_bounded_file_handoff_not_bash_pipe_capture(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        preflight_start = client.index("- name: Start exact Windows preflight candidate")
        preflight_stop = client.index("- name: Stop Windows preflight candidate before Render handoff")
        functional_start = client.index("- name: Start exact Windows functional candidate")
        run_start = client.index("- name: Run canonical Windows functional scenarios")
        preflight = client[preflight_start:preflight_stop]
        functional = client[functional_start:run_start]

        for launch in (preflight, functional):
            # A native child must not be placed inside Bash command
            # substitution or a background PowerShell job: either can outlive
            # the shell and strand the candidate without a cleanup handoff.
            self.assertNotRegex(launch, r"service_pid=\"\$\(.*powershell\.exe")
            self.assertNotIn("Start-Job", launch)
            self.assertNotIn("Wait-Job", launch)
            self.assertNotIn("Stop-Job", launch)
            self.assertIn('timeout --signal=TERM --kill-after=1s "${launch_watchdog_timeout}s"', launch)
            self.assertIn('> "$launch_log" 2>&1 || launch_status=$?', launch)
            self.assertIn("WriteAllText($env:DOBBYVPN_WINDOWS_SERVICE_PID_FILE", launch)
            self.assertIn("System.Text.Encoding]::ASCII", launch)
            self.assertNotIn("[Environment]::NewLine", launch)
            self.assertIn("SERVICE_IDENTITY_FILE", launch)
            self.assertIn("candidate-discovery", launch)
            self.assertIn("service_pid=\"\"", launch)
            self.assertIn("tr -d '\\r\\n'", launch)
            self.assertIn("emit_private_evidence", launch)
            self.assertIn("LAUNCH_TIMEOUT", launch)

        self.assertIn("PREFLIGHT_SERVICE_PID_FILE", preflight)
        self.assertIn("SERVICE_PID_FILE", functional)
        self.assertIn("launch_watchdog_timeout=$((launch_timeout + 3))", preflight)
        self.assertIn("launch_watchdog_timeout=$((launch_timeout + 3))", functional)
        self.assertIn('emit_private_evidence preflight-service-log "$service_log"', preflight)
        self.assertIn('emit_private_evidence preflight-service-error "$service_err"', preflight)
        self.assertIn('emit_private_display preflight-launch "$launch_log"', preflight)
        self.assertIn('emit_private_evidence service-log "$service_log"', functional)
        self.assertIn('emit_private_evidence service-error "$service_err"', functional)
        self.assertIn('emit_private_display service-launch "$launch_log"', functional)
        self.assertLess(
            preflight.index('printf \'PREFLIGHT_SERVICE_PID_FILE='),
            preflight.index('powershell.exe -NoLogo -NoProfile -NonInteractive -Command'),
        )
        self.assertLess(
            functional.index('printf \'SERVICE_PID_FILE='),
            functional.index('powershell.exe -NoLogo -NoProfile -NonInteractive -Command'),
        )

    def test_windows_client_paths_are_private_and_process_identity_is_required(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn('private_root="$RUNNER_TEMP/dobbyvpn-private"', client)
        self.assertIn('test ! -e "$private_root" && test ! -L "$private_root"', client)
        self.assertIn('mkdir "$private_root"', client)
        self.assertIn('mkdir "$handoff" "$service"', client)
        self.assertIn('chmod 700 "$private_root" "$handoff" "$service"', client)
        self.assertIn("WindowsIdentity]::GetCurrent().User.Value", client)
        self.assertIn("SetAccessRuleProtection($true,$false)", client)
        self.assertIn("private ACL verification failed", client)
        self.assertIn("SERVICE_IDENTITY_FILE", client)
        self.assertIn("PREFLIGHT_SERVICE_IDENTITY_FILE", client)
        self.assertIn("CreationDate.ToUniversalTime().Ticks", client)
        self.assertIn("fallback_state=path-mismatch", client)
        self.assertIn("fallback_state=identity-mismatch", client)
        self.assertIn("PREFLIGHT_SERVICE_LAUNCH_STARTED_EPOCH", client)
        self.assertIn("SERVICE_LAUNCH_STARTED_EPOCH", client)
        self.assertGreaterEqual(client.count("FromUnixTimeSeconds([int64]$args[2])"), 2)
        self.assertIn("cleanup_deadline_epoch=$((RUN_DEADLINE_EPOCH - 60))", client)
        self.assertIn("launch_remaining=$((RUN_DEADLINE_EPOCH - $(date +%s) - 60))", client)
        self.assertGreaterEqual(client.count('timeout --foreground --signal=TERM --kill-after=1s "${probe_timeout}s"'), 1)
        self.assertIn("readiness_reserve_seconds=180", client)
        self.assertIn('readiness_remaining=$((RUN_DEADLINE_EPOCH - $(date +%s) - readiness_reserve_seconds))', client)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=1s "${status_timeout}s"', client)
        self.assertIn('discovery_remaining=$((RUN_DEADLINE_EPOCH - $(date +%s) - 60 - 1))', client)
        self.assertGreaterEqual(client.count('timeout --foreground --signal=TERM --kill-after=1s "${fallback_timeout}s"'), 2)

    def test_cleanup_keeps_authoritative_identity_when_pid_file_is_stale(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        for begin, end in (
            (
                "- name: Stop Windows preflight candidate before Render handoff",
                "- name: Upload public certificate and opaque request",
            ),
            (
                "- name: Stop exact Windows service and verify cleanup",
                "- name: Remove plaintext handoff material and prepare completion marker",
            ),
        ):
            cleanup = client[client.index(begin):client.index(end)]
            self.assertIn("service_identity_file=", cleanup)
            self.assertIn("service_identity=\"$(tr -d", cleanup)
            self.assertIn("service_pid=\"${service_identity%%|*}\"", cleanup)
            self.assertIn(
                "python -m torturer_checks.hosted.finalize_windows_service",
                cleanup,
            )
            self.assertIn("--service-identity-file \"$service_identity_file\"", cleanup)
            self.assertIn("--service-binary \"$service_binary\"", cleanup)
            self.assertIn("--raw-log-dir \"$controller_raw\"", cleanup)
            self.assertIn("--timeout-seconds \"$controller_timeout\"", cleanup)
            self.assertNotIn('python - "$service_identity_file"', cleanup)
            self.assertNotIn("service_pid_file=", cleanup)
            self.assertNotIn("candidate-discovery", cleanup)
            self.assertNotIn("taskkill", cleanup.lower())

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
        marker = self.text.index("id: post_lane_marker_prepare")
        remove = self.text.index("- name: Remove plaintext handoff material and prepare completion marker")
        self.assertLess(remove, marker)
        marker_upload = self.text.index("- name: Upload opaque Windows completion marker")
        self.assertLess(marker, marker_upload)
        self.assertLess(stop, remove)
        self.assertLess(marker_upload, result)
        self.assertLess(stop, result)
        self.assertIn("if: always()", self.text[remove:marker_upload])
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:])
        self.assertIn(
            "python -m torturer_checks.hosted.finalize_windows_service",
            self.text[stop:result],
        )
        self.assertIn("Stop-Process", self.text[stop:result])
        self.assertNotIn("taskkill", self.text[stop:result].lower())
        uploads = self.text[result:remove]
        self.assertNotIn("profile.cms", uploads)
        self.assertNotIn("upload.cms", uploads)
        self.assertNotIn("upload-url.txt", uploads)
        self.assertNotIn("profile.toml", uploads)
        self.assertIn("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/upload-url.txt\" \"$HANDOFF_DIR/recipient.key\"", self.text)

    def test_no_diagnostic_suppression(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)|SilentlyContinue")
        self.assertNotIn("-InformationLevel Quiet", self.text)
        self.assertIn("Prove Windows runner architecture and elevation", self.text)
        self.assertIn("is_administrator=", self.text)
        self.assertIn("control_token_ready=1", self.text)
        self.assertIn("emit_private_evidence", self.text)
        self.assertGreaterEqual(self.text.count("umask 077"), 4)
        self.assertNotIn('cat "$service_log"', self.text)
        self.assertNotIn('cat "$service_err"', self.text)
        self.assertNotIn('| tee "$SERVICE_DIR/preflight-control-status.raw.log"', self.text)
        self.assertNotIn('| tee "$SERVICE_DIR/control-status.raw.log"', self.text)
        self.assertNotIn("taskkill", self.text.lower())
        self.assertIn("Stop-Process -Id $processId -Force", self.text)
        self.assertIn("emit_private_evidence preflight-controller-fallback", self.text)
        self.assertIn("emit_private_evidence controller-fallback", self.text)
        self.assertGreaterEqual(
            self.text.count("state=retained-runner-private"),
            2,
        )
        self.assertNotIn('diagnostic_display label=%s text=%s', self.text)
        self.assertNotIn('read_bytes().decode("utf-8", "replace")', self.text)
        self.assertNotIn("private_acl_path=", self.text)
        self.assertNotIn(' sid=" + $sid', self.text)
        self.assertIn("private_acl_verified_count=", self.text)

    def test_windows_cleanup_uses_trusted_controller_and_fail_closed_fallback(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        for begin, end in (
            (
                "- name: Stop Windows preflight candidate before Render handoff",
                "- name: Upload public certificate and opaque request",
            ),
            (
                "- name: Stop exact Windows service and verify cleanup",
                "- name: Remove plaintext handoff material and prepare completion marker",
            ),
        ):
            cleanup = client[client.index(begin):client.index(end)]
            self.assertIn(
                'env PYTHONPATH="$GITHUB_WORKSPACE/torturer" python -m '
                "torturer_checks.hosted.finalize_windows_service",
                cleanup,
            )
            self.assertIn("--service-identity-file \"$service_identity_file\"", cleanup)
            self.assertIn("--service-binary \"$service_binary\"", cleanup)
            self.assertIn("--raw-log-dir \"$controller_raw\"", cleanup)
            self.assertIn("--timeout-seconds \"$controller_timeout\"", cleanup)
            self.assertNotIn("controller._terminate_initial_external", cleanup)
            self.assertNotIn('python - "$service_identity_file"', cleanup)
            self.assertIn("Stop-Process -Id $processId -Force", cleanup)
            self.assertIn("tree-unproven", cleanup)
            self.assertIn("exit 1", cleanup)
            self.assertNotIn("taskkill", cleanup.lower())
            self.assertNotIn(" /T", cleanup)

        self.assertLess(
            client.index("- name: Verify trusted Torturer checkout and candidate closure"),
            client.index("- name: Stop exact Windows service and verify cleanup"),
        )

    def test_completed_hosted_controller_absence_is_the_only_clean_fallback(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        cleanup = client[
            client.index("- name: Stop exact Windows service and verify cleanup"):
            client.index("- name: Remove plaintext handoff material and prepare completion marker")
        ]
        allow = cleanup.index('allow_already_gone=0')
        trusted_outcome = cleanup.index('[ "$FUNCTIONAL_OUTCOME" = "success" ]', allow)
        absent_proof = cleanup.index('fallback_state=leader-absent trusted-controller-result', trusted_outcome)
        success = cleanup.index(
            'if [ "$allow_already_gone" -eq 1 ] && [ "$fallback_status" -eq 0 ]; then',
            absent_proof,
        )
        failure = cleanup.index(
            "service_cleanup=failed code=CONTROLLER_FINALIZER",
            success,
        )
        self.assertLess(allow, trusted_outcome)
        self.assertLess(trusted_outcome, absent_proof)
        self.assertLess(absent_proof, success)
        self.assertLess(success, failure)
        self.assertIn("FUNCTIONAL_OUTCOME: ${{ steps.functional.outcome }}", cleanup)
        self.assertNotIn("RESULT_PATH", cleanup[allow:success])
        self.assertNotIn("grep -Fqx", cleanup)
        self.assertIn(
            "service_stop_verified=true method=completed-hosted-controller tree=proven",
            cleanup[success:failure],
        )

        preflight = client[
            client.index("- name: Stop Windows preflight candidate before Render handoff"):
            client.index("- name: Upload public certificate and opaque request")
        ]
        self.assertNotIn("allow_already_gone", preflight)
        self.assertNotIn("trusted-controller-result", preflight)

    def test_shared_finalizer_is_the_only_workflow_controller_entrypoint(self) -> None:
        finalizer = (ROOT / "torturer_checks" / "hosted" / "finalize_windows_service.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("controller.finalize_initial_service", finalizer)
        self.assertIn("_ensure_owner_only_directory", finalizer)
        self.assertIn("read_windows_service_identity", finalizer)
        self.assertIn("expected_initial_identity=identity", finalizer)
        self.assertNotIn("_terminate_initial_external", finalizer)
        self.assertNotIn("taskkill", finalizer.lower())

    def test_schema_two_validator_rejects_identity_binding_and_private_field_attacks(self) -> None:
        self.assertEqual(run_validator(self.text, valid_lease("windows")).returncode, 0)
        for label, lease in adversarial_leases("windows").items():
            with self.subTest(label=label):
                self.assertNotEqual(run_validator(self.text, lease).returncode, 0)

    def test_expired_and_short_budgets_fail_closed(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn('if [ "$readiness_remaining" -le 0 ]; then', client)
        self.assertIn('if [ "$discovery_remaining" -le 0 ]; then', client)
        self.assertIn('if [ "$discovery_timeout" -gt "$discovery_remaining" ]; then', client)
        self.assertIn('if [ "$status_timeout" -le 0 ]; then', client)
        self.assertIn('if [ "$openssl_timeout" -le 0 ]; then', client)
        self.assertIn('if [ "$transfer_timeout" -le 0 ]; then', client)


if __name__ == "__main__":
    unittest.main()
