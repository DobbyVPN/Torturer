"""Policy tests for the isolated trusted macos functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from .lease_validator_helpers import adversarial_leases, run_validator, valid_lease


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "functional-macos.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class FunctionalMacOSWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_manual_macos_lane_has_hard_thirty_minute_client_bound(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^    runs-on: macos-15$")
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
        self.assertIn("Prove macOS runner architecture and elevation", build)
        self.assertIn("desktop_build.py libs --platform macos --arch arm64", build)
        self.assertIn("desktop_build.py app --platform macos --skip-libs", build)
        self.assertIn("sha256sum kmp_module/services/macos_grpcvpnserver kmp_module/services/dobby-cli", build)
        self.assertNotIn("wintun.dll", build)
        self.assertNotIn("dobby_bridge.dll", build)
        self.assertIn("candidate.py stage", build)
        self.assertIn("--platform macos --architecture arm64", build)
        self.assertIn("candidate-macos-${{ inputs.commit_sha }}", build)

    def test_client_verifies_provenance_before_candidate_execution(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn("candidate.py verify", client)
        verify = client.index("- name: Verify trusted Torturer checkout and candidate closure")
        prepare = client.index("- name: Create ephemeral recipient and opaque Render lease request")
        preflight_start = client.index("- name: Start exact macOS preflight candidate")
        preflight_stop = client.index("- name: Stop macOS preflight candidate before Render handoff")
        upload = client.index("- name: Upload public certificate and opaque request")
        wait = client.index("- name: Wait for and download exact encrypted Render lease response")
        decrypt = client.index("- name: Validate and decrypt encrypted profile")
        functional_start = client.index("- name: Start exact macOS functional candidate")
        run = client.index("- name: Run canonical macOS functional scenarios")
        cleanup = client.index("- name: Stop exact macOS service and verify cleanup")
        self.assertLess(verify, prepare)
        self.assertLess(prepare, preflight_start)
        self.assertLess(preflight_start, preflight_stop)
        self.assertLess(preflight_stop, upload)
        self.assertLess(upload, wait)
        self.assertLess(wait, decrypt)
        self.assertLess(decrypt, functional_start)
        self.assertLess(functional_start, run)
        self.assertLess(run, cleanup)

        self.assertIn("Prove macOS client runner architecture and elevation", client)
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
        self.assertIn('sudo -n kill -TERM "$service_pid"', preflight_handoff)
        self.assertIn("PREFLIGHT_SERVICE_CONTROL_SOCKET", preflight_handoff)
        self.assertIn('emit_private_evidence preflight-service-children "$children_snapshot"', preflight_handoff)
        self.assertIn('test "$children_count" -eq 0', preflight_handoff)
        self.assertIn("_MACOS_PROCESS_IDENTITY_SCRIPT", preflight_execution)
        self.assertIn("_parse_macos_process_identity", preflight_execution)
        self.assertIn('"native_start"', preflight_execution)
        self.assertIn("start_new_session=True", preflight_execution)
        self.assertIn('"pid=,pgid="', preflight_execution)
        self.assertIn("service_group=", preflight_execution)
        self.assertIn("process-group isolation proof", preflight_execution)
        self.assertNotIn("lstart=", preflight_handoff)
        self.assertIn("GH_TOKEN", token_region)
        self.assertIn("github.token", token_region)
        for forbidden in ("windows_grpcvpnserver.exe", "macos_grpcvpnserver", "dobby-cli", "Start-Process", "taskkill.exe", "PREFLIGHT_SERVICE_PID"):
            self.assertNotIn(forbidden, token_region)
        self.assertNotIn("GH_TOKEN", functional)
        self.assertNotIn("github.token", functional)
        self.assertNotIn("GH_TOKEN", after_decrypt)
        self.assertNotIn("github.token", after_decrypt)
        self.assertIn("hosted.deadline", functional)
        self.assertIn("--platform macos", functional)
        self.assertIn("--service-socket", functional)
        self.assertIn('--service-identity-file "$SERVICE_IDENTITY_FILE"', functional)
        self.assertIn("--candidate-manifest \"$GITHUB_WORKSPACE/candidate/manifest.json\"", functional)
        self.assertNotRegex(functional, r"--artifact(?:\s|=)")
        self.assertNotIn("--download-url", functional)
        self.assertNotIn("proof.ovh.net", functional)
        self.assertNotIn("speed.cloudflare.com/__down?", functional)
        self.assertIn('upload_url="$(cat "$HANDOFF_DIR/upload-url.txt")"', functional)
        self.assertIn('--upload-url "$upload_url"', functional)
        self.assertIn("TORTURER_HOSTED_DEADLINE_EVIDENCE_DIR=", functional)
        self.assertIn("TORTURER_HOSTED_DEADLINE_SUMMARY_PATH=", functional)
        self.assertIn('>> "$GITHUB_ENV"', functional)
        self.assertIn("--summary-output", functional)
        self.assertIn("FUNCTIONAL_STATUS=", functional)
        self.assertIn('route_remaining=$((RUN_DEADLINE_EPOCH - $(date +%s) - 120 - 1))', self.text)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=1s "${route_timeout}s" route -n get default', self.text)
        self.assertIn("readiness_reserve_seconds=180", functional)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=1s "${status_timeout}s"', functional)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=1s "${identity_probe_timeout}s"', functional)
        self.assertIn('"TMPDIR":', functional)
        self.assertIn('"DOBBY_LOG_PATH":', functional)
        self.assertIn("SERVICE_IDENTITY_FILE=", functional)
        self.assertIn("service.identity.json", functional)
        self.assertIn("_MACOS_PROCESS_IDENTITY_SCRIPT", functional)
        self.assertIn("_parse_macos_process_identity", functional)
        self.assertIn('"native_start"', functional)
        self.assertIn("start_new_session=True", functional)
        self.assertIn('"pid=,pgid="', functional)
        self.assertIn("service_group=", functional)
        self.assertIn("process-group isolation proof", functional)
        self.assertNotIn("lstart=", functional)
        self.assertIn("SERVER_SINK_IMAGE_DIGEST", client)
        self.assertIn("--expect-file upload.cms", client)
        self.assertIn('test -f "$LEASE_RESPONSE_DIR/upload.cms"', client)
        self.assertIn('"schema": 2', client)
        self.assertIn('{"outline", "upload-sink"}', client)
        self.assertIn('"provider_generation"', client)
        self.assertIn('"url", "path", "password", "secret"', client)

    def test_render_handoff_is_opaque_and_bound_to_macos_origin(self) -> None:
        self.assertIn("render-request-${lease_run_id}-${PLATFORM}", self.text)
        self.assertIn("render-lease-${LEASE_RUN_ID}-${PLATFORM}", self.text)
        self.assertIn("render-complete-${{ env.LEASE_RUN_ID }}-macos", self.text)
        self.assertIn("inputs[origin_workflow_path]=.github/workflows/functional-macos.yml", self.text)
        self.assertIn("profile.cms", self.text)
        self.assertIn("recipient.crt", self.text)
        self.assertIn("recipient.key", self.text)
        self.assertIn("profile.toml", self.text)
        self.assertIn("openssl cms -decrypt", self.text)

    def test_cleanup_and_completion_are_unconditional(self) -> None:
        stop = self.text.index("- name: Stop exact macOS service")
        retain = self.text.index("- name: Retain opaque macOS functional evidence after provider-release marker")
        restore = self.text.index("- name: Restore macOS default route")
        failure_evidence = self.text.index("- name: Upload safe macOS failure evidence")
        result = self.text.index("- name: Upload safe macOS functional result")
        marker = self.text.index("id: post_lane_marker_prepare")
        remove = self.text.index("- name: Remove plaintext handoff material and prepare completion marker")
        self.assertLess(stop, retain)
        self.assertLess(stop, restore)
        self.assertLess(remove, marker)
        marker_upload = self.text.index("- name: Upload opaque macOS completion marker")
        self.assertLess(restore, remove)
        self.assertLess(marker, marker_upload)
        self.assertLess(marker_upload, retain)
        self.assertLess(marker_upload, failure_evidence)
        self.assertLess(retain, failure_evidence)
        self.assertLess(failure_evidence, result)
        self.assertIn("if: always()", self.text[remove:marker_upload])
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:])
        self.assertIn("sudo -n kill -TERM", self.text[stop:result])
        self.assertIn("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/upload-url.txt\" \"$HANDOFF_DIR/recipient.key\"", self.text)
        self.assertIn("if: always()", self.text[retain:failure_evidence])
        self.assertIn("if: always()", self.text[failure_evidence:result])
        upload = self.text[failure_evidence:result]
        self.assertIn("macos-failure-evidence.json", upload)
        self.assertIn("functional-deadline-summary.json", upload)
        self.assertNotIn("service.raw.log", upload)
        self.assertNotIn("hosted-command-raw", upload)
        self.assertNotIn("profile.toml", upload)
        self.assertNotIn("profile.cms", upload)
        self.assertNotIn("upload.cms", upload)
        self.assertNotIn("upload-url.txt", upload)
        self.assertNotIn("recipient.key", upload)

    def test_no_diagnostic_suppression(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)|SilentlyContinue")
        self.assertIn("Prove macOS runner architecture and elevation", self.text)
        self.assertIn("sudo -n id", self.text)
        self.assertIn("control_socket_ready=1", self.text)
        self.assertIn("SERVICE_CONTROL_SOCKET=%s", self.text)
        self.assertIn("emit_private_evidence", self.text)

    def test_schema_two_validator_rejects_identity_binding_and_private_field_attacks(self) -> None:
        self.assertEqual(run_validator(self.text, valid_lease("macos")).returncode, 0)
        for label, lease in adversarial_leases("macos").items():
            with self.subTest(label=label):
                self.assertNotEqual(run_validator(self.text, lease).returncode, 0)

    def test_expired_and_short_budgets_fail_closed(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn('if [ "$readiness_remaining" -le 0 ]; then', client)
        self.assertIn('if [ "$route_remaining" -le 0 ]; then', client)
        self.assertIn('if [ "$route_timeout" -gt "$route_remaining" ]; then', client)
        self.assertIn('if [ "$status_timeout" -le 0 ]; then', client)
        self.assertIn('if [ "$openssl_timeout" -le 0 ]; then', client)
        self.assertIn('if [ "$transfer_timeout" -le 0 ]; then', client)
        self.assertGreaterEqual(self.text.count("umask 077"), 4)
        self.assertIn('private_root="$RUNNER_TEMP/dobbyvpn-private"', self.text)
        self.assertIn('handoff="$private_root/render-handoff"', self.text)
        self.assertIn('service="$private_root/service"', self.text)
        self.assertIn('diagnostics="$private_root/diagnostics"', self.text)
        self.assertIn('test ! -e "$private_root" && test ! -L "$private_root"', self.text)
        self.assertIn('mkdir "$private_root"', self.text)
        self.assertIn('mkdir "$handoff" "$service" "$diagnostics"', self.text)
        self.assertIn(
            'chmod 700 "$private_root" "$handoff" "$service" "$diagnostics"',
            self.text,
        )
        establish = self.text[
            self.text.index("- name: Establish runner-local paths"):
            self.text.index("- name: Prove macOS client runner architecture")
        ]
        self.assertNotIn('mkdir -p "$private_root"', establish)
        self.assertNotIn('$RUNNER_TEMP/dobbyvpn-render-handoff', establish)
        self.assertNotIn('$RUNNER_TEMP/dobbyvpn-service', establish)
        self.assertNotIn('$RUNNER_TEMP/dobbyvpn-diagnostics', establish)
        self.assertNotIn('cat "$service_log"', self.text)
        self.assertNotIn('cat "$service_err"', self.text)
        self.assertNotIn('| tee "$SERVICE_DIR/preflight-control-status.raw.log"', self.text)
        self.assertNotIn('| tee "$SERVICE_DIR/control-status.raw.log"', self.text)
        self.assertIn('ps -axo pid=,ppid=,command= > "$children_snapshot" 2>&1', self.text)
        self.assertIn('emit_private_evidence service-children "$children_snapshot"', self.text)

    def test_route_recovery_is_explicit_and_fail_closed(self) -> None:
        route = self.text[
            self.text.index("- name: Restore macOS default route"):
            self.text.index("- name: Upload safe macOS failure evidence")
        ]
        self.assertIn("torturer_checks.hosted.macos_route", route)
        self.assertIn("--confirmation-file", route)
        self.assertIn("--service-probe-file", route)
        self.assertIn('"not in table"', route)
        self.assertNotIn("reason=baseline-not-captured", route)
        self.assertIn('restore_status=0', route)
        self.assertIn('exit "$restore_status"', route)
        self.assertIn('emit_private_evidence macos-restore-default-route', route)
        self.assertIn('emit_private_evidence macos-service-death-probe', route)
        self.assertIn('--service-identity-file "$SERVICE_IDENTITY_FILE"', route)
        self.assertIn("identity_probe_remaining", self.text)
        self.assertIn("fallback_remaining", self.text)

    def test_macos_cleanup_rejects_legacy_identity_and_stale_pid_fallback(self) -> None:
        functional_start = self.text.index("- name: Start exact macOS functional candidate")
        cleanup = self.text[functional_start:self.text.index("- name: Restore macOS default route")]
        self.assertIn('set(value) != {"command", "native_start", "pid", "start"}', cleanup)
        self.assertIn("NATIVE_IDENTITY_UNAVAILABLE", cleanup)
        self.assertNotIn("ps -p \"$pid\" -o pid=,lstart=,command=", cleanup)
        self.assertNotIn("The legacy lstart", cleanup)


if __name__ == "__main__":
    unittest.main()
