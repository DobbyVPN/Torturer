"""Policy tests for the isolated trusted macos functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


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
        self.assertIn("--candidate-manifest \"$GITHUB_WORKSPACE/candidate/manifest.json\"", functional)
        self.assertNotRegex(functional, r"--artifact(?:\s|=)")
        self.assertIn("--download-url \"https://proof.ovh.net/files/1Mb.dat\"", functional)
        self.assertNotIn("speed.cloudflare.com/__down?", functional)

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
        result = self.text.index("- name: Upload safe macOS functional result")
        marker = self.text.index("- name: Publish opaque macOS completion marker")
        remove = self.text.index("- name: Remove plaintext handoff material")
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:marker])
        self.assertIn("if: always()", self.text[marker:remove])
        self.assertIn("sudo -n kill -TERM", self.text[stop:result])
        self.assertIn("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/recipient.key\"", self.text)

    def test_no_diagnostic_suppression(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)|SilentlyContinue")
        self.assertIn("Prove macOS runner architecture and elevation", self.text)
        self.assertIn("sudo -n id", self.text)
        self.assertIn("control_socket_ready=1", self.text)
        self.assertIn("SERVICE_CONTROL_SOCKET=%s", self.text)
        self.assertIn("emit_private_evidence", self.text)
        self.assertGreaterEqual(self.text.count("umask 077"), 4)
        self.assertNotIn('cat "$service_log"', self.text)
        self.assertNotIn('cat "$service_err"', self.text)
        self.assertNotIn('| tee "$SERVICE_DIR/preflight-control-status.raw.log"', self.text)
        self.assertNotIn('| tee "$SERVICE_DIR/control-status.raw.log"', self.text)
        self.assertIn('ps -axo pid=,ppid=,command= > "$children_snapshot" 2>&1', self.text)
        self.assertIn('emit_private_evidence service-children "$children_snapshot"', self.text)


if __name__ == "__main__":
    unittest.main()
