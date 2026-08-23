"""Policy tests for the isolated trusted Android functional workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "functional-android.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
    "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95",
    "android-actions/setup-android@40fd30fb8d7440372e1316f5d1809ec01dcd3699",
}


class FunctionalAndroidWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_manual_android_lane_has_hard_thirty_minute_client_bound(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^    runs-on: ubuntu-24\.04$")
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 30$")
        self.assertIn("deadline = int(started.timestamp()) + 30 * 60", self.text)
        self.assertIn('if [ "$remaining" -lt 650 ]', self.text)
        self.assertIn("six applicable canonical scenarios plus resets", self.text)
        self.assertIn("hosted.deadline", self.text)
        self.assertIn("--kill-grace-seconds 30", self.text)

    def test_actions_are_immutable_and_minimal(self) -> None:
        self.assertEqual(set(self.uses), EXPECTED_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("actions/cache", self.text)

    def test_build_is_secretless_and_stages_exact_apk_closure(self) -> None:
        build = self.text[self.text.index("  build:"):self.text.index("\n\n  client:")]
        self.assertNotIn("GH_TOKEN", build)
        self.assertNotIn("github.token", build)
        self.assertNotIn("secrets.", build)
        self.assertIn(":app:assembleDebug :app:assembleDebugAndroidTest", build)
        self.assertIn("candidate.py stage", build)
        self.assertIn("--platform android --architecture x86_64", build)
        self.assertIn("candidate-android-${{ inputs.commit_sha }}", build)

    def test_kvm_emulator_and_provenance_precede_candidate_execution(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn("test -e /dev/kvm", client)
        self.assertIn("-accel-check", client)
        self.assertRegex(client, r"KVM .*usable")
        self.assertIn("-accel on", client)
        self.assertIn("-no-window", client)
        self.assertIn("candidate.py verify", client)
        self.assertIn("--source-sha \"$SOURCE_SHA\"", client)
        start = client.index("- name: Start exact Android emulator")
        upload = client.index("- name: Upload public certificate and opaque request", start)
        run = client.index("- name: Run canonical Android functional scenarios", upload)
        runtime = client[start:upload]
        functional = client[run:]
        self.assertNotIn("GH_TOKEN", runtime)
        self.assertNotIn("github.token", runtime)
        self.assertIn("hosted.deadline", functional)
        self.assertIn("--platform android", functional)
        self.assertIn("--candidate-manifest \"$GITHUB_WORKSPACE/candidate/manifest.json\"", functional)
        self.assertIn("--adb \"$ADB_PATH\"", functional)
        self.assertNotIn("--artifact", functional)
        self.assertNotIn("--cli", functional)

    def test_render_provisioning_waits_for_headless_client_readiness(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        start = client.index("- name: Start exact Android emulator")
        upload = client.index("- name: Upload public certificate and opaque request")
        wait = client.index("- name: Wait for and download exact encrypted Render lease response")
        decrypt = client.index("- name: Validate and decrypt encrypted profile")
        run = client.index("- name: Run canonical Android functional scenarios")
        self.assertLess(start, upload)
        self.assertLess(upload, wait)
        self.assertLess(wait, decrypt)
        self.assertLess(decrypt, run)
        self.assertNotIn("GH_TOKEN", client[run:])
        self.assertNotIn("github.token", client[run:])
        self.assertIn("app-debug.apk", client[start:upload])
        self.assertIn("app-debug-androidTest.apk", client[start:upload])

    def test_android_external_waits_are_bounded_and_diagnostics_are_retained(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn("timeout --foreground --signal=TERM --kill-after=10s", client)
        self.assertIn("adb_bounded()", client)
        self.assertNotIn("wait-for-device", client)
        self.assertIn("setsid timeout", client)
        self.assertIn("tee \"$emulator_log\"", client)
        self.assertIn("tee \"$accel_check_log\"", client)
        self.assertIn("android_emulator_post_kill_verified=true", client)
        self.assertIn("android_cleanup_force_stop_app=failed", client)
        self.assertIn('kill -TERM -- "-$emulator_pid"', client)
        self.assertIn('kill -KILL -- "-$emulator_pid"', client)

    def test_every_runner_side_external_wait_has_a_bound(self) -> None:
        workflow = self.text
        for command in (
            "timeout --foreground --signal=TERM --kill-after=10s 30s sudo chmod",
            "timeout --foreground --signal=TERM --kill-after=10s 300s sdkmanager",
            "timeout --foreground --signal=TERM --kill-after=10s 480s ./kmp_module/gradlew",
            "timeout --foreground --signal=TERM --kill-after=10s 30s gh api",
            "timeout --foreground --signal=TERM --kill-after=10s 60s openssl req",
            "timeout --foreground --signal=TERM --kill-after=10s 120s avdmanager",
            "setsid timeout --foreground --signal=TERM --kill-after=10s 1500s",
            "timeout --foreground --signal=TERM --kill-after=10s 120s python3 -m torturer_checks.hosted.artifacts",
            "timeout --foreground --signal=TERM --kill-after=10s 60s openssl cms",
        ):
            with self.subTest(command=command):
                self.assertIn(command, workflow)

    def test_runtime_endpoints_are_query_fragment_and_userinfo_free(self) -> None:
        runtime = self.text[self.text.index("- name: Run canonical Android functional scenarios"):self.text.index("- name: Stop Android emulator")]
        values = re.findall(r"--(?:identity|latency|download|upload)-url\s+\"([^\"]+)\"", runtime)
        self.assertEqual(len(values), 4)
        for value in values:
            self.assertNotRegex(value, r"[?#@]")
        self.assertIn("https://proof.ovh.net/files/1Mb.dat", values)

    def test_render_handoff_is_opaque_and_bound_to_android_origin(self) -> None:
        self.assertIn("render-request-${lease_run_id}-${PLATFORM}", self.text)
        self.assertIn("render-lease-${LEASE_RUN_ID}-${PLATFORM}", self.text)
        self.assertIn("render-complete-${{ env.LEASE_RUN_ID }}-android", self.text)
        self.assertIn("inputs[origin_workflow_path]=.github/workflows/functional-android.yml", self.text)
        self.assertIn("profile.cms", self.text)
        self.assertIn("recipient.crt", self.text)
        self.assertIn("recipient.key", self.text)
        self.assertIn("profile.toml", self.text)
        self.assertIn("openssl cms -decrypt", self.text)

    def test_cleanup_and_completion_are_unconditional(self) -> None:
        stop = self.text.index("- name: Stop Android emulator")
        result = self.text.index("- name: Upload safe Android functional result")
        marker = self.text.index("- name: Publish opaque Android completion marker")
        remove = self.text.index("- name: Remove plaintext handoff material")
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:marker])
        self.assertIn("if: always()", self.text[marker:remove])
        self.assertIn("android_emulator_shutdown_requested", self.text[stop:result])
        self.assertIn("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/recipient.key\"", self.text)

    def test_no_diagnostic_suppression_or_desktop_service_contract(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)|SilentlyContinue")
        self.assertNotIn("powershell", self.text)
        self.assertNotIn("taskkill", self.text)
        self.assertNotIn("PROGRAMDATA", self.text)
        self.assertNotIn("SERVICE_PID", self.text)


if __name__ == "__main__":
    unittest.main()
