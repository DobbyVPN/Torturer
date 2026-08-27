"""Policy tests for the isolated trusted Android functional workflow."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import textwrap
import time
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
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertRegex(client, r"(?m)^    timeout-minutes: 20$")
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

    def test_android_build_children_share_the_run_start_deadline(self) -> None:
        build = self.text[self.text.index("  build:"):self.text.index("\n\n  client:")]
        self.assertIn("WORKFLOW_RUN_STARTED_AT: ${{ github.run_started_at }}", build)
        self.assertIn("android-build-run-with-deadline.sh", build)
        self.assertIn('android_build_deadline_child configured=', build)
        for command in (
            '"$DEADLINE_COMMAND" 300 sdkmanager',
            '"$DEADLINE_COMMAND" 240 bash -c',
            '"$DEADLINE_COMMAND" 240 go install',
            '"$DEADLINE_COMMAND" 480 ./kmp_module/gradlew',
            '"$DEADLINE_COMMAND" 60 python3 torturer/torturer_checks/hosted/candidate.py stage',
        ):
            with self.subTest(command=command):
                self.assertIn(command, build)

    def test_kvm_emulator_and_provenance_precede_candidate_execution(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn("test -c /dev/kvm", client)
        self.assertIn("-accel-check", client)
        self.assertIn("is installed and usable", client)
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
        self.assertIn('upload_url="$(cat "$HANDOFF_DIR/upload-url.txt")"', functional)
        self.assertIn('--upload-url "$upload_url"', functional)
        self.assertNotIn("speed.cloudflare.com/__up", functional)
        self.assertIn("adb-incremental-wrapper.py", client)
        self.assertIn("DOBBY_ADB_LOGCAT_CURSOR", client)
        self.assertNotIn("--artifact", functional)
        self.assertNotIn("--cli", functional)

    def test_kvm_positive_check_rejects_negative_acceleration_output(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        match = re.search(r"grep -Eiq '([^']+)' \"\$accel_check_log\"", client)
        self.assertIsNotNone(match)
        pattern = match.group(1)
        negative = subprocess.run(
            ["grep", "-Eiq", pattern],
            input=b"KVM is not installed or usable.\n",
            capture_output=True,
            check=False,
        )
        positive = subprocess.run(
            ["grep", "-Eiq", pattern],
            input=b"KVM (version 12) is installed and usable.\n",
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(negative.returncode, 0)
        self.assertEqual(positive.returncode, 0)

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
        self.assertIn("SERVER_SINK_IMAGE_DIGEST", client)
        self.assertIn("--expect-file upload.cms", client)
        self.assertIn('test -f "$LEASE_RESPONSE_DIR/upload.cms"', client)
        self.assertIn('"schema": 2', client)
        self.assertIn('expected_digests = {', client)
        self.assertIn('"outline": os.environ["SERVER_IMAGE_DIGEST"]', client)
        self.assertIn('"upload-sink": os.environ["SERVER_SINK_IMAGE_DIGEST"]', client)
        self.assertIn('"provider_generation"', client)
        self.assertIn('"url", "path", "password", "secret"', client)
        self.assertIn("by_role", client)
        self.assertIn("service IDs must be distinct", client)
        self.assertIn("lease provider generation is invalid", client)

    def test_android_schema_two_lease_validation_rejects_identity_confusion(self) -> None:
        marker = '          python3 - "$LEASE_RESPONSE_DIR/lease.json" <<\'PY\'\n'
        body = self.text.split(marker, 1)[1].split("\n          PY\n", 1)[0]
        script = textwrap.dedent(body)
        outline_digest = "sha256:" + "a" * 64
        sink_digest = "sha256:" + "b" * 64
        valid = {
            "schema": 2,
            "kind": "dobbyvpn.render-lease",
            "run_id": "c" * 32,
            "platform": "android",
            "source_sha": "d" * 40,
            "state": "issued",
            "services": [
                {
                    "role": "outline",
                    "service_id": "srv-outline123",
                    "image_digest": outline_digest,
                    "provider_generation": "dep-outline123",
                },
                {
                    "role": "upload-sink",
                    "service_id": "srv-sink123",
                    "image_digest": sink_digest,
                    "provider_generation": "dep-sink123",
                },
            ],
        }
        environment = {
            **os.environ,
            "LEASE_RUN_ID": valid["run_id"],
            "SOURCE_SHA": valid["source_sha"],
            "SERVER_IMAGE_DIGEST": outline_digest,
            "SERVER_SINK_IMAGE_DIGEST": sink_digest,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script_path = root / "validate-lease.py"
            script_path.write_text(script, encoding="utf-8")

            def run(value: dict[str, object]) -> subprocess.CompletedProcess[bytes]:
                lease_path = root / "lease.json"
                lease_path.write_text(json.dumps(value), encoding="utf-8")
                return subprocess.run(
                    ["python3", str(script_path), str(lease_path)],
                    env=environment,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(run(valid).returncode, 0)
            swapped = json.loads(json.dumps(valid))
            swapped["services"][0]["image_digest"], swapped["services"][1]["image_digest"] = (
                swapped["services"][1]["image_digest"],
                swapped["services"][0]["image_digest"],
            )
            self.assertNotEqual(run(swapped).returncode, 0)
            duplicate_id = json.loads(json.dumps(valid))
            duplicate_id["services"][1]["service_id"] = duplicate_id["services"][0]["service_id"]
            self.assertNotEqual(run(duplicate_id).returncode, 0)
            empty_generation = json.loads(json.dumps(valid))
            empty_generation["services"][1]["provider_generation"] = ""
            self.assertNotEqual(run(empty_generation).returncode, 0)
            non_string_generation = json.loads(json.dumps(valid))
            non_string_generation["services"][1]["provider_generation"] = 123
            self.assertNotEqual(run(non_string_generation).returncode, 0)

    def test_android_evidence_roots_are_private_and_fail_closed(self) -> None:
        establish = self.text[self.text.index("- name: Establish runner-local paths"):self.text.index(
            "- name: Validate trusted functional inputs"
        )]
        self.assertIn("umask 077", establish)
        self.assertIn('if [ -L "$private_dir" ]', establish)
        self.assertIn('chmod 700 "$handoff" "$service"', establish)
        self.assertIn("stat -c '%u'", establish)
        self.assertIn("stat -c '%a'", establish)
        self.assertIn('private_mode" != "700"', establish)

    def test_android_readiness_adb_waits_share_the_hard_deadline(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        start = client[client.index("- name: Start exact Android emulator"):client.index(
            "- name: Upload public certificate and opaque request"
        )]
        self.assertIn('"$DEADLINE_COMMAND" 120 "$adb"', start)
        self.assertIn("ANDROID_CLEANUP_RESERVE_SECONDS", start)
        self.assertIn("readiness_sleep()", start)
        self.assertIn("readiness_sleep 2", start)
        self.assertNotIn(
            'timeout --foreground --signal=TERM --kill-after=10s 120s "$adb"',
            start,
        )

    def test_android_deadline_helper_caps_children_and_fails_when_reserve_is_exhausted(self) -> None:
        client = self.text[self.text.index("- name: Establish hard thirty-minute workflow deadline"):]
        start = '          cat > "$deadline_command" <<\'SH\'\n'
        body = client.split(start, 1)[1].split("\n          SH\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "run-with-deadline.sh"
            helper.write_text(textwrap.dedent(body), encoding="utf-8")
            helper.chmod(0o700)
            environment = {
                **os.environ,
                "RUN_DEADLINE_EPOCH": str(int(time.time()) + 100),
                "ANDROID_CLEANUP_RESERVE_SECONDS": "20",
            }
            capped = subprocess.run(
                [str(helper), "300", "true"],
                env=environment,
                capture_output=True,
                check=False,
            )
            self.assertEqual(capped.returncode, 0, capped.stderr.decode())
            match = re.search(rb"configured=300 selected=([0-9]+) remaining=([0-9]+)", capped.stdout)
            self.assertIsNotNone(match, capped.stdout.decode())
            assert match is not None
            self.assertGreater(int(match.group(1)), 0)
            self.assertLessEqual(int(match.group(1)), int(match.group(2)))
            available = subprocess.run(
                [str(helper), "--check", "50"],
                env=environment,
                capture_output=True,
                check=False,
            )
            self.assertEqual(available.returncode, 0, available.stderr.decode())
            insufficient = subprocess.run(
                [str(helper), "--check", "300"],
                env=environment,
                capture_output=True,
                check=False,
            )
            self.assertEqual(insufficient.returncode, 124, insufficient.stderr.decode())
            self.assertIn(b"android_deadline_check=insufficient", insufficient.stderr)
            exhausted_environment = {
                **environment,
                "RUN_DEADLINE_EPOCH": str(int(time.time()) + 5),
            }
            exhausted = subprocess.run(
                [str(helper), "--check", "1"],
                env=exhausted_environment,
                capture_output=True,
                check=False,
            )
            self.assertEqual(exhausted.returncode, 124, exhausted.stderr.decode())
            self.assertIn(b"android_deadline_child=exhausted", exhausted.stderr)

    def test_android_cleanup_validates_process_identity_and_zombies(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        start = client[client.index("- name: Start exact Android emulator"):client.index(
            "- name: Upload public certificate and opaque request"
        )]
        cleanup = client[client.index("- name: Stop Android emulator"):]
        for value in ("emulator.identity", "start_time", "process_group", "/proc/"):
            self.assertIn(value, start)
        self.assertIn("Publish the cleanup handoff before any identity probe", start)
        self.assertIn('printf \'%s\\n\' "$emulator_pid" > "$HANDOFF_DIR/emulator.pid"', start)
        for value in (
            "identity_valid=false",
            "expected_start_time",
            "expected_pgrp",
            "identity-mismatch",
            "zombie-only",
            'kill -TERM -- "-$expected_pgrp"',
            'kill -KILL -- "-$expected_pgrp"',
        ):
            self.assertIn(value, cleanup)
        self.assertNotIn('kill -TERM -- "-$emulator_pid"', cleanup)
        self.assertNotIn('kill -KILL -- "-$emulator_pid"', cleanup)

    def test_android_cleanup_adb_errors_fail_closed(self) -> None:
        cleanup = self.text[self.text.index("- name: Stop Android emulator"):self.text.index(
            "- name: Upload safe Android functional result"
        )]
        self.assertGreaterEqual(cleanup.count("emulator_cleanup_failure=true"), 5)
        self.assertIn('emulator_cleanup_failure=true', cleanup)
        self.assertIn('if [ "$emulator_cleanup_failure" = true ]; then exit 1; fi', cleanup)
        self.assertNotIn("DELETE_FAILED_INTERNAL_ERROR", cleanup)
        self.assertIn("signal_failure=true", cleanup)
        self.assertIn("signal_failure=false", cleanup)
        self.assertIn("signal-failure-unproven", cleanup)

    def test_android_process_group_scan_fails_closed_when_proc_is_incomplete(self) -> None:
        cleanup = self.text[self.text.index("- name: Stop Android emulator"):self.text.index(
            "- name: Upload safe Android functional result"
        )]
        self.assertIn("scan_process_group()", cleanup)
        self.assertIn("process_group_scan_complete=false", cleanup)
        self.assertIn('if [ -e "$identity_stat_path" ]; then', cleanup)
        self.assertIn('identity_state_value" =~ ^[A-Za-z]$', cleanup)
        self.assertIn('identity_pgrp_value" =~ ^[1-9][0-9]*$', cleanup)
        self.assertIn("android_emulator_proc_scan=incomplete", cleanup)
        self.assertIn("scan-incomplete", cleanup)

    def test_android_external_waits_are_bounded_and_diagnostics_are_retained(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        self.assertIn('kill_grace=10', client)
        self.assertIn('exec timeout --foreground --signal=TERM --kill-after="${kill_grace}s"', client)
        self.assertIn("adb_bounded()", client)
        self.assertNotIn("wait-for-device", client)
        self.assertIn('setsid "$emulator_launcher"', client)
        self.assertIn('"$DEADLINE_COMMAND" 1500 "$ANDROID_SDK_ROOT/emulator/emulator"', client)
        self.assertIn('> "$EMULATOR_LOG" 2>&1', client)
        self.assertIn('> "$accel_check_log" 2>&1', client)
        self.assertIn('> "$sdk_install_log" 2>&1', client)
        self.assertIn('> "$sdk_list_log" 2>&1', client)
        self.assertIn('> "$avd_log" 2>&1', client)
        self.assertIn('> "$adb_start_log" 2>&1', client)
        self.assertIn('> "$kvm_chmod_log" 2>&1', client)
        self.assertIn('> "$kvm_device_log" 2>&1', client)
        build = self.text[self.text.index("- name: Install exact Android build toolchain"):self.text.index("- name: Verify checkout and build Android candidate")]
        self.assertIn('> "$sdk_install_log" 2>&1', build)
        self.assertIn('> "$sdk_list_log" 2>&1', build)
        self.assertIn('emit_private_evidence', build)
        self.assertIn("umask 077", build)
        self.assertIn("emit_private_evidence", client)
        self.assertGreaterEqual(client.count("umask 077"), 3)
        self.assertNotIn('cat "$EMULATOR_LOG"', client)
        self.assertIn("android_emulator_post_kill_verified=true", client)
        self.assertIn("android-emulator-exit-summary", client)
        self.assertIn("android-cleanup-transport-state", client)
        self.assertIn("android_cleanup_force_stop_app=failed", client)
        self.assertIn('kill -TERM -- "-$expected_pgrp"', client)
        self.assertIn('kill -KILL -- "-$expected_pgrp"', client)
        self.assertNotIn('adb_missing_during_cleanup=%s', client)

    def test_android_diagnostics_ignore_non_command_raw_logs(self) -> None:
        self.assertIn(
            'files = sorted(raw_dir.glob("command-*.raw.log"))',
            self.text,
        )
        self.assertNotIn(
            'files = sorted(raw_dir.glob("*.raw.log"))',
            self.text,
        )

    def test_android_logcat_diagnostics_are_incremental_and_lossless(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        wrapper = client[client.index("adb-incremental-wrapper.py"):client.index(
            "- name: Upload public certificate and opaque request"
        )]
        self.assertIn('normalized.extend(["-v", "epoch"])', wrapper)
        self.assertIn('normalized.extend(["-T", cursor])', wrapper)
        self.assertIn("selectors.DefaultSelector()", wrapper)
        self.assertIn("write_all(fd, chunk)", wrapper)
        self.assertIn("if returncode == 0 and last_epoch is not None", wrapper)
        self.assertNotIn("logcat -d -b all", client)
        self.assertNotIn("logcat -t", client)

    def test_android_logcat_wrapper_preserves_streams_and_advances_cursor(self) -> None:
        start = '          cat > "$adb_wrapper" <<\'PY\'\n'
        body = self.text.split(start, 1)[1].split("\n          PY\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / "adb-incremental-wrapper.py"
            wrapper.write_text(textwrap.dedent(body), encoding="utf-8")
            cursor = root / "cursor"
            calls = root / "calls"
            fake_adb = root / "adb.py"
            fake_adb.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import sys\n"
                f"calls = Path({str(calls)!r})\n"
                "with calls.open('a', encoding='utf-8') as stream:\n"
                "    stream.write(' '.join(sys.argv[1:]) + '\\n')\n"
                "count = len(calls.read_text(encoding='utf-8').splitlines())\n"
                "print(f'{1000 + count}.000 I fixture: stdout-{count}', flush=True)\n"
                "print(f'stderr-{count}', file=sys.stderr, flush=True)\n",
                encoding="utf-8",
            )
            fake_adb.chmod(0o700)
            environment = {
                **os.environ,
                "DOBBY_REAL_ADB": str(fake_adb),
                "DOBBY_ADB_LOGCAT_CURSOR": str(cursor),
            }
            first = subprocess.run(
                ["python3", str(wrapper), "logcat", "-d", "-b", "all"],
                env=environment, capture_output=True, check=False,
            )
            second = subprocess.run(
                ["python3", str(wrapper), "logcat", "-d", "-b", "all"],
                env=environment, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            self.assertEqual(second.returncode, 0, second.stderr.decode())
            self.assertIn(b"stdout-1", first.stdout)
            self.assertIn(b"stderr-1", first.stderr)
            self.assertIn(b"stdout-2", second.stdout)
            self.assertIn(b"stderr-2", second.stderr)
            commands = calls.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(commands), 2)
            self.assertNotIn("-T", commands[0])
            self.assertIn("-T 1001.000", commands[1])
            self.assertEqual(cursor.read_text(encoding="ascii").strip(), "1002.000")

    def test_android_logcat_wrapper_handles_chunk_boundaries_and_failed_reads(self) -> None:
        start = '          cat > "$adb_wrapper" <<\'PY\'\n'
        body = self.text.split(start, 1)[1].split("\n          PY\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / "adb-incremental-wrapper.py"
            wrapper.write_text(textwrap.dedent(body), encoding="utf-8")
            cursor = root / "cursor"
            calls = root / "calls"
            fake_adb = root / "adb.py"
            fake_adb.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "from pathlib import Path\n"
                "import sys\n"
                f"calls = Path({str(calls)!r})\n"
                "with calls.open('a', encoding='utf-8') as stream:\n"
                "    stream.write(' '.join(sys.argv[1:]) + '\\n')\n"
                "count = len(calls.read_text(encoding='utf-8').splitlines())\n"
                "if count == 1:\n"
                "    os.write(1, b'1000.000 I split-')\n"
                "    os.write(1, b'line\\n1001.')\n"
                "    os.write(1, b'000 I final\\n')\n"
                "    os.write(2, b'stderr-')\n"
                "    os.write(2, b'split\\n')\n"
                "elif count == 2:\n"
                "    os.write(1, b'1002.000 I failed\\n')\n"
                "    os.write(2, b'failed stderr\\n')\n"
                "    raise SystemExit(7)\n"
                "else:\n"
                "    os.write(1, b'1003.000 I recovered\\n')\n",
                encoding="utf-8",
            )
            fake_adb.chmod(0o700)
            environment = {
                **os.environ,
                "DOBBY_REAL_ADB": str(fake_adb),
                "DOBBY_ADB_LOGCAT_CURSOR": str(cursor),
            }
            first = subprocess.run(
                ["python3", str(wrapper), "logcat", "-d", "-b", "all"],
                env=environment, capture_output=True, check=False,
            )
            second = subprocess.run(
                ["python3", str(wrapper), "logcat", "-d", "-b", "all"],
                env=environment, capture_output=True, check=False,
            )
            third = subprocess.run(
                ["python3", str(wrapper), "logcat", "-d", "-b", "all"],
                env=environment, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            self.assertEqual(second.returncode, 7, second.stderr.decode())
            self.assertEqual(third.returncode, 0, third.stderr.decode())
            self.assertEqual(first.stdout, b"1000.000 I split-line\n1001.000 I final\n")
            self.assertEqual(first.stderr, b"stderr-split\n")
            self.assertEqual(second.stdout, b"1002.000 I failed\n")
            self.assertEqual(second.stderr, b"failed stderr\n")
            self.assertEqual(cursor.read_text(encoding="ascii").strip(), "1003.000")
            commands = calls.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(commands), 3)
            self.assertNotIn("-T", commands[0])
            self.assertIn("-T 1001.000", commands[1])
            self.assertIn("-T 1001.000", commands[2])

    def test_android_transport_summary_is_fixed_safe_metadata(self) -> None:
        diagnostic = self.text[self.text.index("- name: Report safe Android command diagnostics"):self.text.index(
            "- name: Upload safe Android command diagnostics"
        )]
        for field in (
            "transport_state=",
            "logcat_command_count=",
            "logcat_nonzero_count=",
            "adb_device_unavailable_count=",
            "first_logcat_failure_sequence=",
            "first_device_unavailable_sequence=",
        ):
            self.assertIn(field, diagnostic)
        self.assertIn("android-transport-summary.txt", self.text)
        cleanup = self.text[self.text.index("- name: Stop Android emulator"):self.text.index(
            "- name: Upload safe Android functional result"
        )]
        for field in (
            "transport_state=",
            "emulator_shutdown_request=",
            "emulator_process_state=",
            "emulator_exit_status_state=",
            "emulator_exit_status=",
            "emulator_log_sha256=",
        ):
            self.assertIn(field, cleanup)
        self.assertIn("android-emulator-exit-summary.txt", self.text)

    def test_android_emulator_exit_record_is_owner_only_and_atomic(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        launcher = client[client.index("emulator-launcher.sh"):client.index(
            "adb_wrapper=\"$HANDOFF_DIR/adb-incremental-wrapper.py\""
        )]
        self.assertIn("record_emulator_status()", launcher)
        self.assertIn("EMULATOR_EXIT_STATUS_FILE", launcher)
        self.assertIn('chmod 600 "$temporary"', launcher)
        self.assertIn('mv -f -- "$temporary" "$EMULATOR_EXIT_STATUS_FILE"', launcher)
        self.assertIn("trap 'record_emulator_status 143; exit 143' TERM INT", launcher)
        self.assertIn('setsid "$emulator_launcher" &', launcher)
        cleanup = client[client.index("- name: Stop Android emulator"):]
        self.assertIn("RECORDED", cleanup)
        self.assertIn("NOT_YET_RECORDED", cleanup)
        self.assertIn("MISSING", cleanup)

    def test_android_emulator_exit_public_view_is_bounded(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        diagnostic = client[client.index('"$DEADLINE_COMMAND" 5 python3 -'):client.index(
            "chmod 600 \"$exit_log\""
        )]
        self.assertIn("reason_count = 0", diagnostic)
        self.assertIn("first_reason = \"none\"", diagnostic)
        self.assertIn("safe_line[:240]", diagnostic)
        self.assertNotIn('" | ".join(reasons)', diagnostic)
        self.assertIn("emulator_exit_reason_count=", diagnostic)
        self.assertIn("sed -n '1,5p' \"$exit_log\"", client)

    def test_android_emulator_exit_public_view_streams_raw_log_and_bounds_reason(self) -> None:
        start = '          "$DEADLINE_COMMAND" 5 python3 - "$emulator_log" "$emulator_wait_status" <<\'PY\' > "$exit_log" 2>&1 || exit_diagnostic_status=$?\n'
        body = self.text.split(start, 1)[1].split("\n          PY\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "exit-diagnostic.py"
            script.write_text(textwrap.dedent(body), encoding="utf-8")
            log = root / "emulator.raw.log"
            log.write_bytes((b"ERROR secret=private-token path=/runner/private\n") * 1000)
            result = subprocess.run(
                ["python3", str(script), str(log), "17"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            output = result.stdout.decode("utf-8")
            self.assertLessEqual(len(output.splitlines()), 5)
            self.assertIn("emulator_wait_status=17", output)
            self.assertIn("emulator_log_bytes=", output)
            self.assertIn("emulator_exit_reason_count=1000", output)
            self.assertIn("<redacted>", output)
            self.assertNotIn("private-token", output)
            reason = next(line for line in output.splitlines() if line.startswith("emulator_exit_reason="))
            self.assertLessEqual(len(reason), len("emulator_exit_reason=") + 240)

    def test_android_emulator_launcher_records_real_exit_status(self) -> None:
        start = '          cat > "$emulator_launcher" <<\'SH\'\n'
        body = self.text.split(start, 1)[1].split("\n          SH\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launcher = root / "emulator-launcher.sh"
            launcher.write_text(textwrap.dedent(body), encoding="utf-8")
            launcher.chmod(0o700)
            fake_timeout = root / "timeout"
            fake_timeout.write_text(
                "#!/usr/bin/env bash\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case \"$1\" in --*) shift;; *s) shift;; *) break;; esac\n"
                "done\n"
                "exec \"$@\"\n",
                encoding="utf-8",
            )
            fake_timeout.chmod(0o700)
            fake_deadline = root / "run-with-deadline.sh"
            fake_deadline.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = --reserve ]; then shift 2; fi\n"
                "if [ \"$1\" = --check ]; then exit 0; fi\n"
                "shift\n"
                "exec \"$@\"\n",
                encoding="utf-8",
            )
            fake_deadline.chmod(0o700)
            emulator = root / "sdk" / "emulator" / "emulator"
            emulator.parent.mkdir(parents=True)
            emulator.write_text("#!/usr/bin/env bash\nprintf 'emulator-output\\n'\nexit 17\n", encoding="utf-8")
            emulator.chmod(0o700)
            status_file = root / "emulator-exit-status.raw.log"
            emulator_log = root / "emulator.raw.log"
            environment = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "ANDROID_SDK_ROOT": str(root / "sdk"),
                "EMULATOR_AVD_NAME": "fixture-avd",
                "EMULATOR_LOG": str(emulator_log),
                "EMULATOR_EXIT_STATUS_FILE": str(status_file),
                "DEADLINE_COMMAND": str(fake_deadline),
            }
            result = subprocess.run([str(launcher)], env=environment, capture_output=True, check=False)
            self.assertEqual(result.returncode, 17, result.stderr.decode())
            self.assertEqual(status_file.read_text(encoding="ascii"), "emulator_exit_status=17\n")
            self.assertEqual(stat.S_IMODE(status_file.stat().st_mode), 0o600)
            self.assertEqual(emulator_log.read_text(encoding="utf-8"), "emulator-output\n")

    def test_android_cleanup_worst_case_fits_the_finalization_reserve(self) -> None:
        client = self.text[self.text.index("  client:"):self.text.index("\n\n  controller:")]
        cleanup = client[client.index("- name: Stop Android emulator"):]
        self.assertIn("adb_timeout_seconds=4", cleanup)
        self.assertIn("adb_kill_grace_seconds=1", cleanup)
        self.assertIn('"${adb_timeout_seconds}s"', cleanup)
        self.assertIn('"${adb_kill_grace_seconds}s"', cleanup)
        self.assertIn("for attempt in $(seq 1 15)", cleanup)
        self.assertEqual(cleanup.count("for attempt in $(seq 1 5)"), 2)
        self.assertIn('emit_private_evidence android-emulator-log "$EMULATOR_LOG"', cleanup)
        self.assertNotIn('cat "$EMULATOR_LOG"', cleanup)
        # Seven adb calls + host process-group proof + bounded log drain.
        worst_case = 7 * (4 + 1) + 15 + 5 + 5 + 5
        self.assertEqual(worst_case, 65)
        self.assertLessEqual(worst_case, 120)

    def test_every_runner_side_external_wait_has_a_bound(self) -> None:
        workflow = self.text
        for command in (
            '"$DEADLINE_COMMAND" 30 sudo chmod',
            '"$DEADLINE_COMMAND" 300 sdkmanager',
            '"$DEADLINE_COMMAND" 60 openssl req',
            '"$DEADLINE_COMMAND" 120 avdmanager',
            '"$DEADLINE_COMMAND" 1500 "$ANDROID_SDK_ROOT/emulator/emulator"',
            '"$DEADLINE_COMMAND" 120 python3 -m torturer_checks.hosted.artifacts',
            '"$DEADLINE_COMMAND" 60 openssl cms',
            '"$DEADLINE_COMMAND" --reserve 70 10 python3 -',
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
        self.assertIn('upload_url="$(cat "$HANDOFF_DIR/upload-url.txt")"', runtime)
        self.assertIn('--upload-url "$upload_url"', runtime)

    def test_render_handoff_is_opaque_and_bound_to_android_origin(self) -> None:
        self.assertIn("render-request-${lease_run_id}-${PLATFORM}", self.text)
        self.assertIn("render-lease-${LEASE_RUN_ID}-${PLATFORM}", self.text)
        self.assertIn("render-complete-${{ env.LEASE_RUN_ID }}-android", self.text)
        self.assertIn("inputs[origin_workflow_path]=.github/workflows/functional-android.yml", self.text)
        self.assertIn("profile.cms", self.text)
        self.assertIn("recipient.crt", self.text)
        self.assertIn("recipient.key", self.text)
        self.assertIn("profile.toml", self.text)
        self.assertIn("upload.cms", self.text)
        self.assertIn("upload-url.txt", self.text)
        self.assertIn('chmod 600 "$HANDOFF_DIR/upload-url.txt"', self.text)
        self.assertIn("openssl cms -decrypt", self.text)

    def test_cleanup_and_completion_are_unconditional(self) -> None:
        stop = self.text.index("- name: Stop Android emulator")
        remove = self.text.index("- name: Remove plaintext handoff material")
        result = self.text.index("- name: Upload safe Android functional result")
        marker = self.text.index("- name: Publish opaque Android completion marker")
        self.assertLess(stop, remove)
        self.assertLess(remove, result)
        self.assertIn("if: always()", self.text[stop:result])
        self.assertIn("if: always()", self.text[result:marker])
        self.assertIn("if: always()", self.text[marker:])
        self.assertIn("android_emulator_shutdown_requested", self.text[stop:result])
        result_upload = self.text[result:marker]
        self.assertNotIn("profile.cms", result_upload)
        self.assertNotIn("upload.cms", result_upload)
        self.assertNotIn("upload-url.txt", result_upload)
        self.assertNotIn("profile.toml", result_upload)
        self.assertIn("rm -f \"$HANDOFF_DIR/profile.toml\" \"$HANDOFF_DIR/upload-url.txt\" \"$HANDOFF_DIR/recipient.key\"", self.text)

    def test_no_diagnostic_suppression_or_desktop_service_contract(self) -> None:
        self.assertNotRegex(self.text, r">\s*/dev/null|2>\s*/dev/null|--quiet(?:\s|$)|SilentlyContinue")
        self.assertNotIn("powershell", self.text)
        self.assertNotIn("taskkill", self.text)
        self.assertNotIn("PROGRAMDATA", self.text)
        self.assertNotIn("SERVICE_PID", self.text)


if __name__ == "__main__":
    unittest.main()
