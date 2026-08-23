from __future__ import annotations

from pathlib import Path
import os
import sys
import tempfile
import time
import unittest
import zipfile
import xml.etree.ElementTree as ElementTree

from torturer_checks.android import (
    ANDROID_NS,
    AndroidContractError,
    CandidateApks,
    CLEANUP_RESERVE_SECONDS,
    INTERNAL_LIFECYCLE_TEST,
    MAX_RUN_SECONDS,
    RunBudget,
    _contains_enabled_package,
    _run,
    build_command,
    enabled_package_command,
    lifecycle_test_command,
    verify_apk_layout,
    verify_application_manifest,
    verify_test_manifest,
)


def manifest(text: str) -> ElementTree.Element:
    return ElementTree.fromstring(text)


class AndroidCommandsTest(unittest.TestCase):
    def test_exact_debug_output_and_gradle_commands(self) -> None:
        apks = CandidateApks.from_candidate_root(Path("/candidate"))

        self.assertEqual(apks.app_apk, Path("/candidate/kmp_module/app/build/outputs/apk/debug/app-debug.apk"))
        self.assertEqual(apks.test_apk, Path("/candidate/kmp_module/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"))
        self.assertEqual(build_command(apks)[-2:], [":app:assembleDebug", ":app:assembleDebugAndroidTest"])
        self.assertIn(":app:connectedDebugAndroidTest", lifecycle_test_command(apks))
        self.assertIn(
            f"-Pandroid.testInstrumentationRunnerArguments.class={INTERNAL_LIFECYCLE_TEST}",
            lifecycle_test_command(apks),
        )


class AndroidArchiveTest(unittest.TestCase):
    def _write_apk(self, path: Path, names: list[str]) -> None:
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                archive.writestr(name, b"payload")

    def test_accepts_expected_minimal_archive_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apks = CandidateApks(root, root / "app.apk", root / "test.apk")
            self._write_apk(apks.app_apk, ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libgojni.so", "lib/arm64-v8a/libc++_shared.so", "lib/x86_64/libgojni.so", "lib/x86_64/libc++_shared.so"])
            self._write_apk(apks.test_apk, ["AndroidManifest.xml", "classes.dex"])

            verify_apk_layout(apks)

    def test_rejects_credential_container_in_apk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apks = CandidateApks(root, root / "app.apk", root / "test.apk")
            self._write_apk(apks.app_apk, ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libgojni.so", "lib/arm64-v8a/libc++_shared.so", "lib/x86_64/libgojni.so", "lib/x86_64/libc++_shared.so", "assets/client.p12"])
            self._write_apk(apks.test_apk, ["AndroidManifest.xml", "classes.dex"])

            with self.assertRaisesRegex(AndroidContractError, "credential"):
                verify_apk_layout(apks)

    def test_rejects_arm64_only_application_apk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apks = CandidateApks(root, root / "app.apk", root / "test.apk")
            self._write_apk(apks.app_apk, ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libgojni.so", "lib/arm64-v8a/libc++_shared.so"])
            self._write_apk(apks.test_apk, ["AndroidManifest.xml", "classes.dex"])

            with self.assertRaisesRegex(AndroidContractError, "x86_64/libgojni.so"):
                verify_apk_layout(apks)


class AndroidDeviceQueryTest(unittest.TestCase):
    def test_enabled_package_query_requires_package_record_not_apk_path(self) -> None:
        self.assertEqual(
            enabled_package_command(Path("/sdk/platform-tools/adb")),
            ["/sdk/platform-tools/adb", "shell", "pm", "list", "packages", "-e", "com.dobby.vpn"],
        )
        self.assertTrue(_contains_enabled_package("package:com.dobby.vpn\n", "com.dobby.vpn"))
        self.assertFalse(_contains_enabled_package("package:/data/app/~~hash/com.dobby.vpn/base.apk\n", "com.dobby.vpn"))

    def test_nonzero_status_query_returns_empty_result(self) -> None:
        result = _run([sys.executable, "-c", "import sys; sys.exit(1)"], allow_nonzero=True)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(),
        "detached-descendant regression requires a POSIX /proc process table",
    )
    def test_bounded_run_kills_detached_resistant_descendant(self) -> None:
        from torturer_checks.android import _run

        with tempfile.TemporaryDirectory(prefix="android-timeout-regression-") as directory:
            root = Path(directory)
            pid_file = root / "descendant.pid"
            command = [
                sys.executable,
                "-c",
                (
                    "import os, signal, time; "
                    "pid = os.fork(); "
                    f"os.setsid() if pid == 0 else None; "
                    f"marker = open({str(pid_file)!r}, 'w', encoding='ascii'); "
                    "marker.write(str(os.getpid()) if pid == 0 else str(pid)); marker.close(); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN) if pid == 0 else None; "
                    "time.sleep(60)"
                ),
            ]
            with self.assertRaisesRegex(AndroidContractError, "timed out"):
                _run(
                    command,
                    timeout=0.2,
                    evidence_directory=root / "evidence",
                    evidence_label="detached-descendant",
                )
            descendant_pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"detached Android command descendant {descendant_pid} survived cleanup")

    def test_run_budget_keeps_the_documented_cleanup_reserve(self) -> None:
        self.assertEqual(MAX_RUN_SECONDS, 1800)
        self.assertEqual(CLEANUP_RESERVE_SECONDS, 120)
        clock = iter((0.0, 0.0, 7.0, 8.1))
        budget = RunBudget(max_seconds=10, cleanup_reserve_seconds=2, clock=lambda: next(clock))
        self.assertEqual(budget.operation_timeout(), 8.0)
        self.assertEqual(budget.operation_timeout(), 1.0)
        with self.assertRaisesRegex(AndroidContractError, "functional budget"):
            budget.operation_timeout()


class AndroidDiagnosticsPolicyTest(unittest.TestCase):
    def test_emulator_log_is_retained_without_truncating_diagnostics_in_errors(self) -> None:
        source = (Path(__file__).resolve().parents[2] / "torturer_checks" / "android.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("stdout=log_handle", source)
        self.assertIn('log_path.open("xb")', source)
        self.assertIn("os.chmod(log_path, 0o600)", source)
        self.assertIn("complete emulator diagnostics retained privately", source)
        self.assertNotIn("diagnostics[-32768:]", source)
        self.assertIn("start_new_session=True", source)
        self.assertIn("_terminate_process_tree", source)
        self.assertNotIn("subprocess.run(", source)


class AndroidManifestTest(unittest.TestCase):
    def test_accepts_expected_application_manifest(self) -> None:
        root = manifest(
            f'''<manifest xmlns:android="{ANDROID_NS}" package="com.dobby.vpn">
              <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
              <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
              <application android:debuggable="true" android:usesCleartextTraffic="false">
                <service android:name="com.dobby.feature.vpn_service.DobbyVpnService" android:exported="true" android:permission="android.permission.BIND_VPN_SERVICE" android:foregroundServiceType="specialUse"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="VPN lifecycle" /><intent-filter><action android:name="android.net.VpnService" /></intent-filter></service>
                <activity android:name="com.dobby.feature.main.ui.DobbySocksActivity" android:exported="true" />
              </application>
            </manifest>'''
        )

        verify_application_manifest(root)

    def test_rejects_vpn_service_without_binding_permission(self) -> None:
        root = manifest(
            f'''<manifest xmlns:android="{ANDROID_NS}" package="com.dobby.vpn">
              <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
              <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
              <application android:debuggable="true" android:usesCleartextTraffic="false">
                <service android:name="com.dobby.feature.vpn_service.DobbyVpnService" android:exported="true" android:foregroundServiceType="specialUse"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="VPN lifecycle" /><intent-filter><action android:name="android.net.VpnService" /></intent-filter></service>
                <activity android:name="com.dobby.feature.main.ui.DobbySocksActivity" android:exported="true" />
              </application>
            </manifest>'''
        )

        with self.assertRaisesRegex(AndroidContractError, "BIND_VPN_SERVICE"):
            verify_application_manifest(root)

    def test_rejects_system_exempted_before_vpn_activation(self) -> None:
        root = manifest(
            f'''<manifest xmlns:android="{ANDROID_NS}" package="com.dobby.vpn">
              <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
              <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />
              <application android:debuggable="true" android:usesCleartextTraffic="false">
                <service android:name="com.dobby.feature.vpn_service.DobbyVpnService" android:exported="true" android:permission="android.permission.BIND_VPN_SERVICE" android:foregroundServiceType="systemExempted"><intent-filter><action android:name="android.net.VpnService" /></intent-filter></service>
                <activity android:name="com.dobby.feature.main.ui.DobbySocksActivity" android:exported="true" />
              </application>
            </manifest>'''
        )

        with self.assertRaisesRegex(AndroidContractError, "FOREGROUND_SERVICE_SPECIAL_USE"):
            verify_application_manifest(root)

    def test_accepts_compiled_special_use_bitmask(self) -> None:
        root = manifest(
            f'''<manifest xmlns:android="{ANDROID_NS}" package="com.dobby.vpn">
              <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
              <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
              <application android:debuggable="true" android:usesCleartextTraffic="false">
                <service android:name="com.dobby.feature.vpn_service.DobbyVpnService" android:exported="true" android:permission="android.permission.BIND_VPN_SERVICE" android:foregroundServiceType="0x40000000"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="VPN lifecycle" /><intent-filter><action android:name="android.net.VpnService" /></intent-filter></service>
                <activity android:name="com.dobby.feature.main.ui.DobbySocksActivity" android:exported="true" />
              </application>
            </manifest>'''
        )

        verify_application_manifest(root)

    def test_accepts_expected_instrumentation_manifest(self) -> None:
        root = manifest(
            f'''<manifest xmlns:android="{ANDROID_NS}" package="com.dobby.vpn.test">
              <instrumentation android:name="com.dobby.TestApplicationRunner" android:targetPackage="com.dobby.vpn" />
            </manifest>'''
        )

        verify_test_manifest(root)
