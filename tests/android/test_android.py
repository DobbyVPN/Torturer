from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ElementTree

from torturer_checks.android import (
    ANDROID_NS,
    AndroidContractError,
    CandidateApks,
    INTERNAL_LIFECYCLE_TEST,
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

    def test_accepts_expected_instrumentation_manifest(self) -> None:
        root = manifest(
            f'''<manifest xmlns:android="{ANDROID_NS}" package="com.dobby.vpn.test">
              <instrumentation android:name="com.dobby.TestApplicationRunner" android:targetPackage="com.dobby.vpn" />
            </manifest>'''
        )

        verify_test_manifest(root)
