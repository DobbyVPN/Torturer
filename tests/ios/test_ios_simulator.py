from __future__ import annotations

import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest

from torturer_checks.artifact import SourceIdentity
from torturer_checks.ios_simulator import (
    IOSSimulatorContractError,
    SimulatorTestContract,
    TreeLimits,
    inspect_simulator_app,
    inspect_xcresult_bundle,
    simctl_boot_command,
    simctl_bootstatus_command,
    simctl_install_command,
    simctl_launch_command,
    simctl_terminate_command,
    source_identity_from_simulator_checkout,
    validate_xcresult_summary,
    xcodebuild_test_command,
    xcresult_summary_command,
)


SOURCE = SourceIdentity.create(repository="DobbyVPN/DobbyVPN", commit="a" * 40)
BUNDLE = "com.dobby.vpn"
UDID = "A12B34C5-1234-5678-9ABC-123456789ABC"
TEST = "DobbySimulatorContractTests/DobbySimulatorContractTests/testStartStop"


def fake_macho(cpu: int = 0x0100000C, payload: bytes = b"") -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + b"\0" * 24 + payload


class IOSSimulatorContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def make_app(self, *, executable: bytes | None = None, bundle: str = BUNDLE) -> Path:
        app = self.root / f"Dobby VPN {len(list(self.root.glob('*.app')))}.app"
        app.mkdir()
        (app / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundlePackageType": "APPL",
            "CFBundleIdentifier": bundle,
            "CFBundleExecutable": "Dobby VPN",
        }))
        (app / "Dobby VPN").write_bytes(executable or fake_macho())
        (app / "Assets").mkdir()
        (app / "Assets" / "icon.bin").write_bytes(b"public fixture")
        return app

    def make_xcresult(self) -> Path:
        result = self.root / "tests.xcresult"
        result.mkdir()
        (result / "Info.plist").write_bytes(plistlib.dumps({"version": "3.0"}))
        (result / "Data").mkdir()
        (result / "Data" / "data.0").write_bytes(b"safe test result")
        return result

    def contract(self) -> SimulatorTestContract:
        return SimulatorTestContract(
            container=Path("/candidate/kmp_module/iosApp/DobbyVPN.xcodeproj"),
            container_kind="project",
            scheme="DobbyVPN Simulator",
            bundle_identifier=BUNDLE,
            test_identifier=TEST,
            architecture="arm64",
        )

    def test_app_contract_hashes_declared_executable_and_manifest_is_stable(self) -> None:
        app = self.make_app()
        result = inspect_simulator_app(
            app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="aarch64"
        )
        manifest = result.manifest_v1()

        self.assertEqual(result.architecture, "arm64")
        self.assertEqual(result.executable_sha256, hashlib.sha256((app / "Dobby VPN").read_bytes()).hexdigest())
        self.assertEqual(manifest["source"], {"repository": "DobbyVPN/DobbyVPN", "commit": "a" * 40})
        self.assertEqual(json.loads(result.manifest_json_v1())["artifact"]["format"], "app-directory")
        self.assertEqual(result.manifest_json_v1(), result.manifest_json_v1())

    def test_app_contract_rejects_wrong_identity_architecture_and_missing_executable(self) -> None:
        app = self.make_app(bundle="com.example.other")
        with self.assertRaisesRegex(IOSSimulatorContractError, "bundle identifier"):
            inspect_simulator_app(app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64")

        app = self.make_app(executable=fake_macho(0x01000007))
        with self.assertRaisesRegex(IOSSimulatorContractError, "architecture"):
            inspect_simulator_app(app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64")

        app = self.make_app()
        (app / "Dobby VPN").unlink()
        with self.assertRaisesRegex(IOSSimulatorContractError, "missing"):
            inspect_simulator_app(app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64")

    def test_app_contract_rejects_symlinks_oversized_members_and_credential_markers_without_echoing_them(self) -> None:
        app = self.make_app()
        try:
            (app / "linked").symlink_to(app / "Assets" / "icon.bin")
        except OSError as error:  # pragma: no cover - unusual developer setup
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaisesRegex(IOSSimulatorContractError, "symbolic links"):
            inspect_simulator_app(app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64")

        (app / "linked").unlink()
        secret = b"ghp_this_must_not_appear_in_diagnostics"
        (app / "Assets" / "credential.bin").write_bytes(secret)
        with self.assertRaises(IOSSimulatorContractError) as raised:
            inspect_simulator_app(app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64")
        self.assertIn("credential marker", str(raised.exception))
        self.assertNotIn(secret.decode(), str(raised.exception))

        (app / "Assets" / "credential.bin").unlink()
        (app / "Assets" / "ordinary.bin").write_bytes(b"compiled-AKIA-AIza-ghp_-xoxb-fragments")
        inspect_simulator_app(
            app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64"
        )
        (app / "Assets" / "ordinary.bin").unlink()
        (app / "Assets" / "large.bin").write_bytes(b"0123456789")
        with self.assertRaisesRegex(IOSSimulatorContractError, "size limit"):
            inspect_simulator_app(
                app, source=SOURCE, expected_bundle_identifier=BUNDLE, architecture="arm64",
                limits=TreeLimits(max_file_bytes=8),
            )

    def test_xcresult_contract_requires_safe_directory_and_info_plist(self) -> None:
        result = self.make_xcresult()
        inspected = inspect_xcresult_bundle(result, source=SOURCE, required_test_identifier=TEST)
        self.assertEqual(inspected.file_count, 2)
        self.assertEqual(json.loads(inspected.manifest_json_v1())["artifact"]["format"], "xcresult-directory")

        (result / "Info.plist").unlink()
        with self.assertRaisesRegex(IOSSimulatorContractError, "Info.plist"):
            inspect_xcresult_bundle(result, source=SOURCE, required_test_identifier=TEST)

        wrong = self.root / "not-result"
        wrong.mkdir()
        with self.assertRaisesRegex(IOSSimulatorContractError, "wrong suffix"):
            inspect_xcresult_bundle(wrong, source=SOURCE, required_test_identifier=TEST)

    def test_safe_command_vectors_reject_injection_shaped_inputs(self) -> None:
        command = xcodebuild_test_command(
            self.contract(), device_udid=UDID, result_bundle=self.root / "tests.xcresult"
        )
        self.assertEqual(command[:5], ["xcodebuild", "test", "-project", "/candidate/kmp_module/iosApp/DobbyVPN.xcodeproj", "-scheme"])
        self.assertIn(f"id={UDID}", command)
        self.assertIn(f"-only-testing:{TEST}", command)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", command)
        self.assertEqual(simctl_boot_command(UDID), ["xcrun", "simctl", "boot", UDID])
        self.assertEqual(simctl_bootstatus_command(UDID), ["xcrun", "simctl", "bootstatus", UDID, "-b"])
        self.assertEqual(simctl_install_command(UDID, "/tmp/Dobby VPN.app")[-1], "/tmp/Dobby VPN.app")
        self.assertEqual(simctl_launch_command(UDID, BUNDLE)[-1], BUNDLE)
        self.assertEqual(simctl_terminate_command(UDID, BUNDLE)[-1], BUNDLE)
        self.assertEqual(xcresult_summary_command(self.root / "tests.xcresult")[-1], str(self.root / "tests.xcresult"))
        with self.assertRaisesRegex(IOSSimulatorContractError, "UDID"):
            xcodebuild_test_command(self.contract(), device_udid="$(evil)", result_bundle="tests.xcresult")
        with self.assertRaisesRegex(IOSSimulatorContractError, "test identifier"):
            SimulatorTestContract(
                container=Path("DobbyVPN.xcodeproj"), container_kind="project", scheme="DobbyVPN",
                bundle_identifier=BUNDLE, test_identifier="test; rm -rf /", architecture="arm64",
            )
        with self.assertRaisesRegex(IOSSimulatorContractError, r"\.app"):
            simctl_install_command(UDID, "not-an-app")

    def test_xcresult_summary_requires_passes_and_no_failures(self) -> None:
        validate_xcresult_summary('{"passedTests": 3, "failedTests": 0}')
        with self.assertRaisesRegex(IOSSimulatorContractError, "no passed"):
            validate_xcresult_summary('{"passedTests": 0, "failedTests": 0}')
        with self.assertRaisesRegex(IOSSimulatorContractError, "failed"):
            validate_xcresult_summary('{"passedTests": 1, "failedTests": 1}')
        with self.assertRaisesRegex(IOSSimulatorContractError, "JSON"):
            validate_xcresult_summary("not JSON")

    def test_source_identity_wrapper_requires_an_exact_clean_checkout(self) -> None:
        candidate = self.root / "candidate"
        candidate.mkdir()
        subprocess.run(["git", "init", "-q", str(candidate)], check=True)
        subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Torturer"], check=True)
        subprocess.run(
            ["git", "-C", str(candidate), "config", "user.email", "torturer@example.invalid"],
            check=True,
        )
        (candidate / "tracked.txt").write_text("clean\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(candidate), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(candidate), "commit", "-qm", "fixture"], check=True)
        commit = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", "HEAD"],
            check=True, text=True, capture_output=True,
        ).stdout.strip()

        identity = source_identity_from_simulator_checkout(
            candidate, repository="DobbyVPN/DobbyVPN", expected_commit=commit
        )
        self.assertEqual(identity.commit, commit)
        (candidate / "tracked.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(IOSSimulatorContractError, "modified tracked"):
            source_identity_from_simulator_checkout(
                candidate, repository="DobbyVPN/DobbyVPN", expected_commit=commit
            )


if __name__ == "__main__":
    unittest.main()
