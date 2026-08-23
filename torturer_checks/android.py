"""Secretless Android artifact and service-shell checks for DobbyVPN.

This module deliberately has two layers:

* independent checks of the APKs and of the installed package; and
* invocation of DobbyVPN's own ``connectedDebugAndroidTest`` lifecycle target.

The latter is not reimplemented here.  It is the only layer that can observe
the service's in-process foreground-promotion ordering.  Neither layer starts
a VPN session, supplies a profile, accepts Android VPN consent, creates a TUN,
or makes a routing/external-IP assertion.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Iterable, Sequence, TextIO
import xml.etree.ElementTree as ElementTree
import zipfile


ANDROID_NS = "http://schemas.android.com/apk/res/android"
PACKAGE_NAME = "com.dobby.vpn"
TEST_PACKAGE_NAME = f"{PACKAGE_NAME}.test"
VPN_SERVICE = "com.dobby.feature.vpn_service.DobbyVpnService"
LAUNCHER_ACTIVITY = "com.dobby.feature.main.ui.DobbySocksActivity"
INSTRUMENTATION_RUNNER = "com.dobby.TestApplicationRunner"
INTERNAL_LIFECYCLE_TEST = (
    "com.dobby.feature.vpn_service.DobbyVpnServiceInstrumentationTest"
)
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class AndroidContractError(RuntimeError):
    """An artifact or public Android contract does not match the expected shape."""


@dataclass(frozen=True)
class CandidateApks:
    """The only debug APK outputs accepted from a candidate checkout."""

    root: Path
    app_apk: Path
    test_apk: Path

    @classmethod
    def from_candidate_root(cls, candidate_root: Path) -> "CandidateApks":
        root = candidate_root.resolve()
        outputs = root / "kmp_module" / "app" / "build" / "outputs" / "apk"
        return cls(
            root=root,
            app_apk=outputs / "debug" / "app-debug.apk",
            test_apk=outputs / "androidTest" / "debug" / "app-debug-androidTest.apk",
        )

    @property
    def gradlew(self) -> Path:
        return self.root / "kmp_module" / "gradlew"


@dataclass(frozen=True)
class AndroidTools:
    """SDK command locations needed on a GitHub-hosted Linux runner."""

    sdk_root: Path
    adb: Path
    emulator: Path
    sdkmanager: Path
    avdmanager: Path
    apkanalyzer: Path

    @classmethod
    def discover(cls, sdk_root: Path) -> "AndroidTools":
        sdk_root = sdk_root.resolve()
        command_line_tools = sdk_root / "cmdline-tools" / "latest" / "bin"
        tools = cls(
            sdk_root=sdk_root,
            adb=sdk_root / "platform-tools" / "adb",
            emulator=sdk_root / "emulator" / "emulator",
            sdkmanager=command_line_tools / "sdkmanager",
            avdmanager=command_line_tools / "avdmanager",
            apkanalyzer=command_line_tools / "apkanalyzer",
        )
        missing = [str(path) for path in vars(tools).values() if isinstance(path, Path) and path != sdk_root and not path.is_file()]
        if missing:
            raise AndroidContractError("Android SDK is missing required tools: " + ", ".join(missing))
        return tools


def _android_attribute(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AndroidContractError(message)


def _run(
    command: Sequence[str | Path], *, cwd: Path | None = None, env: dict[str, str] | None = None,
    input_text: str | None = None, timeout: float | None = None, allow_nonzero: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run an argument-vector command; candidate values are never shell-expanded.

    ``allow_nonzero`` is only for status queries whose negative result is
    meaningful, such as ``pidof`` after force-stopping a package.
    """

    rendered = [str(item) for item in command]
    completed = subprocess.run(
        rendered,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    print(f"[android-contract-command] returncode={completed.returncode} output-begin")
    if completed.stdout:
        sys.stdout.write(completed.stdout)
        sys.stdout.flush()
    print("[android-contract-command] output-end")
    if completed.returncode and not allow_nonzero:
        raise AndroidContractError(
            f"command failed ({completed.returncode}): {rendered!r}\n{completed.stdout}"
        )
    return completed


def build_command(apks: CandidateApks) -> list[str]:
    """Return the exact Gradle invocation that produces both candidate APKs."""

    return [
        str(apks.gradlew),
        "--no-daemon",
        "--stacktrace",
        ":app:assembleDebug",
        ":app:assembleDebugAndroidTest",
    ]


def lifecycle_test_command(apks: CandidateApks) -> list[str]:
    """Invoke DobbyVPN's owned device test without copying its source-internal seam."""

    return [
        str(apks.gradlew),
        "--no-daemon",
        "--stacktrace",
        ":app:connectedDebugAndroidTest",
        f"-Pandroid.testInstrumentationRunnerArguments.class={INTERNAL_LIFECYCLE_TEST}",
    ]


def verify_candidate_commit(candidate_root: Path, commit_sha: str) -> None:
    """Ensure a build is made from the full SHA already selected by the caller."""

    _require(bool(COMMIT_SHA.fullmatch(commit_sha)), "commit_sha must be a lowercase full 40-character SHA")
    resolved = _run(["git", "-C", candidate_root, "rev-parse", "HEAD"]).stdout.strip()
    _require(resolved == commit_sha, f"candidate checkout is {resolved!r}, not requested commit {commit_sha!r}")
    tracked_state = _run(
        ["git", "-C", candidate_root, "status", "--porcelain=v1", "--untracked-files=no"]
    ).stdout
    _require(not tracked_state.strip(), "candidate checkout has modified tracked files")


def build_candidate(apks: CandidateApks) -> None:
    _require(apks.gradlew.is_file(), f"candidate Gradle wrapper is missing: {apks.gradlew}")
    _run(build_command(apks), cwd=apks.root / "kmp_module")
    _require(apks.app_apk.is_file(), f"Gradle did not produce the expected debug APK: {apks.app_apk}")
    _require(apks.test_apk.is_file(), f"Gradle did not produce the expected debug test APK: {apks.test_apk}")


def _safe_archive_names(apk: Path) -> set[str]:
    try:
        with zipfile.ZipFile(apk) as archive:
            names = [entry.filename for entry in archive.infolist()]
    except (OSError, zipfile.BadZipFile) as error:
        raise AndroidContractError(f"not a readable APK zip: {apk}") from error
    _require(len(names) == len(set(names)), f"APK has duplicate archive entries: {apk}")
    for name in names:
        path = Path(name)
        _require(not path.is_absolute() and ".." not in path.parts, f"APK has unsafe archive entry {name!r}")
    return set(names)


def verify_apk_layout(apks: CandidateApks) -> None:
    """Check archive structure independently of source or instrumentation code."""

    application = _safe_archive_names(apks.app_apk)
    test = _safe_archive_names(apks.test_apk)
    for names, label in ((application, "application"), (test, "instrumentation")):
        _require("AndroidManifest.xml" in names, f"{label} APK is missing AndroidManifest.xml")
        _require(any(re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", name) for name in names), f"{label} APK has no DEX payload")
        _require(not any(name.lower().endswith((".jks", ".keystore", ".p12", ".pfx", ".pem")) for name in names), f"{label} APK contains an obvious credential container")
    for required in (
        "lib/arm64-v8a/libgojni.so",
        "lib/arm64-v8a/libc++_shared.so",
        # The public runner is an x86_64 GitHub-hosted emulator.  Its native
        # payload must be present; an arm64-only APK cannot exercise it.
        "lib/x86_64/libgojni.so",
        "lib/x86_64/libc++_shared.so",
    ):
        _require(required in application, f"application APK is missing required native payload {required}")


def _manifest_xml(apkanalyzer: Path, apk: Path) -> ElementTree.Element:
    output = _run([apkanalyzer, "manifest", "print", apk]).stdout
    try:
        return ElementTree.fromstring(output)
    except ElementTree.ParseError as error:
        raise AndroidContractError(f"apkanalyzer did not emit a readable manifest for {apk}") from error


def verify_application_manifest(root: ElementTree.Element) -> None:
    _require(root.tag == "manifest", "application manifest root is not <manifest>")
    _require(root.get("package") == PACKAGE_NAME, "unexpected application package name")
    uses_sdk = root.find("uses-sdk")
    _require(uses_sdk is not None, "application manifest has no <uses-sdk>")
    _require(uses_sdk.get(_android_attribute("minSdkVersion")) == "26", "application minSdkVersion must be 26")
    _require(uses_sdk.get(_android_attribute("targetSdkVersion")) == "35", "application targetSdkVersion must be 35")
    application = root.find("application")
    _require(application is not None, "application manifest has no <application>")
    _require(application.get(_android_attribute("debuggable")) == "true", "debug APK must be debuggable")
    _require(application.get(_android_attribute("usesCleartextTraffic")) == "false", "application must disable cleartext traffic")
    permissions = {
        item.get(_android_attribute("name"))
        for item in root.findall("uses-permission")
    }
    _require(
        "android.permission.FOREGROUND_SERVICE_SPECIAL_USE" in permissions,
        "application must declare FOREGROUND_SERVICE_SPECIAL_USE",
    )
    _require(
        "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" not in permissions,
        "application must not rely on systemExempted before the VPN is active",
    )

    service = next((item for item in application.findall("service") if item.get(_android_attribute("name")) == VPN_SERVICE), None)
    _require(service is not None, "VPN service is absent from application manifest")
    _require(service.get(_android_attribute("exported")) == "true", "VPN service must be exported to Android")
    _require(service.get(_android_attribute("permission")) == "android.permission.BIND_VPN_SERVICE", "VPN service must require BIND_VPN_SERVICE")
    _require(
        service.get(_android_attribute("foregroundServiceType"))
        in {"specialUse", "0x40000000"},
        "VPN service must use the specialUse foreground-service type",
    )
    special_use = next(
        (
            item
            for item in service.findall("property")
            if item.get(_android_attribute("name"))
            == "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
        ),
        None,
    )
    _require(
        special_use is not None
        and bool(special_use.get(_android_attribute("value"), "").strip()),
        "VPN service must explain its specialUse foreground-service subtype",
    )
    actions = {action.get(_android_attribute("name")) for action in service.findall("./intent-filter/action")}
    _require("android.net.VpnService" in actions, "VPN service must advertise android.net.VpnService")

    activity = next((item for item in application.findall("activity") if item.get(_android_attribute("name")) == LAUNCHER_ACTIVITY), None)
    _require(activity is not None and activity.get(_android_attribute("exported")) == "true", "launcher activity is missing or not exported")


def verify_test_manifest(root: ElementTree.Element) -> None:
    _require(root.tag == "manifest", "test manifest root is not <manifest>")
    _require(root.get("package") == TEST_PACKAGE_NAME, "unexpected instrumentation package name")
    instrumentation = root.find("instrumentation")
    _require(instrumentation is not None, "test APK has no <instrumentation>")
    _require(instrumentation.get(_android_attribute("targetPackage")) == PACKAGE_NAME, "test APK targets the wrong application package")
    _require(instrumentation.get(_android_attribute("name")) == INSTRUMENTATION_RUNNER, "test APK uses an unexpected instrumentation runner")


def verify_manifests(apks: CandidateApks, apkanalyzer: Path) -> None:
    verify_application_manifest(_manifest_xml(apkanalyzer, apks.app_apk))
    verify_test_manifest(_manifest_xml(apkanalyzer, apks.test_apk))


def _sdk_environment(tools: AndroidTools, avd_home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["ANDROID_HOME"] = str(tools.sdk_root)
    env["ANDROID_SDK_ROOT"] = str(tools.sdk_root)
    env["ANDROID_AVD_HOME"] = str(avd_home)
    return env


def provision_emulator(
    tools: AndroidTools, *, avd_name: str, avd_home: Path, api_level: int = 35
) -> tuple[subprocess.Popen[str], TextIO, Path]:
    """Provision and start a no-window x86_64 emulator suitable for GitHub-hosted Linux."""

    _require(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", avd_name) is not None, "AVD name contains unsupported characters")
    _require(api_level == 35, "the Android contract is pinned to API 35")
    avd_home.mkdir(parents=True, exist_ok=True)
    env = _sdk_environment(tools, avd_home)
    image = "system-images;android-35;google_apis;x86_64"
    _run([tools.sdkmanager, "--licenses"], env=env, input_text="y\n" * 128, timeout=180)
    _run([tools.sdkmanager, "--install", image], env=env, timeout=900)
    _run([tools.avdmanager, "create", "avd", "--force", "--name", avd_name, "--package", image, "--device", "pixel"], env=env, input_text="no\n", timeout=120)
    log_path = avd_home.parent / "emulator.log"
    log_handle = log_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [str(tools.emulator), "-avd", avd_name, "-port", "5554", "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect", "-no-snapshot", "-wipe-data"],
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception:
        log_handle.close()
        raise
    return process, log_handle, log_path


def wait_for_boot(
    tools: AndroidTools,
    *,
    emulator: subprocess.Popen[str] | None = None,
    timeout_seconds: int = 300,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    _run([tools.adb, "wait-for-device"], timeout=min(timeout_seconds, 120))
    while time.monotonic() < deadline:
        if emulator is not None and emulator.poll() is not None:
            raise AndroidContractError(
                f"Android emulator exited before boot with code {emulator.returncode}"
            )
        if _run([tools.adb, "shell", "getprop", "sys.boot_completed"]).stdout.strip() == "1":
            _run([tools.adb, "shell", "settings", "put", "global", "window_animation_scale", "0"])
            _run([tools.adb, "shell", "settings", "put", "global", "transition_animation_scale", "0"])
            _run([tools.adb, "shell", "settings", "put", "global", "animator_duration_scale", "0"])
            return
        time.sleep(2)
    raise AndroidContractError("Android emulator did not complete boot within timeout")


def install_and_check_package(tools: AndroidTools, apks: CandidateApks) -> None:
    """Install exact APK outputs and exercise only public package-facing behavior."""

    _run([tools.adb, "install", "-r", apks.app_apk], timeout=180)
    _run([tools.adb, "install", "-r", apks.test_apk], timeout=180)
    enabled_packages = _run(enabled_package_command(tools.adb)).stdout
    _require(_contains_enabled_package(enabled_packages, PACKAGE_NAME), "installed application package is not enabled")
    package_dump = _run([tools.adb, "shell", "dumpsys", "package", PACKAGE_NAME]).stdout
    _require(VPN_SERVICE in package_dump, "installed package does not expose the expected VPN service")
    _require("android.permission.BIND_VPN_SERVICE" in package_dump, "installed VPN service lacks its Android binding permission")
    launch = _run([tools.adb, "shell", "am", "start", "-W", "-n", f"{PACKAGE_NAME}/{LAUNCHER_ACTIVITY}"]).stdout
    _require("Status: ok" in launch or "Activity:" in launch, "launcher activity did not start successfully")
    _require(bool(_run([tools.adb, "shell", "pidof", PACKAGE_NAME]).stdout.strip()), "application process did not start")
    _run([tools.adb, "shell", "am", "force-stop", PACKAGE_NAME])
    time.sleep(1)
    stopped = _run([tools.adb, "shell", "pidof", PACKAGE_NAME], allow_nonzero=True)
    _require(not stopped.stdout.strip(), "application process remained after force-stop")


def _contains_enabled_package(output: str, package_name: str) -> bool:
    """Match a complete ``pm list packages -e`` record, never an APK path."""

    return f"package:{package_name}" in {line.strip() for line in output.splitlines()}


def enabled_package_command(adb: Path) -> list[str]:
    """Query enabled package records; ``pm path`` returns filesystem paths instead."""

    return [str(adb), "shell", "pm", "list", "packages", "-e", PACKAGE_NAME]


def run_internal_lifecycle_test(apks: CandidateApks) -> None:
    """Run candidate-owned safe instrumentation, not a Torturer copy of its seam."""

    _run(lifecycle_test_command(apks), cwd=apks.root / "kmp_module", timeout=600)


def _default_sdk_root(candidate_root: Path) -> Path:
    configured = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if configured:
        return Path(configured)
    local_properties = candidate_root / "kmp_module" / "local.properties"
    if local_properties.is_file():
        for line in local_properties.read_text(encoding="utf-8").splitlines():
            if line.startswith("sdk.dir="):
                return Path(line.removeprefix("sdk.dir=").replace("\\\\", "\\"))
    raise AndroidContractError("set ANDROID_SDK_ROOT/ANDROID_HOME or pass --sdk-root")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True, help="checked-out DobbyVPN candidate at the requested SHA")
    parser.add_argument("--commit-sha", required=True, help="full lowercase candidate SHA selected by the reusable-workflow caller")
    parser.add_argument("--sdk-root", type=Path, help="Android SDK root; defaults to ANDROID_SDK_ROOT/ANDROID_HOME")
    parser.add_argument("--work-dir", type=Path, default=Path(".torturer-android"), help="writable job-local directory for the AVD")
    parser.add_argument("--avd-name", default="torturer-api35", help="ephemeral AVD name")
    parser.add_argument("--static-only", action="store_true", help="build and validate artifacts without provisioning an emulator")
    args = parser.parse_args(list(argv) if argv is not None else None)

    apks = CandidateApks.from_candidate_root(args.candidate_root)
    verify_candidate_commit(apks.root, args.commit_sha)
    build_candidate(apks)
    tools = AndroidTools.discover(args.sdk_root or _default_sdk_root(apks.root))
    verify_apk_layout(apks)
    verify_manifests(apks, tools.apkanalyzer)
    if args.static_only:
        return 0

    emulator, emulator_log, emulator_log_path = provision_emulator(
        tools,
        avd_name=args.avd_name,
        avd_home=args.work_dir.resolve() / "avd",
    )
    try:
        wait_for_boot(tools, emulator=emulator)
        install_and_check_package(tools, apks)
        run_internal_lifecycle_test(apks)
    except Exception as error:
        emulator_log.flush()
        diagnostics = emulator_log_path.read_text(encoding="utf-8", errors="replace")
        raise AndroidContractError(
            f"{error}\nemulator log:\n{diagnostics[-32768:]}"
        ) from error
    finally:
        emulator.terminate()
        try:
            emulator.wait(timeout=30)
        except subprocess.TimeoutExpired:
            emulator.kill()
            emulator.wait(timeout=10)
        emulator_log.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AndroidContractError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"Android Torturer check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
