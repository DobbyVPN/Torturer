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
import signal
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO, Iterable, Sequence
import xml.etree.ElementTree as ElementTree
import zipfile

from torturer_checks.public_output import emit_evidence


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
MAX_RUN_SECONDS = 30 * 60
CLEANUP_RESERVE_SECONDS = 120
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
COMMAND_TERMINATION_GRACE_SECONDS = 15


# Public command failures may identify the fixed internal stage that failed,
# but must never echo an arbitrary evidence label.  Keep this map aligned with
# the labels used by the production Android checks below.  The boot-state
# probe includes a bounded sequence number in its private evidence filename;
# expose only its fixed stage name.
_ANDROID_COMMAND_STAGES = frozenset(
    {
        "source-rev-parse",
        "source-status",
        "gradle-build",
        "apkanalyzer",
        "apkanalyzer-application",
        "apkanalyzer-instrumentation",
        "sdkmanager-licenses",
        "sdkmanager-install",
        "avdmanager-create",
        "adb-wait-for-device",
        "adb-window-animation",
        "adb-transition-animation",
        "adb-animator-duration",
        "adb-install-application",
        "adb-install-instrumentation",
        "adb-enabled-packages",
        "adb-package-dump",
        "adb-launch-application",
        "adb-application-pid",
        "adb-force-stop",
        "adb-stopped-pid",
        "gradle-lifecycle-test",
    }
)
_ANDROID_BOOT_STATE_STAGE = re.compile(r"adb-boot-state-[0-9]{3}\Z")
_ANDROID_UNCLASSIFIED_STAGE = "unclassified"


def _public_command_stage(evidence_label: object) -> str:
    """Return only a fixed public stage for a production evidence label."""

    if isinstance(evidence_label, str):
        if evidence_label in _ANDROID_COMMAND_STAGES:
            return evidence_label
        if _ANDROID_BOOT_STATE_STAGE.fullmatch(evidence_label):
            return "adb-boot-state"
    return _ANDROID_UNCLASSIFIED_STAGE


class AndroidContractError(RuntimeError):
    """An artifact or public Android contract does not match the expected shape."""


class RunBudget:
    """Track one Android lane's hard deadline and reserved cleanup window."""

    def __init__(
        self,
        *,
        max_seconds: float = MAX_RUN_SECONDS,
        cleanup_reserve_seconds: float = CLEANUP_RESERVE_SECONDS,
        clock=time.monotonic,
    ) -> None:
        if max_seconds <= 0 or cleanup_reserve_seconds < 0 or cleanup_reserve_seconds >= max_seconds:
            raise ValueError("cleanup reserve must be non-negative and smaller than the run deadline")
        self.max_seconds = float(max_seconds)
        self.cleanup_reserve_seconds = float(cleanup_reserve_seconds)
        self.clock = clock
        self.started_at = clock()

    @property
    def deadline(self) -> float:
        return self.started_at + self.max_seconds

    def operation_timeout(self, requested: float | None = None) -> float:
        remaining = self.deadline - self.clock() - self.cleanup_reserve_seconds
        if remaining <= 0:
            raise AndroidContractError("Android lane exhausted its functional budget before cleanup reserve")
        if requested is None:
            return remaining
        if requested <= 0:
            raise AndroidContractError("Android command timeout must be positive")
        return min(float(requested), remaining)

    def cleanup_timeout(self) -> float:
        return max(0.0, min(self.cleanup_reserve_seconds, self.deadline - self.clock()))

    def assert_within_deadline(self) -> None:
        if self.clock() > self.deadline:
            raise AndroidContractError("Android lane exceeded its strict 1800-second deadline")


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


def _safe_evidence_stem(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return stem or "command"


def _evidence_directory(requested: Path | None) -> Path | None:
    if requested is None:
        requested = Path(tempfile.mkdtemp(prefix="torturer-android-evidence-"))
    if requested.is_symlink():
        raise AndroidContractError("Android evidence directory must not be a symlink")
    requested.mkdir(mode=0o700, parents=True, exist_ok=True)
    requested.chmod(0o700)
    return requested


def _retain_bytes(directory: Path | None, label: str, payload: bytes) -> Path | None:
    if directory is None:
        raise AndroidContractError("Android diagnostics require an owner-only evidence directory")
    directory = _evidence_directory(directory)
    assert directory is not None
    path = directory / f"{_safe_evidence_stem(label)}.raw.log"
    if path.exists() or path.is_symlink():
        raise AndroidContractError(f"refusing to overwrite existing Android evidence: {path}")
    with path.open("xb", buffering=0) as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    path.chmod(0o600)
    return path


def _process_group_alive(process: subprocess.Popen[bytes]) -> bool:
    if os.name == "nt":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _proc_descendants(root_pid: int) -> set[int]:
    """Return recursive descendants, including children that create a new session."""

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        raise AndroidContractError("cannot inspect the Android process tree because /proc is unavailable")
    parent_by_pid: dict[int, int] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_line = (entry / "stat").read_text(encoding="ascii")
            close = stat_line.rfind(")")
            fields = stat_line[close + 2 :].split()
            parent_by_pid[int(entry.name)] = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
    descendants: set[int] = set()
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        for child, child_parent in parent_by_pid.items():
            if child_parent == parent and child not in descendants:
                descendants.add(child)
                frontier.append(child)
    return descendants


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = stat_line.rfind(")")
        fields = stat_line[close + 2 :].split()
        return bool(fields) and fields[0] != "Z"
    except FileNotFoundError:
        return False
    except (OSError, ValueError, IndexError):
        return True


def _wait_for_process_tree(
    process: subprocess.Popen[bytes], tracked: set[int], timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        tracked.update(_proc_descendants(process.pid))
        if (
            process.poll() is not None
            and not _process_group_alive(process)
            and not any(_pid_alive(pid) for pid in tracked if pid != process.pid)
        ):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            pass


def _terminate_process_tree(
    process: subprocess.Popen[bytes], *, grace_seconds: float, description: str,
    tracked: set[int] | None = None,
) -> set[int]:
    tracked = tracked if tracked is not None else set()
    tracked.update({process.pid} | _proc_descendants(process.pid))
    if os.name == "nt":
        process.terminate()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for pid in tracked:
            if pid != process.pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
    if _wait_for_process_tree(process, tracked, grace_seconds):
        return tracked
    print(f"[android-process] {description} graceful-stop-expired", file=sys.stderr)
    if os.name == "nt":
        process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        tracked.update(_proc_descendants(process.pid))
        for pid in tracked:
            if pid != process.pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    if not _wait_for_process_tree(process, tracked, max(1.0, grace_seconds)):
        raise AndroidContractError(f"{description} process tree survived forced termination")
    return tracked


def _run(
    command: Sequence[str | Path], *, cwd: Path | None = None, env: dict[str, str] | None = None,
    input_text: str | None = None, timeout: float | None = None, allow_nonzero: bool = False,
    budget: RunBudget | None = None, evidence_directory: Path | None = None,
    evidence_label: str = "command",
) -> subprocess.CompletedProcess[str]:
    """Run a bounded argument-vector command and retain complete original output."""

    rendered = [str(item) for item in command]
    command_stage = _public_command_stage(evidence_label)
    requested_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT_SECONDS
    command_timeout = budget.operation_timeout(requested_timeout) if budget else requested_timeout
    evidence_directory = _evidence_directory(evidence_directory)
    try:
        process = subprocess.Popen(
            rendered,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
    except OSError as error:
        _retain_bytes(evidence_directory, f"{evidence_label}.exception", str(error).encode())
        raise AndroidContractError(
            f"Android command could not start (stage={command_stage}; {type(error).__name__}); "
            "diagnostics retained privately"
        ) from error
    tracked: set[int] = {process.pid}
    timed_out = False
    output = b""
    termination_error: AndroidContractError | None = None
    try:
        output, _ = process.communicate(
            input=input_text.encode() if input_text is not None else None,
            timeout=command_timeout,
        )
    except subprocess.TimeoutExpired as error:
        timed_out = True
        output = error.output or b""
        print(
            f"[android-contract-command] stage={command_stage} timeout after {command_timeout:g}s; "
            "terminating process tree",
            file=sys.stderr,
        )
        try:
            tracked = _terminate_process_tree(
                process,
                grace_seconds=min(COMMAND_TERMINATION_GRACE_SECONDS, max(1.0, command_timeout)),
                description="command",
                tracked=tracked,
            )
        except AndroidContractError as cleanup_error:
            termination_error = cleanup_error
        try:
            recovered, _ = process.communicate(timeout=max(1.0, COMMAND_TERMINATION_GRACE_SECONDS))
            output += recovered or b""
        except subprocess.TimeoutExpired as drain_error:
            output += drain_error.output or b""
            termination_error = termination_error or AndroidContractError(
                "Android command process tree and diagnostic pipe survived final cleanup"
            )
        try:
            if not _wait_for_process_tree(process, tracked, 0.0):
                termination_error = termination_error or AndroidContractError(
                    "Android command process tree remained after final diagnostic drain"
                )
        except AndroidContractError as cleanup_error:
            termination_error = termination_error or cleanup_error
    _retain_bytes(evidence_directory, evidence_label, output)
    emit_evidence(
        "android-command",
        status=("timed-out" if timed_out else ("failed" if process.returncode else "completed")),
        payloads={"combined": output},
    )
    if timed_out:
        cleanup_detail = f"; cleanup={termination_error}" if termination_error is not None else ""
        raise AndroidContractError(
            f"Android command timed out (stage={command_stage}) after {command_timeout:g}s{cleanup_detail}; "
            "complete diagnostics retained privately"
        )
    if process.returncode and not allow_nonzero:
        raise AndroidContractError(
            f"Android command failed (stage={command_stage}; code={process.returncode}); "
            "complete diagnostics retained privately"
        )
    return subprocess.CompletedProcess(rendered, process.returncode, output.decode("utf-8", errors="replace"))


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


def verify_candidate_commit(
    candidate_root: Path,
    commit_sha: str,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    """Ensure a build is made from the full SHA already selected by the caller."""

    _require(bool(COMMIT_SHA.fullmatch(commit_sha)), "commit_sha must be a lowercase full 40-character SHA")
    resolved = _run(
        ["git", "-C", candidate_root, "rev-parse", "HEAD"],
        timeout=30,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="source-rev-parse",
    ).stdout.strip()
    _require(resolved == commit_sha, f"candidate checkout is {resolved!r}, not requested commit {commit_sha!r}")
    tracked_state = _run(
        ["git", "-C", candidate_root, "status", "--porcelain=v1", "--untracked-files=all"],
        timeout=30,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="source-status",
    ).stdout
    _require(not tracked_state.strip(), "candidate checkout has modified tracked files")


def build_candidate(
    apks: CandidateApks,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    _require(apks.gradlew.is_file(), f"candidate Gradle wrapper is missing: {apks.gradlew}")
    _run(
        build_command(apks),
        cwd=apks.root / "kmp_module",
        timeout=600,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="gradle-build",
    )
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


def _manifest_xml(
    apkanalyzer: Path,
    apk: Path,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
    evidence_label: str = "apkanalyzer",
) -> ElementTree.Element:
    output = _run(
        [apkanalyzer, "manifest", "print", apk],
        timeout=120,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label=evidence_label,
    ).stdout
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


def verify_manifests(
    apks: CandidateApks,
    apkanalyzer: Path,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    verify_application_manifest(
        _manifest_xml(
            apkanalyzer,
            apks.app_apk,
            budget=budget,
            evidence_directory=evidence_directory,
            evidence_label="apkanalyzer-application",
        )
    )
    verify_test_manifest(
        _manifest_xml(
            apkanalyzer,
            apks.test_apk,
            budget=budget,
            evidence_directory=evidence_directory,
            evidence_label="apkanalyzer-instrumentation",
        )
    )


def _sdk_environment(tools: AndroidTools, avd_home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["ANDROID_HOME"] = str(tools.sdk_root)
    env["ANDROID_SDK_ROOT"] = str(tools.sdk_root)
    env["ANDROID_AVD_HOME"] = str(avd_home)
    return env


def provision_emulator(
    tools: AndroidTools,
    *,
    avd_name: str,
    avd_home: Path,
    api_level: int = 35,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> tuple[subprocess.Popen[bytes], BinaryIO, Path]:
    """Provision and start a no-window x86_64 emulator suitable for GitHub-hosted Linux."""

    _require(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", avd_name) is not None, "AVD name contains unsupported characters")
    _require(api_level == 35, "the Android contract is pinned to API 35")
    avd_home.mkdir(parents=True, exist_ok=True)
    env = _sdk_environment(tools, avd_home)
    image = "system-images;android-35;google_apis;x86_64"
    _run(
        [tools.sdkmanager, "--licenses"],
        env=env,
        input_text="y\n" * 128,
        timeout=180,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="sdkmanager-licenses",
    )
    _run(
        [tools.sdkmanager, "--install", image],
        env=env,
        timeout=900,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="sdkmanager-install",
    )
    _run(
        [tools.avdmanager, "create", "avd", "--force", "--name", avd_name, "--package", image, "--device", "pixel"],
        env=env,
        input_text="no\n",
        timeout=120,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="avdmanager-create",
    )
    log_path = avd_home.parent / "emulator.log"
    log_handle = log_path.open("xb")
    os.chmod(log_path, 0o600)
    try:
        process = subprocess.Popen(
            [str(tools.emulator), "-avd", avd_name, "-port", "5554", "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect", "-no-snapshot", "-wipe-data"],
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception:
        log_handle.close()
        raise
    return process, log_handle, log_path


def wait_for_boot(
    tools: AndroidTools,
    *,
    emulator: subprocess.Popen[bytes] | None = None,
    timeout_seconds: int = 300,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    boot_timeout = budget.operation_timeout(timeout_seconds) if budget else timeout_seconds
    deadline = time.monotonic() + boot_timeout
    _run(
        [tools.adb, "wait-for-device"],
        timeout=min(boot_timeout, 120),
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-wait-for-device",
    )
    probe_sequence = 0
    while time.monotonic() < deadline:
        if emulator is not None and emulator.poll() is not None:
            raise AndroidContractError(
                f"Android emulator exited before boot with code {emulator.returncode}"
            )
        probe_sequence += 1
        if _run(
            [tools.adb, "shell", "getprop", "sys.boot_completed"],
            timeout=30,
            budget=budget,
            evidence_directory=evidence_directory,
            evidence_label=f"adb-boot-state-{probe_sequence:03d}",
        ).stdout.strip() == "1":
            for setting, label in (
                ("window_animation_scale", "adb-window-animation"),
                ("transition_animation_scale", "adb-transition-animation"),
                ("animator_duration_scale", "adb-animator-duration"),
            ):
                _run(
                    [tools.adb, "shell", "settings", "put", "global", setting, "0"],
                    timeout=30,
                    budget=budget,
                    evidence_directory=evidence_directory,
                    evidence_label=label,
                )
            return
        time.sleep(2)
    raise AndroidContractError("Android emulator did not complete boot within timeout")


def install_and_check_package(
    tools: AndroidTools,
    apks: CandidateApks,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    """Install exact APK outputs and exercise only public package-facing behavior."""

    _run(
        [tools.adb, "install", "-r", apks.app_apk],
        timeout=180,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-install-application",
    )
    _run(
        [tools.adb, "install", "-r", apks.test_apk],
        timeout=180,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-install-instrumentation",
    )
    enabled_packages = _run(
        enabled_package_command(tools.adb),
        timeout=30,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-enabled-packages",
    ).stdout
    _require(_contains_enabled_package(enabled_packages, PACKAGE_NAME), "installed application package is not enabled")
    package_dump = _run(
        [tools.adb, "shell", "dumpsys", "package", PACKAGE_NAME],
        timeout=60,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-package-dump",
    ).stdout
    _require(VPN_SERVICE in package_dump, "installed package does not expose the expected VPN service")
    _require("android.permission.BIND_VPN_SERVICE" in package_dump, "installed VPN service lacks its Android binding permission")
    launch = _run(
        [tools.adb, "shell", "am", "start", "-W", "-n", f"{PACKAGE_NAME}/{LAUNCHER_ACTIVITY}"],
        timeout=60,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-launch-application",
    ).stdout
    _require("Status: ok" in launch or "Activity:" in launch, "launcher activity did not start successfully")
    _require(
        bool(
            _run(
                [tools.adb, "shell", "pidof", PACKAGE_NAME],
                timeout=30,
                budget=budget,
                evidence_directory=evidence_directory,
                evidence_label="adb-application-pid",
            ).stdout.strip()
        ),
        "application process did not start",
    )
    _run(
        [tools.adb, "shell", "am", "force-stop", PACKAGE_NAME],
        timeout=30,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-force-stop",
    )
    time.sleep(1)
    stopped = _run(
        [tools.adb, "shell", "pidof", PACKAGE_NAME],
        timeout=30,
        allow_nonzero=True,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="adb-stopped-pid",
    )
    _require(not stopped.stdout.strip(), "application process remained after force-stop")


def _contains_enabled_package(output: str, package_name: str) -> bool:
    """Match a complete ``pm list packages -e`` record, never an APK path."""

    return f"package:{package_name}" in {line.strip() for line in output.splitlines()}


def enabled_package_command(adb: Path) -> list[str]:
    """Query enabled package records; ``pm path`` returns filesystem paths instead."""

    return [str(adb), "shell", "pm", "list", "packages", "-e", PACKAGE_NAME]


def run_internal_lifecycle_test(
    apks: CandidateApks,
    *,
    budget: RunBudget | None = None,
    evidence_directory: Path | None = None,
) -> None:
    """Run candidate-owned safe instrumentation, not a Torturer copy of its seam."""

    _run(
        lifecycle_test_command(apks),
        cwd=apks.root / "kmp_module",
        timeout=600,
        budget=budget,
        evidence_directory=evidence_directory,
        evidence_label="gradle-lifecycle-test",
    )


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

    budget = RunBudget()
    apks = CandidateApks.from_candidate_root(args.candidate_root)
    evidence_directory = Path(
        os.environ.get("TORTURER_ANDROID_RAW_LOG_DIR", str(args.work_dir.resolve() / "raw"))
    )
    evidence_directory = _evidence_directory(evidence_directory)
    verify_candidate_commit(apks.root, args.commit_sha, budget=budget, evidence_directory=evidence_directory)
    build_candidate(apks, budget=budget, evidence_directory=evidence_directory)
    tools = AndroidTools.discover(args.sdk_root or _default_sdk_root(apks.root))
    verify_apk_layout(apks)
    verify_manifests(apks, tools.apkanalyzer, budget=budget, evidence_directory=evidence_directory)
    if args.static_only:
        budget.assert_within_deadline()
        return 0

    emulator, emulator_log, emulator_log_path = provision_emulator(
        tools,
        avd_name=args.avd_name,
        avd_home=args.work_dir.resolve() / "avd",
        budget=budget,
        evidence_directory=evidence_directory,
    )
    failure: AndroidContractError | None = None
    try:
        wait_for_boot(tools, emulator=emulator, budget=budget, evidence_directory=evidence_directory)
        install_and_check_package(tools, apks, budget=budget, evidence_directory=evidence_directory)
        run_internal_lifecycle_test(apks, budget=budget, evidence_directory=evidence_directory)
    except Exception as error:
        failure = AndroidContractError(
            f"{error}; complete emulator diagnostics retained privately"
        )
    finally:
        try:
            _terminate_process_tree(
                emulator,
                grace_seconds=budget.cleanup_timeout(),
                description="Android emulator",
            )
        except Exception as error:
            cleanup_error = AndroidContractError(f"Android emulator cleanup failed: {error}")
            failure = cleanup_error if failure is None else AndroidContractError(f"{failure}; {cleanup_error}")
        emulator_log.flush()
        os.fsync(emulator_log.fileno())
        try:
            evidence_path = evidence_directory / "emulator.raw.log"
            if not evidence_path.exists() and not evidence_path.is_symlink():
                emulator_payload = emulator_log_path.read_bytes()
                _retain_bytes(evidence_directory, "emulator", emulator_payload)
                emit_evidence(
                    "android-emulator",
                    status=("failed" if failure is not None else "retained"),
                    payloads={"combined": emulator_payload},
                )
        except (OSError, AndroidContractError) as retention_error:
            cleanup_error = AndroidContractError(
                f"emulator diagnostics retention failed ({type(retention_error).__name__})"
            )
            failure = cleanup_error if failure is None else AndroidContractError(f"{failure}; {cleanup_error}")
        emulator_log.close()
    if failure is not None:
        raise failure
    budget.assert_within_deadline()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AndroidContractError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"android_contract status=failed code={type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from error
