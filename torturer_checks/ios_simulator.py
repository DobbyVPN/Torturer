"""Fail-closed, secretless evidence checks for an iOS Simulator contract.

This module intentionally does not start a Simulator or execute candidate
build logic.  H2 will use its safe argument-vector builders to drive a fixed,
public ``xcodebuild`` contract.  The checks here independently inspect the
resulting Simulator ``.app`` and XCTest result bundle.  They never accept a
shell fragment from a candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import plistlib
import re
import stat
import struct
from typing import Any

from torturer_checks.artifact import (
    ArtifactContractError,
    CREDENTIAL_SCAN_OVERLAP_BYTES,
    SourceIdentity,
    obvious_credential_marker,
    source_identity_from_checkout,
)


_ARCH_ALIASES = {"x86_64": "amd64", "aarch64": "arm64"}
_MACHO_CPUS = {0x01000007: "amd64", 0x0100000C: "arm64"}
_MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf",
    b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca",
    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
}
_STATIC_ARCHIVE_MAGIC = b"!<arch>\n"
_UDID = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\Z")
_BUNDLE_ID = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z")
_SCHEME = re.compile(r"[A-Za-z0-9 ._-]{1,100}\Z")
_TEST_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-/]{1,300}\Z")


class IOSSimulatorContractError(ValueError):
    """The public iOS Simulator evidence does not meet its contract."""


@dataclass(frozen=True)
class TreeLimits:
    """Bounds for a built app or xcresult bundle before its files are read."""

    max_files: int = 16_384
    max_file_bytes: int = 512 * 1024 * 1024
    max_total_bytes: int = 2 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_files <= 0 or self.max_file_bytes <= 0 or self.max_total_bytes <= 0:
            raise ValueError("tree limits must be positive")


@dataclass(frozen=True)
class SimulatorTestContract:
    """Fixed, public xcodebuild inputs for a future Simulator test lane."""

    container: Path
    container_kind: str
    scheme: str
    bundle_identifier: str
    test_identifier: str
    architecture: str

    def __post_init__(self) -> None:
        if self.container_kind not in {"project", "workspace"}:
            raise IOSSimulatorContractError("container kind must be project or workspace")
        expected_suffix = ".xcodeproj" if self.container_kind == "project" else ".xcworkspace"
        if self.container.suffix != expected_suffix:
            raise IOSSimulatorContractError(f"{self.container_kind} container has the wrong suffix")
        if not _SCHEME.fullmatch(self.scheme):
            raise IOSSimulatorContractError("scheme contains unsupported characters")
        _validate_bundle_identifier(self.bundle_identifier)
        _validate_test_identifier(self.test_identifier)
        if _normalize_architecture(self.architecture) not in _MACHO_CPUS.values():
            raise IOSSimulatorContractError("unsupported Simulator architecture")

    @property
    def container_flag(self) -> str:
        return "-project" if self.container_kind == "project" else "-workspace"

    @property
    def normalized_architecture(self) -> str:
        return _normalize_architecture(self.architecture)


@dataclass(frozen=True)
class SimulatorAppInspection:
    """Validated, serializable evidence for a built iOS Simulator application."""

    source: SourceIdentity
    app_path: Path
    bundle_identifier: str
    architecture: str
    executable_name: str
    executable_sha256: str
    executable_size_bytes: int
    file_count: int
    total_size_bytes: int

    def manifest_v1(self) -> dict[str, object]:
        return {
            "schema": 1,
            "source": {"repository": self.source.repository, "commit": self.source.commit},
            "artifact": {
                "platform": "ios-simulator",
                "format": "app-directory",
                "file": self.app_path.name,
                "bundle_identifier": self.bundle_identifier,
                "architecture": self.architecture,
            },
            "components": [{
                "path": f"{self.app_path.name}/{self.executable_name}",
                "sha256": self.executable_sha256,
                "size_bytes": self.executable_size_bytes,
                "architecture": self.architecture,
            }],
            "tree": {"file_count": self.file_count, "size_bytes": self.total_size_bytes},
        }

    def manifest_json_v1(self) -> str:
        return json.dumps(self.manifest_v1(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class XCResultInspection:
    """Validated, serializable evidence for one XCTest result bundle."""

    source: SourceIdentity
    result_path: Path
    required_test_identifier: str
    file_count: int
    total_size_bytes: int

    def manifest_v1(self) -> dict[str, object]:
        return {
            "schema": 1,
            "source": {"repository": self.source.repository, "commit": self.source.commit},
            "artifact": {
                "platform": "ios-simulator",
                "format": "xcresult-directory",
                "file": self.result_path.name,
            },
            "required_test_identifier": self.required_test_identifier,
            "tree": {"file_count": self.file_count, "size_bytes": self.total_size_bytes},
        }

    def manifest_json_v1(self) -> str:
        return json.dumps(self.manifest_v1(), sort_keys=True, separators=(",", ":"))


def source_identity_from_simulator_checkout(
    checkout: str | Path, *, repository: str, expected_commit: str
) -> SourceIdentity:
    """Prove candidate identity using the same exact-clean rule as other artifacts."""
    try:
        return source_identity_from_checkout(
            checkout, repository=repository, expected_commit=expected_commit
        )
    except ArtifactContractError as error:
        raise IOSSimulatorContractError(str(error)) from error


def inspect_simulator_app(
    app: str | Path,
    *,
    source: SourceIdentity,
    expected_bundle_identifier: str,
    architecture: str,
    limits: TreeLimits = TreeLimits(),
) -> SimulatorAppInspection:
    """Inspect a built Simulator app without following links or executing it."""
    source = _validated_source(source)
    _validate_bundle_identifier(expected_bundle_identifier)
    normalized_architecture = _normalize_architecture(architecture)
    if normalized_architecture not in _MACHO_CPUS.values():
        raise IOSSimulatorContractError("unsupported Simulator architecture")
    app_path = _required_directory(Path(app), suffix=".app", label="Simulator app")
    files, total_size = _scan_tree(app_path, limits=limits)
    info_path = app_path / "Info.plist"
    if info_path not in files:
        raise IOSSimulatorContractError("Simulator app is missing Info.plist")
    info_data = _read_file(info_path, maximum=2 * 1024 * 1024)
    try:
        plist = plistlib.loads(info_data)
    except (TypeError, ValueError) as error:
        raise IOSSimulatorContractError("Simulator app Info.plist is invalid") from error
    if not isinstance(plist, dict):
        raise IOSSimulatorContractError("Simulator app Info.plist is invalid")
    if plist.get("CFBundlePackageType") != "APPL":
        raise IOSSimulatorContractError("Simulator app Info.plist is not an application bundle")
    if plist.get("CFBundleIdentifier") != expected_bundle_identifier:
        raise IOSSimulatorContractError("Simulator app bundle identifier differs from the contract")
    executable_name = plist.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not _simple_name(executable_name):
        raise IOSSimulatorContractError("Simulator app executable name is invalid")
    executable = app_path / executable_name
    if executable not in files:
        raise IOSSimulatorContractError("Simulator app is missing its declared executable")
    executable_sha256, executable_size = _hash_file(executable)
    if normalized_architecture not in _macho_architectures(_read_file(executable, maximum=4096)):
        raise IOSSimulatorContractError("Simulator app executable architecture differs from the contract")
    return SimulatorAppInspection(
        source=source,
        app_path=app_path,
        bundle_identifier=expected_bundle_identifier,
        architecture=normalized_architecture,
        executable_name=executable_name,
        executable_sha256=executable_sha256,
        executable_size_bytes=executable_size,
        file_count=len(files),
        total_size_bytes=total_size,
    )


def inspect_xcresult_bundle(
    result: str | Path,
    *,
    source: SourceIdentity,
    required_test_identifier: str,
    limits: TreeLimits = TreeLimits(),
) -> XCResultInspection:
    """Inspect a result bundle's safe on-disk shape before querying it with xcrun."""
    source = _validated_source(source)
    _validate_test_identifier(required_test_identifier)
    result_path = _required_directory(Path(result), suffix=".xcresult", label="xcresult bundle")
    files, total_size = _scan_tree(result_path, limits=limits)
    info_path = result_path / "Info.plist"
    if info_path not in files:
        raise IOSSimulatorContractError("xcresult bundle is missing Info.plist")
    try:
        info = plistlib.loads(_read_file(info_path, maximum=2 * 1024 * 1024))
    except (TypeError, ValueError) as error:
        raise IOSSimulatorContractError("xcresult bundle Info.plist is invalid") from error
    if not isinstance(info, dict):
        raise IOSSimulatorContractError("xcresult bundle Info.plist is invalid")
    return XCResultInspection(
        source=source,
        result_path=result_path,
        required_test_identifier=required_test_identifier,
        file_count=len(files),
        total_size_bytes=total_size,
    )


def xcodebuild_test_command(
    contract: SimulatorTestContract, *, device_udid: str, result_bundle: str | Path
) -> list[str]:
    """Build an argument vector for the fixed public Simulator test target."""
    result_path = _result_bundle_path(result_bundle)
    return [
        "xcodebuild", "test", contract.container_flag, str(contract.container),
        "-scheme", contract.scheme, "-destination", f"id={_validate_udid(device_udid)}",
        f"-only-testing:{contract.test_identifier}", "-resultBundlePath", str(result_path),
        "CODE_SIGNING_ALLOWED=NO",
    ]


def simctl_boot_command(device_udid: str) -> list[str]:
    return ["xcrun", "simctl", "boot", _validate_udid(device_udid)]


def simctl_bootstatus_command(device_udid: str) -> list[str]:
    """Wait for one validated Simulator device to finish booting."""
    return ["xcrun", "simctl", "bootstatus", _validate_udid(device_udid), "-b"]


def simctl_install_command(device_udid: str, app: str | Path) -> list[str]:
    app_path = Path(app)
    if app_path.suffix != ".app":
        raise IOSSimulatorContractError("Simulator install path must end in .app")
    return ["xcrun", "simctl", "install", _validate_udid(device_udid), str(app_path)]


def simctl_launch_command(device_udid: str, bundle_identifier: str) -> list[str]:
    _validate_bundle_identifier(bundle_identifier)
    return ["xcrun", "simctl", "launch", _validate_udid(device_udid), bundle_identifier]


def simctl_terminate_command(device_udid: str, bundle_identifier: str) -> list[str]:
    _validate_bundle_identifier(bundle_identifier)
    return ["xcrun", "simctl", "terminate", _validate_udid(device_udid), bundle_identifier]


def xcresult_summary_command(result_bundle: str | Path) -> list[str]:
    """Return the xcrun query H2 can run after safe bundle inspection."""
    return [
        "xcrun", "xcresulttool", "get", "test-results", "summary", "--path",
        str(_result_bundle_path(result_bundle)),
    ]


def validate_xcresult_summary(summary_json: str) -> None:
    """Require a non-empty, failure-free XCTest summary JSON document.

    H2 obtains this JSON only from the host ``xcresulttool`` command above.
    The check intentionally handles the stable count names emitted by several
    Xcode generations without parsing candidate log text.
    """
    try:
        summary = json.loads(summary_json)
    except (TypeError, ValueError) as error:
        raise IOSSimulatorContractError("xcresult summary is not valid JSON") from error
    if not isinstance(summary, (dict, list)):
        raise IOSSimulatorContractError("xcresult summary has an invalid shape")
    counts = _summary_counts(summary)
    if not counts["passed"]:
        raise IOSSimulatorContractError("xcresult summary reports no passed tests")
    if counts["failed"]:
        raise IOSSimulatorContractError("xcresult summary reports failed tests")


def _scan_tree(root: Path, *, limits: TreeLimits) -> tuple[frozenset[Path], int]:
    files: set[Path] = set()
    total_size = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError as error:
            raise IOSSimulatorContractError("artifact directory could not be read") from error
        for entry in entries:
            try:
                mode = entry.lstat().st_mode
            except OSError as error:
                raise IOSSimulatorContractError("artifact member could not be inspected") from error
            if stat.S_ISLNK(mode):
                raise IOSSimulatorContractError("artifact contains symbolic links")
            if stat.S_ISDIR(mode):
                pending.append(entry)
                continue
            if not stat.S_ISREG(mode):
                raise IOSSimulatorContractError("artifact contains an unsupported filesystem member")
            if entry.stat().st_size > limits.max_file_bytes:
                raise IOSSimulatorContractError("artifact member exceeds size limit")
            files.add(entry)
            if len(files) > limits.max_files:
                raise IOSSimulatorContractError("artifact has too many files")
            total_size += entry.stat().st_size
            if total_size > limits.max_total_bytes:
                raise IOSSimulatorContractError("artifact exceeds total size limit")
            _reject_credentials_in_file(entry)
    return frozenset(files), total_size


def _required_directory(path: Path, *, suffix: str, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise IOSSimulatorContractError(f"{label} is unavailable") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise IOSSimulatorContractError(f"{label} must be a non-symlink directory")
    if path.suffix != suffix:
        raise IOSSimulatorContractError(f"{label} has the wrong suffix")
    return path


def _read_file(path: Path, *, maximum: int) -> bytes:
    try:
        size = path.stat().st_size
        if size > maximum:
            raise IOSSimulatorContractError("artifact member exceeds inspection size limit")
        data = path.read_bytes()
    except OSError as error:
        raise IOSSimulatorContractError("artifact member could not be read") from error
    if len(data) != size:
        raise IOSSimulatorContractError("artifact member changed while it was inspected")
    return data


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    try:
        before = path.stat()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
    except OSError as error:
        raise IOSSimulatorContractError("artifact member could not be read") from error
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise IOSSimulatorContractError("artifact member changed while it was inspected")
    return digest.hexdigest(), before.st_size


def _reject_credentials_in_file(path: Path) -> None:
    previous = b""
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                # Compiled executables contain token-format parser constants
                # from dependencies (for example PEM headers), not embedded
                # credentials. Source secret scanning covers executable input;
                # this artifact pass protects plists and bundled resources.
                if not previous and chunk[:4] in _MACHO_MAGICS:
                    return
                # Static archives also contain dependency token-format parser
                # constants rather than embedded credentials. Keep scanning
                # every ordinary resource, including opaque binary resources.
                if not previous and chunk.startswith(_STATIC_ARCHIVE_MAGIC):
                    return
                marker = obvious_credential_marker(previous + chunk)
                if marker:
                    suffix = path.suffix.lower()
                    safe_suffix = suffix if re.fullmatch(r"\.[a-z0-9]{1,16}", suffix) else "<other>"
                    name = path.name
                    safe_name = name if re.fullmatch(r"[A-Za-z0-9._ -]{1,100}", name) else "<other>"
                    raise IOSSimulatorContractError(
                        "artifact contains an obvious credential marker "
                        f"(category={marker}, member={safe_name}, suffix={safe_suffix})"
                    )
                previous = (previous + chunk)[-CREDENTIAL_SCAN_OVERLAP_BYTES:]
    except OSError as error:
        raise IOSSimulatorContractError("artifact member could not be read") from error

def _macho_architectures(data: bytes) -> set[str]:
    if len(data) < 8:
        raise IOSSimulatorContractError("Simulator app executable is not a Mach-O file")
    magic = data[:4]
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        count = struct.unpack_from(">I", data, 4)[0]
        entry_size = 32 if magic == b"\xca\xfe\xba\xbf" else 20
        if count == 0 or count > 32 or 8 + count * entry_size > len(data):
            raise IOSSimulatorContractError("Simulator app executable has an invalid Mach-O header")
        architectures = {
            _MACHO_CPUS[cpu]
            for offset in range(8, 8 + count * entry_size, entry_size)
            if (cpu := struct.unpack_from(">I", data, offset)[0]) in _MACHO_CPUS
        }
    else:
        byte_order = {
            b"\xcf\xfa\xed\xfe": "<", b"\xce\xfa\xed\xfe": "<",
            b"\xfe\xed\xfa\xcf": ">", b"\xfe\xed\xfa\xce": ">",
        }.get(magic)
        if byte_order is None:
            raise IOSSimulatorContractError("Simulator app executable is not a Mach-O file")
        cpu = struct.unpack_from(byte_order + "I", data, 4)[0]
        architectures = {_MACHO_CPUS[cpu]} if cpu in _MACHO_CPUS else set()
    if not architectures:
        raise IOSSimulatorContractError("Simulator app executable has an unsupported architecture")
    return architectures


def _summary_counts(value: Any) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0}
    pass_keys = {"passedTests", "passedTestCount", "numberOfPassedTests"}
    fail_keys = {"failedTests", "failedTestCount", "numberOfFailedTests"}
    if isinstance(value, dict):
        for key, item in value.items():
            if key in pass_keys and isinstance(item, int) and not isinstance(item, bool):
                counts["passed"] += item
            elif key in fail_keys and isinstance(item, int) and not isinstance(item, bool):
                counts["failed"] += item
            nested = _summary_counts(item)
            counts["passed"] += nested["passed"]
            counts["failed"] += nested["failed"]
    elif isinstance(value, list):
        for item in value:
            nested = _summary_counts(item)
            counts["passed"] += nested["passed"]
            counts["failed"] += nested["failed"]
    return counts


def _validated_source(source: SourceIdentity) -> SourceIdentity:
    if not isinstance(source, SourceIdentity):
        raise IOSSimulatorContractError("source must be a SourceIdentity")
    try:
        return SourceIdentity.create(repository=source.repository, commit=source.commit)
    except ArtifactContractError as error:
        raise IOSSimulatorContractError(str(error)) from error


def _normalize_architecture(architecture: str) -> str:
    if not isinstance(architecture, str):
        raise IOSSimulatorContractError("architecture must be a string")
    return _ARCH_ALIASES.get(architecture, architecture)


def _simple_name(value: str) -> bool:
    return bool(value) and value not in {".", ".."} and "/" not in value and "\\" not in value and "\x00" not in value


def _validate_bundle_identifier(value: str) -> None:
    if not isinstance(value, str) or not _BUNDLE_ID.fullmatch(value):
        raise IOSSimulatorContractError("bundle identifier has an unsupported format")


def _validate_test_identifier(value: str) -> None:
    if not isinstance(value, str) or not _TEST_IDENTIFIER.fullmatch(value):
        raise IOSSimulatorContractError("test identifier has unsupported characters")


def _validate_udid(value: str) -> str:
    if not isinstance(value, str) or not _UDID.fullmatch(value):
        raise IOSSimulatorContractError("Simulator UDID has an unsupported format")
    return value.upper()


def _result_bundle_path(value: str | Path) -> Path:
    path = Path(value)
    if path.suffix != ".xcresult":
        raise IOSSimulatorContractError("result bundle path must end in .xcresult")
    return path
