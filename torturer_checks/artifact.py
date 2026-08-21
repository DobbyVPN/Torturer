"""Fail-closed public contracts for desktop ZIP artifacts.

This module deliberately uses only the Python standard library.  It does not
extract an untrusted archive: layout checks, member hashing, architecture
parsing, and the narrow credential-marker scan all read ZIP members directly.
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
import subprocess
from typing import Iterable
import zipfile


_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_REPOSITORY_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
    r"/[A-Za-z0-9_.-]{1,100}"
)
_WINDOWS_MACHINES = {0x8664: "amd64", 0xAA64: "arm64", 0x14C: "x86"}
_MACHO_CPUS = {0x01000007: "amd64", 0x0100000C: "arm64"}
_ARCH_ALIASES = {"x86_64": "amd64", "aarch64": "arm64"}

# Labels, rather than matched bytes, are intentionally reported.  Require a
# plausible complete token shape: short prefixes such as AKIA legitimately
# occur in compiled binaries and are not credentials by themselves.
_CREDENTIAL_PATTERNS = (
    ("private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----", re.IGNORECASE)),
    ("aws-access-key", re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("github-token", re.compile(rb"ghp_[A-Za-z0-9_]{20,}")),
    ("github-fine-grained-token", re.compile(rb"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack-bot-token", re.compile(rb"xoxb-[A-Za-z0-9-]{20,}")),
    ("slack-user-token", re.compile(rb"xoxp-[A-Za-z0-9-]{20,}")),
    ("slack-app-token", re.compile(rb"xapp-[A-Za-z0-9-]{20,}")),
    ("google-api-key", re.compile(rb"AIza[A-Za-z0-9_-]{30,}")),
)
CREDENTIAL_SCAN_OVERLAP_BYTES = 128


class ArtifactContractError(ValueError):
    """An artifact or its recorded identity does not meet the public contract."""


@dataclass(frozen=True)
class ArchiveLimits:
    """Bounds applied before reading untrusted ZIP member data."""

    max_entries: int = 4096
    max_member_bytes: int = 256 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_compression_ratio: int = 200

    def __post_init__(self) -> None:
        if (
            self.max_entries <= 0
            or self.max_member_bytes <= 0
            or self.max_total_bytes <= 0
            or self.max_compression_ratio <= 0
        ):
            raise ValueError("archive limits must be positive")


@dataclass(frozen=True)
class SourceIdentity:
    """The immutable public source identity recorded beside an artifact."""

    repository: str
    commit: str

    @classmethod
    def create(cls, *, repository: str, commit: str) -> "SourceIdentity":
        if not _REPOSITORY_RE.fullmatch(repository):
            raise ArtifactContractError("source repository must be a GitHub owner/repository slug")
        owner, name = repository.split("/", maxsplit=1)
        if owner in {".", ".."} or name in {".", ".."}:
            raise ArtifactContractError("source repository must not contain path-navigation segments")
        if not _COMMIT_RE.fullmatch(commit):
            raise ArtifactContractError("source commit must be a lowercase full 40-character SHA")
        return cls(repository=repository, commit=commit)


@dataclass(frozen=True)
class ArtifactInspection:
    """Validated, serializable evidence for one desktop artifact."""

    source: SourceIdentity
    platform: str
    architecture: str
    artifact_path: Path
    artifact_sha256: str
    artifact_size_bytes: int
    components: tuple[dict[str, object], ...]

    def manifest_v1(
        self,
        *,
        workflow_revision: str | None = None,
        runner_os: str | None = None,
        runner_arch: str | None = None,
    ) -> dict[str, object]:
        """Return deterministic manifest schema v1.

        Callers that need runner/build attribution must pass fixed observed
        values.  Timestamps are intentionally absent so identical evidence has
        identical JSON.
        """
        manifest: dict[str, object] = {
            "schema": 1,
            "source": {"repository": self.source.repository, "commit": self.source.commit},
            "artifact": {
                "platform": self.platform,
                "format": "zip",
                "file": self.artifact_path.name,
                "sha256": self.artifact_sha256,
                "size_bytes": self.artifact_size_bytes,
                "architecture": self.architecture,
            },
            "components": list(self.components),
        }
        if runner_os is not None or runner_arch is not None:
            if not runner_os or not runner_arch:
                raise ArtifactContractError("runner os and architecture must be supplied together")
            manifest["runner"] = {"os": runner_os, "arch": runner_arch}
        if workflow_revision is not None:
            if not _COMMIT_RE.fullmatch(workflow_revision):
                raise ArtifactContractError("workflow revision must be a lowercase full 40-character SHA")
            manifest["build"] = {"workflow_revision": workflow_revision}
        return manifest

    def manifest_json_v1(self, **kwargs: str) -> str:
        """Return the manifest in stable compact JSON form."""
        return json.dumps(self.manifest_v1(**kwargs), sort_keys=True, separators=(",", ":"))


def source_identity_from_checkout(
    checkout: str | Path, *, repository: str, expected_commit: str
) -> SourceIdentity:
    """Prove that a checked-out repository is exactly ``expected_commit``.

    This intentionally compares complete SHA values, never a ref or prefix.
    Git is invoked without a shell and only to read the checkout's resolved
    ``HEAD``; no candidate-controlled values are executed.
    """
    expected = SourceIdentity.create(repository=repository, commit=expected_commit)
    directory = Path(checkout)
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--verify", "HEAD^{commit}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ArtifactContractError("could not resolve checked-out source commit") from error
    resolved = result.stdout.strip()
    if result.returncode != 0 or not _COMMIT_RE.fullmatch(resolved):
        raise ArtifactContractError("could not resolve checked-out source commit")
    if resolved != expected.commit:
        raise ArtifactContractError("checked-out source commit differs from requested commit")
    try:
        status = subprocess.run(
            [
                "git",
                "-C",
                str(directory),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ArtifactContractError("could not verify checked-out source state") from error
    if status.returncode != 0:
        raise ArtifactContractError("could not verify checked-out source state")
    if status.stdout.strip():
        raise ArtifactContractError("checked-out source has modified tracked files")
    return expected


def inspect_windows_zip(
    artifact: str | Path,
    *,
    source: SourceIdentity,
    architecture: str = "amd64",
    executable_path: str = "dobbyVPN-windows/bin/Dobby Vpn.exe",
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    limits: ArchiveLimits = ArchiveLimits(),
) -> ArtifactInspection:
    """Validate the Windows ZIP layout and PE architecture without extraction."""
    source = _validated_source(source)
    _validate_expected_file_identity(expected_sha256, expected_size_bytes)
    normalized_arch = _normalize_architecture(architecture)
    if normalized_arch not in _WINDOWS_MACHINES.values():
        raise ArtifactContractError("unsupported Windows target architecture")
    executable = _canonical_contract_path(executable_path)
    root = executable.split("/", 1)[0]
    fingerprint = _file_fingerprint(_artifact_path(artifact))
    entries, file_infos = _open_safe_zip(artifact, limits=limits, case_insensitive=True)
    _require_layout(entries, root=root, required=(executable,))
    info = file_infos[executable]
    _reject_credentials_in_archive(entries, file_infos, artifact)
    executable_header = _read_member_prefix(artifact, info, maximum=1024 * 1024)
    actual_arch = _pe_architecture(executable_header)
    if actual_arch != normalized_arch:
        raise ArtifactContractError("Windows executable architecture does not match target")
    return _inspection(
        artifact=artifact,
        source=source,
        platform="windows",
        architecture=normalized_arch,
        component_path=executable,
        component_digest=_hash_member(artifact, info),
        component_size=info.file_size,
        expected_fingerprint=fingerprint,
        expected_sha256=expected_sha256,
        expected_size_bytes=expected_size_bytes,
    )


def inspect_macos_zip(
    artifact: str | Path,
    *,
    source: SourceIdentity,
    architecture: str,
    app_name: str = "Dobby Vpn.app",
    executable_name: str = "Dobby Vpn",
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    limits: ArchiveLimits = ArchiveLimits(),
) -> ArtifactInspection:
    """Validate a macOS app ZIP layout and main Mach-O architecture."""
    source = _validated_source(source)
    _validate_expected_file_identity(expected_sha256, expected_size_bytes)
    normalized_arch = _normalize_architecture(architecture)
    if normalized_arch not in _MACHO_CPUS.values():
        raise ArtifactContractError("unsupported macOS target architecture")
    app = _canonical_contract_path(app_name)
    if "/" in app or not app.endswith(".app"):
        raise ArtifactContractError("macOS app name must be one .app directory name")
    executable = _canonical_contract_path(f"{app}/Contents/MacOS/{executable_name}")
    info_plist = f"{app}/Contents/Info.plist"
    fingerprint = _file_fingerprint(_artifact_path(artifact))
    entries, file_infos = _open_safe_zip(artifact, limits=limits, case_insensitive=True)
    _require_layout(entries, root=app, required=(info_plist, executable))
    _reject_credentials_in_archive(entries, file_infos, artifact)
    plist_data = _read_member(artifact, file_infos[info_plist], limits=limits, maximum=2 * 1024 * 1024)
    try:
        plist = plistlib.loads(plist_data)
    except (ValueError, TypeError) as error:
        raise ArtifactContractError("macOS app Info.plist is invalid") from error
    if not isinstance(plist, dict) or plist.get("CFBundleExecutable") != executable_name:
        raise ArtifactContractError("macOS app executable disagrees with Info.plist")
    executable_info = file_infos[executable]
    executable_header = _read_member_prefix(artifact, executable_info, maximum=4096)
    if normalized_arch not in _macho_architectures(executable_header):
        raise ArtifactContractError("macOS executable architecture does not match target")
    return _inspection(
        artifact=artifact,
        source=source,
        platform="macos",
        architecture=normalized_arch,
        component_path=executable,
        component_digest=_hash_member(artifact, executable_info),
        component_size=executable_info.file_size,
        expected_fingerprint=fingerprint,
        expected_sha256=expected_sha256,
        expected_size_bytes=expected_size_bytes,
    )


def _inspection(
    *, artifact: str | Path, source: SourceIdentity, platform: str,
    architecture: str, component_path: str, component_digest: str, component_size: int,
    expected_fingerprint: tuple[int, int, int, int, int],
    expected_sha256: str | None, expected_size_bytes: int | None,
) -> ArtifactInspection:
    path = _artifact_path(artifact)
    digest, size = _hash_file(path, expected_fingerprint=expected_fingerprint)
    if expected_sha256 is not None and digest != expected_sha256:
        raise ArtifactContractError("artifact SHA-256 differs from the expected value")
    if expected_size_bytes is not None and size != expected_size_bytes:
        raise ArtifactContractError("artifact size differs from the expected value")
    component = {
        "path": component_path,
        "sha256": component_digest,
        "size_bytes": component_size,
        "architecture": architecture,
    }
    return ArtifactInspection(
        source=source,
        platform=platform,
        architecture=architecture,
        artifact_path=path,
        artifact_sha256=digest,
        artifact_size_bytes=size,
        components=(component,),
    )


def _artifact_path(artifact: str | Path) -> Path:
    path = Path(artifact)
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise ArtifactContractError("artifact file is unavailable") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ArtifactContractError("artifact must be a regular non-symlink file")
    return path


def _file_fingerprint(path: Path) -> tuple[int, int, int, int, int]:
    try:
        state = path.stat()
    except OSError as error:
        raise ArtifactContractError("artifact file is unavailable") from error
    return (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns)


def _hash_file(
    path: Path, *, expected_fingerprint: tuple[int, int, int, int, int]
) -> tuple[str, int]:
    try:
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
    except OSError as error:
        raise ArtifactContractError("artifact file could not be read") from error
    before_fingerprint = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    after_fingerprint = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if before_fingerprint != expected_fingerprint or after_fingerprint != expected_fingerprint:
        raise ArtifactContractError("artifact changed while it was inspected")
    return digest.hexdigest(), before.st_size


def _open_safe_zip(
    artifact: str | Path, *, limits: ArchiveLimits, case_insensitive: bool
) -> tuple[tuple[str, ...], dict[str, zipfile.ZipInfo]]:
    path = _artifact_path(artifact)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
    except (OSError, zipfile.BadZipFile, NotImplementedError) as error:
        raise ArtifactContractError("artifact is not a readable ZIP archive") from error
    if len(infos) > limits.max_entries:
        raise ArtifactContractError("archive has too many entries")
    names: list[str] = []
    files: dict[str, zipfile.ZipInfo] = {}
    seen: set[str] = set()
    total = 0
    for info in infos:
        name = _safe_member_name(info.filename)
        comparison_name = name.casefold() if case_insensitive else name
        if comparison_name in seen:
            raise ArtifactContractError("archive has duplicate or colliding entries")
        seen.add(comparison_name)
        if info.flag_bits & 0x1:
            raise ArtifactContractError("archive contains encrypted entries")
        mode = info.external_attr >> 16
        if stat.S_IFMT(mode) == stat.S_IFLNK:
            raise ArtifactContractError("archive contains symbolic links")
        if info.file_size > limits.max_member_bytes:
            raise ArtifactContractError("archive member exceeds size limit")
        total += info.file_size
        if total > limits.max_total_bytes:
            raise ArtifactContractError("archive exceeds total size limit")
        if info.file_size and info.compress_size == 0:
            raise ArtifactContractError("archive has an invalid compressed member")
        if info.compress_size and info.file_size > info.compress_size * limits.max_compression_ratio:
            raise ArtifactContractError("archive member exceeds compression ratio limit")
        names.append(name)
        if not name.endswith("/"):
            files[name] = info
    return tuple(names), files


def _safe_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise ArtifactContractError("archive contains an unsafe path")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ArtifactContractError("archive contains an unsafe path")
    parts = name.rstrip("/").split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ArtifactContractError("archive contains an unsafe path")
    return name


def _canonical_contract_path(value: str) -> str:
    if not isinstance(value, str):
        raise ArtifactContractError("contract path must be a string")
    normalized = _safe_member_name(value)
    if normalized.endswith("/"):
        raise ArtifactContractError("contract path must name a file")
    return normalized


def _require_layout(entries: Iterable[str], *, root: str, required: Iterable[str]) -> None:
    files = {entry for entry in entries if not entry.endswith("/")}
    root_prefix = root + "/"
    if any(not entry.startswith(root_prefix) for entry in entries):
        raise ArtifactContractError("archive has files outside the expected package root")
    if any(path not in files for path in required):
        raise ArtifactContractError("archive is missing a required package component")


def _read_member(
    artifact: str | Path, info: zipfile.ZipInfo, *, limits: ArchiveLimits, maximum: int | None = None
) -> bytes:
    read_limit = min(limits.max_member_bytes, maximum) if maximum is not None else limits.max_member_bytes
    if info.file_size > read_limit:
        raise ArtifactContractError("archive member exceeds inspection size limit")
    try:
        with zipfile.ZipFile(_artifact_path(artifact)) as archive, archive.open(info) as handle:
            data = handle.read(read_limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ArtifactContractError("archive member could not be read") from error
    if len(data) != info.file_size or len(data) > read_limit:
        raise ArtifactContractError("archive member size changed while it was inspected")
    return data


def _read_member_prefix(artifact: str | Path, info: zipfile.ZipInfo, *, maximum: int) -> bytes:
    """Read only a bounded executable header; never materialize a large app."""
    try:
        with zipfile.ZipFile(_artifact_path(artifact)) as archive, archive.open(info) as handle:
            data = handle.read(maximum)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ArtifactContractError("archive member could not be read") from error
    if not data:
        raise ArtifactContractError("archive member is empty")
    return data


def _hash_member(artifact: str | Path, info: zipfile.ZipInfo) -> str:
    """Hash a member with bounded memory and confirm its advertised size."""
    digest = hashlib.sha256()
    size = 0
    try:
        with zipfile.ZipFile(_artifact_path(artifact)) as archive, archive.open(info) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ArtifactContractError("archive member could not be read") from error
    if size != info.file_size:
        raise ArtifactContractError("archive member size changed while it was inspected")
    return digest.hexdigest()


def _reject_credentials_in_archive(
    entries: Iterable[str], file_infos: dict[str, zipfile.ZipInfo], artifact: str | Path
) -> None:
    for name in entries:
        if _credential_marker(name.encode("utf-8", "replace")):
            raise ArtifactContractError("artifact contains an obvious credential marker")
    for info in file_infos.values():
        marker = _credential_marker_in_member(artifact, info)
        if marker:
            raise ArtifactContractError("artifact contains an obvious credential marker")


def _credential_marker_in_member(artifact: str | Path, info: zipfile.ZipInfo) -> str | None:
    previous = b""
    try:
        with zipfile.ZipFile(_artifact_path(artifact)) as archive, archive.open(info) as handle:
            while chunk := handle.read(1024 * 1024):
                marker = _credential_marker(previous + chunk)
                if marker:
                    return marker
                previous = (previous + chunk)[-CREDENTIAL_SCAN_OVERLAP_BYTES:]
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ArtifactContractError("archive member could not be read") from error
    return None


def _credential_marker(data: bytes) -> str | None:
    for label, pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(data):
            return label
    return None


def obvious_credential_marker(data: bytes) -> str | None:
    """Return a safe label for an unmistakable credential marker, if present.

    The label is safe to include in diagnostics; callers must never display the
    matching candidate bytes.  This narrow public check is shared by public
    artifact contracts and is not a general-purpose secret scanner.
    """
    return _credential_marker(data)


def _normalize_architecture(value: str) -> str:
    if not isinstance(value, str):
        raise ArtifactContractError("architecture must be a string")
    return _ARCH_ALIASES.get(value, value)


def _validated_source(source: SourceIdentity) -> SourceIdentity:
    if not isinstance(source, SourceIdentity):
        raise ArtifactContractError("source must be a SourceIdentity")
    return SourceIdentity.create(repository=source.repository, commit=source.commit)


def _validate_expected_file_identity(
    expected_sha256: str | None, expected_size_bytes: int | None
) -> None:
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ArtifactContractError("expected artifact SHA-256 must be lowercase hexadecimal")
    if expected_size_bytes is not None and (
        not isinstance(expected_size_bytes, int)
        or isinstance(expected_size_bytes, bool)
        or expected_size_bytes < 0
    ):
        raise ArtifactContractError("expected artifact size must be a non-negative integer")


def _pe_architecture(data: bytes) -> str:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ArtifactContractError("Windows executable is not a PE file")
    header_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if header_offset + 6 > len(data) or data[header_offset:header_offset + 4] != b"PE\0\0":
        raise ArtifactContractError("Windows executable has an invalid PE header")
    machine = struct.unpack_from("<H", data, header_offset + 4)[0]
    try:
        return _WINDOWS_MACHINES[machine]
    except KeyError as error:
        raise ArtifactContractError("Windows executable has an unsupported PE architecture") from error


def _macho_architectures(data: bytes) -> set[str]:
    if len(data) < 8:
        raise ArtifactContractError("macOS executable is not a Mach-O file")
    magic = data[:4]
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        is_64_bit_fat = magic == b"\xca\xfe\xba\xbf"
        count = struct.unpack_from(">I", data, 4)[0]
        entry_size = 32 if is_64_bit_fat else 20
        if count == 0 or count > 32 or 8 + count * entry_size > len(data):
            raise ArtifactContractError("macOS executable has an invalid fat Mach-O header")
        architectures = {
            _MACHO_CPUS[cpu]
            for offset in range(8, 8 + count * entry_size, entry_size)
            if (cpu := struct.unpack_from(">I", data, offset)[0]) in _MACHO_CPUS
        }
        if not architectures:
            raise ArtifactContractError("macOS executable has an unsupported Mach-O architecture")
        return architectures
    byte_order = {b"\xcf\xfa\xed\xfe": "<", b"\xce\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">", b"\xfe\xed\xfa\xce": ">"}.get(magic)
    if byte_order is None:
        raise ArtifactContractError("macOS executable is not a Mach-O file")
    cpu = struct.unpack_from(byte_order + "I", data, 4)[0]
    try:
        return {_MACHO_CPUS[cpu]}
    except KeyError as error:
        raise ArtifactContractError("macOS executable has an unsupported Mach-O architecture") from error
