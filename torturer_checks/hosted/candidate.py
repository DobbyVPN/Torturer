"""Stage and verify the allow-listed untrusted hosted candidate closure."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import secrets
import stat
import sys


_SHA = re.compile(r"^[0-9a-f]{40}$")
_PLATFORMS = frozenset(("linux", "windows", "macos", "android"))
_ARCHITECTURES = {
    "linux": "amd64",
    "windows": "amd64",
    "macos": "arm64",
    "android": "x86_64",
}


class CandidateClosureError(RuntimeError):
    """The candidate closure is incomplete, unsafe, or has stale provenance."""


def expected_architecture(platform: str) -> str:
    """Return the immutable architecture expected by one hosted lane."""
    try:
        return _ARCHITECTURES[platform]
    except KeyError as error:
        raise CandidateClosureError("candidate platform is unsupported") from error


def closure_sha256(manifest: dict[str, object]) -> str:
    """Hash the validated multi-file candidate identity, not ``manifest.json``.

    ``verify`` must run before this function.  The digest is deliberately
    independent of JSON object insertion order, while binding the validated
    header and every ordered member name, byte digest, size, and executable
    policy.  The raw manifest-file digest is a separate provenance value.
    """
    expected = {"schema", "kind", "platform", "architecture", "source_sha", "files"}
    if set(manifest) != expected or not isinstance(manifest.get("files"), dict):
        raise CandidateClosureError("candidate manifest is not a validated closure")
    files = manifest["files"]
    members: list[dict[str, object]] = []
    for name in sorted(files):
        record = files[name]
        if not isinstance(name, str) or not isinstance(record, dict):
            raise CandidateClosureError("candidate closure member identity is invalid")
        if set(record) != {"sha256", "size", "executable"}:
            raise CandidateClosureError("candidate closure member record is invalid")
        members.append(
            {
                "name": name,
                "sha256": record["sha256"],
                "size": record["size"],
                "executable": record["executable"],
            }
        )
    canonical = {
        "digest_version": 1,
        "schema": manifest["schema"],
        "kind": manifest["kind"],
        "platform": manifest["platform"],
        "architecture": manifest["architecture"],
        "source_sha": manifest["source_sha"],
        "members": members,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CandidateFile:
    source: str
    name: str
    executable: bool


_FILES: dict[str, tuple[CandidateFile, ...]] = {
    "linux": (
        CandidateFile("kmp_module/services/ubuntu_grpcvpnserver", "ubuntu_grpcvpnserver", True),
        CandidateFile("kmp_module/services/dobby-cli", "dobby-cli", True),
        CandidateFile("kmp_module/services/libdobby_bridge.so", "libdobby_bridge.so", True),
        CandidateFile("kmp_module/services/libc++.so.1", "libc++.so.1", True),
        CandidateFile("kmp_module/services/libc++abi.so.1", "libc++abi.so.1", True),
    ),
    "windows": (
        CandidateFile("kmp_module/services/windows_grpcvpnserver.exe", "windows_grpcvpnserver.exe", True),
        CandidateFile("kmp_module/services/dobby-cli.exe", "dobby-cli.exe", True),
        CandidateFile("kmp_module/services/wintun.dll", "wintun.dll", False),
        CandidateFile("kmp_module/services/dobby_bridge.dll", "dobby_bridge.dll", False),
    ),
    "macos": (
        CandidateFile("kmp_module/services/macos_grpcvpnserver", "macos_grpcvpnserver", True),
        CandidateFile("kmp_module/services/dobby-cli", "dobby-cli", True),
    ),
    "android": (
        CandidateFile("kmp_module/app/build/outputs/apk/debug/app-debug.apk", "app-debug.apk", False),
        CandidateFile(
            "kmp_module/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk",
            "app-debug-androidTest.apk",
            False,
        ),
    ),
}


def _validate_identity(platform: str, architecture: str, source_sha: str) -> None:
    if platform not in _PLATFORMS:
        raise CandidateClosureError("candidate platform is unsupported")
    if architecture != _ARCHITECTURES[platform]:
        raise CandidateClosureError("candidate architecture does not match the hosted lane")
    if _SHA.fullmatch(source_sha) is None or source_sha == "0" * 40:
        raise CandidateClosureError("candidate source SHA is invalid")


def _absolute(path: Path) -> Path:
    # abspath normalizes ``..`` without resolving symlinks; this is intentional.
    return Path(os.path.abspath(os.fspath(path)))


def _is_link(path: Path, details: os.stat_result) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return stat.S_ISLNK(details.st_mode) or path.is_symlink() or bool(
        is_junction is not None and is_junction()
    )


def _reject_symlink_components(path: Path, description: str) -> None:
    """Reject symlink/junction components in an existing path prefix."""
    absolute = _absolute(path)
    current = Path(absolute.anchor) if absolute.anchor else Path(".")
    for part in absolute.parts:
        if part == absolute.anchor:
            continue
        current /= part
        try:
            details = current.lstat()
        except FileNotFoundError:
            # A missing tail is safe to inspect only after its existing parent
            # has been checked by the caller.
            break
        except OSError as error:
            raise CandidateClosureError(f"{description} path is unavailable") from error
        if _is_link(current, details):
            raise CandidateClosureError(f"{description} path contains a symlink component")


def _directory(path: Path, description: str) -> Path:
    absolute = _absolute(path)
    _reject_symlink_components(absolute, description)
    try:
        details = absolute.lstat()
    except OSError as error:
        raise CandidateClosureError(f"{description} is unavailable") from error
    if _is_link(absolute, details) or not stat.S_ISDIR(details.st_mode):
        raise CandidateClosureError(f"{description} is not a real directory")
    return absolute


def _new_output_directory(path: Path) -> Path:
    absolute = _absolute(path)
    if absolute.exists() or absolute.is_symlink():
        raise CandidateClosureError("candidate output root must not already exist")
    _directory(absolute.parent, "candidate output parent")
    try:
        absolute.mkdir(mode=0o700, exist_ok=False)
        absolute.chmod(0o700)
    except OSError as error:
        raise CandidateClosureError("candidate output root could not be created securely") from error
    return absolute


def _regular(path: Path, description: str) -> os.stat_result:
    _reject_symlink_components(path.parent, description)
    try:
        details = path.lstat()
    except OSError as error:
        raise CandidateClosureError(f"{description} is unavailable") from error
    if _is_link(path, details) or not stat.S_ISREG(details.st_mode):
        raise CandidateClosureError(f"{description} is not a regular file")
    if details.st_size <= 0:
        raise CandidateClosureError(f"{description} is empty")
    return details


def _descriptor_identity(details: os.stat_result) -> tuple[int, ...]:
    """Return portable identity and mutation metadata for an open file.

    Windows exposes ``st_ctime`` as creation time (and deprecated that field
    in Python 3.12), while the path and descriptor stat implementations can
    report different creation-time values for the same NTFS file.  The
    stable file identity, size, and last-write time are the useful checks on
    that platform; POSIX keeps the stricter ownership, mode, and ctime checks.
    """

    common = (
        details.st_dev,
        details.st_ino,
        details.st_size,
        getattr(details, "st_mtime_ns", int(details.st_mtime * 1_000_000_000)),
    )
    if os.name == "nt":
        return common
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        getattr(details, "st_uid", -1),
        details.st_size,
        getattr(details, "st_mtime_ns", int(details.st_mtime * 1_000_000_000)),
        getattr(details, "st_ctime_ns", int(details.st_ctime * 1_000_000_000)),
    )


def _validate_descriptor(details: os.stat_result, description: str) -> None:
    """Validate the object represented by an already-open descriptor."""

    if not stat.S_ISREG(details.st_mode):
        raise CandidateClosureError(f"{description} is not a regular file")
    if details.st_size <= 0:
        raise CandidateClosureError(f"{description} is empty")
    if os.name != "nt":
        if hasattr(os, "geteuid") and details.st_uid != os.geteuid():
            raise CandidateClosureError(f"{description} is not owned by the current user")
        if details.st_mode & 0o022:
            raise CandidateClosureError(f"{description} has unsafe permissions")


def _open_pinned(path: Path, description: str) -> tuple[int, os.stat_result]:
    """Open a candidate file and bind the checks to that exact descriptor."""

    path = Path(path)
    _reject_symlink_components(path.parent, description)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise CandidateClosureError(f"{description} is not a regular file") from error
        raise CandidateClosureError(f"{description} is unavailable") from error
    try:
        details = os.fstat(descriptor)
        _validate_descriptor(details, description)
        try:
            path_details = path.lstat()
        except OSError as error:
            raise CandidateClosureError(f"{description} disappeared while opening") from error
        if _descriptor_identity(path_details) != _descriptor_identity(details):
            raise CandidateClosureError(f"{description} changed while being opened")
        return descriptor, details
    except Exception:
        os.close(descriptor)
        raise


def _iter_descriptor_bytes(descriptor: int):
    while True:
        try:
            chunk = os.read(descriptor, 1024 * 1024)
        except InterruptedError:
            continue
        if not chunk:
            return
        yield chunk


def _ensure_descriptor_stable(
    descriptor: int,
    path: Path,
    before: os.stat_result,
    description: str,
) -> os.stat_result:
    """Prove both the descriptor and its pathname stayed the same after I/O."""

    try:
        after = os.fstat(descriptor)
        _validate_descriptor(after, description)
        path_details = path.lstat()
    except OSError as error:
        raise CandidateClosureError(f"{description} became unavailable during I/O") from error
    if _descriptor_identity(after) != _descriptor_identity(before):
        raise CandidateClosureError(f"{description} changed while being read or copied")
    if _descriptor_identity(path_details) != _descriptor_identity(before):
        raise CandidateClosureError(f"{description} was replaced while being read or copied")
    return after


def _digest_descriptor(
    descriptor: int,
    path: Path,
    before: os.stat_result,
    description: str,
) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    for chunk in _iter_descriptor_bytes(descriptor):
        digest.update(chunk)
        size += len(chunk)
    _ensure_descriptor_stable(descriptor, path, before, description)
    return digest.hexdigest(), size


def _read_descriptor(
    descriptor: int,
    path: Path,
    before: os.stat_result,
    description: str,
) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = b"".join(_iter_descriptor_bytes(descriptor))
    _ensure_descriptor_stable(descriptor, path, before, description)
    return data


def _copy_descriptor(
    descriptor: int,
    source: Path,
    before: os.stat_result,
    destination: Path,
    description: str,
) -> None:
    _reject_symlink_components(destination.parent, "candidate output")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        target = os.open(destination, flags, 0o600)
    except OSError as error:
        raise CandidateClosureError(f"candidate output {destination.name} could not be created") from error
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        for chunk in _iter_descriptor_bytes(descriptor):
            offset = 0
            while offset < len(chunk):
                offset += os.write(target, chunk[offset:])
        os.fsync(target)
    except OSError as error:
        raise CandidateClosureError(f"candidate {description} could not be copied") from error
    finally:
        os.close(target)
    _ensure_descriptor_stable(descriptor, source, before, description)


def _write_manifest(path: Path, manifest: dict[str, object]) -> None:
    payload = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise CandidateClosureError("candidate manifest could not be created") from error
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fchmod(descriptor, 0o600) if hasattr(os, "fchmod") else os.chmod(path, 0o600)
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        _validate_descriptor(details, "candidate manifest")
        path_details = path.lstat()
        if _descriptor_identity(path_details) != _descriptor_identity(details):
            raise CandidateClosureError("candidate manifest changed while being written")
    except OSError as error:
        raise CandidateClosureError("candidate manifest could not be written") from error
    finally:
        os.close(descriptor)


def stage(
    source_root: Path,
    output_root: Path,
    *,
    platform: str,
    architecture: str,
    source_sha: str,
) -> dict[str, object]:
    _validate_identity(platform, architecture, source_sha)
    source_root = _directory(source_root, "candidate source root")
    output_root = _new_output_directory(output_root)
    files: dict[str, dict[str, object]] = {}
    for item in _FILES[platform]:
        source = source_root / item.source
        descriptor, details = _open_pinned(source, f"candidate source {item.name}")
        try:
            if item.executable and os.name != "nt" and not details.st_mode & stat.S_IXUSR:
                raise CandidateClosureError(f"candidate source {item.name} is not executable")
            destination = output_root / item.name
            _copy_descriptor(descriptor, source, details, destination, f"source {item.name}")
        finally:
            os.close(descriptor)
        destination_descriptor, destination_details = _open_pinned(
            destination, f"candidate output {item.name}"
        )
        try:
            mode = 0o700 if item.executable else 0o600
            if hasattr(os, "fchmod"):
                os.fchmod(destination_descriptor, mode)
                destination_details = os.fstat(destination_descriptor)
            else:
                destination.chmod(mode)
            digest, size = _digest_descriptor(
                destination_descriptor, destination, destination_details, f"candidate output {item.name}"
            )
        finally:
            os.close(destination_descriptor)
        files[item.name] = {"sha256": digest, "size": size, "executable": item.executable}
    manifest: dict[str, object] = {
        "schema": 1,
        "kind": "dobbyvpn.hosted-candidate-closure",
        "platform": platform,
        "architecture": architecture,
        "source_sha": source_sha,
        "files": files,
    }
    manifest_path = output_root / "manifest.json"
    _write_manifest(manifest_path, manifest)
    total_bytes = sum(int(record["size"]) for record in files.values())
    print(
        "candidate_closure status=staged "
        f"id={secrets.token_hex(16)} bytes={total_bytes} "
        f"sha256={closure_sha256(manifest)}"
    )
    return manifest


def verify(
    root: Path,
    *,
    platform: str,
    architecture: str,
    source_sha: str,
) -> dict[str, object]:
    _validate_identity(platform, architecture, source_sha)
    root = _directory(root, "candidate artifact root")
    manifest_path = root / "manifest.json"
    manifest_descriptor, manifest_details = _open_pinned(manifest_path, "candidate manifest")
    try:
        manifest = json.loads(
            _read_descriptor(manifest_descriptor, manifest_path, manifest_details, "candidate manifest")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateClosureError("candidate manifest is unreadable") from error
    finally:
        os.close(manifest_descriptor)
    expected_header = {
        "schema": 1,
        "kind": "dobbyvpn.hosted-candidate-closure",
        "platform": platform,
        "architecture": architecture,
        "source_sha": source_sha,
    }
    if not isinstance(manifest, dict) or set(manifest) != {*expected_header, "files"}:
        raise CandidateClosureError("candidate manifest has an unsafe shape")
    for key, wanted in expected_header.items():
        actual = manifest.get(key)
        if type(actual) is not type(wanted) or actual != wanted:
            raise CandidateClosureError(f"candidate manifest {key} mismatch")
    expected_specs = {item.name: item for item in _FILES[platform]}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(expected_specs):
        raise CandidateClosureError("candidate manifest file allow-list mismatch")
    expected_members = set(expected_specs) | {"manifest.json"}
    actual_members = {path.name for path in root.iterdir()}
    if actual_members != expected_members:
        raise CandidateClosureError("candidate artifact member allow-list mismatch")
    for name, item in expected_specs.items():
        path = root / name
        descriptor, details = _open_pinned(path, f"candidate artifact {name}")
        record = files.get(name)
        try:
            if not isinstance(record, dict) or set(record) != {"sha256", "size", "executable"}:
                raise CandidateClosureError(f"candidate manifest file record is invalid: {name}")
            digest = record["sha256"]
            size = record["size"]
            executable = record["executable"]
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise CandidateClosureError(f"candidate manifest digest is invalid: {name}")
            if type(size) is not int or size <= 0:
                raise CandidateClosureError(f"candidate manifest size is invalid: {name}")
            if type(executable) is not bool:
                raise CandidateClosureError(f"candidate manifest executable flag is invalid: {name}")
            actual_digest, actual_size = _digest_descriptor(
                descriptor, path, details, f"candidate artifact {name}"
            )
            if digest != actual_digest or size != actual_size:
                raise CandidateClosureError(f"candidate artifact digest or size mismatch: {name}")
            if executable is not item.executable:
                raise CandidateClosureError(f"candidate executable policy mismatch: {name}")
            mode = 0o700 if item.executable else 0o600
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, mode)
            else:
                path.chmod(mode)
        finally:
            os.close(descriptor)
    total_bytes = sum(int(record["size"]) for record in files.values())
    print(
        "candidate_closure status=verified "
        f"id={secrets.token_hex(16)} bytes={total_bytes} "
        f"sha256={closure_sha256(manifest)}"
    )
    return manifest


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    for command in ("stage", "verify"):
        child = commands.add_parser(command)
        child.add_argument("--root", type=Path, required=True)
        child.add_argument("--platform", choices=sorted(_PLATFORMS), required=True)
        child.add_argument("--architecture", required=True)
        child.add_argument("--source-sha", required=True)
        if command == "stage":
            child.add_argument("--output", type=Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "stage":
            stage(
                args.root,
                args.output,
                platform=args.platform,
                architecture=args.architecture,
                source_sha=args.source_sha,
            )
        else:
            verify(
                args.root,
                platform=args.platform,
                architecture=args.architecture,
                source_sha=args.source_sha,
            )
    except (CandidateClosureError, OSError, ValueError) as error:
        print(
            f"candidate_closure status=failed code={type(error).__name__} "
            f"reason={error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
