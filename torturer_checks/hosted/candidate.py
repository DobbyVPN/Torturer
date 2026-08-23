"""Stage and verify the allow-listed untrusted hosted candidate closure."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
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


def _digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


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
        details = _regular(source, f"candidate source {item.name}")
        if item.executable and os.name != "nt" and not details.st_mode & stat.S_IXUSR:
            raise CandidateClosureError(f"candidate source {item.name} is not executable")
        destination = output_root / item.name
        shutil.copyfile(source, destination)
        destination.chmod(0o700 if item.executable else 0o600)
        files[item.name] = {
            "sha256": _digest(destination),
            "size": destination.stat().st_size,
            "executable": item.executable,
        }
    manifest: dict[str, object] = {
        "schema": 1,
        "kind": "dobbyvpn.hosted-candidate-closure",
        "platform": platform,
        "architecture": architecture,
        "source_sha": source_sha,
        "files": files,
    }
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)
    print(json.dumps(manifest, sort_keys=True))
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
    _regular(manifest_path, "candidate manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateClosureError("candidate manifest is unreadable") from error
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
        details = _regular(path, f"candidate artifact {name}")
        record = files.get(name)
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
        if digest != _digest(path) or size != details.st_size:
            raise CandidateClosureError(f"candidate artifact digest or size mismatch: {name}")
        if executable is not item.executable:
            raise CandidateClosureError(f"candidate executable policy mismatch: {name}")
        path.chmod(0o700 if item.executable else 0o600)
        print(f"{digest}  {name}")
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
        print(f"hosted candidate closure failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
