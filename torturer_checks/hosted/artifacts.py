"""Download exact GitHub Actions artifacts without exposing credentials.

The helper is used only by the trusted client/controller workflow.  It binds
an artifact name to one originating run, retains complete API/ZIP bytes in a
private directory, and extracts only an explicitly allow-listed set of regular
files.  It never prints response bodies or token-bearing URLs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
from pathlib import PurePosixPath
from typing import Iterable
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile


class ArtifactDownloadError(RuntimeError):
    """The requested artifact is missing or unsafe."""


class _CredentialSafeRedirectHandler(HTTPRedirectHandler):
    """Never forward GitHub credentials to an artifact storage host."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        if redirected is None:
            return None
        source = urlsplit(request.full_url)
        target = urlsplit(new_url)
        if target.scheme.lower() != "https":
            raise ArtifactDownloadError("artifact redirect is not HTTPS")
        source_origin = (source.scheme.lower(), source.hostname, source.port)
        target_origin = (target.scheme.lower(), target.hostname, target.port)
        if source_origin != target_origin:
            redirected.remove_header("Authorization")
            redirected.remove_header("X-GitHub-Api-Version")
        return redirected


_OPENER = build_opener(_CredentialSafeRedirectHandler())


def _owner_dir(path: Path) -> None:
    """Create/check a private directory without traversing symlinks."""

    path = Path(path)
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
            if cursor.parent == cursor:
                raise ArtifactDownloadError("owner-only directory has no valid root")
            cursor = cursor.parent
            continue
        except OSError as error:
            raise ArtifactDownloadError("owner-only directory cannot be inspected") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ArtifactDownloadError("owner-only directory is not a real directory")
        break
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        try:
            info = directory.lstat()
        except OSError as error:
            raise ArtifactDownloadError("owner-only directory disappeared") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ArtifactDownloadError("owner-only directory contains a symlink")
        os.chmod(directory, 0o700)
    try:
        info = path.lstat()
    except OSError as error:
        raise ArtifactDownloadError("owner-only directory is unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ArtifactDownloadError("owner-only directory is not a real directory")
    if info.st_mode & 0o077:
        raise ArtifactDownloadError("owner-only directory has unsafe permissions")


def _owner_file(path: Path, data: bytes) -> None:
    """Create one owner-only file, refusing every existing destination."""

    path = Path(path)
    _owner_dir(path.parent)
    temporary = path.with_name(f".{path.name}.tmp")
    for candidate in (path, temporary):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ArtifactDownloadError("owner-only destination cannot be inspected") from error
        raise ArtifactDownloadError("owner-only destination already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise ArtifactDownloadError("owner-only destination already exists") from error
    except OSError as error:
        raise ArtifactDownloadError("owner-only destination cannot be created") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:

            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
            raise ArtifactDownloadError("owner-only file has unsafe permissions")
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise

def _token() -> str:
    token = os.environ.get("GH_TOKEN", "")
    if not token or any(ch.isspace() for ch in token):
        raise ArtifactDownloadError("GH_TOKEN is missing")
    return token


def _get(url: str) -> bytes:
    request = Request(
        url,
        headers={
            "Authorization": f"Bearer {_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "DobbyVPN-Torturer-artifact-client",
        },
    )
    try:
        with _OPENER.open(request, timeout=30) as response:
            return response.read()
    except Exception as error:  # pragma: no cover - provider/network boundary
        raise ArtifactDownloadError("GitHub artifact request failed") from error


def _repository(value: str) -> str:
    pieces = value.split("/", 1)
    if len(pieces) != 2 or not all(pieces) or any(ch.isspace() for ch in value):
        raise ArtifactDownloadError("repository must be owner/name")
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", piece) or piece in {".", ".."} for piece in pieces):
        raise ArtifactDownloadError("repository must be owner/name")
    return value


def _select(document: dict[str, object], *, name: str, run_id: int) -> dict[str, object]:
    matches = []
    for item in document.get("artifacts", []):
        if not isinstance(item, dict) or item.get("name") != name:
            continue
        workflow_run = item.get("workflow_run")
        if not isinstance(workflow_run, dict) or workflow_run.get("id") != run_id:
            continue
        if item.get("expired") is True:
            continue
        matches.append(item)
    if len(matches) != 1:
        raise ArtifactDownloadError("artifact identity is missing or ambiguous")
    url = matches[0].get("archive_download_url")
    if not isinstance(url, str) or not url.startswith("https://api.github.com/"):
        raise ArtifactDownloadError("artifact archive URL is invalid")
    return matches[0]


def _safe_member_name(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ArtifactDownloadError("artifact member path is unsafe")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in value
    ):

        raise ArtifactDownloadError("artifact member path is unsafe")
    return value


def _extract(archive: Path, output: Path, expected: set[str]) -> None:
    _owner_dir(output)
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            names = {item.filename for item in infos}
            if len(names) != len(infos):
                raise ArtifactDownloadError("artifact contains duplicate members")
            if names != expected:
                raise ArtifactDownloadError(
                    f"artifact members differ from allow-list: {sorted(names)}"
                )
            safe_items: list[tuple[zipfile.ZipInfo, str]] = []
            for item in infos:
                name = _safe_member_name(item.filename)
                mode = (item.external_attr >> 16) & 0o170000
                if item.is_dir() or mode not in (0, stat.S_IFREG):
                    raise ArtifactDownloadError("artifact contains an unsafe member")
                safe_items.append((item, name))
            for item, name in safe_items:
                target = output / name
                _owner_file(target, bundle.read(item))
    except (OSError, zipfile.BadZipFile) as error:
        raise ArtifactDownloadError("artifact archive is unreadable") from error


def download_artifact(
    *,
    repository: str,
    artifact_name: str,
    run_id: int,
    output_dir: Path,
    expected_files: Iterable[str],
    metadata_path: Path,
    archive_path: Path,
) -> dict[str, object]:
    """Fetch and extract one exact artifact, retaining complete raw bytes."""

    if run_id <= 0 or not artifact_name or any(ch.isspace() for ch in artifact_name):
        raise ArtifactDownloadError("artifact identity is invalid")
    repository = _repository(repository)
    expected_values = tuple(expected_files)
    if not expected_values or len(set(expected_values)) != len(expected_values):
        raise ArtifactDownloadError("artifact allow-list is invalid")
    try:
        expected = {_safe_member_name(value) for value in expected_values}
    except ArtifactDownloadError as error:
        raise ArtifactDownloadError("artifact allow-list is invalid") from error
    listing_url = f"https://api.github.com/repos/{repository}/actions/artifacts?name={quote(artifact_name, safe='')}&per_page=100"
    listing_bytes = _get(listing_url)
    _owner_file(metadata_path, listing_bytes)
    try:
        listing = json.loads(listing_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactDownloadError("artifact listing is not JSON") from error
    if not isinstance(listing, dict):
        raise ArtifactDownloadError("artifact listing has an unsafe shape")
    selected = _select(listing, name=artifact_name, run_id=run_id)
    archive_bytes = _get(str(selected["archive_download_url"]))
    _owner_file(archive_path, archive_bytes)
    _extract(archive_path, output_dir, expected)
    return {
        "name": artifact_name,
        "run_id": run_id,
        "artifact_id": selected.get("id"),
        "files": sorted(expected),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expect-file", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        result = download_artifact(
            repository=args.repository,
            artifact_name=args.artifact_name,
            run_id=args.run_id,
            output_dir=args.output_dir,
            expected_files=args.expect_file,
            metadata_path=args.metadata,
            archive_path=args.archive,
        )
        print(json.dumps({"artifact": result["name"], "run_id": result["run_id"], "files": result["files"]}, sort_keys=True))
        return 0
    except ArtifactDownloadError as error:
        print(f"artifact-download failed code={type(error).__name__}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
