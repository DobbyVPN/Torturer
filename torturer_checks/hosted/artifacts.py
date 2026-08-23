"""Download exact GitHub Actions artifacts without exposing credentials.

The helper is used only by the trusted client/controller workflow.  It binds
an artifact name to one originating run, retains complete API/ZIP bytes in a
private directory, and extracts only an explicitly allow-listed set of regular
files.  It never prints response bodies or token-bearing URLs.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from pathlib import PurePosixPath
from typing import Iterable
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from torturer_checks.public_output import emit_evidence


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
_DEFAULT_TRANSFER_TIMEOUT_SECONDS = 30.0
_TRANSFER_CHUNK_BYTES = 64 * 1024
_DEADLINE_CLEANUP_RESERVE_SECONDS = 0.01


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")


def _deadline_for(timeout_seconds: float) -> float:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    return time.monotonic() + timeout_seconds


def _owner_dir(path: Path, *, deadline: float | None = None) -> None:
    """Create/check a private directory without traversing symlinks."""

    path = Path(path)
    _check_deadline(deadline)
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
        _check_deadline(deadline)
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
        _check_deadline(deadline)
        info = path.lstat()
    except OSError as error:
        raise ArtifactDownloadError("owner-only directory is unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ArtifactDownloadError("owner-only directory is not a real directory")
    if info.st_mode & 0o077:
        raise ArtifactDownloadError("owner-only directory has unsafe permissions")


def _fsync_with_deadline(descriptor: int, deadline: float | None) -> None:
    """Flush through a duplicate descriptor without overrunning the deadline."""

    if deadline is None:
        os.fsync(descriptor)
        return
    _check_deadline(deadline)
    duplicate = os.dup(descriptor)
    result: list[BaseException] = []

    def flush() -> None:
        try:
            os.fsync(duplicate)
        except BaseException as error:  # preserve the provider/filesystem failure
            result.append(error)
        finally:
            os.close(duplicate)

    worker = threading.Thread(target=flush, name="artifact-fsync", daemon=True)
    worker.start()
    remaining = max(0.0, deadline - time.monotonic() - _DEADLINE_CLEANUP_RESERVE_SECONDS)
    worker.join(remaining)
    if worker.is_alive():
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    if result:
        raise result[0]
    _check_deadline(deadline)


def _owner_file(path: Path, data: bytes, *, deadline: float | None = None) -> None:
    """Create one owner-only file, refusing every existing destination."""

    path = Path(path)
    _check_deadline(deadline)
    _owner_dir(path.parent, deadline=deadline)
    _check_deadline(deadline)
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
            offset = 0
            while offset < len(data):
                _check_deadline(deadline)
                offset += output.write(data[offset : offset + _TRANSFER_CHUNK_BYTES])
            output.flush()
            _fsync_with_deadline(output.fileno(), deadline)
        _check_deadline(deadline)
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


def _close_response(response: object, deadline: float | None = None) -> bool:
    close = getattr(response, "close", None)
    if not callable(close):
        return True
    if deadline is None:
        close()
        return True
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    result: list[BaseException] = []

    def close_response() -> None:
        try:
            close()
        except BaseException as error:  # preserve provider cleanup failure
            result.append(error)

    worker = threading.Thread(target=close_response, name="artifact-response-closer", daemon=True)
    worker.start()
    worker.join(remaining)
    if worker.is_alive():
        return False
    if result:
        raise result[0]
    return True


def _read_chunk_with_deadline(response: object, deadline: float) -> bytes:
    """Read one response chunk without allowing a blocking read to overrun the deadline."""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    result: list[object] = []

    def read_chunk() -> None:
        try:
            result.append(response.read(_TRANSFER_CHUNK_BYTES))  # type: ignore[attr-defined]
        except BaseException as error:  # retain the original provider failure
            result.append(error)

    reader = threading.Thread(target=read_chunk, name="artifact-response-reader", daemon=True)
    reader.start()
    reader.join(max(0.0, remaining - _DEADLINE_CLEANUP_RESERVE_SECONDS))
    if reader.is_alive():
        _close_response(response, deadline)
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    if not result:
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_FAILED")
    value = result[0]
    if isinstance(value, BaseException):
        if isinstance(value, TimeoutError):
            raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT") from value
        raise value
    if not isinstance(value, bytes):
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_FAILED")
    if time.monotonic() >= deadline:
        _close_response(response, deadline)
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    return value


def _open_with_deadline(request: Request, deadline: float):
    """Open the response without allowing a blocking provider call to overrun the deadline."""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    result: list[object] = []
    cancelled = threading.Event()

    def open_response() -> None:
        try:
            response = _OPENER.open(request, timeout=min(30.0, remaining))
            if cancelled.is_set() or time.monotonic() >= deadline:
                _close_response(response, deadline)
            else:
                result.append(response)
        except BaseException as error:  # retain the original provider failure
            if not cancelled.is_set():
                result.append(error)

    opener = threading.Thread(target=open_response, name="artifact-response-opener", daemon=True)
    opener.start()
    opener.join(max(0.0, remaining - _DEADLINE_CLEANUP_RESERVE_SECONDS))
    if opener.is_alive():
        cancelled.set()
        if result:
            _close_response(result[0])
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    if not result:
        if time.monotonic() >= deadline:
            raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_FAILED")
    value = result[0]
    if isinstance(value, BaseException):
        raise value
    return value


def _get(
    url: str,
    *,
    timeout_seconds: float = _DEFAULT_TRANSFER_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> bytes:
    if deadline is None:
        deadline = _deadline_for(timeout_seconds)
    _check_deadline(deadline)
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
        response = _open_with_deadline(request, deadline)
    except ArtifactDownloadError:
        raise
    except TimeoutError as error:
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT") from error
    except Exception as error:  # pragma: no cover - provider/network boundary
        raise ArtifactDownloadError("GitHub artifact request failed") from error
    chunks: list[bytes] = []
    pending: BaseException | None = None
    value: bytes | None = None
    try:
        while True:
            chunk = _read_chunk_with_deadline(response, deadline)
            if not chunk:
                value = b"".join(chunks)
                break
            chunks.append(chunk)
    except BaseException as error:
        pending = error
    finally:
        try:
            if not _close_response(response, deadline) and pending is None:
                pending = ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
        except BaseException as error:
            if pending is None:
                pending = error
    if pending is not None:
        if isinstance(pending, ArtifactDownloadError):
            raise pending
        if isinstance(pending, TimeoutError):
            raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT") from pending
        if isinstance(pending, Exception):
            raise ArtifactDownloadError("GitHub artifact request failed") from pending
        raise pending
    assert value is not None
    return value


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


def _read_zip_member(bundle: zipfile.ZipFile, item: zipfile.ZipInfo, deadline: float | None) -> bytes:
    chunks: list[bytes] = []
    with bundle.open(item, "r") as source:
        while True:
            _check_deadline(deadline)
            chunk = source.read(_TRANSFER_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
    _check_deadline(deadline)
    return b"".join(chunks)


def _extract(
    archive: Path,
    output: Path,
    expected: set[str],
    *,
    deadline: float | None = None,
) -> None:
    _check_deadline(deadline)
    _owner_dir(output, deadline=deadline)
    try:
        with zipfile.ZipFile(archive) as bundle:
            _check_deadline(deadline)
            infos = bundle.infolist()
            _check_deadline(deadline)
            names = {item.filename for item in infos}
            if len(names) != len(infos):
                raise ArtifactDownloadError("artifact contains duplicate members")
            if names != expected:
                raise ArtifactDownloadError(
                    f"artifact members differ from allow-list: {sorted(names)}"
                )
            safe_items: list[tuple[zipfile.ZipInfo, str]] = []
            for item in infos:
                _check_deadline(deadline)
                name = _safe_member_name(item.filename)
                mode = (item.external_attr >> 16) & 0o170000
                if item.is_dir() or mode not in (0, stat.S_IFREG):
                    raise ArtifactDownloadError("artifact contains an unsafe member")
                safe_items.append((item, name))
            for item, name in safe_items:
                target = output / name
                _owner_file(target, _read_zip_member(bundle, item, deadline), deadline=deadline)
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
    timeout_seconds: float = _DEFAULT_TRANSFER_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Fetch and extract one exact artifact, retaining complete raw bytes."""

    if run_id <= 0 or not artifact_name or any(ch.isspace() for ch in artifact_name):
        raise ArtifactDownloadError("artifact identity is invalid")
    repository = _repository(repository)
    expected_values = tuple(expected_files)
    if not expected_values or len(set(expected_values)) != len(expected_values):
        raise ArtifactDownloadError("artifact allow-list is invalid")
    deadline = _deadline_for(timeout_seconds)
    try:
        expected = {_safe_member_name(value) for value in expected_values}
    except ArtifactDownloadError as error:
        raise ArtifactDownloadError("artifact allow-list is invalid") from error
    listing_url = f"https://api.github.com/repos/{repository}/actions/artifacts?name={quote(artifact_name, safe='')}&per_page=100"
    listing_bytes = _get(listing_url, deadline=deadline)
    _owner_file(metadata_path, listing_bytes, deadline=deadline)
    _check_deadline(deadline)
    try:
        listing = json.loads(listing_bytes)
        _check_deadline(deadline)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactDownloadError("artifact listing is not JSON") from error
    if not isinstance(listing, dict):
        raise ArtifactDownloadError("artifact listing has an unsafe shape")
    selected = _select(listing, name=artifact_name, run_id=run_id)
    _check_deadline(deadline)
    archive_bytes = _get(str(selected["archive_download_url"]), deadline=deadline)
    _owner_file(archive_path, archive_bytes, deadline=deadline)
    _check_deadline(deadline)
    extraction_result: list[BaseException] = []

    def extract() -> None:
        try:
            _extract(archive_path, output_dir, expected, deadline=deadline)
        except BaseException as error:
            extraction_result.append(error)

    worker = threading.Thread(target=extract, name="artifact-extractor", daemon=True)
    worker.start()
    remaining = max(0.0, deadline - time.monotonic() - _DEADLINE_CLEANUP_RESERVE_SECONDS)
    worker.join(remaining)
    if worker.is_alive():
        raise ArtifactDownloadError("ARTIFACT_TRANSFER_TIMEOUT")
    if extraction_result:
        raise extraction_result[0]
    _check_deadline(deadline)
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
    parser.add_argument("--timeout-seconds", type=float, default=_DEFAULT_TRANSFER_TIMEOUT_SECONDS)
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
            timeout_seconds=args.timeout_seconds,
        )
        # The archive and API listing remain complete runner-local evidence.
        # Do not echo artifact names, run ids, or member names into public
        # Actions; expose only a fresh opaque id and archive byte metadata.
        archive_bytes = args.archive.read_bytes()
        emit_evidence("artifact-download", status="completed", payloads={"archive": archive_bytes})
        return 0
    except ArtifactDownloadError as error:
        print(f"artifact-download failed code={type(error).__name__}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
