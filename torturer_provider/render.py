"""Small, secret-safe controller for one disposable Render web service.

The controller manages Render's control plane only.  It deliberately does
not create or serialize an Outline access key: that is a server-image
protocol concern and must cross into a trusted test job through the separate
profile handoff.  Every API error is reduced to a stable code and HTTP
status; response bodies and the bearer token are never included in an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import time
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


_SERVICE_ID = re.compile(r"^srv-[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_DEPLOY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_OWNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,99}$")
_SERVICE_NAME = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
_IMAGE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{2,255}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_READY_STATUSES = frozenset({"live"})
_FAILED_STATUSES = frozenset({"build_failed", "update_failed", "canceled", "deactivated"})
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_REGIONS = frozenset({"frankfurt", "oregon", "ohio", "singapore", "virginia"})


class RenderAPIError(RuntimeError):
    """A stable, non-sensitive provider failure."""

    def __init__(self, code: str, status: int | None = None) -> None:
        self.code = code
        self.status = status
        detail = f"{code}:{status}" if status is not None else code
        super().__init__(detail)


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    payload: object


class RenderTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> HTTPResponse: ...


class _URLTransport:
    def __init__(self, base_url: str, timeout_seconds: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> HTTPResponse:
        body = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            headers=dict(headers),
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                status = int(response.status)
        except HTTPError as error:
            raise RenderAPIError("HTTP_ERROR", int(error.code)) from error
        except (OSError, URLError, TimeoutError) as error:
            raise RenderAPIError("TRANSPORT_ERROR") from error
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise RenderAPIError("RESPONSE_TOO_LARGE", status)
        if not raw:
            return HTTPResponse(status, {})
        try:
            payload_value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RenderAPIError("INVALID_JSON", status) from error
        return HTTPResponse(status, payload_value)


def _require(value: object, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{name} has an invalid format")
    return value


def _timestamp(value: object, name: str = "created_at") -> float:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} has an invalid format")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} has an invalid format") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc).timestamp()


def _service_prefix(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,62}", value):
        raise ValueError("service name prefix has an invalid format")
    return value


@dataclass(frozen=True)
class RenderServiceSpec:
    """The only service configuration allowed by the disposable lane."""

    owner_id: str
    name: str
    image_owner_id: str
    image_path: str
    image_digest: str
    region: str = "oregon"
    plan: str = "free"
    # None is intentional for Outline WSS images: the listener rejects a
    # plain HTTP GET, so authenticated WebSocket readiness belongs to the
    # functional adapter rather than a fabricated HTTP health path.
    health_check_path: str | None = None
    secret_files: tuple[tuple[str, str], ...] = ()
    docker_command: str | None = None

    def __post_init__(self) -> None:
        _require(self.owner_id, _OWNER_ID, "owner_id")
        _require(self.image_owner_id, _OWNER_ID, "image_owner_id")
        _require(self.name, _SERVICE_NAME, "name")
        _require(self.image_path, _IMAGE_PATH, "image_path")
        _require(self.image_digest, _IMAGE_DIGEST, "image_digest")
        if self.region not in _REGIONS:
            raise ValueError("unsupported Render region")
        if self.plan != "free":
            raise ValueError("disposable controller only permits the free plan")
        if self.health_check_path is not None:
            if not isinstance(self.health_check_path, str) or not self.health_check_path.startswith("/"):
                raise ValueError("health_check_path must be an absolute path")
            if any(character in self.health_check_path for character in "?#"):
                raise ValueError("health_check_path must not contain a query or fragment")
        if not isinstance(self.secret_files, tuple):
            raise ValueError("secret_files must be a tuple")
        seen_names: set[str] = set()
        for name, content in self.secret_files:
            _require(name, _SECRET_NAME, "secret file name")
            if name in seen_names:
                raise ValueError("secret file names must be unique")
            seen_names.add(name)
            if not isinstance(content, str) or not content or "\x00" in content:
                raise ValueError("secret file content must be non-empty text")
        if self.docker_command is not None:
            if not isinstance(self.docker_command, str) or not self.docker_command or "\x00" in self.docker_command:
                raise ValueError("docker_command must be non-empty text")
            if any(character in self.docker_command for character in "\r\n"):
                raise ValueError("docker_command must be one line")

    def payload(self) -> dict[str, object]:
        """Build the image-backed, one-instance, no-autodeploy request."""

        service_details: dict[str, object] = {
            "runtime": "image",
            "plan": self.plan,
            "region": self.region,
            "numInstances": 1,
        }
        if self.health_check_path is not None:
            service_details["healthCheckPath"] = self.health_check_path
        if self.docker_command is not None:
            service_details["envSpecificDetails"] = {"dockerCommand": self.docker_command}
        payload: dict[str, object] = {
            "type": "web_service",
            "name": self.name,
            "ownerId": self.owner_id,
            "autoDeploy": "no",
            "image": {"ownerId": self.image_owner_id, "imagePath": self.image_path},
            "serviceDetails": service_details,
        }
        if self.secret_files:
            payload["secretFiles"] = [
                {"name": name, "content": content} for name, content in self.secret_files
            ]
        return payload

@dataclass(frozen=True)
class RenderServiceRecord:
    """Safe identity fields returned by the Render service list endpoint."""

    service_id: str
    name: str
    owner_id: str
    service_type: str
    created_at: str

    def __post_init__(self) -> None:
        _require(self.service_id, _SERVICE_ID, "service_id")
        _require(self.name, _SERVICE_NAME, "name")
        _require(self.owner_id, _OWNER_ID, "owner_id")
        if self.service_type != "web_service":
            raise ValueError("service list contained a non-web service")
        _timestamp(self.created_at)


@dataclass(frozen=True)
class RenderServiceHandle:
    service_id: str
    deploy_id: str | None
    image_digest: str

    def __post_init__(self) -> None:
        _require(self.service_id, _SERVICE_ID, "service_id")
        if self.deploy_id is not None:
            _require(self.deploy_id, _DEPLOY_ID, "deploy_id")
        _require(self.image_digest, _IMAGE_DIGEST, "image_digest")


@dataclass(frozen=True)
class RenderServiceReady:
    handle: RenderServiceHandle
    url: str
    provider_generation: str

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Render service URL must be an HTTPS URL without credentials")
        _require(self.provider_generation, _DEPLOY_ID, "provider_generation")


class RenderAPI:
    """Typed API operations with no response/token echoing."""

    def __init__(
        self,
        token: str,
        *,
        base_url: str = "https://api.render.com/v1",
        timeout_seconds: float = 20.0,
        transport: RenderTransport | None = None,
    ) -> None:
        if not isinstance(token, str) or not token or any(character.isspace() for character in token):
            raise ValueError("Render API token must be a non-empty single value")
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Render API base URL must be HTTPS without credentials")
        if timeout_seconds <= 0:
            raise ValueError("Render API timeout must be positive")
        self._token = token
        self._transport = transport or _URLTransport(base_url, timeout_seconds)

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        expected: frozenset[int],
        query: Mapping[str, object] | None = None,
    ) -> object:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("Render API path must be a fixed path")
        request_path = path
        if query:
            if any(not isinstance(key, str) or not key for key in query):
                raise ValueError("Render API query names must be non-empty strings")
            if any(not isinstance(value, (str, int)) or isinstance(value, bool) for value in query.values()):
                raise ValueError("Render API query values must be strings or integers")
            request_path = f"{path}?{urlencode(query)}"
        try:
            response = self._transport.request(
                method,
                request_path,
                payload,
                {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
            )
        except RenderAPIError:
            raise
        except Exception as error:
            raise RenderAPIError("TRANSPORT_ERROR") from error
        if response.status not in expected:
            raise RenderAPIError("UNEXPECTED_STATUS", response.status)
        return response.payload

    @staticmethod
    def _object(payload: object, code: str = "INVALID_RESPONSE") -> Mapping[str, Any]:
        if not isinstance(payload, dict):
            raise RenderAPIError(code)
        return payload

    def create_service(self, spec: RenderServiceSpec) -> RenderServiceHandle:
        payload = self._object(self._request("POST", "/services", spec.payload(), expected=frozenset({201})))
        service = self._object(payload.get("service"))
        service_id = service.get("id")
        if not isinstance(service_id, str) or not _SERVICE_ID.fullmatch(service_id):
            raise RenderAPIError("INVALID_SERVICE_ID")
        deploy_id = payload.get("deployId")
        if deploy_id is not None and (not isinstance(deploy_id, str) or not _DEPLOY_ID.fullmatch(deploy_id)):
            raise RenderAPIError("INVALID_DEPLOY_ID")
        return RenderServiceHandle(service_id, deploy_id, spec.image_digest)

    def service(self, service_id: str) -> Mapping[str, Any]:
        _require(service_id, _SERVICE_ID, "service_id")
        return self._object(self._request("GET", f"/services/{service_id}", expected=frozenset({200})))

    def list_services(
        self,
        owner_id: str,
        *,
        page_limit: int = 100,
        max_pages: int = 100,
    ) -> tuple[RenderServiceRecord, ...]:
        """List only web services in one owner workspace, with bounded pagination."""
        _require(owner_id, _OWNER_ID, "owner_id")
        if not 1 <= page_limit <= 100 or max_pages <= 0:
            raise ValueError("Render service-list bounds are invalid")
        records: list[RenderServiceRecord] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(max_pages):
            query: dict[str, object] = {
                "ownerId": owner_id,
                "type": "web_service",
                "limit": page_limit,
            }
            if cursor is not None:
                query["cursor"] = cursor
            payload = self._request("GET", "/services", expected=frozenset({200}), query=query)
            if not isinstance(payload, list):
                raise RenderAPIError("INVALID_SERVICE_LIST")
            for item in payload:
                wrapper = self._object(item, "INVALID_SERVICE_LIST")
                service = self._object(wrapper.get("service"), "INVALID_SERVICE_LIST")
                try:
                    records.append(RenderServiceRecord(
                        service_id=service["id"],
                        name=service["name"],
                        owner_id=service["ownerId"],
                        service_type=service["type"],
                        created_at=service["createdAt"],
                    ))
                except (KeyError, TypeError, ValueError) as error:
                    raise RenderAPIError("INVALID_SERVICE_LIST") from error
            if len(payload) < page_limit:
                return tuple(records)
            if not payload:
                return tuple(records)
            last = self._object(payload[-1], "INVALID_SERVICE_LIST")
            next_cursor = last.get("cursor")
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise RenderAPIError("INVALID_SERVICE_CURSOR")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise RenderAPIError("SERVICE_LIST_PAGINATION_LIMIT")


    def deploy(self, service_id: str, deploy_id: str) -> Mapping[str, Any]:
        _require(service_id, _SERVICE_ID, "service_id")
        _require(deploy_id, _DEPLOY_ID, "deploy_id")
        return self._object(self._request("GET", f"/services/{service_id}/deploys/{deploy_id}", expected=frozenset({200})))

    def delete_service(self, service_id: str) -> bool:
        _require(service_id, _SERVICE_ID, "service_id")
        try:
            self._request("DELETE", f"/services/{service_id}", expected=frozenset({204}))
            return True
        except RenderAPIError as error:
            if error.status == 404:
                return True
            raise

    def exists(self, service_id: str) -> bool:
        _require(service_id, _SERVICE_ID, "service_id")
        try:
            self.service(service_id)
            return True
        except RenderAPIError as error:
            if error.status == 404:
                return False
            raise


class DisposableRenderController:
    """Create one service, wait for readiness, and clean it up fail-closed."""

    def __init__(
        self,
        api: RenderAPI,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api = api
        self._clock = clock
        self._sleeper = sleeper

    def acquire(self, spec: RenderServiceSpec, *, timeout_seconds: float = 600.0, poll_seconds: float = 5.0) -> RenderServiceReady:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("Render readiness bounds must be positive")
        handle = self.api.create_service(spec)
        try:
            return self._wait_until_ready(handle, timeout_seconds, poll_seconds)
        except Exception:
            try:
                self.api.delete_service(handle.service_id)
            except Exception as cleanup_error:
                raise RenderAPIError("CREATE_CLEANUP_FAILED") from cleanup_error
            raise

    def _wait_until_ready(self, handle: RenderServiceHandle, timeout_seconds: float, poll_seconds: float) -> RenderServiceReady:
        deadline = self._clock() + timeout_seconds
        while True:
            service = self.api.service(handle.service_id)
            suspended = service.get("suspended")
            if suspended == "suspended":
                raise RenderAPIError("SERVICE_SUSPENDED")
            details = service.get("serviceDetails")
            if isinstance(details, dict):
                url = details.get("url")
                instances = details.get("numInstances")
                if instances is not None and instances != 1:
                    raise RenderAPIError("INSTANCE_COUNT_MISMATCH")
            else:
                url = None
            deploy_status: str | None = None
            if handle.deploy_id is not None:
                deploy = self.api.deploy(handle.service_id, handle.deploy_id)
                deploy_status_value = deploy.get("status")
                if isinstance(deploy_status_value, str):
                    deploy_status = deploy_status_value
                if deploy_status in _FAILED_STATUSES:
                    raise RenderAPIError("DEPLOY_FAILED")
            if deploy_status in _READY_STATUSES and isinstance(url, str):
                ready = RenderServiceReady(handle, url, handle.deploy_id or handle.service_id)
                return ready
            now = self._clock()
            if now >= deadline:
                raise RenderAPIError("READINESS_TIMEOUT")
            self._sleeper(min(poll_seconds, max(0.0, deadline - now)))

    def release(self, ready: RenderServiceReady) -> None:
        self.api.delete_service(ready.handle.service_id)
        if self.api.exists(ready.handle.service_id):
            raise RenderAPIError("DELETE_NOT_VERIFIED")


class RenderReaper:
    """Idempotent cleanup for explicit IDs or aged, name-selected test services."""

    def __init__(self, api: RenderAPI, *, clock: Callable[[], float] = time.time) -> None:
        self.api = api
        self._clock = clock

    def reap(self, service_ids: tuple[str, ...]) -> None:
        for service_id in service_ids:
            _require(service_id, _SERVICE_ID, "service_id")
            self.api.delete_service(service_id)
            if self.api.exists(service_id):
                raise RenderAPIError("REAPER_DELETE_NOT_VERIFIED")

    def reap_tagged(
        self,
        owner_id: str,
        name_prefix: str,
        *,
        active_service_ids: tuple[str, ...] = (),
        older_than_seconds: float = 900.0,
    ) -> tuple[str, ...]:
        """Delete only aged services in the dedicated owner/name namespace.

        Render's public service API has no arbitrary tag field.  The safe
        selector is therefore the exact owner, web-service type, and a
        validated dedicated name prefix; active lease IDs are excluded.
        """
        _require(owner_id, _OWNER_ID, "owner_id")
        prefix = _service_prefix(name_prefix)
        if older_than_seconds < 0:
            raise ValueError("reaper age bound must not be negative")
        active = set()
        for service_id in active_service_ids:
            active.add(_require(service_id, _SERVICE_ID, "active_service_id"))
        now = self._clock()
        if not isinstance(now, (int, float)) or isinstance(now, bool):
            raise ValueError("reaper clock returned an invalid value")
        deleted: list[str] = []
        for record in self.api.list_services(owner_id):
            if record.owner_id != owner_id or record.service_id in active or not record.name.startswith(prefix):
                continue
            try:
                age = now - _timestamp(record.created_at)
            except ValueError:
                continue
            if age < older_than_seconds:
                continue
            self.reap((record.service_id,))
            deleted.append(record.service_id)
        return tuple(deleted)


__all__ = [
    "DisposableRenderController",
    "HTTPResponse",
    "RenderAPI",
    "RenderAPIError",
    "RenderReaper",
    "RenderServiceHandle",
    "RenderServiceRecord",
    "RenderServiceReady",
    "RenderServiceSpec",
]
