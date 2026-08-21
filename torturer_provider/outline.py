"""Secret-safe construction of one disposable Outline WSS profile.

The Render lease controller owns the control-plane service lifecycle.  This
module owns only the run-scoped Outline input that the trusted lease workflow
must install into the pinned image and hand to the prepared client.  It never
logs or serializes the secret as public metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import secrets
from typing import Mapping
from urllib.parse import urlparse


_CIPHER = "chacha20-ietf-poly1305"
_SECRET = re.compile(r"^[0-9a-f]{64}$")
_WEB_PATH = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_-]{15,95}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("listen port must be an integer between 1 and 65535")
    return value


@dataclass(frozen=True)
class OutlineWSSProfile:
    """One disposable key and shared path prefix for stream and packet WSS."""

    web_path: str
    secret: str = field(repr=False)
    cipher: str = _CIPHER

    def __post_init__(self) -> None:
        if not isinstance(self.web_path, str) or not _WEB_PATH.fullmatch(self.web_path):
            raise ValueError("web_path has an invalid format")
        if not isinstance(self.secret, str) or not _SECRET.fullmatch(self.secret):
            raise ValueError("secret must be 32 bytes represented as lowercase hex")
        if self.cipher != _CIPHER:
            raise ValueError("only the pinned Outline AEAD cipher is supported")

    @classmethod
    def random(cls, *, path_bytes: int = 16, secret_bytes: int = 32) -> "OutlineWSSProfile":
        """Create high-entropy run material without accepting caller strings."""

        if not 16 <= path_bytes <= 32:
            raise ValueError("path entropy must be between 16 and 32 bytes")
        if secret_bytes != 32:
            raise ValueError("Outline secret entropy must be exactly 32 bytes")
        return cls(
            web_path=f"/dobby-{secrets.token_hex(path_bytes)}",
            secret=secrets.token_hex(secret_bytes),
        )

    @property
    def stream_path(self) -> str:
        return f"{self.web_path}/tcp"

    @property
    def packet_path(self) -> str:
        return f"{self.web_path}/udp"

    def config_yaml(self, listen_port: int) -> str:
        """Return the owner-only Render secret-file contents.

        The values are validated above before interpolation.  The generated
        config intentionally contains no ordinary TCP/UDP listener and binds
        the provider's single HTTP/WebSocket port.
        """

        listen_port = _port(listen_port)
        return (
            "web:\n"
            "  servers:\n"
            "    - id: dobby-render\n"
            "      listen:\n"
            f'        - "0.0.0.0:{listen_port}"\n'
            "\n"
            "services:\n"
            "  - listeners:\n"
            "      - type: websocket-stream\n"
            "        web_server: dobby-render\n"
            f'        path: "{self.stream_path}"\n'
            "      - type: websocket-packet\n"
            "        web_server: dobby-render\n"
            f'        path: "{self.packet_path}"\n'
            "    keys:\n"
            "      - id: dobby-run\n"
            f"        cipher: {self.cipher}\n"
            f'        secret: "{self.secret}"\n'
        )

    def render_secret_files(self, listen_port: int) -> tuple[tuple[str, str], ...]:
        """Return the only Render secret file needed by the pinned image."""

        return (("config.yml", self.config_yaml(listen_port)),)

    def client_block(self, service_url: str) -> Mapping[str, object]:
        """Build the in-memory DobbyVPN Outline block after service readiness."""

        parsed = urlparse(service_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("service URL must be an HTTPS URL without credentials")
        host = parsed.hostname
        if not _HOST.fullmatch(host):
            raise ValueError("service URL host has an invalid format")
        if parsed.port not in (None, 443):
            raise ValueError("Render WSS service must use HTTPS port 443")
        return {
            "Method": self.cipher,
            "Password": self.secret,
            "Server": host,
            "Port": 443,
            "WebSocket": True,
            "WebSocketPath": self.web_path,
            "DisguisePrefix": "POST ",
        }

    def client_toml(self, service_url: str) -> str:
        """Serialize the trusted client block in DobbyVPN's public TOML shape.

        This serializer is intentionally kept beside the provider contract so
        the hosted lease does not invent a second profile format. Values are
        validated by :meth:`client_block` before interpolation; the returned
        string is handoff data and must remain owner-only.
        """

        block = self.client_block(service_url)
        return (
            "[[Outline]]\n"
            'Description = "DobbyVPN Torturer disposable Render lease"\n'
            f"WebSocket = {str(block['WebSocket']).lower()}\n"
            f'Server = "{block["Server"]}"\n'
            f"Port = {block['Port']}\n"
            f'Password = "{block["Password"]}"\n'
            f'WebSocketPath = "{block["WebSocketPath"]}"\n'
            f'DisguisePrefix = "{block["DisguisePrefix"]}"\n'
        )

    def public_metadata(self) -> Mapping[str, str]:
        """Safe metadata suitable for a lease journal or hosted result."""

        return {
            "cipher": self.cipher,
            "web_path": self.web_path,
            "stream_path": self.stream_path,
            "packet_path": self.packet_path,
        }
