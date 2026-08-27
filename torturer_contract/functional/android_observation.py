"""Safe observation contract for a future Android profile test seam."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Mapping


_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class AndroidObservationError(ValueError):
    """Raised when a candidate Android observation record is unsafe or incomplete."""


@dataclass(frozen=True)
class AndroidProfileObservation:
    """Only product observations; no profile, endpoint, or literal IP values."""

    source_sha: str
    configured: bool
    connected: bool
    tunnel_interface: bool
    routing_identity_changed: bool
    stability_verified: bool
    network_transition_verified: bool
    sleep_wake_verified: bool
    process_loss_verified: bool
    latency_ms: float
    download_mbps: float
    upload_mbps: float
    disconnect_clean: bool
    restart_verified: bool
    reconnect_bounded: bool
    second_tunnel_interface: bool
    second_routing_identity_changed: bool
    final_disconnect_clean: bool
    cleanup_verified: bool
    error_code: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_sha, str)
            or re.fullmatch(r"[0-9a-f]{40}", self.source_sha) is None
            or self.source_sha == "0" * 40
        ):
            raise AndroidObservationError("source_sha is invalid")
        for name in (
            "configured", "connected", "tunnel_interface",
            "routing_identity_changed", "stability_verified", "disconnect_clean",
            "network_transition_verified", "sleep_wake_verified", "process_loss_verified",
            "restart_verified", "reconnect_bounded", "second_tunnel_interface",
            "second_routing_identity_changed", "final_disconnect_clean",
            "cleanup_verified",
        ):
            if not isinstance(getattr(self, name), bool):
                raise AndroidObservationError(f"{name} must be boolean")
        for name in ("latency_ms", "download_mbps", "upload_mbps"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise AndroidObservationError(f"{name} must be finite and non-negative")
        if self.error_code is not None and _ERROR_CODE.fullmatch(self.error_code) is None:
            raise AndroidObservationError("error_code is invalid")

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object],
        *,
        expected_source_sha: str | None = None,
    ) -> "AndroidProfileObservation":
        expected = {
            "schema", "kind", "platform", "source_sha", "configured", "connected",
            "tunnel_interface", "routing_identity_changed",
            "stability_verified", "network_transition_verified", "sleep_wake_verified",
            "process_loss_verified", "latency_ms", "download_mbps",
            "upload_mbps", "disconnect_clean", "restart_verified", "reconnect_bounded",
            "second_tunnel_interface", "second_routing_identity_changed",
            "final_disconnect_clean", "cleanup_verified",
        }
        optional = {"error_code"}
        if not isinstance(value, Mapping) or set(value) - (expected | optional) or not expected <= set(value):
            raise AndroidObservationError("observation has an unexpected shape")
        if value.get("schema") != 1 or value.get("kind") != "dobbyvpn.android.profile-observation":
            raise AndroidObservationError("observation identity is invalid")
        if value.get("platform") != "android":
            raise AndroidObservationError("observation platform is invalid")
        error_code = value.get("error_code")
        if error_code is not None and not isinstance(error_code, str):
            raise AndroidObservationError("error_code is invalid")
        observation = cls(
            source_sha=value["source_sha"],
            configured=value["configured"],
            connected=value["connected"],
            tunnel_interface=value["tunnel_interface"],
            routing_identity_changed=value["routing_identity_changed"],
            stability_verified=value["stability_verified"],
            network_transition_verified=value["network_transition_verified"],
            sleep_wake_verified=value["sleep_wake_verified"],
            process_loss_verified=value["process_loss_verified"],
            latency_ms=value["latency_ms"],
            download_mbps=value["download_mbps"],
            upload_mbps=value["upload_mbps"],
            disconnect_clean=value["disconnect_clean"],
            restart_verified=value["restart_verified"],
            reconnect_bounded=value["reconnect_bounded"],
            second_tunnel_interface=value["second_tunnel_interface"],
            second_routing_identity_changed=value["second_routing_identity_changed"],
            final_disconnect_clean=value["final_disconnect_clean"],
            cleanup_verified=value["cleanup_verified"],
            error_code=error_code,
        )
        if expected_source_sha is not None:
            if (
                re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None
                or expected_source_sha == "0" * 40
            ):
                raise AndroidObservationError("expected source_sha is invalid")
            if observation.source_sha != expected_source_sha:
                raise AndroidObservationError("source_sha does not match candidate")
        return observation

    def to_observations(self) -> dict[str, object]:
        """Map safe product facts to the canonical engine vocabulary."""

        if self.error_code is not None:
            raise AndroidObservationError("observation reports an error")
        return {
            "configured": self.configured,
            "connected": self.connected,
            "tunnel_interface": self.tunnel_interface,
            "routing_identity_changed": self.routing_identity_changed,
            "stability_verified": self.stability_verified,
            "network_transition_verified": self.network_transition_verified,
            "sleep_wake_verified": self.sleep_wake_verified,
            "process_loss_verified": self.process_loss_verified,
            "latency_ms": self.latency_ms,
            "download_mbps": self.download_mbps,
            "upload_mbps": self.upload_mbps,
            "disconnect_clean": self.disconnect_clean,
            "restart_verified": self.restart_verified,
            "reconnect_bounded": self.reconnect_bounded,
            "second_tunnel_interface": self.second_tunnel_interface,
            "second_routing_identity_changed": self.second_routing_identity_changed,
            "final_disconnect_clean": self.final_disconnect_clean,
            "cleanup_verified": self.cleanup_verified,
        }
