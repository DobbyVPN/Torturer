from __future__ import annotations

import math
import unittest

from torturer_contract.functional.android_observation import (
    AndroidObservationError,
    AndroidProfileObservation,
)


def _valid() -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "dobbyvpn.android.profile-observation",
        "platform": "android",
        "source_sha": "a" * 40,
        "configured": True,
        "connected": True,
        "tunnel_interface": True,
        "routing_identity_changed": True,
        "stability_verified": True,
        "network_transition_verified": True,
        "sleep_wake_verified": True,
        "process_loss_verified": True,
        "latency_ms": 12.5,
        "download_mbps": 20.0,
        "upload_mbps": 10.0,
        "disconnect_clean": True,
        "restart_verified": True,
        "reconnect_bounded": True,
        "second_tunnel_interface": True,
        "second_routing_identity_changed": True,
        "final_disconnect_clean": True,
        "cleanup_verified": True,
    }


class AndroidObservationContractTests(unittest.TestCase):
    def test_accepts_safe_observation_and_maps_only_engine_facts(self) -> None:
        observation = AndroidProfileObservation.from_mapping(_valid())
        self.assertEqual(observation.to_observations()["routing_identity_changed"], True)
        self.assertNotIn("source_sha", observation.to_observations())
        self.assertNotIn("observed_ipv4", observation.to_observations())

    def test_requires_matching_source_sha_and_rejects_reported_errors(self) -> None:
        value = _valid()
        with self.assertRaisesRegex(AndroidObservationError, "source_sha"):
            AndroidProfileObservation.from_mapping(value, expected_source_sha="b" * 40)
        value["error_code"] = "DRIVER_ERROR"
        observation = AndroidProfileObservation.from_mapping(
            value, expected_source_sha="a" * 40
        )
        with self.assertRaisesRegex(AndroidObservationError, "reports an error"):
            observation.to_observations()

    def test_rejects_profile_or_literal_identity_fields(self) -> None:
        value = _valid()
        value["profile"] = "secret"
        with self.assertRaisesRegex(AndroidObservationError, "unexpected shape"):
            AndroidProfileObservation.from_mapping(value)
        value = _valid()
        value["observed_ipv4"] = "198.51.100.10"
        with self.assertRaisesRegex(AndroidObservationError, "unexpected shape"):
            AndroidProfileObservation.from_mapping(value)

    def test_rejects_invalid_identity_platform_and_nonfinite_metrics(self) -> None:
        value = _valid()
        value["platform"] = "linux"
        with self.assertRaisesRegex(AndroidObservationError, "platform"):
            AndroidProfileObservation.from_mapping(value)
        value = _valid()
        value["latency_ms"] = math.nan
        with self.assertRaisesRegex(AndroidObservationError, "finite"):
            AndroidProfileObservation.from_mapping(value)


if __name__ == "__main__":
    unittest.main()
