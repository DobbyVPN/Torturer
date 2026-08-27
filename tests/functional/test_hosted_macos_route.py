from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from torturer_checks.hosted.macos_route import (
    MacOSDefaultRoute,
    MacOSRouteError,
    MacOSRouteProbe,
    RestoreDecision,
    decide_restore,
    parse_baseline,
    parse_default_route,
    restore,
    verify_baseline,
)
from torturer_checks.hosted.macos_route import _service_is_dead


_BASELINE_TEXT = (
    "   route to: default\n"
    "destination: default\n"
    "       mask: default\n"
    "    gateway: 192.168.64.1\n"
    "  interface: en0\n"
    "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
)
_TUNNEL_TEXT = (
    "   route to: default\n"
    "destination: default\n"
    "    gateway: link#20\n"
    "  interface: utun233\n"
    "      flags: <UP,GATEWAY,DONE,STATIC>\n"
)
_ABSENT_TEXT = "route: writing to routing socket: not in table\n"


class HostedMacOSRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = MacOSDefaultRoute(
            "192.168.64.1",
            "en0",
            "<UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>",
        )

    def test_parse_normal_default_route(self) -> None:
        probe = parse_default_route(_BASELINE_TEXT)
        self.assertFalse(probe.absent)
        self.assertEqual(probe.route, self.baseline)

    def test_not_in_table_is_absent_even_when_route_returns_success(self) -> None:
        probe = parse_default_route(_ABSENT_TEXT, returncode=0)
        self.assertTrue(probe.absent)
        self.assertIsNone(probe.route)
        self.assertTrue(parse_default_route(_ABSENT_TEXT, returncode=1).absent)

    def test_absent_route_with_fields_is_ambiguous(self) -> None:
        with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_STATE_AMBIGUOUS"):
            parse_default_route(_ABSENT_TEXT + "  interface: en0\n")

    def test_missing_baseline_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macos-route-test-") as directory:
            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_BASELINE_MISSING"):
                parse_baseline(missing)
            absent = Path(directory) / "absent"
            absent.write_text(_ABSENT_TEXT, encoding="utf-8")
            with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_BASELINE_MISSING"):
                parse_baseline(absent)

    def test_matching_route_is_a_verified_noop(self) -> None:
        decision = decide_restore(
            self.baseline,
            parse_default_route(_BASELINE_TEXT),
            service_dead=True,
        )
        self.assertEqual(decision, RestoreDecision("not-needed", None))

    def test_absent_route_selects_add_with_captured_gateway(self) -> None:
        decision = decide_restore(
            self.baseline,
            parse_default_route(_ABSENT_TEXT),
            service_dead=True,
        )
        self.assertEqual(decision.action, "add")
        self.assertEqual(
            decision.command,
            ("sudo", "-n", "route", "-n", "add", "default", "192.168.64.1"),
        )

    def test_tunnel_route_selects_change_and_foreign_route_is_rejected(self) -> None:
        decision = decide_restore(
            self.baseline,
            parse_default_route(_TUNNEL_TEXT),
            service_dead=True,
        )
        self.assertEqual(decision.action, "change")
        self.assertEqual(
            decision.command,
            ("sudo", "-n", "route", "-n", "change", "default", "192.168.64.1"),
        )
        foreign = _TUNNEL_TEXT.replace("utun233", "en1")
        with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_STATE_AMBIGUOUS"):
            decide_restore(self.baseline, parse_default_route(foreign), service_dead=True)

    def test_live_service_is_rejected_before_route_mutation(self) -> None:
        with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_SERVICE_LIVE"):
            decide_restore(
                self.baseline,
                parse_default_route(_ABSENT_TEXT),
                service_dead=False,
            )

    def test_verify_requires_exact_gateway_and_interface(self) -> None:
        verify_baseline(self.baseline, parse_default_route(_BASELINE_TEXT))
        with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_VERIFY_FAILED"):
            verify_baseline(
                self.baseline,
                parse_default_route(_BASELINE_TEXT.replace("192.168.64.1", "192.168.64.2")),
            )

    def test_restore_absent_route_confirms_absence_adds_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macos-route-restore-") as directory:
            root = Path(directory)
            baseline = root / "baseline.raw.log"
            service_probe = root / "service-probe.raw.log"
            current = root / "current.raw.log"
            confirmation = root / "confirmation.raw.log"
            restored = root / "restore.raw.log"
            verified = root / "verified.raw.log"
            baseline.write_text(_BASELINE_TEXT, encoding="utf-8")
            calls: list[tuple[str, ...]] = []

            def capture(command, path, timeout_seconds):
                calls.append(tuple(command))
                if path in (current, confirmation):
                    path.write_text(_ABSENT_TEXT, encoding="utf-8")
                elif path == verified:
                    path.write_text(_BASELINE_TEXT, encoding="utf-8")
                else:
                    path.write_text("route restored\n", encoding="utf-8")
                return 0

            with (
                mock.patch("torturer_checks.hosted.macos_route._capture", side_effect=capture),
                mock.patch("torturer_checks.hosted.macos_route._service_is_dead", return_value=True),
            ):
                action = restore(
                    baseline_file=baseline,
                    service_probe_file=service_probe,
                    current_file=current,
                    confirmation_file=confirmation,
                    restore_file=restored,
                    verified_file=verified,
                    service_pid=123,
                    timeout_seconds=10,
                )
            self.assertEqual(action, "add")
            self.assertIn(
                ("sudo", "-n", "route", "-n", "add", "default", "192.168.64.1"),
                calls,
            )

    def test_restore_rejects_ambiguous_current_route_and_missing_baseline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macos-route-restore-") as directory:
            root = Path(directory)
            baseline = root / "baseline.raw.log"
            service_probe = root / "service-probe.raw.log"
            baseline.write_text(_BASELINE_TEXT, encoding="utf-8")
            current = root / "current.raw.log"
            confirmation = root / "confirmation.raw.log"
            restored = root / "restore.raw.log"
            verified = root / "verified.raw.log"

            def capture(command, path, timeout_seconds):
                if path == current:
                    path.write_text(_ABSENT_TEXT + "  interface: en0\n", encoding="utf-8")
                return 0

            with (
                mock.patch("torturer_checks.hosted.macos_route._capture", side_effect=capture),
                mock.patch("torturer_checks.hosted.macos_route._service_is_dead", return_value=True),
            ):
                with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_STATE_AMBIGUOUS"):
                    restore(
                        baseline_file=baseline,
                        service_probe_file=service_probe,
                        current_file=current,
                        confirmation_file=confirmation,
                        restore_file=restored,
                        verified_file=verified,
                        service_pid=123,
                        timeout_seconds=10,
                    )
            with self.assertRaisesRegex(MacOSRouteError, "DEFAULT_ROUTE_BASELINE_MISSING"):
                decide_restore(None, MacOSRouteProbe(0, None, True), service_dead=True)

    def test_service_probe_is_bound_to_pid_start_identity_and_command(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macos-route-identity-") as directory:
            root = Path(directory)
            probe = root / "service-probe.raw.log"
            identity = root / "service.identity.json"
            identity.write_text(
                json.dumps(
                    {
                        "pid": 123,
                        "start": "Wed Aug 27 12:34:56 2026",
                        "command": "/candidate/macos_grpcvpnserver -port 50051",
                    }
                ),
                encoding="utf-8",
            )

            def capture(command, path, timeout_seconds):
                path.write_text(
                    "123 Wed Aug 27 12:34:56 2026 /candidate/macos_grpcvpnserver -port 50051\n",
                    encoding="utf-8",
                )
                return 0

            with mock.patch("torturer_checks.hosted.macos_route._capture", side_effect=capture):
                self.assertFalse(_service_is_dead(123, 10, probe, identity))

            identity.write_text(
                json.dumps(
                    {
                        "pid": 123,
                        "start": "Wed Aug 27 12:34:57 2026",
                        "command": "/candidate/macos_grpcvpnserver -port 50051",
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch("torturer_checks.hosted.macos_route._capture", side_effect=capture),
                self.assertRaisesRegex(
                    MacOSRouteError, "DEFAULT_ROUTE_SERVICE_IDENTITY_MISMATCH"
                ),
            ):
                _service_is_dead(123, 10, probe, identity)


if __name__ == "__main__":
    unittest.main()
