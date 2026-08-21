"""Tests for the disposable Outline WSS profile/config boundary."""

from __future__ import annotations

import unittest

from torturer_provider.outline import OutlineWSSProfile


class OutlineWSSProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = OutlineWSSProfile(
            "/dobby-0123456789abcdef0123456789abcdef",
            "a" * 64,
        )

    def test_config_has_both_distinct_canonical_listener_paths(self) -> None:
        config = self.profile.config_yaml(10000)
        self.assertIn('"0.0.0.0:10000"', config)
        self.assertIn("type: websocket-stream", config)
        self.assertIn("type: websocket-packet", config)
        self.assertIn(f'path: "{self.profile.stream_path}"', config)
        self.assertIn(f'path: "{self.profile.packet_path}"', config)
        self.assertNotIn("type: tcp", config)
        self.assertNotIn("type: udp", config)
        self.assertNotIn("$PORT", config)

    def test_client_block_matches_dobbyvpn_shared_websocket_normalization(self) -> None:
        block = self.profile.client_block("https://example.onrender.com")
        self.assertEqual(block["Server"], "example.onrender.com")
        self.assertEqual(block["Port"], 443)
        self.assertEqual(block["WebSocketPath"], self.profile.web_path)
        self.assertEqual(block["Password"], "a" * 64)

    def test_client_toml_matches_the_product_outline_websocket_shape(self) -> None:
        toml = self.profile.client_toml("https://example.onrender.com")
        self.assertIn("[[Outline]]", toml)
        self.assertIn("WebSocket = true", toml)
        self.assertIn('Server = "example.onrender.com"', toml)
        self.assertIn("Port = 443", toml)
        self.assertIn('WebSocketPath = "' + self.profile.web_path + '"', toml)
        self.assertIn('Password = "' + ("a" * 64) + '"', toml)

    def test_public_metadata_and_repr_never_include_secret(self) -> None:
        metadata = repr(dict(self.profile.public_metadata()))
        self.assertNotIn("a" * 64, metadata)
        self.assertNotIn("a" * 64, repr(self.profile))

    def test_secret_file_contract_is_owner_workflow_only(self) -> None:
        files = self.profile.render_secret_files(443)
        self.assertEqual(files[0][0], "config.yml")
        self.assertIn("secret: \"" + ("a" * 64) + "\"", files[0][1])

    def test_validation_rejects_unsafe_values_and_urls(self) -> None:
        with self.assertRaises(ValueError):
            OutlineWSSProfile("/short", "a" * 64)
        with self.assertRaises(ValueError):
            OutlineWSSProfile(self.profile.web_path, "not-a-secret")
        with self.assertRaises(ValueError):
            self.profile.config_yaml(0)
        with self.assertRaises(ValueError):
            self.profile.client_block("http://example.onrender.com")
        with self.assertRaises(ValueError):
            self.profile.client_block("https://user:pass@example.onrender.com")

    def test_random_profiles_are_run_scoped(self) -> None:
        first = OutlineWSSProfile.random()
        second = OutlineWSSProfile.random()
        self.assertNotEqual(first.web_path, second.web_path)
        self.assertNotEqual(first.secret, second.secret)
        self.assertEqual(len(first.secret), 64)


if __name__ == "__main__":
    unittest.main()
