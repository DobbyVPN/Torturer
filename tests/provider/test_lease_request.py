from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from torturer_provider.lease_request import LeaseRequestError, RenderLeaseRequest


class RenderLeaseRequestTests(unittest.TestCase):
    def test_round_trip_contains_only_opaque_fields(self) -> None:
        request = RenderLeaseRequest("a" * 32, "linux", "sha256:" + "b" * 64)
        parsed = RenderLeaseRequest.parse(request.to_dict())
        self.assertEqual(parsed, request)
        self.assertNotIn("profile", json.dumps(request.to_dict()).lower())
        self.assertNotIn("endpoint", json.dumps(request.to_dict()).lower())

    def test_rejects_extra_fields_and_unsafe_values(self) -> None:
        value = RenderLeaseRequest("a" * 32, "linux", "sha256:" + "b" * 64).to_dict()
        value["owner_id"] = "must-not-cross"
        with self.assertRaises(LeaseRequestError):
            RenderLeaseRequest.parse(value)
        for field, bad in (("run_id", "short"), ("platform", "freebsd"), ("image_digest", "latest")):
            candidate = RenderLeaseRequest("a" * 32, "linux", "sha256:" + "b" * 64).to_dict()
            candidate[field] = bad
            with self.assertRaises(LeaseRequestError):
                RenderLeaseRequest.parse(candidate)

    def test_file_reader_rejects_oversized_input_and_reads_valid_input(self) -> None:
        request = RenderLeaseRequest("c" * 32, "macos", "sha256:" + "d" * 64)
        with tempfile.TemporaryDirectory(prefix="lease-request-") as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request.to_dict()), encoding="utf-8")
            self.assertEqual(RenderLeaseRequest.from_file(path), request)
            path.write_text("x" * (64 * 1024 + 1), encoding="utf-8")
            with self.assertRaises(LeaseRequestError):
                RenderLeaseRequest.from_file(path)


if __name__ == "__main__":
    unittest.main()
