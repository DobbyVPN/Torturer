from __future__ import annotations

import json
from pathlib import Path
import unittest


class SchemaDocumentTests(unittest.TestCase):
    def test_functional_schema_documents_are_valid_json_and_versioned(self):
        schema_root = Path(__file__).parents[2] / "torturer_contract/functional/schema"
        scenario_schema = json.loads((schema_root / "scenario-v1.schema.json").read_text(encoding="utf-8"))
        result_v1_schema = json.loads((schema_root / "result-v1.schema.json").read_text(encoding="utf-8"))
        result_v2_schema = json.loads((schema_root / "result-v2.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(scenario_schema["$id"].rsplit("/", 1)[-1], "scenario-v1.schema.json")
        self.assertEqual(result_v1_schema["$id"].rsplit("/", 1)[-1], "result-v1.schema.json")
        self.assertEqual(result_v2_schema["$id"].rsplit("/", 1)[-1], "result-v2.schema.json")
        self.assertEqual(scenario_schema["properties"]["schema"]["const"], 1)
        self.assertEqual(result_v1_schema["properties"]["schema"]["const"], 1)
        self.assertEqual(result_v2_schema["properties"]["schema"]["const"], 2)
        self.assertIn("allOf", result_v1_schema)
        self.assertIn("allOf", result_v2_schema)
        self.assertNotIn("monotonic_start_ns", result_v1_schema["required"])
        self.assertTrue(
            {
                "monotonic_start_ns",
                "monotonic_end_ns",
                "phase_durations_ms",
                "evidence_refs",
            }.issubset(result_v2_schema["required"])
        )
        self.assertTrue(
            {
                "platform_version",
                "architecture",
                "artifact_kind",
                "artifact_sha256",
                "artifact_manifest_sha256",
            }.issubset(result_v2_schema["$defs"]["provenance"]["required"])
        )


if __name__ == "__main__":
    unittest.main()
