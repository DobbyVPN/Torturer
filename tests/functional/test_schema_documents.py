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

    def test_v2_private_provider_branch_forbids_server_image_digest(self):
        schema_root = Path(__file__).parents[2] / "torturer_contract/functional/schema"
        schema = json.loads((schema_root / "result-v2.schema.json").read_text(encoding="utf-8"))
        branches = schema["$defs"]["provenance"]["oneOf"]
        private = next(
            branch
            for branch in branches
            if branch.get("properties", {}).get("provider_kind", {}).get("const") == "private"
        )
        self.assertEqual(private["required"], ["provider_kind"])
        self.assertEqual(private["not"], {"required": ["server_image_digest"]})

    def test_v2_semantic_constraints_are_model_layer_contract(self):
        schema_root = Path(__file__).parents[2] / "torturer_contract/functional/schema"
        schema = json.loads((schema_root / "result-v2.schema.json").read_text(encoding="utf-8"))
        # Standard JSON Schema has no portable cross-property equality or
        # aggregate-sum operator. The canonical Python model is the required
        # second validation stage for these semantic invariants.
        self.assertNotIn("$data", schema)
        self.assertNotIn("artifact_manifest_distinct", schema)
        self.assertNotIn("phase_duration_sum", schema)


if __name__ == "__main__":
    unittest.main()
