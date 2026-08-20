from __future__ import annotations

import json
from pathlib import Path
import unittest


class SchemaDocumentTests(unittest.TestCase):
    def test_functional_schema_documents_are_valid_json_and_versioned(self):
        schema_root = Path(__file__).parents[2] / "torturer_contract/functional/schema"
        scenario_schema = json.loads((schema_root / "scenario-v1.schema.json").read_text(encoding="utf-8"))
        result_schema = json.loads((schema_root / "result-v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(scenario_schema["$id"].rsplit("/", 1)[-1], "scenario-v1.schema.json")
        self.assertEqual(result_schema["$id"].rsplit("/", 1)[-1], "result-v1.schema.json")
        self.assertEqual(scenario_schema["properties"]["schema"]["const"], 1)
        self.assertEqual(result_schema["properties"]["schema"]["const"], 1)
        self.assertIn("allOf", result_schema)


if __name__ == "__main__":
    unittest.main()
