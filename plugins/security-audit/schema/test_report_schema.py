#!/usr/bin/env python3
"""Tests that the emitter example and the fixture agree with the JSON Schema."""

import json
import os
import unittest

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "report.schema.json")
EXAMPLE_PATH = os.path.join(HERE, "report.example.json")
FIXTURE_PATH = os.path.join(HERE, "report.fixture.json")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@unittest.skipIf(jsonschema is None, "jsonschema package not installed")
class ReportSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load(SCHEMA_PATH)

    def check_valid(self, path):
        report = load(path)
        jsonschema.validate(instance=report, schema=self.schema)
        self.assertEqual(report["report_format_version"], 1)
        return report

    def test_example_validates_against_schema(self):
        report = self.check_valid(EXAMPLE_PATH)
        # The example mirrors the pinned contract: non-empty findings and controls.
        self.assertTrue(report["findings"])
        self.assertTrue(report["control_results"])

    def test_fixture_validates_against_schema(self):
        report = self.check_valid(FIXTURE_PATH)
        self.assertTrue(report["findings"])
        self.assertTrue(report["control_results"])

    def test_schema_pins_report_format_version(self):
        self.assertEqual(
            self.schema["properties"]["report_format_version"].get("const"), 1
        )

    def test_schema_rejects_extra_top_level_fields(self):
        self.assertIs(self.schema.get("additionalProperties"), False)


if __name__ == "__main__":
    unittest.main()
