#!/usr/bin/env python3
"""Tests for the publisher's pre-flight validation of the pinned v1 contract."""

import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
FIXTURE_PATH = os.path.join(
    REPO_ROOT, "plugins", "security-audit", "schema", "report.fixture.json"
)
EXAMPLE_PATH = os.path.join(
    REPO_ROOT, "plugins", "security-audit", "schema", "report.example.json"
)

sys.path.insert(0, HERE)
from foundri_publish import validate_report  # noqa: E402


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class ValidateReportTest(unittest.TestCase):
    def test_shipped_fixture_is_valid(self):
        self.assertEqual(validate_report(load(FIXTURE_PATH)), [])

    def test_shipped_example_is_valid(self):
        self.assertEqual(validate_report(load(EXAMPLE_PATH)), [])

    def test_summary_must_match_the_findings_it_ships(self):
        report = copy.deepcopy(load(FIXTURE_PATH))
        report["summary"]["high"] += 3
        errors = validate_report(report)
        self.assertTrue(
            any("summary does not match" in error for error in errors),
            f"expected a summary mismatch error, got {errors}",
        )

    def test_mismatch_names_only_the_severities_that_disagree(self):
        report = copy.deepcopy(load(FIXTURE_PATH))
        report["summary"]["low"] += 1
        (error,) = [e for e in validate_report(report) if "summary does not match" in e]
        self.assertIn("low:", error)
        self.assertNotIn("critical:", error)

    def test_an_empty_report_tallies_to_zero(self):
        report = copy.deepcopy(load(FIXTURE_PATH))
        report["findings"] = []
        report["control_results"] = []
        report["summary"] = dict.fromkeys(
            ["critical", "high", "medium", "low", "info"], 0
        )
        self.assertEqual(validate_report(report), [])


if __name__ == "__main__":
    unittest.main()
