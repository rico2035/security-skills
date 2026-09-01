#!/usr/bin/env python3
"""Unit tests for the Foundri hook-event JSONL logger in security_hook."""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import security_hook  # noqa: E402

REQUIRED_KEYS = {"id", "decision", "rule", "tool", "file_path", "match", "actor", "at"}


class LogDecisionTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.log_path = os.path.join(self.tmpdir.name, "nested", "hook-events.jsonl")
        os.environ["FOUNDRI_HOOK_LOG"] = self.log_path
        self.addCleanup(lambda: os.environ.pop("FOUNDRI_HOOK_LOG", None))

    def read_lines(self):
        with open(self.log_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_writes_valid_line_and_creates_parent_dirs(self):
        security_hook.log_decision("block", ["AWS Access Key ID detected"], "Write", "src/config/aws.ts")
        lines = self.read_lines()
        self.assertEqual(len(lines), 1)
        record = lines[0]
        self.assertEqual(set(record.keys()), REQUIRED_KEYS)
        self.assertEqual(record["decision"], "block")
        self.assertEqual(record["rule"], "AWS Access Key ID detected")
        self.assertEqual(record["tool"], "Write")
        self.assertEqual(record["file_path"], "src/config/aws.ts")
        self.assertTrue(record["id"])
        self.assertTrue(record["actor"])
        # ISO 8601 UTC timestamp
        self.assertTrue(record["at"].endswith("Z"))
        datetime.fromisoformat(record["at"].replace("Z", "+00:00"))

    def test_match_is_redacted_descriptor(self):
        security_hook.log_decision("block", ["AWS Access Key ID detected"], "Write", "src/config/aws.ts")
        record = self.read_lines()[0]
        self.assertEqual(record["match"], "AWS Access Key ID (redacted)")
        # The logged match must never be raw secret-shaped material.
        self.assertNotIn("AKIA", record["match"].replace("AWS Access Key ID", ""))
        self.assertTrue(record["match"].endswith("(redacted)"))

    def test_allow_line_has_null_rule_and_match(self):
        security_hook.log_decision("allow", [], "Edit", "src/app.ts")
        record = self.read_lines()[0]
        self.assertEqual(record["decision"], "allow")
        self.assertIsNone(record["rule"])
        self.assertIsNone(record["match"])

    def test_appends_one_line_per_decision(self):
        security_hook.log_decision("ask", ["eval() usage, potential code injection"], "Write", "a.ts")
        security_hook.log_decision("allow", [], "Write", "b.ts")
        lines = self.read_lines()
        self.assertEqual([r["decision"] for r in lines], ["ask", "allow"])
        self.assertNotEqual(lines[0]["id"], lines[1]["id"])

    def test_fail_open_on_unwritable_sink(self):
        # Point the sink at a path inside a regular file: makedirs must fail,
        # and log_decision must swallow the error instead of raising.
        blocker_file = os.path.join(self.tmpdir.name, "a-file")
        with open(blocker_file, "w", encoding="utf-8") as fh:
            fh.write("x")
        os.environ["FOUNDRI_HOOK_LOG"] = os.path.join(blocker_file, "child", "events.jsonl")
        try:
            security_hook.log_decision("block", ["AWS Access Key ID detected"], "Write", "src/x.ts")
        except Exception as exc:  # noqa: BLE001 - the test is "no exception escapes"
            self.fail(f"log_decision raised instead of failing open: {exc}")


if __name__ == "__main__":
    unittest.main()
