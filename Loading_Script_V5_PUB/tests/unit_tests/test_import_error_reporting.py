#!/usr/bin/env python3
"""Unit tests for user-visible import error reporting."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from import_error_reporting import (
    clip_error_text,
    compact_api_body,
    error_message_from_result,
    format_batch_session_error,
    format_phoenix_http_error,
)


class TestCompactApiBody(unittest.TestCase):
    def test_extracts_json_message(self):
        body = '{"message": "Unrecognized field \\"fixVersions\\""}'
        self.assertEqual(compact_api_body(body), 'Unrecognized field "fixVersions"')

    def test_empty_body(self):
        self.assertEqual(compact_api_body(""), "empty response body")

    def test_plain_text_is_clipped(self):
        self.assertIn("boom", compact_api_body("boom"))


class TestFormatPhoenixHttpError(unittest.TestCase):
    def test_includes_status_and_message(self):
        err = format_phoenix_http_error(400, '{"detail": "At least one of Dockerfile or Repository is required"}')
        self.assertTrue(err.startswith("Phoenix API 400:"))
        self.assertIn("Dockerfile or Repository", err)


class TestFormatBatchSessionError(unittest.TestCase):
    def test_none_when_all_succeeded(self):
        session = SimpleNamespace(
            total_batches=1,
            failed_batches=0,
            batch_results=[SimpleNamespace(success=True, error_message=None)],
        )
        self.assertIsNone(format_batch_session_error(session))

    def test_groups_duplicate_batch_errors(self):
        session = SimpleNamespace(
            total_batches=2,
            failed_batches=2,
            batch_results=[
                SimpleNamespace(success=False, error_message='Phoenix API 400: Unrecognized field "fixVersions"'),
                SimpleNamespace(success=False, error_message='Phoenix API 400: Unrecognized field "fixVersions"'),
            ],
        )
        err = format_batch_session_error(session)
        self.assertIn("2/2 batches", err)
        self.assertEqual(err.count("fixVersions"), 1)


class TestErrorMessageFromResult(unittest.TestCase):
    def test_prefers_direct_error(self):
        self.assertIn(
            "WORKSPACE_PREFIX",
            error_message_from_result(
                {"success": False, "error": "--tv-tags requires the WORKSPACE_PREFIX environment variable to be set"}
            ),
        )

    def test_uses_batch_errors_when_error_missing(self):
        result = {
            "success": False,
            "batch_summary": {"total_batches": 1, "failed_batches": 1},
            "batch_errors": [{"batch_number": 1, "error": "Phoenix API 400: Unrecognized field \"fixVersions\""}],
        }
        err = error_message_from_result(result)
        self.assertNotEqual(err, "Unknown error")
        self.assertIn("fixVersions", err)

    def test_never_returns_unknown_error(self):
        self.assertEqual(
            error_message_from_result({}, fallback="Import failed without an error message"),
            "Import failed without an error message",
        )

    def test_clips_long_messages(self):
        huge = "x" * 5000
        self.assertLessEqual(len(clip_error_text(huge)), 1200)


if __name__ == "__main__":
    unittest.main()
