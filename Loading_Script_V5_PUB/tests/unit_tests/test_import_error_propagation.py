#!/usr/bin/env python3
"""Import results carry the real outcome: an unbatched upload that succeeded is reported as success,
and authentication / HTTP failures reach the result's error text through the API client, the
batching layer and the manager instead of "Unknown error" or "No response from API"."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phoenix_import_refactored import PhoenixAPIClient, PhoenixConfig
from phoenix_multi_scanner_enhanced import EnhancedMultiScannerImportManager

GRYPE = {
    "descriptor": {"name": "grype"},
    "source": {"type": "image", "target": {"userInput": "registry.example.com/app:1.0"}},
    "matches": [{
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "x",
                          "fix": {"versions": ["2.0"], "state": "fixed"}},
        "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
    }],
}


def http_response(status_code, body):
    response = MagicMock(status_code=status_code, text=json.dumps(body))
    response.json.return_value = body
    return response


class TestApiClientErrors(unittest.TestCase):
    def client(self):
        return PhoenixAPIClient(PhoenixConfig(client_id="c", client_secret="s",
                                              api_base_url="https://phoenix.example.invalid"))

    def test_authentication_failure_is_reported(self):
        with patch.object(PhoenixAPIClient, "get_access_token", return_value=None):
            request_id, response = self.client().import_assets([], "errors")
        self.assertIsNone(request_id)
        self.assertIn("authentication failed", response["message"].lower())

    def test_http_failure_is_reported_with_status_and_detail(self):
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post",
                      return_value=http_response(400, {"detail": "Synthetic validation failure"})):
            _, response = self.client().import_assets([], "errors")
        self.assertEqual(response["message"], "Phoenix API 400: Synthetic validation failure")


class TestManagerResults(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # the manager writes logs/ and errors/ into the working directory
        Path("audit.ini").write_text(
            "[phoenix]\nclient_id = c\nclient_secret = s\n"
            "api_base_url = https://phoenix.example.invalid\nimport_type = merge\nwait_for_completion = false\n")
        Path("scan.json").write_text(json.dumps(GRYPE))
        self.manager = EnhancedMultiScannerImportManager("audit.ini")
        self.manager.enhanced_importer.request_interval = 0
        self.manager.enhanced_importer.max_retries = 0

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def process(self, response, **kwargs):
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response) as post:
            result = self.manager.process_scanner_file_enhanced(
                str(Path("scan.json").resolve()), scanner_type="grype", assessment_name="errors", **kwargs)
        self.assertTrue(post.called, "no import request was sent")
        return result

    def test_unbatched_success_is_success(self):
        result = self.process(http_response(200, {"id": "r1"}), enable_batching=False)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["request_id"], "r1")

    def test_unbatched_http_failure_keeps_the_error(self):
        result = self.process(http_response(400, {"detail": "Synthetic validation failure"}), enable_batching=False)
        self.assertFalse(result["success"])
        self.assertIn("Phoenix API 400: Synthetic validation failure", result["error"])

    def test_batched_http_failure_has_a_top_level_error(self):
        result = self.process(http_response(400, {"detail": "Synthetic validation failure"}))
        self.assertFalse(result["success"])
        self.assertIn("Phoenix API 400: Synthetic validation failure", result.get("error") or "")


class TestSelectedTranslatorIsUsed(unittest.TestCase):
    def test_translator_object_from_another_module_copy_is_not_redetected(self):
        class CompatibleTranslator:  # not a subclass of this process's ScannerTranslator
            def can_handle(self, file_path):
                return True

            def parse_file(self, file_path):
                return ["parsed-by-selected-translator"]

        manager = EnhancedMultiScannerImportManager.__new__(EnhancedMultiScannerImportManager)
        manager.translators = []
        manager.detect_scanner_type = MagicMock(side_effect=AssertionError("translator was re-detected"))
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            self.assertEqual(manager._parse_file_to_assets(f.name, CompatibleTranslator(), None),
                             ["parsed-by-selected-translator"])


if __name__ == "__main__":
    unittest.main()
