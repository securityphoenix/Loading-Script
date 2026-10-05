#!/usr/bin/env python3
"""The requested import type (--import-type) is the importType sent to Phoenix, batched and
unbatched. With no import type requested, the config file's import_type still applies, also on a
manager that already imported with a requested type."""

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

from phoenix_import_refactored import PhoenixAPIClient
from phoenix_multi_scanner_enhanced import EnhancedMultiScannerImportManager

GRYPE = {
    "descriptor": {"name": "grype"},
    "source": {"type": "image", "target": {"userInput": "registry.example.com/app:1.0"}},
    "matches": [{
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "x"},
        "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
    }],
}


class TestRequestedImportType(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # the manager writes logs/ and errors/ into the working directory
        Path("scan.json").write_text(json.dumps(GRYPE))

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def manager(self, ini_import_type):
        Path("audit.ini").write_text(
            "[phoenix]\nclient_id = c\nclient_secret = s\n"
            f"api_base_url = https://phoenix.example.invalid\nimport_type = {ini_import_type}\n"
            "wait_for_completion = false\n")
        manager = EnhancedMultiScannerImportManager("audit.ini")
        manager.enhanced_importer.request_interval = 0
        manager.enhanced_importer.max_retries = 0
        return manager

    def import_type_sent(self, ini_import_type, manager=None, **kwargs):
        manager = manager or self.manager(ini_import_type)
        response = MagicMock(status_code=200, text='{"id": "r1"}')
        response.json.return_value = {"id": "r1"}
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response) as post:
            manager.process_scanner_file_enhanced(
                str(Path("scan.json").resolve()), scanner_type="grype", assessment_name="import-type", **kwargs)
        self.assertEqual(post.call_count, 1)
        return post.call_args.kwargs["json"]["importType"]

    def test_requested_type_is_sent_batched(self):
        self.assertEqual(self.import_type_sent("new", import_type="delta"), "delta")

    def test_requested_type_is_sent_unbatched(self):
        self.assertEqual(self.import_type_sent("new", import_type="delta", enable_batching=False), "delta")

    def test_config_type_applies_without_a_request_batched(self):
        self.assertEqual(self.import_type_sent("merge"), "merge")

    def test_config_type_applies_without_a_request_unbatched(self):
        self.assertEqual(self.import_type_sent("merge", enable_batching=False), "merge")

    def test_requested_type_does_not_stick_to_a_reused_manager(self):
        manager = self.manager("merge")
        self.assertEqual(self.import_type_sent("merge", manager, import_type="delta"), "delta")
        self.assertEqual(self.import_type_sent("merge", manager), "merge")


if __name__ == "__main__":
    unittest.main()
