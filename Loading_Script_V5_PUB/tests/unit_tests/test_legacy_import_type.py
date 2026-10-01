#!/usr/bin/env python3
"""phoenix_multi_scanner_import.py (the older CLI) sends the requested --import-type, and without the
flag the config file's import_type applies instead of a hard-coded "new", also on a manager that
already imported with a requested type. Runs the real main() and a reused manager."""

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

import phoenix_multi_scanner_import
from phoenix_import_refactored import PhoenixAPIClient

GRYPE = {
    "descriptor": {"name": "grype"},
    "source": {"type": "image", "target": {"userInput": "registry.example.com/app:1.0"}},
    "matches": [{
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "x"},
        "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
    }],
}


class TestLegacyImportType(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # the manager writes logs/ and errors/ into the working directory
        Path("scan.json").write_text(json.dumps(GRYPE))

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def import_type_sent(self, ini_import_type, *cli_args):
        Path("audit.ini").write_text(
            "[phoenix]\nclient_id = c\nclient_secret = s\n"
            f"api_base_url = https://phoenix.example.invalid\nimport_type = {ini_import_type}\n"
            "wait_for_completion = false\n")
        response = MagicMock(status_code=200, text='{"id": "r1"}')
        response.json.return_value = {"id": "r1"}
        argv = ["phoenix_multi_scanner_import.py", "--config", "audit.ini", "--file", "scan.json", *cli_args]
        with patch.object(sys, "argv", argv), \
                patch.object(phoenix_multi_scanner_import, "setup_logging"), \
                patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response) as post:
            phoenix_multi_scanner_import.main()
        import_posts = [c for c in post.call_args_list if c.args and c.args[0].endswith("/v1/import/assets")]
        self.assertEqual(len(import_posts), 1)
        return import_posts[0].kwargs["json"]["importType"]

    def test_config_type_applies_without_the_flag(self):
        self.assertEqual(self.import_type_sent("merge"), "merge")

    def test_requested_type_is_sent(self):
        self.assertEqual(self.import_type_sent("new", "--import-type", "delta"), "delta")


class TestLegacyManagerReuse(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # the manager writes logs/ and errors/ into the working directory
        Path("scan.json").write_text(json.dumps(GRYPE))
        Path("audit.ini").write_text(
            "[phoenix]\nclient_id = c\nclient_secret = s\n"
            "api_base_url = https://phoenix.example.invalid\nimport_type = merge\n"
            "wait_for_completion = false\n")

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_requested_type_does_not_stick_to_a_reused_manager(self):
        manager = phoenix_multi_scanner_import.MultiScannerImportManager("audit.ini")
        manager.load_configuration()
        manager.tag_config = manager.load_tag_configuration()
        manager._initialize_translators()
        response = MagicMock(status_code=200, text='{"id": "r1"}')
        response.json.return_value = {"id": "r1"}
        sent = []
        for kwargs in ({"import_type": "delta"}, {}):
            with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                    patch("phoenix_import_refactored.requests.post", return_value=response) as post:
                manager.process_scanner_file(str(Path("scan.json").resolve()), assessment_name="reuse", **kwargs)
            sent += [c.kwargs["json"]["importType"] for c in post.call_args_list
                     if c.args and c.args[0].endswith("/v1/import/assets")]
        self.assertEqual(sent, ["delta", "merge"])


if __name__ == "__main__":
    unittest.main()
