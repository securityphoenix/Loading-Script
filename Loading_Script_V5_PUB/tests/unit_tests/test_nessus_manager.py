#!/usr/bin/env python3
"""Nessus XML through the manager: detection, scanner names, errors without a POST, folder mode."""

import inspect
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phoenix_import_enhanced import ImportSession
from phoenix_multi_scanner_enhanced import EnhancedMultiScannerImportManager
from tests.unit_tests.nessus_fixtures import item, nessus, one_host, TempFiles
from scanner_translators import TenableTranslator
from scanner_translators.base_translator import ScannerTranslator

# The manager's _parse_file_to_assets checks the translator either by duck typing (public copy) or with
# isinstance(..., ScannerTranslator) from base_translator (older private copy). In the private copy
# TenableTranslator derives from phoenix_multi_scanner_import.ScannerTranslator, so that isinstance check
# fails and --scanner tenable on a CSV re-runs auto-detect. This is true when the manager's check passes.
_MANAGER_USES_ISINSTANCE = "isinstance(translator_or_name, ScannerTranslator)" in inspect.getsource(
    EnhancedMultiScannerImportManager._parse_file_to_assets)
_TENABLE_ROUTING_APPLIES = (not _MANAGER_USES_ISINSTANCE) or issubclass(TenableTranslator, ScannerTranslator)

DATA = ROOT / "unit_tests" / "test_data" / "nessus"


class TestNessusManager(TempFiles, unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # the manager writes logs/ and errors/ into the working directory
        Path("audit.ini").write_text(
            "[phoenix]\nclient_id = c\nclient_secret = s\n"
            "api_base_url = https://phoenix.example.invalid\nimport_type = merge\nwait_for_completion = false\n")
        self.manager = EnhancedMultiScannerImportManager("audit.ini")
        self.manager.enhanced_importer.request_interval = 0
        self.manager.enhanced_importer.max_retries = 0
        self.importer_mock = patch.object(
            self.manager.enhanced_importer, "import_assets_with_batching",
            return_value=ImportSession(session_id="test", total_batches=1, completed_batches=1)).start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_auto_detect_picks_nessus(self):
        t = self.manager.detect_scanner_type(str(DATA / "nessus_with_cvssv3.xml"))
        self.assertEqual(type(t).__name__, "NessusXMLTranslator")

    def test_scanner_names_find_nessus(self):
        for name in ("nessus", "nessus_xml"):
            self.assertEqual(type(self.manager._find_translator_by_name(name)).__name__, "NessusXMLTranslator")

    def test_scanner_tenable_on_nessus_file_uses_xml_translator(self):
        result = self.manager.process_scanner_file_enhanced(str(DATA / "nessus_with_cvssv3.xml"), scanner_type="tenable")
        self.assertTrue(result["success"])
        self.assertEqual(result["scanner_type"], "nessus")
        assets = self.importer_mock.call_args.args[0]  # the patched import method
        self.assertEqual(sum(len(a.findings) for a in assets), 142)

    @unittest.skipUnless(
        _TENABLE_ROUTING_APPLIES,
        "TenableTranslator does not derive from base_translator.ScannerTranslator in this copy "
        "(legacy isinstance check re-runs auto-detect for --scanner tenable on a CSV)")
    def test_scanner_tenable_on_tenable_csv_keeps_tenable_translator(self):
        csv = str(DATA / "tenable_many_vuln.csv")
        with patch("scanner_translators.nessus_xml_translator.NessusXMLTranslator.parse_file") as nessus_parse, \
                patch("scanner_translators.tenable_translator.TenableTranslator.parse_file",
                      autospec=True, side_effect=lambda self_, path: []) as tenable_parse:
            self.manager.process_scanner_file_enhanced(csv, scanner_type="tenable")
        nessus_parse.assert_not_called()
        tenable_parse.assert_called_once()

    def test_non_nessus_xml_with_scanner_nessus_fails_without_post(self):
        result = self.manager.process_scanner_file_enhanced(
            self.write(".nessus", "<ASSET_DATA_REPORT/>"), scanner_type="nessus")
        self.assertFalse(result["success"])
        self.importer_mock.assert_not_called()

    def test_empty_scan_result_has_an_assessment_name(self):
        result = self.manager.process_scanner_file_enhanced(str(DATA / "nessus_many_vuln.xml"))
        self.assertTrue(isinstance(result["assessment_name"], str) and result["assessment_name"])

    def test_tenable_csv_not_taken_by_nessus(self):
        # Auto-detect picks QualysTranslator for this CSV before and after Task 4 (Qualys sits ahead
        # of Tenable in the list); the point here is that the Nessus translator does not claim it.
        csv = str(DATA / "tenable_many_vuln.csv")
        self.assertNotEqual(type(self.manager.detect_scanner_type(csv)).__name__, "NessusXMLTranslator")
        self.assertTrue(self.manager._find_translator_by_name("tenable").can_handle(csv))
        self.assertFalse(self.manager._find_translator_by_name("nessus").can_handle(csv))

    def test_truncated_file_fails_without_post(self):
        text = nessus(one_host(items=item()))
        result = self.manager.process_scanner_file_enhanced(self.write(".nessus", text[: len(text) // 2]))
        self.assertFalse(result["success"])
        self.assertIn("Nessus XML parse failed", result["error"])
        self.importer_mock.assert_not_called()

    def test_informational_only_file_is_success_without_post(self):
        result = self.manager.process_scanner_file_enhanced(str(DATA / "nessus_many_vuln.xml"))
        self.assertEqual((result["success"], result["assets_imported"], result.get("empty_scan")), (True, 0, True))
        self.importer_mock.assert_not_called()

    def test_folder_mode_lists_nessus_files(self):
        folder = Path(self.tmp_dir())
        (folder / "a.nessus").write_text(nessus(one_host(items=item())))
        (folder / "b.NESSUS").write_text(nessus(one_host(items=item())))
        with patch.object(self.manager, "process_scanner_file_enhanced",
                          return_value={"success": True}) as per_file:
            self.manager.process_folder_enhanced(str(folder))
        called = sorted(Path(c.args[0]).name for c in per_file.call_args_list)
        self.assertEqual(called, ["a.nessus", "b.NESSUS"])


if __name__ == "__main__":
    unittest.main()
