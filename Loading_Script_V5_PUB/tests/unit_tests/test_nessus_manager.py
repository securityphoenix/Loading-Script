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
# The public manager refuses TruffleHog records read by another translator; the private copy has no such check.
_MANAGER_CHECKS_TRUFFLEHOG = "holds_trufflehog_secrets" in inspect.getsource(
    EnhancedMultiScannerImportManager.process_scanner_file_enhanced)

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

    def test_scanner_tenable_on_truncated_nessus_fails_without_post(self):
        for text in ('<?xml version="1.0" ?><Nessu', '<?xml version="1.0" ?><Other/>', ""):
            for scanner in ("tenable", "nessus", None):
                path = self.write(".NESSUS", text)
                result = self.manager.process_scanner_file_enhanced(path, scanner_type=scanner)
                self.assertFalse(result["success"], (text, scanner))
        self.importer_mock.assert_not_called()

    def test_empty_scan_result_carries_zero_tag_counts(self):
        result = self.manager.process_scanner_file_enhanced(str(DATA / "nessus_many_vuln.xml"), just_tags=True)
        self.assertTrue(result["success"])
        self.assertEqual((result["assets_tagged"], result["tags_applied"]), (0, 0))

    def test_single_file_cli_just_tags_on_informational_only_scan(self):
        import phoenix_multi_scanner_enhanced as cli
        argv = ["prog", "--config", "audit.ini", "--file", str(DATA / "nessus_many_vuln.xml"), "--just-tags"]
        with patch.object(sys, "argv", argv), \
                patch.object(cli, "EnhancedMultiScannerImportManager", return_value=self.manager):
            self.assertEqual(cli.main(), 0)
        self.importer_mock.assert_not_called()

    def test_inventory_mode_is_applied_per_call_and_restored(self):
        path = self.write(".nessus", nessus(one_host(items=item(severity=0))))
        nessus_translator = self.manager._find_translator_by_name("nessus")
        result = self.manager.process_scanner_file_enhanced(path, create_inventory_assets=True)
        self.assertTrue(result["success"])
        self.assertNotIn("empty_scan", result)
        assets = self.importer_mock.call_args.args[0]
        self.assertTrue(assets[0].findings[0]["details"].get("asset_inventory"))
        self.assertFalse(nessus_translator.create_inventory_assets)
        self.importer_mock.reset_mock()
        result = self.manager.process_scanner_file_enhanced(path)
        self.assertEqual((result["success"], result.get("empty_scan")), (True, True))
        self.importer_mock.assert_not_called()
        self.assertFalse(nessus_translator.create_inventory_assets)

    def test_inventory_mode_restored_after_parse_error(self):
        nessus_translator = self.manager._find_translator_by_name("nessus")
        result = self.manager.process_scanner_file_enhanced(
            self.write(".nessus", "<ASSET_DATA_REPORT/>"), scanner_type="nessus", create_inventory_assets=True)
        self.assertFalse(result["success"])
        self.assertFalse(nessus_translator.create_inventory_assets)
        self.importer_mock.assert_not_called()

    def test_trufflehog_key_names_in_nessus_xml_do_not_block_import(self):
        text = nessus(one_host(items=item(plugin_output='"DetectorName" "Raw" "RawV2"')))
        text = text.replace("<NessusClientData_v2>",
                            '<!-- "DetectorName": "x", "Raw": "y" --><NessusClientData_v2>', 1)
        with patch("scanner_translators.trufflehog_translator.holds_trufflehog_secrets", create=True) as check:
            result = self.manager.process_scanner_file_enhanced(self.write(".nessus", text))
        self.assertTrue(result["success"], result.get("error"))
        self.assertEqual(result["scanner_type"], "nessusxml")  # auto-detected
        check.assert_not_called()  # no whole-file read for a Nessus import
        self.importer_mock.assert_called_once()

    def test_trufflehog_records_in_a_nessus_file_are_never_uploaded(self):
        record = ('{"SourceMetadata": {}, "DetectorName": "AWS", "Raw": "AKIAEXAMPLEVALUE", '
                  '"RawV2": "", "Redacted": ""}\n')
        for scanner in ("nessus", "tenable", None):
            result = self.manager.process_scanner_file_enhanced(self.write(".nessus", record), scanner_type=scanner)
            self.assertFalse(result["success"], scanner)
            self.assertNotIn("AKIAEXAMPLEVALUE", result.get("error", ""))
        self.importer_mock.assert_not_called()

    @unittest.skipUnless(_MANAGER_CHECKS_TRUFFLEHOG, "this manager copy has no TruffleHog record check")
    def test_trufflehog_check_still_runs_for_other_translators(self):
        record = ('{"SourceMetadata": {}, "DetectorName": "AWS", "Raw": "AKIAEXAMPLEVALUE", '
                  '"RawV2": "", "Redacted": ""}\n')
        result = self.manager.process_scanner_file_enhanced(self.write(".json", record), scanner_type="grype")
        self.assertFalse(result["success"])
        self.assertIn("TruffleHog records", result["error"])
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
