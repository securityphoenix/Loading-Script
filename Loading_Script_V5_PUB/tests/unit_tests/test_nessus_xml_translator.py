#!/usr/bin/env python3
"""Nessus XML translator: detection and safe parsing."""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner_translators.base_translator import ScannerConfig
from scanner_translators.nessus_xml_translator import (
    NessusEmptyScan, NessusParseError, NessusXMLTranslator,
)
from tests.unit_tests.nessus_fixtures import (
    BILLION_LAUGHS, XXE_FILE, item, nessus, one_host, tags, write,
)

DATA = ROOT / "unit_tests" / "test_data" / "nessus"
_HAS_CUSTOM_OPTIONS = "custom_options" in ScannerConfig.__dataclass_fields__


def _translator(**custom_options) -> NessusXMLTranslator:
    tag_config = MagicMock()
    tag_config.get_all_tags.return_value = []
    kwargs = {"custom_options": custom_options} if _HAS_CUSTOM_OPTIONS else {}
    return NessusXMLTranslator(
        ScannerConfig(scanner_type="nessus", asset_type="INFRA", **kwargs),
        tag_config,
    )


class TestNessusDetectionAndSafeParsing(unittest.TestCase):
    def test_can_handle_nessus_files(self):
        self.assertTrue(_translator().can_handle(str(DATA / "nessus_with_cvssv3.xml")))
        self.assertTrue(_translator().can_handle(write(".nessus", nessus(one_host(items=item())))))
        self.assertTrue(_translator().can_handle(write(".NESSUS", nessus(one_host(items=item())))))

    def test_rejects_other_files(self):
        self.assertFalse(_translator().can_handle(write(".xml", "<ASSET_DATA_REPORT/>")))
        self.assertFalse(_translator().can_handle(write(".xml", "<issues/>")))
        self.assertFalse(_translator().can_handle(write(".csv", "Plugin ID,Host\n")))
        self.assertFalse(_translator().can_handle(write(".nessus", "")))
        self.assertFalse(_translator().can_handle("/no/such/file.nessus"))

    def test_truncated_file_raises(self):
        text = nessus(one_host(items=item()))
        with self.assertRaises(NessusParseError):
            _translator().parse_file(write(".nessus", text[: len(text) // 2]))

    def test_entity_expansion_raises(self):
        with self.assertRaises(NessusParseError):
            _translator().parse_file(write(".nessus", BILLION_LAUGHS))

    def test_external_entity_raises_and_reads_nothing(self):
        path = write(".nessus", XXE_FILE)
        with patch("builtins.open", wraps=open) as spy:
            with self.assertRaises(NessusParseError):
                _translator().parse_file(path)
        self.assertNotIn("/etc/passwd", [str(c.args[0]) for c in spy.call_args_list if c.args])

    def test_package_imports_without_defusedxml(self):
        path = write(".nessus", nessus(one_host(items=item())))
        code = (
            "import sys; sys.modules['defusedxml'] = None; sys.path.insert(0, %r);"
            "import scanner_translators;"
            "from scanner_translators.nessus_xml_translator import NessusXMLTranslator, NessusParseError;"
            "from unittest.mock import MagicMock;"
            "from scanner_translators.base_translator import ScannerConfig;"
            "t = NessusXMLTranslator(ScannerConfig(scanner_type='nessus'), MagicMock());"
            "\ntry:\n    t.parse_file(%r)\nexcept NessusParseError as e:\n"
            "    sys.exit(0 if 'pip install defusedxml' in str(e) else 3)\n"
            "sys.exit(4)\n" % (str(ROOT), path)
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_elements_are_released(self):
        t = _translator()
        text = nessus(
            one_host(name="10.0.0.1", items=item(plugin_id=1) + item(plugin_id=2)),
            one_host(name="10.0.0.2", items=item(plugin_id=3)),
            one_host(name="10.0.0.3", items=item(plugin_id=4)),
        )
        with patch.object(t, "_release", wraps=t._release) as spy:
            t.parse_file(write(".nessus", text))
        tags = [c.args[0].tag for c in spy.call_args_list]
        self.assertEqual((tags.count("ReportItem"), tags.count("ReportHost")), (4, 3))


class TestNessusAssets(unittest.TestCase):
    def test_host_attributes_from_sample(self):
        assets = _translator().parse_file(str(DATA / "nessus_with_cvssv3.xml"))
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "INFRA")
        self.assertEqual(assets[0].attributes["ip"], "44.228.249.3")
        self.assertEqual(assets[0].attributes["fqdn"], "testphp.vulnweb.com")
        self.assertEqual(assets[0].attributes["hostname"], "testphp.vulnweb.com")
        self.assertIn({"key": "scanner", "value": "tenable-nessus"}, assets[0].tags)

    def test_host_without_properties_uses_report_host_name(self):
        a = _translator().parse_file(write(".nessus", nessus(one_host(name="10.0.0.5", props="", items=item()))))
        self.assertEqual(a[0].attributes["ip"], "10.0.0.5")
        a = _translator().parse_file(write(".nessus", nessus(one_host(name="web01", props="", items=item()))))
        self.assertEqual(a[0].attributes["hostname"], "web01")

    def test_same_host_in_two_reports_is_one_asset(self):
        text = nessus(one_host(items=item(plugin_id=1)), one_host(items=item(plugin_id=2)))
        assets = _translator().parse_file(write(".nessus", text))
        self.assertEqual(len(assets), 1)
        self.assertEqual(sorted(f["name"] for f in assets[0].findings), ["Plugin-1", "Plugin-2"])

    def test_mac_and_os_take_first_line(self):
        props = tags(**{"host-ip": "10.0.0.5", "mac-address": "aa:bb\ncc:dd",
                        "operating-system": "Win 2019\nWin 2016"})
        attrs = _translator().parse_file(write(".nessus", nessus(one_host(props=props, items=item()))))[0].attributes
        self.assertEqual((attrs["macAddress"], attrs["operatingSystem"]), ("aa:bb", "Win 2019"))

    def test_no_hosts_is_empty_scan(self):
        with self.assertRaises(NessusEmptyScan):
            _translator().parse_file(write(".nessus", nessus("")))

    def _one(self, text):
        return _translator().parse_file(write(".nessus", text))

    def test_netbios_only_sets_hostname(self):
        props = tags(**{"host-ip": "10.0.0.5", "netbios-name": "WINBOX"})
        attrs = self._one(nessus(one_host(props=props, items=item())))[0].attributes
        self.assertEqual((attrs["hostname"], attrs["netbios"]), ("WINBOX", "WINBOX"))

    def test_fqdn_wins_over_netbios_for_hostname(self):
        props = tags(**{"host-ip": "10.0.0.5", "host-fqdn": "a.example.test", "netbios-name": "WINBOX"})
        attrs = self._one(nessus(one_host(props=props, items=item())))[0].attributes
        self.assertEqual((attrs["hostname"], attrs["fqdn"], attrs["netbios"]),
                         ("a.example.test", "a.example.test", "WINBOX"))

    def test_fqdn_and_netbios_take_first_non_empty_line(self):
        props = tags(**{"host-ip": "10.0.0.5", "host-fqdn": "\n a.example.test \nb.example.test",
                        "netbios-name": "\nWINBOX\nOTHER"})
        attrs = self._one(nessus(one_host(props=props, items=item())))[0].attributes
        self.assertEqual((attrs["fqdn"], attrs["hostname"], attrs["netbios"]),
                         ("a.example.test", "a.example.test", "WINBOX"))

    def test_unnamed_host_without_tags_is_invalid(self):
        with self.assertRaises(NessusEmptyScan) as ctx:
            self._one(nessus(one_host(name="", props="", items=item())))
        self.assertEqual(ctx.exception.stats["invalid_hosts"], 1)

    def test_informational_only_host_is_dropped(self):
        with self.assertRaises(NessusEmptyScan) as ctx:
            self._one(nessus(one_host(items=item(severity=0))))
        self.assertEqual(ctx.exception.stats["assets_without_findings"], 1)

    def test_two_blocks_merge_first_wins_and_adds_missing(self):
        p1 = tags(**{"host-ip": "10.0.0.5", "operating-system": "Win 2019"})
        p2 = tags(**{"host-ip": "10.0.0.5", "operating-system": "Win 2016", "mac-address": "aa:bb:cc"})
        text = nessus(one_host(props=p1, items=item(plugin_id=1)), one_host(props=p2, items=item(plugin_id=2)))
        assets = self._one(text)
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].attributes["operatingSystem"], "Win 2019")
        self.assertEqual(assets[0].attributes["macAddress"], "aa:bb:cc")


if __name__ == "__main__":
    unittest.main()
