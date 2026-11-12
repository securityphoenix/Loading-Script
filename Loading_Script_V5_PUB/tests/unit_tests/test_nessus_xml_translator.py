#!/usr/bin/env python3
"""Nessus XML translator: detection and safe parsing."""

import json
import subprocess
import sys
import time
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
    BILLION_LAUGHS, XXE_FILE, item, nessus, one_host, tags, TempFiles,
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


class TestNessusDetectionAndSafeParsing(TempFiles, unittest.TestCase):
    def test_can_handle_nessus_files(self):
        self.assertTrue(_translator().can_handle(str(DATA / "nessus_with_cvssv3.xml")))
        self.assertTrue(_translator().can_handle(self.write(".nessus", nessus(one_host(items=item())))))
        self.assertTrue(_translator().can_handle(self.write(".NESSUS", nessus(one_host(items=item())))))

    def test_rejects_other_files(self):
        self.assertFalse(_translator().can_handle(self.write(".xml", "<ASSET_DATA_REPORT/>")))
        self.assertFalse(_translator().can_handle(self.write(".xml", "<issues/>")))
        self.assertFalse(_translator().can_handle(self.write(".csv", "Plugin ID,Host\n")))
        self.assertFalse(_translator().can_handle(self.write(".nessus", "")))
        self.assertFalse(_translator().can_handle("/no/such/file.nessus"))

    def test_truncated_file_raises(self):
        text = nessus(one_host(items=item()))
        with self.assertRaises(NessusParseError):
            _translator().parse_file(self.write(".nessus", text[: len(text) // 2]))

    def test_entity_expansion_raises(self):
        with self.assertRaises(NessusParseError):
            _translator().parse_file(self.write(".nessus", BILLION_LAUGHS))

    def test_external_entity_raises_and_reads_nothing(self):
        path = self.write(".nessus", XXE_FILE)
        with patch("builtins.open", wraps=open) as spy:
            with self.assertRaises(NessusParseError):
                _translator().parse_file(path)
        self.assertNotIn("/etc/passwd", [str(c.args[0]) for c in spy.call_args_list if c.args])

    def test_package_imports_without_defusedxml(self):
        path = self.write(".nessus", nessus(one_host(items=item())))
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
            t.parse_file(self.write(".nessus", text))
        tags = [c.args[0].tag for c in spy.call_args_list]
        self.assertEqual((tags.count("ReportItem"), tags.count("ReportHost")), (4, 3))


class TestNessusAssets(TempFiles, unittest.TestCase):
    def test_host_attributes_from_sample(self):
        assets = _translator().parse_file(str(DATA / "nessus_with_cvssv3.xml"))
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "INFRA")
        self.assertEqual(assets[0].attributes["ip"], "44.228.249.3")
        self.assertEqual(assets[0].attributes["fqdn"], "testphp.vulnweb.com")
        self.assertEqual(assets[0].attributes["hostname"], "testphp.vulnweb.com")
        self.assertIn({"key": "scanner", "value": "tenable-nessus"}, assets[0].tags)

    def test_host_without_properties_uses_report_host_name(self):
        a = _translator().parse_file(self.write(".nessus", nessus(one_host(name="10.0.0.5", props="", items=item()))))
        self.assertEqual(a[0].attributes["ip"], "10.0.0.5")
        a = _translator().parse_file(self.write(".nessus", nessus(one_host(name="web01", props="", items=item()))))
        self.assertEqual(a[0].attributes["hostname"], "web01")

    def test_same_host_in_two_reports_is_one_asset(self):
        text = nessus(one_host(items=item(plugin_id=1)), one_host(items=item(plugin_id=2)))
        assets = _translator().parse_file(self.write(".nessus", text))
        self.assertEqual(len(assets), 1)
        self.assertEqual(sorted(f["name"] for f in assets[0].findings), ["Plugin-1", "Plugin-2"])

    def test_mac_and_os_take_first_line(self):
        props = tags(**{"host-ip": "10.0.0.5", "mac-address": "aa:bb\ncc:dd",
                        "operating-system": "Win 2019\nWin 2016"})
        attrs = _translator().parse_file(self.write(".nessus", nessus(one_host(props=props, items=item()))))[0].attributes
        self.assertEqual((attrs["macAddress"], attrs["operatingSystem"]), ("aa:bb", "Win 2019"))

    def test_no_hosts_is_empty_scan(self):
        with self.assertRaises(NessusEmptyScan):
            _translator().parse_file(self.write(".nessus", nessus("")))

    def _one(self, text):
        return _translator().parse_file(self.write(".nessus", text))

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


class TestNessusFindings(TempFiles, unittest.TestCase):
    def test_counts_on_cvssv3_sample(self):
        t = _translator()
        findings = t.parse_file(str(DATA / "nessus_with_cvssv3.xml"))[0].findings
        self.assertEqual(len(findings), 142)
        self.assertEqual(t.last_stats["duplicates_merged"], 3)
        self.assertEqual(sum(1 for f in findings if f["severity"] == "10.0"), 1)
        self.assertTrue(all(f["name"].startswith(("CVE-", "Plugin-")) for f in findings))

    def test_informational_only_file_is_empty_scan(self):
        with self.assertRaises(NessusEmptyScan):
            _translator().parse_file(str(DATA / "nessus_many_vuln.xml"))

    @unittest.skipUnless(_HAS_CUSTOM_OPTIONS, "ScannerConfig has no custom_options")
    def test_informational_included_when_option_set(self):
        for value in ("true", "YES", "1"):
            assets = _translator(include_informational=value).parse_file(str(DATA / "nessus_many_vuln.xml"))
            self.assertEqual(len(assets[0].findings), 7)
            self.assertTrue(all(f["severity"] == "1.0" for f in assets[0].findings))

    def test_one_finding_per_cve(self):
        text = nessus(one_host(items=item(severity=3, plugin_id=1001, cves=("CVE-2024-1", "CVE-2024-2"))))
        findings = _translator().parse_file(self.write(".nessus", text))[0].findings
        self.assertEqual([f["name"] for f in findings], ["CVE-2024-1", "CVE-2024-2"])
        self.assertEqual({f["severity"] for f in findings}, {"8.0"})
        self.assertEqual(findings[0]["details"]["plugin_id"], "1001")

    def test_item_without_cve_and_port_zero(self):
        findings = _translator().parse_file(self.write(".nessus", nessus(one_host(items=item(plugin_id=42, port="0")))))[0].findings
        self.assertEqual((findings[0]["name"], findings[0]["location"]), ("Plugin-42", "tcp/0"))

    def test_duplicate_keeps_highest_severity(self):
        items = item(severity=2, plugin_id=1, cves=("CVE-2024-9",)) + item(severity=4, plugin_id=2, cves=("CVE-2024-9",))
        f = _translator().parse_file(self.write(".nessus", nessus(one_host(items=items))))[0].findings
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["severity"], f[0]["details"]["plugin_ids"]), ("10.0", ["2", "1"]))

    def test_invalid_items_are_skipped_and_counted(self):
        items = (item(extra_attrs={"severity": "9"}) + item(severity=2, plugin_id="abc")
                 + item(plugin_id=7, extra_attrs={"port": "abc", "protocol": None}))
        t = _translator()
        f = t.parse_file(self.write(".nessus", nessus(one_host(items=items))))[0].findings
        self.assertEqual(t.last_stats["invalid_items"], 2)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["location"], "tcp/0")

    def test_text_rules(self):
        f = _translator().parse_file(self.write(".nessus", nessus(one_host(items=item(
            synopsis=None, description="x" * 2000, cwes=("79", "n/a"), vuln_publication_date="2024/03/05",
            attachment="A" * 10_000, plugin_output="secret-host")))))[0].findings[0]
        self.assertEqual(len(f["description"]), 500)
        self.assertTrue(f["description"].endswith("..."))
        self.assertEqual(f["cwes"], ["CWE-79"])
        self.assertEqual(f["published_date_time"], "2024-03-05T00:00:00")
        self.assertNotIn("AAAAAAAAAA", json.dumps(f))
        self.assertNotIn("secret-host", json.dumps(f))

    @unittest.skipUnless(_HAS_CUSTOM_OPTIONS, "ScannerConfig has no custom_options")
    def test_plugin_output_sent_only_when_enabled(self):
        text = nessus(one_host(items=item(plugin_output="o" * 900)))
        f = _translator(include_plugin_output="true").parse_file(self.write(".nessus", text))[0].findings[0]
        self.assertEqual(len(f["details"]["plugin_output"]), 500)

    def _parse(self, text, **options):
        t = _translator(**options)
        return t, t.parse_file(self.write(".nessus", nessus(one_host(items=text))))[0].findings

    def test_plugin_output_absent_when_option_off(self):
        _, f = self._parse(item(plugin_output="out"))
        self.assertNotIn("plugin_output", f[0]["details"])

    def test_tie_keeps_first_seen(self):
        _, f = self._parse(item(severity=3, plugin_id=1, cves=("CVE-1",), description="first")
                           + item(severity=3, plugin_id=2, cves=("CVE-1",), description="second"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["details"]["plugin_ids"], ["1", "2"])
        self.assertIn("first", f[0]["description"])

    def test_lower_severity_later_is_merged(self):
        items = "".join(item(severity=s, plugin_id=i, cves=("CVE-1",)) for s, i in ((2, 1), (4, 2), (3, 3)))
        t, f = self._parse(items)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "10.0")
        self.assertEqual(f[0]["details"]["plugin_ids"], ["2", "1", "3"])
        self.assertEqual(t.last_stats["duplicates_merged"], 2)

    def test_plugin_ids_absent_when_unmerged(self):
        _, f = self._parse(item(cves=("CVE-1", "CVE-2")))
        self.assertTrue(all("plugin_ids" not in x["details"] for x in f))

    def test_synopsis_and_description_joined(self):
        _, f = self._parse(item(synopsis="Syn", description="Desc"))
        self.assertEqual(f[0]["description"], "Syn\n\nDesc")

    def test_remedy_default_and_cut(self):
        _, f = self._parse(item(solution=None))
        self.assertEqual(f[0]["remedy"], "See scanner output for remediation")
        _, f = self._parse(item(solution="s" * 2000))
        self.assertEqual(len(f[0]["remedy"]), 500)
        self.assertTrue(f[0]["remedy"].endswith("..."))

    def test_invalid_item_debug_line(self):
        with self.assertLogs("scanner_translators.nessus_xml_translator", level="DEBUG") as logs:
            self._parse(item(plugin_id=777, extra_attrs={"severity": "9"}) + item(plugin_id=1))
        self.assertTrue(any("777" in line and "severity" in line for line in logs.output))

    def test_item_findings_callable_directly(self):
        from defusedxml import ElementTree as safe_et
        element = safe_et.fromstring(item(cves=("CVE-1",)))
        t = _translator()
        self.assertEqual(len(t._item_findings(element)), 1)
        self.assertEqual(set(t.last_stats), {
            "hosts", "items", "informational_skipped", "invalid_items", "invalid_hosts",
            "duplicates_merged", "findings", "assets"})

    def test_impossible_date_is_none(self):
        _, f = self._parse(item(vuln_publication_date="2024/13/45"))
        self.assertIsNone(f[0]["published_date_time"])

    def test_long_plugin_and_service_names_are_cut(self):
        _, f = self._parse(item(plugin_name="p" * 600, svc_name="v" * 600))
        self.assertEqual(len(f[0]["details"]["plugin_name"]), 500)
        self.assertEqual(len(f[0]["details"]["svc_name"]), 500)

    def test_repeated_cve_in_one_item_is_one_finding(self):
        t, f = self._parse(item(cves=("CVE-2024-1", "CVE-2024-1")))
        self.assertEqual(len(f), 1)
        self.assertEqual(t.last_stats["duplicates_merged"], 0)

    def test_summary_log_line(self):
        with self.assertLogs("scanner_translators.nessus_xml_translator", level="INFO") as logs:
            _translator().parse_file(str(DATA / "nessus_with_cvssv3.xml"))
        self.assertTrue(any("informational_skipped=23" in line and "findings=142" in line for line in logs.output))


class TestNessusCsvXmlParity(TempFiles, unittest.TestCase):
    def test_same_name_severity_location_as_tenable_csv(self):
        from scanner_translators.tenable_translator import TenableTranslator
        xml = self.write(".nessus", nessus(one_host(items=(
            item(severity=3, plugin_id=10, port="443", protocol="tcp",
                 plugin_name="Weak TLS", cves=("CVE-2024-1", "CVE-2024-2"))
            + item(severity=2, plugin_id=11, port="0", protocol="tcp", plugin_name="Banner leak")))))
        header = "Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution"
        rows = [
            "10,CVE-2024-1,7.5,High,10.0.0.5,tcp,443,Weak TLS,Short.,Long.,Fix it.",
            "10,CVE-2024-2,7.5,High,10.0.0.5,tcp,443,Weak TLS,Short.,Long.,Fix it.",
            "11,,5.0,Medium,10.0.0.5,tcp,0,Banner leak,Short.,Long.,Fix it.",
        ]
        csv_path = self.write(".csv", "\n".join([header] + rows) + "\n")
        tag_config = MagicMock()
        tag_config.get_all_tags.return_value = []
        kwargs = {"custom_options": {}} if _HAS_CUSTOM_OPTIONS else {}
        csv_translator = TenableTranslator(
            ScannerConfig(scanner_type="tenable", asset_type="INFRA", **kwargs), tag_config)

        def keys(assets):
            return {(f["name"], f["severity"], f["location"])
                    for a in assets for f in a.findings}

        xml_keys = keys(_translator().parse_file(xml))
        csv_keys = keys(csv_translator.parse_file(csv_path))
        self.assertEqual(len(xml_keys), 3)
        self.assertEqual(xml_keys, csv_keys)


class TestNessusStructureAndHardening(TempFiles, unittest.TestCase):
    def test_non_nessus_root_raises(self):
        for text in ("<ASSET_DATA_REPORT/>",
                     "<Foo><Report><ReportHost name='10.0.0.5'>" + item() + "</ReportHost></Report></Foo>"):
            with self.assertRaises(NessusParseError) as ctx:
                _translator().parse_file(self.write(".nessus", text))
            self.assertIn("not NessusClientData_v2", str(ctx.exception))

    def test_item_without_any_text_falls_back_to_plugin_id(self):
        f = _translator().parse_file(self.write(".nessus", nessus(one_host(items=item(
            plugin_id=55, synopsis=None, description=None, plugin_name=""))))) [0].findings[0]
        self.assertEqual(f["description"], "Plugin-55")

    def test_item_outside_report_host_is_invalid(self):
        text = ('<?xml version="1.0" ?><NessusClientData_v2><Report name="r">' + item(plugin_id=999)
                + one_host(items=item(plugin_id=1)) + "</Report></NessusClientData_v2>")
        t = _translator()
        with self.assertLogs("scanner_translators.nessus_xml_translator", level="DEBUG") as logs:
            f = t.parse_file(self.write(".nessus", text))[0].findings
        self.assertEqual([x["name"] for x in f], ["Plugin-1"])
        self.assertEqual(t.last_stats["invalid_items"], 1)
        self.assertTrue(any("999" in line and "outside ReportHost" in line for line in logs.output))

    def test_conflicting_merge_is_logged(self):
        p1 = tags(**{"host-ip": "10.0.0.5", "operating-system": "Win 2019"})
        p2 = tags(**{"host-ip": "10.0.0.5", "operating-system": "Win 2016"})
        text = nessus(one_host(props=p1, items=item(plugin_id=1)), one_host(props=p2, items=item(plugin_id=2)))
        t = _translator()
        with self.assertLogs("scanner_translators.nessus_xml_translator", level="INFO") as logs:
            t.parse_file(self.write(".nessus", text))
        self.assertTrue(any("merged hosts with conflicting attributes=1" in line for line in logs.output))
        self.assertEqual(set(t.last_stats), {
            "hosts", "items", "informational_skipped", "invalid_items", "invalid_hosts",
            "duplicates_merged", "findings", "assets"})

    def test_no_conflict_line_when_attributes_agree(self):
        text = nessus(one_host(items=item(plugin_id=1)), one_host(items=item(plugin_id=2)))
        with self.assertLogs("scanner_translators.nessus_xml_translator", level="INFO") as logs:
            _translator().parse_file(self.write(".nessus", text))
        self.assertFalse(any("conflicting" in line for line in logs.output))

    @staticmethod
    def _inventory_translator(enabled: bool) -> NessusXMLTranslator:
        tag_config = MagicMock()
        tag_config.get_all_tags.return_value = []
        kwargs = {"custom_options": {}} if _HAS_CUSTOM_OPTIONS else {}
        return NessusXMLTranslator(ScannerConfig(scanner_type="nessus", asset_type="INFRA", **kwargs),
                                   tag_config, create_inventory_assets=enabled)

    def test_inventory_option_adds_placeholder_to_empty_asset(self):
        t = self._inventory_translator(True)
        assets = t.parse_file(self.write(".nessus", nessus(one_host(items=item(severity=0)))))
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].attributes["ip"], "10.0.0.5")
        self.assertEqual(len(assets[0].findings), 1)
        self.assertTrue(assets[0].findings[0]["details"].get("asset_inventory"))

    def test_inventory_mode_switches_between_successive_calls(self):
        path = self.write(".nessus", nessus(one_host(items=item(severity=0))))
        for order in ((True, False, True), (False, True, False)):
            t = self._inventory_translator(order[0])
            for enabled in order:
                t.create_inventory_assets = enabled
                if enabled:
                    assets = t.parse_file(path)
                    self.assertEqual(len(assets[0].findings), 1)
                    self.assertTrue(assets[0].findings[0]["details"].get("asset_inventory"))
                else:
                    with self.assertRaises(NessusEmptyScan):
                        t.parse_file(path)

    def test_inventory_mode_keeps_real_findings_without_placeholder(self):
        text = nessus(one_host(name="10.0.0.1", items=item(severity=3)),
                      one_host(name="10.0.0.2", items=item(severity=0)))
        assets = self._inventory_translator(True).parse_file(self.write(".nessus", text))
        by_ip = {a.attributes["ip"]: a.findings for a in assets}
        self.assertEqual(by_ip["10.0.0.1"][0]["name"], "Plugin-42")
        self.assertTrue(by_ip["10.0.0.2"][0]["details"].get("asset_inventory"))


class TestNessusReviewFixes(TempFiles, unittest.TestCase):
    def test_pathological_doctype_header_is_rejected_fast(self):
        path = self.write(".nessus", "<!DOCTYPE" + "[]" * 100)
        started = time.perf_counter()
        self.assertFalse(_translator().can_handle(path))
        self.assertLess(time.perf_counter() - started, 0.5)
        big = self.write(".nessus", "<!DOCTYPE" + "[]" * 2100 + "<NessusClientData_v2/>")
        started = time.perf_counter()
        self.assertFalse(_translator().can_handle(big))
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_prolog_with_declaration_comments_and_doctype_is_detected(self):
        body = nessus(one_host(items=item())).split("?>", 1)[1]
        for prolog in (
            '<?xml version="1.0" encoding="UTF-8"?>\n',
            '<?xml version="1.0"?>\n<!-- export -->\n<!-- two -->\n',
            '<?xml version="1.0"?>\n<!DOCTYPE NessusClientData_v2>\n',
            '<?xml version="1.0"?><!doctype NessusClientData_v2 [ <!ELEMENT x ANY> ]>\n<!-- c -->',
            '\ufeff<?xml version="1.0"?>\n<?pi data?>\n',
        ):
            path = self.write(".nessus", prolog + body)
            self.assertTrue(_translator().can_handle(path), prolog)
        for broken in ("<!-- never closed <NessusClientData_v2/>", "<?xml never closed <NessusClientData_v2/>",
                       "<!DOCTYPE x [ <NessusClientData_v2/>"):
            self.assertFalse(_translator().can_handle(self.write(".nessus", broken)), broken)

    def test_ip_in_report_host_name_kept_when_only_fqdn_tag(self):
        props = tags(**{"host-fqdn": "a.example.test"})
        attrs = _translator().parse_file(self.write(".nessus", nessus(
            one_host(name="10.0.0.9", props=props, items=item()))))[0].attributes
        self.assertEqual((attrs["ip"], attrs["hostname"], attrs["fqdn"]),
                         ("10.0.0.9", "a.example.test", "a.example.test"))

    def test_same_ip_with_and_without_host_ip_tag_is_one_asset(self):
        with_ip = tags(**{"host-ip": "10.0.0.9", "host-fqdn": "a.example.test"})
        fqdn_only = tags(**{"host-fqdn": "a.example.test"})
        text = nessus(one_host(name="10.0.0.9", props=with_ip, items=item(plugin_id=1)),
                      one_host(name="10.0.0.9", props=fqdn_only, items=item(plugin_id=2)))
        assets = _translator().parse_file(self.write(".nessus", text))
        self.assertEqual(len(assets), 1)
        self.assertEqual(sorted(f["name"] for f in assets[0].findings), ["Plugin-1", "Plugin-2"])

    def test_hostname_name_still_used_when_no_tags(self):
        props = tags(**{"host-fqdn": "a.example.test"})
        attrs = _translator().parse_file(self.write(".nessus", nessus(
            one_host(name="web01", props=props, items=item()))))[0].attributes
        self.assertEqual((attrs["hostname"], "ip" in attrs), ("a.example.test", False))

    def test_finished_elements_are_detached_from_the_root(self):
        t = _translator()
        seen = []
        original = t._events

        def spy(path):
            for event, tag, elem in original(path):
                if event == "start" and not seen:
                    seen.append(elem)
                yield event, tag, elem

        text = nessus(
            one_host(name="10.0.0.1", items=item(plugin_id=1, attachment="A" * 100) + item(plugin_id=2)),
            one_host(name="10.0.0.2", items=item(plugin_id=3)),
        )
        with patch.object(t, "_events", side_effect=spy):
            assets = t.parse_file(self.write(".nessus", text))
        self.assertEqual(seen[0].tag, "NessusClientData_v2")
        self.assertEqual(len(list(seen[0])), 0)
        self.assertEqual(sum(len(a.findings) for a in assets), 3)

    def test_each_element_is_released_from_its_own_parent(self):
        t = _translator()
        with patch.object(t, "_release", wraps=t._release) as spy:
            t.parse_file(self.write(".nessus", nessus(one_host(items=item(attachment="x")))))
        pairs = [(c.args[0].tag, c.args[1].tag) for c in spy.call_args_list]
        self.assertEqual(pairs, [("HostProperties", "ReportHost"), ("attachment", "ReportItem"),
                                 ("ReportItem", "ReportHost"), ("ReportHost", "Report"),
                                 ("Report", "NessusClientData_v2")])

    def test_many_duplicates_merge_without_list_search(self):
        count = 20000
        low = "".join(item(severity=1, plugin_id=i, cves=(f"CVE-2024-{i}",)) for i in range(count))
        high = "".join(item(severity=4, plugin_id=count + i, cves=(f"CVE-2024-{i}",)) for i in range(count))
        path = self.write(".nessus", nessus(one_host(items=low + high)))
        t = _translator()
        started = time.perf_counter()
        findings = t.parse_file(path)[0].findings
        elapsed = time.perf_counter() - started
        self.assertEqual(len(findings), count)
        self.assertEqual(t.last_stats["duplicates_merged"], count)
        self.assertEqual([f["name"] for f in findings[:3]], ["CVE-2024-0", "CVE-2024-1", "CVE-2024-2"])
        self.assertTrue(all(f["severity"] == "10.0" for f in findings))
        self.assertEqual(findings[5]["details"]["plugin_ids"], [str(count + 5), "5"])
        self.assertLess(elapsed, 20)

    def test_merge_never_searches_the_findings_list(self):
        from phoenix_import_refactored import AssetData

        class NoSearch(list):
            def index(self, *args, **kwargs):
                raise AssertionError("findings list was searched")

        t = _translator()
        asset = AssetData(asset_type="INFRA", attributes={"ip": "10.0.0.5"}, tags=[])
        asset.findings = NoSearch()
        index = {}
        low = [{"name": f"CVE-{i}", "location": "tcp/1", "severity": "3.0", "details": {"plugin_id": str(i)}}
               for i in range(50)]
        high = [{"name": f"CVE-{i}", "location": "tcp/1", "severity": "10.0",
                 "details": {"plugin_id": str(100 + i)}} for i in range(50)]
        t._add_findings(asset, index, low)
        t._add_findings(asset, index, high)
        self.assertEqual([f["name"] for f in asset.findings], [f"CVE-{i}" for i in range(50)])
        self.assertTrue(all(f["severity"] == "10.0" for f in asset.findings))
        self.assertEqual(asset.findings[7]["details"]["plugin_ids"], ["107", "7"])


if __name__ == "__main__":
    unittest.main()
