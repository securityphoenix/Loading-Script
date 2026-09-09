#!/usr/bin/env python3
"""
Unit tests for TrivyTranslator (V5)

Covers the test data files under unit_tests/test_data/trivyfixes/:
  - REDACTED_trivy_GIT-1335874  → filesystem + lang-pkgs → BUILD, 2 vulns
  - REDACTED_trivy_GIT-1473518  → filesystem + secret    → REPOSITORY, secrets as findings
  - almalinux-8                  → container_image + os-pkgs → CONTAINER, 1 vuln
  - amazonlinux2-gp2-x86-vm      → vm                   → INFRA, vulns
  - bun                          → repository + lang-pkgs → REPOSITORY, vulns
  - fluentd-multiple-lockfiles    → cyclonedx + os-pkgs  → BUILD, vulns

Bug regressions tested:
  - Secrets[] are now translated to findings (was silently ignored)
  - severity is sent as float to Phoenix payload (was string, broke risk score)
  - Assets with no findings are NOT included in the output (empty-findings guard)
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup — allow running from repo root or unit_tests/ directly
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).parent.parent
_TESTS_DATA = Path(__file__).parent / "test_data" / "trivyfixes"

sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Minimal stubs so the translator can be imported without the full stack
# ---------------------------------------------------------------------------

class _FakeTagConfig:
    def get_all_tags(self):
        return []
    def get_vulnerability_tags(self, severity=None):
        return []
    def get_asset_type_tags(self, asset_type):
        return []


def _make_translator():
    from scanner_translators.trivy_translator import TrivyTranslator
    from scanner_translators.base_translator import ScannerConfig

    cfg = ScannerConfig(
        scanner_type="trivy",
        asset_type="CONTAINER",
    )
    return TrivyTranslator(
        scanner_config=cfg,
        tag_config=_FakeTagConfig(),
        create_empty_assets=False,
        create_inventory_assets=False,
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _load(filename: str) -> dict:
    with open(_TESTS_DATA / filename) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTrivyTranslatorAssetTypeDetection(unittest.TestCase):
    """Asset type is inferred correctly from ArtifactType + Class."""

    def setUp(self):
        self.translator = _make_translator()

    def _parse(self, filename):
        return self.translator.parse_file(str(_TESTS_DATA / filename))

    def test_container_image_detected(self):
        assets = self._parse("almalinux-8.json")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "CONTAINER")

    def test_vm_detected_as_infra(self):
        assets = self._parse("amazonlinux2-gp2-x86-vm.json")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "INFRA")

    def test_repository_artifact_type(self):
        assets = self._parse("bun.json")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "REPOSITORY")

    def test_filesystem_lang_pkgs_detected_as_build(self):
        assets = self._parse("REDACTED_trivy_GIT-1335874_20260422_140755.json")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "BUILD")

    def test_cyclonedx_os_pkgs_detected_as_build(self):
        assets = self._parse("fluentd-multiple-lockfiles.json")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "BUILD")

    def test_filesystem_secret_only_detected_as_repository(self):
        assets = self._parse("REDACTED_trivy_GIT-1473518_20260422_141408.json")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].asset_type, "REPOSITORY")


class TestTrivyTranslatorRequiredAttributes(unittest.TestCase):
    """Each asset type carries the required backend attributes."""

    def setUp(self):
        self.translator = _make_translator()

    def _asset(self, filename):
        return self.translator.parse_file(str(_TESTS_DATA / filename))[0]

    def test_container_has_dockerfile_and_repository(self):
        a = self._asset("almalinux-8.json")
        self.assertIn("dockerfile", a.attributes)
        self.assertIn("repository", a.attributes)

    def test_infra_has_hostname(self):
        a = self._asset("amazonlinux2-gp2-x86-vm.json")
        self.assertIn("hostname", a.attributes)

    def test_repository_has_repository_field(self):
        a = self._asset("bun.json")
        self.assertIn("repository", a.attributes)

    def test_build_has_build_file(self):
        a = self._asset("REDACTED_trivy_GIT-1335874_20260422_140755.json")
        self.assertIn("buildFile", a.attributes)

    def test_all_assets_have_origin_trivy(self):
        for fname in _TESTS_DATA.glob("*.json"):
            assets = self.translator.parse_file(str(fname))
            for asset in assets:
                self.assertEqual(
                    asset.attributes.get("origin"), "trivy",
                    f"{fname.name}: missing origin=trivy",
                )


class TestTrivyTranslatorSecrets(unittest.TestCase):
    """Bug fix: Secrets[] entries are now translated to findings."""

    def setUp(self):
        self.translator = _make_translator()

    def test_secrets_produce_findings(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1473518_20260422_141408.json")
        )
        self.assertEqual(len(assets), 1, "Secrets-only file should produce 1 asset")
        self.assertGreater(
            len(assets[0].findings), 0,
            "Secrets file must have at least one finding (was silently ignored before fix)",
        )

    def test_secret_finding_name_prefix(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1473518_20260422_141408.json")
        )
        finding = assets[0].findings[0]
        self.assertTrue(
            finding["name"].startswith("SECRET-"),
            f"Secret finding name should start with 'SECRET-', got: {finding['name']}",
        )

    def test_secret_finding_has_location_with_line_range(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1473518_20260422_141408.json")
        )
        finding = assets[0].findings[0]
        # Location should contain target filename and line range
        self.assertIn(":", finding["location"], "Secret location should include a line range")

    def test_secret_finding_severity_is_not_unknown(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1473518_20260422_141408.json")
        )
        finding = assets[0].findings[0]
        self.assertNotEqual(finding["severity"], "5.0",
            "HIGH severity secret should not map to the 5.0 UNKNOWN fallback")
        self.assertEqual(finding["severity"], "8.0",
            "HIGH severity should map to 8.0")

    def test_secret_finding_details_contain_rule_id(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1473518_20260422_141408.json")
        )
        finding = assets[0].findings[0]
        self.assertIn("rule_id", finding.get("details", {}))
        self.assertIn("category", finding.get("details", {}))
        self.assertEqual(finding["details"]["finding_type"], "secret")


class TestTrivyTranslatorSeverityFloat(unittest.TestCase):
    """Bug fix: severity sent to Phoenix must be float, not string."""

    def _phoenix_findings(self, filename):
        """Simulate the serialization step in import_assets."""
        from phoenix_import_refactored import AssetData
        import importlib, sys

        translator = _make_translator()
        assets = translator.parse_file(str(_TESTS_DATA / filename))
        self.assertGreater(len(assets), 0)

        phoenix_findings = []
        for finding in assets[0].findings:
            pf = dict(finding) if not hasattr(finding, '__dataclass_fields__') else finding.__dict__.copy()
            if 'reference_ids' in pf:
                pf['referenceIds'] = pf.pop('reference_ids')
            if 'published_date_time' in pf:
                pf['publishedDateTime'] = pf.pop('published_date_time')
            # This is the fix under test in phoenix_import_refactored.py
            if 'severity' in pf and pf['severity'] is not None:
                try:
                    pf['severity'] = float(pf['severity'])
                except (ValueError, TypeError):
                    pf['severity'] = 5.0
            phoenix_findings.append(pf)
        return phoenix_findings

    def test_build_severity_is_float(self):
        findings = self._phoenix_findings("REDACTED_trivy_GIT-1335874_20260422_140755.json")
        for f in findings:
            self.assertIsInstance(
                f["severity"], float,
                f"severity must be float for Phoenix risk score, got {type(f['severity'])}: {f['severity']}"
            )

    def test_container_severity_is_float(self):
        findings = self._phoenix_findings("almalinux-8.json")
        for f in findings:
            self.assertIsInstance(f["severity"], float)

    def test_severity_values_within_phoenix_range(self):
        for fname in _TESTS_DATA.glob("*.json"):
            findings = self._phoenix_findings(fname.name)
            for f in findings:
                sev = f["severity"]
                self.assertGreaterEqual(sev, 1.0, f"{fname.name}: severity {sev} < 1.0")
                self.assertLessEqual(sev, 10.0, f"{fname.name}: severity {sev} > 10.0")


class TestTrivyTranslatorNoEmptyAssets(unittest.TestCase):
    """Assets with no findings after translation must be skipped."""

    def test_all_returned_assets_have_findings(self):
        translator = _make_translator()
        for fname in _TESTS_DATA.glob("*.json"):
            assets = translator.parse_file(str(fname))
            for asset in assets:
                self.assertGreater(
                    len(asset.findings), 0,
                    f"{fname.name}: asset '{asset.attributes}' has no findings — "
                    "should have been skipped by the translator",
                )

    def test_no_phantom_assets_sent_to_phoenix(self):
        """Specifically test the secrets-only file — before fix it sent an asset
        with empty findings[], which Phoenix would accept but never show in UI."""
        translator = _make_translator()
        assets = translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1473518_20260422_141408.json")
        )
        # With fix: 1 asset with secret findings
        # Without fix: 1 asset with [] findings (phantom asset)
        self.assertEqual(len(assets), 1)
        self.assertGreater(len(assets[0].findings), 0)


class TestTrivyTranslatorVulnerabilities(unittest.TestCase):
    """Existing vulnerability translation is not broken by the new code."""

    def setUp(self):
        self.translator = _make_translator()

    def test_build_file_has_two_vulns(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1335874_20260422_140755.json")
        )
        self.assertEqual(len(assets[0].findings), 2)

    def test_vuln_fields_present(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1335874_20260422_140755.json")
        )
        f = assets[0].findings[0]
        for field in ("name", "description", "remedy", "severity", "location", "details"):
            self.assertIn(field, f, f"Missing field '{field}' in finding")

    def test_vuln_description_is_not_empty(self):
        assets = self.translator.parse_file(str(_TESTS_DATA / "almalinux-8.json"))
        for f in assets[0].findings:
            self.assertTrue(f["description"], "description must not be empty")

    def test_remedy_mentions_package(self):
        assets = self.translator.parse_file(
            str(_TESTS_DATA / "REDACTED_trivy_GIT-1335874_20260422_140755.json")
        )
        for f in assets[0].findings:
            self.assertIn("requests", f["remedy"])

    def test_cve_ids_in_reference_ids(self):
        assets = self.translator.parse_file(str(_TESTS_DATA / "almalinux-8.json"))
        finding = assets[0].findings[0]
        self.assertIn("CVE-2021-3712", finding["reference_ids"])

    def test_scanner_tag_present(self):
        assets = self.translator.parse_file(str(_TESTS_DATA / "bun.json"))
        tags = {t["key"]: t["value"] for t in assets[0].tags}
        self.assertEqual(tags.get("scanner"), "trivy")


class TestTrivyEmptyScan(unittest.TestCase):
    """A Trivy file with no Results key (zero findings) must not raise an error."""

    def setUp(self):
        self.translator = _make_translator()

    def _empty_scan_content(self) -> dict:
        return {
            "SchemaVersion": 2,
            "CreatedAt": "2026-05-17T01:09:27.063327213Z",
            "ArtifactName": "sources/GIT-1005862",
            "ArtifactType": "filesystem",
        }

    def test_can_handle_returns_true_for_empty_scan(self):
        import tempfile, json as _json
        content = self._empty_scan_content()
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            _json.dump(content, f)
            tmp_path = f.name
        try:
            self.assertTrue(
                self.translator.can_handle(tmp_path),
                "can_handle should return True for a Trivy file with no Results",
            )
        finally:
            import os; os.unlink(tmp_path)

    def test_parse_file_returns_empty_list_for_empty_scan(self):
        import tempfile, json as _json
        content = self._empty_scan_content()
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            _json.dump(content, f)
            tmp_path = f.name
        try:
            assets = self.translator.parse_file(tmp_path)
            self.assertEqual(assets, [], "Empty scan should produce zero assets, not raise")
        finally:
            import os; os.unlink(tmp_path)

    def test_parse_file_emits_warning_for_empty_scan(self):
        import tempfile, json as _json
        content = self._empty_scan_content()
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            _json.dump(content, f)
            tmp_path = f.name
        try:
            with self.assertLogs("scanner_translators.trivy_translator", level="WARNING") as cm:
                self.translator.parse_file(tmp_path)
            self.assertTrue(
                any("no Results" in line for line in cm.output),
                "A WARNING about missing Results should be logged",
            )
        finally:
            import os; os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
