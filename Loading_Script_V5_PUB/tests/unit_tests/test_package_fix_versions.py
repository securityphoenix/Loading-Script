#!/usr/bin/env python3
"""findings[].packages[].fixVersions from Grype fix.versions and Trivy FixedVersion:
order kept, duplicates and blanks dropped, and the list reaches the import request body."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phoenix_import_refactored import PhoenixAPIClient, PhoenixConfig
from scanner_translators.base_translator import ScannerConfig
from scanner_translators.grype_translator import GrypeTranslator
from scanner_translators.trivy_translator import TrivyTranslator


def tag_config():
    tc = MagicMock()
    tc.get_all_tags.return_value = []
    return tc


def parse(translator, doc):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(doc, f)
    try:
        return translator.parse_file(f.name)
    finally:
        Path(f.name).unlink()


def grype_doc(fix):
    return {
        "descriptor": {"name": "grype"},
        "source": {"type": "image", "target": {"userInput": "registry.example.com/app:1.0"}},
        "matches": [{
            "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "x", "fix": fix},
            "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
        }],
    }


def trivy_doc(fixed_version):
    return {
        "SchemaVersion": 2, "ArtifactName": "registry.example.com/app:1.0", "ArtifactType": "container_image",
        "Results": [{"Target": "app", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0001", "PkgName": "openssl", "InstalledVersion": "1.0.0",
            "FixedVersion": fixed_version, "Severity": "HIGH", "Description": "x"}]}],
    }


def package(assets):
    return assets[0].findings[0]["packages"][0]


class TestNormalizeFixVersions(unittest.TestCase):
    def test_keeps_first_seen_order_and_drops_duplicates_and_blanks(self):
        from scanner_translators.grype_translator import normalize_fix_versions
        self.assertEqual(normalize_fix_versions(["3.0", " 2.0 ", "3.0", "", None]), ["3.0", "2.0"])

    def test_nothing_usable_is_none(self):
        from scanner_translators.grype_translator import normalize_fix_versions
        self.assertIsNone(normalize_fix_versions([]))
        self.assertIsNone(normalize_fix_versions(None))


class TestGrype(unittest.TestCase):
    def translator(self):
        return GrypeTranslator(ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"), tag_config())

    def test_fix_versions_deduped_in_order(self):
        pkg = package(parse(self.translator(), grype_doc({"versions": ["2.0", "2.0", " 3.0 "], "state": "fixed"})))
        self.assertEqual(pkg["fixVersions"], ["2.0", "3.0"])

    def test_no_fix_means_no_key(self):
        pkg = package(parse(self.translator(), grype_doc({"versions": [], "state": "not-fixed"})))
        self.assertNotIn("fixVersions", pkg)


class TestTrivy(unittest.TestCase):
    def translator(self):
        return TrivyTranslator(ScannerConfig(scanner_type="trivy", asset_type="CONTAINER"), tag_config())

    def test_comma_joined_fixed_versions_are_split(self):
        pkg = package(parse(self.translator(), trivy_doc("2.0.1, 3.0.4, 2.0.1")))
        self.assertEqual(pkg["fixVersions"], ["2.0.1", "3.0.4"])

    def test_single_fixed_version(self):
        self.assertEqual(package(parse(self.translator(), trivy_doc("1.1.1w-0+deb12u1")))["fixVersions"],
                         ["1.1.1w-0+deb12u1"])

    def test_empty_fixed_version_means_no_key(self):
        self.assertNotIn("fixVersions", package(parse(self.translator(), trivy_doc(""))))


class TestRequestBody(unittest.TestCase):
    def test_fix_versions_reach_the_import_request(self):
        assets = parse(GrypeTranslator(ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"),
                                       tag_config()), grype_doc({"versions": ["2.0", "3.0"], "state": "fixed"}))
        client = PhoenixAPIClient(PhoenixConfig(client_id="c", client_secret="s",
                                                api_base_url="https://phoenix.example.invalid"))
        response = MagicMock(status_code=200, text='{"id": "r1"}')
        response.json.return_value = {"id": "r1"}
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response) as post:
            client.import_assets(assets, "fix-versions")
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["assets"][0]["findings"][0]["packages"][0]["fixVersions"], ["2.0", "3.0"])


if __name__ == "__main__":
    unittest.main()
