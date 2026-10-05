#!/usr/bin/env python3
"""Grype imports send assessment.assetSubType=CONTAINER_IMAGE through the manager, the batching
layer and the API client (batched and unbatched); other scanners such as Trivy send no subtype."""

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
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "x",
                          "fix": {"versions": ["2.0"], "state": "fixed"}},
        "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
    }],
}
TRIVY = {
    "SchemaVersion": 2, "ArtifactName": "registry.example.com/app:1.0", "ArtifactType": "container_image",
    "Results": [{"Target": "app", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2026-0001", "PkgName": "openssl", "InstalledVersion": "1.0.0",
        "FixedVersion": "2.0", "Severity": "HIGH", "Description": "x"}]}],
}


class TestGrypeAssetSubType(unittest.TestCase):
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

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def assessment_sent(self, doc, scanner, **kwargs):
        Path("scan.json").write_text(json.dumps(doc))
        response = MagicMock(status_code=200, text='{"id": "r1"}')
        response.json.return_value = {"id": "r1"}
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response) as post:
            self.manager.process_scanner_file_enhanced(
                str(Path("scan.json").resolve()), scanner_type=scanner, assessment_name="sub-type", **kwargs)
        self.assertTrue(post.called, "no import request was sent")
        return post.call_args.kwargs["json"]["assessment"]

    def test_grype_batched(self):
        self.assertEqual(self.assessment_sent(GRYPE, "grype")["assetSubType"], "CONTAINER_IMAGE")

    def test_grype_unbatched(self):
        self.assertEqual(self.assessment_sent(GRYPE, "grype", enable_batching=False)["assetSubType"],
                         "CONTAINER_IMAGE")

    def test_trivy_has_no_sub_type(self):
        self.assertNotIn("assetSubType", self.assessment_sent(TRIVY, "trivy"))


if __name__ == "__main__":
    unittest.main()
