#!/usr/bin/env python3
"""The child's own imageDigest comes from source.target.repoDigests; the OCI base.* labels stay
base attributes. Covers both Grype translators: scanner_translators.GrypeTranslator (enhanced entry
point) and the legacy phoenix_multi_scanner_import.AnchoreGrypeTranslator."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import phoenix_multi_scanner_import as legacy
from scanner_translators.base_translator import ScannerConfig
from scanner_translators.grype_translator import GrypeTranslator

CHILD_DIGEST = "sha256:" + "a" * 64
BASE_DIGEST = "sha256:" + "b" * 64
DOC = {
    "descriptor": {"name": "grype"},
    "source": {"type": "image", "target": {
        "userInput": "registry.example.com/app:1.0",
        "repoDigests": [f"registry.example.com/app@{CHILD_DIGEST}"],
        "labels": {
            "org.opencontainers.image.base.name": "ubuntu:24.04",
            "org.opencontainers.image.base.digest": BASE_DIGEST,
        },
    }},
    "matches": [],
}


def parse(translator):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(DOC, f)
    try:
        return translator.parse_file(f.name)[0].attributes
    finally:
        Path(f.name).unlink()


def tag_config():
    tc = MagicMock()
    tc.get_all_tags.return_value = []
    return tc


class TestChildImageDigest(unittest.TestCase):
    def assert_attributes(self, attrs):
        self.assertEqual(attrs["imageDigest"], CHILD_DIGEST)
        self.assertEqual(attrs["baseImageDigest"], BASE_DIGEST)
        self.assertEqual(attrs["baseImageName"], "ubuntu:24.04")
        self.assertNotIn("imageName", attrs)

    def test_grype_translator(self):
        self.assert_attributes(parse(GrypeTranslator(
            ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"), tag_config())))

    def test_legacy_anchore_grype_translator(self):
        self.assert_attributes(parse(legacy.AnchoreGrypeTranslator(
            legacy.ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"), tag_config())))


if __name__ == "__main__":
    unittest.main()
