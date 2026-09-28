#!/usr/bin/env python3
"""Unit tests for Grype OCI base-image label promotion.

base.name / base.digest describe the parent image, so they must land in
baseImageName / baseImageDigest, never in the child's own imageName / imageDigest
(Phoenix keys container assets on imageName). Like every other label they are also
kept as tags (Utils 84c63ba).
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner_translators.base_translator import ScannerConfig, ScannerTranslator
from scanner_translators.grype_translator import GrypeTranslator

BASE_NAME = "org.opencontainers.image.base.name"
BASE_DIGEST = "org.opencontainers.image.base.digest"


def grype_doc(user_input, labels):
    return {
        "descriptor": {"name": "grype"},
        "source": {"type": "image", "target": {"userInput": user_input, "labels": labels}},
        "matches": [],
    }


class TestPromoteOciLabels(unittest.TestCase):
    def test_base_labels_map_to_base_image_attributes(self):
        attrs, tags = ScannerTranslator.promote_oci_labels({
            "labels": {BASE_NAME: "ubuntu:24.04", BASE_DIGEST: "sha256:base", "team": "x"},
        })
        self.assertEqual(attrs, {"baseImageName": "ubuntu:24.04", "baseImageDigest": "sha256:base"})
        self.assertEqual(tags, [
            {"key": BASE_NAME, "value": "ubuntu:24.04"},
            {"key": BASE_DIGEST, "value": "sha256:base"},
            {"key": "team", "value": "x"},
        ])


class TestGrypeChildrenOfOneBase(unittest.TestCase):
    def parse(self, doc):
        tag_config = MagicMock()
        tag_config.get_all_tags.return_value = []
        translator = GrypeTranslator(
            ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"),
            tag_config,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
        try:
            return translator.parse_file(f.name)[0]
        finally:
            Path(f.name).unlink()

    def test_children_keep_their_own_identity(self):
        labels = {BASE_NAME: "ubuntu:24.04", BASE_DIGEST: "sha256:base"}
        a = self.parse(grype_doc("registry/app-a:1.0", labels))
        b = self.parse(grype_doc("registry/app-b:1.0", labels))

        for asset, repo in ((a, "registry/app-a:1.0"), (b, "registry/app-b:1.0")):
            attrs = asset.attributes
            self.assertEqual(attrs["repository"], repo)
            self.assertEqual(attrs["baseImageName"], "ubuntu:24.04")
            self.assertEqual(attrs["baseImageDigest"], "sha256:base")
            self.assertIn({"key": BASE_NAME, "value": "ubuntu:24.04"}, asset.tags)
            self.assertIn({"key": BASE_DIGEST, "value": "sha256:base"}, asset.tags)
            self.assertNotIn("imageName", attrs)
            self.assertNotIn("imageDigest", attrs)


if __name__ == "__main__":
    unittest.main()
