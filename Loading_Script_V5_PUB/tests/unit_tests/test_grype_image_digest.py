#!/usr/bin/env python3
"""Unit tests for Grype imageDigest resolution from repoDigests."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from grype_digest_utils import (
    normalize_image_digest,
    resolve_image_digest_from_grype_target,
)
from scanner_translators.base_translator import ScannerConfig
from scanner_translators.grype_translator import GrypeTranslator

SAMPLE_FILE = (
    ROOT
    / "unit_tests"
    / "test_data"
    / "anchore_grype"
    / "aptly_updates_master-775254_masked.json"
)


class TestNormalizeImageDigest(unittest.TestCase):
    def test_extracts_digest_after_at_sign(self):
        value = "registry.example.com/app@sha256:abc123"
        self.assertEqual(normalize_image_digest(value), "sha256:abc123")

    def test_preserves_algorithm_prefixed_digest(self):
        self.assertEqual(normalize_image_digest("sha512:deadbeef"), "sha512:deadbeef")

    def test_returns_none_for_empty_or_invalid(self):
        self.assertIsNone(normalize_image_digest(""))
        self.assertIsNone(normalize_image_digest("registry.example.com/app"))


class TestResolveImageDigestFromGrypeTarget(unittest.TestCase):
    def test_single_repo_digest(self):
        target = {
            "userInput": "registry.example.com/app:tag",
            "repoDigests": ["registry.example.com/app@sha256:aaa"],
        }
        self.assertEqual(
            resolve_image_digest_from_grype_target(target),
            "sha256:aaa",
        )

    def test_multiple_repo_digests_user_input_matches_one(self):
        digest_a = "registry.example.com/app@sha256:aaa"
        digest_b = "registry.example.com/app@sha256:bbb"
        target = {
            "userInput": digest_b,
            "repoDigests": [digest_a, digest_b],
        }
        self.assertEqual(
            resolve_image_digest_from_grype_target(target),
            "sha256:bbb",
        )

    def test_multiple_repo_digests_tag_user_input_uses_first(self):
        digest_a = "registry.example.com/app@sha256:aaa"
        digest_b = "registry.example.com/app@sha256:bbb"
        target = {
            "userInput": "registry.example.com/app:tag",
            "repoDigests": [digest_a, digest_b],
        }
        self.assertEqual(
            resolve_image_digest_from_grype_target(target),
            "sha256:aaa",
        )

    def test_missing_repo_digests_returns_none(self):
        self.assertIsNone(resolve_image_digest_from_grype_target({}))
        self.assertIsNone(resolve_image_digest_from_grype_target({"repoDigests": []}))
        self.assertIsNone(resolve_image_digest_from_grype_target("not-a-dict"))

    def test_string_repo_digest_value(self):
        target = {"repoDigests": "registry.example.com/app@sha256:single"}
        self.assertEqual(
            resolve_image_digest_from_grype_target(target),
            "sha256:single",
        )


class TestGrypeTranslatorIntegration(unittest.TestCase):
    def test_sample_file_sets_image_and_base_digest(self):
        if not SAMPLE_FILE.exists():
            self.skipTest(f"Sample file not found: {SAMPLE_FILE}")

        tag_config = MagicMock()
        tag_config.get_all_tags.return_value = []

        translator = GrypeTranslator(
            ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"),
            tag_config,
            create_empty_assets=True,
        )
        assets = translator.parse_file(str(SAMPLE_FILE))

        self.assertEqual(len(assets), 1)
        attrs = assets[0].attributes
        self.assertEqual(
            attrs["imageDigest"],
            "sha256:f87443ebdcae71de8171aedf233afd96ea9bc29d8cc35f52cab546f041cb8682",
        )
        self.assertEqual(
            attrs["baseImageDigest"],
            "sha256:cb2b36ce16f2f8190f0ebc7ae765402d24eb865f7766e150b50731ae63213c41",
        )


if __name__ == "__main__":
    unittest.main()
