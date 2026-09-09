#!/usr/bin/env python3
"""Grype translator records parse failures and tolerates null nested fields."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner_translators.base_translator import ScannerConfig
from scanner_translators.grype_translator import GrypeTranslator


def _translator() -> GrypeTranslator:
    tag_config = MagicMock()
    tag_config.get_all_tags.return_value = []
    return GrypeTranslator(
        ScannerConfig(scanner_type="anchore_grype", asset_type="CONTAINER"),
        tag_config,
        create_empty_assets=True,
    )


def _write_scan(payload: dict) -> str:
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(payload, handle)
    handle.close()
    return handle.name


def _base_scan(**match_overrides) -> dict:
    match = {
        "vulnerability": {
            "id": "CVE-2024-0001",
            "severity": "High",
            "description": "test",
            "cvss": None,
            "fix": None,
        },
        "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
    }
    match.update(match_overrides)
    return {
        "descriptor": {"name": "grype"},
        "source": {"type": "image", "target": {"userInput": "app:latest"}},
        "matches": [match],
    }


class TestGrypeNullFieldsDoNotCrash(unittest.TestCase):
    def test_null_fix_and_cvss_parse(self):
        path = _write_scan(_base_scan())
        assets = _translator().parse_file(path)
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].findings[0]["name"], "CVE-2024-0001")

    def test_null_artifact_parse(self):
        path = _write_scan(_base_scan(artifact=None))
        assets = _translator().parse_file(path)
        self.assertEqual(assets[0].findings[0]["name"], "CVE-2024-0001")

    def test_null_matches_parse_as_empty(self):
        payload = _base_scan()
        payload["matches"] = None
        path = _write_scan(payload)
        assets = _translator().parse_file(path)
        self.assertEqual(len(assets), 1)


class TestGrypeParseErrorIsExplicit(unittest.TestCase):
    def test_non_dict_match_raises_with_path_and_index(self):
        payload = _base_scan()
        payload["matches"] = ["not-a-match"]
        path = _write_scan(payload)
        with self.assertRaises(ValueError) as ctx:
            _translator().parse_file(path)
        message = str(ctx.exception)
        self.assertIn(path, message)
        self.assertIn("match[0]", message)

    def test_invalid_json_raises_with_path(self):
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        handle.write("{")
        handle.close()
        with self.assertRaises(ValueError) as ctx:
            _translator().parse_file(handle.name)
        self.assertIn(handle.name, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
