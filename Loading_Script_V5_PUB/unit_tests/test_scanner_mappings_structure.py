#!/usr/bin/env python3
"""
Structural tests for scanner_field_mappings.yaml

Guards the defect fixed alongside issue #121: 155 of the 191 scanner
definitions were indented one level too deep and landed under
`asset_type_detection:` instead of `scanners:`. The file still parsed as valid
YAML and nothing raised, but FieldMapper reads `config.get('scanners', {})`, so
those scanners were invisible to the universal translator at runtime.

The failure mode is silent, which is exactly why it survived: a report whose
mapping lived in the orphaned block either failed detection or was matched by
some other scanner with a broad `*.json` pattern and imported with zero
findings.
"""

import unittest
from pathlib import Path

import yaml

_V5_ROOT = Path(__file__).parent.parent
_MAPPINGS = _V5_ROOT / "scanner_field_mappings.yaml"

# `asset_type_detection` legitimately holds only these two keys. Anything else
# under it is a scanner definition that leaked in through mis-indentation.
_ASSET_TYPE_DETECTION_KEYS = {"patterns", "default_by_scanner"}


class TestScannerMappingsStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_MAPPINGS, "r", encoding="utf-8") as fh:
            cls.config = yaml.safe_load(fh)

    def test_top_level_keys(self):
        """The file exposes exactly the four sections FieldMapper reads."""
        self.assertEqual(
            {"phoenix_fields", "scanners", "default_severity_mappings",
             "asset_type_detection"},
            set(self.config),
        )

    def test_no_scanner_definitions_leaked_into_asset_type_detection(self):
        """A scanner definition under asset_type_detection is unreachable.

        This is the regression guard. A scanner definition is identifiable by
        its `formats` list; asset_type_detection should contain no such entry.
        """
        leaked = sorted(
            key for key, value in self.config["asset_type_detection"].items()
            if isinstance(value, dict) and "formats" in value
        )
        self.assertEqual(
            [], leaked,
            "%d scanner definition(s) are nested under asset_type_detection and "
            "are therefore invisible to FieldMapper. Re-indent them under "
            "`scanners:`. Leaked: %s" % (len(leaked), leaked),
        )

    def test_asset_type_detection_holds_only_its_own_keys(self):
        self.assertEqual(
            _ASSET_TYPE_DETECTION_KEYS,
            set(self.config["asset_type_detection"]),
        )

    def test_every_scanner_definition_is_well_formed(self):
        """Each scanner needs at least one format with a detectable shape."""
        malformed = []
        for name, definition in self.config["scanners"].items():
            formats = (definition or {}).get("formats")
            if not isinstance(formats, list) or not formats:
                malformed.append("%s: no formats" % name)
                continue
            for fmt in formats:
                if not fmt.get("name"):
                    malformed.append("%s: format missing name" % name)
                if not fmt.get("file_patterns"):
                    malformed.append("%s/%s: no file_patterns"
                                     % (name, fmt.get("name")))
        self.assertEqual([], malformed, "Malformed scanner definitions: %s" % malformed)

    def test_known_scanners_are_reachable(self):
        """Spot-check scanners that were unreachable before the fix."""
        for name in ("jfrog_xray_unified", "sonatype", "anchore_engine",
                     "api_blackduck", "mend"):
            self.assertIn(
                name, self.config["scanners"],
                "%s is not reachable under `scanners:`" % name,
            )

    def test_scanner_count_matches_definition_count(self):
        """No scanner definition exists anywhere outside `scanners:`."""
        stray = [
            key for section in ("phoenix_fields", "default_severity_mappings",
                                "asset_type_detection")
            for key, value in (self.config[section] or {}).items()
            if isinstance(value, dict) and "formats" in value
        ]
        self.assertEqual([], stray,
                         "Scanner definitions found outside `scanners:`: %s" % stray)


if __name__ == "__main__":
    unittest.main(verbosity=2)
