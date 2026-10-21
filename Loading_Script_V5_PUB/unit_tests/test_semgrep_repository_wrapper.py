#!/usr/bin/env python3
"""Semgrep results wrapped with the scanned repository's URL (YAML format semgrep_repository_json)."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from client_extensions.oci_label_remap.grype_oci_tags import apply_oci_label_remap_to_grype_translator
from phoenix_import_refactored import TagConfig
from phoenix_multi_scanner_import import ConfigurableScannerTranslator, ScannerConfig


WRAPPER = {
    'object_key': 'GIT-1',
    'repository': 'https://user:FAKE@git.example.invalid/grp/repo.git',
    'scanner': 'semgrep',
    'scanned_at': '2026-01-01T00:00:00Z',
    'phoenix_tags': {'new_authors': '38593', 'team': 't1'},
    'results': [{
        'check_id': 'python.lang.security.example',
        'path': 'app/main.py',
        'start': {'line': 12, 'col': 1},
        'end': {'line': 12, 'col': 9},
        'extra': {'message': 'm', 'severity': 'ERROR', 'metadata': {'cwe': ['CWE-79: x']}},
    }],
}


class TestSemgrepRepositoryWrapper(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = str(Path(temp.name) / 'wrapper.json')
        Path(self.path).write_text(json.dumps(WRAPPER), encoding='utf-8')
        cwd = os.getcwd()
        os.chdir(ROOT)  # FieldMapper reads scanner_field_mappings.yaml from the working directory
        self.addCleanup(os.chdir, cwd)
        self.translator = ConfigurableScannerTranslator(ScannerConfig('universal', 'INFRA'), TagConfig())

    def tags(self):
        return {t['key']: t['value'] for t in self.translator.parse_file(self.path)[0].tags}

    def test_wrapper_is_detected_as_semgrep_repository_json(self):
        self.assertEqual(self.translator.universal_translator.get_scanner_info(self.path)['format'],
                         'semgrep_repository_json')

    def test_repository_asset_with_credentials_stripped(self):
        asset = self.translator.parse_file(self.path)[0]
        self.assertEqual(asset.asset_type, 'REPOSITORY')
        self.assertEqual(asset.attributes['repository'], 'https://git.example.invalid/grp/repo.git')
        self.assertEqual(asset.attributes['scannerSource'], 'semgrep')

    def test_location_is_path_and_line(self):
        self.assertEqual(self.translator.parse_file(self.path)[0].findings[0]['location'], 'app/main.py:12')

    def test_phoenix_tags_reach_the_asset_and_new_authors_is_remapped(self):
        with patch.dict(os.environ, {'WORKSPACE_PREFIX': 'ws-1'}):
            apply_oci_label_remap_to_grype_translator(self.translator)
        tags = self.tags()
        self.assertEqual(tags['team'], 't1')
        self.assertEqual(tags['new_authors'], 'ws-1:38593')

    def test_remap_without_workspace_prefix_imports_new_authors_unchanged(self):
        with patch.dict(os.environ):
            os.environ.pop('WORKSPACE_PREFIX', None)
            apply_oci_label_remap_to_grype_translator(self.translator)
        self.assertEqual(self.tags()['new_authors'], '38593')


if __name__ == '__main__':
    unittest.main()
