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
        os.chdir(temp.name)
        self.addCleanup(os.chdir, cwd)
        self.translator = ConfigurableScannerTranslator(ScannerConfig('universal', 'INFRA'), TagConfig())

    def tags(self):
        return {t['key']: t['value'] for t in self.translator.parse_file(self.path)[0].tags}

    def test_wrapper_is_detected_as_semgrep_repository_json(self):
        self.assertEqual(self.translator.universal_translator.get_scanner_info(self.path)['format'],
                         'semgrep_repository_json')

    def test_empty_wrapper_with_null_object_key_remains_a_repository_scan(self):
        Path(self.path).write_text(json.dumps(dict(WRAPPER, object_key=None, results=[])))
        info = self.translator.universal_translator.get_scanner_info(self.path)
        self.assertEqual(info['format'], 'semgrep_repository_json')
        asset = self.translator.parse_file(self.path)[0]
        self.assertEqual(asset.asset_type, 'REPOSITORY')
        self.assertEqual(asset.findings, [])

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


class TestSemgrepDetectionAndPerResultFallback(unittest.TestCase):
    """Wrapper text containing 'paths'/'errors' must not select plain semgrep_json (which copies every result per finding)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        cwd = os.getcwd()
        os.chdir(ROOT)
        self.addCleanup(os.chdir, cwd)
        self.translator = ConfigurableScannerTranslator(ScannerConfig('universal', 'INFRA'), TagConfig())

    def write(self, data):
        path = str(self.dir / 'f.json')
        Path(path).write_text(json.dumps(data), encoding='utf-8')
        return path

    def result(self, i, path, message):
        return {'check_id': f'rule.{i}', 'path': path, 'start': {'line': 10, 'col': 1}, 'end': {'line': 10, 'col': 2},
                'extra': {'message': message, 'severity': 'WARNING', 'metadata': {'cwe': ['CWE-20: x']}}}

    def test_wrapper_mentioning_paths_and_errors_is_still_semgrep_repository_json(self):
        wrapper = dict(WRAPPER, results=[self.result(1, 'src/paths/a.js', 'Handle errors before use'),
                                         self.result(2, 'src/b.js', 'other')])
        path = self.write(wrapper)
        self.assertEqual(self.translator.universal_translator.get_scanner_info(path)['format'], 'semgrep_repository_json')
        finding = self.translator.parse_file(path)[0].findings[0]
        self.assertEqual(finding['location'], 'src/paths/a.js:10')
        self.assertEqual(finding['remedy'], 'No remedy provided')
        self.assertNotIn('referenceIds', finding)

    def test_missing_per_result_field_does_not_pull_in_all_results(self):
        same_rule = [dict(self.result(1, 'a.js', 'm')), dict(self.result(1, 'b.js', 'm'))]
        path = self.write({'results': same_rule, 'errors': [], 'paths': {'scanned': ['a.js', 'b.js']}})
        findings = self.translator.parse_file(path)[0].findings
        self.assertEqual([f['location'] for f in findings], ['a.js:10', 'b.js:10'])  # path:line, not only the line
        for finding in findings:
            self.assertEqual(finding['remedy'], 'No remedy provided')
            self.assertNotIn('referenceIds', finding)


if __name__ == '__main__':
    unittest.main()
