"""Jenkins TruffleHog wrapper and manager dispatch regressions."""

import copy
import json
import logging
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phoenix_import_refactored import PhoenixAPIClient, PhoenixConfig, TagConfig
from phoenix_multi_scanner_import import ScannerConfig
from phoenix_multi_scanner_enhanced import EnhancedMultiScannerImportManager
from scanner_translators.trufflehog_translator import (
    TruffleHogEmptyScan,
    TruffleHogJenkinsError,
    TruffleHogTranslator,
)


FIXTURE = Path(__file__).parent / 'test_data/trufflehog/jenkins_wrapper_v1_sanitized.json'
JOB_URL = 'https://jenkins.example.invalid/job/Example_Team/job/deploy-example-service/'


class TestTruffleHogJenkins(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.translator = TruffleHogTranslator(ScannerConfig('trufflehog', 'CODE'), None)
        self.wrapper = json.loads(FIXTURE.read_text(encoding='utf-8'))

    def write_wrapper(self, wrapper=None, indent=2):
        # indent=2 matches the client's file; indent=None writes the wrapper on one line
        path = Path(self.temp.name) / 'scan.json'
        path.write_text(
            json.dumps(self.wrapper if wrapper is None else wrapper, indent=indent), encoding='utf-8'
        )
        return str(path)

    def record(self, link=None, project=None, **changes):
        record = copy.deepcopy(self.wrapper['findings'][0])
        if link is not None:
            record['SourceMetadata']['Data']['Jenkins']['link'] = link
        if project is not None:
            record['SourceMetadata']['Data']['Jenkins']['project_name'] = project
        record.update(changes)
        return record

    def manager(self):
        manager = EnhancedMultiScannerImportManager.__new__(EnhancedMultiScannerImportManager)
        manager.translators = [self.translator]
        manager._translators_initialized = True
        manager._find_translator_by_name = lambda name: self.translator
        manager.enhanced_importer = Mock()
        manager._convert_session_to_result = lambda *args: {'success': True}
        return manager

    def real_manager(self):
        """A manager with every real translator, including the YAML fallback."""
        manager = EnhancedMultiScannerImportManager.__new__(EnhancedMultiScannerImportManager)
        manager.config_file = str(Path(self.temp.name) / 'missing.ini')
        manager.scanner_configs = {}
        manager.tag_config = TagConfig()
        manager.create_empty_assets = False
        manager.create_inventory_assets = False
        manager._translators_initialized = False
        return manager

    def test_current_wrapper_imports_one_job_and_deduplicates_builds(self):
        for indent in (2, None):
            with self.subTest(indent=indent):
                assets = self.translator.parse_file(self.write_wrapper(indent=indent))
                self.assertEqual(len(assets), 1)
                asset = assets[0]
                self.assertEqual(asset.attributes, {'repository': JOB_URL, 'scannerSource': JOB_URL})
                self.assertIn({'key': 'jenkins-folder', 'value': 'Example_Team'}, asset.tags)
                self.assertEqual(len(asset.findings), 1)
                finding = asset.findings[0]
                self.assertEqual(finding['name'], 'ExampleDetector secret in Jenkins job Example_Team/deploy-example-service')
                self.assertEqual(finding['location'], JOB_URL + '#ExampleDetector')
                self.assertEqual(finding['severity'], self.translator.normalize_severity('Medium'))
                # The fixture's records have an empty Redacted, as in the client's sample
                self.assertEqual(finding['details'], {'specific': {'verified': False}})
                payload = json.dumps(assets, default=lambda value: value.__dict__)
                self.assertNotIn('MUST_NOT_USE_', payload)
                self.assertNotIn('/559', payload)
                self.assertNotIn('/560', payload)

    def test_same_detector_in_one_job_is_one_finding(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'].append(self.record(Raw='SYNTHETIC_OTHER_SECRET'))
        findings = self.translator.parse_file(self.write_wrapper(wrapper))[0].findings
        self.assertEqual(len(findings), 1)

    def test_verified_observation_promotes_a_duplicate(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'][1]['Verified'] = True
        findings = self.translator.parse_file(self.write_wrapper(wrapper))[0].findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], self.translator.normalize_severity('High'))
        self.assertTrue(findings[0]['details']['specific']['verified'])

    def test_redacted_value_is_used_only_when_it_does_not_contain_raw(self):
        for redacted, expected in (
            ('abc***', {'various': {'Redacted': 'abc***'}}),
            ('SYNTHETIC_SECRET', {}),
            ('prefix SYNTHETIC_SECRET suffix', {}),
            ('', {}),
            ('   ', {}),
        ):
            with self.subTest(redacted=redacted):
                wrapper = copy.deepcopy(self.wrapper)
                wrapper['findings'] = [self.record(Raw='SYNTHETIC_SECRET', Redacted=redacted)]
                finding = self.translator.parse_file(self.write_wrapper(wrapper))[0].findings[0]
                self.assertEqual(finding['details']['specific'], {'verified': False, **expected})
                self.assertNotIn('SYNTHETIC_SECRET', json.dumps(finding))

    def test_raw_v2_is_not_uploaded_when_redacted_matches_it(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] = [self.record(Raw='', RawV2='SYNTHETIC_RAW_V2',
                                           Redacted='SYNTHETIC_RAW_V2')]
        finding = self.translator.parse_file(self.write_wrapper(wrapper))[0].findings[0]
        self.assertNotIn('various', finding['details']['specific'])
        self.assertNotIn('SYNTHETIC_RAW_V2', json.dumps(finding))

    def test_pre_parser_output_sends_its_truncated_redacted(self):
        # The client's parser blanks Raw and RawV2 and writes a truncated value to Redacted
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] = [self.record(Raw='', RawV2='', Redacted='AKIA****')]
        finding = self.translator.parse_file(self.write_wrapper(wrapper))[0].findings[0]
        self.assertEqual(finding['details']['specific']['various'], {'Redacted': 'AKIA****'})

    def test_distinct_detectors_and_jobs_remain_distinct(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] += [
            self.record(DetectorName='OtherDetector', Verified=True),
            self.record(link='https://jenkins.example.invalid/job/Other_Team/job/deploy-example-service/12/consoleText'),
        ]
        assets = self.translator.parse_file(self.write_wrapper(wrapper))
        self.assertEqual(sorted(len(asset.findings) for asset in assets), [1, 2])
        first = next(asset for asset in assets if asset.attributes['repository'] == JOB_URL)
        self.assertEqual(
            sorted(finding['severity'] for finding in first.findings),
            sorted([
                self.translator.normalize_severity('High'),
                self.translator.normalize_severity('Medium'),
            ]),
        )

    def test_pre_parser_tags_are_added_to_the_asset(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'][1]['phoenix_tags'] = {'org.opencontainers.image.new_authors_key': 'prefix:123'}
        asset = self.translator.parse_file(self.write_wrapper(wrapper))[0]
        self.assertIn({'key': 'org.opencontainers.image.new_authors_key', 'value': 'prefix:123'}, asset.tags)

    def test_rotation_guide_goes_in_remedy_and_name_shows_the_parent_folder(self):
        base = 'https://jenkins.example.invalid/job/Product/job/News%20-%20Justice/job/go-service/job/integration-tests'
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] = [
            self.record(link=base + '/387/consoleText', project='integration-tests', DetectorName='Gitlab',
                        ExtraData={'rotation_guide': 'https://howtorotate.com/docs/tutorials/gitlab/', 'version': '1'}),
            self.record(link='https://jenkins.example.invalid/job/top-level/5/consoleText', project='top-level',
                        ExtraData={'rotation_guide': 'javascript:alert(1)'}),
        ]
        assets = self.translator.parse_file(self.write_wrapper(wrapper))
        deep, top = sorted(assets, key=lambda asset: asset.attributes['repository'])
        self.assertEqual(deep.findings[0]['name'], 'Gitlab secret in Jenkins job go-service/integration-tests')
        self.assertEqual(
            deep.findings[0]['remedy'],
            'Rotate the exposed secret and remove it from Jenkins build logs. '
            'Rotation guide: https://howtorotate.com/docs/tutorials/gitlab/',
        )
        self.assertIn({'key': 'jenkins-folder', 'value': 'Product'}, deep.tags)
        self.assertEqual(top.findings[0]['name'], 'ExampleDetector secret in Jenkins job top-level')
        self.assertEqual(top.findings[0]['remedy'], 'Rotate the exposed secret and remove it from Jenkins build logs.')

    def test_job_name_comes_from_project_name_with_the_link_as_fallback(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] = [
            self.record(link='https://jenkins.example.invalid/job/Team/job/from-link/3/consoleText', project='from-field'),
            self.record(link='https://jenkins.example.invalid/job/Team/job/only-link/3/consoleText'),
        ]
        del wrapper['findings'][1]['SourceMetadata']['Data']['Jenkins']['project_name']
        field, link = sorted(self.translator.parse_file(self.write_wrapper(wrapper)),
                             key=lambda asset: asset.attributes['repository'])
        self.assertIn({'key': 'jenkins-job', 'value': 'from-field'}, field.tags)
        self.assertEqual(field.findings[0]['name'], 'ExampleDetector secret in Jenkins job Team/from-field')
        self.assertIn({'key': 'jenkins-job', 'value': 'only-link'}, link.tags)
        self.assertEqual(link.findings[0]['name'], 'ExampleDetector secret in Jenkins job Team/only-link')

    def test_remap_oci_labels_converts_the_team_tag_like_grype(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'][0]['phoenix_tags'] = {
            'org.opencontainers.image.new_authors_key': 'HRDB-123', 'other': 'HRDB-9',
        }
        with patch.dict(os.environ, {'WORKSPACE_PREFIX': 'ws-1'}):
            self.manager()._apply_oci_label_remap_to_translator(self.translator, True)
        tags = self.translator.parse_file(self.write_wrapper(wrapper))[0].tags
        self.assertIn({'key': 'org.opencontainers.image.new_authors_key', 'value': 'ws-1:123'}, tags)
        self.assertIn({'key': 'other', 'value': 'HRDB-9'}, tags)

    def test_phoenix_request_contains_only_allowed_jenkins_fields(self):
        assets = self.translator.parse_file(self.write_wrapper())
        client = PhoenixAPIClient(PhoenixConfig(
            client_id='test', client_secret='test', api_base_url='https://phoenix.example.invalid'
        ))
        response = Mock(status_code=200, text='{}')
        response.json.return_value = {}
        with patch.object(client, 'get_access_token', return_value='test'), \
             patch('phoenix_import_refactored.requests.post', return_value=response) as post, \
             patch('phoenix_import_refactored.DebugLogger.log_request'), \
             patch('phoenix_import_refactored.DebugLogger.log_response'):
            client.import_assets(assets, 'fixed')
        payload = post.call_args.kwargs['json']
        self.assertEqual(payload['assessment']['assetType'], 'CODE')
        finding = payload['assets'][0]['findings'][0]
        self.assertEqual(finding['severity'], 5.0)
        self.assertEqual(finding['details'], {'specific': {'verified': False}})
        serialized = json.dumps(payload)
        self.assertNotIn('MUST_NOT_USE_', serialized)
        self.assertNotIn('build_number', serialized)
        self.assertNotIn('/559', serialized)
        self.assertNotIn('/560', serialized)

    def test_translator_logs_no_secret_values(self):
        with self.assertLogs(level='INFO') as captured:
            self.translator.parse_file(self.write_wrapper())
        self.assertNotIn('MUST_NOT_USE_', '\n'.join(captured.output))

    def test_invalid_records_are_skipped_not_fatal(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] += [
            self.record(link='bad-url'),
            self.record(DetectorName=''),
            {'SourceMetadata': {'Data': {'Git': {}}}},
            'not-a-record',
        ]
        with self.assertLogs(level='INFO') as captured:
            assets = self.translator.parse_file(self.write_wrapper(wrapper))
        self.assertEqual([len(asset.findings) for asset in assets], [1])
        self.assertIn('skipped=4', '\n'.join(captured.output))

    def test_wrapper_level_problems_fail_closed(self):
        cases = {}
        for change in ('version', 'exit_code', 'source', 'missing_scan', 'no_valid_records'):
            wrapper = copy.deepcopy(self.wrapper)
            if change == 'version':
                wrapper['schema_version'] = '2.0'
            elif change == 'missing_scan':
                del wrapper['scan']
            elif change == 'exit_code':
                wrapper['scan']['trufflehog_exit_code'] = 1
            elif change == 'source':
                wrapper['scan']['source'] = 'git'
            elif change == 'no_valid_records':
                for record in wrapper['findings']:
                    record['SourceMetadata']['Data']['Jenkins']['link'] = 'bad-url'
            cases[change] = json.dumps(wrapper, indent=2)
        cases['malformed_json'] = json.dumps(self.wrapper, indent=2)[:-10]
        for label, content in cases.items():
            with self.subTest(label=label):
                path = Path(self.temp.name) / 'scan.json'
                path.write_text(content, encoding='utf-8')
                if label != 'malformed_json':
                    # Claimed in auto mode, so the YAML fallback never sees raw secrets
                    self.assertTrue(self.translator.can_handle(str(path)))
                with self.assertRaises(TruffleHogJenkinsError) as raised:
                    self.translator.parse_file(str(path))
                self.assertNotIn('MUST_NOT_USE_', str(raised.exception))

    def test_fail_exit_code_and_minor_version_are_accepted(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['scan']['trufflehog_exit_code'] = 183
        wrapper['schema_version'] = '1.1'
        self.assertEqual(len(self.translator.parse_file(self.write_wrapper(wrapper))), 1)

    def test_wrapper_keys_can_be_reordered(self):
        wrapper = dict(reversed(list(self.wrapper.items())))
        path = self.write_wrapper(wrapper)
        self.assertTrue(self.translator.can_handle(path))
        self.assertEqual(len(self.translator.parse_file(path)), 1)

    def test_job_url_keeps_context_and_numeric_job_name(self):
        link = 'https://jenkins.example.invalid/jenkins/job/Team/job/123/559/consoleText'
        self.assertEqual(
            self.translator._jenkins_job(link),
            ('https://jenkins.example.invalid/jenkins/job/Team/job/123/', ['Team', '123']),
        )

    def test_top_level_encoded_multibranch_and_invalid_links(self):
        self.assertEqual(
            self.translator._jenkins_job('https://jenkins.example.invalid/job/deploy/7/consoleText'),
            ('https://jenkins.example.invalid/job/deploy/', ['deploy']),
        )
        self.assertEqual(
            self.translator._jenkins_job(
                'https://jenkins.example.invalid/jenkins/job/My%20Team/job/feature%252Fx/45/consoleText'
            ),
            ('https://jenkins.example.invalid/jenkins/job/My%20Team/job/feature%252Fx/', ['My Team', 'feature%2Fx']),
        )
        self.assertEqual(
            self.translator._jenkins_job(
                'https://user:token@jenkins.example.invalid:8443/job/deploy/7/consoleText'
            )[0],
            'https://jenkins.example.invalid:8443/job/deploy/',
        )
        for link in ('bad-url', 'ftp://jenkins.example.invalid/job/x/1/consoleText',
                     'https://jenkins.example.invalid/view/x/', None):
            with self.subTest(link=link):
                self.assertIsNone(self.translator._jenkins_job(link))

    def test_empty_scan_is_a_successful_manager_noop(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] = []
        wrapper['scan']['tool'] = 'TruffleHog'
        path = self.write_wrapper(wrapper)
        self.assertIsInstance(self.real_manager().detect_scanner_type(path), TruffleHogTranslator)
        with self.assertRaises(TruffleHogEmptyScan):
            self.translator.parse_file(path)
        manager = self.manager()
        result = manager.process_scanner_file_enhanced(
            path, scanner_type='trufflehog', assessment_name='fixed', fix_data=False
        )
        self.assertTrue(result['success'])
        self.assertEqual(result['assets_imported'], 0)
        manager.enhanced_importer.import_assets_with_batching.assert_not_called()

    def test_manager_uses_selected_translator_and_never_falls_back(self):
        manager = self.manager()
        path = self.write_wrapper()
        manager.detect_scanner_type = Mock(side_effect=AssertionError('unexpected re-detection'))
        assets = manager._parse_file_to_assets(path, self.translator, None)
        self.assertEqual(len(assets), 1)
        manager.detect_scanner_type.assert_not_called()
        result = manager.process_scanner_file_enhanced(
            path, scanner_type='trufflehog', assessment_name='fixed', fix_data=False
        )
        self.assertTrue(result['success'])
        submitted = manager.enhanced_importer.import_assets_with_batching.call_args.args[0]
        self.assertEqual(len(submitted), 1)
        manager._create_fallback_asset = Mock(side_effect=AssertionError('unexpected fallback'))
        self.wrapper['schema_version'] = '2.0'
        result = manager.process_scanner_file_enhanced(
            self.write_wrapper(), scanner_type='trufflehog', assessment_name='fixed', fix_data=False
        )
        self.assertFalse(result['success'])
        manager._create_fallback_asset.assert_not_called()

    def test_malformed_one_line_wrapper_fails_closed_like_the_pretty_one(self):
        # urlsplit raises ValueError on this link; the one-line route used to report an empty success
        wrapper = copy.deepcopy(self.wrapper)
        wrapper['findings'] = [self.record(link='https://[::1/job/x/5/consoleText')]
        manager = self.manager()
        manager._create_fallback_asset = Mock(side_effect=AssertionError('unexpected fallback'))
        errors = []
        for indent in (2, None):
            with self.subTest(indent=indent):
                result = manager.process_scanner_file_enhanced(
                    self.write_wrapper(wrapper, indent=indent), scanner_type='trufflehog',
                    assessment_name='fixed', fix_data=False
                )
                self.assertFalse(result['success'])
                errors.append(result.get('error'))
        self.assertEqual(errors, ['Jenkins wrapper could not be parsed: ValueError'] * 2)
        manager._create_fallback_asset.assert_not_called()
        manager.enhanced_importer.import_assets_with_batching.assert_not_called()

    def test_auto_detection_claims_wrapper(self):
        manager = self.manager()
        self.assertIs(manager.detect_scanner_type(self.write_wrapper()), self.translator)

    def test_real_translator_order_selects_trufflehog_before_yaml(self):
        manager = self.real_manager()
        selected = manager.detect_scanner_type(self.write_wrapper())
        self.assertIsInstance(selected, TruffleHogTranslator)
        explicit = manager._find_translator_by_name('trufflehog')
        self.assertIs(explicit, selected)
        self.assertEqual(len(manager._parse_file_to_assets(self.write_wrapper(), explicit, None)), 1)

    def test_format_variants_are_never_left_to_the_yaml_fallback(self):
        # The YAML fallback copies raw secrets, so every variant must be claimed by TruffleHog
        pretty = json.dumps(self.wrapper, indent=2)
        variants = {
            'utf8_bom': '﻿' + pretty,
            'leading_blank_line': '\n' + pretty,
            'first_line_holds_a_key': pretty.replace('{\n  ', '{', 1),
            'crlf': pretty.replace('\n', '\r\n'),
            'tool_capitalised': pretty.replace('"tool": "trufflehog"', '"tool": "TruffleHog"'),
        }
        manager = self.real_manager()
        for label, text in variants.items():
            with self.subTest(label=label):
                path = Path(self.temp.name) / 'scan.json'
                path.write_text(text, encoding='utf-8', newline='')
                self.assertIsInstance(manager.detect_scanner_type(str(path)), TruffleHogTranslator)
                assets = self.translator.parse_file(str(path))
                self.assertEqual([len(asset.findings) for asset in assets], [1])

    def test_existing_git_and_json_array_formats_still_parse(self):
        inputs = [
            ({'branch': 'main', 'commit': 'abc', 'reason': 'Secret Found',
              'commitHash': 'abcdef12', 'path': 'safe/path'}, 'main:safe/path'),
            ({'SourceMetadata': {'Data': {'Git': {
                'file': 'safe/path', 'commit': 'abcdef12', 'repository': 'repo'
            }}}, 'DetectorType': 990, 'DetectorName': 'Example',
              'Redacted': '[redacted]'}, 'repo:safe/path'),
            ({'SourceMetadata': {'Data': {'Git': {
                'file': 'safe/path', 'commit': 'abcdef12', 'repository': 'repo'
            }}}, 'DetectorType': 990, 'DetectorName': 'Example',
              'Raw': 'SYNTHETIC_NATIVE_SECRET', 'Redacted': ''}, 'repo:safe/path'),
        ]
        for record, expected_location in inputs:
            with self.subTest(location=expected_location):
                path = Path(self.temp.name) / 'native.json'
                path.write_text(json.dumps(record) + '\n', encoding='utf-8')
                self.assertTrue(self.translator.can_handle(str(path)))
                assets = self.translator.parse_file(str(path))
                self.assertEqual(assets[0].findings[0]['location'], expected_location)
                self.assertNotIn('SYNTHETIC_NATIVE_SECRET', json.dumps(assets[0].findings[0]))
        path = Path(self.temp.name) / 'array.json'
        path.write_text(json.dumps([{
            'rule': {'id': 'example', 'message': 'Secret Found'},
            'path': 'safe/path', 'start_line': 2, 'end_line': 2,
        }]), encoding='utf-8')
        self.assertTrue(self.translator.can_handle(str(path)))
        assets = self.translator.parse_file(str(path))
        self.assertEqual(assets[0].findings[0]['location'], 'safe/path:2')

    def test_native_git_redacted_value_is_omitted_when_empty_or_unsafe(self):
        for redacted, expected in (('abc***', 'abc***'), ('', None), ('SYNTHETIC_NATIVE_SECRET', None)):
            with self.subTest(redacted=redacted):
                path = Path(self.temp.name) / 'native.json'
                path.write_text(json.dumps({
                    'SourceMetadata': {'Data': {'Git': {'file': 'safe/path', 'repository': 'repo'}}},
                    'DetectorName': 'Example', 'Raw': 'SYNTHETIC_NATIVE_SECRET', 'Redacted': redacted,
                }) + '\n', encoding='utf-8')
                details = self.translator.parse_file(str(path))[0].findings[0]['details']
                self.assertEqual(details.get('redacted_value'), expected)
                self.assertNotIn('SYNTHETIC_NATIVE_SECRET', json.dumps(details))

    def test_native_jenkins_ndjson_matches_the_wrapper(self):
        path = Path(self.temp.name) / 'native.json'
        path.write_text(''.join(json.dumps(record) + '\n' for record in self.wrapper['findings']),
                        encoding='utf-8')
        self.assertTrue(self.translator.can_handle(str(path)))
        native = self.translator.parse_file(str(path))
        wrapped = self.translator.parse_file(self.write_wrapper())
        self.assertEqual([asset.attributes for asset in native], [asset.attributes for asset in wrapped])
        self.assertEqual([asset.findings for asset in native], [asset.findings for asset in wrapped])

    def test_no_trufflehog_shape_sends_a_secret_through_the_real_manager(self):
        # The committed loader sent the wrapper to the YAML fallback, which copied Raw into the
        # finding name, location and remedy. Every shape and mode goes through the real manager here.
        secrets = {'Raw': 'FAKE_RAW_1a2b3c', 'RawV2': 'FAKE_RAWV2_4d5e6f',
                   'SecretParts': {'key': 'FAKE_PART_7g8h9i'}, 'Redacted': ''}
        jenkins = [dict(record, **secrets) for record in self.wrapper['findings']]
        git = dict(secrets, DetectorName='AWS', SourceMetadata={'Data': {'Git': {
            'file': 'safe/.env', 'commit': 'abcdef12', 'repository': 'repo'}}})
        v2 = {'branch': 'main', 'commitHash': 'abcdef12', 'path': 'safe/.env', 'reason': 'High Entropy',
              'diff': '+FAKE_V2DIFF_0j1k2l', 'printDiff': 'FAKE_V2DIFF_0j1k2l', 'stringsFound': ['FAKE_V2STR_6p7q8r']}
        wrapper = dict(self.wrapper, findings=jenkins)
        shapes = {
            'wrapper.json': json.dumps(wrapper, indent=2),
            'wrapper_oneline.json': json.dumps(wrapper),
            'wrapper_v2.json': json.dumps(dict(wrapper, schema_version='2.0'), indent=2),
            **{f'wrapper_{key}_key.json': json.dumps(
                dict({k: v for k, v in wrapper.items() if k != 'findings'}, **{key: jenkins}), indent=2)
               for key in ('results', 'vulnerabilities', 'matches', 'issues')},
            'jenkins_native.json': ''.join(json.dumps(record) + '\n' for record in jenkins),
            'jenkins_array.json': json.dumps(jenkins, indent=2),
            'v2.json': json.dumps(v2) + '\n',
            'git.json': json.dumps(git) + '\n',
            'git_pretty.json': json.dumps(git, indent=2),
            'git_array.json': json.dumps([git], indent=2),
        }
        config = Path(self.temp.name) / 'loader.ini'
        config.write_text('[phoenix]\nclient_id = x\nclient_secret = x\n'
                          'api_base_url = https://phoenix.example.invalid\nimport_type = merge\n', encoding='utf-8')
        bodies = []

        def send(adapter, request, **kwargs):  # nothing leaves the machine
            bodies.append(request.body.decode() if isinstance(request.body, bytes) else str(request.body or ''))
            response = requests.Response()
            response.status_code, response._content = 200, b'{"token": "x", "id": "x"}'
            return response

        import requests
        records = []
        handler = logging.Handler(logging.DEBUG)
        handler.emit = lambda record: records.append(record.getMessage())
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        cwd = os.getcwd()
        os.chdir(ROOT)  # the YAML fallback reads scanner_field_mappings.yaml from the working directory
        self.addCleanup(os.chdir, cwd)
        with patch('requests.adapters.HTTPAdapter.send', send):
            manager = EnhancedMultiScannerImportManager(str(config))
            for name, text in shapes.items():
                for scanner in (None, 'trufflehog'):
                    with self.subTest(shape=name, scanner=scanner):
                        path = Path(self.temp.name) / name
                        path.write_text(text, encoding='utf-8')
                        bodies.clear(), records.clear()
                        try:
                            result = manager.process_scanner_file_enhanced(
                                str(path), scanner_type=scanner, assessment_name='fixed', import_type='merge')
                        except Exception as error:  # the service stores the error message
                            result = {'error': repr(error)}
                        sinks = '\n'.join(bodies + records + [json.dumps(result, default=str)])
                        leaked = sorted(set(re.findall(r'FAKE_(RAW|RAWV2|PART|V2DIFF|V2STR)_', sinks)))
                        self.assertEqual(leaked, [], f'secret markers in the request, logs or result: {leaked}')
        self.assertTrue(bodies or records)


if __name__ == '__main__':
    unittest.main()
