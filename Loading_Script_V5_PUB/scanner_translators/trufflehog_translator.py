#!/usr/bin/env python3
"""
TruffleHog Translator - Consolidated
=====================================

Unified translator for all TruffleHog secret scanner formats:
- TruffleHog V2 (NDJSON format with branch, commit, reason)
- TruffleHog V3 (NDJSON format with SourceMetadata, DetectorType)
- TruffleHog v3 (JSON array format with rule.id)

Consolidates 2 translators→1:
- TruffleHogTranslator (round19_98percent.py) - V2/V3 NDJSON
- TruffleHog3Translator (round20_final_push.py) - v3 JSON array

Note: TruffleHog has confusing version naming with overlapping "V3" and "v3" formats.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit, urlunsplit

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class TruffleHogJenkinsError(ValueError):
    """A Jenkins input that must fail the import instead of creating a fallback asset."""


class TruffleHogEmptyScan(Exception):
    """A valid Jenkins wrapper with no findings."""


def holds_trufflehog_secrets(file_path: str) -> bool:
    """True when a file has TruffleHog records: a DetectorName next to Raw, RawV2 or SecretParts.

    Only the presence of those keys in the text is checked; no values are read.
    """
    try:
        with open(file_path, encoding='utf-8-sig', errors='replace') as f:
            text = f.read()
    except OSError:
        return False
    return '"DetectorName"' in text and any(f'"{key}"' in text for key in ('Raw', 'RawV2', 'SecretParts'))


class TruffleHogTranslator(ScannerTranslator):
    """Unified translator for all TruffleHog outputs (V2, V3 NDJSON, v3 JSON)"""


    @staticmethod
    def _safe_redacted_value(record: Dict[str, Any]) -> str:
        """Redacted as received, or '' when it is empty or contains the Raw or RawV2 value.

        Masking or truncating Redacted is expected before import, on the client side: for example a
        pre-parser that empties Raw and RawV2 and writes a truncated Redacted. SecretParts values
        are not inspected.
        """
        redacted = record.get('Redacted')
        if isinstance(redacted, str) and redacted.strip():
            raw_values = (record.get('Raw'), record.get('RawV2'))
            if not any(isinstance(raw, str) and raw and raw in redacted for raw in raw_values):
                return redacted
        return ''

    def _jenkins_secret_fields(self, record: Dict[str, Any]) -> Dict[str, str]:
        """The non-empty secret fields to show in Phoenix; empty fields are left out."""
        redacted = self._safe_redacted_value(record)
        return {'Redacted': redacted} if redacted else {}
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect any TruffleHog format (V2/V3 NDJSON or v3 JSON)"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = next((line.strip() for line in f if line.strip()), '')
                if not first_line:
                    return False
                
                # Try NDJSON format first (V2/V3)
                try:
                    obj = json.loads(first_line)
                    if isinstance(obj, dict):
                        # V3 NDJSON: Has SourceMetadata, DetectorType, DetectorName
                        if 'SourceMetadata' in obj and 'DetectorType' in obj:
                            return True
                        # V2 NDJSON: Has branch, commit, reason, stringsFound
                        if 'branch' in obj and 'commit' in obj and 'reason' in obj:
                            return True
                except json.JSONDecodeError:
                    pass
                
                # Try v3 JSON array format, or the Jenkins wrapper object
                f.seek(0)
                try:
                    content = json.load(f)
                    if self._is_jenkins_wrapper(content):
                        return True
                    if isinstance(content, list) and len(content) > 0:
                        first = content[0]
                        if isinstance(first, dict) and 'rule' in first:
                            rule = first.get('rule', {})
                            if isinstance(rule, dict) and 'id' in rule:
                                return True
                except json.JSONDecodeError:
                    pass
            
            return False
        except Exception as e:
            logger.debug(f"TruffleHogTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse TruffleHog file (auto-detects format)"""
        try:
            # First, try to detect if it's v3 JSON array format
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = next((line.strip() for line in f if line.strip()), '')
                if first_line.startswith('['):
                    # Likely JSON array (v3)
                    f.seek(0)
                    try:
                        content = json.load(f)
                        if isinstance(content, list):
                            return self._parse_v3_json_array(file_path, content)
                    except json.JSONDecodeError:
                        pass
                elif first_line.startswith('{') and not self._is_json(first_line):
                    # An object spread over several lines is not NDJSON: the Jenkins wrapper
                    f.seek(0)
                    try:
                        return self._parse_jenkins_wrapper(json.load(f))
                    except (TruffleHogJenkinsError, TruffleHogEmptyScan):
                        raise
                    except Exception as e:
                        # Never fall back to a placeholder asset for a broken wrapper
                        raise TruffleHogJenkinsError(
                            f'Jenkins wrapper could not be parsed: {type(e).__name__}'
                        ) from e
            
            # Otherwise, parse as NDJSON (V2/V3)
            return self._parse_ndjson(file_path)
            
        except (TruffleHogJenkinsError, TruffleHogEmptyScan):
            raise
        except Exception as e:
            logger.error(f"Error parsing TruffleHog file: {e}")
            import traceback
            traceback.print_exc()
            return []

    @staticmethod
    def _is_json(text: str) -> bool:
        try:
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False

    @staticmethod
    def _is_jenkins_wrapper(content: Any) -> bool:
        """The client's JSON object wrapping TruffleHog records in a `findings` list.

        Claimed loosely and validated strictly: an unclaimed wrapper reaches the YAML
        fallback, which copies the raw secrets.
        """
        findings = content.get('findings') if isinstance(content, dict) else None
        if not isinstance(findings, list):
            return False
        scan = content.get('scan')
        return (isinstance(scan, dict) and str(scan.get('tool')).lower() == 'trufflehog') or (
            bool(findings) and isinstance(findings[0], dict) and 'SourceMetadata' in findings[0])

    @staticmethod
    def _jenkins_metadata(record: Any) -> Optional[Dict[str, Any]]:
        metadata = record.get('SourceMetadata') if isinstance(record, dict) else None
        data = metadata.get('Data') if isinstance(metadata, dict) else None
        jenkins = data.get('Jenkins') if isinstance(data, dict) else None
        return jenkins if isinstance(jenkins, dict) else None

    @staticmethod
    def _jenkins_job(link: Any) -> Optional[Tuple[str, List[str]]]:
        """Build log link -> (job URL, folder and job names from the top down).

        https://host/job/Team/job/deploy/559/consoleText -> https://host/job/Team/job/deploy/
        """
        if not isinstance(link, str):
            return None
        parsed = urlsplit(link)
        parts = [part for part in parsed.path.split('/') if part]
        if parts and parts[-1] == 'consoleText':
            parts.pop()
        if len(parts) >= 2 and parts[-1].isdigit() and parts[-2] != 'job':
            parts.pop()  # the build number; a numeric job name directly follows 'job'
        if parsed.scheme not in ('http', 'https') or 'job' not in parts:
            return None
        job_path = parts[parts.index('job'):]
        if len(job_path) % 2 or any(marker != 'job' for marker in job_path[::2]):
            return None
        names = [unquote(name) for name in job_path[1::2]]
        host = parsed.netloc.rpartition('@')[2]  # drop user:token@ copied from TruffleHog's --url
        job_url = urlunsplit((parsed.scheme, host, '/' + '/'.join(parts) + '/', '', ''))
        return job_url, names

    def _parse_jenkins_wrapper(self, wrapper: Any) -> List[AssetData]:
        if not self._is_jenkins_wrapper(wrapper):
            raise TruffleHogJenkinsError('Not a TruffleHog Jenkins wrapper')
        scan = wrapper.get('scan') if isinstance(wrapper.get('scan'), dict) else {}
        if (str(scan.get('tool')).lower() != 'trufflehog' or str(scan.get('source')).lower() != 'jenkins'
                or not str(wrapper.get('schema_version')).startswith('1.')):
            raise TruffleHogJenkinsError('Unsupported Jenkins wrapper version or source')
        # Reject failed scans: merge would still close findings on the jobs they reached.
        # 183 is TruffleHog's --fail exit code when results were found.
        if scan.get('trufflehog_exit_code') not in (0, 183):
            raise TruffleHogJenkinsError('Jenkins scan did not complete successfully')
        if not wrapper['findings']:
            raise TruffleHogEmptyScan()
        return self._jenkins_assets(wrapper['findings'])

    def _jenkins_assets(self, records: List[Any]) -> List[AssetData]:
        """One asset per Jenkins job and one finding per detector; build numbers are ignored.

        Raw and RawV2 are only compared with Redacted, which is sent as received unless it is empty
        or contains them (see _safe_redacted_value). SecretParts values are never read.

        Import with import_type = merge (set in the INI; --import-type is ignored). Merge leaves
        jobs absent from a scan untouched, so a scan that skipped build logs it could not fetch
        (TruffleHog only logs those errors) cannot close real findings. The cost: a job cleaned
        of every secret is absent too, so its findings close only through the organisation's
        lifecycle rule for findings not seen in N days, or by hand.
        """
        assets: Dict[str, AssetData] = {}
        findings: Dict[Tuple[str, str], Dict[str, Any]] = {}
        skipped = 0
        for record in records:
            jenkins = self._jenkins_metadata(record)
            job = self._jenkins_job(jenkins.get('link')) if jenkins else None
            detector = record.get('DetectorName') if job else None
            if not isinstance(detector, str) or not detector:
                skipped += 1
                continue
            job_url, names = job
            project = jenkins.get('project_name')
            job_name = project if isinstance(project, str) and project else names[-1]
            folder = names[0] if len(names) > 1 else None
            asset = assets.get(job_url)
            if asset is None:
                tags = get_tags_safely(self.tag_config) + [
                    {'key': 'scanner', 'value': 'trufflehog-v3'},
                    {'key': 'source', 'value': 'jenkins'},
                    {'key': 'jenkins-job', 'value': job_name},
                ]
                if folder:
                    tags.append({'key': 'jenkins-folder', 'value': folder})
                asset = assets[job_url] = AssetData(
                    asset_type='CODE',
                    attributes={'repository': job_url, 'scannerSource': job_url},
                    tags=tags,
                )
            # Each record can carry phoenix_tags {key: value}, added before import; they become asset tags.
            # The owning team is expected as {"org.opencontainers.image.new_authors_key": "<value>"};
            # --remap-oci-labels transforms that value exactly as for Grype image labels.
            extra_tags = record.get('phoenix_tags')
            transforms = getattr(self, 'label_value_transforms', None) or {}
            if isinstance(extra_tags, dict):
                for key, value in extra_tags.items():
                    if not value:
                        continue
                    value = str(value)
                    tag = {'key': str(key), 'value': transforms[key](value) if key in transforms else value}
                    if tag not in asset.tags:
                        asset.tags.append(tag)
            verified = record.get('Verified') is True
            finding = findings.get((job_url, detector))
            if finding is None:
                description = f'TruffleHog detector {detector} found a secret in the build logs of this Jenkins job.'
                if isinstance(record.get('DetectorDescription'), str):
                    description += ' ' + record['DetectorDescription']
                remedy = 'Rotate the exposed secret and remove it from Jenkins build logs.'
                extra = record.get('ExtraData')
                guide = extra.get('rotation_guide') if isinstance(extra, dict) else None
                if isinstance(guide, str) and guide.startswith(('https://', 'http://')):
                    remedy += f' Rotation guide: {guide}'
                specific = {'verified': verified}
                secret_fields = self._jenkins_secret_fields(record)
                if secret_fields:
                    specific['various'] = secret_fields
                finding = findings[(job_url, detector)] = {
                    # The parent folder tells apart jobs with generic names such as "deploy"
                    'name': f"{detector} secret in Jenkins job {'/'.join(names[-2:-1] + [job_name])}",
                    'description': description,
                    # One location per detector: under merge the backend treats findings at the
                    # same location with similar names or descriptions as one finding.
                    'location': f'{job_url}#{detector}',
                    'remedy': remedy,
                    'severity': self.normalize_severity('High' if verified else 'Medium'),
                    # Everything else is already in the name, location, description or tags
                    'details': {'specific': specific},
                }
                asset.findings.append(finding)
            elif verified and not finding['details']['specific']['verified']:
                finding['severity'] = self.normalize_severity('High')
                finding['details']['specific']['verified'] = True
        if not assets:
            raise TruffleHogJenkinsError('No valid Jenkins records in the file')
        logger.info(
            'Parsed TruffleHog Jenkins records: records=%d jobs=%d findings=%d skipped=%d',
            len(records), len(assets), len(findings), skipped,
        )
        return list(assets.values())
    
    def _parse_ndjson(self, file_path: str) -> List[AssetData]:
        """Parse TruffleHog NDJSON format (V2 or V3)"""
        logger.info(f"Parsing TruffleHog NDJSON: {file_path}")
        
        secrets = []
        jenkins_records = []
        is_v3 = False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                        continue
                    
                    if self._is_jenkins_wrapper(finding):  # the wrapper written on one line
                        try:
                            return self._parse_jenkins_wrapper(finding)
                        except (TruffleHogJenkinsError, TruffleHogEmptyScan):
                            raise
                        except Exception as e:
                            # As for the pretty-printed wrapper: never fall back to a placeholder asset
                            raise TruffleHogJenkinsError(
                                f'Jenkins wrapper could not be parsed: {type(e).__name__}'
                            ) from e
                    if self._jenkins_metadata(finding) is not None:
                        jenkins_records.append(finding)
                        continue

                    # Detect version and parse
                    if 'SourceMetadata' in finding:
                        is_v3 = True
                        vuln = self._parse_v3_ndjson_finding(finding)
                    else:
                        vuln = self._parse_v2_finding(finding)
                    
                    if vuln:
                        secrets.append(vuln)

            assets = []
            if jenkins_records:
                try:
                    assets = self._jenkins_assets(jenkins_records)
                except (TruffleHogJenkinsError, TruffleHogEmptyScan):
                    raise
                except Exception as e:
                    raise TruffleHogJenkinsError(
                        f'Jenkins records could not be parsed: {type(e).__name__}'
                    ) from e
            
            if not secrets:
                if assets:
                    return assets
                logger.info("No secrets found in TruffleHog NDJSON")
                return []
            
            # Create single asset for all secrets
            version = "V3" if is_v3 else "V2"
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': f"TruffleHog {version} Scan Results",
                    'scanner': f'TruffleHog {version}'
                },
                tags=tags + [{"key": "scanner", "value": f"trufflehog-{version.lower()}"}]
            )
            
            for vuln in secrets:
                asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(secrets)} secrets from TruffleHog {version} NDJSON")
            return assets
            
        except (TruffleHogJenkinsError, TruffleHogEmptyScan):
            raise
        except Exception as e:
            logger.error(f"Error parsing TruffleHog NDJSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_v3_json_array(self, file_path: str, findings: List[Dict]) -> List[AssetData]:
        """Parse TruffleHog v3 JSON array format"""
        logger.info(f"Parsing TruffleHog v3 JSON array: {file_path}")
        
        secrets = []
        
        try:
            for finding in findings:
                vuln = self._parse_v3_json_finding(finding)
                if vuln:
                    secrets.append(vuln)
            
            if not secrets:
                logger.info("No secrets found in TruffleHog v3 JSON")
                return []
            
            # Create single asset
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': 'TruffleHog v3 Scan Results',
                    'scanner': 'TruffleHog v3'
                },
                tags=tags + [{"key": "scanner", "value": "trufflehog3"}]
            )
            
            for vuln in secrets:
                asset.findings.append(vuln)
            
            assets = [self.ensure_asset_has_findings(asset)]
            
            logger.info(f"Parsed {len(secrets)} secrets from TruffleHog v3 JSON")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing TruffleHog v3 JSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_v3_ndjson_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse TruffleHog V3 NDJSON finding (OCSF-like structure)"""
        try:
            detector_name = finding.get('DetectorName', 'Unknown')
            verified = finding.get('Verified', False)
            redacted = self._safe_redacted_value(finding)
            
            # Get source info
            source_metadata = finding.get('SourceMetadata', {})
            source_data = source_metadata.get('Data', {})
            git_data = source_data.get('Git', {})
            
            file_path = git_data.get('file', 'unknown')
            commit = git_data.get('commit', 'unknown')
            repo = git_data.get('repository', 'unknown')
            
            # Severity based on verification
            severity = 'High' if verified else 'Medium'
            severity_normalized = self.normalize_severity(severity)

            details = {
                'detector': detector_name,
                'verified': verified,
                'commit': commit,
                'repository': repo,
            }
            if redacted:
                details['redacted_value'] = redacted[:50]

            return {
                'name': f"{detector_name}: Secret Found",
                'description': f"Secret detected in {file_path}",
                'remedy': "Rotate the exposed secret immediately",
                'severity': severity_normalized,
                'location': f"{repo}:{file_path}",
                'reference_ids': [commit[:8]] if commit and commit != 'unknown' else [],
                'details': details
            }
            
        except Exception as e:
            logger.debug(f"Error parsing TruffleHog V3 NDJSON finding: {e}")
            return None
    
    def _parse_v2_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse TruffleHog V2 NDJSON finding"""
        try:
            reason = finding.get('reason', 'Secret Found')
            branch = finding.get('branch', 'unknown')
            commit_hash = finding.get('commitHash', 'unknown')
            path = finding.get('path', 'unknown')
            strings_found = finding.get('stringsFound', [])
            
            return {
                'name': f"{reason}",
                'description': f"Secret detected in {path} (commit: {commit_hash[:8]})",
                'remedy': "Rotate the exposed secret immediately",
                'severity': self.normalize_severity('High'),
                'location': f"{branch}:{path}",
                'reference_ids': [commit_hash[:8]] if commit_hash and commit_hash != 'unknown' else [],
                'details': {
                    'reason': reason,
                    'commit': commit_hash,
                    'branch': branch,
                    'strings_found_count': len(strings_found) if strings_found else 0
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing TruffleHog V2 finding: {e}")
            return None
    
    def _parse_v3_json_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse TruffleHog v3 JSON array finding (rule-based)"""
        try:
            rule = finding.get('rule', {})
            rule_id = rule.get('id', 'Unknown')
            rule_message = rule.get('message', 'Secret Found')
            
            path = finding.get('path', 'unknown')
            start_line = finding.get('start_line', 0)
            end_line = finding.get('end_line', 0)
            
            return {
                'name': f"{rule_id}: {rule_message}",
                'description': f"Secret detected in {path} (lines {start_line}-{end_line})",
                'remedy': "Rotate the exposed secret immediately",
                'severity': self.normalize_severity('High'),
                'location': f"{path}:{start_line}",
                'reference_ids': [rule_id],
                'details': {
                    'rule_id': rule_id,
                    'rule_message': rule_message,
                    'start_line': start_line,
                    'end_line': end_line
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing TruffleHog v3 JSON finding: {e}")
            return None


# Export
__all__ = ['TruffleHogTranslator']
