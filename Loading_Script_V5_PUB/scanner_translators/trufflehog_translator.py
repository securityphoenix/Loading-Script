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
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class TruffleHogTranslator(ScannerTranslator):
    """Unified translator for all TruffleHog outputs (V2, V3 NDJSON, v3 JSON)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect any TruffleHog format (V2/V3 NDJSON or v3 JSON)"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
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
                
                # Try v3 JSON array format
                f.seek(0)
                try:
                    content = json.load(f)
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
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if first_line.startswith('['):
                    # Likely JSON array (v3)
                    f.seek(0)
                    try:
                        content = json.load(f)
                        if isinstance(content, list):
                            return self._parse_v3_json_array(file_path, content)
                    except json.JSONDecodeError:
                        pass
            
            # Otherwise, parse as NDJSON (V2/V3)
            return self._parse_ndjson(file_path)
            
        except Exception as e:
            logger.error(f"Error parsing TruffleHog file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_ndjson(self, file_path: str) -> List[AssetData]:
        """Parse TruffleHog NDJSON format (V2 or V3)"""
        logger.info(f"Parsing TruffleHog NDJSON: {file_path}")
        
        secrets = []
        is_v3 = False
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                        continue
                    
                    # Detect version and parse
                    if 'SourceMetadata' in finding:
                        is_v3 = True
                        vuln = self._parse_v3_ndjson_finding(finding)
                    else:
                        vuln = self._parse_v2_finding(finding)
                    
                    if vuln:
                        secrets.append(vuln)
            
            if not secrets:
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
            
            assets = [self.ensure_asset_has_findings(asset)]
            
            logger.info(f"Parsed {len(secrets)} secrets from TruffleHog {version} NDJSON")
            return assets
            
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
            raw = finding.get('Redacted', finding.get('Raw', ''))
            
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
            
            return {
                'name': f"{detector_name}: Secret Found",
                'description': f"Secret detected in {file_path}",
                'remedy': "Rotate the exposed secret immediately",
                'severity': severity_normalized,
                'location': f"{repo}:{file_path}",
                'reference_ids': [commit[:8]] if commit and commit != 'unknown' else [],
                'details': {
                    'detector': detector_name,
                    'verified': verified,
                    'commit': commit,
                    'repository': repo,
                    'redacted_value': raw[:50] if raw else ''
                }
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

