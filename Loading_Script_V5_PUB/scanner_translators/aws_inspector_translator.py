#!/usr/bin/env python3
"""
AWS Inspector v2 Scanner Translator
====================================

Translator for AWS Inspector v2 findings format.

Supported Formats:
- JSON with 'findings' array
- JSON array of findings directly

Scanner Detection:
- Dict with 'findings' array containing 'findingArn', 'awsAccountId', or 'inspectorScore'
- Array with items containing 'findingArn' or 'inspectorScore'

Asset Types: CLOUD, CONTAINER (ECR), INFRA (EC2)
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class AWSInspectorTranslator(ScannerTranslator):
    """Translator for AWS Inspector v2 findings format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect AWS Inspector v2 format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Inspector v2 format has 'findings' array with specific structure
            if isinstance(file_content, dict):
                findings = file_content.get('findings', [])
                if findings and isinstance(findings, list):
                    first = findings[0] if findings else {}
                    # Check for Inspector-specific fields
                    if 'findingArn' in first or 'awsAccountId' in first or 'inspectorScore' in first:
                        return True
            elif isinstance(file_content, list) and len(file_content) > 0:
                # Array of findings
                first = file_content[0]
                if isinstance(first, dict) and ('findingArn' in first or 'inspectorScore' in first):
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"AWSInspectorTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse AWS Inspector v2 file"""
        logger.info(f"Parsing AWS Inspector v2 file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Get findings
            if isinstance(data, dict):
                findings = data.get('findings', [])
            elif isinstance(data, list):
                findings = data
            else:
                return []
            
            if not findings:
                logger.info("No findings in AWS Inspector v2 response")
                return []
            
            # Group by resource
            resources = {}
            for finding in findings:
                resource_id = finding.get('resourceId', finding.get('resources', [{}])[0].get('id', 'unknown'))
                if resource_id not in resources:
                    resources[resource_id] = []
                
                vuln_dict = self._parse_finding(finding)
                if vuln_dict:
                    resources[resource_id].append(vuln_dict)
            
            # Create assets
            assets = []
            for resource_id, vuln_dicts in resources.items():
                if not vuln_dicts:
                    continue
                
                # Determine asset type from resource ID (ARN)
                if resource_id.startswith('arn:aws:ecr'):
                    asset_type = 'CONTAINER'
                elif resource_id.startswith('arn:aws:ec2'):
                    asset_type = 'INFRA'
                else:
                    asset_type = 'CLOUD'
                
                asset = AssetData(
                    asset_type=asset_type,
                    attributes={
                        'cloud_provider': 'AWS',
                        'resource_id': resource_id
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "aws-inspector-v2"},
                        {"key": "cloud_provider", "value": "aws"}
                    ]
                )
                
                for vuln_dict in vuln_dicts:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} resources with {sum(len(a.findings) for a in assets)} findings from AWS Inspector v2")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing AWS Inspector v2 file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse a single Inspector v2 finding"""
        try:
            finding_arn = finding.get('findingArn', 'UNKNOWN')
            title = finding.get('title', finding.get('description', 'Security Finding'))
            severity = finding.get('severity', 'MEDIUM')
            score = finding.get('inspectorScore', 0)
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Get CVE/package info
            package_vuln = finding.get('packageVulnerabilityDetails', {})
            vuln_id = package_vuln.get('vulnerabilityId', finding.get('type', 'UNKNOWN'))
            
            # Remediation
            remediation = finding.get('remediation', {})
            remedy_text = remediation.get('recommendation', {}).get('text', 'See AWS Inspector for remediation')
            
            return {
                'name': f"{vuln_id}: {title[:100]}",
                'description': finding.get('description', title)[:500],
                'remedy': remedy_text[:500],
                'severity': severity_normalized,
                'location': finding.get('resourceId', 'unknown'),
                'reference_ids': [vuln_id],
                'details': {
                    'inspector_score': score,
                    'finding_arn': finding_arn,
                    'first_observed_at': finding.get('firstObservedAt', ''),
                    'last_observed_at': finding.get('lastObservedAt', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Inspector v2 finding: {e}")
            return None


__all__ = ['AWSInspectorTranslator']

