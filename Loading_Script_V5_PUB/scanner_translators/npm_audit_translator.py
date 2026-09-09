#!/usr/bin/env python3
"""
npm audit Scanner Translator
==============================

Translator for npm audit vulnerability scanner (Node.js package manager).

Supported Formats:
- npm audit v7+ format (vulnerabilities + metadata)
- npm audit v6 format (advisories + actions)
- npm audit fix --dry-run format

Scanner Detection:
- v7+: 'vulnerabilities' dict AND 'metadata' dict
- v6: 'advisories' dict AND 'actions' array
- dry-run: 'actions' array with 'resolves' in first item

Asset Type: BUILD
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class NpmAuditTranslator(ScannerTranslator):
    """Translator for npm audit JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect npm audit JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # npm audit v7+ format has 'vulnerabilities' dict
            # npm audit v6 format has 'advisories' dict and 'actions' array
            if isinstance(file_content, dict):
                if file_content.get('bomFormat') == 'CycloneDX':
                    return False
                if 'vulnerabilities' in file_content and 'metadata' in file_content:
                    vulnerabilities = file_content.get('vulnerabilities')
                    if isinstance(vulnerabilities, dict):
                        return True
                if 'advisories' in file_content and 'actions' in file_content:
                    return True
                # npm audit fix --dry-run format
                if 'actions' in file_content and isinstance(file_content['actions'], list):
                    actions = file_content['actions']
                    if actions and isinstance(actions[0], dict) and 'resolves' in actions[0]:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"NpmAuditTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse npm audit JSON file"""
        logger.info(f"Parsing npm audit file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Determine format version
            if 'vulnerabilities' in data:
                assets = self._parse_v7_format(data)
            elif 'advisories' in data:
                assets = self._parse_v6_format(data)
            else:
                assets = []
            
            logger.info(f"Parsed {len(assets)} npm packages with {sum(len(a.findings) for a in assets)} vulnerabilities")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing npm audit: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_v7_format(self, data: Dict) -> List[AssetData]:
        """Parse npm audit v7+ format"""
        assets = []
        
        vulnerabilities = data.get('vulnerabilities', {})
        
        for package_name, vuln_info in vulnerabilities.items():
            # Get vulnerability details
            vuln_name = vuln_info.get('via', [])
            if not vuln_name:
                continue
            
            # Create asset
            asset_name = f"{package_name}@{vuln_info.get('range', 'unknown')}"
            
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': 'package.json',
                    'origin': 'npm-audit',
                    'component': package_name,
                    'version': vuln_info.get('range', 'unknown')
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "npm-audit"},
                    {"key": "package-manager", "value": "npm"}
                ]
            )
            
            # Add vulnerabilities
            for via in vuln_info.get('via', []):
                if isinstance(via, dict):
                    vuln_data = self._parse_vuln_v7(via, package_name)
                    if vuln_data:
                        vuln_obj = VulnerabilityData(**vuln_data)
                        asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_v6_format(self, data: Dict) -> List[AssetData]:
        """Parse npm audit v6 format"""
        assets = []
        
        advisories = data.get('advisories', {})
        
        for adv_id, advisory in advisories.items():
            module_name = advisory.get('module_name', 'unknown')
            
            # Create asset
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': 'package.json',
                    'origin': 'npm-audit',
                    'component': module_name
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "npm-audit"},
                    {"key": "package-manager", "value": "npm"}
                ]
            )
            
            # Parse vulnerability
            vuln_data = self._parse_vuln_v6(advisory, module_name)
            if vuln_data:
                vuln_obj = VulnerabilityData(**vuln_data)
                asset.findings.append(vuln_obj.__dict__)
                assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_vuln_v7(self, via: Dict, package: str) -> Optional[Dict]:
        """Parse npm audit v7 vulnerability"""
        try:
            vuln_id = via.get('source', '') or via.get('title', 'UNKNOWN')
            if not vuln_id:
                return None
            
            title = via.get('title', vuln_id)
            url = via.get('url', '')
            severity = self.normalize_severity(via.get('severity', 'medium'))
            
            description = title
            if url:
                description += f"\n{url}"
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            return {
                'name': str(vuln_id),
                'description': description,
                'remedy': "Update to a non-vulnerable version. Run: npm audit fix",
                'severity': severity,
                'location': package,
                'reference_ids': [str(vuln_id)]
            }
            
        except Exception as e:
            logger.debug(f"Error parsing npm audit v7 vulnerability: {e}")
            return None
    
    def _parse_vuln_v6(self, advisory: Dict, package: str) -> Optional[Dict]:
        """Parse npm audit v6 advisory"""
        try:
            vuln_id = advisory.get('cves', [''])[0] if advisory.get('cves') else str(advisory.get('id', 'UNKNOWN'))
            title = advisory.get('title', vuln_id)
            overview = advisory.get('overview', '')
            recommendation = advisory.get('recommendation', 'Update to a non-vulnerable version')
            severity = self.normalize_severity(advisory.get('severity', 'moderate'))
            
            description = f"{title}\n{overview}" if overview else title
            if len(description) > 500:
                description = description[:497] + "..."
            
            if len(recommendation) > 500:
                recommendation = recommendation[:497] + "..."
            
            # Get CWEs
            cwes = []
            if 'cwe' in advisory:
                cwes = [advisory['cwe']]
            
            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': recommendation,
                'severity': severity,
                'location': package,
                'reference_ids': [vuln_id]
            }
            
            if cwes:
                vuln_dict['cwes'] = cwes
            
            # Add CVSS if available
            if 'cvss' in advisory:
                vuln_dict['details'] = {'cvss_score': advisory['cvss'].get('score')}
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing npm audit v6 advisory: {e}")
            return None


__all__ = ['NpmAuditTranslator']

