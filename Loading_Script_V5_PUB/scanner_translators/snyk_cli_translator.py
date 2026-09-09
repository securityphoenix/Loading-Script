#!/usr/bin/env python3
"""
Snyk CLI Scanner Translator
============================

Translator for Snyk CLI output (different from Snyk API format).

Supported Formats:
- JSON with 'vulnerabilities' and 'packageManager'
- JSON with 'vulnerabilities' and 'dependencyCount'  
- Array of project scan results

Scanner Detection:
- Dict with 'vulnerabilities' AND 'packageManager'
- Dict with 'vulnerabilities' AND 'dependencyCount'
- Array with first item having 'vulnerabilities'

Asset Type: BUILD
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def get_tags_safely(tag_config):
    """Safely get tags from tag_config"""
    if not tag_config:
        return []
    if hasattr(tag_config, 'get_all_tags'):
        return tag_config.get_all_tags()
    return []


class SnykCLITranslator(ScannerTranslator):
    """Translator for Snyk CLI output (different from Snyk API)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Snyk CLI JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Snyk CLI format has vulnerabilities array and packageManager
            if isinstance(file_content, dict):
                if 'vulnerabilities' in file_content and 'packageManager' in file_content:
                    return True
                # Alternative: array of project results
                if 'vulnerabilities' in file_content and 'dependencyCount' in file_content:
                    return True
            elif isinstance(file_content, list) and len(file_content) > 0:
                # Array of scan results
                first = file_content[0]
                if isinstance(first, dict) and 'vulnerabilities' in first:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"SnykCLITranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Snyk CLI JSON file"""
        logger.info(f"Parsing Snyk CLI file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle array of projects or single project
            if isinstance(data, list):
                projects = data
            else:
                projects = [data]
            
            assets = []
            
            for project in projects:
                if not isinstance(project, dict):
                    continue
                
                project_name = project.get('projectName', project.get('displayTargetFile', 'unknown'))
                package_manager = project.get('packageManager', 'npm')
                vulnerabilities = project.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': project_name,
                        'origin': 'snyk-cli',
                        'packageManager': package_manager
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "snyk-cli"},
                        {"key": "package_manager", "value": package_manager}
                    ]
                )
                
                for vuln in vulnerabilities:
                    vuln_data = self._parse_vulnerability(vuln)
                    if vuln_data:
                        asset.findings.append(vuln_data)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} projects with {sum(len(a.findings) for a in assets)} vulnerabilities from Snyk CLI")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Snyk CLI file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """Parse a single Snyk CLI vulnerability"""
        try:
            vuln_id = vuln.get('id', 'UNKNOWN')
            title = vuln.get('title', vuln.get('name', 'Security Vulnerability'))
            package = vuln.get('packageName', vuln.get('name', 'unknown'))
            severity = vuln.get('severity', 'medium')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Get upgrade path
            upgrade_path = vuln.get('upgradePath', [])
            if upgrade_path:
                remedy = f"Upgrade to {upgrade_path[-1]}" if len(upgrade_path) > 0 else "See Snyk for remediation"
            else:
                remedy = "See Snyk for remediation"
            
            # Extract CVEs and CWEs from identifiers
            identifiers = vuln.get('identifiers', {})
            cves = identifiers.get('CVE', [])
            cwes = [f"CWE-{cwe}" for cwe in identifiers.get('CWE', [])]
            
            return {
                'name': f"{vuln_id}: {title}",
                'description': vuln.get('description', title),
                'remedy': remedy,
                'severity': severity_normalized,
                'location': f"{package}@{vuln.get('version', 'unknown')}",
                'reference_ids': [vuln_id] + cves,
                'cwes': cwes if cwes else None,
                'details': {
                    'is_upgradable': vuln.get('isUpgradable', False),
                    'is_patchable': vuln.get('isPatchable', False),
                    'exploit_maturity': vuln.get('exploitMaturity', ''),
                    'publication_time': vuln.get('publicationTime', ''),
                    'disclosure_time': vuln.get('disclosureTime', ''),
                    'cvss_score': vuln.get('cvssScore', 0)
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Snyk CLI vulnerability: {e}")
            return None


__all__ = ['SnykCLITranslator']

