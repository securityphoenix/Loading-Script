#!/usr/bin/env python3
"""
ORT (OSS Review Toolkit) Scanner Translator
============================================

Translator for OSS Review Toolkit (ORT) JSON reports.

Supported Formats:
- JSON with 'packages', 'scan_results', or 'issues' keys

Scanner Detection:
- JSON dict with 'packages', 'scan_results', or 'issues' keys

Asset Type: BUILD

About ORT:
The OSS Review Toolkit (ORT) is a suite of tools to assist with reviewing
Open Source Software dependencies.
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


class ORTTranslator(ScannerTranslator):
    """Translator for OSS Review Toolkit (ORT) JSON reports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is an ORT report"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # ORT reports have specific keys
            if isinstance(data, dict):
                has_packages = 'packages' in data
                has_scan_results = 'scan_results' in data
                has_issues = 'issues' in data
                return has_packages or has_scan_results or has_issues
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse ORT JSON report"""
        logger.info(f"Parsing ORT report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Parse packages
            packages = data.get('packages', [])
            issues = data.get('issues', [])
            scan_results = data.get('scan_results', [])
            
            # Group issues by package
            package_issues = {}
            for issue in issues:
                pkg_id = issue.get('pkg', 0)
                if pkg_id not in package_issues:
                    package_issues[pkg_id] = []
                
                severity = issue.get('severity', 'ERROR')
                message = issue.get('message', 'ORT Issue')
                
                vuln_dict = {
                    'name': f"ORT-{issue.get('type', 'ISSUE')}",
                    'description': message[:500],
                    'remedy': issue.get('how_to_fix', 'See ORT documentation'),
                    'severity': self._map_ort_severity(severity),
                    'location': issue.get('source', 'ORT Scanner'),
                    'reference_ids': []
                }
                
                package_issues[pkg_id].append(vuln_dict)
            
            # Create assets from packages
            assets = []
            
            for idx, package in enumerate(packages):
                package_id = package.get('id', package.get('purl', f"package-{idx}"))
                
                # Get issues for this package
                pkg_issues = package_issues.get(idx, [])
                
                # Create asset
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': package.get('definition_file_path', 'ort_report'),
                        'origin': 'ort',
                        'packageName': package_id,
                        'purl': package.get('purl', package_id)
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "ort"},
                        {"key": "sbom-tool", "value": "ort"}
                    ]
                )
                
                # Add findings
                if pkg_issues:
                    for vuln_dict in pkg_issues:
                        vuln_obj = VulnerabilityData(**vuln_dict)
                        asset.findings.append(vuln_obj.__dict__)
                    
                    assets.append(self.ensure_asset_has_findings(asset))
            
            # If no packages, create a single asset with all issues
            if not packages and issues:
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'ort_analyzed_model',
                        'origin': 'ort',
                        'packageName': 'ORT-Report'
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "ort"}
                    ]
                )
                
                # Add all issues
                for vuln_dict in package_issues.get(0, []):
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                if asset.findings:
                    assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Created {len(assets)} assets from ORT report")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing ORT report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_ort_severity(self, severity: str) -> str:
        """Map ORT severity to Phoenix severity"""
        mapping = {
            'error': 'High',
            'warning': 'Medium',
            'hint': 'Low',
            'resolved': 'Info'
        }
        return mapping.get(severity.lower().strip(), 'Medium')


__all__ = ['ORTTranslator']

