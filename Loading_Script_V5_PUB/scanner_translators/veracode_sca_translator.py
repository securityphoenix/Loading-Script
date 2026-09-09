#!/usr/bin/env python3
"""
Veracode SCA Scanner Translator
================================

Translator for Veracode SCA (Software Composition Analysis) CSV exports.

Supported Formats:
- CSV with 'Library' and 'CVE' columns

Scanner Detection:
- CSV file with 'library' and 'cve' in first line (case-insensitive)

Asset Type: BUILD
"""

import csv
import logging
import sys
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def increase_csv_field_size_limit():
    """Increase CSV field size limit to handle large fields"""
    maxInt = sys.maxsize
    while True:
        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt/10)


def get_tags_safely(tag_config):
    """Safely get tags from tag_config"""
    if not tag_config:
        return []
    if hasattr(tag_config, 'get_all_tags'):
        return tag_config.get_all_tags()
    return []


class VeracodeSCACSVTranslator(ScannerTranslator):
    """Translator for Veracode SCA CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Veracode SCA CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'library' in first_line and 'cve' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Veracode SCA CSV file"""
        logger.info(f"Parsing Veracode SCA CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by library
            libraries = {}
            for row in rows:
                library = row.get('Library', row.get('library', row.get('Component', 'Unknown')))
                if library not in libraries:
                    libraries[library] = []
                
                cve = row.get('CVE', row.get('cve', row.get('Vulnerability', 'VERACODE-FINDING')))
                cvss = row.get('CVSS', row.get('cvss', row.get('Score', '5.0')))
                description = row.get('Description', cve)
                remediation = row.get('Remediation', 'Update library to a non-vulnerable version')
                
                # Create vulnerability dict
                vuln_dict = {
                    'name': cve,
                    'description': description[:500] if description else cve,
                    'remedy': remediation[:500] if remediation else 'Update library',
                    'severity': self._normalize_severity_score(cvss),
                    'location': library,
                    'reference_ids': [cve] if cve.startswith('CVE') else []
                }
                
                libraries[library].append(vuln_dict)
            
            # Create assets
            assets = []
            
            for library, vulns in libraries.items():
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'veracode_sca',
                        'origin': 'veracode-sca',
                        'packageName': library,
                        'component': library
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "veracode-sca"}
                    ]
                )
                
                # Add findings
                for vuln_dict in vulns:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} libraries with {sum(len(a.findings) for a in assets)} vulnerabilities from Veracode SCA CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Veracode SCA CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _normalize_severity_score(self, severity: str) -> str:
        """Convert severity to Phoenix severity format"""
        try:
            # Try to parse as CVSS score
            score = float(severity)
            # Map CVSS to Phoenix severity
            if score >= 9.0:
                return 'Critical'
            elif score >= 7.0:
                return 'High'
            elif score >= 4.0:
                return 'Medium'
            elif score > 0.0:
                return 'Low'
            else:
                return 'Info'
        except:
            # Map string severity
            mapping = {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'moderate': 'Medium',
                'low': 'Low',
                'informational': 'Info',
                'info': 'Info'
            }
            return mapping.get(str(severity).lower().strip(), 'Medium')


__all__ = ['VeracodeSCACSVTranslator']

