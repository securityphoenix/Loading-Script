#!/usr/bin/env python3
"""
Sysdig Scanner Translator
==========================

Translator for Sysdig container security scanner.

Supported Formats:
- CSV exports from Sysdig CLI
- CSV exports from Sysdig Reports

Scanner Detection:
- Checks for 'sysdig' in first line
- OR checks for 'vulnerability' AND 'package' in first line

Asset Type: CONTAINER
"""

import csv
import logging
import sys
from typing import Any, Dict, List

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def increase_csv_field_size_limit():
    """Increase CSV field size limit to handle large CSV files"""
    max_int = sys.maxsize
    while True:
        try:
            csv.field_size_limit(max_int)
            break
        except OverflowError:
            max_int = int(max_int / 10)


class SysdigTranslator(ScannerTranslator):
    """Translator for Sysdig CSV exports (both CLI and Reports)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Sysdig CSV file"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'sysdig' in first_line or ('vulnerability' in first_line and 'package' in first_line)
        except Exception as e:
            logger.debug(f"SysdigTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Sysdig CSV file"""
        logger.info(f"Parsing Sysdig CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by package/image
            packages = {}
            for row in rows:
                package = row.get('Package', row.get('package', row.get('Image', 'Unknown')))
                if package not in packages:
                    packages[package] = []
                
                vuln = row.get('Vulnerability', row.get('vulnerability', row.get('CVE', 'Sysdig Finding')))
                severity = row.get('Severity', row.get('severity', 'Medium'))
                
                vuln_data = VulnerabilityData(
                    name=vuln,
                    description=row.get('Description', vuln)[:500],
                    remedy=row.get('Fix', row.get('Remediation', 'Update package')),
                    severity=self._map_sysdig_severity(severity),
                    location=package,
                    reference_ids=[vuln] if vuln.startswith('CVE') else []
                )
                packages[package].append(vuln_data)
            
            # Create assets
            assets = []
            
            for package, vulns in packages.items():
                asset = AssetData(
                    asset_type='CONTAINER',
                    attributes={
                        'dockerfile': 'Dockerfile',
                        'origin': 'sysdig',
                        'repository': package
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "sysdig"}
                    ]
                )
                
                # Add vulnerability findings
                for vuln in vulns:
                    asset.findings.append(vuln.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities from Sysdig CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Sysdig CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_sysdig_severity(self, severity: str) -> str:
        """Map Sysdig severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'negligible': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


__all__ = ['SysdigTranslator']

