#!/usr/bin/env python3
"""
Kiuwan Translator
=================

Translator for Kiuwan SAST CSV exports.
"""

import csv
import logging
import sys
from typing import Any, List

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

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


class KiuwanCSVTranslator(ScannerTranslator):
    """Translator for Kiuwan CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'cwe' in first_line and ('vulnerability' in first_line or 'defect' in first_line)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Kiuwan CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by file
            files = {}
            for row in rows:
                file_path_val = row.get('File', row.get('file', row.get('fileName', 'unknown')))
                if file_path_val not in files:
                    files[file_path_val] = []
                
                vuln_name = row.get('Vulnerability', row.get('vulnerability', row.get('Defect', 'Kiuwan Finding')))
                severity = row.get('Priority', row.get('priority', row.get('Severity', 'Medium')))
                cwe = row.get('CWE', row.get('cwe', ''))
                
                vuln_dict = VulnerabilityData(
                    name=vuln_name[:100],
                    description=row.get('Description', vuln_name)[:500],
                    remedy=row.get('Remediation', 'Fix vulnerability'),
                    severity=self._map_kiuwan_severity(severity),
                    location=file_path_val,
                    reference_ids=[],
                    cwes=[cwe] if cwe else []
                ).__dict__
                
                files[file_path_val].append(vuln_dict)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for file_path_val, vulns in files.items():
                asset = AssetData(
                    asset_type='CODE',
                    attributes={'filePath': file_path_val, 'scanner': 'Kiuwan'},
                    findings=vulns,
                    tags=tags + [{"key": "scanner", "value": "kiuwan"}]
                )
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets from Kiuwan CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Kiuwan CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_kiuwan_severity(self, severity: str) -> str:
        """Map Kiuwan severity to Phoenix decimal"""
        severity_lower = str(severity).lower().strip()
        mapping = {
            'very high': '10.0',
            'high': '8.0',
            'normal': '5.0',
            'low': '3.0',
            'info': '0.0'
        }
        return mapping.get(severity_lower, '5.0')


# Export
__all__ = ['KiuwanCSVTranslator']

