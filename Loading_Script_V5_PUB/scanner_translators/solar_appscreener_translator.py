#!/usr/bin/env python3
"""
Solar appScreener Translator
=============================

Translator for Solar appScreener CSV reports (DAST scanner).
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


class SolarAppScreenerCSVTranslator(ScannerTranslator):
    """Translator for Solar appScreener CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'vulnerability' in first_line and 'owasp' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Solar appScreener CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by application/URL
            apps = {}
            for row in rows:
                app = row.get('Application', row.get('URL', row.get('Target', 'Unknown')))
                if app not in apps:
                    apps[app] = []
                
                vuln = row.get('Vulnerability', row.get('Finding', 'Solar Finding'))
                risk = row.get('Risk', row.get('Severity', 'Medium'))
                
                vuln_dict = VulnerabilityData(
                    name=vuln[:100],
                    description=row.get('Description', vuln)[:500],
                    remedy=row.get('Recommendation', 'See Solar appScreener'),
                    severity=self._map_solar_severity(risk),
                    location=app,
                    reference_ids=[]
                ).__dict__
                apps[app].append(vuln_dict)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for app, vulns in apps.items():
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'fqdn': app if '.' in app else f"{app}.local",
                        'scanner': 'Solar appScreener'
                    },
                    findings=vulns,
                    tags=tags + [{"key": "scanner", "value": "solar-appscreener"}]
                )
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets from Solar appScreener CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Solar appScreener CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_solar_severity(self, severity: str) -> str:
        """Map Solar severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'info': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


# Export
__all__ = ['SolarAppScreenerCSVTranslator']

