#!/usr/bin/env python3
"""
BugCrowd Translator
===================

Translator for BugCrowd bug bounty platform CSV exports.
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


class BugCrowdCSVTranslator(ScannerTranslator):
    """Translator for BugCrowd CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'reference_number' in first_line and 'bounty_code' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing BugCrowd CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by target
            targets = {}
            for row in rows:
                target = row.get('target_name', 'Unknown Target')
                if target not in targets:
                    targets[target] = []
                
                title = row.get('title', row.get('caption', 'BugCrowd Finding'))
                severity = row.get('priority', row.get('severity', '3'))
                
                vuln_dict = VulnerabilityData(
                    name=title[:100],
                    description=row.get('description', title)[:500],
                    remedy=row.get('remediation_advice', 'See BugCrowd platform'),
                    severity=self._map_priority_to_severity(severity),
                    location=target,
                    reference_ids=[row.get('reference_number', row.get('bug_url', ''))]
                ).__dict__
                targets[target].append(vuln_dict)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for target_name, vulns in targets.items():
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'fqdn': target_name if '.' in target_name else f"{target_name}.local",
                        'scanner': 'BugCrowd'
                    },
                    findings=vulns if vulns else [VulnerabilityData(
                        name="NO_FINDINGS",
                        description="No vulnerabilities found",
                        remedy="No action required",
                        severity="0.0",
                        location=target_name
                    ).__dict__],
                    tags=tags + [{"key": "scanner", "value": "bugcrowd"}]
                )
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets from BugCrowd CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing BugCrowd CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_priority_to_severity(self, priority: str) -> str:
        """Map BugCrowd priority (1-5) to severity"""
        mapping = {'1': '3.0', '2': '5.0', '3': '7.0', '4': '8.5', '5': '10.0'}
        return mapping.get(str(priority).strip(), '5.0')


# Export
__all__ = ['BugCrowdCSVTranslator']

