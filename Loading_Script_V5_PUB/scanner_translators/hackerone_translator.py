#!/usr/bin/env python3
"""
HackerOne Translator
====================

Translator for HackerOne bug bounty platform CSV exports.
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


class HackerOneCSVTranslator(ScannerTranslator):
    """Translator for HackerOne (H1) Bug Bounty CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a HackerOne CSV"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                # HackerOne CSVs have specific columns
                return 'severity_rating' in first_line and 'reporter' in first_line and 'weakness' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse HackerOne CSV"""
        logger.info(f"Parsing HackerOne CSV: {file_path}")
        
        try:
            # Increase CSV field size limit
            maxInt = sys.maxsize
            while True:
                try:
                    csv.field_size_limit(maxInt)
                    break
                except OverflowError:
                    maxInt = int(maxInt/10)
            
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by structured_scope or reference
            scope_findings = {}
            for row in rows:
                scope = row.get('structured_scope', row.get('reference', 'HackerOne Program'))
                if not scope:
                    scope = 'HackerOne Program'
                
                if scope not in scope_findings:
                    scope_findings[scope] = []
                
                report_id = row.get('id', 'unknown')
                title = row.get('title', 'Security Finding')
                severity = row.get('severity_rating', row.get('severity_score', 'medium'))
                state = row.get('state', 'open')
                weakness = row.get('weakness', '')
                cve_ids = row.get('cve_ids', '')
                
                # Only include open/triaged reports or resolved with bounty
                if state in ['open', 'triaged', 'resolved'] or row.get('bounty'):
                    vuln_dict = VulnerabilityData(
                        name=f"H1-{report_id}",
                        description=f"{title} ({weakness})" if weakness else title,
                        remedy=f"State: {state}, Substate: {row.get('substate', 'N/A')}",
                        severity=self._map_h1_severity(severity),
                        location=row.get('reference_url', scope),
                        reference_ids=[cve_ids] if cve_ids else [f"H1-{report_id}"],
                        details={
                            'weakness': weakness,
                            'state': state,
                            'bounty': row.get('bounty', ''),
                            'reporter': row.get('reporter', '')
                        }
                    ).__dict__
                    scope_findings[scope].append(vuln_dict)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if scope_findings:
                for scope, findings in scope_findings.items():
                    asset = AssetData(
                        asset_type='WEB',
                        attributes={
                            'fqdn': scope if '.' in scope else f"{scope}.bugbounty",
                            'program': 'HackerOne',
                            'scanner': 'HackerOne'
                        },
                        findings=findings,
                        tags=tags + [{"key": "scanner", "value": "hackerone"}]
                    )
                    assets.append(self.ensure_asset_has_findings(asset))
            else:
                # No findings
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'fqdn': 'hackerone.program',
                        'program': 'HackerOne',
                        'scanner': 'HackerOne'
                    },
                    findings=[VulnerabilityData(
                        name="NO_REPORTS",
                        description="No bug bounty reports",
                        remedy="No action required",
                        severity="0.0",
                        location="HackerOne"
                    ).__dict__],
                    tags=tags + [{"key": "scanner", "value": "hackerone"}]
                )
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Created {len(assets)} assets from HackerOne")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing HackerOne CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_h1_severity(self, severity: str) -> str:
        """Map HackerOne severity to Phoenix decimal"""
        severity_str = str(severity).lower().strip()
        
        # Try numeric CVSS score first
        try:
            score = float(severity_str)
            return str(score)
        except:
            pass
        
        # Map text severity
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'none': '0.0'
        }
        return mapping.get(severity_str, '5.0')


# Export
__all__ = ['HackerOneCSVTranslator']

