#!/usr/bin/env python3
"""
DSOP Translator
===============

Translator for DSOP (DevSecOps Platform) Excel (XLSX) reports.
Requires openpyxl library for Excel file parsing.
"""

import logging
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class DSOPTranslator(ScannerTranslator):
    """Translator for DSOP XLSX (Excel) format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect DSOP XLSX format"""
        if not file_path.lower().endswith(('.xlsx', '.xls')):
            return False
        
        try:
            # Try to import openpyxl for Excel support
            import openpyxl
            return True
        except ImportError:
            logger.warning("openpyxl not installed - XLSX files cannot be parsed. Install with: pip install openpyxl")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse DSOP XLSX file"""
        logger.info(f"Parsing DSOP Excel file: {file_path}")
        
        try:
            import openpyxl
            
            # Don't use read_only mode - it doesn't work well with some XLSX files
            workbook = openpyxl.load_workbook(file_path)
            sheet = workbook.active
            
            # Convert to list of dicts
            headers = []
            rows = []
            found_headers = False
            
            for idx, row in enumerate(sheet.iter_rows(values_only=True)):
                # Skip classification/metadata rows (e.g., "UNCLASSIFIED//FOUO")
                if not found_headers:
                    # Look for actual column headers (skip metadata rows)
                    if row and any(cell for cell in row if cell and isinstance(cell, str) and len(str(cell)) > 2):
                        # Check if this looks like a header row (has multiple non-empty strings)
                        non_empty = [cell for cell in row if cell]
                        if len(non_empty) >= 3:
                            headers = [str(cell) if cell else f"Column{i}" for i, cell in enumerate(row)]
                            found_headers = True
                    continue
                else:
                    if any(row):  # Skip empty rows
                        row_dict = dict(zip(headers, row))
                        rows.append(row_dict)
            
            if not rows:
                logger.info("No data rows in DSOP Excel")
                return []
            
            # Group by asset (assuming there's a hostname/IP column)
            assets_dict = {}
            
            for row in rows:
                # Try common asset identification fields
                asset_key = (row.get('Hostname') or row.get('Host') or 
                            row.get('IP') or row.get('IP Address') or 
                            row.get('System') or row.get('Asset') or 
                            'DSOP-Scan')
                
                if asset_key not in assets_dict:
                    assets_dict[asset_key] = []
                
                vuln = self._parse_row(row)
                if vuln:
                    assets_dict[asset_key].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for asset_key, vulns in assets_dict.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='INFRA',
                    attributes={
                        'name': str(asset_key),
                        'scanner': 'DSOP'
                    },
                    findings=vulns,
                    tags=tags + [{"key": "scanner", "value": "dsop"}]
                )
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} findings from DSOP")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing DSOP Excel file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_row(self, row: Dict) -> Optional[Dict]:
        """Parse a single DSOP row"""
        try:
            # Try common vulnerability field names
            vuln_name = (row.get('Vulnerability') or row.get('Finding') or 
                        row.get('Issue') or row.get('Title') or 'DSOP Finding')
            
            severity = (row.get('Severity') or row.get('Risk') or 
                       row.get('Impact') or 'Medium')
            
            description = (row.get('Description') or row.get('Details') or 
                          str(vuln_name))
            
            # Skip if no meaningful data
            if not vuln_name or vuln_name == 'None':
                return None
            
            severity_normalized = self.normalize_severity(str(severity))
            
            return {
                'name': str(vuln_name)[:200],
                'description': str(description)[:500],
                'remedy': row.get('Remediation', row.get('Fix', 'See DSOP report for remediation')),
                'severity': severity_normalized,
                'location': row.get('Location', row.get('Path', 'N/A')),
                'reference_ids': [row.get('CVE', row.get('ID', f"DSOP-{str(hash(str(vuln_name)))[:8]}"))]
            }
            
        except Exception as e:
            logger.debug(f"Error parsing DSOP row: {e}")
            return None


# Export
__all__ = ['DSOPTranslator']

