#!/usr/bin/env python3
"""
Contrast Security Translator
============================

Translator for Contrast Security CSV reports.

Supported Formats:
------------------
- **Contrast Security CSV** - IAST/DAST vulnerability report
  - Columns: Vulnerability Name, Vulnerability ID, Application Name, Category, Severity

Scanner Detection:
-----------------
- File extension: .csv
- Has columns: 'Vulnerability Name', 'Vulnerability ID', 'Application Name', 'Category'

Asset Type: WEB
Grouping: By Application Name
"""

import csv
import sys
import logging
from typing import Any, Dict, List, Optional

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class ContrastTranslator(ScannerTranslator):
    """
    Translator for Contrast Security CSV format
    
    Interactive Application Security Testing (IAST) findings.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect Contrast CSV format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is Contrast CSV format
        """
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                if headers:
                    # Check for Contrast-specific columns
                    contrast_cols = ['Vulnerability Name', 'Vulnerability ID', 'Application Name', 'Category']
                    matches = sum(1 for col in contrast_cols if col in headers)
                    if matches >= 3:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"ContrastTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse Contrast CSV file
        
        Args:
            file_path: Path to the Contrast Security CSV file
            
        Returns:
            List of AssetData objects with findings
        """
        logger.info(f"Parsing Contrast Security file: {file_path}")
        
        try:
            # Increase CSV field size limit for large fields
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
                logger.info("No rows in Contrast CSV")
                return []
            
            # Group by application
            applications = {}
            for row in rows:
                app_name = row.get('Application Name', 'unknown')
                if app_name not in applications:
                    applications[app_name] = []
                
                vuln = self._parse_row(row)
                if vuln:
                    applications[app_name].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for app_name, vulns in applications.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': app_name,
                        'fqdn': app_name if '.' in app_name else f"{app_name}.local",
                        'scanner': 'Contrast Security'
                    },
                    tags=tags + [{"key": "scanner", "value": "contrast"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} applications with {sum(len(a.findings) for a in assets)} vulnerabilities from Contrast")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Contrast file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_row(self, row: Dict) -> Optional[Dict]:
        """
        Parse a single Contrast CSV row
        
        Args:
            row: CSV row dictionary
            
        Returns:
            Vulnerability dictionary or None
        """
        try:
            vuln_name = row.get('Vulnerability Name', 'Unknown')
            vuln_id = row.get('Vulnerability ID', 'UNKNOWN')
            severity = row.get('Severity', 'Medium')
            category = row.get('Category', '')
            rule_name = row.get('Rule Name', '')
            
            # Location from request info
            request_uri = row.get('Request URI', '')
            request_method = row.get('Request Method', '')
            location = f"{request_method} {request_uri}" if request_method and request_uri else vuln_name
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Extract CWE if present
            cwes = []
            cwe_id = row.get('CWE ID', '')
            if cwe_id:
                cwes.append(f"CWE-{cwe_id}" if not cwe_id.startswith('CWE') else cwe_id)
            
            return {
                'name': f"{vuln_name}",
                'description': f"{category} - {rule_name}" if category and rule_name else vuln_name,
                'remedy': "See Contrast Security for remediation details",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [vuln_id],
                'cwes': cwes,
                'details': {
                    'category': category,
                    'rule_name': rule_name,
                    'status': row.get('Status', ''),
                    'language': row.get('Language', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Contrast row: {e}")
            return None

