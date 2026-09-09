#!/usr/bin/env python3
"""
Rapid7 CSV Translator
Handles Rapid7 vulnerability export CSV format
"""

import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class Rapid7CSVTranslator:
    """Translator for Rapid7 vulnerability export CSV format"""
    
    # Rapid7 CSV column names
    RAPID7_COLUMNS = [
        'Asset IP Address',
        'Service Port',
        'Vulnerability Test Result Code',
        'Vulnerability ID',
        'Vulnerability CVE IDs',
        'Vulnerability Severity Level',
        'Vulnerability Title'
    ]
    
    def __init__(self, scanner_config, tag_config):
        """Initialize Rapid7 CSV translator"""
        self.scanner_config = scanner_config
        self.tag_config = tag_config
        
        logger.info("🔧 Initialized Rapid7CSVTranslator")
    
    def can_handle(self, file_path: str) -> bool:
        """Check if this translator can handle the file"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Skip first line if it's "report"
                first_line = f.readline().strip()
                if first_line.lower().startswith('report'):
                    headers_line = f.readline()
                else:
                    headers_line = first_line
                
                # Check for Rapid7-specific headers
                headers_lower = headers_line.lower()
                has_asset_ip = 'asset ip address' in headers_lower
                has_vuln_title = 'vulnerability title' in headers_lower
                has_severity = 'vulnerability severity level' in headers_lower
                
                return has_asset_ip and has_vuln_title and has_severity
        except Exception as e:
            logger.debug(f"Cannot handle {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str, asset_name_override: Optional[str] = None) -> List:
        """
        Parse Rapid7 CSV file
        
        Args:
            file_path: Path to CSV file
            asset_name_override: Optional user-provided asset name (not typically used with Rapid7 since it has IPs)
            
        Returns:
            List of AssetData objects
        """
        logger.info(f"📄 Parsing Rapid7 CSV: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Skip "report" line if present
                first_line = f.readline().strip()
                if first_line.lower().startswith('report'):
                    # Next line is headers
                    pass
                else:
                    # First line is headers, seek back
                    f.seek(0)
                
                reader = csv.DictReader(f)
                rows = list(reader)
            
            logger.info(f"📋 Read {len(rows)} rows from Rapid7 CSV")
            
            # Group vulnerabilities by asset IP
            assets_dict = {}
            
            for row_num, row in enumerate(rows, start=2):
                try:
                    # Extract asset IP
                    asset_ip = row.get('Asset IP Address', '').strip()
                    if not asset_ip:
                        logger.debug(f"Row {row_num}: No asset IP, skipping")
                        continue
                    
                    # Extract vulnerability data
                    finding = self._extract_vulnerability(row)
                    if not finding:
                        logger.debug(f"Row {row_num}: No vulnerability data, skipping")
                        continue
                    
                    # Initialize asset if not seen before
                    if asset_ip not in assets_dict:
                        assets_dict[asset_ip] = {
                            'attributes': {
                                'ip': asset_ip,
                                'hostname': asset_name_override or f'rapid7-host-{asset_ip}'
                            },
                            'tags': [
                                {'key': 'source', 'value': 'rapid7'},
                                {'key': 'scanner', 'value': 'rapid7-vm'}
                            ],
                            'findings': []
                        }
                    
                    # Add finding to asset
                    assets_dict[asset_ip]['findings'].append(finding)
                    
                except Exception as e:
                    logger.warning(f"Row {row_num}: Error parsing row: {e}")
                    continue
            
            # Convert to AssetData objects
            from phoenix_import_refactored import AssetData
            assets = []
            
            for asset_ip, asset_data in assets_dict.items():
                asset = AssetData(
                    asset_type='INFRA',  # Rapid7 VM scans are always INFRA
                    attributes=asset_data['attributes'],
                    tags=asset_data['tags'],
                    findings=asset_data['findings']
                )
                assets.append(asset)
            
            logger.info(f"✅ Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
            return assets
            
        except Exception as e:
            logger.error(f"❌ Failed to parse Rapid7 CSV: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return []
    
    def _extract_vulnerability(self, row: Dict) -> Optional[Dict]:
        """Extract vulnerability data from Rapid7 CSV row"""
        
        vuln_title = row.get('Vulnerability Title', '').strip()
        if not vuln_title:
            return None
        
        # Extract port for location
        port = row.get('Service Port', '').strip()
        location = f"Port {port}" if port and port != '0' else ""
        
        # Required fields
        finding = {
            'name': vuln_title,
            'description': vuln_title,  # Rapid7 doesn't provide separate description
            'remedy': 'Please refer to Rapid7 console for detailed remediation steps.',
            'severity': self._parse_severity(row.get('Vulnerability Severity Level', '5'))
        }
        
        # Optional fields
        vuln_id = row.get('Vulnerability ID', '').strip()
        cve_ids = row.get('Vulnerability CVE IDs', '').strip()
        
        # Add reference IDs (CVEs)
        if cve_ids:
            # Can be comma-separated
            cves = [cve.strip() for cve in cve_ids.split(',') if cve.strip()]
            if cves:
                finding['referenceIds'] = cves
        
        # Add location if available
        if location:
            finding['location'] = location
        
        # Add details with Rapid7-specific fields
        details = {}
        if vuln_id:
            details['rapid7_vuln_id'] = vuln_id
        
        test_result = row.get('Vulnerability Test Result Code', '').strip()
        if test_result:
            details['test_result_code'] = test_result
        
        if port:
            details['port'] = port
        
        if details:
            finding['details'] = details
        
        # Add Rapid7-specific tags
        finding['tags'] = [
            {'key': 'scanner', 'value': 'rapid7'}
        ]
        
        if vuln_id:
            finding['tags'].append({'key': 'rapid7_id', 'value': vuln_id})
        
        return finding
    
    def _parse_severity(self, severity_str: str) -> str:
        """
        Parse Rapid7 severity level to Phoenix 1-10 scale
        
        Rapid7 typically uses 1-10 scale, but may also use text levels
        """
        try:
            severity = float(severity_str)
            # Ensure it's between 1 and 10
            severity = max(1.0, min(10.0, severity))
            return str(severity)
        except (ValueError, TypeError):
            # Handle text severity levels
            severity_lower = str(severity_str).lower()
            
            if 'critical' in severity_lower:
                return "10.0"
            elif 'severe' in severity_lower or 'high' in severity_lower:
                return "8.0"
            elif 'moderate' in severity_lower or 'medium' in severity_lower:
                return "5.0"
            elif 'low' in severity_lower:
                return "3.0"
            else:
                return "5.0"  # Default to medium


