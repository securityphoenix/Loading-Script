#!/usr/bin/env python3
"""
TestSSL Translator
=================

Translator for TestSSL.sh CSV reports.

Supported Formats:
------------------
- **TestSSL CSV** - SSL/TLS vulnerability scanner output
  - Columns: fqdn/ip, port, severity, id, finding, cve, cwe

Scanner Detection:
-----------------
- File extension: .csv
- Has columns: 'fqdn/ip', 'severity', 'finding'

Asset Type: WEB
Grouping: By host:port
"""

import csv
import sys
import logging
from typing import Any, List

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData, VulnerabilityData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class TestSSLTranslator(ScannerTranslator):
    """
    Translator for TestSSL.sh CSV reports
    
    Tests SSL/TLS security configuration of hosts.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect TestSSL CSV format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is TestSSL CSV format
        """
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                # TestSSL has specific columns
                return 'fqdn/ip' in first_line and 'severity' in first_line and 'finding' in first_line
        except Exception as e:
            logger.debug(f"TestSSLTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse TestSSL CSV report
        
        Args:
            file_path: Path to the TestSSL CSV file
            
        Returns:
            List of AssetData objects with SSL/TLS findings
        """
        logger.info(f"Parsing TestSSL CSV: {file_path}")
        
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
            
            # Group by host (fqdn/ip)
            hosts = {}
            for row in rows:
                host = row.get('fqdn/ip', 'unknown')
                port = row.get('port', '443')
                host_key = f"{host}:{port}"
                
                if host_key not in hosts:
                    hosts[host_key] = {
                        'host': host,
                        'port': port,
                        'findings': []
                    }
                
                severity = row.get('severity', 'INFO')
                finding = row.get('finding', 'SSL/TLS Test Result')
                test_id = row.get('id', 'testssl')
                cve = row.get('cve', '')
                cwe = row.get('cwe', '')
                
                # Only include findings with severity (not INFO/OK unless it's a vulnerability)
                if severity not in ['INFO', 'OK', ''] or cve or cwe:
                    # Skip purely informational entries without issues
                    if severity in ['INFO', 'OK'] and not cve and not cwe and 'not offered' in finding.lower():
                        continue
                    
                    hosts[host_key]['findings'].append(VulnerabilityData(
                        name=f"TESTSSL-{test_id}",
                        description=f"{finding}",
                        remedy="Review SSL/TLS configuration and apply security best practices",
                        severity=self._map_testssl_severity(severity),
                        location=host_key,
                        reference_ids=[cve] if cve else [],
                        cwes=[cwe] if cwe else []
                    ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host_key, data in hosts.items():
                findings = data['findings']
                
                if not findings:
                    findings = [VulnerabilityData(
                        name="SSL_TLS_SECURE",
                        description="SSL/TLS configuration appears secure",
                        remedy="No action required",
                        severity="0.0",
                        location=host_key
                    )]
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'fqdn': data['host'] if '.' in data['host'] else f"{data['host']}.local",
                        'port': data['port'],
                        'scanner': 'TestSSL'
                    },
                    findings=findings,
                    tags=tags + [{"key": "scanner", "value": "testssl"}]
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from TestSSL")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing TestSSL CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_testssl_severity(self, severity: str) -> str:
        """
        Map TestSSL severity to Phoenix decimal
        
        Args:
            severity: TestSSL severity string
            
        Returns:
            Normalized severity decimal string
        """
        severity_lower = severity.lower().strip()
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'warn': '5.0',
            'info': '0.0',
            'ok': '0.0'
        }
        return mapping.get(severity_lower, '5.0')

