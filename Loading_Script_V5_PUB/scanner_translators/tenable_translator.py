#!/usr/bin/env python3
"""
Tenable Translator - Consolidated
==================================

Unified translator for all Tenable scanner CSV formats:
- Tenable Nessus (standard CSV format)
- Tenable PCI (PCI compliance-specific CSV format)

Consolidates 2 translators→1:
- TenableNessusTranslator (tier1_additional_translators.py)
- TenablePCITranslator (tenable_pci_translator.py)
"""

import csv
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class TenableTranslator(ScannerTranslator):
    """Unified translator for all Tenable Nessus CSV outputs (standard + PCI)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Tenable CSV format (both standard and PCI)"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                
                # Check for PCI-specific indicators first
                pci_indicators = ['pci severity', 'pci-']
                has_pci = any(indicator in first_line for indicator in pci_indicators)
                
                # Reset and check headers
                f.seek(0)
                reader = csv.DictReader(f)
                headers = set(reader.fieldnames or [])
                
                # Tenable-specific headers (multiple variants)
                variant1 = {'Plugin ID', 'CVE', 'Risk', 'Host', 'Name'}
                variant2 = {'Plugin', 'Severity', 'IP Address', 'Plugin Name'}
                variant3 = {'Plugin', 'Plugin Name', 'Family', 'Severity'}
                
                optional_headers = {'CVSS', 'Synopsis', 'Description', 'Solution', 'Plugin Output'}
                
                # Check if any variant matches
                if (variant1.issubset(headers) or 
                    variant2.issubset(headers) or 
                    variant3.issubset(headers)):
                    # Check if at least some optional headers are present
                    if any(h in headers for h in optional_headers):
                        return True
                
                # Also check for PCI format
                if has_pci:
                    tenable_indicators = {'plugin', 'synopsis', 'cvss'}
                    has_tenable = any(indicator in first_line for indicator in tenable_indicators)
                    if has_tenable:
                        return True
                
                return False
        except Exception as e:
            logger.debug(f"TenableTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Tenable CSV file (auto-detects standard vs PCI format)"""
        try:
            # Detect format by checking headers
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = set(reader.fieldnames or [])
                
                # Check if PCI format (has PCI Severity column)
                if 'PCI Severity' in headers:
                    logger.info(f"Detected Tenable PCI format: {file_path}")
                    return self._parse_pci_format(file_path)
                else:
                    logger.info(f"Detected Tenable Nessus format: {file_path}")
                    return self._parse_nessus_format(file_path)
        except Exception as e:
            logger.error(f"Error parsing Tenable CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_nessus_format(self, file_path: str) -> List[AssetData]:
        """Parse standard Tenable Nessus CSV format"""
        assets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                
                # Group vulnerabilities by host
                hosts_data = {}
                
                for row in reader:
                    # Skip informational rows (support both 'Risk' and 'Severity')
                    risk = row.get('Risk', row.get('Severity', '')).strip()
                    if not risk or risk.lower() in ['none', 'info', 'informational']:
                        continue
                    
                    # Get host identifier (support multiple header variants)
                    host = row.get('Host', row.get('DNS Name', '')).strip()
                    ip = row.get('IP Address', row.get('IP', '')).strip()
                    fqdn = row.get('FQDN', row.get('DNS Name', '')).strip()
                    
                    # Use best available identifier
                    host_key = host or ip or fqdn or 'unknown'
                    
                    if host_key not in hosts_data:
                        hosts_data[host_key] = {
                            'host': host,
                            'ip': ip,
                            'fqdn': fqdn,
                            'os': row.get('OS', row.get('Operating System', '')).strip(),
                            'vulnerabilities': []
                        }
                    
                    # Parse vulnerability
                    vuln = self._parse_nessus_vulnerability(row)
                    if vuln:
                        hosts_data[host_key]['vulnerabilities'].append(vuln)
                
                # Convert to asset format
                tags = get_tags_safely(self.tag_config)
                
                for host_key, host_data in hosts_data.items():
                    if not host_data['vulnerabilities']:
                        continue
                    
                    # Create asset attributes
                    attributes = {
                        'name': host_data['host'] or host_data['ip'] or host_data['fqdn'] or host_key
                    }
                    if host_data['ip']:
                        attributes['IP'] = host_data['ip']
                    if host_data['fqdn']:
                        attributes['FQDN'] = host_data['fqdn']
                    if host_data['host']:
                        attributes['hostname'] = host_data['host']
                    if host_data['os']:
                        attributes['OS'] = host_data['os']
                    
                    # Create AssetData object
                    asset = AssetData(
                        asset_type='INFRA',
                        attributes=attributes,
                        tags=tags + [{"key": "scanner", "value": "tenable-nessus"}]
                    )
                    
                    # Add findings
                    for v_dict in host_data['vulnerabilities']:
                        # Separate extra fields into details dict
                        details = {}
                        if 'cvss_score' in v_dict:
                            details['cvss_score'] = v_dict.pop('cvss_score')
                        if 'cvss3_score' in v_dict:
                            details['cvss3_score'] = v_dict.pop('cvss3_score')
                        if 'issue_type' in v_dict:
                            details['issue_type'] = v_dict.pop('issue_type')
                        
                        # Add details if present
                        if details:
                            v_dict['details'] = details
                        
                        vuln = VulnerabilityData(**v_dict)
                        asset.findings.append(vuln.__dict__)
                    
                    assets.append(self.ensure_asset_has_findings(asset))
                
            logger.info(f"Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities from Tenable Nessus")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Tenable Nessus CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_nessus_vulnerability(self, row: Dict) -> Optional[Dict]:
        """Parse a single vulnerability from Nessus CSV row"""
        try:
            # Get vulnerability ID (support multiple header variants)
            plugin_id = row.get('Plugin ID', row.get('Plugin', '')).strip()
            cve = row.get('CVE', '').strip()
            name = row.get('Name', row.get('Plugin Name', '')).strip()
            
            if not name:
                return None
            
            # Use CVE if available, otherwise Plugin ID
            vuln_id = cve if cve and cve != 'N/A' else f"Plugin-{plugin_id}"
            
            # Get severity (support both 'Risk' and 'Severity')
            risk = row.get('Risk', row.get('Severity', 'Unknown')).strip()
            severity = self._map_risk_to_severity(risk)
            
            # Get description
            synopsis = row.get('Synopsis', '').strip()
            description = row.get('Description', '').strip()
            full_description = f"{synopsis}\n\n{description}".strip() if synopsis and description else (description or synopsis or name)
            
            # Truncate description
            if len(full_description) > 500:
                full_description = full_description[:497] + "..."
            
            # Get solution
            solution = row.get('Solution', '').strip() or "See scanner output for remediation"
            if len(solution) > 500:
                solution = solution[:497] + "..."
            
            # Get location (port + protocol)
            port = row.get('Port', '').strip()
            protocol = row.get('Protocol', '').strip()
            location = f"{protocol}/{port}" if protocol and port else (port or 'general')
            
            # Create vulnerability
            vuln_dict = {
                'name': vuln_id,
                'description': full_description,
                'remedy': solution,
                'severity': severity,
                'location': location,
                'reference_ids': [vuln_id] if vuln_id else []
            }
            
            # Add optional CVSS scores
            cvss = row.get('CVSS', row.get('CVSS v2.0 Base Score', '')).strip()
            cvss3 = row.get('CVSS v3.0 Base Score', '').strip()
            
            if cvss:
                vuln_dict['cvss_score'] = cvss
            if cvss3:
                vuln_dict['cvss3_score'] = cvss3
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing Nessus vulnerability: {e}")
            return None
    
    def _parse_pci_format(self, file_path: str) -> List[AssetData]:
        """Parse Tenable PCI compliance CSV format"""
        logger.info(f"Parsing Tenable PCI format: {file_path}")
        
        assets_map = {}
        tags = get_tags_safely(self.tag_config)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # Extract asset information
                    ip_address = row.get('IP Address', '').strip()
                    hostname = row.get('DNS Name', '').strip()
                    mac_address = row.get('MAC Address', '').strip()
                    
                    # Create asset key
                    asset_key = ip_address or hostname or mac_address or 'unknown-host'
                    
                    if asset_key not in assets_map:
                        # Create new asset
                        attributes = {}
                        if ip_address:
                            attributes['ip'] = ip_address
                        if hostname:
                            attributes['hostname'] = hostname
                            attributes['fqdn'] = hostname
                        if mac_address:
                            attributes['macAddress'] = mac_address
                        
                        # Ensure required fields
                        if not attributes.get('ip') and not attributes.get('hostname'):
                            attributes['hostname'] = f"tenable-pci-host-{asset_key}"
                        
                        asset = AssetData(
                            asset_type="INFRA",
                            attributes=attributes,
                            tags=tags + [
                                {"key": "scanner", "value": "tenable-pci"},
                                {"key": "scan-type", "value": "pci-compliance"}
                            ]
                        )
                        assets_map[asset_key] = asset
                    
                    # Extract vulnerability information
                    plugin_id = row.get('Plugin', '').strip()
                    plugin_name = row.get('Plugin Name', '').strip()
                    severity = row.get('Severity', '').strip()
                    pci_severity = row.get('PCI Severity', '').strip()
                    
                    # Skip if no essential vulnerability data
                    if not plugin_id or not plugin_name:
                        continue
                    
                    # Use PCI severity if available, otherwise use regular severity
                    risk_level = pci_severity if pci_severity and pci_severity.lower() not in ['pass', ''] else severity
                    
                    # Skip informational findings unless they're PCI failures
                    if (risk_level.lower() in ['none', 'info', 'pass'] and 
                        pci_severity.lower() != 'fail'):
                        continue
                    
                    # Handle duplicate Description columns - use the first non-empty one
                    description = ''
                    if 'Description' in row:
                        # Get all Description columns (there might be multiple)
                        descriptions = []
                        for key, value in row.items():
                            if key == 'Description' and value and value.strip():
                                descriptions.append(value.strip())
                        
                        # Use the first non-empty description
                        description = descriptions[0] if descriptions else row.get('Synopsis', '')
                    else:
                        description = row.get('Synopsis', '')
                    
                    vulnerability = VulnerabilityData(
                        name=f"Plugin-{plugin_id}: {plugin_name}",
                        description=description,
                        remedy=row.get('Solution', 'No solution provided'),
                        severity=self._normalize_pci_severity(risk_level, pci_severity),
                        location=f"{ip_address}:{row.get('Port', '')}",
                        reference_ids=self._extract_cves(row.get('CVE', '')),
                        published_date_time=self._convert_date_to_iso8601(row.get('Plugin Publication Date', '')),
                        details={
                            'plugin_id': plugin_id,
                            'plugin_family': row.get('Family', ''),
                            'port': row.get('Port', ''),
                            'protocol': row.get('Protocol', ''),
                            'pci_severity': pci_severity,
                            'severity': severity,
                            'cvss_v2_base_score': row.get('CVSS V2 Base Score', ''),
                            'cvss_v3_base_score': row.get('CVSS V3 Base Score', ''),
                            'cvss_v2_vector': row.get('CVSS V2 Vector', ''),
                            'cvss_v3_vector': row.get('CVSS V3 Vector', ''),
                            'exploit_available': row.get('Exploit?', ''),
                            'first_discovered': self._convert_date_to_iso8601(row.get('First Discovered', '')),
                            'last_observed': self._convert_date_to_iso8601(row.get('Last Observed', '')),
                            'vuln_publication_date': self._convert_date_to_iso8601(row.get('Vuln Publication Date', '')),
                            'patch_publication_date': self._convert_date_to_iso8601(row.get('Patch Publication Date', '')),
                            'plugin_modification_date': self._convert_date_to_iso8601(row.get('Plugin Modification Date', '')),
                            'risk_factor': row.get('Risk Factor', ''),
                            'vpr_score': row.get('Vulnerability Priority Rating', ''),
                            'synopsis': row.get('Synopsis', '')
                        }
                    )
                    
                    assets_map[asset_key].findings.append(vulnerability.__dict__)
            
            # Ensure all assets have findings if create_empty_assets is enabled
            assets = [self.ensure_asset_has_findings(asset) for asset in assets_map.values()]
            logger.info(f"Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities from Tenable PCI")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Tenable PCI CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_risk_to_severity(self, risk: str) -> str:
        """Map Tenable risk level to numeric severity"""
        risk_lower = risk.lower()
        
        severity_map = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'none': '0.0',
            'info': '0.0',
            'informational': '0.0'
        }
        
        return severity_map.get(risk_lower, '5.0')  # Default to medium
    
    def _normalize_pci_severity(self, severity: str, pci_severity: str) -> str:
        """Normalize PCI severity to numeric scale"""
        # PCI failures are always high priority
        if pci_severity and pci_severity.lower() == 'fail':
            # Map based on underlying severity
            severity_map = {
                'critical': '10.0',
                'high': '8.0', 
                'medium': '5.0',
                'low': '3.0',
                'info': '1.0'
            }
            return severity_map.get(severity.lower(), '5.0')  # Default to medium for PCI failures
        
        # Standard severity mapping
        return self._map_risk_to_severity(severity)
    
    def _extract_cves(self, cve_string: str) -> List[str]:
        """Extract CVE IDs from comma-separated string"""
        if not cve_string or cve_string.strip() in ['N/A', '', 'NULL']:
            return []
        
        cves = []
        for cve in cve_string.split(','):
            cve = cve.strip()
            if cve and cve not in ['N/A', 'NULL']:
                cves.append(cve)
        
        return cves
    
    def _convert_date_to_iso8601(self, date_str: str) -> str:
        """Convert date string to ISO-8601 format, handling N/A and various formats"""
        if not date_str or date_str.strip() in ['N/A', '', 'NULL', 'null', 'None']:
            return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        
        # Clean the date string
        date_str = date_str.strip()
        
        # Common date formats to handle
        date_formats = [
            '%Y-%m-%dT%H:%M:%S',      # ISO format
            '%Y-%m-%d %H:%M:%S',      # Standard datetime
            '%Y-%m-%d',               # Date only
            '%m/%d/%Y %H:%M:%S',      # US format with time
            '%m/%d/%Y',               # US format
            '%d/%m/%Y %H:%M:%S',      # EU format with time
            '%d/%m/%Y',               # EU format
            '%b %d, %Y %H:%M:%S',     # Text month with time
            '%b %d, %Y',              # Text month
            '%Y/%m/%d',               # Alternative format
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                continue
        
        # If no format matches, log warning and return current time
        logger.warning(f"Could not parse date '{date_str}', using current time")
        return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')


# Export
__all__ = ['TenableTranslator']

