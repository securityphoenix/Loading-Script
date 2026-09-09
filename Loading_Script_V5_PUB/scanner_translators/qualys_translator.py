#!/usr/bin/env python3
"""
Qualys Translator - Consolidated
==================================

Unified translator for all Qualys scanner formats:
- Qualys WebApp Scanner (XML: WAS_SCAN_REPORT, WAS_WEBAPP_REPORT)
- Qualys VM/VMDR (XML: ASSET_DATA_REPORT, SCAN with HOST/VULN)
- Qualys CSV exports (all variants with QID column)

Consolidates 4 translators→1:
- QualysWebAppTranslator (tier2_translators.py)
- QualysVMTranslator (round20_final_push.py)
- QualysCSVTranslator (round24_final_fixes.py)
- QualysXMLTranslator (xml_translators.py)
"""

import csv
import json
import logging
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class QualysTranslator(ScannerTranslator):
    """Unified translator for all Qualys scanner outputs (XML and CSV)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Qualys XML or CSV format"""
        file_lower = file_path.lower()
        
        # Handle XML formats
        if file_lower.endswith('.xml'):
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Check for Qualys-specific XML structures
                if root.tag in ['WAS_SCAN_REPORT', 'WAS_WEBAPP_REPORT', 'ASSET_DATA_REPORT']:
                    return True
                
                # Check for generic Qualys VM format (SCAN with HOST)
                if root.tag == 'SCAN' or root.find('.//HOST') is not None:
                    # Verify it's Qualys by checking for QID elements
                    if root.find('.//QID') is not None:
                        return True
                
                return False
            except Exception as e:
                logger.debug(f"QualysTranslator.can_handle XML failed: {e}")
                return False
        
        # Handle CSV format
        elif file_lower.endswith('.csv'):
            try:
                with open(file_path, 'r', encoding='utf-8-sig') as f:
                    first_line = f.readline().lower()
                    # Qualys CSV has QID column or Qualys-specific keywords
                    return any(keyword in first_line for keyword in 
                              ['qid', 'qualys', 'vulnerability', 'severity'])
            except Exception as e:
                logger.debug(f"QualysTranslator.can_handle CSV failed: {e}")
                return False
        
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Qualys file (auto-detects XML WebApp, XML VM, or CSV)"""
        file_lower = file_path.lower()
        
        if file_lower.endswith('.xml'):
            return self._parse_xml(file_path)
        elif file_lower.endswith('.csv'):
            return self._parse_csv(file_path)
        else:
            logger.warning(f"Unsupported Qualys file format: {file_path}")
            return []
    
    def _parse_xml(self, file_path: str) -> List[AssetData]:
        """Parse Qualys XML file (auto-detects WebApp vs VM format)"""
        logger.info(f"Parsing Qualys XML file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Detect format and parse accordingly
            if root.tag in ['WAS_SCAN_REPORT', 'WAS_WEBAPP_REPORT']:
                return self._parse_webapp_xml(root)
            elif root.tag == 'ASSET_DATA_REPORT':
                return self._parse_vm_xml_asset_report(root)
            else:
                # Generic VM format with HOST elements
                return self._parse_vm_xml_generic(root)
                
        except Exception as e:
            logger.error(f"Error parsing Qualys XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_webapp_xml(self, root: ET.Element) -> List[AssetData]:
        """Parse Qualys WebApp Scanner XML"""
        logger.info("Detected Qualys WebApp format")
        
        # Get web app name
        webapp_name = "Web Application"
        target = root.find('.//TARGET')
        if target is not None:
            scan_elem = target.find('.//SCAN')
            if scan_elem is not None and scan_elem.text:
                webapp_name = scan_elem.text.strip()
            # Alternative: URL
            url_elem = target.find('.//URL')
            if url_elem is not None and url_elem.text:
                webapp_name = url_elem.text.strip()
        
        # Parse vulnerabilities
        vulnerabilities = []
        vuln_list = root.find('.//VULNERABILITY_LIST')
        if vuln_list is not None:
            for vuln_elem in vuln_list.findall('.//VULNERABILITY'):
                vuln = self._parse_webapp_vulnerability(vuln_elem)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Create asset if vulnerabilities found
        if not vulnerabilities:
            logger.info("No vulnerabilities found in Qualys WebApp scan")
            return []
        
        tags = get_tags_safely(self.tag_config)
        
        asset = AssetData(
            asset_type='WEB',
            attributes={
                'name': webapp_name,
                'application': webapp_name,
                'scanner': 'Qualys WebApp Scanner'
            },
            tags=tags + [{"key": "scanner", "value": "qualys-webapp"}]
        )
        
        for vuln_dict in vulnerabilities:
            vuln_obj = VulnerabilityData(**vuln_dict)
            asset.findings.append(vuln_obj.__dict__)
        
        assets = [self.ensure_asset_has_findings(asset)]
        
        logger.info(f"Parsed 1 web application with {len(vulnerabilities)} vulnerabilities from Qualys WebApp")
        return assets
    
    def _parse_webapp_vulnerability(self, vuln_elem: ET.Element) -> Optional[Dict]:
        """Parse Qualys WebApp vulnerability"""
        try:
            # Get QID (Qualys ID)
            qid_elem = vuln_elem.find('.//QID')
            qid = qid_elem.text.strip() if qid_elem is not None and qid_elem.text else 'UNKNOWN'
            
            # Get vulnerability name/title
            name_elem = vuln_elem.find('.//NAME')
            title_elem = vuln_elem.find('.//TITLE')
            name = (name_elem.text.strip() if name_elem is not None and name_elem.text 
                   else title_elem.text.strip() if title_elem is not None and title_elem.text 
                   else qid)
            
            # Get URL where vulnerability was found
            url_elem = vuln_elem.find('.//URL')
            url = url_elem.text.strip() if url_elem is not None and url_elem.text else ''
            
            # Get severity (LEVEL1-5 or 1-5, where 5 is critical)
            severity = 'Medium'
            severity_elem = vuln_elem.find('.//SEVERITY')
            if severity_elem is not None and severity_elem.text:
                level = severity_elem.text.strip()
                severity = self._map_qualys_severity(level)
            
            # Get description/impact
            impact_elem = vuln_elem.find('.//IMPACT')
            impact = impact_elem.text.strip() if impact_elem is not None and impact_elem.text else ''
            
            description = name
            if impact:
                description += f"\n\n{impact}"
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get solution
            solution_elem = vuln_elem.find('.//SOLUTION')
            solution = solution_elem.text.strip() if solution_elem is not None and solution_elem.text else "See Qualys for remediation"
            if len(solution) > 500:
                solution = solution[:497] + "..."
            
            # Get CVE if available
            cve_elem = vuln_elem.find('.//CVE_ID_LIST/CVE_ID')
            reference_ids = [f"QID-{qid}"]
            if cve_elem is not None and cve_elem.text:
                cve = cve_elem.text.strip()
                reference_ids.append(cve)
            
            return {
                'name': f"QID-{qid}",
                'description': description,
                'remedy': solution,
                'severity': severity,
                'location': url if url else 'web-application',
                'reference_ids': reference_ids
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Qualys WebApp vulnerability: {e}")
            return None
    
    def _parse_vm_xml_asset_report(self, root: ET.Element) -> List[AssetData]:
        """Parse Qualys VM XML (ASSET_DATA_REPORT format)"""
        logger.info("Detected Qualys VM ASSET_DATA_REPORT format")
        
        hosts = {}
        
        # Try direct HOSTS elements first
        host_elems = root.findall('.//HOSTS') or root.findall('HOSTS')
        
        if not host_elems:
            # Try alternative structure: RISK_SCORE_PER_HOST/HOSTS
            host_elems = root.findall('.//RISK_SCORE_PER_HOST/HOSTS')
        
        for host_elem in host_elems:
            # Try different IP field names
            host_ip = (host_elem.findtext('IP_ADDRESS') or 
                      host_elem.findtext('IP') or 
                      host_elem.findtext('.//IP_ADDRESS') or 
                      host_elem.findtext('.//IP') or 
                      'unknown')
            
            if host_ip == 'unknown':
                continue
            
            if host_ip not in hosts:
                hosts[host_ip] = []
            
            # Parse vulnerabilities for this host
            vuln_elems = host_elem.findall('.//VULNERABILITY') or host_elem.findall('VULNERABILITY')
            for vuln_elem in vuln_elems:
                vuln = self._parse_vm_vulnerability(vuln_elem)
                if vuln:
                    hosts[host_ip].append(vuln)
        
        return self._create_vm_assets(hosts)
    
    def _parse_vm_xml_generic(self, root: ET.Element) -> List[AssetData]:
        """Parse generic Qualys VM XML (SCAN with HOST elements)"""
        logger.info("Detected Qualys VM generic format")
        
        hosts = {}
        
        # Find all HOST elements
        for host_elem in root.findall('.//HOST'):
            # Get IP address
            ip_elem = host_elem.find('IP')
            host_ip = ip_elem.text.strip() if ip_elem is not None and ip_elem.text else 'unknown'
            
            if host_ip == 'unknown':
                continue
            
            if host_ip not in hosts:
                hosts[host_ip] = []
            
            # Parse vulnerabilities
            for vuln_elem in host_elem.findall('.//VULN'):
                vuln = self._parse_vm_vulnerability(vuln_elem)
                if vuln:
                    hosts[host_ip].append(vuln)
        
        return self._create_vm_assets(hosts)
    
    def _parse_vm_vulnerability(self, vuln_elem: ET.Element) -> Optional[Dict]:
        """Parse a single Qualys VM vulnerability"""
        try:
            qid = vuln_elem.findtext('QID', 'UNKNOWN')
            title = vuln_elem.findtext('TITLE', vuln_elem.findtext('NAME', 'Security Finding'))
            severity = vuln_elem.findtext('SEVERITY', '3')
            
            # Map Qualys severity (1-5)
            severity_normalized = self._map_qualys_severity(severity)
            
            return {
                'name': f"QID-{qid}",
                'description': title,
                'remedy': "See Qualys for remediation guidance",
                'severity': severity_normalized,
                'location': qid,
                'reference_ids': [f"QID-{qid}"],
                'details': {
                    'qid': qid,
                    'severity_level': severity
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Qualys VM vulnerability: {e}")
            return None
    
    def _create_vm_assets(self, hosts: Dict[str, List[Dict]]) -> List[AssetData]:
        """Create AssetData objects for VM hosts"""
        assets = []
        tags = get_tags_safely(self.tag_config)
        
        for host_ip, vulns in hosts.items():
            if not vulns:
                # Add placeholder for hosts with no vulnerabilities
                vulns = [{
                    'name': 'NO_VULNERABILITIES_FOUND',
                    'description': f'No vulnerabilities found for host {host_ip}',
                    'remedy': 'No action required',
                    'severity': self.normalize_severity('Low'),
                    'location': host_ip,
                    'reference_ids': []
                }]
            
            asset = AssetData(
                asset_type='INFRA',
                attributes={
                    'name': host_ip,
                    'ip': host_ip,
                    'scanner': 'Qualys VM'
                },
                tags=tags + [{"key": "scanner", "value": "qualys-vm"}]
            )
            
            for vuln in vulns:
                asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} vulnerabilities from Qualys VM")
        return assets
    
    def _parse_csv(self, file_path: str) -> List[AssetData]:
        """Parse Qualys CSV file"""
        logger.info(f"Parsing Qualys CSV: {file_path}")
        
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
            
            logger.info(f"Parsed {len(rows)} rows from Qualys CSV")
            
            if not rows:
                return []
            
            # Group by host/IP
            hosts = {}
            
            for row in rows:
                # Try multiple column names for host
                host = (row.get('IP') or row.get('IP Address') or 
                       row.get('Host') or row.get('DNS') or row.get('FQDN') or 'unknown')
                
                if host == 'unknown':
                    continue
                
                if host not in hosts:
                    hosts[host] = []
                
                # Extract vulnerability
                qid = row.get('QID') or row.get('Vuln ID') or row.get('ID')
                title = row.get('Title') or row.get('Vulnerability') or row.get('Name')
                
                if qid or title:
                    severity_str = (row.get('Severity') or row.get('Level') or 
                                  row.get('Risk') or 'Medium')
                    
                    hosts[host].append({
                        'name': f"QID-{qid}" if qid else title,
                        'description': title or f"Qualys finding {qid}",
                        'remedy': row.get('Solution', 'See Qualys console'),
                        'severity': self.normalize_severity(str(severity_str)),
                        'location': host,
                        'reference_ids': [str(qid)] if qid else []
                    })
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host, vulns in hosts.items():
                if not vulns:
                    continue
                
                findings = []
                for v in vulns:
                    vuln_obj = VulnerabilityData(**v)
                    findings.append(vuln_obj.__dict__)
                
                asset = AssetData(
                    asset_type='INFRA',
                    attributes={
                        'name': host,
                        'ip': host if host.replace('.', '').isdigit() else None,
                        'fqdn': host if '.' in host and not host.replace('.', '').isdigit() else f"{host}.local"
                    },
                    tags=tags + [{"key": "scanner", "value": "qualys-csv"}]
                )
                asset.findings.extend(findings)
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Created {len(assets)} assets from Qualys CSV")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing Qualys CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_qualys_severity(self, level: str) -> str:
        """Map Qualys severity level to Phoenix severity"""
        level_str = str(level).strip().upper()
        
        # Numeric levels (1-5)
        severity_map = {
            '5': 'Critical',
            '4': 'High',
            '3': 'Medium',
            '2': 'Low',
            '1': 'Info',
            'LEVEL5': 'Critical',
            'LEVEL4': 'High',
            'LEVEL3': 'Medium',
            'LEVEL2': 'Low',
            'LEVEL1': 'Info',
            'URGENT': 'Critical',
            'CRITICAL': 'High',
            'SERIOUS': 'Medium',
            'MEDIUM': 'Low',
            'MINIMAL': 'Info'
        }
        
        return self.normalize_severity(severity_map.get(level_str, level_str))


# Export
__all__ = ['QualysTranslator']

