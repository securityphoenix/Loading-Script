#!/usr/bin/env python3
"""
MicroFocus WebInspect Translator
=================================

Translator for MicroFocus WebInspect XML reports (DAST scanner).
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class MicroFocusWebInspectTranslator(ScannerTranslator):
    """Translator for MicroFocus WebInspect XML format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect MicroFocus WebInspect XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for WebInspect-specific structure: Sessions/Session/Issues
            if root.tag == 'Sessions':
                # Look for Session elements with Issues
                for session in root.findall('.//Session'):
                    if session.find('.//Issues') is not None:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"MicroFocusWebInspectTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse MicroFocus WebInspect XML file"""
        logger.info(f"Parsing MicroFocus WebInspect file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Group by URL/Host
            hosts = {}
            
            for session in root.findall('.//Session'):
                url = session.findtext('URL', 'unknown')
                host = session.findtext('Host', url)
                
                if host not in hosts:
                    hosts[host] = []
                
                # Parse issues for this session
                issues_elem = session.find('Issues')
                if issues_elem is not None:
                    for issue in issues_elem.findall('Issue'):
                        vuln = self._parse_issue(issue, url)
                        if vuln:
                            hosts[host].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host, vulns in hosts.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': host,
                        'fqdn': host if '.' in host else f"{host}.local",
                        'scanner': 'MicroFocus WebInspect'
                    },
                    findings=vulns,
                    tags=tags + [{"key": "scanner", "value": "microfocus-webinspect"}]
                )
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} issues from WebInspect")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing WebInspect file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: ET.Element, url: str) -> Optional[Dict]:
        """Parse a single WebInspect issue"""
        try:
            vuln_id = issue.findtext('VulnerabilityID', 'UNKNOWN')
            name = issue.findtext('Name', 'Security Issue')
            severity = issue.findtext('Severity', '0')
            check_type = issue.findtext('CheckTypeID', 'Unknown')
            
            # Get summary/description from ReportSection
            description = ''
            remedy = ''
            for section in issue.findall('.//ReportSection'):
                section_name = section.findtext('Name', '')
                section_text = section.findtext('SectionText', '')
                
                if section_name == 'Summary':
                    description = section_text
                elif section_name == 'Fix':
                    remedy = section_text
            
            # Clean CDATA and HTML tags from description
            if description:
                description = description.replace('<![CDATA[', '').replace(']]>', '')
                description = description[:500]  # Limit length
            
            if remedy:
                remedy = remedy.replace('<![CDATA[', '').replace(']]>', '')
                remedy = remedy[:500]
            
            # Map WebInspect severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)
            severity_map = {'0': 'Low', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical'}
            severity_normalized = self.normalize_severity(severity_map.get(severity, severity))
            
            # Get CWE/classifications
            cwes = []
            for classification in issue.findall('.//Classification'):
                if classification.get('kind') == 'CWE':
                    cwe_id = classification.get('identifier', '')
                    if cwe_id:
                        cwe_text = str(cwe_id).strip()
                        if cwe_text.upper().startswith('CWE-'):
                            cwes.append(cwe_text.upper())
                        else:
                            cwes.append(f"CWE-{cwe_text}")

            return {
                'name': f"{vuln_id}: {name[:100]}",
                'description': description if description else name,
                'remedy': remedy if remedy else "See WebInspect report for remediation",
                'severity': severity_normalized,
                'location': url,
                'reference_ids': [vuln_id],
                'cwes': cwes,
                'details': {
                    'check_type': check_type,
                    'engine_type': issue.findtext('EngineType', ''),
                    'issue_id': issue.get('id', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing WebInspect issue: {e}")
            return None


# Export
__all__ = ['MicroFocusWebInspectTranslator']

