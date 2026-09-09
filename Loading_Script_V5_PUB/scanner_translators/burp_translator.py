#!/usr/bin/env python3
"""
Burp Suite Translator - Consolidated
=====================================

Unified translator for all Burp Suite scanner formats:
- Burp Suite API (JSON format with scan_metrics and issue_events)
- Burp Suite XML (XML export with <issues><issue> structure)
- Burp Suite DAST HTML (HTML reports from Burp Scanner)

Consolidates 3 translators→1:
- BurpAPITranslator (tier3_quick_wins.py)
- BurpXMLTranslator (xml_translators.py)
- BurpSuiteDASTTranslator (round22_final_four.py)
"""

import json
import logging
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class BurpHTMLParser(HTMLParser):
    """Simple HTML parser for Burp DAST reports"""
    
    def __init__(self):
        super().__init__()
        self.in_issue = False
        self.current_data = []
        self.issues = []
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        # Detect issue blocks (common patterns in Burp HTML)
        if tag in ['div', 'tr'] and any('issue' in str(v).lower() or 'vulnerability' in str(v).lower() 
                                         for k, v in attrs):
            self.in_issue = True
    
    def handle_data(self, data):
        data = data.strip()
        if data and self.in_issue:
            self.current_data.append(data)
    
    def handle_endtag(self, tag):
        if self.in_issue and tag in ['div', 'tr']:
            if self.current_data:
                text = ' '.join(self.current_data)
                if len(text) > 10:
                    self.issues.append({'text': text, 'data': list(self.current_data)})
            self.current_data = []
            self.in_issue = False


class BurpTranslator(ScannerTranslator):
    """Unified translator for all Burp Suite outputs (JSON, XML, HTML)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Burp Suite JSON, XML, or HTML format"""
        file_lower = file_path.lower()
        
        # Handle JSON API format
        if file_lower.endswith('.json'):
            try:
                if file_content is None:
                    with open(file_path, 'r') as f:
                        file_content = json.load(f)
                
                # Burp API format has scan_metrics and issue_events
                if isinstance(file_content, dict):
                    if 'scan_metrics' in file_content and 'issue_events' in file_content:
                        return True
                
                return False
            except Exception as e:
                logger.debug(f"BurpTranslator.can_handle JSON failed: {e}")
                return False
        
        # Handle XML format
        elif file_lower.endswith('.xml'):
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Burp XML format has <issues> root or <issue> elements
                if root.tag.lower() == 'issues' or root.find('.//issue') is not None:
                    # Verify Burp-specific fields
                    issue = root.find('.//issue')
                    if issue is not None:
                        if (issue.find('name') is not None and 
                            issue.find('host') is not None):
                            return True
                
                return False
            except Exception as e:
                logger.debug(f"BurpTranslator.can_handle XML failed: {e}")
                return False
        
        # Handle HTML format
        elif file_lower.endswith(('.html', '.htm')):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5000)  # Read first 5KB
                    # Check for Burp-specific markers
                    if any(marker in content.lower() for marker in 
                          ['burp suite', 'portswigger', 'burp scanner']):
                        return True
                
                return False
            except Exception as e:
                logger.debug(f"BurpTranslator.can_handle HTML failed: {e}")
                return False
        
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Burp Suite file (auto-detects JSON, XML, or HTML)"""
        file_lower = file_path.lower()
        
        if file_lower.endswith('.json'):
            return self._parse_json(file_path)
        elif file_lower.endswith('.xml'):
            return self._parse_xml(file_path)
        elif file_lower.endswith(('.html', '.htm')):
            return self._parse_html(file_path)
        else:
            logger.warning(f"Unsupported Burp Suite file format: {file_path}")
            return []
    
    def _parse_json(self, file_path: str) -> List[AssetData]:
        """Parse Burp Suite JSON API format"""
        logger.info(f"Parsing Burp Suite JSON API: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            issue_events = data.get('issue_events', [])
            if not issue_events:
                logger.info("No issue events found in Burp API scan")
                return []
            
            # Group issues by origin
            issues_by_origin = {}
            
            for event in issue_events:
                if event.get('type') != 'issue_found':
                    continue
                
                issue = event.get('issue', {})
                origin = issue.get('origin', 'unknown')
                
                if origin not in issues_by_origin:
                    issues_by_origin[origin] = []
                
                vuln = self._parse_json_issue(issue)
                if vuln:
                    issues_by_origin[origin].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for origin, vulnerabilities in issues_by_origin.items():
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': origin,
                        'fqdn': origin.replace('https://', '').replace('http://', '').split('/')[0],
                        'scanner': 'Burp Suite API'
                    },
                    tags=tags + [{"key": "scanner", "value": "burp-api"}]
                )
                
                for vuln_dict in vulnerabilities:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} web applications with {sum(len(a.findings) for a in assets)} issues from Burp API")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Burp API JSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_json_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a Burp Suite JSON API issue"""
        try:
            name = issue.get('name', 'Unknown Issue')
            if not name:
                return None
            
            severity_str = issue.get('severity', 'medium')
            severity = self.normalize_severity(severity_str)
            
            confidence = issue.get('confidence', 'firm')
            
            description = issue.get('description', name)
            if len(description) > 500:
                description = description[:497] + "..."
            
            remedy = issue.get('remediation_background', "See Burp Suite for remediation details")
            if len(remedy) > 500:
                remedy = remedy[:497] + "..."
            
            path = issue.get('path', '/')
            
            return {
                'name': name,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': path,
                'reference_ids': [name],
                'details': {
                    'confidence': confidence,
                    'type_index': issue.get('type_index'),
                    'serial_number': issue.get('serial_number')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Burp JSON issue: {e}")
            return None
    
    def _parse_xml(self, file_path: str) -> List[AssetData]:
        """Parse Burp Suite XML export format"""
        logger.info(f"Parsing Burp Suite XML: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Group issues by host
            issues_by_host = {}
            
            for issue_elem in root.findall('.//issue'):
                host = issue_elem.findtext('host', 'unknown')
                
                if host not in issues_by_host:
                    issues_by_host[host] = []
                
                vuln = self._parse_xml_issue(issue_elem)
                if vuln:
                    issues_by_host[host].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host, vulnerabilities in issues_by_host.items():
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': host,
                        'fqdn': host,
                        'scanner': 'Burp Suite XML'
                    },
                    tags=tags + [{"key": "scanner", "value": "burp-xml"}]
                )
                
                for vuln_dict in vulnerabilities:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} issues from Burp XML")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Burp XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_xml_issue(self, issue_elem: ET.Element) -> Optional[Dict]:
        """Parse a Burp Suite XML issue"""
        try:
            name = issue_elem.findtext('name', 'Unknown Issue')
            if not name:
                return None
            
            host = issue_elem.findtext('host', '')
            path = issue_elem.findtext('path', '/')
            location = f"{host}{path}" if host else path
            
            severity_str = issue_elem.findtext('severity', 'Medium')
            severity = self.normalize_severity(severity_str)
            
            confidence = issue_elem.findtext('confidence', 'Certain')
            
            issue_background = issue_elem.findtext('issueBackground', '')
            issue_detail = issue_elem.findtext('issueDetail', '')
            description = f"{issue_background}\n\n{issue_detail}".strip() or name
            if len(description) > 500:
                description = description[:497] + "..."
            
            remediation_background = issue_elem.findtext('remediationBackground', '')
            remediation_detail = issue_elem.findtext('remediationDetail', '')
            remedy = f"{remediation_background}\n\n{remediation_detail}".strip() or "See Burp Suite for remediation"
            if len(remedy) > 500:
                remedy = remedy[:497] + "..."
            
            return {
                'name': name,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': location,
                'reference_ids': [name],
                'details': {
                    'confidence': confidence,
                    'vulnerability_classifications': issue_elem.findtext('vulnerabilityClassifications', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Burp XML issue: {e}")
            return None
    
    def _parse_html(self, file_path: str) -> List[AssetData]:
        """Parse Burp Suite DAST HTML format"""
        logger.info(f"Parsing Burp Suite DAST HTML: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                html_content = f.read()
            
            # Use simple HTML parser
            parser = BurpHTMLParser()
            parser.feed(html_content)
            
            tags = get_tags_safely(self.tag_config)
            
            if not parser.issues:
                logger.info("No issues found in Burp HTML (basic parsing)")
                # Create placeholder asset
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': 'Burp Suite DAST Scan',
                        'fqdn': 'burp-scan.local',
                        'scanner': 'Burp Suite DAST'
                    },
                    tags=tags + [{"key": "scanner", "value": "burp-dast"}]
                )
                asset.findings.append({
                    'name': 'NO_VULNERABILITIES_FOUND',
                    'description': 'Burp Suite DAST scan completed with no high-risk findings detected',
                    'remedy': 'No action required',
                    'severity': self.normalize_severity('Low'),
                    'location': 'Full scan',
                    'reference_ids': []
                })
                return [asset]
            
            # Create single asset with all findings
            asset = AssetData(
                asset_type='WEB',
                attributes={
                    'name': 'Burp Suite DAST Scan',
                    'fqdn': 'burp-scan.local',
                    'scanner': 'Burp Suite DAST'
                },
                tags=tags + [{"key": "scanner", "value": "burp-dast"}]
            )
            
            for idx, issue in enumerate(parser.issues[:50], 1):  # Limit to 50 findings
                asset.findings.append({
                    'name': f"Finding #{idx}",
                    'description': issue['text'][:500],
                    'remedy': 'See Burp Suite report for details',
                    'severity': self.normalize_severity('Medium'),
                    'location': 'Web Application',
                    'reference_ids': [f"BURP-{idx}"]
                })
            
            assets = [self.ensure_asset_has_findings(asset)]
            logger.info(f"Parsed {len(parser.issues)} findings from Burp DAST HTML")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Burp DAST HTML: {e}")
            import traceback
            traceback.print_exc()
            return []


# Export
__all__ = ['BurpTranslator']

