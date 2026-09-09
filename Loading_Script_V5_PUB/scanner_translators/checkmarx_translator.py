#!/usr/bin/env python3
"""
Checkmarx Translator - Consolidated
====================================

Unified translator for all Checkmarx scanner formats:
- Checkmarx OSA (Open Source Analysis) - JSON format
- Checkmarx CxSAST (Static Application Security Testing) - XML format

Consolidates 2 translators→1:
- CheckmarxOSATranslator (tier3_quick_wins.py)
- CheckmarxXMLTranslator (xml_translators.py)
"""

import json
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class CheckmarxTranslator(ScannerTranslator):
    """Unified translator for all Checkmarx outputs (OSA JSON and CxSAST XML)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Checkmarx OSA JSON or CxSAST XML format"""
        file_lower = file_path.lower()
        
        # Handle JSON format (OSA)
        if file_lower.endswith('.json'):
            try:
                if file_content is None:
                    with open(file_path, 'r') as f:
                        file_content = json.load(f)
                
                # Checkmarx OSA is an array of arrays with vulnerability objects
                if isinstance(file_content, list) and len(file_content) > 0:
                    if isinstance(file_content[0], list) and len(file_content[0]) > 0:
                        first_vuln = file_content[0][0]
                        if isinstance(first_vuln, dict):
                            # Check for Checkmarx OSA-specific fields
                            if 'cveName' in first_vuln and 'libraryId' in first_vuln and 'sourceFileName' in first_vuln:
                                return True
                
                return False
            except Exception as e:
                logger.debug(f"CheckmarxTranslator.can_handle JSON failed: {e}")
                return False
        
        # Handle XML format (CxSAST)
        elif file_lower.endswith('.xml'):
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Check for Checkmarx CxSAST XML structure
                if 'CxXML' in root.tag or root.find('.//Query') is not None:
                    return True
                
                return False
            except Exception as e:
                logger.debug(f"CheckmarxTranslator.can_handle XML failed: {e}")
                return False
        
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Checkmarx file (auto-detects OSA JSON vs CxSAST XML)"""
        file_lower = file_path.lower()
        
        if file_lower.endswith('.json'):
            return self._parse_osa_json(file_path)
        elif file_lower.endswith('.xml'):
            return self._parse_cxsast_xml(file_path)
        else:
            logger.warning(f"Unsupported Checkmarx file format: {file_path}")
            return []
    
    def _parse_osa_json(self, file_path: str) -> List[AssetData]:
        """Parse Checkmarx OSA (Open Source Analysis) JSON format"""
        logger.info(f"Parsing Checkmarx OSA JSON: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                return []
            
            # Group by libraryId
            libs_by_id = {}
            
            for lib_group in data:
                if not isinstance(lib_group, list):
                    continue
                
                for vuln in lib_group:
                    lib_id = vuln.get('libraryId', 'unknown')
                    
                    if lib_id not in libs_by_id:
                        libs_by_id[lib_id] = {
                            'vulnerabilities': [],
                            'library_id': lib_id,
                            'source_file': vuln.get('sourceFileName', 'unknown')
                        }
                    
                    vuln_data = self._parse_osa_vulnerability(vuln)
                    if vuln_data:
                        libs_by_id[lib_id]['vulnerabilities'].append(vuln_data)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for lib_id, lib_info in libs_by_id.items():
                if not lib_info['vulnerabilities']:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': lib_info['source_file'] if lib_info['source_file'] != 'unknown' else lib_id[:16],
                        'library_id': lib_id,
                        'scanner': 'Checkmarx OSA',
                        'buildFile': lib_info['source_file'] or 'pom.xml'
                    },
                    tags=tags + [{"key": "scanner", "value": "checkmarx-osa"}]
                )
                
                for vuln_dict in lib_info['vulnerabilities']:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} libraries with {sum(len(a.findings) for a in assets)} vulnerabilities from Checkmarx OSA")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Checkmarx OSA JSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_osa_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """Parse Checkmarx OSA vulnerability"""
        try:
            cve_name = vuln.get('cveName', '')
            if not cve_name:
                vuln_id = vuln.get('id', 'UNKNOWN')
            else:
                vuln_id = cve_name
            
            # Get severity
            severity_info = vuln.get('severity', {})
            if isinstance(severity_info, dict):
                severity_str = severity_info.get('name', 'Medium')
            else:
                severity_str = str(severity_info) if severity_info else 'Medium'
            
            severity = self.normalize_severity(severity_str)
            
            # Get description
            description = vuln.get('description', f"Vulnerability {vuln_id}")
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get recommendations
            remedy = vuln.get('recommendations', "Update to a non-vulnerable version")
            if len(remedy) > 500:
                remedy = remedy[:497] + "..."
            
            # Get score
            score = vuln.get('score')
            
            # Get state
            state = vuln.get('state', {})
            state_name = state.get('name', 'TO_VERIFY') if isinstance(state, dict) else str(state)
            
            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': vuln.get('sourceFileName', 'library'),
                'reference_ids': [vuln_id, vuln.get('url', '')] if vuln.get('url') else [vuln_id]
            }
            
            # Add details
            details = {}
            if score:
                try:
                    details['cvss_score'] = float(score)
                except:
                    pass
            
            if state_name:
                details['state'] = state_name
            
            if vuln.get('publishDate'):
                details['publish_date'] = vuln['publishDate']
            
            if details:
                vuln_dict['details'] = details
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing Checkmarx OSA vulnerability: {e}")
            return None
    
    def _parse_cxsast_xml(self, file_path: str) -> List[AssetData]:
        """Parse Checkmarx CxSAST XML format"""
        logger.info(f"Parsing Checkmarx CxSAST XML: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            findings = []
            
            # Checkmarx format: <CxXMLResults><Query><Result>...</Result></Query></CxXMLResults>
            for query in root.findall('.//Query'):
                query_name = query.get('name', 'Unknown Query')
                query_severity = query.get('Severity', 'Medium')
                query_language = query.get('Language', '')
                query_group = query.get('group', '')
                
                for result in query.findall('Result'):
                    finding = {
                        'name': query_name,
                        'severity': query_severity,
                        'language': query_language,
                        'group': query_group,
                        'file_name': result.get('FileName', ''),
                        'line': result.get('Line', ''),
                        'column': result.get('Column', ''),
                        'false_positive': result.get('FalsePositive', 'False'),
                        'status': result.get('Status', 'New'),
                        'remark': result.get('Remark', ''),
                        'deep_link': result.get('DeepLink', ''),
                        'path': []
                    }
                    
                    # Extract path nodes (data flow)
                    path = result.find('Path')
                    if path is not None:
                        for path_node in path.findall('PathNode'):
                            node_info = {
                                'file_name': path_node.findtext('FileName', ''),
                                'line': path_node.findtext('Line', ''),
                                'column': path_node.findtext('Column', ''),
                                'node_id': path_node.findtext('NodeId', ''),
                                'name': path_node.findtext('Name', ''),
                                'type': path_node.findtext('Type', ''),
                                'length': path_node.findtext('Length', ''),
                                'snippet': path_node.findtext('Snippet/Line/Code', '')
                            }
                            finding['path'].append(node_info)
                    
                    findings.append(finding)
            
            if not findings:
                logger.info("No results found in Checkmarx CxSAST XML")
                return []
            
            # Group findings by file
            findings_by_file = {}
            for finding in findings:
                file_name = finding.get('file_name', 'unknown')
                if file_name not in findings_by_file:
                    findings_by_file[file_name] = []
                findings_by_file[file_name].append(finding)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for file_name, file_findings in findings_by_file.items():
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'name': file_name,
                        'scanner': 'Checkmarx CxSAST',
                        'language': file_findings[0].get('language', 'Unknown') if file_findings else 'Unknown'
                    },
                    tags=tags + [{"key": "scanner", "value": "checkmarx-sast"}]
                )
                
                # Add findings
                for finding in file_findings:
                    vuln = self._parse_cxsast_finding(finding)
                    if vuln:
                        asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} files with {sum(len(a.findings) for a in assets)} results from Checkmarx CxSAST")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Checkmarx CxSAST XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_cxsast_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse Checkmarx CxSAST finding"""
        try:
            name = finding.get('name', 'Unknown Query')
            severity = finding.get('severity', 'Medium')
            line = finding.get('line', '')
            file_name = finding.get('file_name', '')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Create location
            location = f"{file_name}:{line}" if line else file_name
            
            # Get description from path (data flow)
            path = finding.get('path', [])
            if path:
                desc = f"Data flow: {len(path)} nodes"
            else:
                desc = name
            
            return {
                'name': name,
                'description': desc,
                'remedy': "Review code and apply secure coding practices",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [finding.get('deep_link', '')] if finding.get('deep_link') else [],
                'details': {
                    'group': finding.get('group', ''),
                    'language': finding.get('language', ''),
                    'false_positive': finding.get('false_positive', 'False'),
                    'status': finding.get('status', 'New'),
                    'path_length': len(path)
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Checkmarx CxSAST finding: {e}")
            return None


# Export
__all__ = ['CheckmarxTranslator']

