#!/usr/bin/env python3
"""
OWASP Dependency Check Translator
===================================

Translator for OWASP Dependency Check XML format.

Supported Formats:
- XML format with dependency-check namespace
- XML with dependencies and projectInfo elements

Scanner Detection:
- 'dependency-check' or 'DependencyCheck' in root tag
- OR has dependencies/projectInfo elements

Asset Type: BUILD
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class DependencyCheckTranslator(ScannerTranslator):
    """Translator for OWASP Dependency Check XML format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Dependency Check XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Dependency Check namespace and structure
            if 'dependency-check' in root.tag.lower() or \
               'DependencyCheck' in root.tag or \
               any('dependency-check' in str(ns) for ns in (root.attrib.get('xmlns', ''),)):
                return True
            
            # Check for characteristic elements
            if root.find('.//dependencies') is not None or \
               root.find('.//projectInfo') is not None:
                return True
            
            return False
        except Exception as e:
            logger.debug(f"DependencyCheckTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Dependency Check XML file"""
        logger.info(f"Parsing OWASP Dependency Check file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Get project name from projectInfo if available
            project_name = "Application"
            project_info = root.find('.//{*}projectInfo')
            if project_info is not None:
                name_elem = project_info.find('.//{*}name')
                if name_elem is not None and name_elem.text:
                    project_name = name_elem.text.strip()
            
            # Find dependencies
            dependencies = root.findall('.//{*}dependency')
            
            assets = []
            for dependency in dependencies:
                asset = self._parse_dependency(dependency, project_name)
                if asset:
                    assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} dependencies with {sum(len(a.findings) for a in assets)} vulnerabilities from Dependency Check XML")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Dependency Check XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_dependency(self, dependency: ET.Element, project_name: str) -> Optional[AssetData]:
        """Parse a single dependency"""
        try:
            # Get file name
            file_name_elem = dependency.find('.//{*}fileName')
            file_name = file_name_elem.text.strip() if file_name_elem is not None and file_name_elem.text else "unknown"
            
            # Get file path
            file_path_elem = dependency.find('.//{*}filePath')
            file_path = file_path_elem.text.strip() if file_path_elem is not None and file_path_elem.text else ""
            
            # Parse vulnerabilities
            vulnerabilities = []
            vuln_elements = dependency.findall('.//{*}vulnerability')
            
            for vuln_elem in vuln_elements:
                vuln = self._parse_vulnerability(vuln_elem, file_name)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Only create asset if it has vulnerabilities
            if not vulnerabilities:
                return None
            
            # Create asset attributes
            attributes = {
                'buildFile': file_name,
                'origin': 'dependency-check',
                'component': file_name,
                'application': project_name
            }
            
            if file_path:
                attributes['file_path'] = file_path
            
            # Get package URL or identifier
            identifiers = dependency.findall('.//{*}identifier')
            for identifier in identifiers:
                id_type = identifier.get('type', '')
                name_elem = identifier.find('.//{*}name')
                if name_elem is not None and name_elem.text:
                    if id_type == 'maven':
                        attributes['maven_coordinates'] = name_elem.text.strip()
                    elif id_type == 'npm':
                        attributes['npm_package'] = name_elem.text.strip()
                    elif id_type == 'cpe':
                        attributes['cpe'] = name_elem.text.strip()
            
            # Create AssetData object
            asset = AssetData(
                asset_type='BUILD',
                attributes=attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "dependency-check"},
                    {"key": "owasp", "value": "true"}
                ]
            )
            
            # Add findings (vulnerabilities)
            for v_dict in vulnerabilities:
                # Create VulnerabilityData from dict
                vuln = VulnerabilityData(**v_dict)
                asset.findings.append(vuln.__dict__)
            
            return self.ensure_asset_has_findings(asset)
            
        except Exception as e:
            logger.debug(f"Error parsing Dependency Check dependency: {e}")
            return None
    
    def _parse_vulnerability(self, vuln_elem: ET.Element, component: str) -> Optional[Dict]:
        """Parse a single vulnerability"""
        try:
            # Get CVE name
            name_elem = vuln_elem.find('.//{*}name')
            if name_elem is None or not name_elem.text:
                return None
            
            vuln_id = name_elem.text.strip()
            
            # Get severity
            severity_elem = vuln_elem.find('.//{*}severity')
            severity_str = severity_elem.text.strip() if severity_elem is not None and severity_elem.text else "Unknown"
            severity = self.normalize_severity(severity_str)
            
            # Get description
            desc_elem = vuln_elem.find('.//{*}description')
            description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else f"Vulnerability {vuln_id} in {component}"
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get CVSS score
            cvss_score = None
            cvss_elem = vuln_elem.find('.//{*}cvssScore')
            if cvss_elem is not None and cvss_elem.text:
                try:
                    cvss_score = float(cvss_elem.text.strip())
                except:
                    pass
            
            # Get CWE
            cwes = []
            cwe_elem = vuln_elem.find('.//{*}cwe')
            if cwe_elem is not None and cwe_elem.text:
                cwes.append(cwe_elem.text.strip())
            
            # Create vulnerability dict
            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': "Update dependency to a non-vulnerable version. See scanner output for details.",
                'severity': severity,
                'location': component,
                'reference_ids': [vuln_id]
            }
            
            # Add optional fields
            if cvss_score:
                vuln_dict['details'] = {'cvss_score': cvss_score}
            
            if cwes:
                vuln_dict['cwes'] = cwes
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing Dependency Check vulnerability: {e}")
            return None


__all__ = ['DependencyCheckTranslator']

