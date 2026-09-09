#!/usr/bin/env python3
"""
JFrog XRay Scanner Translator (Consolidated)
=============================================

Comprehensive translator handling ALL JFrog XRay format variations:
1. API Summary Artifact: artifacts[] → issues[] structure  
2. Unified: rows[] structure with total_rows
3. On-Demand: array of scan_id + vulnerabilities
4. Legacy: total_count/data with component_versions structure
5. Simple: total_count/data with basic component/provider structure

Supported Formats:
- JSON with multiple JFrog XRay API response formats
- Handles both BUILD and CONTAINER asset types

Scanner Detection:
- Auto-detects format variant and routes to appropriate parser

Asset Types: BUILD (default), CONTAINER (for Docker/OCI packages)
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class JFrogXRayTranslator(ScannerTranslator):
    """
    Consolidated translator for all JFrog XRay format variations
    
    Handles 5 distinct format types with automatic detection:
    - API Summary Artifact
    - Unified (rows format)
    - On-Demand Binary Scan
    - Legacy (component_versions)
    - Simple (basic total_count/data)
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect any JFrog XRay JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Try each format detector
            if self._is_api_summary_artifact(file_content):
                return True
            if self._is_unified_format(file_content):
                return True
            if self._is_ondemand_format(file_content):
                return True
            if self._is_legacy_format(file_content):
                return True
            if self._is_simple_format(file_content):
                return True
            
            return False
        except Exception as e:
            logger.debug(f"JFrogXRayTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse JFrog XRay JSON file (auto-detects format)"""
        logger.info(f"Parsing JFrog XRay file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Detect format and route to appropriate parser
            if self._is_api_summary_artifact(data):
                logger.info("Detected JFrog XRay API Summary Artifact format")
                return self._parse_api_summary_artifact(data)
            elif self._is_unified_format(data):
                logger.info("Detected JFrog XRay Unified format")
                return self._parse_unified_format(data)
            elif self._is_ondemand_format(data):
                logger.info("Detected JFrog XRay On-Demand format")
                return self._parse_ondemand_format(data)
            elif self._is_legacy_format(data):
                logger.info("Detected JFrog XRay Legacy format")
                return self._parse_legacy_format(data)
            elif self._is_simple_format(data):
                logger.info("Detected JFrog XRay Simple format")
                return self._parse_simple_format(data)
            else:
                logger.warning("Unknown JFrog XRay format")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing JFrog XRay file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    # ========== FORMAT DETECTORS ==========
    
    def _is_api_summary_artifact(self, data: Any) -> bool:
        """Detect API Summary Artifact format: artifacts[] with general/issues"""
        if isinstance(data, dict) and 'artifacts' in data:
            artifacts = data.get('artifacts', [])
            if artifacts and isinstance(artifacts, list):
                first_artifact = artifacts[0]
                return 'general' in first_artifact and 'issues' in first_artifact
        return False
    
    def _is_unified_format(self, data: Any) -> bool:
        """Detect Unified format: rows[] with total_rows"""
        if isinstance(data, dict):
            if 'rows' in data and 'total_rows' in data:
                rows = data.get('rows', [])
                if rows and isinstance(rows, list):
                    first_row = rows[0]
                    # Must have vulnerable_component or issue_id AND provider='JFrog'
                    if 'vulnerable_component' in first_row or 'issue_id' in first_row:
                        return first_row.get('provider') == 'JFrog'
        return False
    
    def _is_ondemand_format(self, data: Any) -> bool:
        """Detect On-Demand format: array with scan_id + vulnerabilities"""
        if isinstance(data, list) and len(data) > 0:
            first_item = data[0]
            # Must have scan_id, vulnerabilities, and component_id/package_type
            return ('scan_id' in first_item and 'vulnerabilities' in first_item and
                    ('component_id' in first_item or 'package_type' in first_item))
        return False
    
    def _is_legacy_format(self, data: Any) -> bool:
        """Detect Legacy format: total_count/data with component_versions"""
        if isinstance(data, dict):
            if 'total_count' in data and 'data' in data:
                items = data.get('data', [])
                if items and isinstance(items, list):
                    first_item = items[0]
                    # Legacy has component_versions AND source_comp_id
                    return 'component_versions' in first_item and 'source_comp_id' in first_item
        return False
    
    def _is_simple_format(self, data: Any) -> bool:
        """Detect Simple format: total_count/data with component + provider"""
        if isinstance(data, dict):
            if 'total_count' in data and 'data' in data:
                items = data.get('data', [])
                if items and isinstance(items, list):
                    first = items[0]
                    # Simple has component and provider='JFrog' (no component_versions)
                    return ('component' in first and 'provider' in first and
                            first.get('provider') == 'JFrog' and
                            'component_versions' not in first)
        return False
    
    # ========== FORMAT PARSERS ==========
    
    def _parse_api_summary_artifact(self, data: Dict) -> List[AssetData]:
        """Parse API Summary Artifact format"""
        assets = []
        artifacts = data.get('artifacts', [])
        
        for artifact in artifacts:
            general = artifact.get('general', {})
            issues = artifact.get('issues', [])
            
            # Extract artifact info
            artifact_name = general.get('name', general.get('component_id', 'unknown'))
            pkg_type = general.get('pkg_type', 'unknown')
            sha256 = general.get('sha256', '')
            
            # Determine asset type
            asset_type = "CONTAINER" if pkg_type in ['Docker', 'OCI'] else "BUILD"
            
            # Create asset
            asset = AssetData(
                asset_type=asset_type,
                attributes={
                    'buildFile': artifact_name,
                    'origin': 'jfrog-xray-api',
                    'repository': artifact_name,
                    'package_type': pkg_type
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "format", "value": "api-summary"},
                    {"key": "package_type", "value": pkg_type}
                ]
            )
            
            # Parse issues
            for issue in issues:
                vuln_dict = self._parse_api_issue(issue, artifact_name)
                if vuln_dict:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} artifacts with {sum(len(a.findings) for a in assets)} issues")
        return assets
    
    def _parse_unified_format(self, data: Dict) -> List[AssetData]:
        """Parse Unified format"""
        assets = []
        rows = data.get('rows', [])
        
        # Group by impacted artifact
        artifacts_dict = {}
        for row in rows:
            artifact_name = row.get('impacted_artifact', row.get('vulnerable_component', 'unknown'))
            if artifact_name not in artifacts_dict:
                artifacts_dict[artifact_name] = []
            
            vuln_dict = self._parse_unified_row(row)
            if vuln_dict:
                artifacts_dict[artifact_name].append(vuln_dict)
        
        # Create assets
        for artifact_name, vuln_dicts in artifacts_dict.items():
            pkg_type = artifact_name.split('://')[0] if '://' in artifact_name else 'unknown'
            
            asset = AssetData(
                asset_type="BUILD",
                attributes={
                    'buildFile': artifact_name,
                    'origin': 'jfrog-xray-unified',
                    'repository': artifact_name,
                    'package_type': pkg_type
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "format", "value": "unified"}
                ]
            )
            
            for vuln_dict in vuln_dicts:
                vuln_obj = VulnerabilityData(**vuln_dict)
                asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} artifacts with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_ondemand_format(self, data: List) -> List[AssetData]:
        """Parse On-Demand format"""
        assets = []
        
        # Data is array of scan results
        if not isinstance(data, list):
            data = [data]
        
        for scan_result in data:
            component_id = scan_result.get('component_id', 'unknown')
            package_type = scan_result.get('package_type', 'unknown')
            scan_id = scan_result.get('scan_id', 'unknown')
            vulnerabilities = scan_result.get('vulnerabilities', [])
            
            asset = AssetData(
                asset_type="BUILD",
                attributes={
                    'buildFile': component_id,
                    'origin': 'jfrog-xray-ondemand',
                    'repository': component_id,
                    'package_type': package_type,
                    'scan_id': scan_id[:12] if scan_id else ''
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "format", "value": "ondemand"}
                ]
            )
            
            for vuln_data in vulnerabilities:
                vuln_dict = self._parse_ondemand_vuln(vuln_data, component_id)
                if vuln_dict:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} scan results with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_legacy_format(self, data: Dict) -> List[AssetData]:
        """Parse Legacy format"""
        assets = []
        data_items = data.get('data', [])
        
        # Group by component
        components_dict = {}
        for item in data_items:
            component = item.get('component', item.get('source_comp_id', 'unknown'))
            if component not in components_dict:
                components_dict[component] = []
            
            vuln_dict = self._parse_legacy_item(item)
            if vuln_dict:
                components_dict[component].append(vuln_dict)
        
        # Create assets
        for component, vuln_dicts in components_dict.items():
            asset = AssetData(
                asset_type="BUILD",
                attributes={
                    'buildFile': 'Dockerfile',
                    'origin': 'jfrog-xray-legacy',
                    'repository': component
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "format", "value": "legacy"}
                ]
            )
            
            for vuln_dict in vuln_dicts:
                vuln_obj = VulnerabilityData(**vuln_dict)
                asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_simple_format(self, data: Dict) -> List[AssetData]:
        """Parse Simple format"""
        assets = []
        issues = data.get('data', [])
        
        # Group by component
        components = {}
        for issue in issues:
            component = issue.get('component', 'unknown')
            if component not in components:
                components[component] = []
            
            vuln_dict = self._parse_simple_issue(issue)
            if vuln_dict:
                components[component].append(vuln_dict)
        
        # Create assets
        for component, vuln_dicts in components.items():
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': 'package',
                    'origin': 'jfrog-xray-simple',
                    'component': component
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "format", "value": "simple"}
                ]
            )
            
            for vuln_dict in vuln_dicts:
                vuln_obj = VulnerabilityData(**vuln_dict)
                asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} issues")
        return assets
    
    # ========== VULNERABILITY PARSERS ==========
    
    def _parse_api_issue(self, issue: Dict, artifact_name: str) -> Optional[Dict]:
        """Parse API Summary issue"""
        issue_id = issue.get('issue_id', issue.get('cve', 'UNKNOWN'))
        if not issue_id:
            return None
        
        # Get CVEs and CVSS
        cves_list = issue.get('cves', [])
        cves = []
        cvss_v3_score = None
        
        for cve_data in cves_list:
            if isinstance(cve_data, dict):
                cves.append(cve_data.get('cve', issue_id))
                if not cvss_v3_score:
                    cvss_v3 = cve_data.get('cvss_v3', '')
                    if cvss_v3 and '/' in cvss_v3:
                        try:
                            cvss_v3_score = float(cvss_v3.split('/')[0])
                        except:
                            pass
        
        if not cves:
            cves = [issue_id]
        
        severity = self.normalize_severity(issue.get('severity', 'Unknown'))
        impact_paths = issue.get('impact_path', [])
        location = impact_paths[0] if impact_paths else artifact_name
        
        return {
            'name': issue_id,
            'description': issue.get('description', issue.get('summary', f"JFrog XRay issue: {issue_id}"))[:500],
            'remedy': f"See JFrog recommendations for {issue_id}",
            'severity': severity,
            'location': str(location),
            'reference_ids': cves,
            'details': {
                'issue_type': issue.get('issue_type', 'security'),
                'provider': issue.get('provider', 'JFrog'),
                'cvss_v3_score': cvss_v3_score,
                'impact_path': impact_paths
            }
        }
    
    def _parse_unified_row(self, row: Dict) -> Optional[Dict]:
        """Parse Unified format row"""
        issue_id = row.get('issue_id', 'UNKNOWN')
        if not issue_id:
            return None
        
        cves_list = row.get('cves', [])
        cves = [cve_data.get('cve', issue_id) for cve_data in cves_list if isinstance(cve_data, dict)]
        if not cves:
            cves = [issue_id]
        
        severity = self.normalize_severity(row.get('severity', 'Unknown'))
        fixed_versions = row.get('fixed_versions', [])
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "No fix available"
        
        return {
            'name': issue_id,
            'description': row.get('description', row.get('summary', f"JFrog XRay issue: {issue_id}"))[:500],
            'remedy': remedy,
            'severity': severity,
            'location': row.get('vulnerable_component', 'unknown'),
            'reference_ids': cves,
            'details': {
                'provider': row.get('provider', 'JFrog'),
                'fixed_versions': fixed_versions,
                'cvss_v3_score': row.get('cvss3_max_score')
            }
        }
    
    def _parse_ondemand_vuln(self, vuln_data: Dict, component_id: str) -> Optional[Dict]:
        """Parse On-Demand vulnerability"""
        issue_id = vuln_data.get('issue_id', 'UNKNOWN')
        if not issue_id:
            return None
        
        cves_list = vuln_data.get('cves', [])
        cves = [cve_data.get('cve', issue_id) for cve_data in cves_list if isinstance(cve_data, dict)]
        if not cves:
            cves = [issue_id]
        
        severity = self.normalize_severity(vuln_data.get('severity', 'Unknown'))
        
        # Get fixed versions from components
        components = vuln_data.get('components', {})
        fixed_versions = []
        for comp_data in components.values():
            if isinstance(comp_data, dict):
                fixed_versions.extend(comp_data.get('fixed_versions', []))
        
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "No fix available"
        
        return {
            'name': issue_id,
            'description': vuln_data.get('summary', f"JFrog XRay issue: {issue_id}")[:500],
            'remedy': remedy,
            'severity': severity,
            'location': component_id,
            'reference_ids': cves,
            'details': {'fixed_versions': fixed_versions}
        }
    
    def _parse_legacy_item(self, item: Dict) -> Optional[Dict]:
        """Parse Legacy format item"""
        component_versions = item.get('component_versions', {})
        more_details = component_versions.get('more_details', {})
        cves_list = more_details.get('cves', [])
        
        cves = []
        cvss_v3_score = None
        for cve_data in cves_list:
            if isinstance(cve_data, dict):
                cve_id = cve_data.get('cve', '')
                if cve_id:
                    cves.append(cve_id)
                    if not cvss_v3_score:
                        cvss_v3 = cve_data.get('cvss_v3', '')
                        if cvss_v3 and '/' in cvss_v3:
                            try:
                                cvss_v3_score = float(cvss_v3.split('/')[0])
                            except:
                                pass
        
        vuln_id = cves[0] if cves else item.get('id', 'UNKNOWN')
        if not vuln_id:
            return None
        
        severity = self.normalize_severity(item.get('severity', 'Unknown'))
        fixed_versions = component_versions.get('fixed_versions', [])
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "No fix available"
        
        return {
            'name': vuln_id,
            'description': more_details.get('description', item.get('summary', f"JFrogXray issue: {vuln_id}"))[:500],
            'remedy': remedy,
            'severity': severity,
            'location': item.get('component', 'unknown'),
            'reference_ids': cves,
            'details': {
                'provider': item.get('provider', 'JFrog'),
                'fixed_versions': fixed_versions,
                'cvss_v3_score': cvss_v3_score
            }
        }
    
    def _parse_simple_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse Simple format issue"""
        issue_id = issue.get('id', 'UNKNOWN')
        summary = issue.get('summary', 'Security Issue')
        component = issue.get('component', 'unknown')
        
        # Get CVEs from component_versions
        cves = []
        component_versions = issue.get('component_versions', {})
        more_details = component_versions.get('more_details', {})
        if isinstance(more_details, dict):
            cve_list = more_details.get('cves', [])
            for cve_info in cve_list:
                if isinstance(cve_info, dict):
                    cve = cve_info.get('cve', '')
                    if cve:
                        cves.append(cve)
        
        severity = self.normalize_severity(issue.get('severity', 'Medium'))
        fixed_versions = component_versions.get('fixed_versions', [])
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "Update to a non-vulnerable version"
        
        return {
            'name': f"{cves[0] if cves else issue_id}: {summary[:100]}",
            'description': summary[:500],
            'remedy': remedy,
            'severity': severity,
            'location': component,
            'reference_ids': cves if cves else [issue_id],
            'details': {
                'issue_type': issue.get('issue_type', ''),
                'fixed_versions': fixed_versions
            }
        }


__all__ = ['JFrogXRayTranslator']

