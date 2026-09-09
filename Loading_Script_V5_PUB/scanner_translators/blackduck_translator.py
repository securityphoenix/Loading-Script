#!/usr/bin/env python3
"""
BlackDuck Scanner Translator (Consolidated)
============================================

Comprehensive translator handling ALL BlackDuck format variations:
1. Binary Analysis CSV: Component/Version/CVE columns
2. API JSON: componentName + vulnerabilityWithRemediation
3. Component Risk ZIP: Contains component/risk CSV/JSON files
4. Standard ZIP: Contains security.csv + files.csv
5. Binary CSV (Alternative): Component/Version/CVE/Object columns

Supported Formats:
- CSV files with BlackDuck-specific columns
- JSON files from BlackDuck API
- ZIP archives containing CSV/JSON vulnerability reports

Scanner Detection:
- Auto-detects format variant and routes to appropriate parser

Asset Type: BUILD
"""

import csv
import json
import logging
import os
import sys
import tempfile
import zipfile
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def increase_csv_field_size_limit():
    """Increase CSV field size limit to handle large fields"""
    maxInt = sys.maxsize
    while True:
        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt/10)


class BlackDuckTranslator(ScannerTranslator):
    """
    Consolidated translator for all BlackDuck format variations
    
    Handles 5 distinct format types with automatic detection:
    - Binary Analysis CSV (with/without Object columns)
    - API JSON
    - Component Risk ZIP
    - Standard ZIP (security.csv)
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect any BlackDuck format"""
        # Try each format detector
        if self._is_blackduck_csv(file_path):
            return True
        if self._is_blackduck_json(file_path, file_content):
            return True
        if self._is_blackduck_zip(file_path):
            return True
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse BlackDuck file (auto-detects format)"""
        logger.info(f"Parsing BlackDuck file: {file_path}")
        
        try:
            # CSV formats
            if file_path.lower().endswith('.csv'):
                return self._parse_csv_format(file_path)
            
            # JSON API format
            elif file_path.lower().endswith('.json'):
                return self._parse_json_format(file_path)
            
            # ZIP formats
            elif file_path.lower().endswith('.zip'):
                return self._parse_zip_format(file_path)
            
            else:
                logger.warning(f"Unknown BlackDuck file extension: {file_path}")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing BlackDuck file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    # ========== FORMAT DETECTORS ==========
    
    def _is_blackduck_csv(self, file_path: str) -> bool:
        """Detect BlackDuck CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            increase_csv_field_size_limit()
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                if headers:
                    # Check for BlackDuck-specific columns
                    bd_cols = ['Component', 'Version', 'CVE']
                    matches = sum(1 for col in bd_cols if col in headers)
                    return matches >= 3
            return False
        except:
            return False
    
    def _is_blackduck_json(self, file_path: str, file_content: Any = None) -> bool:
        """Detect BlackDuck API JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for BlackDuck API structure
            if isinstance(file_content, list) and len(file_content) > 0:
                first_item = file_content[0]
                if isinstance(first_item, dict):
                    required_keys = ["componentName", "vulnerabilityWithRemediation"]
                    return all(k in first_item for k in required_keys)
            
            return False
        except:
            return False
    
    def _is_blackduck_zip(self, file_path: str) -> bool:
        """Detect BlackDuck ZIP format"""
        if not file_path.lower().endswith('.zip'):
            return False
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                files = [f.lower() for f in zip_ref.namelist()]
                
                # Standard ZIP: has security.csv and files.csv
                has_security = any('security.csv' in f for f in files)
                has_files = any('files.csv' in f for f in files)
                if has_security and has_files:
                    return True
                
                # Component Risk ZIP: has component/risk in filename or CSV/JSON files
                for name in files:
                    if ('component' in name and 'risk' in name):
                        return True
                    if name.endswith(('.csv', '.json')):
                        return True
                
            return False
        except:
            return False
    
    # ========== FORMAT PARSERS ==========
    
    def _parse_csv_format(self, file_path: str) -> List[AssetData]:
        """Parse BlackDuck CSV format"""
        logger.info("Detected BlackDuck CSV format")
        
        try:
            increase_csv_field_size_limit()
            
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by component
            components = {}
            for row in rows:
                component = row.get('Component', 'unknown')
                version = row.get('Version', '')
                key = f"{component}:{version}" if version else component
                
                if key not in components:
                    components[key] = []
                
                vuln_dict = self._parse_csv_row(row)
                if vuln_dict:
                    components[key].append(vuln_dict)
            
            # Create assets
            assets = []
            for component_key, vuln_dicts in components.items():
                if not vuln_dicts:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'binary',
                        'origin': 'blackduck-csv',
                        'component': component_key
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "blackduck"},
                        {"key": "format", "value": "csv"}
                    ]
                )
                
                for vuln_dict in vuln_dicts:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing BlackDuck CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_json_format(self, file_path: str) -> List[AssetData]:
        """Parse BlackDuck API JSON format"""
        logger.info("Detected BlackDuck API JSON format")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                data = [data]
            
            # Group by component
            assets_dict = {}
            for item in data:
                asset_name = item.get('componentName', 'unknown')
                
                if asset_name not in assets_dict:
                    assets_dict[asset_name] = []
                
                vuln_dict = self._parse_json_vuln(item)
                if vuln_dict:
                    assets_dict[asset_name].append(vuln_dict)
            
            # Create assets
            assets = []
            for asset_name, vuln_dicts in assets_dict.items():
                asset = AssetData(
                    asset_type="BUILD",
                    attributes={
                        'buildFile': 'Dockerfile',
                        'origin': 'blackduck-api',
                        'repository': asset_name
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "blackduck"},
                        {"key": "format", "value": "api-json"}
                    ]
                )
                
                for vuln_dict in vuln_dicts:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing BlackDuck API JSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_zip_format(self, file_path: str) -> List[AssetData]:
        """Parse BlackDuck ZIP format"""
        logger.info("Detected BlackDuck ZIP format")
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract ZIP
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Check for security.csv (Standard ZIP)
                security_csv = None
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.lower() == 'security.csv':
                            security_csv = os.path.join(root, file)
                            break
                    if security_csv:
                        break
                
                if security_csv:
                    logger.info("Found security.csv - parsing as Standard ZIP")
                    return self._parse_security_csv(security_csv)
                else:
                    # Component Risk ZIP - parse all CSV/JSON files
                    logger.info("No security.csv - parsing as Component Risk ZIP")
                    return self._parse_component_risk_zip(temp_dir)
        
        except Exception as e:
            logger.error(f"Error parsing BlackDuck ZIP: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_security_csv(self, csv_path: str) -> List[AssetData]:
        """Parse security.csv from BlackDuck Standard ZIP"""
        try:
            increase_csv_field_size_limit()
            
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by component
            components = {}
            for row in rows:
                # Try various column names
                component = (row.get('Channel version origin id') or
                           row.get('Project name') or
                           row.get('Component') or
                           row.get('Component name') or
                           'unknown')
                
                if component == 'unknown' or not component:
                    continue
                
                if component not in components:
                    components[component] = []
                
                # Extract vulnerability details
                vuln_id = row.get('Vulnerability id') or row.get('Vulnerability')
                
                if vuln_id and vuln_id != 'None':
                    severity_str = row.get('Base score') or row.get('Security Risk') or row.get('Severity') or 'Medium'
                    
                    vuln_dict = {
                        'name': f"BDSA-{vuln_id}" if not vuln_id.startswith('CVE') else vuln_id,
                        'description': row.get('Description', f"Vulnerability {vuln_id}")[:500],
                        'remedy': row.get('Remediation', 'Update to a non-vulnerable version'),
                        'severity': self._map_severity(severity_str),
                        'location': component,
                        'reference_ids': [vuln_id]
                    }
                    
                    components[component].append(vuln_dict)
            
            # Create assets
            assets = []
            for component, vuln_dicts in components.items():
                if not vuln_dicts:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'security.csv',
                        'origin': 'blackduck-standard-zip',
                        'component': component
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "blackduck"},
                        {"key": "format", "value": "standard-zip"}
                    ]
                )
                
                for vuln_dict in vuln_dicts:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities from security.csv")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing security.csv: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_component_risk_zip(self, temp_dir: str) -> List[AssetData]:
        """Parse Component Risk ZIP format"""
        assets = []
        
        # Find and parse all CSV/JSON files
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                if file.endswith('.csv'):
                    assets.extend(self._parse_csv_format(file_path))
                elif file.endswith('.json'):
                    # Try parsing as BlackDuck JSON
                    try:
                        assets.extend(self._parse_json_format(file_path))
                    except:
                        pass
        
        logger.info(f"Parsed {len(assets)} assets from Component Risk ZIP")
        return assets
    
    # ========== VULNERABILITY PARSERS ==========
    
    def _parse_csv_row(self, row: Dict) -> Optional[Dict]:
        """Parse CSV row into vulnerability dict"""
        vuln_id = row.get('CVE', row.get('BDSA', '')).strip()
        if not vuln_id:
            return None
        
        component = row.get('Component', 'unknown')
        cvss_str = row.get('CVSS3', row.get('CVSS', '0.0'))
        
        try:
            cvss_score = float(cvss_str) if cvss_str else 0.0
        except:
            cvss_score = 0.0
        
        severity = self._map_cvss_to_severity(cvss_score)
        
        return {
            'name': vuln_id,
            'description': row.get('Summary', f"Vulnerability: {vuln_id}")[:500],
            'remedy': "See vendor advisories for remediation",
            'severity': severity,
            'location': row.get('Object', component),
            'reference_ids': [vuln_id],
            'details': {
                'cvss_score': cvss_score,
                'cvss_vector': row.get('CVSS vector (v3)', row.get('CVSS vector', '')),
                'url': row.get('Vulnerability URL', '')
            }
        }
    
    def _parse_json_vuln(self, item: Dict) -> Optional[Dict]:
        """Parse JSON API vulnerability"""
        vuln_with_rem = item.get('vulnerabilityWithRemediation', {})
        if not vuln_with_rem:
            return None
        
        vuln_id = vuln_with_rem.get('vulnerabilityName', 'UNKNOWN')
        if not vuln_id:
            return None
        
        severity_str = vuln_with_rem.get('severity', 'Unknown')
        severity = self.normalize_severity(severity_str)
        
        return {
            'name': vuln_id,
            'description': vuln_with_rem.get('description', f"Vulnerability: {vuln_id}")[:500],
            'remedy': vuln_with_rem.get('remediationComment', "See scanner output for remediation"),
            'severity': severity,
            'location': item.get('componentVersionName', 'unknown'),
            'reference_ids': [vuln_id]
        }
    
    # ========== HELPER METHODS ==========
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to Phoenix severity"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0:
            return 'Low'
        else:
            return 'Info'
    
    def _map_severity(self, severity_str: str) -> str:
        """Map severity string to Phoenix severity"""
        # Try CVSS score first
        try:
            score = float(severity_str)
            return self._map_cvss_to_severity(score)
        except:
            # Map string severity
            severity_lower = str(severity_str).lower().strip()
            mapping = {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'moderate': 'Medium',
                'low': 'Low',
                'info': 'Info',
                'informational': 'Info'
            }
            return mapping.get(severity_lower, 'Medium')


__all__ = ['BlackDuckTranslator']

