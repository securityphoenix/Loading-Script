#!/usr/bin/env python3
"""
pip-audit Scanner Translator
==============================

Translator for pip-audit vulnerability scanner (Python package manager).

Supported Formats:
- JSON array format with 'name', 'version', 'vulns' fields

Scanner Detection:
- Array of objects with 'name', 'version', and 'vulns' fields
- Empty arrays with 'pip' in filename

Asset Type: BUILD
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class PipAuditTranslator(ScannerTranslator):
    """Translator for pip-audit JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect pip-audit JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # pip-audit produces an array of vulnerability objects
            # Each has 'name', 'version', 'vulns' fields
            if isinstance(file_content, list):
                if len(file_content) == 0:
                    # Empty results - could be pip-audit
                    # Check filename as hint
                    if 'pip' in Path(file_path).stem.lower():
                        return True
                elif len(file_content) > 0:
                    first_item = file_content[0]
                    if isinstance(first_item, dict) and \
                       'name' in first_item and \
                       'version' in first_item and \
                       'vulns' in first_item:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"PipAuditTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse pip-audit JSON file"""
        logger.info(f"Parsing pip-audit file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                return []
            
            assets = []
            
            # Each item is a package with vulnerabilities
            for package_info in data:
                name = package_info.get('name', 'unknown')
                version = package_info.get('version', 'unknown')
                vulns = package_info.get('vulns', [])
                
                if not vulns:
                    continue
                
                # Create asset
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'requirements.txt',
                        'origin': 'pip-audit',
                        'component': name,
                        'version': version
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "pip-audit"},
                        {"key": "package-manager", "value": "pip"}
                    ]
                )
                
                # Add vulnerabilities
                for vuln in vulns:
                    vuln_data = self._parse_vulnerability(vuln, name)
                    if vuln_data:
                        vuln_obj = VulnerabilityData(**vuln_data)
                        asset.findings.append(vuln_obj.__dict__)
                
                if asset.findings:
                    assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} Python packages with {sum(len(a.findings) for a in assets)} vulnerabilities from pip-audit")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing pip-audit: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln: Dict, package: str) -> Optional[Dict]:
        """Parse pip-audit vulnerability"""
        try:
            vuln_id = vuln.get('id', 'UNKNOWN')
            if not vuln_id:
                return None
            
            description = vuln.get('description', f"Vulnerability {vuln_id} in {package}")
            fix_versions = vuln.get('fix_versions', [])
            aliases = vuln.get('aliases', [])
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Build remedy message
            if fix_versions:
                remedy = f"Update to version: {', '.join(fix_versions)}"
            else:
                remedy = "No fix available yet. See advisory for details."
            
            # Reference IDs include main ID and aliases
            reference_ids = [vuln_id] + aliases
            
            return {
                'name': vuln_id,
                'description': description,
                'remedy': remedy,
                'severity': 'Medium',  # pip-audit doesn't provide severity
                'location': package,
                'reference_ids': reference_ids
            }
            
        except Exception as e:
            logger.debug(f"Error parsing pip-audit vulnerability: {e}")
            return None


__all__ = ['PipAuditTranslator']

