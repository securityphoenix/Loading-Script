#!/usr/bin/env python3
"""
NSP (Node Security Project) Scanner Translator
===============================================

Translator for Node Security Project (NSP) vulnerability scanner.

Supported Formats:
- Array of advisories with 'id', 'module', 'vulnerable_versions'
- Dict with 'advisories' array

Scanner Detection:
- Array with items having 'id', 'module', 'vulnerable_versions'
- Dict with 'advisories' key

Asset Type: BUILD

Note: NSP was deprecated in favor of npm audit, but legacy reports may still exist.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def get_tags_safely(tag_config):
    """Safely get tags from tag_config"""
    if not tag_config:
        return []
    if hasattr(tag_config, 'get_all_tags'):
        return tag_config.get_all_tags()
    return []


class NSPTranslator(ScannerTranslator):
    """Translator for Node Security Project (NSP) JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect NSP JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # NSP format has specific structure
            if isinstance(file_content, list) and len(file_content) > 0:
                first = file_content[0]
                if isinstance(first, dict):
                    # Check for NSP-specific fields
                    if 'id' in first and 'module' in first and 'vulnerable_versions' in first:
                        return True
            elif isinstance(file_content, dict):
                # Alternative format with advisories
                if 'advisories' in file_content:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"NSPTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse NSP JSON file"""
        logger.info(f"Parsing NSP file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle different NSP formats
            if isinstance(data, dict) and 'advisories' in data:
                advisories = data['advisories']
            elif isinstance(data, list):
                advisories = data
            else:
                logger.warning("Unknown NSP format")
                return []
            
            # Group vulnerabilities by module
            modules = {}
            for advisory in advisories:
                if isinstance(advisory, dict):
                    module_name = advisory.get('module', advisory.get('module_name', 'unknown'))
                    
                    if module_name not in modules:
                        modules[module_name] = []
                    
                    vuln = self._parse_advisory(advisory)
                    if vuln:
                        modules[module_name].append(vuln)
            
            # Create assets
            assets = []
            
            for module_name, vulns in modules.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'package.json',
                        'origin': 'nsp',
                        'component': module_name
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "nsp"},
                        {"key": "package-manager", "value": "npm"}
                    ]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} modules with {sum(len(a.findings) for a in assets)} vulnerabilities from NSP")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing NSP file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_advisory(self, advisory: Dict) -> Optional[Dict]:
        """Parse a single NSP advisory"""
        try:
            advisory_id = advisory.get('id', advisory.get('advisory', 'UNKNOWN'))
            title = advisory.get('title', advisory.get('overview', 'Security Advisory'))
            module = advisory.get('module', advisory.get('module_name', 'unknown'))
            severity = advisory.get('severity', 'medium')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Get CVEs if available
            cves = advisory.get('cves', [])
            reference_ids = [f"NSP-{advisory_id}"] + cves
            
            return {
                'name': f"NSP-{advisory_id}: {title}",
                'description': advisory.get('overview', title),
                'remedy': advisory.get('recommendation', 'Update to a non-vulnerable version'),
                'severity': severity_normalized,
                'location': module,
                'reference_ids': reference_ids,
                'details': {
                    'vulnerable_versions': advisory.get('vulnerable_versions', ''),
                    'patched_versions': advisory.get('patched_versions', ''),
                    'cvss_score': advisory.get('cvss_score', 0)
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing NSP advisory: {e}")
            return None


__all__ = ['NSPTranslator']

