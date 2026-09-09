#!/usr/bin/env python3
"""
Kubeaudit Translator
====================

Translator for Shopify's kubeaudit - Kubernetes security scanner.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class KubeauditTranslator(ScannerTranslator):
    """Translator for Kubeaudit JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Kubeaudit JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Kubeaudit format is an array of audit results
            if isinstance(file_content, list) and len(file_content) > 0:
                first = file_content[0]
                if isinstance(first, dict):
                    # Check for kubeaudit-specific fields
                    if 'AuditResultName' in first and 'ResourceNamespace' in first and 'ResourceKind' in first:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"KubeauditTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Kubeaudit JSON/NDJSON file"""
        logger.info(f"Parsing Kubeaudit file: {file_path}")
        
        try:
            # Try to load as regular JSON first
            with open(file_path, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    # If that fails, try NDJSON (one JSON per line)
                    f.seek(0)
                    data = []
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    if not data:
                        raise ValueError("Could not parse as JSON or NDJSON")
            
            if not isinstance(data, list):
                data = [data]
            
            # Group by resource
            resources = {}
            
            for audit_result in data:
                # Get resource info
                namespace = audit_result.get('ResourceNamespace', 'default')
                kind = audit_result.get('ResourceKind', 'Unknown')
                name = audit_result.get('ResourceName', 'unknown')
                
                resource_key = f"{namespace}/{kind}/{name}"
                
                if resource_key not in resources:
                    resources[resource_key] = {
                        'namespace': namespace,
                        'kind': kind,
                        'name': name,
                        'findings': []
                    }
                
                # Parse finding
                vuln = self._parse_audit_result(audit_result)
                if vuln:
                    resources[resource_key]['findings'].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for resource_key, resource_info in resources.items():
                asset = AssetData(
                    asset_type='CONTAINER',
                    attributes={
                        'name': resource_info['name'],
                        'namespace': resource_info['namespace'],
                        'kind': resource_info['kind'],
                        'scanner': 'Kubeaudit'
                    },
                    tags=tags + [
                        {"key": "scanner", "value": "kubeaudit"},
                        {"key": "namespace", "value": resource_info['namespace']},
                        {"key": "kind", "value": resource_info['kind']}
                    ]
                )
                
                # Add findings
                for vuln in resource_info['findings']:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} Kubernetes resources with {sum(len(a.findings) for a in assets)} audit results")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Kubeaudit file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_audit_result(self, result: Dict) -> Optional[Dict]:
        """Parse a single kubeaudit result"""
        try:
            audit_name = result.get('AuditResultName', 'Unknown')
            level = result.get('Level', 'Warning')
            msg = result.get('msg', '')
            container = result.get('Container', '')
            
            # Map level to severity
            level_to_severity = {
                'Error': 'High',
                'Warn': 'Medium',
                'Warning': 'Medium',
                'Info': 'Low'
            }
            severity_str = level_to_severity.get(level, 'Medium')
            severity = self.normalize_severity(severity_str)
            
            # Create location
            location_parts = []
            if container:
                location_parts.append(f"container:{container}")
            if result.get('ResourceName'):
                location_parts.append(result['ResourceName'])
            location = '/'.join(location_parts) if location_parts else 'resource'
            
            return {
                'name': audit_name,
                'description': msg if msg else audit_name,
                'remedy': "Review Kubernetes security configuration",
                'severity': severity,
                'location': location,
                'reference_ids': [],
                'details': {
                    'level': level,
                    'audit_result_name': audit_name,
                    'container': container,
                    'namespace': result.get('ResourceNamespace', ''),
                    'kind': result.get('ResourceKind', ''),
                    'capability': result.get('Capability', ''),
                    'missing_annotation': result.get('MissingAnnotation', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing kubeaudit result: {e}")
            return None


# Export translator
__all__ = ['KubeauditTranslator']

