#!/usr/bin/env python3
"""
Azure Security Center Scanner Translator
=========================================

Translator for Azure Security Center Recommendations CSV exports.

Supported Formats:
- CSV with 'subscriptionId' and 'recommendationName' columns

Scanner Detection:
- CSV with 'subscriptionid' and 'recommendationname' in headers (case-insensitive)

Asset Type: CLOUD (Azure)
"""

import csv
import logging
import sys
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


class AzureSecurityCenterTranslator(ScannerTranslator):
    """Translator for Azure Security Center Recommendations CSV"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Azure Security Center CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'subscriptionid' in first_line and 'recommendationname' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Azure Security Center CSV file"""
        logger.info(f"Parsing Azure Security Center CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by resource
            resources = {}
            for row in rows:
                resource_id = row.get('resourceId', row.get('resourceName', 'Unknown'))
                if resource_id not in resources:
                    resources[resource_id] = {
                        'name': row.get('resourceName', resource_id),
                        'type': row.get('resourceType', 'Azure Resource'),
                        'group': row.get('resourceGroup', ''),
                        'vulns': []
                    }
                
                # Only include unhealthy/failed recommendations
                state = row.get('state', '').lower()
                if state in ['unhealthy', 'failed', 'open']:
                    recommendation = row.get('recommendationDisplayName', row.get('recommendationName', 'Azure Recommendation'))
                    severity = row.get('severity', 'Medium')
                    
                    vuln_dict = {
                        'name': recommendation[:100],
                        'description': row.get('description', recommendation)[:500],
                        'remedy': row.get('remediationSteps', 'See Azure Security Center for remediation steps'),
                        'severity': self._map_azure_severity(severity),
                        'location': resource_id,
                        'reference_ids': [row.get('recommendationId', '')]
                    }
                    
                    resources[resource_id]['vulns'].append(vuln_dict)
            
            # Create assets
            assets = []
            for resource_id, data in resources.items():
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'cloud_provider': 'Azure',
                        'cloudResourceId': resource_id,
                        'cloudResourceType': data['type'],
                        'cloudResourceGroup': data['group']
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "azure-security-center"},
                        {"key": "cloud_provider", "value": "azure"}
                    ]
                )
                
                # Add findings
                if data['vulns']:
                    for vuln_dict in data['vulns']:
                        vuln_obj = VulnerabilityData(**vuln_dict)
                        asset.findings.append(vuln_obj.__dict__)
                    
                    assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} recommendations from Azure Security Center CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Azure Security Center CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_azure_severity(self, severity: str) -> str:
        """Map Azure severity to Phoenix severity"""
        severity_lower = str(severity).lower().strip()
        mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'moderate': 'Medium',
            'low': 'Low',
            'informational': 'Info'
        }
        return mapping.get(severity_lower, 'Medium')


__all__ = ['AzureSecurityCenterTranslator']

