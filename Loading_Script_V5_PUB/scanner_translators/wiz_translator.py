#!/usr/bin/env python3
"""
Wiz Scanner Translator (Consolidated)
======================================

Comprehensive translator handling Wiz cloud security CSV formats:
1. Wiz Standard CSV: 'Issue' and ('Project' OR 'Resource') columns
2. Wiz Issues CSV: 'Created At', 'Issue ID', 'Control ID' columns

Supported Formats:
- CSV exports from Wiz platform (standard format)
- CSV exports from Wiz Issues (detailed format)

Scanner Detection:
- Auto-detects format variant and routes to appropriate parser

Asset Type: CLOUD
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


class WizTranslator(ScannerTranslator):
    """
    Consolidated translator for all Wiz CSV format variations
    
    Handles 2 distinct format types with automatic detection:
    - Wiz Standard CSV
    - Wiz Issues CSV (detailed)
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect any Wiz CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline()
                first_line_lower = first_line.lower()
                
                # Wiz Issues CSV: 'Created At', 'Issue ID', 'Control ID'
                if 'created at' in first_line_lower and 'issue id' in first_line_lower and 'control id' in first_line_lower:
                    return True
                
                # Wiz Standard CSV: 'issue' and ('project' or 'resource')
                if 'issue' in first_line_lower and ('project' in first_line_lower or 'resource' in first_line_lower):
                    return True
                
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Wiz CSV file (auto-detects format)"""
        logger.info(f"Parsing Wiz CSV file: {file_path}")
        
        try:
            # Detect format
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline()
                
            if 'Created At' in first_line and 'Issue ID' in first_line and 'Control ID' in first_line:
                logger.info("Detected Wiz Issues CSV format")
                return self._parse_issues_format(file_path)
            else:
                logger.info("Detected Wiz Standard CSV format")
                return self._parse_standard_format(file_path)
                
        except Exception as e:
            logger.error(f"Error parsing Wiz CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_standard_format(self, file_path: str) -> List[AssetData]:
        """Parse Wiz Standard CSV format"""
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
                resource = row.get('Resource', row.get('resource', row.get('Project', 'Unknown')))
                if resource not in resources:
                    resources[resource] = []
                
                issue = row.get('Issue', row.get('issue', row.get('Finding', 'Wiz Finding')))
                severity = row.get('Severity', row.get('severity', 'MEDIUM'))
                
                vuln_dict = {
                    'name': issue[:100],
                    'description': row.get('Description', issue)[:500],
                    'remedy': row.get('Remediation', row.get('Resolution', 'See Wiz console for remediation')),
                    'severity': self._map_wiz_severity(severity),
                    'location': resource,
                    'reference_ids': []
                }
                
                resources[resource].append(vuln_dict)
            
            # Create assets
            assets = []
            for resource, vuln_dicts in resources.items():
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'cloud_provider': 'Multi-Cloud',
                        'resource': resource
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "wiz"},
                        {"key": "format", "value": "standard"}
                    ]
                )
                
                for vuln_dict in vuln_dicts:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} resources with {sum(len(a.findings) for a in assets)} issues from Wiz CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Wiz Standard CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issues_format(self, file_path: str) -> List[AssetData]:
        """Parse Wiz Issues CSV format (detailed)"""
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by Resource Name or Resource external ID
            resource_issues = {}
            for row in rows:
                resource_name = row.get('Resource Name', row.get('Resource external ID', 'unknown'))
                if not resource_name:
                    resource_name = 'Wiz-Resource'
                
                if resource_name not in resource_issues:
                    resource_issues[resource_name] = {
                        'resource_type': row.get('Resource Type', 'Unknown'),
                        'platform': row.get('Resource Platform', 'Cloud'),
                        'region': row.get('Resource Region', ''),
                        'findings': []
                    }
                
                issue_id = row.get('Issue ID', 'unknown')
                title = row.get('Title', 'Security Issue')
                severity = row.get('Severity', 'MEDIUM')
                status = row.get('Status', 'OPEN')
                description = row.get('Description', '')
                
                # Only include open issues or high severity
                if status == 'OPEN' or severity in ['CRITICAL', 'HIGH']:
                    vuln_dict = {
                        'name': f"WIZ-{issue_id[:8]}",
                        'description': f"{title}: {description[:200]}" if description else title,
                        'remedy': row.get('Remediation Recommendation', 'Review and remediate as per Wiz recommendations'),
                        'severity': self._map_wiz_severity(severity),
                        'location': row.get('Wiz URL', resource_name),
                        'reference_ids': [issue_id],
                        'details': {
                            'control_id': row.get('Control ID', ''),
                            'status': status,
                            'resource_type': row.get('Resource Type', ''),
                            'subscription': row.get('Subscription Name', '')
                        }
                    }
                    
                    resource_issues[resource_name]['findings'].append(vuln_dict)
            
            # Create assets
            assets = []
            for resource_name, data in resource_issues.items():
                if data['findings']:
                    asset = AssetData(
                        asset_type='CLOUD',
                        attributes={
                            'cloud_provider': data['platform'],
                            'resource': resource_name,
                            'resourceType': data['resource_type'],
                            'region': data['region']
                        },
                        tags=self.tag_config.get_all_tags() + [
                            {"key": "scanner", "value": "wiz"},
                            {"key": "format", "value": "issues"}
                        ]
                    )
                    
                    for vuln_dict in data['findings']:
                        vuln_obj = VulnerabilityData(**vuln_dict)
                        asset.findings.append(vuln_obj.__dict__)
                    
                    assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} resources with {sum(len(a.findings) for a in assets)} issues from Wiz Issues CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Wiz Issues CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_wiz_severity(self, severity: str) -> str:
        """Map Wiz severity to Phoenix severity"""
        severity_upper = str(severity).upper().strip()
        mapping = {
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFORMATIONAL': 'Info',
            'INFO': 'Info'
        }
        return mapping.get(severity_upper, 'Medium')


__all__ = ['WizTranslator']

