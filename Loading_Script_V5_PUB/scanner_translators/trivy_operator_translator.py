#!/usr/bin/env python3
"""
Trivy Operator Scanner Translator
===================================

Translator for Trivy Operator Kubernetes CRD formats.

Supported Formats:
- Kubernetes CRD format (e.g., cis_benchmark.json)
- Multiple reports in dict format (all_reports_in_dict)

Scanner Detection:
- Checks for apiVersion starting with 'aquasecurity.github.io'
- OR checks for keys ending with 'aquasecurity.github.io'

Asset Type: CONTAINER
"""

import json
import logging
from typing import Any, Dict, List

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class TrivyOperatorTranslator(ScannerTranslator):
    """Translator for Trivy Operator Kubernetes CRD formats"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Trivy Operator report"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Trivy Operator signatures
            if isinstance(file_content, dict):
                # CRD format (cis_benchmark.json)
                if file_content.get('apiVersion', '').startswith('aquasecurity.github.io'):
                    return True
                
                # All reports in dict format
                if any(key.endswith('aquasecurity.github.io') for key in file_content.keys()):
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"TrivyOperatorTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Trivy Operator report"""
        logger.info(f"Parsing Trivy Operator report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check format
            if data.get('apiVersion', '').startswith('aquasecurity.github.io'):
                # CRD format (single resource)
                return self._parse_crd_format(data)
            elif any(key.endswith('aquasecurity.github.io') for key in data.keys()):
                # Multiple reports in dict
                return self._parse_all_reports_format(data)
            
            return []
        
        except Exception as e:
            logger.error(f"Error parsing Trivy Operator report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_crd_format(self, data: Dict) -> List[AssetData]:
        """Parse Kubernetes CRD format (e.g., cis_benchmark.json)"""
        try:
            kind = data.get('kind', '')
            metadata = data.get('metadata', {})
            status = data.get('status', {})
            
            # Get asset name from metadata
            asset_name = metadata.get('name', 'trivy-operator-report')
            namespace = metadata.get('namespace', 'default')
            
            # Parse findings based on kind
            findings = []
            
            if 'Compliance' in kind or 'Benchmark' in kind:
                # Compliance/Benchmark report
                summary = status.get('summary', {})
                
                # Get detailed checks
                checks = status.get('detailReport', {}).get('results', [])
                
                for check in checks:
                    if isinstance(check, dict):
                        check_id = check.get('id', check.get('checkID', 'unknown'))
                        severity = check.get('severity', 'MEDIUM')
                        status_check = check.get('status', 'FAIL')
                        
                        if status_check in ['FAIL', 'ERROR']:
                            vuln = VulnerabilityData(
                                name=f"CIS-{check_id}",
                                description=check.get('description', check.get('title', f"CIS check {check_id} failed")),
                                remedy=check.get('remediation', 'Follow CIS benchmark recommendations'),
                                severity=self._map_trivy_severity(severity),
                                location=f"{namespace}/{asset_name}",
                                reference_ids=[check_id]
                            )
                            findings.append(vuln)
            
            elif 'Vulnerability' in kind:
                # Vulnerability report
                vulnerabilities = status.get('vulnerabilities', [])
                
                for vuln_data in vulnerabilities:
                    if isinstance(vuln_data, dict):
                        vuln_id = vuln_data.get('vulnerabilityID', 'unknown')
                        vuln = VulnerabilityData(
                            name=vuln_id,
                            description=vuln_data.get('title', vuln_id),
                            remedy=vuln_data.get('fixedVersion', 'Update package'),
                            severity=self._map_trivy_severity(vuln_data.get('severity', 'MEDIUM')),
                            location=vuln_data.get('resource', asset_name),
                            reference_ids=[vuln_id]
                        )
                        findings.append(vuln)
            
            # Create asset
            asset = AssetData(
                asset_type='CONTAINER',
                attributes={
                    'dockerfile': 'Dockerfile',
                    'origin': 'trivy-operator',
                    'repository': asset_name,
                    'namespace': namespace,
                    'kind': kind
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy-operator"},
                    {"key": "namespace", "value": namespace},
                    {"key": "kind", "value": kind}
                ]
            )
            
            # Add findings
            for finding in findings:
                asset.findings.append(finding.__dict__)
            
            return [self.ensure_asset_has_findings(asset)]
        
        except Exception as e:
            logger.error(f"Error parsing CRD format: {e}")
            return []
    
    def _parse_all_reports_format(self, data: Dict) -> List[AssetData]:
        """Parse all_reports_in_dict format"""
        try:
            assets = []
            
            for report_type, reports in data.items():
                if not isinstance(reports, (list, dict)):
                    continue
                
                # Convert single dict to list
                if isinstance(reports, dict):
                    reports = [reports]
                
                for report in reports:
                    if isinstance(report, dict):
                        # Parse each report as a CRD
                        parsed = self._parse_crd_format(report)
                        assets.extend(parsed)
            
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing all_reports format: {e}")
            return []
    
    def _map_trivy_severity(self, severity: str) -> str:
        """Map Trivy severity to Phoenix decimal"""
        mapping = {
            'CRITICAL': '10.0',
            'HIGH': '8.0',
            'MEDIUM': '5.0',
            'LOW': '3.0',
            'UNKNOWN': '0.0',
            'INFO': '0.0'
        }
        return mapping.get(str(severity).upper(), '5.0')


__all__ = ['TrivyOperatorTranslator']

