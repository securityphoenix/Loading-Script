#!/usr/bin/env python3
"""
GitLab Secret Detection Translator
==================================

Translator for GitLab Secret Detection scanner reports.

Supported Formats:
------------------
- **GitLab Secret Detection JSON** - Standard security report format
  - Structure: {"scan": {...}, "vulnerabilities": [...]}
  - Scan type: "secret_detection"

Scanner Detection:
-----------------
- File extension: .json
- Has 'scan' and 'vulnerabilities' keys
- scan.type == 'secret_detection'

Asset Type: CODE
Grouping: By file path
"""

import json
import logging
from typing import Any, Dict, List

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData, VulnerabilityData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class GitLabSecretDetectionTranslator(ScannerTranslator):
    """
    Translator for GitLab Secret Detection reports
    
    Handles GitLab's standardized security report format for secret detection.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect GitLab Secret Detection format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is GitLab Secret Detection format
        """
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # GitLab security reports have specific schema
            if isinstance(data, dict):
                has_scan = 'scan' in data
                has_vulnerabilities = 'vulnerabilities' in data
                scan_type = data.get('scan', {}).get('type', '')
                return has_scan and has_vulnerabilities and scan_type == 'secret_detection'
            return False
        except Exception as e:
            logger.debug(f"GitLabSecretDetectionTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse GitLab Secret Detection report
        
        Args:
            file_path: Path to the GitLab Secret Detection JSON file
            
        Returns:
            List of AssetData objects with secret findings
        """
        logger.info(f"Parsing GitLab Secret Detection report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', [])
            scan_info = data.get('scan', {})
            scanner_name = scan_info.get('scanner', {}).get('name', 'GitLab Secret Detection')
            
            # Group secrets by file/location
            file_secrets = {}
            for vuln in vulnerabilities:
                location_info = vuln.get('location', {})
                file_path_val = location_info.get('file', location_info.get('dependency', {}).get('path', 'unknown'))
                
                if file_path_val not in file_secrets:
                    file_secrets[file_path_val] = []
                
                secret_name = vuln.get('name', 'Secret Detected')
                severity = vuln.get('severity', 'Medium')
                
                file_secrets[file_path_val].append(VulnerabilityData(
                    name=f"SECRET-{vuln.get('id', 'DETECTED')[:8]}",
                    description=f"{secret_name}: {vuln.get('message', 'Secret detected in repository')}",
                    remedy=vuln.get('solution', 'Remove secret from repository and rotate credentials'),
                    severity=self._map_gitlab_severity(severity),
                    location=file_path_val,
                    reference_ids=[vuln.get('id', '')[:8]],
                    details={
                        'category': vuln.get('category', 'secret_detection'),
                        'scanner': scanner_name,
                        'confidence': vuln.get('confidence', 'UNKNOWN')
                    }
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if file_secrets:
                for file_path_val, secrets in file_secrets.items():
                    asset = AssetData(
                        asset_type='CODE',
                        attributes={
                            'filePath': file_path_val,
                            'repository': 'GitLab',
                            'scanner': scanner_name
                        },
                        findings=secrets,
                        tags=tags + [{"key": "scanner", "value": "gitlab-secret-detection"}]
                    )
                    assets.append(asset)
            else:
                # No secrets found - create one asset to indicate clean scan
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'filePath': 'Repository',
                        'repository': 'GitLab',
                        'scanner': scanner_name
                    },
                    findings=[VulnerabilityData(
                        name="NO_SECRETS_FOUND",
                        description="No secrets detected in repository",
                        remedy="No action required",
                        severity="0.0",
                        location="Repository scan"
                    )],
                    tags=tags + [{"key": "scanner", "value": "gitlab-secret-detection"}]
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from GitLab Secret Detection")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing GitLab Secret Detection report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_gitlab_severity(self, severity: str) -> str:
        """
        Map GitLab severity to Phoenix decimal
        
        Args:
            severity: GitLab severity string
            
        Returns:
            Normalized severity decimal string
        """
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'info': '0.0',
            'unknown': '5.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')

