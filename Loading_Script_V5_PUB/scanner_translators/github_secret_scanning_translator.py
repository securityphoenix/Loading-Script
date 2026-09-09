#!/usr/bin/env python3
"""
GitHub Secret Scanning Translator
==================================

Translator for GitHub Secret Scanning API reports.

Supported Formats:
------------------
- **GitHub Secret Scanning API JSON** - Array of alert objects
  - Structure: [{number, secret_type, locations_url, state, ...}, ...]
  - Fields: number, secret_type, secret_type_display_name, state, resolution

Scanner Detection:
-----------------
- File extension: .json
- Array format with objects containing 'number', 'secret_type', 'locations_url'

Asset Type: CODE
Grouping: By repository
"""

import json
import logging
from typing import Any, Dict, List

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData, VulnerabilityData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class GitHubSecretScanningTranslator(ScannerTranslator):
    """
    Translator for GitHub Secret Scanning API reports
    
    Handles GitHub's secret scanning alert format from the API.
    Filters out false positives and resolved secrets.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect GitHub Secret Scanning format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is GitHub Secret Scanning format
        """
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # GitHub secret scanning: array of alert objects with specific keys
            if isinstance(data, list):
                if not data:
                    return False  # Empty array, can't determine
                # Check first object has GitHub secret scanning keys
                first = data[0]
                return 'number' in first and 'secret_type' in first and 'locations_url' in first
            return False
        except Exception as e:
            logger.debug(f"GitHubSecretScanningTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse GitHub Secret Scanning report
        
        Args:
            file_path: Path to the GitHub Secret Scanning JSON file
            
        Returns:
            List of AssetData objects with secret findings
        """
        logger.info(f"Parsing GitHub Secret Scanning report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                logger.warning("GitHub Secret Scanning report must be a JSON array")
                return []
            
            # Group secrets by repository (from URL)
            repo_secrets = {}
            for alert in data:
                # Extract repository from URL
                url = alert.get('url', alert.get('html_url', ''))
                if '/repos/' in url:
                    repo_part = url.split('/repos/')[1]
                    repo_name = '/'.join(repo_part.split('/')[:2]) if '/' in repo_part else 'unknown'
                else:
                    repo_name = 'github-repository'
                
                if repo_name not in repo_secrets:
                    repo_secrets[repo_name] = []
                
                alert_number = alert.get('number', 'unknown')
                secret_type = alert.get('secret_type', 'Secret')
                secret_display = alert.get('secret_type_display_name', secret_type)
                state = alert.get('state', 'open')
                resolution = alert.get('resolution', '')
                
                # Skip resolved false positives (not real secrets)
                if state == 'resolved' and resolution == 'false_positive':
                    continue
                
                repo_secrets[repo_name].append(VulnerabilityData(
                    name=f"SECRET-{alert_number}",
                    description=f"{secret_display}: {state}",
                    remedy=f"Revoke and rotate this secret. Resolution: {resolution or 'pending'}",
                    severity=self._map_github_state_to_severity(state, resolution),
                    location=alert.get('html_url', url),
                    reference_ids=[str(alert_number)],
                    details={
                        'secret_type': secret_type,
                        'secret_type_display_name': secret_display,
                        'created_at': alert.get('created_at', ''),
                        'updated_at': alert.get('updated_at', ''),
                        'state': state,
                        'resolution': resolution
                    }
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if repo_secrets:
                for repo_name, secrets in repo_secrets.items():
                    asset = AssetData(
                        asset_type='CODE',
                        attributes={
                            'repository': repo_name,
                            'scanner': 'GitHub Secret Scanning'
                        },
                        findings=secrets,
                        tags=tags + [{"key": "scanner", "value": "github-secret-scanning"}]
                    )
                    assets.append(asset)
            else:
                # No active secrets found
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'repository': 'github-repository',
                        'scanner': 'GitHub Secret Scanning'
                    },
                    findings=[VulnerabilityData(
                        name="NO_ACTIVE_SECRETS",
                        description="No active secrets detected",
                        remedy="No action required",
                        severity="0.0",
                        location="GitHub scan"
                    )],
                    tags=tags + [{"key": "scanner", "value": "github-secret-scanning"}]
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from GitHub Secret Scanning")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing GitHub Secret Scanning report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_github_state_to_severity(self, state: str, resolution: str) -> str:
        """
        Map GitHub secret state to Phoenix decimal
        
        Args:
            state: Secret alert state (open, resolved)
            resolution: Resolution type if resolved
            
        Returns:
            Normalized severity decimal string
        """
        if state == 'open':
            return '10.0'  # Critical - active exposed secret
        elif state == 'resolved':
            if resolution in ['revoked', 'used_in_tests', 'false_positive']:
                return '0.0'  # Fixed or not a real secret
            else:
                return '3.0'  # Resolved but unclear how
        return '5.0'

