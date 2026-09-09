#!/usr/bin/env python3
"""
Scout Suite Scanner Translator
===============================

Translator for Scout Suite JavaScript-wrapped JSON format.

Supported Formats:
- JavaScript files with 'scoutsuite_results = {JSON}' structure
- Extracts JSON from JS and parses cloud security findings

Scanner Detection:
- .js file extension
- Contains 'scoutsuite_results' variable declaration

Asset Type: CLOUD
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class ScoutSuiteTranslator(ScannerTranslator):
    """
    Translator for Scout Suite JavaScript-wrapped JSON format.
    
    Scout Suite outputs JavaScript files with JSON data:
    scoutsuite_results = {JSON DATA HERE}
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Scout Suite JS format"""
        if not file_path.lower().endswith('.js'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 chars
            
            # Check for Scout Suite signature
            if 'scoutsuite_results' in content.lower():
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"ScoutSuiteTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Scout Suite JS file"""
        logger.info(f"Parsing Scout Suite JS file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract JSON from JavaScript
            # Pattern: scoutsuite_results = {JSON}
            match = re.search(r'scoutsuite_results\s*=\s*({.+})', content, re.DOTALL)
            if not match:
                logger.warning("Could not extract JSON from Scout Suite JS file")
                return []
            
            json_str = match.group(1)
            data = json.loads(json_str)
            
            # Parse Scout Suite structure
            account_id = data.get('account_id', 'unknown')
            last_run = data.get('last_run', {})
            
            # Group findings by service
            services = last_run.get('summary', {})
            
            # Create asset per cloud service with findings
            assets = []
            for service_name, service_data in services.items():
                flagged = service_data.get('flagged_items', 0)
                if flagged == 0:
                    continue
                
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'cloud_provider': 'AWS',  # Scout Suite primarily AWS
                        'account_id': account_id,
                        'service': service_name
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "scout-suite"},
                        {"key": "cloud_provider", "value": "aws"}
                    ]
                )
                
                # Create a finding for the service
                vuln_dict = {
                    'name': f"Scout Suite - {service_name} issues",
                    'description': f"Scout Suite found {flagged} flagged items in {service_name}. Review detailed report for specific issues.",
                    'remedy': 'Review Scout Suite report for detailed remediation steps per finding',
                    'severity': 'Medium',
                    'location': service_name,
                    'reference_ids': [f"ScoutSuite-{service_name}"]
                }
                
                vuln_obj = VulnerabilityData(**vuln_dict)
                asset.findings.append(vuln_obj.__dict__)
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} services with findings from Scout Suite")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Scout Suite JS: {e}")
            import traceback
            traceback.print_exc()
            return []


__all__ = ['ScoutSuiteTranslator']

