#!/usr/bin/env python3
"""
SonarQube Translator
===================

Consolidated translator for SonarQube scanner outputs.

Supported Formats:
------------------
1. **SonarQube API** - Issues endpoint JSON format
   - Structure: {"issues": [...], "paging": {...}}
   - Fields: key, rule, component, message, severity, type
   
2. **SonarQube Export** - Classic export JSON format
   - Structure: {"issues": [...]} or [...]
   - Legacy format support

Scanner Detection:
-----------------
- File extension: .json
- API format: Has 'issues' + 'paging' with 'key', 'rule', 'component' fields
- Export format: Has issues array with SonarQube-specific structure

Asset Type: CODE
Grouping: By component (source file)
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class SonarQubeTranslator(ScannerTranslator):
    """
    Translator for SonarQube scanner outputs (API and Export formats)
    
    Handles:
    - SonarQube API issues endpoint JSON
    - SonarQube classic export JSON
    - Multiple severity levels and issue types
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect SonarQube format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is SonarQube format
        """
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # SonarQube API format has 'issues' array and specific structure
            if isinstance(file_content, dict):
                if 'issues' in file_content or 'paging' in file_content:
                    # Check if issues have SonarQube-specific fields
                    issues = file_content.get('issues', [])
                    if issues and isinstance(issues, list):
                        first_issue = issues[0] if issues else {}
                        if 'key' in first_issue and 'rule' in first_issue and 'component' in first_issue:
                            return True
            
            # Also support array format
            if isinstance(file_content, list) and file_content:
                first = file_content[0]
                if isinstance(first, dict) and 'rule' in first and 'component' in first:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"SonarQubeTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse SonarQube issues file
        
        Args:
            file_path: Path to the SonarQube JSON file
            
        Returns:
            List of AssetData objects with findings
        """
        logger.info(f"Parsing SonarQube file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle both formats: {"issues": [...]} or [...]
            if isinstance(data, list):
                issues = data
            elif isinstance(data, dict):
                issues = data.get('issues', [])
            else:
                logger.info("Unknown SonarQube format")
                return []
            
            if not issues:
                logger.info("No issues found in SonarQube response")
                return []
            
            # Group by component (file)
            components = {}
            for issue in issues:
                component = issue.get('component', 'unknown')
                if component not in components:
                    components[component] = []
                
                vuln = self._parse_issue(issue)
                if vuln:
                    components[component].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for component, vulns in components.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'name': component,
                        'scanner': 'SonarQube'
                    },
                    tags=tags + [{"key": "scanner", "value": "sonarqube"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} issues from SonarQube")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing SonarQube file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict) -> Optional[Dict]:
        """
        Parse a single SonarQube issue
        
        Args:
            issue: Issue dictionary from SonarQube
            
        Returns:
            Vulnerability dictionary or None
        """
        try:
            key = issue.get('key', 'UNKNOWN')
            rule = issue.get('rule', 'unknown-rule')
            message = issue.get('message', 'Code quality issue')
            severity = issue.get('severity', 'MAJOR')
            type_str = issue.get('type', 'CODE_SMELL')
            
            # Normalize severity (SonarQube: INFO, MINOR, MAJOR, CRITICAL, BLOCKER)
            severity_map = {
                'INFO': 'Low',
                'MINOR': 'Low',
                'MAJOR': 'Medium',
                'CRITICAL': 'High',
                'BLOCKER': 'Critical'
            }
            severity_normalized = self.normalize_severity(severity_map.get(severity, severity))
            
            # Get location
            line = issue.get('line', 0)
            component = issue.get('component', '')
            location = f"{component}:{line}" if line else component
            
            # Build details
            details = {
                'type': type_str,
                'status': issue.get('status', 'OPEN'),
                'creation_date': issue.get('creationDate', '')
            }
            
            # Add optional fields if present
            if 'effort' in issue:
                details['effort'] = issue['effort']
            if 'debt' in issue:
                details['debt'] = issue['debt']
            if 'author' in issue:
                details['author'] = issue['author']
            if 'project' in issue:
                details['project'] = issue['project']
            
            return {
                'name': f"{rule}: {message[:100]}",
                'description': message,
                'remedy': "Fix the code quality issue according to SonarQube rule",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [key, rule],
                'details': details
            }
            
        except Exception as e:
            logger.debug(f"Error parsing SonarQube issue: {e}")
            return None

