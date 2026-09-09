#!/usr/bin/env python3
"""
Snyk Issues API Scanner Translator
===================================

Translator for Snyk Issues API format (JSON:API 1.0 standard).

Supported Formats:
- JSON:API 1.0 format with 'jsonapi' and 'data' fields
- Data array containing Snyk issues with 'type' and 'attributes'

Scanner Detection:
- 'jsonapi' dict with version '1.0'
- 'data' array with items having 'type' and 'attributes'

Asset Type: BUILD

Note: This is different from Snyk CLI format - this handles Snyk API responses.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class SnykIssueAPITranslator(ScannerTranslator):
    """Translator for Snyk Issues API format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Snyk Issues API JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Snyk API uses JSON:API format
            if isinstance(file_content, dict):
                if 'jsonapi' in file_content and 'data' in file_content:
                    jsonapi = file_content.get('jsonapi', {})
                    if isinstance(jsonapi, dict) and jsonapi.get('version') == '1.0':
                        # Check if data contains issues
                        data = file_content.get('data', [])
                        if isinstance(data, list):
                            if len(data) == 0:
                                # Empty results still valid Snyk
                                return True
                            if len(data) > 0 and isinstance(data[0], dict):
                                # Check for Snyk issue structure
                                if 'type' in data[0] and 'attributes' in data[0]:
                                    return True
            
            return False
        except Exception as e:
            logger.debug(f"SnykIssueAPITranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Snyk Issues API JSON file"""
        logger.info(f"Parsing Snyk Issues API file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            issues = data.get('data', [])
            if not issues:
                logger.info("No issues found in Snyk API response")
                return []
            
            # Group by project
            issues_by_project = {}
            
            for issue in issues:
                attributes = issue.get('attributes', {})
                relationships = issue.get('relationships', {})
                
                # Get project from relationships
                project_data = relationships.get('scan_item', {}).get('data', {})
                project_id = project_data.get('id', 'unknown-project')
                
                if project_id not in issues_by_project:
                    issues_by_project[project_id] = []
                
                vuln = self._parse_issue(issue)
                if vuln:
                    issues_by_project[project_id].append(vuln)
            
            # Create assets
            assets = []
            for project_id, vulnerabilities in issues_by_project.items():
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'buildFile': 'package.json',
                        'origin': 'snyk-api',
                        'project_id': project_id
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "snyk-api"}
                    ]
                )
                
                for vuln_dict in vulnerabilities:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} projects with {sum(len(a.findings) for a in assets)} issues from Snyk API")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Snyk API: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a Snyk issue"""
        try:
            attributes = issue.get('attributes', {})
            
            # Get issue details
            title = attributes.get('title', 'Unknown Issue')
            issue_type = attributes.get('type', 'vulnerability')
            
            # Get severity
            severity_str = attributes.get('severity', 'medium')
            effective_severity_str = attributes.get('effective_severity_level', severity_str)
            severity = self.normalize_severity(effective_severity_str)
            
            # Get description
            description = attributes.get('description', title)
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get problem details
            problems = attributes.get('problems', [])
            problem_text = ""
            if problems:
                problem_text = " | ".join([p.get('source', '') for p in problems if p.get('source')])[:200]
            
            if problem_text:
                description = f"{description}\nAffects: {problem_text}"
            
            # Build remedy
            remedy = "Update the affected package to a non-vulnerable version. See Snyk for detailed remediation."
            
            # Get key
            key = attributes.get('key', 'SNYK-UNKNOWN')
            
            return {
                'name': key,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': issue_type,
                'reference_ids': [key],
                'details': {
                    'issue_type': issue_type,
                    'title': title
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Snyk issue: {e}")
            return None


__all__ = ['SnykIssueAPITranslator']

