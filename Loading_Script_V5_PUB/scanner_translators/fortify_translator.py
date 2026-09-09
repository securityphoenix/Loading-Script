#!/usr/bin/env python3
"""
Fortify Translator
==================

Translator for Micro Focus Fortify SCA (Static Code Analyzer) XML reports.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class FortifyXMLTranslator(ScannerTranslator):
    """Translator for Fortify XML report exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Fortify XML report"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            # Fortify XML has ReportDefinition root or specific Fortify elements
            return root.tag == 'ReportDefinition' or 'Fortify' in ET.tostring(root, encoding='unicode')[:500]
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Fortify XML report"""
        logger.info(f"Parsing Fortify XML: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Try to find issues/vulnerabilities in various Fortify XML structures
            issues = []
            
            # Try ReportSection > IssueListing > Chart > GroupingSection > Issue
            for issue_elem in root.findall('.//Issue'):
                issues.append(self._parse_fortify_issue(issue_elem))
            
            # Try alternate paths
            if not issues:
                for issue_elem in root.findall('.//Vulnerability'):
                    issues.append(self._parse_fortify_issue(issue_elem))
            
            # Group by file/location
            file_issues = {}
            for issue in issues:
                if issue:
                    location = issue.get('location', 'Unknown')
                    if location not in file_issues:
                        file_issues[location] = []
                    file_issues[location].append(issue)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if file_issues:
                for location, location_issues in file_issues.items():
                    findings = []
                    for issue in location_issues:
                        findings.append(VulnerabilityData(
                            name=issue.get('category', 'Security Finding'),
                            description=issue.get('abstract', issue.get('category', 'Fortify finding')),
                            remedy=issue.get('recommendation', 'Review and fix security vulnerability'),
                            severity=issue.get('severity', '5.0'),
                            location=location,
                            reference_ids=[issue.get('instanceId', '')]
                        ).__dict__)
                    
                    asset = AssetData(
                        asset_type='CODE',
                        attributes={
                            'filePath': location,
                            'scanner': 'Fortify'
                        },
                        findings=findings,
                        tags=tags + [{"key": "scanner", "value": "fortify"}]
                    )
                    assets.append(self.ensure_asset_has_findings(asset))
            else:
                # No issues found - create placeholder
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'filePath': 'Fortify Scan',
                        'scanner': 'Fortify'
                    },
                    findings=[VulnerabilityData(
                        name="FORTIFY_SCAN_COMPLETE",
                        description="Fortify scan completed with no critical findings",
                        remedy="No action required",
                        severity="0.0",
                        location="Fortify report"
                    ).__dict__],
                    tags=tags + [{"key": "scanner", "value": "fortify"}]
                )
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Created {len(assets)} assets from Fortify")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing Fortify XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_fortify_issue(self, issue_elem: ET.Element) -> Dict[str, Any]:
        """Parse a single Fortify issue element"""
        try:
            # Extract various fields that might be present
            issue = {}
            
            # Try to get category/type
            category = issue_elem.find('.//Category')
            if category is not None:
                issue['category'] = category.text
            elif issue_elem.get('type'):
                issue['category'] = issue_elem.get('type')
            else:
                issue['category'] = 'Security Issue'
            
            # Try to get abstract/description
            abstract = issue_elem.find('.//Abstract')
            if abstract is not None:
                issue['abstract'] = abstract.text
            
            # Try to get recommendation
            recommendation = issue_elem.find('.//Recommendation')
            if recommendation is not None:
                issue['recommendation'] = recommendation.text
            
            # Try to get severity
            severity = issue_elem.find('.//Severity')
            priority = issue_elem.find('.//Priority')
            if severity is not None:
                issue['severity'] = self._map_fortify_severity(severity.text)
            elif priority is not None:
                issue['severity'] = self._map_fortify_priority(priority.text)
            else:
                issue['severity'] = '5.0'
            
            # Try to get location
            location = issue_elem.find('.//FilePath')
            source_file = issue_elem.find('.//SourceFile')
            if location is not None:
                issue['location'] = location.text
            elif source_file is not None:
                issue['location'] = source_file.text
            else:
                issue['location'] = 'Code'
            
            # Try to get instance ID
            instance_id = issue_elem.find('.//InstanceID')
            if instance_id is not None:
                issue['instanceId'] = instance_id.text
            else:
                issue['instanceId'] = issue.get('category', '')[:20]
            
            return issue
        except Exception as e:
            logger.debug(f"Error parsing Fortify issue element: {e}")
            return {}
    
    def _map_fortify_severity(self, severity: str) -> str:
        """Map Fortify severity to Phoenix decimal"""
        try:
            # Try numeric severity first
            score = float(severity)
            return str(score)
        except:
            pass
        
        # Map text severity
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')
    
    def _map_fortify_priority(self, priority: str) -> str:
        """Map Fortify priority to Phoenix decimal"""
        mapping = {
            '1': '10.0',
            '2': '8.0',
            '3': '5.0',
            '4': '3.0',
            '5': '1.0'
        }
        return mapping.get(priority.strip(), '5.0')


# Export
__all__ = ['FortifyXMLTranslator']

