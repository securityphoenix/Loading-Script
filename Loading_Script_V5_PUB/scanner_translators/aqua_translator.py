#!/usr/bin/env python3
"""
Aqua Security Scanner Translator
==================================

Translator for Aqua Security container vulnerability scanner.

Supported Formats:
- JSON output from Aqua scanner

Scanner Detection:
- Checks for Aqua-specific fields: 'image', 'resources', 'vulnerability_summary', 'aqua_score'
- Excludes Grype files (checks descriptor.name != 'grype')

Asset Type: CONTAINER
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class AquaTranslator(ScannerTranslator):
    """Translator for Aqua Security scanner results"""
    
    def _convert_date_to_iso8601(self, date_str: str) -> str:
        """Convert various date formats to ISO-8601 format (YYYY-MM-DDTHH:MM:SS)"""
        if not date_str:
            return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        # Try various date formats
        formats = [
            "%Y-%m-%dT%H:%M:%S",      # Already ISO-8601 with time
            "%Y-%m-%dT%H:%M:%SZ",     # ISO-8601 with Z
            "%Y-%m-%d %H:%M:%S",      # Space separated
            "%Y-%m-%d",               # Date only
            "%d/%m/%Y",               # European format
            "%m/%d/%Y",               # US format
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.strftime("%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue
        
        # If no format matches, return current time
        logger.warning(f"Could not parse date '{date_str}', using current time")
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is an Aqua scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Aqua-specific fields (but NOT Grype fields)
            if isinstance(file_content, dict):
                # Exclude Grype files
                if 'descriptor' in file_content:
                    descriptor = file_content.get('descriptor', {})
                    if isinstance(descriptor, dict) and descriptor.get('name', '').lower() == 'grype':
                        return False
                
                # Check for Aqua-specific fields
                aqua_indicators = ['image', 'resources', 'vulnerability_summary', 'aqua_score', 'aqua_severity']
                return any(indicator in str(file_content) for indicator in aqua_indicators)
            
            return False
        except Exception as e:
            logger.debug(f"AquaTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str, asset_name_override: str = None) -> List[AssetData]:
        """Parse Aqua scan results
        
        Args:
            file_path: Path to the Aqua scan JSON file
            asset_name_override: Optional custom asset name to use instead of the one from the file
        """
        logger.info(f"Parsing Aqua scan file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse Aqua file: {e}")
            raise
        
        assets = []
        
        # Extract image information - use override if provided
        if asset_name_override:
            image_name = asset_name_override
            logger.info(f"🏷️ Using custom asset name: {image_name}")
        else:
            image_name = data.get('image', 'unknown-image')
            logger.info(f"📦 Using asset name from file: {image_name}")
        image_digest = data.get('digest', '')
        os_info = f"{data.get('os', '')} {data.get('version', '')}".strip()
        
        # Create container asset
        asset_attributes = {
            'dockerfile': 'Dockerfile',
            'origin': 'aqua-scan'
        }
        
        if image_name:
            asset_attributes['repository'] = image_name
        
        # Build tags conditionally - only add tags with non-empty values
        aqua_tags = [{"key": "scanner", "value": "aqua"}]
        
        # Only add image-digest if it exists
        if image_digest and str(image_digest).strip():
            aqua_tags.append({"key": "image-digest", "value": image_digest[:16]})
        
        # Only add os if it's not empty/unknown
        if os_info and str(os_info).strip() and os_info != "unknown":
            aqua_tags.append({"key": "os", "value": os_info})
        
        # Combine all tags and filter out any with empty values
        all_tags = self.tag_config.get_all_tags() + aqua_tags
        filtered_tags = [
            tag for tag in all_tags 
            if tag.get("value") and str(tag.get("value")).strip()
        ]
        
        asset = AssetData(
            asset_type="CONTAINER",
            attributes=asset_attributes,
            tags=filtered_tags
        )
        
        # Process vulnerabilities from resources
        resources = data.get('resources', [])
        for resource in resources:
            resource_info = resource.get('resource', {})
            vulnerabilities = resource.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                # Convert dates to ISO-8601 format
                publish_date = vuln.get('publish_date', '')
                published_date_time = self._convert_date_to_iso8601(publish_date) if publish_date else None
                
                # Create vulnerability
                vulnerability = VulnerabilityData(
                    name=vuln.get('name', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    remedy=vuln.get('solution', 'No solution provided'),
                    severity=self.normalize_severity(vuln.get('aqua_severity', vuln.get('nvd_severity', 'medium'))),
                    location=f"{resource_info.get('name', '')}:{resource_info.get('version', '')}",
                    reference_ids=[vuln.get('name', '')] if vuln.get('name', '').startswith('CVE-') else [],
                    published_date_time=published_date_time,
                    details={
                        'package_name': resource_info.get('name', ''),
                        'package_version': resource_info.get('version', ''),
                        'package_format': resource_info.get('format', ''),
                        'package_arch': resource_info.get('arch', ''),
                        'nvd_score': vuln.get('nvd_score', ''),
                        'nvd_score_v3': vuln.get('nvd_score_v3', ''),
                        'aqua_score': vuln.get('aqua_score', ''),
                        'fix_version': vuln.get('fix_version', ''),
                        'nvd_url': vuln.get('nvd_url', ''),
                        'vendor_severity': vuln.get('vendor_severity', ''),
                        'modification_date': self._convert_date_to_iso8601(vuln.get('modification_date', '')) if vuln.get('modification_date') else ''
                    }
                )
                
                asset.findings.append(vulnerability.__dict__)
        
        assets.append(self.ensure_asset_has_findings(asset))
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


__all__ = ['AquaTranslator']

