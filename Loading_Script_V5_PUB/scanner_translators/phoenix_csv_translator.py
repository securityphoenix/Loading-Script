#!/usr/bin/env python3
"""
Phoenix Native CSV Translator
Handles Phoenix Security's native CSV export format for all asset types (INFRA, CLOUD, WEB, SOFTWARE/BUILD)
"""

import csv
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class PhoenixCSVTranslator:
    """Translator for Phoenix Security native CSV format"""
    
    # Phoenix CSV column mappings by asset type
    PHOENIX_CSV_COLUMNS = {
        'INFRA': ['a_id', 'a_subtype', 'at_ip', 'at_network', 'at_hostname', 'at_netbios', 
                  'at_os', 'at_mac', 'at_fqdn', 'a_tags'],
        'CLOUD': ['a_id', 'a_subtype', 'at_provider_type', 'at_provider_resource_id', 'at_vpc', 
                  'at_subnet', 'at_region', 'at_resource_group', 'at_provider_asset_id', 'a_tags'],
        'WEB': ['a_id', 'a_subtype', 'at_ip', 'at_fqdn', 'a_tags'],
        'SOFTWARE': ['a_id', 'a_subtype', 'a_resource_type', 'at_origin', 'at_repository', 'at_build', 
                     'at_dockerfile', 'at_scanner_source', 'at_image_digest', 'at_image_name', 
                     'at_registry', 'a_tags']
    }
    
    # Common vulnerability columns across all types
    VULN_COLUMNS = ['v_name', 'v_description', 'v_remedy', 'v_severity', 'v_cve', 'v_cwe', 
                    'v_published_datetime', 'v_tags', 'v_details', 'v_location']
    
    def __init__(self, scanner_config, tag_config, asset_type: str = 'INFRA'):
        """
        Initialize Phoenix CSV translator
        
        Args:
            scanner_config: Scanner configuration
            tag_config: Tag configuration
            asset_type: Asset type (INFRA, CLOUD, WEB, SOFTWARE/BUILD)
        """
        self.scanner_config = scanner_config
        self.tag_config = tag_config
        self.asset_type = asset_type.upper()
        
        logger.info(f"🔧 Initialized PhoenixCSVTranslator for {self.asset_type} assets")
    
    def can_handle(self, file_path: str) -> bool:
        """Check if this translator can handle the file"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames or []
                
                # Check for Phoenix CSV headers (must have a_id and v_name at minimum)
                has_asset_id = 'a_id' in headers
                has_vuln_name = 'v_name' in headers
                
                return has_asset_id and has_vuln_name
        except Exception as e:
            logger.debug(f"Cannot handle {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str, asset_name_override: Optional[str] = None) -> List:
        """
        Parse Phoenix native CSV file
        
        Args:
            file_path: Path to CSV file
            asset_name_override: Optional user-provided asset name
            
        Returns:
            List of AssetData objects
        """
        logger.info(f"📄 Parsing Phoenix CSV: {file_path} (Type: {self.asset_type})")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            logger.info(f"📋 Read {len(rows)} rows from CSV")
            
            # Group vulnerabilities by asset
            assets_dict = {}
            
            for row_num, row in enumerate(rows, start=2):  # Start at 2 (header is row 1)
                try:
                    # Extract vulnerability data
                    finding = self._extract_vulnerability(row)
                    if not finding:
                        logger.debug(f"Row {row_num}: No vulnerability data, skipping")
                        continue
                    
                    # Extract or generate asset identifier
                    asset_key = self._get_asset_key(row, row_num, asset_name_override)
                    
                    # Initialize asset if not seen before
                    if asset_key not in assets_dict:
                        assets_dict[asset_key] = {
                            'attributes': self._extract_asset_attributes(row, asset_key, asset_name_override),
                            'tags': self._extract_tags(row.get('a_tags', '')),
                            'findings': []
                        }
                    
                    # Add finding to asset
                    assets_dict[asset_key]['findings'].append(finding)
                    
                except Exception as e:
                    logger.warning(f"Row {row_num}: Error parsing row: {e}")
                    continue
            
            # Convert to AssetData objects
            from phoenix_import_refactored import AssetData
            assets = []
            
            for asset_key, asset_data in assets_dict.items():
                asset = AssetData(
                    asset_type=self.asset_type,
                    attributes=asset_data['attributes'],
                    tags=asset_data['tags'],
                    findings=asset_data['findings']
                )
                assets.append(asset)
            
            logger.info(f"✅ Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
            return assets
            
        except Exception as e:
            logger.error(f"❌ Failed to parse Phoenix CSV: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return []
    
    def _get_asset_key(self, row: Dict, row_num: int, asset_name_override: Optional[str]) -> str:
        """
        Generate a unique asset key from row data
        
        Priority:
        1. User-provided asset name override (all vulnerabilities go to one asset)
        2. Asset identifier from CSV (IP, hostname, ARN, etc.)
        3. Generic auto-generated name per vulnerability
        """
        # If user provided an asset name, use it for ALL rows
        if asset_name_override:
            return f"USER-PROVIDED-{asset_name_override}"
        
        # Try to extract asset identifier from CSV
        if self.asset_type == 'INFRA':
            ip = row.get('at_ip', '').strip()
            hostname = row.get('at_hostname', '').strip()
            
            if ip:
                return f"INFRA-IP-{ip}"
            elif hostname:
                return f"INFRA-HOST-{hostname}"
        
        elif self.asset_type == 'CLOUD':
            provider = row.get('at_provider_type', '').strip()
            resource_id = row.get('at_provider_resource_id', '').strip()
            
            if provider and resource_id:
                return f"CLOUD-{provider}-{resource_id}"
        
        elif self.asset_type == 'WEB':
            ip = row.get('at_ip', '').strip()
            fqdn = row.get('at_fqdn', '').strip()
            
            if ip:
                return f"WEB-IP-{ip}"
            elif fqdn:
                return f"WEB-FQDN-{fqdn}"
        
        elif self.asset_type in ['SOFTWARE', 'BUILD', 'CODE', 'REPOSITORY', 'CONTAINER']:
            repo = row.get('at_repository', '').strip()
            scanner_source = row.get('at_scanner_source', '').strip()
            
            if repo:
                return f"SOFTWARE-REPO-{repo}"
            elif scanner_source:
                return f"SOFTWARE-SOURCE-{scanner_source}"
        
        # No asset identifier found - create one asset per vulnerability
        vuln_cve = row.get('v_cve', '').strip()
        vuln_name = row.get('v_name', '').strip()
        
        if vuln_cve:
            return f"GENERIC-ASSET-{vuln_cve}-ROW{row_num}"
        elif vuln_name:
            # Truncate and sanitize
            safe_name = vuln_name[:50].replace(' ', '-').replace('/', '-')
            return f"GENERIC-ASSET-{safe_name}-ROW{row_num}"
        else:
            return f"GENERIC-ASSET-ROW{row_num}"
    
    def _extract_asset_attributes(self, row: Dict, asset_key: str, 
                                   asset_name_override: Optional[str]) -> Dict[str, str]:
        """Extract asset attributes from CSV row"""
        
        attributes = {}
        
        if self.asset_type == 'INFRA':
            ip = row.get('at_ip', '').strip()
            hostname = row.get('at_hostname', '').strip()
            
            # Use provided values, or fallback to placeholders
            attributes['ip'] = ip if ip else '0.0.0.0'
            attributes['hostname'] = hostname if hostname else (asset_name_override or 'Phoenix-import')
            
            # Optional fields
            if row.get('at_network'):
                attributes['network'] = row['at_network']
            if row.get('at_fqdn'):
                attributes['fqdn'] = row['at_fqdn']
            if row.get('at_os'):
                attributes['os'] = row['at_os']
            if row.get('at_netbios'):
                attributes['netbios'] = row['at_netbios']
            if row.get('at_mac'):
                attributes['macAddress'] = row['at_mac']
        
        elif self.asset_type == 'CLOUD':
            provider = row.get('at_provider_type', '').strip()
            resource_id = row.get('at_provider_resource_id', '').strip()
            region = row.get('at_region', '').strip()
            
            attributes['providerType'] = provider if provider else 'AWS'
            attributes['providerAccountId'] = resource_id if resource_id else f'arn:aws:unknown::{asset_name_override or "phoenix-import"}'
            attributes['region'] = region if region else 'us-east-1'
            
            # Optional fields
            if row.get('at_vpc'):
                attributes['vpc'] = row['at_vpc']
            if row.get('at_subnet'):
                attributes['subnet'] = row['at_subnet']
            if row.get('at_resource_group'):
                attributes['resourceGroup'] = row['at_resource_group']
            if row.get('at_provider_asset_id'):
                attributes['providerAssetId'] = row['at_provider_asset_id']
        
        elif self.asset_type == 'WEB':
            ip = row.get('at_ip', '').strip()
            fqdn = row.get('at_fqdn', '').strip()
            
            # WEB requires at least one of IP or FQDN
            if ip:
                attributes['ip'] = ip
            if fqdn:
                attributes['fqdn'] = fqdn
            
            # If neither, use placeholders
            if not ip and not fqdn:
                attributes['fqdn'] = asset_name_override or 'phoenix-import.local'
        
        elif self.asset_type in ['SOFTWARE', 'BUILD', 'CODE', 'REPOSITORY', 'CONTAINER']:
            repo = row.get('at_repository', '').strip()
            build = row.get('at_build', '').strip()
            dockerfile = row.get('at_dockerfile', '').strip()
            scanner_source = row.get('at_scanner_source', '').strip()
            
            attributes['repository'] = repo if repo else (asset_name_override or 'phoenix-import/unknown')
            
            if build:
                attributes['buildFile'] = build
            if dockerfile:
                attributes['dockerfile'] = dockerfile
            if scanner_source:
                attributes['scannerSource'] = scanner_source
            if row.get('at_origin'):
                attributes['origin'] = row['at_origin']
            if row.get('at_image_name'):
                attributes['imageName'] = row['at_image_name']
            if row.get('at_registry'):
                attributes['registry'] = row['at_registry']
        
        return attributes
    
    def _extract_vulnerability(self, row: Dict) -> Optional[Dict]:
        """Extract vulnerability data from CSV row"""
        
        v_name = row.get('v_name', '').strip()
        if not v_name:
            return None
        
        # Required fields
        finding = {
            'name': v_name,
            'description': row.get('v_description', v_name),
            'remedy': row.get('v_remedy', 'Please refer to vendor security advisory for remediation steps.'),
            'severity': self._parse_severity(row.get('v_severity', '5'))
        }
        
        # Optional fields - CVE/CWE as arrays
        cve = row.get('v_cve', '').strip()
        if cve:
            finding['referenceIds'] = [cve]
        
        cwe = row.get('v_cwe', '').strip()
        if cwe:
            # Ensure CWE format
            if not cwe.startswith('CWE-'):
                cwe = f'CWE-{cwe}'
            finding['cwes'] = [cwe]
        
        # Published datetime
        published = row.get('v_published_datetime', '').strip()
        if published:
            finding['publishedDateTime'] = published
        
        # Location (for CODE assets)
        location = row.get('v_location', '').strip()
        if location:
            finding['location'] = location
        
        # Details (JSON object)
        details = row.get('v_details', '').strip()
        if details:
            try:
                finding['details'] = json.loads(details)
            except json.JSONDecodeError:
                finding['details'] = {'raw': details}
        
        # Tags
        v_tags = row.get('v_tags', '').strip()
        if v_tags:
            try:
                tags = json.loads(v_tags)
                finding['tags'] = tags
            except json.JSONDecodeError:
                pass
        
        return finding
    
    def _extract_tags(self, tags_str: str) -> List[Dict]:
        """Parse tags from JSON string"""
        if not tags_str or not tags_str.strip():
            return []
        
        try:
            tags = json.loads(tags_str)
            
            # Handle both array of strings and array of objects
            result = []
            for tag in tags:
                if isinstance(tag, str):
                    result.append({'value': tag})
                elif isinstance(tag, dict):
                    result.append(tag)
            
            return result
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse tags: {tags_str}")
            return []
    
    def _parse_severity(self, severity_str: str) -> str:
        """Parse severity value (1-10 as string)"""
        try:
            severity = float(severity_str)
            # Ensure it's between 1 and 10
            severity = max(1.0, min(10.0, severity))
            return str(severity)
        except (ValueError, TypeError):
            return "5.0"  # Default to medium
    
    @staticmethod
    def detect_asset_type_from_file(file_path: str) -> Optional[str]:
        """Auto-detect asset type from filename or CSV columns"""
        filename = Path(file_path).stem.lower()
        
        # Filename-based detection
        if 'infra' in filename:
            return 'INFRA'
        elif 'cloud' in filename:
            return 'CLOUD'
        elif 'web' in filename:
            return 'WEB'
        elif any(x in filename for x in ['software', 'build', 'code', 'container', 'repository']):
            return 'SOFTWARE'
        
        # Column-based detection
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                headers = set(reader.fieldnames or [])
                
                # Check for specific asset type columns
                if 'at_provider_type' in headers:
                    return 'CLOUD'
                elif 'at_repository' in headers or 'at_dockerfile' in headers:
                    return 'SOFTWARE'
                elif 'at_fqdn' in headers and 'at_ip' in headers and 'v_location' in headers:
                    return 'WEB'
                elif 'at_ip' in headers and 'at_hostname' in headers:
                    return 'INFRA'
        except Exception:
            pass
        
        # Default to INFRA
        return 'INFRA'


