#!/usr/bin/env python3
"""
AWS Prowler Scanner Translator (Consolidated)
==============================================

Comprehensive translator handling ALL AWS Prowler format variations:
1. Prowler V2: NDJSON format (newline-delimited JSON)
2. Prowler V3: OCSF JSON format (Open Cybersecurity Schema Framework)
3. Prowler V4/V5: OCSF JSON format (enhanced, compatible with V3)
4. Prowler CSV: CSV export format with ACCOUNT_NUM, SEVERITY, etc.

Supported Formats:
- NDJSON (each line is a complete JSON finding)
- OCSF JSON (findings array with metadata)
- CSV (with Prowler-specific columns)

Scanner Detection:
- Auto-detects format variant and routes to appropriate parser

Asset Type: CLOUD (AWS)
"""

import csv
import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class ProwlerTranslator(ScannerTranslator):
    """
    Consolidated translator for all AWS Prowler format variations
    
    Handles 4 distinct format types with automatic detection:
    - Prowler V2 (NDJSON)
    - Prowler V3 (OCSF JSON)
    - Prowler V4/V5 (OCSF JSON enhanced)
    - Prowler CSV
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect any Prowler format"""
        # CSV format
        if self._is_prowler_csv(file_path):
            return True
        
        # JSON/NDJSON formats
        if self._is_prowler_json(file_path, file_content):
            return True
        
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Prowler file (auto-detects format)"""
        logger.info(f"Parsing Prowler file: {file_path}")
        
        try:
            # CSV format
            if file_path.lower().endswith('.csv'):
                return self._parse_csv_format(file_path)
            
            # JSON/NDJSON formats
            elif file_path.lower().endswith(('.json', '.ndjson', '.jsonl', '.ocsf')):
                return self._parse_json_format(file_path)
            
            else:
                logger.warning(f"Unknown Prowler file extension: {file_path}")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing Prowler file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    # ========== FORMAT DETECTORS ==========
    
    def _is_prowler_csv(self, file_path: str) -> bool:
        """Detect Prowler CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                if headers:
                    prowler_cols = ['ACCOUNT_NUM', 'PROFILE', 'SEVERITY', 'STATUS', 'CONTROL_ID', 'SCORED']
                    matches = sum(1 for col in prowler_cols if col in headers)
                    return matches >= 4
            return False
        except:
            return False
    
    def _is_prowler_json(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Prowler JSON/NDJSON format"""
        if not file_path.lower().endswith(('.json', '.ndjson', '.jsonl', '.ocsf')):
            return False
        
        try:
            # Try to load entire file as JSON first (for OCSF multi-line format)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Check if it's a list (OCSF array format)
                if isinstance(data, list):
                    if len(data) > 0 and isinstance(data[0], dict):
                        first_finding = data[0]
                        # Check for OCSF structure with Prowler metadata
                        if 'metadata' in first_finding and 'finding_info' in first_finding:
                            return True
                        # Also check for Prowler product name
                        metadata = first_finding.get('metadata', {})
                        product = metadata.get('product', {})
                        if product.get('name') == 'Prowler':
                            return True
                
                # Check if it's a dict (single OCSF finding)
                elif isinstance(data, dict):
                    # Prowler OCSF single finding
                    if 'metadata' in data and 'finding_info' in data:
                        return True
                    # Check for Prowler product name
                    metadata = data.get('metadata', {})
                    product = metadata.get('product', {})
                    if product.get('name') == 'Prowler':
                        return True
                    # Also check for class_uid (OCSF indicator)
                    if 'class_uid' in data and 'finding_info' in data:
                        return True
            
            except json.JSONDecodeError:
                # If full file isn't valid JSON, try NDJSON (line by line)
                with open(file_path, 'r') as f:
                    first_line = f.readline().strip()
                    if not first_line:
                        return False
                    
                    first_obj = json.loads(first_line)
                    
                    # Prowler V2 (NDJSON): has 'Profile', 'AccountId', 'CheckID'
                    if isinstance(first_obj, dict):
                        if 'Profile' in first_obj and 'AccountId' in first_obj and 'CheckID' in first_obj:
                            return True
            
            return False
        except:
            return False
    
    # ========== FORMAT PARSERS ==========
    
    def _parse_csv_format(self, file_path: str) -> List[AssetData]:
        """Parse Prowler CSV format"""
        logger.info("Detected Prowler CSV format")
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by account and region
            accounts = {}
            for row in rows:
                account_id = row.get('ACCOUNT_NUM', row.get('Account Number', 'unknown'))
                region = row.get('REGION', row.get('Region', 'global'))
                
                key = f"{account_id}:{region}"
                if key not in accounts:
                    accounts[key] = {'account_id': account_id, 'region': region, 'findings': []}
                
                # Only parse failed findings
                status = row.get('CHECK_RESULT', row.get('STATUS', row.get('Status', ''))).upper()
                if status in ['FAIL', 'FAILED']:
                    vuln_dict = self._parse_csv_row(row)
                    if vuln_dict:
                        accounts[key]['findings'].append(vuln_dict)
            
            # Create assets
            assets = []
            for key, data in accounts.items():
                if not data['findings']:
                    continue
                
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'cloud_provider': 'AWS',
                        'account_id': data['account_id'],
                        'region': data['region']
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "prowler"},
                        {"key": "format", "value": "csv"},
                        {"key": "cloud_provider", "value": "aws"}
                    ]
                )
                
                for vuln_dict in data['findings']:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} accounts with {sum(len(a.findings) for a in assets)} findings")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Prowler CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_json_format(self, file_path: str) -> List[AssetData]:
        """Parse Prowler JSON/NDJSON format (auto-detects V2/V3/V4/V5)"""
        try:
            # Try to load entire file as JSON first (OCSF format)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # If it's a valid JSON array or object, it's likely OCSF
                if isinstance(data, list) and len(data) > 0:
                    first_finding = data[0]
                    if 'metadata' in first_finding and 'finding_info' in first_finding:
                        logger.info("Detected Prowler OCSF format (V3/V4/V5)")
                        return self._parse_ocsf_format(data)
                elif isinstance(data, dict):
                    if 'metadata' in data and 'finding_info' in data:
                        logger.info("Detected Prowler OCSF format (V3/V4/V5) - single finding")
                        return self._parse_ocsf_format([data])
            except json.JSONDecodeError:
                # If full file isn't valid JSON, try NDJSON
                pass
            
            # Try NDJSON format (V2)
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if not first_line:
                    return []
                
                first_obj = json.loads(first_line)
                
                # Detect format
                if 'Profile' in first_obj and 'AccountId' in first_obj:
                    logger.info("Detected Prowler V2 (NDJSON) format")
                    return self._parse_v2_ndjson(file_path)
                else:
                    logger.warning("Unknown Prowler JSON format")
                    return []
        
        except Exception as e:
            logger.error(f"Error parsing Prowler JSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_v2_ndjson(self, file_path: str) -> List[AssetData]:
        """Parse Prowler V2 NDJSON format"""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Error reading NDJSON: {e}")
            return []
        
        # Group by account and region
        accounts = {}
        for finding in findings:
            account_id = finding.get('AccountId', 'unknown')
            region = finding.get('Region', 'global')
            
            # Skip PASS findings
            if finding.get('Status', '').upper() == 'PASS':
                continue
            
            key = f"{account_id}:{region}"
            if key not in accounts:
                accounts[key] = {'account_id': account_id, 'region': region, 'findings': []}
            
            vuln_dict = self._parse_v2_finding(finding)
            if vuln_dict:
                accounts[key]['findings'].append(vuln_dict)
        
        # Create assets
        assets = []
        for key, data in accounts.items():
            if not data['findings']:
                continue
            
            asset = AssetData(
                asset_type='CLOUD',
                attributes={
                    'cloud_provider': 'AWS',
                    'account_id': data['account_id'],
                    'region': data['region']
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "prowler"},
                    {"key": "format", "value": "v2-ndjson"},
                    {"key": "cloud_provider", "value": "aws"}
                ]
            )
            
            for vuln_dict in data['findings']:
                vuln_obj = VulnerabilityData(**vuln_dict)
                asset.findings.append(vuln_obj.__dict__)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} accounts with {sum(len(a.findings) for a in assets)} findings from Prowler V2")
        return assets
    
    def _parse_ocsf_format(self, findings: List[Dict]) -> List[AssetData]:
        """Parse Prowler OCSF format (V3/V4/V5)"""
        try:
            # Group by cloud account and region
            accounts = {}
            
            for finding in findings:
                # Skip PASS/MUTED findings
                status = finding.get('status', '')
                status_code = finding.get('status_code', '')
                if status in ['PASS', 'MUTED'] or status_code == 'PASS':
                    continue
                
                # Extract cloud account info
                cloud = finding.get('cloud', {})
                account_info = cloud.get('account', {})
                account_uid = account_info.get('uid', 'unknown')
                region = cloud.get('region', 'global')
                provider = cloud.get('provider', 'AWS')
                
                key = f"{account_uid}:{region}"
                if key not in accounts:
                    accounts[key] = {
                        'account_id': account_uid,
                        'region': region,
                        'provider': provider,
                        'findings': []
                    }
                
                vuln_dict = self._parse_ocsf_finding(finding)
                if vuln_dict:
                    accounts[key]['findings'].append(vuln_dict)
            
            # Create assets
            assets = []
            for key, data in accounts.items():
                if not data['findings']:
                    continue
                
                # Map provider to proper format
                provider_map = {
                    'aws': 'AWS',
                    'azure': 'AZURE',
                    'gcp': 'GCP',
                    'google': 'GCP'
                }
                provider_type = provider_map.get(data['provider'].lower(), 'AWS')
                
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'providerType': provider_type,
                        'providerAccountId': data['account_id'],
                        'region': data['region'],
                        'origin': 'prowler-ocsf'
                    },
                    tags=self.tag_config.get_all_tags() + [
                        {"key": "scanner", "value": "prowler"},
                        {"key": "format", "value": "ocsf"},
                        {"key": "cloud_provider", "value": data['provider'].lower()}
                    ]
                )
                
                for vuln_dict in data['findings']:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} accounts with {sum(len(a.findings) for a in assets)} findings from Prowler OCSF")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Prowler OCSF: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    # ========== FINDING PARSERS ==========
    
    def _parse_csv_row(self, row: Dict) -> Optional[Dict]:
        """Parse Prowler CSV row"""
        control_id = row.get('TITLE_ID', row.get('CONTROL_ID', 'UNKNOWN'))
        control = row.get('TITLE_TEXT', row.get('CONTROL', 'Unknown Control'))
        severity = row.get('CHECK_SEVERITY', row.get('SEVERITY', 'Medium'))
        message = row.get('CHECK_RESULT_EXTENDED', row.get('MESSAGE', ''))
        resource_id = row.get('RESOURCE_ID', '')
        service = row.get('CHECK_SERVICENAME', row.get('SERVICE', ''))
        
        severity_normalized = self.normalize_severity(severity)
        
        description = f"{control}"
        if message:
            description += f"\n{message[:300]}"
        if resource_id:
            description += f"\nResource: {resource_id}"
        
        return {
            'name': control_id,
            'description': description[:500],
            'remedy': "Review and remediate according to AWS best practices",
            'severity': severity_normalized,
            'location': f"{service}:{resource_id}" if resource_id else service,
            'reference_ids': [control_id]
        }
    
    def _parse_v2_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse Prowler V2 finding"""
        check_id = finding.get('CheckID', 'UNKNOWN')
        check_title = finding.get('CheckTitle', 'Security Finding')
        severity = finding.get('Severity', 'medium')
        status_extended = finding.get('StatusExtended', '')
        resource_id = finding.get('ResourceId', '')
        service_name = finding.get('ServiceName', '')
        
        severity_normalized = self.normalize_severity(severity)
        
        description = f"{check_title}"
        if status_extended:
            description += f"\n{status_extended[:300]}"
        
        return {
            'name': check_id,
            'description': description[:500],
            'remedy': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'Review and remediate'),
            'severity': severity_normalized,
            'location': f"{service_name}:{resource_id}" if resource_id else service_name,
            'reference_ids': [check_id]
        }
    
    def _parse_ocsf_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse Prowler OCSF (V3/V4/V5) finding"""
        try:
            # Extract finding info
            finding_info = finding.get('finding_info', {})
            finding_uid = finding_info.get('uid', 'UNKNOWN')
            title = finding_info.get('title', finding.get('message', 'Security Finding'))
            
            # Extract severity
            severity_str = finding.get('severity', 'Medium')
            severity_id = finding.get('severity_id', 3)
            
            # Map OCSF severity_id to Phoenix severity (1-5)
            # OCSF: 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
            severity_num = min(max(severity_id, 1), 5)
            
            # Extract description
            description = finding_info.get('desc', title)
            if not description:
                description = finding.get('message', title)
            
            # Extract remediation
            remediation_info = finding.get('remediation', {})
            remedy = remediation_info.get('desc', 'Review and remediate according to AWS best practices')
            if not remedy:
                remedy = remediation_info.get('kb_articles', [''])[0] if remediation_info.get('kb_articles') else 'Review and remediate'
            
            # Extract resources for location
            resources = finding.get('resources', [])
            if resources and len(resources) > 0:
                resource_names = [r.get('name', r.get('uid', '')) for r in resources if r.get('name') or r.get('uid')]
                location = ', '.join(resource_names[:3]) if resource_names else finding_uid
            else:
                # Use service name or check ID
                metadata = finding.get('metadata', {})
                service = metadata.get('product', {}).get('feature', {}).get('name', '')
                location = service if service else finding_uid
            
            # Extract event code for name
            event_code = finding.get('metadata', {}).get('event_code', finding_uid.split('-')[-1] if '-' in finding_uid else finding_uid)
            
            return {
                'name': event_code,
                'description': description[:500],
                'remedy': remedy[:500],
                'severity': severity_num,
                'location': location,
                'reference_ids': [finding_uid],
                'details': {
                    'title': title,
                    'severity_name': severity_str,
                    'finding_uid': finding_uid,
                    'status': finding.get('status', ''),
                    'status_code': finding.get('status_code', '')
                }
            }
        except Exception as e:
            logger.warning(f"Error parsing OCSF finding: {e}")
            return None


__all__ = ['ProwlerTranslator']
