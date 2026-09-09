#!/usr/bin/env python3
"""
Microsoft Defender Translator
==============================

Translator for Microsoft Defender for Endpoint ZIP exports.
Handles machines.json and vulnerabilities/*.json files.
"""

import json
import logging
import zipfile
import tempfile
import os
from typing import Any, Dict, List

from phoenix_multi_scanner_import import (
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class MSDefenderTranslator(ScannerTranslator):
    """Translator for Microsoft Defender ZIP exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is an MS Defender ZIP"""
        if not file_path.lower().endswith('.zip'):
            return False
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                files = zip_ref.namelist()
                # Look for machines/machines.json and vulnerabilities/*.json
                has_machines = any('machines/machines.json' in f.lower() for f in files)
                has_vulns = any('vulnerabilities/' in f.lower() and f.endswith('.json') for f in files)
                return has_machines or has_vulns
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse MS Defender ZIP"""
        logger.info(f"Parsing MS Defender ZIP: {file_path}")
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract ZIP
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Parse machines
                machines = self._parse_machines(temp_dir)
                
                # Parse vulnerabilities
                vulnerabilities = self._parse_vulnerabilities(temp_dir)
                
                # Create assets
                return self._create_assets(machines, vulnerabilities)
        
        except Exception as e:
            logger.error(f"Error parsing MS Defender ZIP: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_machines(self, temp_dir: str) -> Dict[str, Dict]:
        """Parse machines.json"""
        machines = {}
        machines_path = os.path.join(temp_dir, 'machines', 'machines.json')
        
        if os.path.exists(machines_path):
            try:
                with open(machines_path, 'r') as f:
                    data = json.load(f)
                    
                # MS Defender API format: {'@odata.context': '...', 'value': [...]}
                machines_list = data.get('value', []) if isinstance(data, dict) else []
                
                for machine in machines_list:
                    machine_id = machine.get('id', machine.get('machineId', 'unknown'))
                    machines[machine_id] = {
                        'computerDnsName': machine.get('computerDnsName', 'unknown'),
                        'lastIpAddress': machine.get('lastIpAddress', ''),
                        'osPlatform': machine.get('osPlatform', 'Windows'),
                        'osVersion': machine.get('osVersion', ''),
                    }
                
                logger.info(f"Parsed {len(machines)} machines from MS Defender")
            except Exception as e:
                logger.warning(f"Failed to parse machines.json: {e}")
        
        return machines
    
    def _parse_vulnerabilities(self, temp_dir: str) -> List[Dict]:
        """Parse vulnerabilities JSON files"""
        vulnerabilities = []
        vuln_dir = os.path.join(temp_dir, 'vulnerabilities')
        
        if os.path.exists(vuln_dir):
            for root, dirs, files in os.walk(vuln_dir):
                for file in files:
                    if file.endswith('.json'):
                        try:
                            file_path = os.path.join(root, file)
                            with open(file_path, 'r') as f:
                                data = json.load(f)
                            
                            # MS Defender API format
                            vulns_list = data.get('value', []) if isinstance(data, dict) else []
                            vulnerabilities.extend(vulns_list)
                        except Exception as e:
                            logger.warning(f"Failed to parse {file}: {e}")
        
        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from MS Defender")
        return vulnerabilities
    
    def _create_assets(self, machines: Dict, vulnerabilities: List[Dict]) -> List[AssetData]:
        """Create assets from machines and vulnerabilities"""
        # Group vulnerabilities by machine
        machine_vulns = {}
        for vuln in vulnerabilities:
            machine_id = vuln.get('machineId', 'unknown')
            if machine_id not in machine_vulns:
                machine_vulns[machine_id] = []
            
            cve_id = vuln.get('cveId', vuln.get('id', 'MS-DEFENDER-FINDING'))
            severity = vuln.get('severity', 'Medium')
            
            machine_vulns[machine_id].append(VulnerabilityData(
                name=cve_id,
                description=f"{vuln.get('productName', 'Unknown')} - {vuln.get('productVendor', 'Unknown')}",
                remedy=f"Apply KB{vuln.get('fixingKbId', 'N/A')}" if vuln.get('fixingKbId') else 'Update software',
                severity=self._map_defender_severity(severity),
                location=vuln.get('productName', 'Unknown'),
                reference_ids=[cve_id] if cve_id.startswith('CVE') else []
            ))
        
        # Create assets
        assets = []
        tags = get_tags_safely(self.tag_config)
        
        # Create assets for machines with vulnerabilities
        for machine_id, vulns in machine_vulns.items():
            machine_info = machines.get(machine_id, {})
            computer_name = machine_info.get('computerDnsName', machine_id) or machine_id
            ip_address = machine_info.get('lastIpAddress', '')
            
            asset = AssetData(
                asset_type='INFRA',
                attributes={
                    'fqdn': computer_name if '.' in str(computer_name) else f"{computer_name}.local",
                    'ip': ip_address or '0.0.0.0',
                    'os': machine_info.get('osPlatform', 'Windows'),
                    'osVersion': machine_info.get('osVersion', '')
                },
                findings=[v.__dict__ for v in vulns],
                tags=tags + [{"key": "scanner", "value": "msdefender"}]
            )
            assets.append(self.ensure_asset_has_findings(asset))
        
        # Create assets for machines without vulnerabilities
        for machine_id, machine_info in machines.items():
            if machine_id not in machine_vulns:
                computer_name = machine_info.get('computerDnsName', machine_id) or machine_id
                ip_address = machine_info.get('lastIpAddress', '')
                
                asset = AssetData(
                    asset_type='INFRA',
                    attributes={
                        'fqdn': computer_name if '.' in str(computer_name) else f"{computer_name}.local",
                        'ip': ip_address or '0.0.0.0',
                        'os': machine_info.get('osPlatform', 'Windows'),
                        'osVersion': machine_info.get('osVersion', '')
                    },
                    findings=[VulnerabilityData(
                        name="NO_VULNERABILITIES_FOUND",
                        description="No vulnerabilities found by MS Defender",
                        remedy="No action required",
                        severity="0.0",
                        location=str(computer_name)
                    ).__dict__],
                    tags=tags + [{"key": "scanner", "value": "msdefender"}]
                )
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets from MS Defender")
        return assets
    
    def _map_defender_severity(self, severity: str) -> str:
        """Map MS Defender severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'informational': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


# Export
__all__ = ['MSDefenderTranslator']

