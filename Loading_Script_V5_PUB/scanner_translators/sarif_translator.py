#!/usr/bin/env python3
"""
SARIF Universal Translator
==========================

Translator for SARIF (Static Analysis Results Interchange Format) 2.1.0.

Supported Formats:
------------------
- **SARIF 2.1.0 / 2.0.0** - Industry standard for static analysis results
  - Structure: {$schema, version, runs: [{tool, results}]}
  - Universal format supported by many tools

Supported Scanners (partial list):
----------------------------------
- Mayhem (API and Code security)
- Fortify (SARIF export)
- CodeQL (GitHub Advanced Security)
- Semgrep (SAST)
- ESLint (with SARIF formatter)
- Snyk Code (SARIF export)
- SonarQube (SARIF export)
- Many others...

Scanner Detection:
-----------------
- File extension: .sarif or .json
- Has '$schema' with 'sarif-schema' and version '2.1.0' or '2.0.0'
- Alternative: Has 'runs' array with tool and results structure

Asset Type: CODE (default), WEB, CONTAINER, INFRA (inferred from tool)
Grouping: By file/artifact from locations

SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

import json
import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class SARIFTranslator(ScannerTranslator):
    """
    Universal translator for SARIF 2.1.0/2.0.0 format
    
    Handles static analysis results from any SARIF-compliant tool.
    Extracts vulnerabilities, locations, rules, and tool metadata.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect SARIF format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is SARIF format
        """
        if not file_path.lower().endswith(('.sarif', '.json')):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check for SARIF-specific fields
            if not isinstance(data, dict):
                return False
            
            # SARIF must have $schema and version
            schema = data.get('$schema', '')
            version = data.get('version', '')
            
            if 'sarif-schema' in schema and version in ['2.1.0', '2.0.0']:
                return True
            
            # Alternative: Check for runs[] with tool structure
            if 'runs' in data and isinstance(data['runs'], list):
                if len(data['runs']) > 0:
                    first_run = data['runs'][0]
                    if 'tool' in first_run and 'results' in first_run:
                        return True
            
            return False
            
        except Exception as e:
            logger.debug(f"SARIFTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse SARIF file and convert to Phoenix format
        
        Args:
            file_path: Path to the SARIF JSON file
            
        Returns:
            List of AssetData objects with findings
        """
        assets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            logger.info(f"Parsing SARIF file: {file_path}")
            
            # Get tool information from first run
            runs = sarif_data.get('runs', [])
            if not runs:
                logger.warning("No runs found in SARIF file")
                return []
            
            # Process each run
            for run_idx, run in enumerate(runs):
                run_assets = self._process_run(run, run_idx, file_path)
                assets.extend(run_assets)
            
            logger.info(f"Parsed {len(assets)} assets from SARIF file")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing SARIF file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _process_run(self, run: Dict, run_idx: int, file_path: str) -> List[AssetData]:
        """
        Process a single SARIF run
        
        Args:
            run: Run dictionary from SARIF
            run_idx: Index of the run
            file_path: Original file path
            
        Returns:
            List of AssetData objects
        """
        assets_dict = {}
        
        # Get tool information
        tool = run.get('tool', {})
        driver = tool.get('driver', {})
        tool_name = driver.get('name', 'Unknown')
        tool_version = driver.get('semanticVersion', driver.get('version', 'unknown'))
        
        # Get rules for detailed vulnerability information
        rules_dict = {}
        rules = driver.get('rules', [])
        for rule in rules:
            rule_id = rule.get('id', '')
            if rule_id:
                rules_dict[rule_id] = rule
        
        # Process results (vulnerabilities/findings)
        results = run.get('results', [])
        logger.info(f"Processing {len(results)} results from run {run_idx + 1}")
        
        for result in results:
            vuln_data = self._parse_result(result, rules_dict, tool_name, tool_version)
            if not vuln_data:
                continue
            
            # Extract asset information from locations
            locations = result.get('locations', [])
            if locations:
                for location in locations:
                    asset_key = self._extract_asset_from_location(location, file_path)
                    
                    if asset_key not in assets_dict:
                        assets_dict[asset_key] = {
                            'asset_type': self._determine_asset_type(tool_name),
                            'attributes': self._create_asset_attributes(asset_key, location, tool_name),
                            'findings': []
                        }
                    
                    assets_dict[asset_key]['findings'].append(vuln_data)
            else:
                # No locations - create a generic asset
                asset_key = f"{tool_name}_scan"
                if asset_key not in assets_dict:
                    assets_dict[asset_key] = {
                        'asset_type': self._determine_asset_type(tool_name),
                        'attributes': {
                            'name': asset_key,
                            'scanner': tool_name,
                            'scanFile': Path(file_path).name
                        },
                        'findings': []
                    }
                
                assets_dict[asset_key]['findings'].append(vuln_data)
        
        # Convert to AssetData objects
        assets = []
        for asset_key, asset_info in assets_dict.items():
            # Get base tags
            base_tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type=asset_info['asset_type'],
                attributes=asset_info['attributes'],
                tags=base_tags + [{"key": "scanner", "value": "sarif"}]
            )
            
            # Add findings
            for vuln_dict in asset_info['findings']:
                asset.findings.append(vuln_dict)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_result(self, result: Dict, rules_dict: Dict, tool_name: str, tool_version: str) -> Optional[Dict]:
        """
        Parse a single SARIF result into a vulnerability
        
        Args:
            result: Result dictionary from SARIF
            rules_dict: Dictionary of rule definitions
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
            
        Returns:
            Vulnerability dictionary or None
        """
        try:
            # Get rule ID
            rule_id = result.get('ruleId', 'unknown')
            
            # Get message
            message_obj = result.get('message', {})
            message_text = message_obj.get('text', '')
            
            # Get detailed info from rule if available
            rule = rules_dict.get(rule_id, {})
            short_desc = rule.get('shortDescription', {}).get('text', '')
            full_desc = rule.get('fullDescription', {}).get('text', '')
            help_text = rule.get('help', {}).get('text', '')
            
            # Construct vulnerability name
            vuln_name = short_desc or message_text or rule_id
            if len(vuln_name) > 200:
                vuln_name = vuln_name[:197] + "..."
            
            # Construct description
            description = message_text or full_desc or vuln_name
            if len(description) > 2000:
                description = description[:1997] + "..."
            
            # Get severity (level in SARIF)
            level = result.get('level', result.get('kind', 'warning'))
            severity = self._map_sarif_level_to_severity(level)
            
            # Get location for context
            locations = result.get('locations', [])
            location_str = 'general'
            if locations:
                first_loc = locations[0]
                phys_loc = first_loc.get('physicalLocation', {})
                artifact = phys_loc.get('artifactLocation', {})
                uri = artifact.get('uri', '')
                region = phys_loc.get('region', {})
                start_line = region.get('startLine', '')
                
                if uri:
                    location_str = uri
                    if start_line:
                        location_str += f":{start_line}"
            
            # Extract CWEs and other references
            reference_ids = []
            cwes = []
            
            # Check rule properties for CWEs
            if rule:
                rule_props = rule.get('properties', {})
                tags = rule_props.get('tags', [])
                for tag in tags:
                    if isinstance(tag, str):
                        if tag.startswith('CWE-'):
                            cwes.append(tag)
                        elif 'CVE' in tag or 'OWASP' in tag:
                            reference_ids.append(tag)
            
            # Add rule ID as reference
            if rule_id and rule_id != 'unknown':
                reference_ids.append(f"{tool_name}-{rule_id}")
            
            # Create vulnerability data
            vuln_data = {
                'name': vuln_name,
                'description': description,
                'remedy': help_text or "See tool output for remediation guidance",
                'severity': severity,
                'location': location_str,
                'reference_ids': reference_ids,
                'cwes': cwes,
                'details': {
                    'tool_version': tool_version,
                    'rule_id': rule_id
                }
            }
            
            return vuln_data
            
        except Exception as e:
            logger.error(f"Error parsing SARIF result: {e}")
            return None
    
    def _extract_asset_from_location(self, location: Dict, file_path: str) -> str:
        """Extract asset identifier from SARIF location"""
        try:
            phys_loc = location.get('physicalLocation', {})
            artifact = phys_loc.get('artifactLocation', {})
            uri = artifact.get('uri', '')
            
            if uri and uri != 'unknown-file':
                # Clean up URI
                uri = uri.replace('%SRCROOT%/', '').replace('file://', '')
                return uri
            
            # Fallback to file name
            return Path(file_path).stem
            
        except Exception:
            return 'unknown-asset'
    
    def _create_asset_attributes(self, asset_key: str, location: Dict, tool_name: str) -> Dict:
        """Create asset attributes from SARIF location"""
        attributes = {
            'name': asset_key,
            'scanner': tool_name
        }
        
        try:
            phys_loc = location.get('physicalLocation', {})
            artifact = phys_loc.get('artifactLocation', {})
            uri = artifact.get('uri', '')
            
            if uri:
                attributes['file_path'] = uri
        
        except Exception as e:
            logger.debug(f"Error extracting asset attributes: {e}")
        
        return attributes
    
    def _determine_asset_type(self, tool_name: str) -> str:
        """Determine Phoenix asset type from tool name"""
        tool_lower = tool_name.lower()
        
        # Container/image scanners
        if any(x in tool_lower for x in ['container', 'docker', 'image', 'trivy']):
            return 'CONTAINER'
        
        # Infrastructure scanners
        if any(x in tool_lower for x in ['infra', 'cloud', 'terraform', 'prowler']):
            return 'INFRA'
        
        # Web application scanners
        if any(x in tool_lower for x in ['web', 'zap', 'nikto', 'api', 'burp']):
            return 'WEB'
        
        # Default to CODE for SAST tools
        return 'CODE'
    
    def _map_sarif_level_to_severity(self, level: str) -> str:
        """Map SARIF level to Phoenix severity decimal"""
        level_lower = str(level).lower()
        
        mapping = {
            'error': '8.0',        # High severity
            'warning': '5.0',      # Medium severity
            'note': '3.0',         # Low severity
            'none': '1.0',         # Informational
            'critical': '10.0',    # Critical
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'informational': '1.0',
            'info': '1.0'
        }
        
        return mapping.get(level_lower, '5.0')

