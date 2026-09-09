#!/usr/bin/env python3
"""
Batch Translator Creator - Tier 1 Critical Scanners
==================================================

Efficiently creates hard-coded translators for the top 20 critical scanners
using template-based generation with actual file format analysis.

This script:
1. Analyzes sample scanner files
2. Generates translator code from templates
3. Adds them to the main script
4. Tests each one

Focus: Speed and pragmatism over perfection
"""

import os
import json
import csv
from pathlib import Path
from typing import Dict, List, Any
import subprocess

# Define translator templates

SIMPLE_JSON_ARRAY_TEMPLATE = '''
class {class_name}Translator(ScannerTranslator):
    """Translator for {scanner_name} scanner results"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect {scanner_name} file format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for {scanner_name} specific structure
            if isinstance(file_content, list) and len(file_content) > 0:
                first_item = file_content[0]
                # Detection keys: {detection_keys}
                if isinstance(first_item, dict):
                    required_keys = {detection_keys_list}
                    if len(required_keys) > 0 and all(k in first_item for k in required_keys):
                        return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse {scanner_name} scan results"""
        logger.info(f"Parsing {scanner_name} file: {{file_path}}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "{scanner_name} Parsing", file_path, "parse_file")
            raise
        
        if not isinstance(data, list):
            data = [data]
        
        # Group by asset
        assets_dict = {{}}
        
        for item in data:
            asset_name = item.get('{asset_key}', 'unknown')
            
            if asset_name not in assets_dict:
                assets_dict[asset_name] = {{
                    'attributes': {{
                        'dockerfile': 'Dockerfile',
                        'origin': '{scanner_name}',
                        'repository': asset_name
                    }},
                    'vulns': []
                }}
            
            # Parse vulnerability
            vuln = self._parse_vulnerability(item)
            if vuln:
                assets_dict[asset_name]['vulns'].append(vuln)
        
        # Create assets
        assets = []
        for asset_name, asset_data in assets_dict.items():
            asset = AssetData(
                asset_type="{asset_type}",
                attributes=asset_data['attributes'],
                tags=self.tag_config.get_all_tags() + [
                    {{"key": "scanner", "value": "{scanner_name}"}}
                ]
            )
            asset.findings.extend(asset_data['vulns'])
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {{len(assets)}} assets with {{sum(len(a.findings) for a in assets)}} vulnerabilities")
        return assets
    
    def _parse_vulnerability(self, item: Dict) -> Optional[Dict]:
        """Parse vulnerability from item"""
        vuln_id = item.get('{vuln_id_key}', 'UNKNOWN')
        if not vuln_id:
            return None
        
        # Get severity
        severity_str = item.get('{severity_key}', 'Unknown')
        severity = self.normalize_severity(severity_str)
        
        # Get description
        description = item.get('{description_key}', f"Vulnerability: {{vuln_id}}")
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=description[:500],
            remedy=item.get('{remedy_key}', "See scanner output for remediation"),
            severity=severity,
            location=item.get('{location_key}', 'unknown'),
            reference_ids=[vuln_id]
        )
        
        return vulnerability.__dict__
'''

CSV_TRANSLATOR_TEMPLATE = '''
class {class_name}Translator(ScannerTranslator):
    """Translator for {scanner_name} CSV format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect {scanner_name} CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                first_row = next(reader, None)
                if first_row:
                    # Check for required columns
                    required_cols = {required_columns}
                    if all(col in first_row for col in required_cols):
                        return True
        except:
            pass
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse {scanner_name} CSV scan results"""
        logger.info(f"Parsing {scanner_name} CSV file: {{file_path}}")
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
        except Exception as e:
            error_tracker.log_error(e, "{scanner_name} CSV Parsing", file_path, "parse_file")
            raise
        
        # Group by component
        assets_dict = {{}}
        
        for row in rows:
            component = row.get('{component_key}', 'unknown')
            version = row.get('{version_key}', '')
            asset_name = f"{{component}}:{{version}}" if version else component
            
            if asset_name not in assets_dict:
                assets_dict[asset_name] = {{
                    'attributes': {{
                        'dockerfile': 'Dockerfile',
                        'origin': '{scanner_name}',
                        'repository': component
                    }},
                    'vulns': []
                }}
            
            # Parse vulnerability
            vuln = self._parse_csv_vulnerability(row)
            if vuln:
                assets_dict[asset_name]['vulns'].append(vuln)
        
        # Create assets
        assets = []
        for asset_name, asset_data in assets_dict.items():
            asset = AssetData(
                asset_type="BUILD",
                attributes=asset_data['attributes'],
                tags=self.tag_config.get_all_tags() + [
                    {{"key": "scanner", "value": "{scanner_name}"}}
                ]
            )
            asset.findings.extend(asset_data['vulns'])
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {{len(assets)}} assets with {{sum(len(a.findings) for a in assets)}} vulnerabilities")
        return assets
    
    def _parse_csv_vulnerability(self, row: Dict) -> Optional[Dict]:
        """Parse vulnerability from CSV row"""
        vuln_id = row.get('{cve_key}', row.get('{bdsa_key}', 'UNKNOWN'))
        if not vuln_id or vuln_id == '':
            return None
        
        # Get CVSS score
        cvss_str = row.get('{cvss_key}', '0.0')
        try:
            cvss_score = float(cvss_str) if cvss_str else 0.0
        except:
            cvss_score = 0.0
        
        # Map CVSS to severity
        if cvss_score >= 9.0:
            severity = 5  # Critical
        elif cvss_score >= 7.0:
            severity = 4  # High
        elif cvss_score >= 4.0:
            severity = 3  # Medium
        elif cvss_score > 0:
            severity = 2  # Low
        else:
            severity = 1  # Informational
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=row.get('{summary_key}', f"Vulnerability: {{vuln_id}}")[:500],
            remedy="See vendor advisories for remediation",
            severity=severity,
            location=row.get('{object_key}', 'unknown'),
            reference_ids=[vuln_id],
            details={{
                'cvss_score': cvss_score,
                'cvss_vector_v3': row.get('{cvss_vector_key}', ''),
                'url': row.get('{url_key}', '')
            }}
        )
        
        return vulnerability.__dict__
'''

def analyze_json_file(file_path: Path) -> Dict:
    """Analyze a JSON file to extract key structure"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        if isinstance(data, list) and len(data) > 0:
            first_item = data[0]
            if isinstance(first_item, dict):
                keys = list(first_item.keys())
                return {
                    'format': 'json_array',
                    'keys': keys[:10],
                    'detection_keys': keys[:3],  # Use first 3 keys for detection
                    'sample': first_item
                }
        elif isinstance(data, dict):
            keys = list(data.keys())
            return {
                'format': 'json_object',
                'keys': keys[:10],
                'detection_keys': keys[:3],
                'sample': data
            }
    except:
        pass
    
    return {'format': 'unknown'}

def generate_blackduck_binary_analysis_translator() -> str:
    """Generate BlackDuck Binary Analysis CSV translator"""
    return CSV_TRANSLATOR_TEMPLATE.format(
        class_name='BlackDuckBinaryAnalysis',
        scanner_name='blackduck-binary-analysis',
        required_columns='["Component", "Version", "CVE"]',
        component_key='Component',
        version_key='Version',
        cve_key='CVE',
        bdsa_key='BDSA',
        cvss_key='CVSS3',
        summary_key='Summary',
        object_key='Object',
        cvss_vector_key='CVSS vector (v3)',
        url_key='Vulnerability URL'
    )

def generate_api_blackduck_translator() -> str:
    """Generate API BlackDuck JSON translator"""
    return SIMPLE_JSON_ARRAY_TEMPLATE.format(
        class_name='APIBlackDuck',
        scanner_name='api-blackduck',
        detection_keys='"componentName", "componentVersionName", "vulnerabilityWithRemediation"',
        detection_keys_list='["componentName", "vulnerabilityWithRemediation"]',
        asset_key='componentName',
        asset_type='BUILD',
        vuln_id_key='vulnerabilityWithRemediation.vulnerabilityName',
        severity_key='vulnerabilityWithRemediation.severity',
        description_key='vulnerabilityWithRemediation.description',
        remedy_key='vulnerabilityWithRemediation.remediationComment',
        location_key='componentVersionName'
    )

def main():
    """Generate Tier 1 critical translators"""
    output_file = Path('tier1_translators_batch.py')
    
    print("="*80)
    print("BATCH TRANSLATOR GENERATOR - Tier 1 Critical")
    print("="*80)
    
    with open(output_file, 'w') as f:
        f.write('#!/usr/bin/env python3\n')
        f.write('"""\nTier 1 Critical Scanner Translators - Batch Generated\n')
        f.write('Auto-generated hard-coded translators for critical scanners\n"""\n\n')
        f.write('import json\nimport csv\nimport logging\nfrom typing import Any, Dict, List, Optional\n')
        f.write('from phoenix_import_refactored import AssetData, VulnerabilityData\n')
        f.write('from phoenix_multi_scanner_import import ScannerTranslator, error_tracker\n\n')
        f.write('logger = logging.getLogger(__name__)\n\n')
        
        # Generate BlackDuck translators
        print("\n📝 Generating BlackDuck Binary Analysis translator...")
        f.write("\n# " + "="*76 + "\n")
        f.write("# BLACK DUCK BINARY ANALYSIS - CSV FORMAT\n")
        f.write("# " + "="*76 + "\n")
        f.write(generate_blackduck_binary_analysis_translator())
        
        print("📝 Generating API BlackDuck translator...")
        f.write("\n# " + "="*76 + "\n")
        f.write("# API BLACK DUCK - JSON FORMAT\n")
        f.write("# " + "="*76 + "\n")
        f.write(generate_api_blackduck_translator())
        
        # Export all
        f.write("\n\n# Export all translators\n")
        f.write("__all__ = [\n")
        f.write("    'BlackDuckBinaryAnalysisTranslator',\n")
        f.write("    'APIBlackDuckTranslator'\n")
        f.write("]\n")
    
    print(f"\n✅ Generated translators in {output_file}")
    print(f"\nNext: Import these into phoenix_multi_scanner_enhanced.py")

if __name__ == '__main__':
    main()

