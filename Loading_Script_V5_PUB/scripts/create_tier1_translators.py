#!/usr/bin/env python3
"""
Tier 1 Critical Scanner Translators - Batch Creator
===================================================

Creates hard-coded translators for the 20 most critical scanners
that failed detection in the comprehensive test.

Priority Order:
1. JFrog XRay (4 variants)
2. BlackDuck (3 variants)  
3. API scanners (7 types)
4. AWS/Cloud (3 types)
5. Other critical (3 types)
"""

import os
import json
from pathlib import Path
from typing import Dict, List

# Template for JFrog XRay translators
JFROG_XRAY_TEMPLATE = '''class JFrogXRay{variant}Translator(ScannerTranslator):
    """Translator for JFrog XRay {variant_name} format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect JFrog XRay {variant_name} format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            if isinstance(file_content, dict):
                # {variant_name} specific detection
                {detection_logic}
                
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse JFrog XRay {variant_name} scan results"""
        logger.info(f"Parsing JFrog XRay {variant_name} file: {{file_path}}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "JFrog XRay {variant_name} Parsing", file_path, "parse_file")
            raise
        
        assets = []
        {parsing_logic}
        
        logger.info(f"Created {{len(assets)}} assets with {{sum(len(a.findings) for a in assets)}} vulnerabilities")
        return assets
'''

def analyze_scanner_format(scanner_dir: Path) -> Dict:
    """Analyze a scanner's file format"""
    test_files = list(scanner_dir.glob('*.json'))[:3]
    
    if not test_files:
        return {'format': 'unknown', 'keys': [], 'structure': 'unknown'}
    
    # Analyze first file
    try:
        with open(test_files[0], 'r') as f:
            data = json.load(f)
        
        if isinstance(data, dict):
            return {
                'format': 'json_object',
                'root_keys': list(data.keys())[:10],
                'structure': 'dict',
                'sample': data
            }
        elif isinstance(data, list):
            return {
                'format': 'json_array',
                'root_keys': list(data[0].keys()) if data and isinstance(data[0], dict) else [],
                'structure': 'array',
                'sample': data[0] if data else None
            }
    except Exception as e:
        return {'format': 'error', 'error': str(e)}

def generate_translator_stub(scanner_name: str, analysis: Dict) -> str:
    """Generate a translator stub based on analysis"""
    
    class_name = ''.join(word.capitalize() for word in scanner_name.split('_'))
    
    return f'''
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
            
            # Detection logic for {scanner_name}
            # Root keys found: {analysis.get('root_keys', [])}
            if isinstance(file_content, dict):
                # Add specific detection based on unique keys
                required_keys = {analysis.get('root_keys', [])[:3]}
                if all(key in file_content for key in required_keys):
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
        
        assets = []
        
        # TODO: Implement parsing logic based on format
        # Format: {analysis.get('format')}
        # Structure: {analysis.get('structure')}
        
        # Create base asset
        asset_attributes = {{
            'dockerfile': 'Dockerfile',
            'origin': '{scanner_name}',
            'repository': 'unknown'
        }}
        
        asset = AssetData(
            asset_type="CONTAINER",  # Adjust based on scanner type
            attributes=asset_attributes,
            tags=self.tag_config.get_all_tags() + [
                {{"key": "scanner", "value": "{scanner_name}"}}
            ]
        )
        
        # TODO: Parse vulnerabilities from data
        # Add findings to asset.findings
        
        assets.append(self.ensure_asset_has_findings(asset))
        logger.info(f"Created {{len(assets)}} assets with {{sum(len(a.findings) for a in assets)}} vulnerabilities")
        return assets
'''

def main():
    """Generate translator stubs for Tier 1 scanners"""
    
    scans_dir = Path('scanner_test_files/scans')
    
    # Tier 1 Critical Scanners (from test results)
    tier1_scanners = [
        # JFrog XRay variants
        'jfrog_xray_unified',
        'jfrog_xray_api_summary_artifact',
        'jfrog_xray_on_demand_binary_scan',
        'jfrogxray',
        
        # BlackDuck variants
        'blackduck',
        'blackduck_binary_analysis',
        
        # API scanners
        'api_sonarqube',
        'api_bugcrowd',
        'api_cobalt',
        'api_edgescan',
        'api_vulners',
        'api_blackduck',
        
        # AWS/Cloud
        'aws_prowler',
        'aws_prowler_v3plus',
        'cloudsploit',
        
        # Other critical
        'contrast',
        'coverity_api',
        'dependency_check',
        'mend',
        'openvas'
    ]
    
    output_file = 'tier1_translators_generated.py'
    
    with open(output_file, 'w') as f:
        f.write('# Generated Tier 1 Translators\n')
        f.write('# Auto-generated stubs - needs manual completion\n\n')
        
        for scanner in tier1_scanners:
            scanner_dir = scans_dir / scanner
            if not scanner_dir.exists():
                print(f"⚠️  Scanner directory not found: {scanner}")
                continue
            
            print(f"📝 Analyzing: {scanner}")
            analysis = analyze_scanner_format(scanner_dir)
            
            stub = generate_translator_stub(scanner, analysis)
            f.write(f'\n{"="*80}\n')
            f.write(f'# {scanner.upper()}\n')
            f.write(f'{"="*80}\n')
            f.write(stub)
            f.write('\n\n')
    
    print(f"\n✅ Generated translator stubs in {output_file}")
    print(f"📝 Manual completion required for each translator")
    print(f"\nNext steps:")
    print(f"1. Review {output_file}")
    print(f"2. Complete parsing logic for each scanner")
    print(f"3. Test each translator")
    print(f"4. Add to phoenix_multi_scanner_import.py")

if __name__ == '__main__':
    main()

