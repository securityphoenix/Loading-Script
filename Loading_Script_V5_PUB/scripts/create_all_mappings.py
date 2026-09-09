#!/usr/bin/env python3
"""
Comprehensive YAML Mapping Generator for ALL Phoenix Security Scanners
Analyzes actual scanner files and generates production-ready YAML mappings
"""

import json
import xml.etree.ElementTree as ET
import os
import sys
import csv
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import re

class ScannerAnalyzer:
    def __init__(self, scans_dir: Path):
        self.scans_dir = scans_dir
        self.mappings = []
        
    def analyze_json_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a JSON scanner file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            # Determine structure
            is_array_root = isinstance(data, list)
            
            if is_array_root and data:
                # Array at root - analyze first item
                sample = data[0]
                vuln_fields = self.find_vuln_fields(sample)
                asset_fields = self.find_asset_fields(sample)
                
                return {
                    'structure': 'array_root',
                    'sample_keys': list(sample.keys()) if isinstance(sample, dict) else [],
                    'vuln_fields': vuln_fields,
                    'asset_fields': asset_fields,
                    'data': sample
                }
            elif isinstance(data, dict):
                # Object at root
                vuln_arrays = self.find_vuln_arrays(data)
                asset_fields = self.find_asset_fields(data)
                
                return {
                    'structure': 'object_root',
                    'root_keys': list(data.keys()),
                    'vuln_arrays': vuln_arrays,
                    'asset_fields': asset_fields,
                    'data': data
                }
            
            return {'structure': 'unknown', 'data': data}
            
        except Exception as e:
            return {'error': str(e)}
    
    def find_vuln_fields(self, obj: Dict) -> List[str]:
        """Find fields that likely contain vulnerability data"""
        vuln_keywords = ['vuln', 'cve', 'cvss', 'severity', 'threat', 'risk', 'weakness', 'flaw', 'issue']
        candidates = []
        
        if not isinstance(obj, dict):
            return candidates
            
        for key in obj.keys():
            key_lower = key.lower()
            if any(keyword in key_lower for keyword in vuln_keywords):
                candidates.append(key)
        
        return candidates
    
    def find_asset_fields(self, obj: Dict) -> List[str]:
        """Find fields that likely contain asset data"""
        asset_keywords = ['image', 'container', 'host', 'ip', 'url', 'target', 'repository', 'project', 'component']
        candidates = []
        
        if not isinstance(obj, dict):
            return candidates
            
        for key in obj.keys():
            key_lower = key.lower()
            if any(keyword in key_lower for keyword in asset_keywords):
                candidates.append(key)
        
        return candidates
    
    def find_vuln_arrays(self, data: Dict, prefix: str = "", depth: int = 0) -> List[str]:
        """Find arrays that contain vulnerabilities"""
        if depth > 3:
            return []
        
        candidates = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, list) and value:
                    # Check if this looks like a vulnerability array
                    if isinstance(value[0], dict):
                        first_item = value[0]
                        vuln_score = sum(1 for k in first_item.keys() if any(x in k.lower() for x in ['vuln', 'cve', 'severity', 'risk']))
                        if vuln_score >= 1:
                            candidates.append(current_path)
                
                elif isinstance(value, dict):
                    candidates.extend(self.find_vuln_arrays(value, current_path, depth + 1))
        
        return candidates
    
    def detect_asset_type(self, scanner_name: str, data: Dict) -> str:
        """Intelligently detect asset type"""
        name_lower = scanner_name.lower()
        data_str = json.dumps(data)[:1000].lower() if data else ""
        
        # Container
        if any(x in name_lower for x in ['docker', 'container', 'image', 'harbor', 'trivy', 'grype', 'aqua', 'anchore', 'clair', 'twistlock']):
            return "CONTAINER"
        
        # Cloud/IaC
        if any(x in name_lower for x in ['aws', 'azure', 'gcp', 'cloud', 'prowler', 'scout', 'inspector']):
            return "CLOUD"
        
        # Code/SAST
        if any(x in name_lower for x in ['code', 'sast', 'sonar', 'checkmarx', 'fortify', 'semgrep', 'bandit']):
            return "CODE"
        
        # Web
        if any(x in name_lower for x in ['web', 'burp', 'zap', 'arachni', 'acunetix', 'netsparker']):
            return "WEB"
        
        # Infrastructure
        if any(x in name_lower for x in ['nmap', 'qualys', 'tenable', 'nessus', 'openvas', 'nexpose']):
            return "INFRA"
        
        # SCA/Dependencies
        if any(x in name_lower for x in ['npm', 'yarn', 'pip', 'maven', 'blackduck', 'whitesource', 'mend', 'snyk', 'audit']):
            return "CODE"
        
        # Repository
        if any(x in name_lower for x in ['git', 'repo', 'github', 'gitlab']):
            return "REPOSITORY"
        
        # Build
        if any(x in name_lower for x in ['build', 'jfrog', 'xray', 'artifactory']):
            return "BUILD"
        
        return "INFRA"
    
    def generate_mapping(self, scanner_name: str) -> Optional[str]:
        """Generate YAML mapping for a scanner"""
        scanner_dir = self.scans_dir / scanner_name
        
        if not scanner_dir.exists():
            return None
        
        # Find sample files
        json_files = list(scanner_dir.glob("*.json"))[:1]
        xml_files = list(scanner_dir.glob("*.xml"))[:1]
        csv_files = list(scanner_dir.glob("*.csv"))[:1]
        
        if json_files:
            return self.generate_json_mapping(scanner_name, json_files[0])
        elif xml_files:
            return self.generate_xml_mapping(scanner_name, xml_files[0])
        elif csv_files:
            return self.generate_csv_mapping(scanner_name, csv_files[0])
        
        return f"  # {scanner_name}: No sample files found\n"
    
    def generate_json_mapping(self, scanner_name: str, file_path: Path) -> str:
        """Generate JSON format mapping"""
        analysis = self.analyze_json_file(file_path)
        
        if 'error' in analysis:
            return f"  # {scanner_name}: Error - {analysis['error']}\n"
        
        asset_type = self.detect_asset_type(scanner_name, analysis.get('data', {}))
        
        yaml = f"\n  # {scanner_name.replace('_', ' ').title()} Scanner\n"
        yaml += f"  {scanner_name}:\n"
        yaml += f"    formats:\n"
        yaml += f"      - name: \"{scanner_name}_json\"\n"
        yaml += f"        file_patterns: [\"*.json\", \"*{scanner_name}*.json\"]\n"
        yaml += f"        format_type: \"json\"\n"
        yaml += f"        asset_type: \"{asset_type}\"\n"
        yaml += f"        detection:\n"
        
        if analysis['structure'] == 'array_root':
            yaml += f"          json_keys: {json.dumps(analysis['sample_keys'][:5])}\n"
            yaml += f"          required_keys: {json.dumps(analysis['sample_keys'][:2])}\n"
            yaml += f"          is_array_root: true\n"
        elif analysis['structure'] == 'object_root':
            yaml += f"          json_keys: {json.dumps(analysis['root_keys'][:5])}\n"
            yaml += f"          required_keys: {json.dumps(analysis['root_keys'][:2])}\n"
        
        yaml += f"        field_mappings:\n"
        yaml += f"          asset:\n"
        
        # Asset mappings based on type
        if asset_type == "CONTAINER":
            asset_field = analysis.get('asset_fields', ['image'])[0] if analysis.get('asset_fields') else 'image'
            yaml += f"            repository: \"{asset_field}\"\n"
            yaml += f"            dockerfile: \"Dockerfile\"\n"
        elif asset_type == "CODE":
            asset_field = analysis.get('asset_fields', ['project'])[0] if analysis.get('asset_fields') else 'project'
            yaml += f"            scannerSource: \"{asset_field}\"\n"
        elif asset_type == "WEB":
            asset_field = analysis.get('asset_fields', ['url'])[0] if analysis.get('asset_fields') else 'url'
            yaml += f"            fqdn: \"{asset_field}\"\n"
        elif asset_type == "CLOUD":
            yaml += f"            providerType: \"AWS\"\n"
            yaml += f"            providerAccountId: \"ACCOUNT_NUM\"\n"
            yaml += f"            region: \"REGION\"\n"
        elif asset_type == "INFRA":
            yaml += f"            ip: \"ip_address\"\n"
            yaml += f"            hostname: \"hostname\"\n"
        
        yaml += f"            origin: \"{scanner_name}\"\n"
        yaml += f"          vulnerability:\n"
        
        # Vulnerability mappings
        if analysis['structure'] == 'array_root':
            vuln_fields = analysis.get('vuln_fields', [])
            yaml += f"            name: \"vuln\"\n"
            yaml += f"            description: \"description\"\n"
            yaml += f"            remedy: \"fix\"\n"
            yaml += f"            severity: \"severity\"\n"
            yaml += f"            location: \"package\"\n"
            yaml += f"            reference_ids: \"cve\"\n"
        elif analysis['structure'] == 'object_root':
            vuln_array = analysis.get('vuln_arrays', ['vulnerabilities'])[0] if analysis.get('vuln_arrays') else 'vulnerabilities'
            yaml += f"            name: \"{vuln_array}[].vuln\"\n"
            yaml += f"            description: \"{vuln_array}[].description\"\n"
            yaml += f"            remedy: \"{vuln_array}[].fix\"\n"
            yaml += f"            severity: \"{vuln_array}[].severity\"\n"
            yaml += f"            location: \"{vuln_array}[].package\"\n"
            yaml += f"            reference_ids: \"{vuln_array}[].cve\"\n"
        
        yaml += f"        severity_mapping:\n"
        yaml += f"          \"Critical\": \"10.0\"\n"
        yaml += f"          \"High\": \"8.0\"\n"
        yaml += f"          \"Medium\": \"5.0\"\n"
        yaml += f"          \"Low\": \"2.0\"\n"
        yaml += f"          \"Negligible\": \"1.0\"\n"
        
        return yaml
    
    def generate_xml_mapping(self, scanner_name: str, file_path: Path) -> str:
        """Generate XML format mapping"""
        asset_type = self.detect_asset_type(scanner_name, {})
        
        yaml = f"\n  # {scanner_name.replace('_', ' ').title()} Scanner\n"
        yaml += f"  {scanner_name}:\n"
        yaml += f"    formats:\n"
        yaml += f"      - name: \"{scanner_name}_xml\"\n"
        yaml += f"        file_patterns: [\"*.xml\"]\n"
        yaml += f"        format_type: \"xml\"\n"
        yaml += f"        asset_type: \"{asset_type}\"\n"
        yaml += f"        detection:\n"
        yaml += f"          xml_root: \"scan\"\n"
        yaml += f"          required_elements: [\"vulnerability\", \"target\"]\n"
        yaml += f"        field_mappings:\n"
        yaml += f"          asset:\n"
        
        if asset_type == "WEB":
            yaml += f"            fqdn: \"//target/url\"\n"
        else:
            yaml += f"            hostname: \"//target/host\"\n"
        
        yaml += f"            origin: \"{scanner_name}\"\n"
        yaml += f"          vulnerability:\n"
        yaml += f"            name: \"//vulnerability/name\"\n"
        yaml += f"            description: \"//vulnerability/description\"\n"
        yaml += f"            remedy: \"//vulnerability/solution\"\n"
        yaml += f"            severity: \"//vulnerability/severity\"\n"
        yaml += f"            location: \"//vulnerability/location\"\n"
        yaml += f"        severity_mapping:\n"
        yaml += f"          \"Critical\": \"10.0\"\n"
        yaml += f"          \"High\": \"8.0\"\n"
        yaml += f"          \"Medium\": \"5.0\"\n"
        yaml += f"          \"Low\": \"2.0\"\n"
        
        return yaml
    
    def generate_csv_mapping(self, scanner_name: str, file_path: Path) -> str:
        """Generate CSV format mapping"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                headers = next(reader)
                
            asset_type = self.detect_asset_type(scanner_name, {})
            
            yaml = f"\n  # {scanner_name.replace('_', ' ').title()} Scanner\n"
            yaml += f"  {scanner_name}:\n"
            yaml += f"    formats:\n"
            yaml += f"      - name: \"{scanner_name}_csv\"\n"
            yaml += f"        file_patterns: [\"*.csv\"]\n"
            yaml += f"        format_type: \"csv\"\n"
            yaml += f"        asset_type: \"{asset_type}\"\n"
            yaml += f"        detection:\n"
            yaml += f"          required_columns: {json.dumps(headers[:3])}\n"
            yaml += f"        field_mappings:\n"
            yaml += f"          asset:\n"
            
            if asset_type == "CLOUD":
                yaml += f"            providerAccountId: \"ACCOUNT_NUM\"\n"
                yaml += f"            region: \"REGION\"\n"
            else:
                yaml += f"            hostname: \"{headers[0]}\"\n"
            
            yaml += f"            origin: \"{scanner_name}\"\n"
            yaml += f"          vulnerability:\n"
            yaml += f"            name: \"TITLE_TEXT\"\n"
            yaml += f"            description: \"CHECK_RESULT_EXTENDED\"\n"
            yaml += f"            remedy: \"CHECK_REMEDIATION\"\n"
            yaml += f"            severity: \"CHECK_SEVERITY\"\n"
            yaml += f"            location: \"REGION\"\n"
            yaml += f"        severity_mapping:\n"
            yaml += f"          \"High\": \"8.0\"\n"
            yaml += f"          \"Medium\": \"5.0\"\n"
            yaml += f"          \"Low\": \"2.0\"\n"
            yaml += f"          \"Informational\": \"1.0\"\n"
            
            return yaml
            
        except Exception as e:
            return f"  # {scanner_name}: CSV Error - {str(e)}\n"

def main():
    scans_dir = Path("{PROJECT_ROOT}")
    
    # Read list of scanners that need mapping
    with open('/tmp/all_scanners.txt', 'r') as f:
        all_scanners = [line.strip() for line in f if line.strip()]
    
    # Scanners already mapped
    already_mapped = {
        'acunetix', 'anchore_enterprise', 'anchore_grype', 'aqua', 'bandit', 'brakeman',
        'burp', 'checkmarx', 'checkov', 'clair', 'dependency_check', 'eslint', 'fortify',
        'gitlab_container_scan', 'gitlab_dep_scan', 'gitlab_sast', 'gitleaks', 'gosec',
        'hadolint', 'nikto', 'nmap', 'npm_audit', 'nuclei', 'qualys', 'semgrep', 'snyk',
        'sonarqube', 'tenable', 'terrascan', 'tfsec', 'trivy', 'trufflehog', 'twistlock',
        'veracode', 'yarn_audit', 'zap'
    }
    
    needs_mapping = [s for s in all_scanners if s not in already_mapped]
    
    analyzer = ScannerAnalyzer(scans_dir)
    
    print("# ============================================================================")
    print("# GENERATED YAML MAPPINGS FOR ALL PHOENIX SECURITY SCANNERS")
    print("# Add these to scanner_field_mappings.yaml under the 'scanners:' section")
    print("# ============================================================================")
    print()
    
    for i, scanner in enumerate(needs_mapping, 1):
        print(f"# Progress: {i}/{len(needs_mapping)} - {scanner}")
        mapping = analyzer.generate_mapping(scanner)
        if mapping:
            print(mapping)

if __name__ == "__main__":
    main()

