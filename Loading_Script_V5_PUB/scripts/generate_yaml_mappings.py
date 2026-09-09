#!/usr/bin/env python3
"""
Automated YAML Mapping Generator for Phoenix Security Scanners
This script analyzes scanner output files and generates YAML mapping templates
"""

import json
import xml.etree.ElementTree as ET
import os
import sys
import csv
from pathlib import Path
from typing import Dict, Any, List, Tuple

def analyze_json_structure(data: Any, prefix: str = "", max_depth: int = 3) -> Dict[str, Any]:
    """Recursively analyze JSON structure to identify key fields"""
    fields = {}
    
    if isinstance(data, dict):
        for key, value in data.items():
            field_path = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, (dict, list)) and max_depth > 0:
                fields[field_path] = type(value).__name__
                if isinstance(value, dict):
                    fields.update(analyze_json_structure(value, field_path, max_depth - 1))
                elif isinstance(value, list) and value:
                    fields.update(analyze_json_structure(value[0], f"{field_path}[]", max_depth - 1))
            else:
                fields[field_path] = type(value).__name__
    
    return fields

def detect_scanner_type(scanner_name: str, sample_data: Dict) -> str:
    """Detect appropriate asset type based on scanner name and data"""
    scanner_lower = scanner_name.lower()
    
    # Container scanners
    if any(x in scanner_lower for x in ['docker', 'container', 'image', 'harbor', 'trivy', 'grype', 'aqua', 'twistlock', 'clair', 'anchore']):
        return "CONTAINER"
    
    # Code/SAST scanners
    if any(x in scanner_lower for x in ['sast', 'code', 'sonar', 'checkmarx', 'fortify', 'bandit', 'semgrep', 'eslint', 'pmd', 'spotbugs']):
        return "CODE"
    
    # Infrastructure scanners
    if any(x in scanner_lower for x in ['nmap', 'nessus', 'openvas', 'qualys', 'tenable', 'nexpose']):
        return "INFRA"
    
    # Web app scanners
    if any(x in scanner_lower for x in ['burp', 'zap', 'arachni', 'acunetix', 'netsparker', 'appspider', 'wapiti']):
        return "WEB"
    
    # Cloud/IaC scanners
    if any(x in scanner_lower for x in ['cloud', 'aws', 'azure', 'gcp', 'terraform', 'checkov', 'tfsec', 'terrascan', 'prowler', 'scout']):
        return "CLOUD"
    
    # Dependency/SCA scanners
    if any(x in scanner_lower for x in ['npm', 'yarn', 'pip', 'maven', 'gradle', 'audit', 'dependency', 'snyk', 'whitesource', 'blackduck']):
        return "CODE"
    
    # Repository scanners
    if any(x in scanner_lower for x in ['git', 'repo', 'github', 'gitlab']):
        return "REPOSITORY"
    
    # Build scanners
    if any(x in scanner_lower for x in ['build', 'ci', 'jfrog', 'xray', 'artifactory']):
        return "BUILD"
    
    # Default
    return "INFRA"

def find_vulnerability_array_path(data: Dict, depth: int = 0, max_depth: int = 5) -> List[str]:
    """Find paths that likely contain vulnerability arrays"""
    candidates = []
    
    if depth > max_depth:
        return candidates
    
    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = key.lower()
            
            # Look for vulnerability-related keys
            if isinstance(value, list) and value:
                if any(x in key_lower for x in ['vuln', 'finding', 'issue', 'alert', 'flaw', 'weakness', 'defect', 'bug']):
                    candidates.append(key)
                # Check if list items look like vulnerabilities
                elif isinstance(value[0], dict):
                    first_item = value[0]
                    vuln_indicators = sum(1 for k in first_item.keys() if any(x in k.lower() for x in ['cve', 'cvss', 'severity', 'description', 'title', 'name']))
                    if vuln_indicators >= 2:
                        candidates.append(key)
            
            elif isinstance(value, dict):
                nested = find_vulnerability_array_path(value, depth + 1, max_depth)
                candidates.extend([f"{key}.{n}" for n in nested])
    
    return candidates

def generate_yaml_mapping(scanner_name: str, sample_file: Path) -> str:
    """Generate YAML mapping template for a scanner"""
    
    try:
        # Determine file type
        file_ext = sample_file.suffix.lower()
        
        if file_ext == '.json':
            with open(sample_file, 'r') as f:
                data = json.load(f)
            
            # Analyze structure
            fields = analyze_json_structure(data, max_depth=4)
            asset_type = detect_scanner_type(scanner_name, data)
            vuln_paths = find_vulnerability_array_path(data)
            
            # Generate YAML
            yaml_content = f"""
  # {scanner_name.replace('_', ' ').title()} Scanner
  {scanner_name}:
    formats:
      - name: "{scanner_name}_json"
        file_patterns: ["*.json", "*{scanner_name}*.json"]
        format_type: "json"
        asset_type: "{asset_type}"
        detection:
          json_keys: {json.dumps(list(data.keys())[:10])}
          required_keys: {json.dumps(list(data.keys())[:3])}
        field_mappings:
          asset:
"""
            
            # Asset mappings based on type
            if asset_type == "CONTAINER":
                yaml_content += f"""            repository: "{list(fields.keys())[0] if fields else 'image'}"
            dockerfile: "Dockerfile"
            origin: "{scanner_name}"
"""
            elif asset_type == "CODE":
                yaml_content += f"""            scannerSource: "{list(fields.keys())[0] if fields else 'project'}"
            origin: "{scanner_name}"
"""
            elif asset_type == "INFRA":
                yaml_content += f"""            ip: "{list(fields.keys())[0] if fields else 'ip_address'}"
            hostname: "{list(fields.keys())[1] if len(fields) > 1 else 'hostname'}"
            origin: "{scanner_name}"
"""
            elif asset_type == "WEB":
                yaml_content += f"""            fqdn: "{list(fields.keys())[0] if fields else 'url'}"
            origin: "{scanner_name}"
"""
            elif asset_type == "CLOUD":
                yaml_content += f"""            providerType: "AWS"  # or AZURE, GCP
            providerAccountId: "{list(fields.keys())[0] if fields else 'account_id'}"
            region: "{list(fields.keys())[1] if len(fields) > 1 else 'region'}"
            origin: "{scanner_name}"
"""
            else:
                yaml_content += f"""            origin: "{scanner_name}"
"""
            
            # Vulnerability mappings
            vuln_path = vuln_paths[0] if vuln_paths else "vulnerabilities"
            yaml_content += f"""          vulnerability:
            name: "{vuln_path}[].title"  # TODO: Adjust based on actual field
            description: "{vuln_path}[].description"
            remedy: "{vuln_path}[].solution"
            severity: "{vuln_path}[].severity"
            location: "{vuln_path}[].location"
            reference_ids: "{vuln_path}[].cve"
            cwes: "{vuln_path}[].cwe"
            published_date_time: "{vuln_path}[].published"
            details:
              scanner_id: "{vuln_path}[].id"
              cvss_score: "{vuln_path}[].cvss_score"
        severity_mapping:
          "critical": "10.0"
          "high": "8.0"
          "medium": "5.0"
          "low": "2.0"
          "info": "1.0"
"""
            
            return yaml_content
            
        elif file_ext == '.xml':
            return f"""
  # {scanner_name.replace('_', ' ').title()} Scanner
  {scanner_name}:
    formats:
      - name: "{scanner_name}_xml"
        file_patterns: ["*.xml"]
        format_type: "xml"
        asset_type: "WEB"  # TODO: Adjust based on scanner
        detection:
          xml_root: "root"  # TODO: Determine actual root element
          required_elements: ["element1", "element2"]
        field_mappings:
          asset:
            fqdn: "//url"
            origin: "{scanner_name}"
          vulnerability:
            name: "//vulnerability/name"
            description: "//vulnerability/description"
            remedy: "//vulnerability/solution"
            severity: "//vulnerability/severity"
            location: "//vulnerability/location"
        severity_mapping:
          "critical": "10.0"
          "high": "8.0"
          "medium": "5.0"
          "low": "2.0"
"""
        
        elif file_ext == '.csv':
            return f"""
  # {scanner_name.replace('_', ' ').title()} Scanner
  {scanner_name}:
    formats:
      - name: "{scanner_name}_csv"
        file_patterns: ["*.csv"]
        format_type: "csv"
        asset_type: "INFRA"  # TODO: Adjust based on scanner
        detection:
          required_columns: ["IP", "Hostname"]  # TODO: Adjust
        field_mappings:
          asset:
            ip: "IP"
            hostname: "DNS"
            origin: "{scanner_name}"
          vulnerability:
            name: "Title"
            description: "Description"
            remedy: "Solution"
            severity: "Severity"
            location: "Port"
            reference_ids: "CVE"
        severity_mapping:
          "5": "10.0"
          "4": "8.0"
          "3": "5.0"
          "2": "2.0"
          "1": "1.0"
"""
        else:
            return f"  # {scanner_name}: Unsupported format {file_ext}\n"
    
    except Exception as e:
        return f"  # {scanner_name}: Error processing - {str(e)}\n"

def main():
    scans_dir = Path("{PROJECT_ROOT}")
    
    # Scanners that need mapping
    scanners_to_map = [
        "anchore_engine", "api_blackduck", "api_bugcrowd", "api_cobalt", "api_edgescan",
        "api_sonarqube", "api_vulners", "appcheck_web_application_scanner", "appspider",
        "arachni", "asff", "auditjs", "aws_inspector2", "aws_prowler", "aws_prowler_v3plus"
    ]
    
    print("# Generated YAML Mappings - Batch 1")
    print("# Add these to scanner_field_mappings.yaml under the 'scanners:' section")
    print()
    
    for scanner in scanners_to_map:
        scanner_dir = scans_dir / scanner
        if not scanner_dir.exists():
            print(f"  # {scanner}: Directory not found")
            continue
        
        # Find first JSON/XML/CSV file
        sample_files = list(scanner_dir.glob("*.json")) + list(scanner_dir.glob("*.xml")) + list(scanner_dir.glob("*.csv"))
        
        if not sample_files:
            print(f"  # {scanner}: No sample files found")
            continue
        
        sample_file = sample_files[0]
        print(generate_yaml_mapping(scanner, sample_file))

if __name__ == "__main__":
    main()

