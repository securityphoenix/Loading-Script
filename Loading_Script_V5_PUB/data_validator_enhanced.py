#!/usr/bin/env python3
"""
Enhanced Data Validator and CSV Fixer for Phoenix Security Import
Handles missing vulnerability descriptions, payload validation, and data quality checks
"""

import csv
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from datetime import datetime
# import pandas as pd  # Removed to avoid hanging issues

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationIssue:
    """Represents a data validation issue"""
    severity: str  # CRITICAL, ERROR, WARNING, INFO
    field: str
    message: str
    row_number: Optional[int] = None
    suggested_fix: Optional[str] = None

@dataclass
class ValidationResult:
    """Results of data validation"""
    is_valid: bool
    issues: List[ValidationIssue]
    fixed_data: Optional[Any] = None
    
    def get_critical_issues(self) -> List[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "CRITICAL"]
    
    def get_error_issues(self) -> List[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "ERROR"]

class EnhancedDataValidator:
    """Enhanced validator with automatic data fixing capabilities"""
    
    def __init__(self):
        self.required_vulnerability_fields = ['name', 'description', 'remedy', 'severity', 'location']
        self.required_asset_fields = ['asset_type', 'attributes']
        
        # CVE pattern for extraction
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        self.cwe_pattern = re.compile(r'CWE-\d+', re.IGNORECASE)
        
        # Common severity mappings
        self.severity_mappings = {
            'critical': '10.0', 'high': '8.0', 'medium': '5.0', 
            'low': '2.0', 'info': '1.0', 'informational': '1.0',
            '5': '10.0', '4': '8.0', '3': '5.0', '2': '2.0', '1': '1.0'
        }
    
    def validate_and_fix_csv(self, file_path: str, output_path: Optional[str] = None) -> ValidationResult:
        """Validate and fix CSV file with missing vulnerability descriptions"""
        logger.info(f"🔍 Validating and fixing CSV file: {file_path}")
        
        issues = []
        fixed_rows = []
        
        try:
            # Read CSV file with proper newline handling
            with open(file_path, 'r', encoding='utf-8', newline='', errors='replace') as f:
                # Try to detect delimiter, with fallback to comma
                delimiter = ','
                try:
                    sample = f.read(1024)
                    f.seek(0)
                    sniffer = csv.Sniffer()
                    delimiter = sniffer.sniff(sample).delimiter
                except Exception:
                    # Fallback: try common delimiters
                    f.seek(0)
                    first_line = f.readline()
                    if first_line.count(',') > first_line.count(';') and first_line.count(',') > first_line.count('\t'):
                        delimiter = ','
                    elif first_line.count(';') > first_line.count('\t'):
                        delimiter = ';'
                    elif first_line.count('\t') > 0:
                        delimiter = '\t'
                    f.seek(0)
                
                reader = csv.DictReader(f, delimiter=delimiter)
                headers = reader.fieldnames
                
                if not headers:
                    issues.append(ValidationIssue(
                        severity="CRITICAL",
                        field="file_structure",
                        message="No headers found in CSV file"
                    ))
                    return ValidationResult(is_valid=False, issues=issues)
                
                logger.info(f"📋 Found headers: {list(headers)}")
                
                # Process each row
                for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                    fixed_row = self._fix_csv_row(row, row_num, issues)
                    fixed_rows.append(fixed_row)
            
            # Write fixed CSV if output path provided
            if output_path and fixed_rows:
                self._write_fixed_csv(fixed_rows, headers, output_path)
                logger.info(f"✅ Fixed CSV written to: {output_path}")
            
            # Determine if validation passed
            critical_issues = [i for i in issues if i.severity == "CRITICAL"]
            is_valid = len(critical_issues) == 0
            
            return ValidationResult(
                is_valid=is_valid,
                issues=issues,
                fixed_data=fixed_rows if fixed_rows else None
            )
            
        except Exception as e:
            logger.error(f"❌ Error validating CSV file: {e}")
            issues.append(ValidationIssue(
                severity="CRITICAL",
                field="file_processing",
                message=f"Failed to process file: {str(e)}"
            ))
            return ValidationResult(is_valid=False, issues=issues)
    
    def _fix_csv_row(self, row: Dict[str, str], row_num: int, issues: List[ValidationIssue]) -> Dict[str, str]:
        """Fix issues in a single CSV row"""
        fixed_row = row.copy()
        
        # Fix missing vulnerability description
        description = row.get('Description', '').strip()
        if not description:
            # Try to generate description from available fields
            generated_desc = self._generate_vulnerability_description(row)
            fixed_row['Description'] = generated_desc
            
            issues.append(ValidationIssue(
                severity="WARNING",
                field="Description",
                message=f"Missing description, generated: '{generated_desc[:50]}...'",
                row_number=row_num,
                suggested_fix=f"Generated from available vulnerability data"
            ))
        
        # Validate and fix severity
        severity = row.get('Severity', '').strip().lower()
        if severity and severity not in self.severity_mappings:
            # Try to map common variations
            if 'crit' in severity:
                fixed_row['Severity'] = 'Critical'
            elif 'high' in severity:
                fixed_row['Severity'] = 'High'
            elif 'med' in severity or 'mid' in severity:
                fixed_row['Severity'] = 'Medium'
            elif 'low' in severity:
                fixed_row['Severity'] = 'Low'
            else:
                fixed_row['Severity'] = 'Medium'  # Default
                
            issues.append(ValidationIssue(
                severity="INFO",
                field="Severity",
                message=f"Normalized severity from '{severity}' to '{fixed_row['Severity']}'",
                row_number=row_num
            ))
        
        # Validate required fields exist
        required_fields = ['Plugin Name', 'IP Address']
        for field in required_fields:
            if not row.get(field, '').strip():
                issues.append(ValidationIssue(
                    severity="ERROR",
                    field=field,
                    message=f"Missing required field: {field}",
                    row_number=row_num
                ))
        
        return fixed_row
    
    def _generate_vulnerability_description(self, row: Dict[str, str]) -> str:
        """Generate vulnerability description from available data"""
        
        # Priority order for description generation
        description_sources = [
            'Synopsis',           # Nessus synopsis
            'Plugin Output',      # Nessus plugin output (truncated)
            'Plugin Name',        # Plugin name as fallback
            'Family',            # Vulnerability family
            'CVE',               # CVE information
            'Risk Factor'        # Risk information
        ]
        
        # Try each source in priority order
        for source in description_sources:
            value = row.get(source, '').strip()
            if value and len(value) > 10:  # Ensure meaningful content
                # Clean and truncate if needed
                if source == 'Plugin Output' and len(value) > 500:
                    value = value[:500] + "... [truncated]"
                
                # Add CVE/CWE information if available
                cve_info = self._extract_reference_info(row)
                if cve_info:
                    value += f" {cve_info}"
                
                return value
        
        # Last resort: generate from available fields
        plugin_name = row.get('Plugin Name', 'Unknown Vulnerability')
        family = row.get('Family', '')
        severity = row.get('Severity', 'Unknown')
        
        description = f"{plugin_name}"
        if family:
            description += f" (Category: {family})"
        description += f" - Severity: {severity}"
        
        # Add reference information
        cve_info = self._extract_reference_info(row)
        if cve_info:
            description += f" {cve_info}"
        else:
            description += " - No additional vulnerability details available"
        
        return description
    
    def _extract_reference_info(self, row: Dict[str, str]) -> str:
        """Extract CVE, CWE, and other reference information"""
        references = []
        
        # Extract CVEs
        cve_field = row.get('CVE', '')
        if cve_field:
            cves = self.cve_pattern.findall(cve_field)
            if cves:
                references.append(f"CVE: {', '.join(cves[:3])}")  # Limit to first 3
        
        # Extract CWEs from various fields
        for field in ['Cross References', 'Plugin Output', 'Description']:
            field_value = row.get(field, '')
            if field_value:
                cwes = self.cwe_pattern.findall(field_value)
                if cwes:
                    references.append(f"CWE: {', '.join(set(cwes[:2]))}")  # Limit and dedupe
                    break
        
        # Add CVSS scores if available
        cvss_v3 = row.get('CVSS V3 Base Score', '').strip()
        cvss_v2 = row.get('CVSS V2 Base Score', '').strip()
        if cvss_v3:
            references.append(f"CVSS v3: {cvss_v3}")
        elif cvss_v2:
            references.append(f"CVSS v2: {cvss_v2}")
        
        return f"[{' | '.join(references)}]" if references else ""
    
    def _write_fixed_csv(self, rows: List[Dict[str, str]], headers: List[str], output_path: str):
        """Write fixed data to CSV file"""
        if not output_path or not output_path.strip():
            logger.warning("Empty output path provided, skipping file write")
            return
            
        output_dir = os.path.dirname(output_path)
        if output_dir:  # Only create directory if path has a directory component
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
    
    def validate_payload_size(self, data: Any, max_size_mb: float = 50.0) -> ValidationResult:
        """Validate payload size and suggest batching if needed"""
        issues = []
        
        try:
            # Convert to JSON to estimate size
            json_str = json.dumps(data, default=str)
            size_bytes = len(json_str.encode('utf-8'))
            size_mb = size_bytes / (1024 * 1024)
            
            logger.info(f"📊 Payload size: {size_mb:.2f} MB")
            
            if size_mb > max_size_mb:
                issues.append(ValidationIssue(
                    severity="ERROR",
                    field="payload_size",
                    message=f"Payload size ({size_mb:.2f} MB) exceeds limit ({max_size_mb} MB)",
                    suggested_fix=f"Split into batches of ~{max_size_mb/2:.0f} MB each"
                ))
                return ValidationResult(is_valid=False, issues=issues)
            
            elif size_mb > max_size_mb * 0.8:  # Warning at 80% of limit
                issues.append(ValidationIssue(
                    severity="WARNING",
                    field="payload_size",
                    message=f"Payload size ({size_mb:.2f} MB) is close to limit ({max_size_mb} MB)",
                    suggested_fix="Consider batching for better performance"
                ))
            
            return ValidationResult(is_valid=True, issues=issues)
            
        except Exception as e:
            issues.append(ValidationIssue(
                severity="ERROR",
                field="payload_validation",
                message=f"Failed to validate payload size: {str(e)}"
            ))
            return ValidationResult(is_valid=False, issues=issues)
    
    def calculate_optimal_batch_size(self, total_items: int, target_size_mb: float = 25.0, 
                                   avg_vulnerabilities_per_asset: int = 1) -> int:
        """Calculate optimal batch size based on target payload size and vulnerability density"""
        if total_items <= 10:
            return total_items  # Don't batch very small datasets
        
        # More accurate estimation based on vulnerability density
        # Base asset: ~2KB, Each vulnerability: ~3-5KB
        base_asset_kb = 2
        kb_per_vulnerability = 4  # Conservative estimate
        
        estimated_kb_per_asset = base_asset_kb + (avg_vulnerabilities_per_asset * kb_per_vulnerability)
        assets_per_mb = 1024 / estimated_kb_per_asset
        
        optimal_batch_size = int(target_size_mb * assets_per_mb)
        
        # More conservative bounds for high-vulnerability datasets
        if avg_vulnerabilities_per_asset > 20:
            # For high-vulnerability datasets, be more conservative
            optimal_batch_size = max(5, min(optimal_batch_size, 50))
        elif avg_vulnerabilities_per_asset > 10:
            optimal_batch_size = max(10, min(optimal_batch_size, 100))
        else:
            optimal_batch_size = max(20, min(optimal_batch_size, 500))
        
        logger.info(f"📦 Calculated optimal batch size: {optimal_batch_size} assets")
        logger.info(f"   Target payload: {target_size_mb} MB")
        logger.info(f"   Avg vulnerabilities per asset: {avg_vulnerabilities_per_asset}")
        logger.info(f"   Estimated size per asset: {estimated_kb_per_asset:.1f} KB")
        
        return optimal_batch_size

def main():
    """Command line interface for data validation and fixing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Data Validator and CSV Fixer for Phoenix Security Import"
    )
    parser.add_argument('--file', required=True, help='CSV file to validate and fix')
    parser.add_argument('--output', help='Output path for fixed CSV file')
    parser.add_argument('--max-size-mb', type=float, default=50.0, 
                       help='Maximum payload size in MB (default: 50)')
    
    args = parser.parse_args()
    
    validator = EnhancedDataValidator()
    
    # Generate output path if not provided
    if not args.output:
        file_path = Path(args.file)
        args.output = str(file_path.parent / f"{file_path.stem}_fixed{file_path.suffix}")
    
    # Validate and fix CSV
    result = validator.validate_and_fix_csv(args.file, args.output)
    
    # Print results
    print(f"\n🔍 Validation Results for: {args.file}")
    print(f"✅ Valid: {result.is_valid}")
    print(f"📊 Issues found: {len(result.issues)}")
    
    # Group issues by severity
    by_severity = {}
    for issue in result.issues:
        if issue.severity not in by_severity:
            by_severity[issue.severity] = []
        by_severity[issue.severity].append(issue)
    
    for severity in ['CRITICAL', 'ERROR', 'WARNING', 'INFO']:
        if severity in by_severity:
            print(f"\n{severity} ({len(by_severity[severity])}):")
            for issue in by_severity[severity][:5]:  # Show first 5
                row_info = f" (Row {issue.row_number})" if issue.row_number else ""
                print(f"  • {issue.field}: {issue.message}{row_info}")
            
            if len(by_severity[severity]) > 5:
                print(f"  ... and {len(by_severity[severity]) - 5} more")
    
    if result.is_valid:
        print(f"\n✅ Fixed file written to: {args.output}")
        return 0
    else:
        print(f"\n❌ Critical issues found. Please review and fix manually.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
