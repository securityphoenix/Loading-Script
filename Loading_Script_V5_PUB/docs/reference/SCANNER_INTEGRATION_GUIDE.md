# Phoenix Security Scanner Integration Guide

## Overview

The Phoenix Security Multi-Scanner Import Tool now supports 15+ security scanners through a universal, YAML-configurable field mapping system. This guide explains how to use the enhanced scanner integration and how to add support for new scanners.

## Supported Scanners

### ✅ Currently Supported (15+ Scanners)

| Scanner | Format(s) | Asset Type | Status |
|---------|-----------|------------|---------|
| **Acunetix** | JSON (360), XML | WEB | ✅ Full Support |
| **Anchore Grype** | JSON | CONTAINER | ✅ Full Support |
| **Anchore Enterprise** | JSON | CONTAINER | ✅ Full Support |
| **Aqua Security** | JSON | CONTAINER | ✅ Enhanced |
| **Bandit** | JSON | CODE | ✅ Full Support |
| **Burp Suite** | XML | WEB | ✅ Full Support |
| **Checkmarx** | XML | CODE | ✅ Full Support |
| **JFrog Xray** | JSON (Multiple) | BUILD | ✅ Enhanced |
| **Nikto** | XML | WEB | ✅ Full Support |
| **Nmap** | XML | INFRA | ✅ Full Support |
| **OWASP ZAP** | XML | WEB | ✅ Full Support |
| **Qualys** | CSV, XML | INFRA | ✅ Enhanced |
| **Snyk** | JSON | CODE | ✅ Full Support |
| **SonarQube** | JSON | CODE | ✅ Enhanced |
| **Tenable/Nessus** | CSV | INFRA | ✅ Enhanced |
| **Trivy** | JSON | CONTAINER | ✅ Full Support |

### 🔄 Planned Support (85+ Additional Scanners)

The system is designed to easily support 100+ additional scanners through YAML configuration. See the `improvements_and_notes.md` file for the complete roadmap.

## Quick Start

### Basic Usage

```bash
# Auto-detect scanner and import
python phoenix_multi_scanner_import.py --file scan_results.json

# Process entire folder with auto-detection
python phoenix_multi_scanner_import.py --folder /path/to/scans/

# Specify scanner type explicitly
python phoenix_multi_scanner_import.py --file results.xml --scanner acunetix
```

### Advanced Usage

```bash
# Import with custom assessment name and verification
python phoenix_multi_scanner_import.py \
  --folder /scans/acunetix/ \
  --scanner auto \
  --asset-type WEB \
  --assessment "Q4-2025-WebApp-Security-Scan" \
  --verify-import

# Import with custom tags and empty asset creation
python phoenix_multi_scanner_import.py \
  --file trivy_results.json \
  --tag-file custom_tags.yaml \
  --create-empty-assets \
  --import-type merge
```

## Scanner-Specific Examples

### Acunetix

```bash
# Acunetix 360 JSON format
python phoenix_multi_scanner_import.py \
  --file acunetix360_scan.json \
  --asset-type WEB \
  --assessment "WebApp-Security-Scan"

# Acunetix XML format  
python phoenix_multi_scanner_import.py \
  --file acunetix_scan.xml \
  --asset-type WEB
```

### Container Scanners

```bash
# Trivy container scan
python phoenix_multi_scanner_import.py \
  --file trivy_results.json \
  --asset-type CONTAINER \
  --assessment "Container-Security-Scan"

# Aqua Security scan
python phoenix_multi_scanner_import.py \
  --file aqua_scan.json \
  --asset-type CONTAINER

# Anchore Grype scan
python phoenix_multi_scanner_import.py \
  --file grype_results.json \
  --asset-type CONTAINER
```

### Code Analysis Scanners

```bash
# SonarQube results
python phoenix_multi_scanner_import.py \
  --file sonarqube_issues.json \
  --asset-type CODE \
  --assessment "Code-Quality-Analysis"

# Bandit Python SAST
python phoenix_multi_scanner_import.py \
  --file bandit_results.json \
  --asset-type CODE

# Checkmarx SAST
python phoenix_multi_scanner_import.py \
  --file checkmarx_results.xml \
  --asset-type CODE
```

### Infrastructure Scanners

```bash
# Qualys vulnerability scan
python phoenix_multi_scanner_import.py \
  --file qualys_results.csv \
  --asset-type INFRA \
  --assessment "Infrastructure-Vulnerability-Scan"

# Tenable Nessus scan
python phoenix_multi_scanner_import.py \
  --file nessus_results.csv \
  --asset-type INFRA

# Nmap network scan
python phoenix_multi_scanner_import.py \
  --file nmap_results.xml \
  --asset-type INFRA
```

### Web Application Scanners

```bash
# OWASP ZAP scan
python phoenix_multi_scanner_import.py \
  --file zap_results.xml \
  --asset-type WEB \
  --assessment "WebApp-Security-Test"

# Burp Suite scan
python phoenix_multi_scanner_import.py \
  --file burp_results.xml \
  --asset-type WEB

# Nikto web server scan
python phoenix_multi_scanner_import.py \
  --file nikto_results.xml \
  --asset-type WEB
```

## Configuration System

### Field Mapping Configuration

The scanner integration uses a YAML configuration file (`scanner_field_mappings.yaml`) to define how scanner fields map to Phoenix Security fields.

#### Example Configuration Structure

```yaml
scanners:
  scanner_name:
    formats:
      - name: "format_name"
        file_patterns: ["*.json", "*scanner*.xml"]
        format_type: "json"  # json, xml, csv
        asset_type: "WEB"    # INFRA, WEB, CLOUD, CONTAINER, CODE, BUILD
        detection:
          json_keys: ["vulnerabilities", "target"]
          required_keys: ["vulnerabilities"]
        field_mappings:
          asset:
            fqdn: "target.url"
            origin: "scanner-name"
          vulnerability:
            name: "vulnerabilities[].name"
            description: "vulnerabilities[].description"
            severity: "vulnerabilities[].severity"
            location: "vulnerabilities[].location"
        severity_mapping:
          "low": "2.0"
          "medium": "5.0"
          "high": "8.0"
          "critical": "10.0"
```

### Phoenix Field Requirements

#### Asset Attributes by Type

| Asset Type | Required Fields | Optional Fields |
|------------|----------------|-----------------|
| **INFRA** | `ip` OR `hostname` | `network`, `fqdn`, `os`, `netbios`, `macAddress` |
| **WEB** | `ip` OR `fqdn` | `ip`, `fqdn` |
| **CLOUD** | `providerType`, `providerAccountId`, `region` | `vpc`, `subnet`, `providerAccountName`, `providerResourceId`, `resourceGroup` |
| **CONTAINER** | `dockerfile` | `repository`, `origin` |
| **REPOSITORY** | `repository` | `origin` |
| **CODE** | `scannerSource` | `origin` |
| **BUILD** | `buildFile` | `repository`, `origin` |

#### Vulnerability Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | ✅ | String | Vulnerability name/title |
| `description` | ✅ | String | Detailed description |
| `remedy` | ✅ | String | Remediation guidance |
| `severity` | ✅ | String | Severity score (1.0-10.0) |
| `location` | ✅ | String | Where vulnerability was found |
| `referenceIds` | ❌ | Array | CVE IDs, etc. |
| `cwes` | ❌ | Array | CWE identifiers |
| `publishedDateTime` | ❌ | String | Publication date (YYYY-MM-DD HH:MM:SS) |
| `details` | ❌ | Object | Additional scanner-specific data |

## Adding New Scanners

### Step-by-Step Process

#### 1. Analyze Scanner Output

```bash
# Examine sample scanner files
ls scanner_test_files/scans/new_scanner/
cat scanner_test_files/scans/new_scanner/sample.json
```

#### 2. Create Field Mapping

Add configuration to `scanner_field_mappings.yaml`:

```yaml
scanners:
  new_scanner:
    formats:
      - name: "new_scanner_json"
        file_patterns: ["*new_scanner*.json"]
        format_type: "json"
        asset_type: "WEB"
        detection:
          json_keys: ["scan_results", "target_info"]
          required_keys: ["scan_results"]
        field_mappings:
          asset:
            fqdn: "target_info.hostname"
            origin: "new-scanner"
          vulnerability:
            name: "scan_results[].issue_name"
            description: "scan_results[].description"
            remedy: "scan_results[].fix_guidance"
            severity: "scan_results[].risk_level"
            location: "scan_results[].location"
        severity_mapping:
          "info": "1.0"
          "low": "2.0"
          "medium": "5.0"
          "high": "8.0"
          "critical": "10.0"
```

#### 3. Test Integration

```bash
# Test with sample file
python phoenix_multi_scanner_import.py \
  --file scanner_test_files/scans/new_scanner/sample.json \
  --debug

# Verify detection and parsing
python test_scanner_integration.py
```

#### 4. Validate Results

- Check asset creation in Phoenix UI
- Verify vulnerability data accuracy
- Test with multiple sample files
- Validate severity mappings

### Advanced Configuration

#### Custom Detection Logic

```yaml
detection:
  json_keys: ["results", "metadata"]
  required_keys: ["results"]
  # Custom validation can be added in code
```

#### Complex Field Mappings

```yaml
field_mappings:
  vulnerability:
    # Static values
    remedy: "Contact security team for remediation"
    
    # Nested array access
    name: "results[].findings[].title"
    
    # Conditional mapping (handled in code)
    severity: "results[].risk_score"
    
    # Complex location building
    location: "results[].target.host:results[].target.port"
```

#### Multiple Format Support

```yaml
scanners:
  multi_format_scanner:
    formats:
      - name: "format_json"
        file_patterns: ["*.json"]
        format_type: "json"
        # ... JSON-specific config
      
      - name: "format_xml"
        file_patterns: ["*.xml"]
        format_type: "xml"
        # ... XML-specific config
```

## Troubleshooting

### Common Issues

#### 1. Scanner Not Detected

```bash
# Enable debug mode to see detection process
python phoenix_multi_scanner_import.py --file scan.json --debug

# Check file patterns and detection criteria
grep -A 10 "scanner_name" scanner_field_mappings.yaml
```

#### 2. Field Mapping Errors

```bash
# Check field mapping paths
python -c "
from scanner_field_mapper import FieldMapper
import json
with open('scan.json') as f:
    data = json.load(f)
mapper = FieldMapper()
print(mapper.get_nested_value(data, 'path.to.field'))
"
```

#### 3. Severity Mapping Issues

```bash
# Verify severity values in scanner output
jq '.vulnerabilities[].severity' scan.json | sort | uniq

# Check mapping configuration
grep -A 5 "severity_mapping" scanner_field_mappings.yaml
```

#### 4. Asset Type Detection

```bash
# Override asset type explicitly
python phoenix_multi_scanner_import.py \
  --file scan.json \
  --asset-type CONTAINER \
  --debug
```

### Debug Mode

Enable comprehensive debugging:

```bash
python phoenix_multi_scanner_import.py \
  --file scan.json \
  --debug \
  --error-log debug_errors.log
```

Debug output includes:
- Scanner detection process
- Field mapping resolution
- HTTP request/response details
- Parsing statistics
- Error details with stack traces

### Log Files

Check log files for detailed information:

```bash
# Main execution logs
tail -f logs/phoenix_multi_scanner_*.log

# Error logs
tail -f errors/phoenix_multi_scanner_errors_*.log

# Debug logs (when --debug enabled)
ls debug/YYYYMMDD/HHMM/
```

## Performance Considerations

### File Size Recommendations

| File Size | Expected Processing Time | Memory Usage |
|-----------|-------------------------|--------------|
| < 1MB | 1-2 seconds | ~2-5MB |
| 1-10MB | 5-15 seconds | ~10-50MB |
| 10-100MB | 30-180 seconds | ~100-500MB |
| > 100MB | Consider splitting | > 500MB |

### Optimization Tips

1. **Large Files**: Split large scanner outputs into smaller files
2. **Batch Processing**: Use folder mode for multiple files
3. **Memory**: Monitor memory usage for very large files
4. **Network**: Ensure stable connection to Phoenix API

## Security Considerations

### Input Validation

- All scanner inputs are validated before processing
- File paths are sanitized to prevent directory traversal
- Scanner data is sanitized before Phoenix import

### Sensitive Data

- Use `--anonymize` flag for sensitive environments
- Consider data masking for IP addresses and hostnames
- Review scanner outputs for sensitive information

### Access Control

- Ensure proper Phoenix API credentials
- Use least-privilege access for scanner files
- Audit scanner import activities

## Support and Maintenance

### Getting Help

1. **Documentation**: Check this guide and `improvements_and_notes.md`
2. **Debug Mode**: Use `--debug` flag for detailed information
3. **Log Files**: Review error and debug logs
4. **Sample Files**: Test with known-good sample files

### Contributing

1. **New Scanners**: Follow the step-by-step process above
2. **Bug Reports**: Include debug logs and sample files
3. **Feature Requests**: Document use cases and requirements
4. **Testing**: Provide sample scanner outputs for validation

### Maintenance

- Regular updates to scanner field mappings
- Performance monitoring and optimization
- Security updates and vulnerability patches
- Documentation updates for new features

---

*Last Updated: September 2025*
*Version: 2.0.0*
