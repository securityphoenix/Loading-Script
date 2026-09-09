# 🚀 Quick Start - ALL 203 Scanner Types

**Status:** ✅ Production Ready - YAML-Only Mode  
**Last Updated:** November 10, 2025

---

## 📋 Quick Summary

- **203 Scanner Types** supported via YAML configuration
- **YAML-Only Mode** - No hard-coded translators
- **Auto-Detection** - Automatically identifies scanner type
- **All Formats** - JSON, XML, CSV supported

---

## 🎯 Basic Usage

### Import Any Scanner File

```bash
cd /path/to/Loading_Script_V4

python3 phoenix_multi_scanner_enhanced.py \
  --file /path/to/scan_results.json \
  --config config_test.ini \
  --assessment "My-Scan-Assessment"
```

### Import with Credentials

```bash
# Using provided credentials
python3 phoenix_multi_scanner_enhanced.py \
  --file scan_results.json \
  --config config_test.ini \
  --assessment "Production-Scan"
```

### Config File Format (config_test.ini)

```ini
[phoenix]
client_id = {REDACTED}
client_secret = {REDACTED_PHOENIX_PAT}
api_base_url = https://api.demo.appsecphx.io

[batch_processing]
# Batching configuration
enable_batching = true
max_batch_size = 500
max_payload_mb = 25.0
```

---

## 📊 Supported Scanners (203 Types)

### Quick Reference by Category

| Category | Count | Examples |
|----------|-------|----------|
| **Container** | 30+ | Trivy, Grype, Aqua, Clair, Docker Bench |
| **SAST/Code** | 50+ | Semgrep, Snyk, SonarQube, Checkmarx, Fortify |
| **Infrastructure** | 20+ | Nmap, Qualys, Tenable, OpenVAS, Nexpose |
| **Web App** | 30+ | Burp, ZAP, Arachni, Acunetix, Nikto |
| **Cloud/IaC** | 20+ | Prowler, Checkov, tfsec, Terrascan, KICS |
| **SCA/Dependencies** | 30+ | npm audit, pip audit, Snyk, Black Duck |
| **API/Platform** | 20+ | GitLab SAST, GitHub, Cobalt, Bugcrowd |

**Total:** 203 scanner types

---

## 🔍 Scanner Detection

### Auto-Detection

The system automatically detects scanner type from file content:

```
Detected trivy format with 1.00 confidence
Detected anchore_grype format with 1.00 confidence
Detected snyk format with 0.72 confidence
```

### Confidence Scores

- **1.00** = Perfect match (all identifiers found)
- **0.80** = Very good match (most identifiers found)
- **0.60** = Good match (minimum identifiers found)
- **<0.60** = No match (try different scanner type)

---

## 📁 Sample Commands by Scanner Type

### Container Scanners

```bash
# Trivy - Container Image Scan (default)
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy_results.json \
  --config config_test.ini \
  --assessment "Container-Scan-Trivy"

# Trivy - Filesystem/SCA Scan (use --asset-type BUILD) 🆕
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy_sca_results.json \
  --config config_test.ini \
  --assessment "SCA-Scan-Trivy" \
  --scanner trivy \
  --asset-type BUILD

# Grype
python3 phoenix_multi_scanner_enhanced.py \
  --file grype_results.json \
  --config config_test.ini \
  --assessment "Container-Scan-Grype"

# Aqua
python3 phoenix_multi_scanner_enhanced.py \
  --file aqua_results.json \
  --config config_test.ini \
  --assessment "Container-Scan-Aqua"
```

### SAST Scanners

```bash
# Semgrep
python3 phoenix_multi_scanner_enhanced.py \
  --file semgrep_results.json \
  --config config_test.ini \
  --assessment "SAST-Semgrep"

# Snyk Code
python3 phoenix_multi_scanner_enhanced.py \
  --file snyk_code_results.json \
  --config config_test.ini \
  --assessment "SAST-Snyk"

# SonarQube
python3 phoenix_multi_scanner_enhanced.py \
  --file sonarqube_issues.json \
  --config config_test.ini \
  --assessment "SAST-SonarQube"
```

### Infrastructure Scanners

```bash
# Nmap
python3 phoenix_multi_scanner_enhanced.py \
  --file nmap_results.xml \
  --config config_test.ini \
  --assessment "Infra-Nmap"

# Qualys
python3 phoenix_multi_scanner_enhanced.py \
  --file qualys_export.csv \
  --config config_test.ini \
  --assessment "Infra-Qualys"

# Tenable
python3 phoenix_multi_scanner_enhanced.py \
  --file tenable_export.csv \
  --config config_test.ini \
  --assessment "Infra-Tenable"
```

### Web Application Scanners

```bash
# OWASP ZAP
python3 phoenix_multi_scanner_enhanced.py \
  --file zap_results.xml \
  --config config_test.ini \
  --assessment "WebApp-ZAP"

# Burp Suite
python3 phoenix_multi_scanner_enhanced.py \
  --file burp_results.xml \
  --config config_test.ini \
  --assessment "WebApp-Burp"

# Nuclei
python3 phoenix_multi_scanner_enhanced.py \
  --file nuclei_results.json \
  --config config_test.ini \
  --assessment "WebApp-Nuclei"
```

### Cloud/IaC Scanners

```bash
# AWS Prowler
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler_results.json \
  --config config_test.ini \
  --assessment "Cloud-Prowler"

# Checkov
python3 phoenix_multi_scanner_enhanced.py \
  --file checkov_results.json \
  --config config_test.ini \
  --assessment "IaC-Checkov"

# tfsec
python3 phoenix_multi_scanner_enhanced.py \
  --file tfsec_results.json \
  --config config_test.ini \
  --assessment "IaC-tfsec"
```

### SCA/Dependency Scanners 🆕

```bash
# Trivy Filesystem/SCA Scan
trivy filesystem /path/to/project --format json --output trivy_sca.json
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy_sca.json \
  --config config_test.ini \
  --assessment "SCA-Trivy" \
  --scanner trivy \
  --asset-type BUILD

# npm audit
python3 phoenix_multi_scanner_enhanced.py \
  --file npm_audit_results.json \
  --config config_test.ini \
  --assessment "SCA-NPM-Audit"

# pip-audit
python3 phoenix_multi_scanner_enhanced.py \
  --file pip_audit_results.json \
  --config config_test.ini \
  --assessment "SCA-Pip-Audit"

# Snyk
python3 phoenix_multi_scanner_enhanced.py \
  --file snyk_results.json \
  --config config_test.ini \
  --assessment "SCA-Snyk"

# OWASP Dependency Check
python3 phoenix_multi_scanner_enhanced.py \
  --file dependency_check_report.xml \
  --config config_test.ini \
  --assessment "SCA-OWASP-DepCheck"

# CycloneDX SBOM
python3 phoenix_multi_scanner_enhanced.py \
  --file sbom.json \
  --config config_test.ini \
  --assessment "SCA-CycloneDX"
```

---

## 🧪 Testing

### Test Single Scanner

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scanner_test_files/scans/trivy/scheme_2_many_vulns.json \
  --config config_test.ini \
  --assessment "TEST-Trivy"
```

### Test All Scanners (203 types)

```bash
python3 test_all_scanners.py
```

This will:
- Test all 203 scanner types
- Find sample files automatically
- Generate comprehensive report
- Save results to JSON

---

## 📈 Command-Line Options

| Option | Required | Description | Example |
|--------|----------|-------------|---------|
| `--file` | ✅ Yes | Path to scan file | `scan.json` |
| `--config` | ✅ Yes | Config file path | `config_test.ini` |
| `--assessment` | ✅ Yes | Assessment name | `"Prod-Scan"` |
| `--scanner-type` | No | Force scanner type | `trivy` |
| `--asset-type` | No | Override asset type | `CONTAINER` |
| `--enable-batching` | No | Enable batching (default from config) | - |
| `--max-batch-size` | No | Max items per batch (default from config) | `50` |
| `--max-payload-mb` | No | Max payload MB (default from config) | `10.0` |
| `--log-level` | No | Logging level | `DEBUG` |

---

## ⚙️ Batching Configuration

### Config File Settings (Recommended)

Configure batching in your `config_test.ini` file:

```ini
[batch_processing]
# Enable intelligent batching for large payloads (true/false)
enable_batching = true

# Maximum number of items (vulnerabilities/assets) per batch
# For large vulnerability counts (300+), reduce to 50-100
max_batch_size = 500

# Maximum payload size in MB per batch
# For API 413 errors, reduce to 10-15 MB
max_payload_mb = 25.0
```

### Command-Line Override

Override config file settings when needed:

```bash
# Override batch size for specific scan
python3 phoenix_multi_scanner_enhanced.py \
  --file large-scan.json \
  --config config_test.ini \
  --assessment "Large-Scan" \
  --max-batch-size 50 \
  --max-payload-mb 10.0
```

### Configuration Hierarchy

1. **Command-line arguments** (highest priority) - Override everything
2. **Config file values** (medium priority) - Used if command-line not provided
3. **Default values** (lowest priority) - Fallback if not specified

---

## 🔧 Troubleshooting

### Problem: "Request Entity Too Large" (HTTP 413)

**Cause:** Payload exceeds API size limits

**Solution 1:** Reduce batch size in config file
```ini
[batch_processing]
max_batch_size = 50
max_payload_mb = 10.0
```

**Solution 2:** Override on command line
```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --config config_test.ini \
  --assessment "test" \
  --max-batch-size 25 \
  --max-payload-mb 5.0
```

### Problem: "Could not detect scanner type"

**Solution 1:** Check YAML mapping exists

```bash
grep -A 5 "scanner_name:" scanner_field_mappings.yaml
```

**Solution 2:** Enable debug logging

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --config config_test.ini \
  --assessment "test" \
  --log-level DEBUG
```

**Solution 3:** Verify file format

```bash
# For JSON files
python3 -m json.tool scan.json

# For XML files
xmllint --format scan.xml
```

### Problem: Low confidence score

**Cause:** Scanner output doesn't match expected patterns

**Solution:** Update YAML mapping in `scanner_field_mappings.yaml`:

```yaml
scanners:
  your_scanner:
    formats:
      - detection:
          json_keys: ["key1", "key2", "key3"]  # Add more keys
          required_keys: ["key1", "key2"]      # Add unique keys
```

### Problem: "Invalid data format" from API

**Cause:** Field mapping doesn't match Phoenix API requirements

**Solution:** Check field mappings in YAML:

```yaml
field_mappings:
  asset:
    # Make sure these match your scanner output
    repository: "actual_field_name_in_scan"
  vulnerability:
    name: "actual_vuln_name_field"
    severity: "actual_severity_field"
```

---

## 📊 Expected Output

### Successful Import

```
🔧 Initializing translators (YAML-ONLY mode - all 200+ scanner types)...
✅ Initialized 1 translator (YAML-based only - supports 200+ scanner types)
🔍 Detected scanner type: configurablescanner
Detected trivy format with 1.00 confidence
📦 Total Assets: 1
🔍 Total Vulnerabilities: 15
✅ Successfully processed scan_results.json
   Scanner: configurablescanner
   Assessment: Production-Scan
   Assets: 1
   Vulnerabilities: 15
   Success Rate: 100.0%
```

### Detection Confidence

```
INFO - Detected trivy format with 1.00 confidence       # Perfect
INFO - Detected snyk format with 0.80 confidence        # Very good
INFO - Detected anchore format with 0.65 confidence     # Good
```

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| `IMPLEMENTATION_COMPLETE_ALL_SCANNERS.md` | Full implementation details |
| `QUICK_START_ALL_SCANNERS.md` | This file - quick reference |
| `scanner_field_mappings.yaml` | All 203 scanner mappings |
| `test_all_scanners.py` | Comprehensive test script |
| `create_all_mappings.py` | Mapping generator tool |

---

## 🎯 Common Use Cases

### Daily Security Scans

```bash
# Morning container scan
python3 phoenix_multi_scanner_enhanced.py \
  --file daily_trivy_scan.json \
  --config config_test.ini \
  --assessment "Daily-Container-$(date +%Y%m%d)"

# Code security scan
python3 phoenix_multi_scanner_enhanced.py \
  --file daily_semgrep_scan.json \
  --config config_test.ini \
  --assessment "Daily-SAST-$(date +%Y%m%d)"
```

### CI/CD Integration

```bash
# In your pipeline
python3 phoenix_multi_scanner_enhanced.py \
  --file $SCAN_OUTPUT \
  --config config_prod.ini \
  --assessment "Build-${BUILD_NUMBER}-${SCANNER_NAME}"
```

### Batch Processing

```bash
# Process all scans in a directory
for file in scans/*.json; do
    scanner=$(basename $(dirname $file))
    python3 phoenix_multi_scanner_enhanced.py \
      --file "$file" \
      --config config_test.ini \
      --assessment "Batch-${scanner}-$(date +%Y%m%d)"
done
```

---

## ✅ Verification

### Check System Status

```bash
# Verify YAML-only mode
python3 -c "from phoenix_multi_scanner_enhanced import EnhancedMultiScannerImportManager; print('✅ YAML-only mode active')"

# Check scanner count in YAML
grep -c "^  [a-z]" scanner_field_mappings.yaml
# Should output: 203
```

### Test Import Pipeline

```bash
# End-to-end test
python3 phoenix_multi_scanner_enhanced.py \
  --file scanner_test_files/scans/trivy/scheme_2_many_vulns.json \
  --config config_test.ini \
  --assessment "Pipeline-Test"
```

---

## 🚀 Next Steps

1. **Choose a scanner type** from the 203 supported types
2. **Generate scan output** using your chosen scanner
3. **Run import command** with your scan file
4. **Verify in Phoenix** - Check assets and vulnerabilities imported
5. **Automate** - Add to CI/CD pipeline

---

## 📞 Support

### For Issues

1. Check this guide
2. Enable debug logging: `--log-level DEBUG`
3. Review logs: `tail -f errors.log`
4. Check YAML mapping: `scanner_field_mappings.yaml`

### For New Scanners

1. Add mapping to `scanner_field_mappings.yaml`
2. Test with sample file
3. Refine mapping based on results
4. No code changes needed!

---

**Status:** ✅ All 203 scanner types ready for use  
**Mode:** YAML-only (no hard-coded translators)  
**Version:** v5.0.0-yaml-only

*Happy Scanning! 🎉*

