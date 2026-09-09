# Phoenix Multi-Scanner Import Tool - Detailed Command Guide

Complete command reference and usage guide for the Phoenix Security Multi-Scanner Import Tools.

## 📋 Table of Contents

- [Tool Selection Guide](#tool-selection-guide)
- [Quick Command Reference](#quick-command-reference)
- [Enhanced Tool Commands](#enhanced-tool-commands)
- [Detailed Command Options](#detailed-command-options)
- [Scanner-Specific Examples](#scanner-specific-examples)
- [Import Modes](#import-modes)
- [Configuration Examples](#configuration-examples)
- [Troubleshooting Commands](#troubleshooting-commands)

---

## 🔧 Tool Selection Guide

### **Enhanced vs Standard Multi-Scanner Tools**

| Tool | Best For | Key Features |
|------|----------|-------------|
| **`phoenix_multi_scanner_enhanced.py`** | **Production imports with large datasets** | Intelligent batching, data validation, retry logic |
| **`phoenix_multi_scanner_import.py`** | Standard imports and testing | Basic multi-scanner support, simpler processing |

### **When to Use Enhanced Tool**
✅ **Large datasets** (1000+ vulnerabilities)  
✅ **Production environments** with reliability requirements  
✅ **Data quality issues** (malformed CSV files)  
✅ **API rate limiting** concerns  
✅ **Batch processing** multiple large files  

### **When to Use Standard Tool**
✅ **Small to medium datasets** (<1000 vulnerabilities)  
✅ **Testing and development**  
✅ **Simple, one-off imports**  
✅ **Learning and experimentation**  

---

## 🚀 Quick Command Reference

### **Enhanced Tool Commands (Recommended for Production)**

```bash
# Auto-detect scanner with intelligent batching (RECOMMENDED)
python phoenix_multi_scanner_enhanced.py --folder /security_scans/ --scanner auto

# Large dataset with conservative batching
python phoenix_multi_scanner_enhanced.py --file large_scan.csv --max-batch-size 50 --max-payload-mb 15

# Production import with verification
python phoenix_multi_scanner_enhanced.py --folder /scans/ --assessment "Production-$(date +%Y%m%d_%H%M%S)" --verify-import

# Fix data quality issues automatically
python phoenix_multi_scanner_enhanced.py --file broken.csv --fix-data --scanner tenable
```

### **Standard Tool Commands**

```bash
# Auto-detect scanner and import (basic processing)
python phoenix_multi_scanner_import.py --file scan_results.json

# Process entire folder with mixed scanner types
python phoenix_multi_scanner_import.py --folder /security_scans/

# Specify scanner type when auto-detection fails
python phoenix_multi_scanner_import.py --file results.csv --scanner qualys

# Merge import to update existing vulnerabilities
python phoenix_multi_scanner_import.py --file scan.json --import-type merge
```

### One-Liner Examples

```bash
# Aqua container scan
python phoenix_multi_scanner_import.py --file aqua_scan.json --scanner aqua

# JFrog Xray build scan  
python phoenix_multi_scanner_import.py --file jfrog_scan.json --scanner jfrog

# Qualys infrastructure scan
python phoenix_multi_scanner_import.py --file qualys_scan.csv --scanner qualys

# SonarQube code scan
python phoenix_multi_scanner_import.py --file sonar_scan.json --scanner sonarqube

# Tenable network scan
python phoenix_multi_scanner_import.py --file nessus_scan.csv --scanner tenable
```

---

## ⚡ Enhanced Tool Commands

### **Performance & Batching Options**

| Option | Type | Description | Example |
|--------|------|-------------|----------|
| `--max-batch-size` | Integer | Maximum assets per batch | `--max-batch-size 50` |
| `--max-payload-mb` | Float | Maximum payload size in MB | `--max-payload-mb 15.0` |
| `--max-retries` | Integer | Maximum retry attempts | `--max-retries 3` |
| `--enable-batching` | Flag | Enable intelligent batching | `--enable-batching` |
| `--disable-batching` | Flag | Disable batching (process all at once) | `--disable-batching` |

**Usage:**
```bash
# Conservative batching for high-vulnerability datasets
python phoenix_multi_scanner_enhanced.py --file large_scan.csv \
  --max-batch-size 50 --max-payload-mb 15 --max-retries 3

# Aggressive batching for clean datasets
python phoenix_multi_scanner_enhanced.py --file clean_scan.csv \
  --max-batch-size 200 --max-payload-mb 50

# Disable batching for small files
python phoenix_multi_scanner_enhanced.py --file small_scan.csv --disable-batching
```

### **Data Quality & Validation Options**

| Option | Type | Description | Example |
|--------|------|-------------|----------|
| `--fix-data` | Flag | Automatically fix data quality issues | `--fix-data` |
| `--no-fix-data` | Flag | Disable automatic data fixing | `--no-fix-data` |
| `--verify-import` | Flag | Verify imported data in Phoenix | `--verify-import` |

**Usage:**
```bash
# Fix malformed CSV files automatically
python phoenix_multi_scanner_enhanced.py --file broken.csv --fix-data --scanner tenable

# Verify successful import
python phoenix_multi_scanner_enhanced.py --file scan.csv --verify-import

# Disable data fixing for clean files
python phoenix_multi_scanner_enhanced.py --file clean.csv --no-fix-data
```

### **Enhanced Tool Complete Example**

```bash
# Production-ready command with all enhanced features
python phoenix_multi_scanner_enhanced.py \
  --folder "data-csv/mcs/tag-import-anonym-1-adm/" \
  --scanner tenable \
  --asset-type INFRA \
  --tag-file "customization/tags_config.yaml" \
  --assessment "PROD-IMPORT-$(date +%Y%m%d_%H%M%S)" \
  --import-type merge \
  --max-batch-size 50 \
  --max-payload-mb 15 \
  --max-retries 3 \
  --fix-data \
  --verify-import \
  --log-level INFO
```

---

## 📖 Detailed Command Options

### Input Options (Mutually Exclusive)

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `--file` | String | Process a single scanner file | `--file aqua_scan.json` |
| `--folder` | String | Process all scanner files in folder | `--folder /security_scans/` |

**Usage:**
```bash
# Single file processing
python phoenix_multi_scanner_import.py --file /path/to/scan_results.json

# Folder processing (recursive)
python phoenix_multi_scanner_import.py --folder /path/to/scan_folder/
```

### Scanner Options

| Option | Type | Values | Default | Description |
|--------|------|--------|---------|-------------|
| `--scanner` | String | `aqua`, `jfrog`, `qualys`, `sonarqube`, `tenable`, `auto` | `auto` | Scanner type |
| `--asset-type` | String | `INFRA`, `WEB`, `CLOUD`, `CONTAINER`, `REPOSITORY`, `CODE`, `BUILD` | Auto-detected | Override asset type |

**Usage:**
```bash
# Let tool auto-detect scanner type
python phoenix_multi_scanner_import.py --file scan.json

# Specify scanner type explicitly
python phoenix_multi_scanner_import.py --file scan.json --scanner qualys

# Override asset type (useful for Qualys web scans)
python phoenix_multi_scanner_import.py --file qualys_webapp.xml --scanner qualys --asset-type WEB
```

### Import Configuration

| Option | Type | Values | Default | Description |
|--------|------|--------|---------|-------------|
| `--assessment` | String | Any string | Auto-generated | Assessment name in Phoenix |
| `--import-type` | String | `new`, `merge`, `delta` | `new` | Import mode |

**Usage:**
```bash
# Custom assessment name
python phoenix_multi_scanner_import.py --file scan.json --assessment "Q4 Security Assessment"

# Merge import (update existing vulnerabilities)
python phoenix_multi_scanner_import.py --file scan.json --import-type merge

# Delta import (only add/update, don't remove)
python phoenix_multi_scanner_import.py --file scan.json --import-type delta
```

### Processing Options

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `--anonymize` | Flag | Anonymize IP addresses and hostnames | `--anonymize` |
| `--just-tags` | Flag | Only add tags, do not import vulnerabilities | `--just-tags` |
| `--file-types` | List | File types to process in folder mode | `--file-types json csv xml` |

**Usage:**
```bash
# Anonymize sensitive data for testing
python phoenix_multi_scanner_import.py --file prod_scan.csv --anonymize

# Only add tags to existing assets
python phoenix_multi_scanner_import.py --file assets.json --just-tags

# Process only specific file types in folder
python phoenix_multi_scanner_import.py --folder /scans/ --file-types json csv
```

### Configuration Options

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `--config` | String | Configuration file path | `--config custom.ini` |
| `--tag-file` | String | Tag configuration file | `--tag-file custom_tags.yaml` |
| `--client-id` | String | Phoenix API client ID (overrides config) | `--client-id YOUR_ID` |
| `--client-secret` | String | Phoenix API client secret (overrides config) | `--client-secret YOUR_SECRET` |
| `--api-url` | String | Phoenix API base URL (overrides config) | `--api-url https://api.demo.appsecphx.io` |

**Usage:**
```bash
# Use custom configuration file
python phoenix_multi_scanner_import.py --file scan.json --config custom_config.ini

# Override API credentials
python phoenix_multi_scanner_import.py --file scan.json \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --api-url https://api.poc1.appsecphx.io

# Use custom tag configuration
python phoenix_multi_scanner_import.py --file scan.json --tag-file security_tags.yaml
```

### Logging Options

| Option | Type | Values | Default | Description |
|--------|------|--------|---------|-------------|
| `--log-level` | String | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` | Logging verbosity |

**Usage:**
```bash
# Debug mode for troubleshooting
python phoenix_multi_scanner_import.py --file scan.json --log-level DEBUG

# Quiet mode (errors only)
python phoenix_multi_scanner_import.py --file scan.json --log-level ERROR
```

---

## 🔍 Scanner-Specific Examples

### Aqua Security Scans

```bash
# Basic Aqua container scan
python phoenix_multi_scanner_import.py --file aqua_scan.json --scanner aqua

# Aqua scan with custom assessment name
python phoenix_multi_scanner_import.py --file aqua_scan.json --scanner aqua --assessment "Container Security Scan"

# Process folder of Aqua scans
python phoenix_multi_scanner_import.py --folder /aqua_scans/ --scanner aqua --file-types json
```

**Aqua File Characteristics:**
- Format: JSON
- Key indicators: `image`, `resources`, `vulnerability_summary`
- Asset type: CONTAINER
- Auto-detection: ✅ Reliable

### JFrog Xray Scans

```bash
# JFrog Xray API Summary format
python phoenix_multi_scanner_import.py --file jfrog_api_summary.json --scanner jfrog

# JFrog Xray On-Demand Binary scan
python phoenix_multi_scanner_import.py --file jfrog_binary_scan.json --scanner jfrog

# JFrog Xray Unified format
python phoenix_multi_scanner_import.py --file jfrog_unified.json --scanner jfrog

# Override asset type for container scans
python phoenix_multi_scanner_import.py --file jfrog_docker.json --scanner jfrog --asset-type CONTAINER
```

**JFrog File Characteristics:**
- Format: JSON (multiple sub-formats)
- Key indicators: `artifacts`, `issues`, `impact_path`
- Asset type: BUILD (default), CONTAINER (for Docker)
- Auto-detection: ✅ Reliable

### Qualys Scans

```bash
# Qualys infrastructure CSV export
python phoenix_multi_scanner_import.py --file qualys_infra.csv --scanner qualys

# Qualys web application XML report
python phoenix_multi_scanner_import.py --file qualys_webapp.xml --scanner qualys --asset-type WEB

# Qualys infrastructure XML report
python phoenix_multi_scanner_import.py --file qualys_infra.xml --scanner qualys

# Process mixed Qualys formats
python phoenix_multi_scanner_import.py --folder /qualys_scans/ --scanner qualys --file-types csv xml
```

**Qualys File Characteristics:**
- Format: CSV, XML
- Key indicators: `qid`, `qualys`, CSV headers with IP/DNS/QID
- Asset type: INFRA (default), WEB (for webapp scans)
- Auto-detection: ✅ Reliable

### SonarQube Scans

```bash
# SonarQube JSON export
python phoenix_multi_scanner_import.py --file sonar_results.json --scanner sonarqube

# SonarQube scan with custom project assessment
python phoenix_multi_scanner_import.py --file sonar_scan.json --scanner sonarqube --assessment "Code Quality Review"

# Process multiple SonarQube projects
python phoenix_multi_scanner_import.py --folder /sonar_exports/ --scanner sonarqube --file-types json
```

**SonarQube File Characteristics:**
- Format: JSON
- Key indicators: `sonarBaseURL`, `projectName`, `rules`, `issues`
- Asset type: CODE
- Auto-detection: ✅ Reliable

### Tenable/Nessus Scans

```bash
# Tenable CSV export
python phoenix_multi_scanner_import.py --file nessus_scan.csv --scanner tenable

# Tenable scan with anonymization
python phoenix_multi_scanner_import.py --file tenable_prod.csv --scanner tenable --anonymize

# Process folder of Tenable exports
python phoenix_multi_scanner_import.py --folder /tenable_scans/ --scanner tenable --file-types csv
```

**Tenable File Characteristics:**
- Format: CSV
- Key indicators: `plugin id`, `nessus`, `tenable`, CSV headers
- Asset type: INFRA
- Auto-detection: ✅ Reliable

---

## 🔄 Import Modes

### New Import (`--import-type new`)

**Description:** Replace all existing vulnerabilities in the assessment with new scan results.

**Use Case:** Fresh, complete scan results that represent the current state.

```bash
# New import (default behavior)
python phoenix_multi_scanner_import.py --file complete_scan.json --import-type new

# Equivalent (new is default)
python phoenix_multi_scanner_import.py --file complete_scan.json
```

**Behavior:**
- Removes existing vulnerabilities not in the new scan
- Adds new vulnerabilities from the scan
- Updates existing vulnerabilities with new data

### Merge Import (`--import-type merge`)

**Description:** Update existing vulnerabilities and add new ones, but don't remove existing ones.

**Use Case:** Incremental scan results or when combining multiple scan sources.

```bash
# Merge import
python phoenix_multi_scanner_import.py --file incremental_scan.json --import-type merge
```

**Behavior:**
- Keeps existing vulnerabilities not in the new scan
- Adds new vulnerabilities from the scan
- Updates existing vulnerabilities with new data

### Delta Import (`--import-type delta`)

**Description:** Only add new vulnerabilities and update existing ones, minimal changes.

**Use Case:** Partial scan results or when you want to preserve existing data.

```bash
# Delta import
python phoenix_multi_scanner_import.py --file partial_scan.json --import-type delta
```

**Behavior:**
- Preserves all existing vulnerabilities
- Adds only new vulnerabilities
- Updates existing vulnerabilities with new data

---

## ⚙️ Configuration Examples

### Basic Configuration File

**File:** `config.ini`
```ini
[phoenix]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
api_base_url = https://api.poc1.appsecphx.io
import_type = new
batch_delay = 10

[scanner_qualys]
asset_type = INFRA
severity_mapping_5 = 10.0
severity_mapping_4 = 8.0
severity_mapping_3 = 5.0
severity_mapping_2 = 2.0
severity_mapping_1 = 1.0
```

**Usage:**
```bash
python phoenix_multi_scanner_import.py --file scan.csv --config config.ini
```

### Scanner-Specific Configuration

**File:** `multi_scanner_config.ini`
```ini
[scanner_aqua]
asset_type = CONTAINER
severity_mapping_critical = 10.0
severity_mapping_high = 8.0
vulnerability_filters = negligible

[scanner_jfrog]
asset_type = BUILD
field_mapping_component_id = repository
severity_mapping_critical = 10.0

[scanner_sonarqube]
asset_type = CODE
severity_mapping_blocker = 10.0
severity_mapping_critical = 9.0
severity_mapping_major = 6.0
```

### Tag Configuration

**File:** `scanner_tags.yaml`
```yaml
custom_data:
  - key: "environment"
    value: "production"
  - key: "scanner-batch"
    value: "2025-q4"
  - key: "compliance"
    value: "SOC2"

environment_tags:
  production:
    - key: "criticality"
      value: "high"
    - key: "sla"
      value: "24h"
```

**Usage:**
```bash
python phoenix_multi_scanner_import.py --file scan.json --tag-file scanner_tags.yaml
```

---

## 🔧 Troubleshooting Commands

### Debug and Validation

```bash
# Enable debug logging for detailed troubleshooting
python phoenix_multi_scanner_import.py --file scan.json --log-level DEBUG

# Test scanner detection
python scanner_mapping_examples.py --detection

# Validate scanner mappings
python scanner_mapping_examples.py --mappings

# Run comprehensive tests
python scanner_mapping_examples.py --all
```

### Common Issues and Solutions

#### Scanner Detection Issues

**Problem:** Scanner type not detected automatically
```bash
❌ Could not detect scanner type for file: unknown_scan.json
```

**Solution:** Specify scanner type explicitly
```bash
python phoenix_multi_scanner_import.py --file unknown_scan.json --scanner qualys
```

#### Authentication Issues

**Problem:** Authentication failed
```bash
❌ Failed to obtain Phoenix API token: 401 - Unauthorized
```

**Solutions:**
```bash
# Check credentials in config file
python phoenix_multi_scanner_import.py --file scan.json --log-level DEBUG

# Override credentials via command line
python phoenix_multi_scanner_import.py --file scan.json \
  --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
```

#### File Format Issues

**Problem:** File format not supported
```bash
❌ No suitable data loader found for file: scan_results.txt
```

**Solution:** Ensure file has supported extension and content
```bash
# Supported formats: .json, .csv, .xml
# Check file content matches scanner format
python phoenix_multi_scanner_import.py --file scan_results.json --log-level DEBUG
```

#### Large File Processing

**Problem:** Large file timeout or memory issues
```bash
⚠️ Import timed out after 3600 seconds
```

**Solutions:**
```bash
# Increase timeout in config.ini
[phoenix]
timeout = 7200

# Process in smaller batches
python phoenix_multi_scanner_import.py --folder /large_scans/ --file-types json
```

### Performance Optimization

```bash
# Process large folders efficiently
python phoenix_multi_scanner_import.py --folder /scans/ --file-types json csv

# Add delays for API rate limiting
# Set batch_delay = 30 in config.ini

# Use anonymization for test environments
python phoenix_multi_scanner_import.py --folder /prod_scans/ --anonymize
```

---

## 🚀 Advanced Usage Patterns

### Automation Scripts

**Daily Processing Script:**
```bash
#!/bin/bash
SCAN_DATE=$(date +%Y%m%d)
SCAN_DIR="/daily_scans/$SCAN_DATE"

python phoenix_multi_scanner_import.py \
  --folder "$SCAN_DIR" \
  --assessment "Daily Security Scan $SCAN_DATE" \
  --import-type merge \
  --log-level INFO
```

**Multi-Environment Processing:**
```bash
#!/bin/bash
for env in prod staging dev; do
  python phoenix_multi_scanner_import.py \
    --folder "/scans/$env/" \
    --assessment "$env Environment Scan" \
    --tag-file "tags_$env.yaml"
done
```

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: Import Security Scans
  run: |
    python phoenix_multi_scanner_import.py \
      --folder ./scan_results/ \
      --assessment "CI Build ${{ github.run_number }}" \
      --client-id ${{ secrets.PHOENIX_CLIENT_ID }} \
      --client-secret ${{ secrets.PHOENIX_CLIENT_SECRET }} \
      --import-type delta
```

**Jenkins Pipeline:**
```groovy
stage('Import Security Scans') {
    steps {
        sh '''
            python phoenix_multi_scanner_import.py \
              --folder scan_results/ \
              --assessment "Build ${BUILD_NUMBER}" \
              --import-type merge
        '''
    }
}
```

This comprehensive command guide provides all the information needed to effectively use the Phoenix Multi-Scanner Import Tool in any environment or use case.
