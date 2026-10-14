# Phoenix Security Import Tools - Master Documentation Index

Complete documentation suite for Phoenix Security import tools with quick command references and detailed guides.

## 📚 Documentation Overview

| Document | Purpose | Audience | Length |
|----------|---------|----------|--------|
| **QUICK_REFERENCE_GUIDE.md** | All tools quick commands | All users | Quick |
| **[README_DATA_ANONYMIZER.md](../guides/README_DATA_ANONYMIZER.md)** | Data anonymizer comprehensive guide | Security teams | Detailed |
| **[README_REFACTORED.md](README_REFACTORED.md)** | Basic Phoenix import tool guide | Developers | Medium |
| **[README_MULTI_SCANNER.md](../guides/README_MULTI_SCANNER.md)** | Multi-scanner tool comprehensive guide | Enterprise users | Detailed |
| **[MULTI_SCANNER_COMMAND_GUIDE.md](../guides/MULTI_SCANNER_COMMAND_GUIDE.md)** | Multi-scanner detailed commands | Power users | Detailed |

## 🚀 Quick Start by Use Case

### I want to...

#### **Anonymize Production Data for Testing**
→ **Use:** `data_anonymizer.py`  
→ **Quick Start:** [Data Anonymizer Quick Commands](#data-anonymizer-quick-commands)  
→ **Full Guide:** [README_DATA_ANONYMIZER.md](../guides/README_DATA_ANONYMIZER.md)

#### **Import Basic CSV/JSON Files**
→ **Use:** `phoenix_import_refactored.py`  
→ **Quick Start:** [Basic Import Quick Commands](#basic-import-quick-commands)  
→ **Full Guide:** [README_REFACTORED.md](README_REFACTORED.md)

#### **Import Multiple Scanner Types**
→ **Use:** `phoenix_multi_scanner_import.py`  
→ **Quick Start:** [Multi-Scanner Quick Commands](#multi-scanner-quick-commands)  
→ **Full Guide:** [README_MULTI_SCANNER.md](../guides/README_MULTI_SCANNER.md)

#### **Automate Security Scan Processing**
→ **Use:** `phoenix_multi_scanner_import.py`  
→ **Quick Start:** [Automation Examples](#automation-examples)  
→ **Full Guide:** [MULTI_SCANNER_COMMAND_GUIDE.md](../guides/MULTI_SCANNER_COMMAND_GUIDE.md)

---

## 🔒 Data Anonymizer Quick Commands

### Most Common Use Cases
```bash
# Anonymize single file for testing
python data_anonymizer.py --file production_scan.csv --output test_scan.csv

# Anonymize entire folder with reproducible results
python data_anonymizer.py --folder /prod_scans/ --output-folder /test_scans/ --seed 12345

# Export mappings for consistency across environments
python data_anonymizer.py --file data.csv --output anon.csv --export-mappings mappings.json
```

### Key Features
- ✅ **IP Address Anonymization** with network structure preservation
- ✅ **Hostname Anonymization** with domain structure retention  
- ✅ **Reproducible Results** using seed values
- ✅ **Batch Processing** for entire folders
- ✅ **Mapping Export/Import** for consistency

**→ Full Documentation:** [README_DATA_ANONYMIZER.md](../guides/README_DATA_ANONYMIZER.md)

---

## 🔧 Basic Import Quick Commands

### Most Common Use Cases
```bash
# Import CSV as infrastructure assets
python phoenix_import_refactored.py --file scan_results.csv --asset-type INFRA

# Import JSON with anonymization
python phoenix_import_refactored.py --file webapp_scan.json --asset-type WEB --anonymize

# Process entire folder
python phoenix_import_refactored.py --folder /scan_results/ --asset-type CLOUD

# Only add tags to existing assets
python phoenix_import_refactored.py --file assets.json --just-tags
```

### Key Features
- ✅ **JSON/CSV Support** with intelligent parsing
- ✅ **Asset Type Mapping** (INFRA, WEB, CLOUD, CONTAINER, REPOSITORY, CODE, BUILD)
- ✅ **Built-in Anonymization** for testing
- ✅ **Tag Management** with YAML configuration
- ✅ **Folder Processing** for batch operations

**→ Full Documentation:** [README_REFACTORED.md](README_REFACTORED.md)

---

## 🚀 Multi-Scanner Quick Commands

### Most Common Use Cases
```bash
# Auto-detect scanner and import (recommended)
python phoenix_multi_scanner_import.py --file scan_results.json

# Process mixed scanner types in folder
python phoenix_multi_scanner_import.py --folder /security_scans/

# Specify scanner type explicitly
python phoenix_multi_scanner_import.py --file results.csv --scanner qualys

# Merge import with custom assessment
python phoenix_multi_scanner_import.py --file scan.json --import-type merge --assessment "Q4 Security Scan"
```

### Supported Scanners
| Scanner | Auto-Detect | Formats | Asset Types |
|---------|-------------|---------|-------------|
| **Aqua Security** | ✅ | JSON | CONTAINER |
| **JFrog Xray** | ✅ | JSON (4 formats) | BUILD, CONTAINER |
| **Qualys** | ✅ | CSV, XML | INFRA, WEB |
| **SonarQube** | ✅ | JSON | CODE |
| **Tenable/Nessus** | ✅ | CSV | INFRA |

### Key Features
- ✅ **Automatic Scanner Detection** from file content
- ✅ **Multi-Format Support** (JSON, CSV, XML)
- ✅ **Import Modes** (new, merge, delta)
- ✅ **Enterprise Features** (batch processing, validation, monitoring)
- ✅ **Maximum Data Preservation** with intelligent mapping

**→ Full Documentation:** [README_MULTI_SCANNER.md](../guides/README_MULTI_SCANNER.md)  
**→ Detailed Commands:** [MULTI_SCANNER_COMMAND_GUIDE.md](../guides/MULTI_SCANNER_COMMAND_GUIDE.md)

---

## ⚙️ Configuration Quick Reference

### Basic Configuration (`config.ini`)
```ini
[phoenix]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
api_base_url = https://api.poc1.appsecphx.io
import_type = new
```

### Multi-Scanner Configuration
```ini
[scanner_qualys]
asset_type = INFRA
severity_mapping_5 = 10.0
vulnerability_filters = info

[scanner_aqua]
asset_type = CONTAINER
severity_mapping_critical = 10.0
```

### Tag Configuration (`tags.yaml`)
```yaml
custom_data:
  - key: "environment"
    value: "production"
  - key: "team"
    value: "security"
```

---

## 🔍 Tool Selection Guide

### Choose the Right Tool

| Scenario | Recommended Tool | Reason |
|----------|------------------|--------|
| **Create test data from production scans** | `data_anonymizer.py` | Specialized anonymization features |
| **Simple CSV/JSON import** | `phoenix_import_refactored.py` | Lightweight, easy to use |
| **Multiple scanner types** | `phoenix_multi_scanner_import.py` | Auto-detection, enterprise features |
| **Unknown scanner format** | `phoenix_multi_scanner_import.py` | Best auto-detection capabilities |
| **Enterprise automation** | `phoenix_multi_scanner_import.py` | Robust error handling, monitoring |
| **One-off data import** | `phoenix_import_refactored.py` | Quick and simple |

### Feature Comparison

| Feature | Data Anonymizer | Basic Import | Multi-Scanner |
|---------|----------------|--------------|---------------|
| **Anonymization** | ✅ Advanced | ✅ Basic | ✅ Basic |
| **Scanner Detection** | ❌ | ❌ | ✅ Advanced |
| **Multiple Formats** | ✅ CSV, JSON | ✅ CSV, JSON | ✅ CSV, JSON, XML |
| **Batch Processing** | ✅ | ✅ | ✅ Advanced |
| **Enterprise Features** | ❌ | ✅ Basic | ✅ Advanced |
| **Configuration** | ✅ Basic | ✅ Medium | ✅ Advanced |

---

## 🚀 Automation Examples

### Daily Scan Processing
```bash
#!/bin/bash
# Process daily security scans
SCAN_DATE=$(date +%Y%m%d)
python phoenix_multi_scanner_import.py \
  --folder "/daily_scans/$SCAN_DATE" \
  --assessment "Daily Security Scan $SCAN_DATE" \
  --import-type merge
```

### Test Data Creation
```bash
#!/bin/bash
# Create anonymized test data weekly
python data_anonymizer.py \
  --folder /production_scans/ \
  --output-folder /test_data/ \
  --seed $(date +%U) \
  --export-mappings /mappings/weekly_mapping.json
```

### CI/CD Integration
```yaml
# GitHub Actions
- name: Import Security Scans
  run: |
    python phoenix_multi_scanner_import.py \
      --folder ./scan_results/ \
      --assessment "CI Build ${{ github.run_number }}" \
      --client-id ${{ secrets.PHOENIX_CLIENT_ID }} \
      --client-secret ${{ secrets.PHOENIX_CLIENT_SECRET }}
```

---

## 🔧 Troubleshooting Quick Reference

### Common Issues

| Issue | Tool | Quick Fix |
|-------|------|-----------|
| **Authentication failed** | All | Check `client_id` and `client_secret` in config |
| **Scanner not detected** | Multi-scanner | Use `--scanner` to specify type |
| **File format error** | All | Verify file extension and content format |
| **Large file timeout** | All | Increase `timeout` in config or split files |
| **Memory issues** | All | Process smaller batches or use folder mode |

### Debug Commands
```bash
# Enable debug logging for any tool
python <tool_name>.py --file scan.json --log-level DEBUG

# Test scanner detection
python scanner_mapping_examples.py --detection

# Validate configuration
python <tool_name>.py --file test.json --log-level INFO
```

---

## 📊 Performance Guidelines

### File Size Recommendations

| File Size | Tool | Recommendation |
|-----------|------|----------------|
| **< 10MB** | Any | Direct processing |
| **10-50MB** | Any | Normal processing with monitoring |
| **50-100MB** | Multi-scanner preferred | Use batch processing |
| **> 100MB** | Any | Split files or use folder processing |

### Processing Speed Estimates

| Operation | Speed | Throughput |
|-----------|-------|------------|
| **Anonymization** | ~1MB/second | 50-100 files/minute |
| **Basic Import** | ~2MB/second | 100-200 files/minute |
| **Multi-Scanner** | ~1MB/second | 50-100 files/minute |

---

## 📚 Complete Documentation Links

### Core Documentation
- **QUICK_REFERENCE_GUIDE.md** - All tools quick command reference
- **[README_DATA_ANONYMIZER.md](../guides/README_DATA_ANONYMIZER.md)** - Complete data anonymizer guide
- **[README_REFACTORED.md](README_REFACTORED.md)** - Basic Phoenix import tool guide
- **[README_MULTI_SCANNER.md](../guides/README_MULTI_SCANNER.md)** - Multi-scanner comprehensive guide
- **[MULTI_SCANNER_COMMAND_GUIDE.md](../guides/MULTI_SCANNER_COMMAND_GUIDE.md)** - Detailed multi-scanner commands

### Implementation Documentation
- **IMPLEMENTATION_SUMMARY.md** - Basic tool implementation summary
- **MULTI_SCANNER_IMPLEMENTATION_SUMMARY.md** - Multi-scanner implementation summary

### Configuration Examples
- **config_refactored.ini** - Basic tool configuration template
- **config_multi_scanner.ini** - Multi-scanner configuration template
- **customization/tags_config.yaml** - Tag configuration examples

### Test and Examples
- **examples_and_tests.py** - Basic tool examples and tests
- **scanner_mapping_examples.py** - Multi-scanner examples and tests

---

## 🎯 Getting Started Checklist

### First Time Setup
- [ ] Install Python 3.8+ and required packages (`pip install requests pyyaml`)
- [ ] Copy and configure `config.ini` with Phoenix API credentials
- [ ] Test connection: `python phoenix_multi_scanner_import.py --file test.json --log-level DEBUG`
- [ ] Configure tags: Copy and customize `customization/tags_config.yaml`

### For Data Anonymization
- [ ] Test anonymization: `python data_anonymizer.py --file sample.csv --output test.csv`
- [ ] Verify anonymized data quality and structure preservation
- [ ] Set up reproducible anonymization with seed values
- [ ] Export mappings for consistency across environments

### For Production Use
- [ ] Set up automated processing scripts
- [ ] Configure appropriate import modes (new/merge/delta)
- [ ] Set up monitoring and alerting for failed imports
- [ ] Test with production-like data volumes
- [ ] Document scanner-specific configuration requirements

This master index provides a complete roadmap for using all Phoenix Security import tools effectively.
