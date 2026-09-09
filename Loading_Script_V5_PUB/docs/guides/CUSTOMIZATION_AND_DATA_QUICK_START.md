# Phoenix Loading Script V5 - Customization & Synthetic Data Quick Start

## 📋 Overview

This quick start guide helps you understand how to **customize** the Phoenix Loading Script V5 and create **synthetic test data**. For complete details, see the comprehensive guides in the `REFERENCE_DOCUMENTATION/` folder.

---

## 🎯 What You Can Customize

### 1. Asset Names
How your assets appear in Phoenix

**Methods:**
- Command-line: `--asset-name "myapp:v1.0.0"`
- JSON file: Add `"image": "myapp:v1.0.0"`
- Interactive prompt (when not specified)

**Example:**
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --asset-name "production-webapp:v2.5.0"
```

### 2. Tags
Add metadata to assets and vulnerabilities

**Location:** `customization/` folder

**Example:**
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file customization/tags_config_PCI-NoSN.yaml
```

### 3. Container Metadata
Enrich container scans with build/CI/CD information

**Location:** `customization/container_metadata_template.yaml`

**Example:**
```bash
python phoenix_multi_scanner_enhanced.py \
  --file trivy_scan.json \
  --container-metadata customization/container_metadata_template.yaml
```

---

## 🏷️ Tag Customization (Most Common)

### Pre-Built Tag Files

```bash
customization/
├── tags_config PCI-NoSN.yaml              # PCI compliance
├── tags_config PCI-NoSN_CIS.yaml          # PCI + CIS
├── tags_config NO-PCI-NoSN_CIS.yaml       # CIS only
├── tags_config_adm1.yaml                  # Admin team 1
└── tags_config_adm2.yaml                  # Admin team 2
```

### Create Your Own Tags

```bash
# 1. Copy a template
cp customization/tags_config_PCI-NoSN.yaml customization/my_tags.yaml

# 2. Edit the file
nano customization/my_tags.yaml

# 3. Use it
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file customization/my_tags.yaml
```

### Tag Structure (Simple Example)

```yaml
# Asset tags (applied to all assets)
custom_data:
  - key: "team"
    value: "security-ops"
  - key: "environment"
    value: "production"

# Vulnerability tags (applied to all vulnerabilities)
vulnerability_tags:
  - key: "compliance"
    value: "PCI-DSS"

# Severity-based tags (applied based on severity)
severity_tags:
  critical:
    - key: "priority"
      value: "P1"
    - key: "sla-hours"
      value: "24"
  high:
    - key: "priority"
      value: "P2"
    - key: "sla-hours"
      value: "72"
```

---

## 🧪 Synthetic Data Creation

### Method 1: Use Existing Test Files (Easiest)

The Loading Script includes **1000+ test files** for 50+ scanners.

**Location:** `scanner_test_files/scans/`

```bash
# List available test scanners
ls -la scanner_test_files/scans/

# Use Qualys test data
python phoenix_multi_scanner_enhanced.py \
  --file scanner_test_files/scans/qualys/Qualys_Sample_Report.xml \
  --scanner qualys

# Use Trivy test data
python phoenix_multi_scanner_enhanced.py \
  --file scanner_test_files/scans/trivy/scheme_2_many_vulns.json \
  --scanner trivy
```

### Method 2: Modify Existing Test Files

```bash
# Copy a test file
cp scanner_test_files/scans/qualys/Qualys_Sample_Report.xml my_test_data.xml

# Edit to customize
nano my_test_data.xml

# Import your modified test data
python phoenix_multi_scanner_enhanced.py \
  --file my_test_data.xml \
  --scanner qualys
```

### Method 3: Generate Synthetic CSV Data

Create a Python script to generate synthetic data:

```python
#!/usr/bin/env python3
"""Generate synthetic Qualys CSV data"""
import csv
import random
from datetime import datetime, timedelta

def generate_synthetic_scan(num_assets=10, output_file='synthetic_scan.csv'):
    headers = ['IP', 'DNS', 'OS', 'QID', 'Title', 'Severity', 
               'Port', 'Protocol', 'CVE ID', 'First Detected']
    
    severities = [5, 4, 3, 2, 1]
    ports = [80, 443, 22, 3306, 8080]
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        
        for i in range(num_assets):
            ip = f"192.168.1.{i+100}"
            hostname = f"server-{i:02d}.company.local"
            
            # Generate 3-5 vulnerabilities per asset
            for _ in range(random.randint(3, 5)):
                writer.writerow({
                    'IP': ip,
                    'DNS': hostname,
                    'OS': 'Linux',
                    'QID': random.randint(10000, 99999),
                    'Title': 'Test Vulnerability',
                    'Severity': random.choice(severities),
                    'Port': random.choice(ports),
                    'Protocol': 'tcp',
                    'CVE ID': f"CVE-2024-{random.randint(1000, 9999)}",
                    'First Detected': (datetime.now() - timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d')
                })
    
    print(f"✅ Generated {num_assets} assets in {output_file}")

if __name__ == "__main__":
    generate_synthetic_scan(num_assets=10, output_file='synthetic_small.csv')
    generate_synthetic_scan(num_assets=100, output_file='synthetic_large.csv')
```

**Usage:**
```bash
# Generate synthetic data
python generate_synthetic_data.py

# Import it
python phoenix_multi_scanner_enhanced.py \
  --file synthetic_small.csv \
  --scanner qualys
```

### Method 4: Validate and Fix Existing Data

```bash
# Validate CSV file
python data_validator_enhanced.py \
  --file problematic_scan.csv \
  --output fixed_scan.csv

# The validator automatically:
# - Fixes missing descriptions
# - Normalizes severity values
# - Validates data structure
# - Adds default values
```

---

## 🚀 Common Use Cases

### Use Case 1: Production Import with Custom Tags

```bash
python phoenix_multi_scanner_enhanced.py \
  --file prod_scan.csv \
  --scanner qualys \
  --asset-name "production-infrastructure" \
  --tag-file customization/tags_production.yaml \
  --assessment "Q1 2024 Production Security Scan"
```

### Use Case 2: Container Scan with Full Metadata

```bash
# Capture metadata
./scripts/capture_container_metadata.sh myapp:v1.0.0 > metadata.yaml

# Run scan
trivy image myapp:v1.0.0 -f json -o scan.json

# Import with everything
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy \
  --asset-name "myapp:v1.0.0" \
  --container-metadata metadata.yaml \
  --tag-file customization/tags_container.yaml \
  --assessment "Container Security - Production Release"
```

### Use Case 3: Development Testing with Synthetic Data

```bash
# Use test data
python phoenix_multi_scanner_enhanced.py \
  --file scanner_test_files/scans/qualys/many_findings.csv \
  --scanner qualys \
  --tag-file customization/tags_development.yaml \
  --assessment "Development Test - $(date +%Y-%m-%d)"
```

### Use Case 4: Multi-Environment Setup

```bash
# Production
python phoenix_multi_scanner_enhanced.py \
  --file prod_scan.csv \
  --tag-file customization/tags_production.yaml \
  --assessment "Production - $(date +%Y-%m-%d)"

# Staging
python phoenix_multi_scanner_enhanced.py \
  --file staging_scan.csv \
  --tag-file customization/tags_staging.yaml \
  --assessment "Staging - $(date +%Y-%m-%d)"

# Development
python phoenix_multi_scanner_enhanced.py \
  --file dev_scan.csv \
  --tag-file customization/tags_development.yaml \
  --assessment "Development - $(date +%Y-%m-%d)"
```

---

## 📖 Complete Documentation

### Detailed Guides

| Guide | Location | What It Covers |
|-------|----------|----------------|
| **Customization Guide** | `REFERENCE_DOCUMENTATION/CUSTOMIZATION_GUIDE.md` | Complete customization reference |
| **Synthetic Data Guide** | `REFERENCE_DOCUMENTATION/SYNTHETIC_DATA_GUIDE.md` | Test data creation methods |
| **Tag Configuration** | `REFERENCE_DOCUMENTATION/TAG_CONFIGURATION_GUIDE.md` | Tag system details |
| **Container Metadata** | `REFERENCE_DOCUMENTATION/CONTAINER_METADATA_STANDARD.md` | Container metadata format |
| **Asset Naming** | `REFERENCE_DOCUMENTATION/ASSET_NAME_CUSTOMIZATION.md` | Asset naming options |
| **Documentation Index** | `REFERENCE_DOCUMENTATION/DOCUMENTATION_INDEX.md` | All documentation |

### Quick Links

```bash
# View customization guide
cat REFERENCE_DOCUMENTATION/CUSTOMIZATION_GUIDE.md

# View synthetic data guide
cat REFERENCE_DOCUMENTATION/SYNTHETIC_DATA_GUIDE.md

# View tag configuration guide
cat REFERENCE_DOCUMENTATION/TAG_CONFIGURATION_GUIDE.md

# View all available docs
ls -la REFERENCE_DOCUMENTATION/
```

---

## 🔍 Finding Test Data by Scanner

```bash
# Find test files for a specific scanner
find scanner_test_files/scans/qualys -type f

# Common patterns:
# - many_findings.* = Multiple vulnerabilities
# - one_vuln.* = Single vulnerability
# - no_vuln.* = No vulnerabilities
# - sample_report.* = General example

# Available scanner test data (50+ scanners):
ls scanner_test_files/scans/

# Examples:
# - qualys/
# - nessus/
# - trivy/
# - aqua/
# - snyk/
# - burp_suite/
# - zap/
# - checkmarx/
# - fortify/
# - aws_prowler/
# ... and many more
```

---

## 🛠️ Quick Troubleshooting

### Tags Not Applied?

```bash
# Enable debug mode
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file tags.yaml \
  --debug \
  --log-level DEBUG

# Check logs
grep "🏷️" logs/phoenix_multi_scanner_enhanced_*.log
```

### YAML Syntax Error?

```bash
# Validate YAML
python -c "import yaml; yaml.safe_load(open('tags.yaml'))"
```

### Data Validation Issues?

```bash
# Validate and fix
python data_validator_enhanced.py \
  --file problematic.csv \
  --output fixed.csv
```

---

## 💡 Best Practices

### 1. Start Simple
```bash
# Begin with existing test data
python phoenix_multi_scanner_enhanced.py \
  --file scanner_test_files/scans/qualys/Qualys_Sample_Report.xml \
  --scanner qualys
```

### 2. Use Pre-Built Configurations
```bash
# Use provided tag files
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file customization/tags_config_PCI-NoSN.yaml
```

### 3. Test Before Production
```bash
# Always test with debug mode first
python phoenix_multi_scanner_enhanced.py \
  --file test.csv \
  --tag-file new_tags.yaml \
  --debug
```

### 4. Organize Your Files
```
customization/
├── production/
│   └── tags_prod.yaml
├── staging/
│   └── tags_staging.yaml
└── development/
    └── tags_dev.yaml
```

### 5. Version Control
```bash
git add customization/
git commit -m "feat: Add production tag configuration"
```

---

## 🎓 Learning Path

### Beginner
1. Use existing test files from `scanner_test_files/scans/`
2. Try basic import without customization
3. Add simple tags using pre-built files

### Intermediate
1. Create custom tag configurations
2. Modify test files for specific scenarios
3. Use asset name customization

### Advanced
1. Generate synthetic data programmatically
2. Integrate container metadata
3. Set up multi-environment configurations
4. Automate with CI/CD pipelines

---

## 📞 Need Help?

1. **Check Documentation**: See `REFERENCE_DOCUMENTATION/` folder
2. **Enable Debug Logging**: Use `--debug --log-level DEBUG`
3. **Review Examples**: Look at existing tag files in `customization/`
4. **Check Test Files**: Browse `scanner_test_files/scans/` for examples
5. **Read Logs**: Check `logs/phoenix_multi_scanner_enhanced_*.log`

---

## 🔗 Related Files

```
Utils/Loading_Script_V5/
├── REFERENCE_DOCUMENTATION/
│   ├── CUSTOMIZATION_GUIDE.md          ← Complete customization guide
│   ├── SYNTHETIC_DATA_GUIDE.md         ← Complete test data guide
│   ├── TAG_CONFIGURATION_GUIDE.md      ← Tag system details
│   ├── CONTAINER_METADATA_STANDARD.md  ← Container metadata
│   ├── ASSET_NAME_CUSTOMIZATION.md     ← Asset naming
│   └── DOCUMENTATION_INDEX.md          ← Main documentation
├── customization/
│   ├── README.md                       ← Customization folder guide
│   ├── tags_config_*.yaml              ← Pre-built tag files
│   └── container_metadata_template.yaml ← Container template
└── scanner_test_files/scans/          ← 1000+ test files (50+ scanners)
```

---

*Last Updated: February 2026*
*Version: Loading Script V5.0*

---

**Next Steps:**
1. Read the complete [CUSTOMIZATION_GUIDE.md](CUSTOMIZATION_GUIDE.md)
2. Read the complete SYNTHETIC_DATA_GUIDE.md
3. Explore the `customization/` folder
4. Try the examples above
5. Check out test data in `scanner_test_files/scans/`
