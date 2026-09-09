# Phoenix Security Platform - Complete Customization Guide

## Overview

This comprehensive guide covers **all customization options** available in the Phoenix Security Loading Script V5. Whether you're customizing asset names, tags, container metadata, or scanner-specific behavior, this guide provides everything you need.

---

## Table of Contents

1. [Customization Overview](#customization-overview)
2. [Asset Name Customization](#asset-name-customization)
3. [Tag Customization](#tag-customization)
4. [Container Metadata Customization](#container-metadata-customization)
5. [Scanner-Specific Customization](#scanner-specific-customization)
6. [Assessment Customization](#assessment-customization)
7. [Data Validation Customization](#data-validation-customization)
8. [Environment-Based Customization](#environment-based-customization)
9. [Command-Line Customization](#command-line-customization)
10. [Configuration File Customization](#configuration-file-customization)
11. [Advanced Customization Scenarios](#advanced-customization-scenarios)
12. [Best Practices](#best-practices)

---

## Customization Overview

### Available Customization Points

| Customization Type | Location | When to Use | Priority |
|-------------------|----------|-------------|----------|
| **Asset Names** | CLI, JSON, Prompt | Change how assets are named | High |
| **Tags** | YAML files | Add metadata to assets/vulnerabilities | High |
| **Container Metadata** | YAML template | Enrich container scan imports | Medium |
| **Scanner Mapping** | Code/Config | Customize field mappings | Advanced |
| **Assessments** | CLI | Organize vulnerability scans | Medium |
| **Data Validation** | Rules/Code | Custom validation logic | Advanced |
| **Environment** | CLI, Config | Environment-specific settings | High |

### Customization Hierarchy (Priority Order)

```
1. Command-Line Arguments      (Highest priority - always wins)
   ↓
2. Interactive Prompts          (User input during runtime)
   ↓
3. JSON/Scan File Fields        (Embedded in scan data)
   ↓
4. YAML Configuration Files     (External config files)
   ↓
5. config.ini Settings          (Global configuration)
   ↓
6. Default Values              (Lowest priority - fallback)
```

---

## Asset Name Customization

Asset names are how your assets appear in the Phoenix platform. You have **3 methods** to customize asset names.

### Method 1: Command-Line Argument (Highest Priority)

**Use when:** You need a quick override for a specific import.

```bash
# Infrastructure asset
python phoenix_multi_scanner_enhanced.py \
  --file qualys_scan.csv \
  --scanner qualys \
  --asset-name "webserver-prod-01.company.com"

# Container asset
python phoenix_multi_scanner_enhanced.py \
  --file trivy_scan.json \
  --scanner trivy \
  --asset-name "myapp:v2.5.0-production"

# Web application asset
python phoenix_multi_scanner_enhanced.py \
  --file burp_scan.xml \
  --scanner burp \
  --asset-name "https://api.company.com"
```

#### Asset Name Templates

```bash
# Container images: name:tag
--asset-name "nginx:1.21.0"

# Infrastructure: hostname or IP
--asset-name "web-prod-01.company.com"
--asset-name "192.168.1.100"

# Applications: descriptive name
--asset-name "customer-portal-application"

# Cloud resources: resource identifier
--asset-name "arn:aws:ec2:us-east-1:123456789:instance/i-1234567890"

# Code repositories: repo name
--asset-name "github.com/company/myapp"
```

### Method 2: Add Field to JSON Scan File

**Use when:** You want persistent, reusable naming in scan files.

#### Container Scanner Example (Aqua/Trivy/Grype)

```json
{
  "image": "myapp:v1.0.0",
  "resource": {
    "name": "myapp",
    "version": "v1.0.0"
  },
  "vulnerabilities": [
    {
      "name": "CVE-2024-12345",
      "severity": "HIGH"
    }
  ]
}
```

#### Adding Image Field to Existing Scan

```bash
# Using jq to add image field
jq '. + {image: "myapp:v1.0.0"}' original_scan.json > modified_scan.json

# Python script to add image field
python3 << 'EOF'
import json

with open('original_scan.json', 'r') as f:
    data = json.load(f)

data['image'] = 'myapp:v1.0.0'

with open('modified_scan.json', 'w') as f:
    json.dump(data, f, indent=2)

print("✅ Added image field to scan file")
EOF
```

### Method 3: Interactive Prompt

**Use when:** Running manual imports and want to specify name interactively.

```bash
# Run without --asset-name to trigger prompt
python phoenix_multi_scanner_enhanced.py \
  --file scan_results.json \
  --scanner trivy \
  --assessment "Weekly Security Scan"

# You'll see:
# ======================================================================
# 🏷️  ASSET NAME CONFIGURATION
# ======================================================================
#
# Current automatic asset name: "alpine:3.18.0"
#
# Options:
#   1. Use automatic name: "alpine:3.18.0"
#   2. Enter custom asset name
#
# Choice (1 or 2): _
```

### Asset Naming Best Practices

```yaml
# Asset Naming Standards by Type

CONTAINER:
  format: "registry/repository:tag"
  examples:
    - "nginx:1.21.0"
    - "company/webapp:v2.5.0"
    - "gcr.io/project/service:latest"
  
INFRA:
  format: "hostname.domain or IP"
  examples:
    - "web-prod-01.company.com"
    - "192.168.1.100"
    - "server-us-east-1a"
  
WEB:
  format: "URL or application name"
  examples:
    - "https://api.company.com"
    - "https://app.company.com/admin"
    - "customer-portal-web-app"
  
CLOUD:
  format: "cloud provider resource identifier"
  examples:
    - "arn:aws:s3:::my-bucket"
    - "projects/my-project/instances/my-vm"
    - "azure://subscription/resourcegroup/vm"
  
CODE:
  format: "repository path"
  examples:
    - "github.com/company/backend-api"
    - "gitlab.company.com/team/frontend"
    - "backend-microservice-v2"
  
BUILD:
  format: "artifact identifier"
  examples:
    - "maven:com.company.app:1.0.0"
    - "npm:@company/package:2.5.0"
    - "frontend-build-artifacts-v3"
```

---

## Tag Customization

Tags are the primary way to add metadata and organize assets/vulnerabilities in Phoenix.

### Location

```
Utils/Loading_Script_V5/customization/
├── tags_config PCI-NoSN.yaml              # PCI compliance tags
├── tags_config PCI-NoSN_CIS.yaml          # PCI + CIS controls
├── tags_config NO-PCI-NoSN_CIS.yaml       # CIS only (non-PCI)
├── tags_config_adm1.yaml                  # Admin team 1
├── tags_config_adm1_NoSN.yaml             # Admin team 1 (no ServiceNow)
├── tags_config_adm2.yaml                  # Admin team 2
└── tags_config_adm2_NoSN.yaml             # Admin team 2 (no ServiceNow)
```

### Tag Configuration Structure

```yaml
# ============================================================================
# ASSET TAGS - Applied to all assets
# ============================================================================
custom_data:
  - key: "team"
    value: "security-ops"
  - key: "business-unit"
    value: "engineering"
  - key: "cost-center"
    value: "CC-12345"
  - key: "environment"
    value: "production"

# ============================================================================
# ASSET TYPE TAGS - Applied based on asset type (INFRA, WEB, CLOUD, etc.)
# ============================================================================
asset_type_tags:
  INFRA:
    - key: "asset-category"
      value: "infrastructure"
    - key: "scan-type"
      value: "network-scan"
  
  WEB:
    - key: "asset-category"
      value: "web-application"
    - key: "scan-type"
      value: "dast-scan"
  
  CONTAINER:
    - key: "asset-category"
      value: "container-image"
    - key: "scan-type"
      value: "container-scan"
  
  CLOUD:
    - key: "asset-category"
      value: "cloud-resource"
    - key: "scan-type"
      value: "cspm-scan"

# ============================================================================
# ENVIRONMENT TAGS - Applied based on environment
# ============================================================================
environment_tags:
  production:
    - key: "environment"
      value: "production"
    - key: "criticality"
      value: "critical"
    - key: "sla"
      value: "24x7"
  
  staging:
    - key: "environment"
      value: "staging"
    - key: "criticality"
      value: "high"
  
  development:
    - key: "environment"
      value: "development"
    - key: "criticality"
      value: "low"

# ============================================================================
# VULNERABILITY TAGS - Applied to all vulnerabilities
# ============================================================================
vulnerability_tags:
  - key: "compliance-required"
    value: "true"
  - key: "tracking-system"
    value: "jira"

# ============================================================================
# SEVERITY TAGS - Applied based on vulnerability severity
# ============================================================================
severity_tags:
  critical:
    - key: "priority"
      value: "P1"
    - key: "sla-hours"
      value: "24"
    - key: "escalation"
      value: "immediate"
  
  high:
    - key: "priority"
      value: "P2"
    - key: "sla-hours"
      value: "72"
  
  medium:
    - key: "priority"
      value: "P3"
    - key: "sla-days"
      value: "7"
  
  low:
    - key: "priority"
      value: "P4"
    - key: "sla-days"
      value: "30"

# ============================================================================
# COMPLIANCE TAGS - Applied to all vulnerabilities for compliance tracking
# ============================================================================
compliance_tags:
  - key: "compliance-framework"
    value: "PCI-DSS-4.0"
  - key: "compliance-framework"
    value: "SOC2-Type-II"
  - key: "audit-required"
    value: "true"
```

### Using Tag Files

```bash
# Basic usage
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --scanner qualys \
  --tag-file customization/tags_config_PCI-NoSN.yaml

# Multiple environments - use different tag files
python phoenix_multi_scanner_enhanced.py \
  --file prod_scan.csv \
  --tag-file customization/tags_production.yaml

python phoenix_multi_scanner_enhanced.py \
  --file staging_scan.csv \
  --tag-file customization/tags_staging.yaml

# Tags-only mode (update existing assets)
python phoenix_multi_scanner_enhanced.py \
  --file existing_assets.json \
  --just-tags \
  --tag-file customization/updated_tags.yaml
```

### Creating Custom Tag Files

```bash
# Copy existing template
cp customization/tags_config_PCI-NoSN.yaml customization/my_custom_tags.yaml

# Edit with your tags
nano customization/my_custom_tags.yaml

# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('customization/my_custom_tags.yaml'))"

# Use your custom tags
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file customization/my_custom_tags.yaml
```

### Common Tag Customization Scenarios

#### Scenario 1: Team-Specific Tags

```yaml
# customization/tags_team_platformsec.yaml
custom_data:
  - key: "team"
    value: "platform-security"
  - key: "team-lead"
    value: "user@example.com"
  - key: "slack-channel"
    value: "#platform-security"
  - key: "pagerduty-schedule"
    value: "platform-oncall"

asset_type_tags:
  INFRA:
    - key: "responsible-team"
      value: "platform-security"
    - key: "escalation-path"
      value: "platform-security-manager"
```

#### Scenario 2: Compliance-Specific Tags

```yaml
# customization/tags_compliance_pci.yaml
custom_data:
  - key: "pci-scope"
    value: "in-scope"
  - key: "cde-zone"
    value: "CDE:Production"

vulnerability_tags:
  - key: "pci-requirement"
    value: "11.2-vulnerability-scans"
  - key: "qsa-review"
    value: "required"

severity_tags:
  critical:
    - key: "pci-sla"
      value: "immediate"
    - key: "compensating-control-required"
      value: "true"
  high:
    - key: "pci-sla"
      value: "30-days"
```

#### Scenario 3: ServiceNow Integration Tags

```yaml
# customization/tags_servicenow.yaml
custom_data:
  - key: "sn-company"
    value: "ACME Corporation"
  - key: "sn-assignment-group"
    value: "Security Operations"

asset_type_tags:
  INFRA:
    - key: "sn-ci-class"
      value: "cmdb_ci_server"
  WEB:
    - key: "sn-ci-class"
      value: "cmdb_ci_appl"

severity_tags:
  critical:
    - key: "sn-priority"
      value: "1"
    - key: "sn-impact"
      value: "1-High"
    - key: "sn-urgency"
      value: "1-High"
  high:
    - key: "sn-priority"
      value: "2"
    - key: "sn-impact"
      value: "2-Medium"
```

### Dynamic Tags (Generated at Runtime)

```bash
#!/bin/bash
# generate_dynamic_tags.sh
# Generate tag file with dynamic values

SCAN_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD)
PIPELINE_ID=${CI_PIPELINE_ID:-"manual"}

cat > customization/tags_dynamic.yaml << EOF
custom_data:
  - key: "scan-date"
    value: "${SCAN_DATE}"
  - key: "git-commit"
    value: "${GIT_COMMIT}"
  - key: "pipeline-id"
    value: "${PIPELINE_ID}"
  - key: "scan-trigger"
    value: "automated-ci"
EOF

echo "✅ Generated dynamic tags file"

# Use the generated tags
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --tag-file customization/tags_dynamic.yaml
```

---

## Container Metadata Customization

Container metadata provides rich context for container vulnerability scans, including build information, CI/CD details, and source code traceability.

### Location

```
Utils/Loading_Script_V5/customization/container_metadata_template.yaml
```

### Container Metadata Structure

```yaml
metadata_version: "1.0"
capture_timestamp: "2024-02-15T10:00:00Z"

# ============================================================================
# CONTAINER IDENTITY
# ============================================================================
container:
  image_full_ref: "registry.company.com/myapp/backend:v1.2.3@sha256:abc123..."
  registry: "registry.company.com"
  repository: "myapp/backend"
  image_name: "backend"
  tag: "v1.2.3"
  digest: "sha256:abc123..."
  image_id: "sha256:def456..."
  created: "2024-02-15T09:00:00Z"
  size_bytes: 524288000
  size_human: "500 MB"
  architecture: "amd64"
  os: "linux"

# ============================================================================
# BASE IMAGE INFORMATION
# ============================================================================
base_image:
  image_ref: "python:3.11-slim-bookworm"
  registry: "docker.io"
  repository: "library/python"
  tag: "3.11-slim-bookworm"
  os_name: "Debian GNU/Linux"
  os_version: "12"
  os_id: "debian"

# ============================================================================
# SOURCE CODE INFORMATION
# ============================================================================
source:
  repository_url: "https://github.com/company/backend-api"
  repository_type: "git"
  commit_sha: "abc123def456789..."
  commit_sha_short: "abc123d"
  commit_message: "feat: Add new authentication endpoint"
  commit_author: "user@example.com"
  commit_timestamp: "2024-02-15T08:00:00Z"
  branch: "main"
  tag: "v1.2.3"
  is_tag: true

# ============================================================================
# BUILD INFORMATION
# ============================================================================
build:
  builder: "docker"
  builder_version: "24.0.7"
  dockerfile_path: "Dockerfile"
  build_context: "."
  build_args:
    - name: "APP_VERSION"
      value: "1.2.3"
    - name: "BUILD_DATE"
      value: "2024-02-15"
  build_start: "2024-02-15T09:00:00Z"
  build_end: "2024-02-15T09:05:00Z"
  build_duration_seconds: 300

# ============================================================================
# CI/CD PIPELINE INFORMATION
# ============================================================================
pipeline:
  ci_system: "github-actions"
  pipeline_id: "1234567890"
  pipeline_url: "https://github.com/company/backend-api/actions/runs/1234567890"
  job_id: "build-and-scan"
  job_url: "https://github.com/company/backend-api/actions/runs/1234567890/job/9876543210"
  trigger_type: "push"
  trigger_actor: "user@example.com"
  trigger_ref: "refs/heads/main"

# ============================================================================
# PHOENIX TAGS (Auto-generated)
# ============================================================================
phoenix_tags:
  - key: "image-name"
    value: "backend"
  - key: "image-tag"
    value: "v1.2.3"
  - key: "image-digest"
    value: "sha256:abc123..."
  - key: "base-image"
    value: "python:3.11-slim-bookworm"
  - key: "source-repo"
    value: "github.com/company/backend-api"
  - key: "commit-sha"
    value: "abc123d"
  - key: "branch"
    value: "main"
  - key: "build-date"
    value: "2024-02-15"
  - key: "ci-system"
    value: "github-actions"
```

### Using Container Metadata

```bash
# Import container scan with metadata
python phoenix_multi_scanner_enhanced.py \
  --file trivy_scan.json \
  --scanner trivy \
  --container-metadata customization/container_metadata_template.yaml

# CI/CD example - capture metadata automatically
./scripts/capture_container_metadata.sh myapp:v1.2.3 > metadata.yaml

python phoenix_multi_scanner_enhanced.py \
  --file trivy_scan.json \
  --scanner trivy \
  --container-metadata metadata.yaml
```

### Capturing Container Metadata Automatically

#### Using Provided Script

```bash
# The script captures metadata automatically
./scripts/capture_container_metadata.sh myapp:v1.2.3 > container_metadata.yaml

# Use the captured metadata
python phoenix_multi_scanner_enhanced.py \
  --file scan_results.json \
  --container-metadata container_metadata.yaml
```

#### In GitHub Actions

```yaml
# .github/workflows/container-scan.yml
name: Container Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Container
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Capture Container Metadata
        run: |
          ./scripts/capture_container_metadata.sh myapp:${{ github.sha }} \
            > container_metadata.yaml
      
      - name: Scan with Trivy
        run: trivy image myapp:${{ github.sha }} -f json -o scan.json
      
      - name: Upload to Phoenix
        run: |
          python phoenix_multi_scanner_enhanced.py \
            --file scan.json \
            --scanner trivy \
            --container-metadata container_metadata.yaml
```

---

## Scanner-Specific Customization

Customize how the Loading Script processes different scanner formats.

### Scanner Field Mapping

Location: `Utils/Loading_Script_V5/scanner_field_mapper.py`

```python
# Example: Custom field mapping for a scanner
CUSTOM_SCANNER_MAPPINGS = {
    'my_custom_scanner': {
        'asset_name_field': 'target.hostname',
        'vulnerability_id_field': 'finding.id',
        'severity_field': 'risk_level',
        'severity_mapping': {
            'critical': 10.0,
            'high': 8.0,
            'medium': 5.0,
            'low': 2.0
        }
    }
}
```

### Scanner Auto-Detection

The Loading Script automatically detects scanner types. You can override this:

```bash
# Let it auto-detect
python phoenix_multi_scanner_enhanced.py --file scan.json

# Explicitly specify scanner
python phoenix_multi_scanner_enhanced.py --file scan.json --scanner trivy
```

### Supported Scanners

```yaml
# Over 50 scanners supported:

Infrastructure:
  - qualys
  - nessus (tenable)
  - openvas
  - rapid7_nexpose

Container:
  - trivy
  - aqua
  - anchore_grype
  - snyk_container
  - clair

Web Application:
  - burp_suite
  - zap (OWASP ZAP)
  - acunetix
  - netsparker
  - appspider

SAST/Code:
  - checkmarx
  - fortify
  - veracode
  - sonarqube
  - semgrep

Cloud:
  - aws_prowler
  - scout_suite
  - wiz
  - prisma_cloud

Dependency:
  - snyk
  - dependency_track
  - npm_audit
  - yarn_audit
  - osv_scanner

IaC:
  - tfsec
  - checkov
  - kics
  - terrascan
```

---

## Assessment Customization

Assessments group vulnerability scans in Phoenix, making it easier to track scan campaigns.

### Basic Assessment Naming

```bash
# Simple assessment name
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --assessment "Weekly Infrastructure Scan"

# Date-based assessment
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --assessment "Security Scan $(date +%Y-%m-%d)"

# Environment-specific
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --assessment "Production Security Audit - Q1 2024"
```

### Assessment Naming Conventions

```yaml
# Recommended patterns:

Time-Based:
  - "Daily Scan - 2024-02-15"
  - "Weekly Scan - Week 07 2024"
  - "Monthly Scan - February 2024"
  - "Quarterly Audit - Q1 2024"

Environment-Based:
  - "Production Infrastructure Scan"
  - "Staging Application Security Test"
  - "Development Dependency Scan"

Purpose-Based:
  - "PCI Compliance Scan - February 2024"
  - "Penetration Test - External Assets"
  - "Vulnerability Assessment - Pre-Release"
  - "Security Audit - Post-Incident"

Team-Based:
  - "Platform Team - Weekly Container Scan"
  - "DevOps - Infrastructure Baseline"
  - "Security Team - Comprehensive Assessment"
```

---

## Data Validation Customization

Customize how data is validated and fixed during import.

### Using the Data Validator

```bash
# Validate CSV file
python data_validator_enhanced.py \
  --file scan_data.csv \
  --validate-only

# Validate and fix
python data_validator_enhanced.py \
  --file scan_data.csv \
  --output fixed_data.csv

# Custom validation rules (extend the validator)
python data_validator_enhanced.py \
  --file scan_data.csv \
  --custom-rules my_validation_rules.yaml
```

### Common Fixes Applied

- Missing vulnerability descriptions → Generated from title/CVE
- Invalid severity values → Normalized to standard scale
- Missing CVE IDs → Extracted from description
- Malformed dates → Converted to ISO 8601
- Empty required fields → Default values applied
- Character encoding issues → UTF-8 conversion

---

## Environment-Based Customization

Different configurations for different environments (dev/staging/prod).

### Environment Configuration Structure

```
Utils/Loading_Script_V5/customization/
├── environments/
│   ├── development/
│   │   ├── config.ini
│   │   └── tags.yaml
│   ├── staging/
│   │   ├── config.ini
│   │   └── tags.yaml
│   └── production/
│       ├── config.ini
│       └── tags.yaml
```

### Environment-Specific Import

```bash
# Development environment
export ENVIRONMENT=development
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --config customization/environments/development/config.ini \
  --tag-file customization/environments/development/tags.yaml

# Production environment
export ENVIRONMENT=production
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --config customization/environments/production/config.ini \
  --tag-file customization/environments/production/tags.yaml
```

### Environment Detection Script

```bash
#!/bin/bash
# detect_environment.sh
# Automatically detect and use appropriate configuration

if [[ "$HOSTNAME" == *"prod"* ]]; then
    ENV="production"
elif [[ "$HOSTNAME" == *"staging"* ]]; then
    ENV="staging"
else
    ENV="development"
fi

echo "🌍 Detected environment: $ENV"

python phoenix_multi_scanner_enhanced.py \
  --file "$1" \
  --config "customization/environments/$ENV/config.ini" \
  --tag-file "customization/environments/$ENV/tags.yaml" \
  --assessment "$(date +%Y-%m-%d) - $ENV Scan"
```

---

## Command-Line Customization

All command-line options for maximum flexibility.

### Complete Command Reference

```bash
python phoenix_multi_scanner_enhanced.py \
  # Input/Output
  --file SCAN_FILE \
  --folder SCAN_FOLDER \
  --scanner SCANNER_NAME \
  
  # Asset Configuration
  --asset-type {INFRA,WEB,CLOUD,CONTAINER,CODE,BUILD,REPOSITORY} \
  --asset-name "custom-asset-name" \
  
  # Assessment
  --assessment "Assessment Name" \
  
  # Tags
  --tag-file TAG_CONFIG_FILE \
  --just-tags \
  
  # Container Metadata
  --container-metadata METADATA_FILE \
  
  # Batching & Performance
  --enable-batching \
  --max-batch-size 100 \
  
  # Data Quality
  --fix-data \
  
  # Debugging
  --debug \
  --log-level {DEBUG,INFO,WARNING,ERROR}
```

### Common Command Patterns

```bash
# Basic import
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --scanner qualys

# Full customization
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --scanner qualys \
  --asset-type INFRA \
  --asset-name "prod-infrastructure" \
  --assessment "Q1 2024 Security Audit" \
  --tag-file customization/tags_production.yaml \
  --enable-batching \
  --fix-data

# Folder processing with tags
python phoenix_multi_scanner_enhanced.py \
  --folder /scans/daily/ \
  --tag-file customization/tags_daily.yaml \
  --assessment "Daily Scan $(date +%Y-%m-%d)"

# Container scan with metadata
python phoenix_multi_scanner_enhanced.py \
  --file trivy_scan.json \
  --scanner trivy \
  --asset-name "myapp:v1.0.0" \
  --container-metadata metadata.yaml \
  --tag-file customization/tags_container.yaml

# Debug mode for troubleshooting
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --scanner qualys \
  --debug \
  --log-level DEBUG
```

---

## Configuration File Customization

Global configuration via `config.ini`.

### config.ini Structure

```ini
[phoenix]
# Phoenix API Configuration
client_id = your_client_id
client_secret = your_client_secret
api_base_url = https://api.demo.appsecphx.io

[import]
# Import Defaults
default_asset_type = INFRA
default_batch_size = 100
enable_batching = true
fix_data_on_import = true

[logging]
# Logging Configuration
log_level = INFO
log_file = phoenix_import.log
console_output = true

[validation]
# Data Validation
strict_validation = false
auto_fix_errors = true
skip_invalid_rows = false
```

### Using Custom Config

```bash
# Use custom config file
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --config my_custom_config.ini

# Override with environment variables
export PHOENIX_CLIENT_ID="your_id"
export PHOENIX_CLIENT_SECRET="your_secret"
export PHOENIX_API_URL="https://api.demo.appsecphx.io"

python phoenix_multi_scanner_enhanced.py --file scan.csv
```

---

## Advanced Customization Scenarios

### Scenario 1: Multi-Team Organization

```bash
# customization/
├── teams/
│   ├── platform-security/
│   │   ├── tags.yaml
│   │   └── config.ini
│   ├── application-security/
│   │   ├── tags.yaml
│   │   └── config.ini
│   └── infrastructure-security/
│       ├── tags.yaml
│       └── config.ini

# Usage
./import_for_team.sh platform-security scan.csv
./import_for_team.sh application-security scan.json
```

### Scenario 2: Compliance Frameworks

```bash
# customization/compliance/
├── pci-dss/
│   └── tags_pci.yaml
├── soc2/
│   └── tags_soc2.yaml
├── iso27001/
│   └── tags_iso27001.yaml
└── hipaa/
    └── tags_hipaa.yaml

# Usage
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file customization/compliance/pci-dss/tags_pci.yaml \
  --tag-file customization/compliance/soc2/tags_soc2.yaml
```

### Scenario 3: CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Determine Environment
        id: env
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "environment=production" >> $GITHUB_OUTPUT
          elif [[ "${{ github.ref }}" == "refs/heads/staging" ]]; then
            echo "environment=staging" >> $GITHUB_OUTPUT
          else
            echo "environment=development" >> $GITHUB_OUTPUT
          fi
      
      - name: Run Security Scan
        run: trivy image myapp:${{ github.sha }} -f json -o scan.json
      
      - name: Upload to Phoenix
        env:
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
        run: |
          python phoenix_multi_scanner_enhanced.py \
            --file scan.json \
            --scanner trivy \
            --asset-name "myapp:${{ github.sha }}" \
            --tag-file "customization/environments/${{ steps.env.outputs.environment }}/tags.yaml" \
            --assessment "CI Scan - ${{ github.sha }}"
```

---

## Best Practices

### 1. Organize Customization Files

```
customization/
├── README.md                    # Documentation
├── tags/
│   ├── base_tags.yaml          # Common tags for all
│   ├── production_tags.yaml    # Prod-specific
│   └── development_tags.yaml   # Dev-specific
├── container_metadata/
│   ├── template.yaml
│   └── examples/
├── compliance/
│   ├── pci_tags.yaml
│   └── soc2_tags.yaml
└── teams/
    ├── platform/
    └── security/
```

### 2. Version Control Your Configurations

```bash
git add customization/
git commit -m "feat: Add team-specific tag configurations"
git tag -a config-v1.0 -m "Configuration version 1.0"
```

### 3. Document Your Customizations

```yaml
# customization/README.md
# Customization Documentation

## Tag Files

- `tags_production.yaml`: Production environment tags
  - Owner: Security Team
  - Last Updated: 2024-02-15
  - Purpose: PCI-DSS compliance tagging

- `tags_development.yaml`: Development environment tags
  - Owner: DevOps Team
  - Last Updated: 2024-02-10
  - Purpose: Development workflow tracking
```

### 4. Test Customizations

```bash
# Test with debug mode
python phoenix_multi_scanner_enhanced.py \
  --file test_scan.csv \
  --tag-file customization/new_tags.yaml \
  --debug \
  --log-level DEBUG

# Verify tags applied correctly
grep "🏷️.*tag" phoenix_import.log
```

### 5. Use Templates

```bash
# Create new customization from template
cp customization/tags_template.yaml customization/tags_myteam.yaml
# Edit and customize
nano customization/tags_myteam.yaml
```

---

## Quick Reference

### Essential Customization Commands

```bash
# Custom asset name
--asset-name "myapp:v1.0.0"

# Apply tags
--tag-file customization/tags.yaml

# Custom assessment
--assessment "Q1 2024 Security Audit"

# Container metadata
--container-metadata metadata.yaml

# Enable batching
--enable-batching --max-batch-size 200

# Fix data issues
--fix-data

# Debug mode
--debug --log-level DEBUG
```

---

## See Also

- SYNTHETIC_DATA_GUIDE.md - Creating test data
- [TAG_CONFIGURATION_GUIDE.md](TAG_CONFIGURATION_GUIDE.md) - Detailed tag guide
- [CONTAINER_METADATA_STANDARD.md](../reference/CONTAINER_METADATA_STANDARD.md) - Container metadata
- [ASSET_NAME_CUSTOMIZATION.md](ASSET_NAME_CUSTOMIZATION.md) - Asset naming
- [DOCUMENTATION_INDEX.md](../reference/DOCUMENTATION_INDEX.md) - Complete documentation

---

*Last Updated: February 2026*
*Version: Loading Script V5.0*
