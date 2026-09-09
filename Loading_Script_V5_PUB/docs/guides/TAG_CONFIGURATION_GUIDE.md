# Phoenix Security Platform - Tag Configuration Guide

## Overview

The Phoenix Loading Script V5 provides comprehensive tag support for assets and vulnerabilities during import. Tags enable you to:

- **Categorize assets** by business unit, team, environment, or compliance requirements
- **Enrich vulnerability data** with priority levels, SLAs, and compliance mappings
- **Automate asset organization** in the Phoenix platform
- **Support compliance reporting** with framework-specific tags (PCI-DSS, SOC2, ISO27001)

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Tag Types Overview](#tag-types-overview)
3. [Configuration File Format](#configuration-file-format)
4. [Command Line Options](#command-line-options)
5. [Tag Configuration Examples](#tag-configuration-examples)
6. [Advanced Usage](#advanced-usage)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Basic Tag Import

```bash
# Import with a tag configuration file
python phoenix_multi_scanner_enhanced.py \
  --file scan_results.csv \
  --tag-file customization/tags_config_PCI-NoSN_CIS.yaml

# Apply tags to existing assets only (no new vulnerability import)
python phoenix_multi_scanner_enhanced.py \
  --file assets.json \
  --just-tags \
  --tag-file my_tags.yaml
```

### Minimal Tag Configuration File

Create a file named `my_tags.yaml`:

```yaml
# Basic asset tags
custom_data:
  - key: "team"
    value: "security-ops"
  - key: "environment"
    value: "production"

# Vulnerability tags
vulnerability_tags:
  - key: "compliance"
    value: "PCI-DSS"
```

---

## Tag Types Overview

The Loading Script V5 supports **six types of tags**, each serving a specific purpose:

| Tag Type | Applied To | When Applied | Use Case |
|----------|-----------|--------------|----------|
| `custom_data` / `custom_tags` | Assets | All imported assets | Business unit, team ownership, general metadata |
| `asset_type_tags` | Assets | Based on asset type (INFRA, WEB, etc.) | Asset categorization, scan type identification |
| `environment_tags` | Assets | Based on environment context | Production/staging/dev differentiation |
| `vulnerability_tags` | Vulnerabilities | All vulnerabilities | Compliance requirements, tracking metadata |
| `severity_tags` | Vulnerabilities | Based on severity level | Priority assignment, SLA mapping |
| `compliance_tags` | Vulnerabilities | All vulnerabilities | Compliance framework mapping, audit requirements |

### Tag Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TAG CONFIGURATION FILE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │   custom_data   │    │ asset_type_tags │    │environment_tags │  │
│  │                 │    │                 │    │                 │  │
│  │ Applied to ALL  │    │ Applied based   │    │ Applied based   │  │
│  │ assets          │    │ on asset type   │    │ on environment  │  │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘  │
│           │                      │                      │           │
│           └──────────────────────┼──────────────────────┘           │
│                                  │                                   │
│                                  ▼                                   │
│                         ┌───────────────┐                           │
│                         │    ASSETS     │                           │
│                         │  (Phoenix)    │                           │
│                         └───────────────┘                           │
│                                                                      │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │vulnerability_   │    │  severity_tags  │    │ compliance_tags │  │
│  │     tags        │    │                 │    │                 │  │
│  │ Applied to ALL  │    │ Applied based   │    │ Applied to ALL  │  │
│  │ vulnerabilities │    │ on severity     │    │ vulnerabilities │  │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘  │
│           │                      │                      │           │
│           └──────────────────────┼──────────────────────┘           │
│                                  │                                   │
│                                  ▼                                   │
│                      ┌────────────────────┐                         │
│                      │  VULNERABILITIES   │                         │
│                      │    (Phoenix)       │                         │
│                      └────────────────────┘                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Configuration File Format

### Complete Tag Configuration Template

```yaml
# ============================================================================
# PHOENIX SECURITY TAG CONFIGURATION
# ============================================================================
# This file defines all tags to be applied during vulnerability import.
# Tags are key-value pairs that help organize and categorize assets and
# vulnerabilities in the Phoenix Security platform.
# ============================================================================

# ----------------------------------------------------------------------------
# ASSET TAGS (custom_data)
# ----------------------------------------------------------------------------
# These tags are applied to ALL imported assets regardless of type.
# Use for: Business unit identification, team ownership, general metadata
#
# Format:
#   - key: "tag-name"
#     value: "tag-value"
# ----------------------------------------------------------------------------
custom_data:
  # Business Unit / Organization Tags
  - key: "business-unit"
    value: "engineering"
  - key: "cost-center"
    value: "CC-12345"
  
  # Team / Ownership Tags
  - key: "team"
    value: "platform-security"
  - key: "owner"
    value: "user@example.com"
  
  # Scanner / Source Tags
  - key: "scanner-source"
    value: "automated-pipeline"
  - key: "import-method"
    value: "phoenix-loader-v5"
  
  # Custom Metadata
  - key: "data-classification"
    value: "internal"
  - key: "region"
    value: "us-east-1"

# ----------------------------------------------------------------------------
# ASSET TYPE TAGS
# ----------------------------------------------------------------------------
# These tags are applied based on the asset type being imported.
# Supported asset types: INFRA, WEB, CLOUD, CONTAINER, REPOSITORY, CODE, BUILD
# ----------------------------------------------------------------------------
asset_type_tags:
  INFRA:
    - key: "asset-category"
      value: "infrastructure"
    - key: "scan-type"
      value: "network-vulnerability-scan"
    - key: "monitoring"
      value: "infrastructure-team"
  
  WEB:
    - key: "asset-category"
      value: "web-application"
    - key: "scan-type"
      value: "dast-scan"
    - key: "monitoring"
      value: "appsec-team"
  
  CLOUD:
    - key: "asset-category"
      value: "cloud-resource"
    - key: "scan-type"
      value: "cspm-scan"
    - key: "monitoring"
      value: "cloud-security-team"
  
  CONTAINER:
    - key: "asset-category"
      value: "container-image"
    - key: "scan-type"
      value: "container-scan"
    - key: "monitoring"
      value: "devsecops-team"
  
  CODE:
    - key: "asset-category"
      value: "source-code"
    - key: "scan-type"
      value: "sast-scan"
    - key: "monitoring"
      value: "appsec-team"
  
  BUILD:
    - key: "asset-category"
      value: "build-artifact"
    - key: "scan-type"
      value: "sca-scan"
    - key: "monitoring"
      value: "devsecops-team"

# ----------------------------------------------------------------------------
# ENVIRONMENT TAGS
# ----------------------------------------------------------------------------
# These tags are applied based on the deployment environment.
# Define your environments and their associated criticality/handling.
# ----------------------------------------------------------------------------
environment_tags:
  production:
    - key: "environment"
      value: "production"
    - key: "criticality"
      value: "critical"
    - key: "change-window"
      value: "scheduled-maintenance"
    - key: "backup-required"
      value: "true"
  
  staging:
    - key: "environment"
      value: "staging"
    - key: "criticality"
      value: "high"
    - key: "change-window"
      value: "business-hours"
  
  development:
    - key: "environment"
      value: "development"
    - key: "criticality"
      value: "low"
    - key: "change-window"
      value: "anytime"
  
  qa:
    - key: "environment"
      value: "qa"
    - key: "criticality"
      value: "medium"
    - key: "change-window"
      value: "business-hours"

# ----------------------------------------------------------------------------
# VULNERABILITY TAGS
# ----------------------------------------------------------------------------
# These tags are applied to ALL vulnerabilities regardless of severity.
# Use for: Compliance mapping, tracking metadata, workflow integration
# ----------------------------------------------------------------------------
vulnerability_tags:
  - key: "vulnerability-source"
    value: "automated-scan"
  - key: "requires-review"
    value: "true"
  - key: "ticket-system"
    value: "jira"

# ----------------------------------------------------------------------------
# SEVERITY-BASED TAGS
# ----------------------------------------------------------------------------
# These tags are applied based on vulnerability severity level.
# Severity levels: critical, high, medium, low, informational
# Use for: Priority assignment, SLA mapping, escalation rules
# ----------------------------------------------------------------------------
severity_tags:
  critical:
    - key: "priority"
      value: "P1"
    - key: "sla-hours"
      value: "24"
    - key: "escalation"
      value: "immediate"
    - key: "notification"
      value: "security-leadership"
  
  high:
    - key: "priority"
      value: "P2"
    - key: "sla-hours"
      value: "72"
    - key: "escalation"
      value: "48-hours"
    - key: "notification"
      value: "security-team"
  
  medium:
    - key: "priority"
      value: "P3"
    - key: "sla-days"
      value: "7"
    - key: "escalation"
      value: "weekly-review"
  
  low:
    - key: "priority"
      value: "P4"
    - key: "sla-days"
      value: "30"
    - key: "escalation"
      value: "monthly-review"
  
  informational:
    - key: "priority"
      value: "P5"
    - key: "sla-days"
      value: "90"
    - key: "action"
      value: "monitor-only"

# ----------------------------------------------------------------------------
# COMPLIANCE TAGS
# ----------------------------------------------------------------------------
# These tags are applied to ALL vulnerabilities for compliance tracking.
# Use for: Audit requirements, framework mapping, regulatory compliance
# ----------------------------------------------------------------------------
compliance_tags:
  # Compliance Frameworks
  - key: "compliance-framework"
    value: "PCI-DSS-4.0"
  - key: "compliance-framework"
    value: "SOC2-Type-II"
  - key: "compliance-framework"
    value: "ISO27001"
  
  # Audit Requirements
  - key: "audit-required"
    value: "true"
  - key: "data-retention"
    value: "7-years"
  - key: "evidence-collection"
    value: "automated"

# ----------------------------------------------------------------------------
# ADDITIONAL CONFIGURATION
# ----------------------------------------------------------------------------
# apply_tags_after_import: If true, tags are applied in a separate API call
# after the initial import completes. Useful for large imports.
# ----------------------------------------------------------------------------
apply_tags_after_import: false
```

---

## Command Line Options

### Tag-Related Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--tag-file` | Path to YAML tag configuration file | `--tag-file tags.yaml` |
| `--just-tags` | Only apply tags, don't import new vulnerabilities | `--just-tags` |

### Complete Command Examples

```bash
# Basic import with tags
python phoenix_multi_scanner_enhanced.py \
  --file qualys_scan.csv \
  --scanner qualys \
  --tag-file customization/tags_config_PCI-NoSN_CIS.yaml

# Import with custom assessment name and tags
python phoenix_multi_scanner_enhanced.py \
  --file trivy_results.json \
  --scanner trivy \
  --assessment "Container Security Scan Q1-2024" \
  --tag-file container_tags.yaml

# Folder processing with tags
python phoenix_multi_scanner_enhanced.py \
  --folder /scans/daily/ \
  --tag-file production_tags.yaml \
  --enable-batching

# Tags-only mode (update existing assets)
python phoenix_multi_scanner_enhanced.py \
  --file existing_assets.json \
  --just-tags \
  --tag-file compliance_update_tags.yaml

# Debug mode to verify tag application
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file tags.yaml \
  --debug \
  --log-level DEBUG
```

---

## Tag Configuration Examples

### Example 1: PCI-DSS Compliance Tags

```yaml
# pci_compliance_tags.yaml
# For assets in PCI-DSS scope (Cardholder Data Environment)

custom_data:
  - key: "pci-scope"
    value: "in-scope"
  - key: "cde-zone"
    value: "CDE:Production"
  - key: "data-classification"
    value: "cardholder-data"

asset_type_tags:
  INFRA:
    - key: "pci-requirement"
      value: "11.2-vulnerability-scans"
  WEB:
    - key: "pci-requirement"
      value: "6.5-secure-coding"

vulnerability_tags:
  - key: "pci-finding"
    value: "true"
  - key: "qsa-review"
    value: "required"

severity_tags:
  critical:
    - key: "pci-sla"
      value: "immediate"
    - key: "compensating-control"
      value: "required-if-delayed"
  high:
    - key: "pci-sla"
      value: "30-days"

compliance_tags:
  - key: "compliance-framework"
    value: "PCI-DSS-4.0"
  - key: "audit-evidence"
    value: "required"
```

### Example 2: Multi-Team Organization Tags

```yaml
# multi_team_tags.yaml
# For organizations with multiple security teams

custom_data:
  - key: "organization"
    value: "acme-corp"
  - key: "import-date"
    value: "2024-01-15"

asset_type_tags:
  INFRA:
    - key: "responsible-team"
      value: "infrastructure-security"
    - key: "slack-channel"
      value: "#infra-sec-alerts"
  
  WEB:
    - key: "responsible-team"
      value: "application-security"
    - key: "slack-channel"
      value: "#appsec-alerts"
  
  CLOUD:
    - key: "responsible-team"
      value: "cloud-security"
    - key: "slack-channel"
      value: "#cloud-sec-alerts"
  
  CONTAINER:
    - key: "responsible-team"
      value: "devsecops"
    - key: "slack-channel"
      value: "#devsecops-alerts"

severity_tags:
  critical:
    - key: "escalation-path"
      value: "ciso-direct"
    - key: "war-room"
      value: "required"
  high:
    - key: "escalation-path"
      value: "security-manager"
```

### Example 3: ServiceNow Integration Tags

```yaml
# servicenow_integration_tags.yaml
# Tags for ServiceNow CMDB and ITSM integration

custom_data:
  - key: "sn-company"
    value: "ACME Corporation"
  - key: "sn-assignment-group"
    value: "Security Operations"
  - key: "sn-category"
    value: "Security Vulnerability"

asset_type_tags:
  INFRA:
    - key: "sn-ci-class"
      value: "cmdb_ci_server"
    - key: "sn-support-group"
      value: "Infrastructure Team"
  
  WEB:
    - key: "sn-ci-class"
      value: "cmdb_ci_appl"
    - key: "sn-support-group"
      value: "Application Team"

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
    - key: "sn-urgency"
      value: "1-High"
  
  medium:
    - key: "sn-priority"
      value: "3"
    - key: "sn-impact"
      value: "2-Medium"
    - key: "sn-urgency"
      value: "2-Medium"
  
  low:
    - key: "sn-priority"
      value: "4"
    - key: "sn-impact"
      value: "3-Low"
    - key: "sn-urgency"
      value: "3-Low"
```

### Example 4: Container/Kubernetes Tags

```yaml
# kubernetes_tags.yaml
# Tags for container and Kubernetes environments

custom_data:
  - key: "platform"
    value: "kubernetes"
  - key: "cluster-name"
    value: "prod-eks-cluster"
  - key: "namespace-default"
    value: "production"

asset_type_tags:
  CONTAINER:
    - key: "registry"
      value: "ecr.aws"
    - key: "image-policy"
      value: "signed-images-only"
    - key: "scan-frequency"
      value: "on-push"

vulnerability_tags:
  - key: "container-context"
    value: "runtime"
  - key: "base-image-check"
    value: "required"

severity_tags:
  critical:
    - key: "deployment-block"
      value: "true"
    - key: "admission-controller"
      value: "deny"
  high:
    - key: "deployment-block"
      value: "true"
    - key: "admission-controller"
      value: "warn"
  medium:
    - key: "deployment-block"
      value: "false"
    - key: "admission-controller"
      value: "log"
```

---

## Advanced Usage

### Using Multiple Tag Files

You can create modular tag configurations and combine them:

```bash
# Base tags + environment-specific tags
# First import with base tags
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file base_tags.yaml

# Then update with environment tags
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --just-tags \
  --tag-file production_env_tags.yaml
```

### Dynamic Tag Values

While the YAML file uses static values, you can create tag files dynamically:

```bash
#!/bin/bash
# generate_tags.sh - Generate dynamic tag configuration

DATE=$(date +%Y-%m-%d)
SCANNER_VERSION=$(trivy --version | head -1)

cat > dynamic_tags.yaml << EOF
custom_data:
  - key: "scan-date"
    value: "${DATE}"
  - key: "scanner-version"
    value: "${SCANNER_VERSION}"
  - key: "pipeline-id"
    value: "${CI_PIPELINE_ID:-manual}"
  - key: "git-commit"
    value: "${GIT_COMMIT:-unknown}"
EOF

python phoenix_multi_scanner_enhanced.py \
  --file scan_results.json \
  --tag-file dynamic_tags.yaml
```

### Tags in CI/CD Pipelines

#### GitHub Actions Example

```yaml
# .github/workflows/security-scan.yml
name: Security Scan with Tags

on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Trivy Scan
        run: trivy image myapp:latest -f json -o trivy_results.json
      
      - name: Generate Tag Config
        run: |
          cat > ci_tags.yaml << EOF
          custom_data:
            - key: "github-repo"
              value: "${{ github.repository }}"
            - key: "github-sha"
              value: "${{ github.sha }}"
            - key: "github-ref"
              value: "${{ github.ref }}"
            - key: "github-actor"
              value: "${{ github.actor }}"
            - key: "scan-trigger"
              value: "github-actions"
          EOF
      
      - name: Upload to Phoenix
        env:
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
        run: |
          python phoenix_multi_scanner_enhanced.py \
            --file trivy_results.json \
            --scanner trivy \
            --tag-file ci_tags.yaml
```

#### GitLab CI Example

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - trivy image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -f json -o trivy_results.json
    - |
      cat > gitlab_tags.yaml << EOF
      custom_data:
        - key: "gitlab-project"
          value: "${CI_PROJECT_PATH}"
        - key: "gitlab-pipeline"
          value: "${CI_PIPELINE_ID}"
        - key: "gitlab-commit"
          value: "${CI_COMMIT_SHA}"
        - key: "gitlab-branch"
          value: "${CI_COMMIT_REF_NAME}"
      EOF
    - python phoenix_multi_scanner_enhanced.py
        --file trivy_results.json
        --tag-file gitlab_tags.yaml
```

---

## Best Practices

### 1. Tag Naming Conventions

```yaml
# GOOD: Consistent, lowercase, hyphenated
custom_data:
  - key: "business-unit"
    value: "engineering"
  - key: "cost-center"
    value: "cc-12345"

# AVOID: Inconsistent naming
custom_data:
  - key: "BusinessUnit"      # Mixed case
    value: "Engineering"
  - key: "cost_center"       # Underscores
    value: "CC-12345"
```

### 2. Meaningful Tag Values

```yaml
# GOOD: Descriptive, actionable values
severity_tags:
  critical:
    - key: "sla"
      value: "24-hours"
    - key: "escalation"
      value: "security-leadership"

# AVOID: Vague or unclear values
severity_tags:
  critical:
    - key: "sla"
      value: "fast"
    - key: "escalation"
      value: "yes"
```

### 3. Environment-Specific Tag Files

Create separate tag files for different environments:

```
customization/
├── tags_base.yaml           # Common tags for all environments
├── tags_production.yaml     # Production-specific tags
├── tags_staging.yaml        # Staging-specific tags
├── tags_development.yaml    # Development-specific tags
└── tags_compliance/
    ├── tags_pci.yaml        # PCI-DSS compliance tags
    ├── tags_soc2.yaml       # SOC2 compliance tags
    └── tags_hipaa.yaml      # HIPAA compliance tags
```

### 4. Documentation in Tag Files

```yaml
# ============================================================================
# TAG CONFIGURATION: Production Environment
# ============================================================================
# Owner: Security Operations Team
# Last Updated: 2024-01-15
# Purpose: Tags for production vulnerability scans
# 
# Change History:
# - 2024-01-15: Added PCI compliance tags
# - 2024-01-01: Initial creation
# ============================================================================

custom_data:
  # Business context tags
  - key: "environment"
    value: "production"
```

### 5. Avoid Tag Sprawl

```yaml
# GOOD: Focused, necessary tags
custom_data:
  - key: "team"
    value: "security-ops"
  - key: "environment"
    value: "production"

# AVOID: Too many tags that add noise
custom_data:
  - key: "team"
    value: "security-ops"
  - key: "team-lead"
    value: "john.doe"
  - key: "team-email"
    value: "user@example.com"
  - key: "team-slack"
    value: "#security"
  - key: "team-oncall"
    value: "pagerduty"
  # ... too many related tags
```

---

## Troubleshooting

### Common Issues

#### 1. Tags Not Appearing in Phoenix

**Symptom**: Import succeeds but tags are missing

**Solutions**:
```bash
# Enable debug logging to see tag application
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file tags.yaml \
  --debug \
  --log-level DEBUG

# Check for empty tag values (these are filtered out)
# Look for log messages like:
# "🔍 DEBUG: filtered_tags after filtering = [...]"
```

**Common causes**:
- Empty tag values are automatically filtered out
- YAML syntax errors in tag file
- Tag file path is incorrect

#### 2. YAML Syntax Errors

**Symptom**: Error loading tag configuration

**Check YAML syntax**:
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('tags.yaml'))"
```

**Common YAML mistakes**:
```yaml
# WRONG: Missing quotes around special characters
custom_data:
  - key: sn-Product:    # Colon needs quotes
    value: adm-1

# CORRECT:
custom_data:
  - key: "sn-Product:"
    value: "adm-1"

# WRONG: Incorrect indentation
custom_data:
- key: "team"           # Should be indented
value: "security"       # Should be indented

# CORRECT:
custom_data:
  - key: "team"
    value: "security"
```

#### 3. Tags Applied to Wrong Entity

**Symptom**: Asset tags appearing on vulnerabilities or vice versa

**Solution**: Review your tag file structure:
```yaml
# Asset tags go under these sections:
custom_data:          # Applied to assets
asset_type_tags:      # Applied to assets
environment_tags:     # Applied to assets

# Vulnerability tags go under these sections:
vulnerability_tags:   # Applied to vulnerabilities
severity_tags:        # Applied to vulnerabilities
compliance_tags:      # Applied to vulnerabilities
```

#### 4. Severity Tags Not Applied

**Symptom**: Severity-specific tags missing

**Check severity mapping**:
```yaml
# Severity keys must be lowercase
severity_tags:
  critical:    # ✓ Correct
  high:        # ✓ Correct
  CRITICAL:    # ✗ Wrong - must be lowercase
  High:        # ✗ Wrong - must be lowercase
```

### Debug Commands

```bash
# Full debug output
python phoenix_multi_scanner_enhanced.py \
  --file scan.csv \
  --tag-file tags.yaml \
  --debug \
  --log-level DEBUG 2>&1 | tee import_debug.log

# Search for tag-related log entries
grep -i "tag" import_debug.log

# Validate tag file loads correctly
python -c "
import yaml
from pathlib import Path

tag_file = 'tags.yaml'
with open(tag_file) as f:
    data = yaml.safe_load(f)
    
print('Tag sections found:')
for key in data.keys():
    if isinstance(data[key], list):
        print(f'  {key}: {len(data[key])} items')
    elif isinstance(data[key], dict):
        print(f'  {key}: {len(data[key])} sub-sections')
"
```

---

## Reference: TagConfig Class

The `TagConfig` class in `phoenix_import_refactored.py` manages all tag operations:

```python
@dataclass
class TagConfig:
    """Configuration class for tag management"""
    tags: List[Dict[str, str]]                           # Base tags
    custom_tags: List[Dict[str, str]]                    # Custom asset tags
    vulnerability_tags: List[Dict[str, str]]             # Vulnerability tags
    severity_tags: Dict[str, List[Dict[str, str]]]       # Severity-based tags
    asset_type_tags: Dict[str, List[Dict[str, str]]]     # Asset type tags
    environment_tags: Dict[str, List[Dict[str, str]]]    # Environment tags
    compliance_tags: List[Dict[str, str]]                # Compliance tags
    apply_tags_after_import: bool = False                # Post-import tag application
    
    # Key methods:
    # get_all_tags() -> List[Dict]           # Returns all asset tags
    # get_vulnerability_tags(severity) -> List[Dict]  # Returns vuln tags
    # get_asset_type_tags(asset_type) -> List[Dict]   # Returns type-specific tags
    # get_environment_tags(environment) -> List[Dict] # Returns env-specific tags
```

---

## See Also

- [DOCUMENTATION_INDEX.md](../reference/DOCUMENTATION_INDEX.md) - Complete documentation index
- [JUNIOR_DEVELOPER_GUIDE.md](JUNIOR_DEVELOPER_GUIDE.md) - Getting started guide
- [PHOENIX_API_INTERACTION_GUIDE.md](../reference/PHOENIX_API_INTERACTION_GUIDE.md) - API reference
- [CONFIG_FILE_GUIDE.md](../guides/CONFIG_FILE_GUIDE.md) - Configuration file reference

---

## Appendix: Pre-Built Tag Configuration Files

The following tag configuration files are included in the `customization/` directory:

| File | Description |
|------|-------------|
| `custom data:.yaml.yml` | Default tag configuration template |
| `tags_config PCI-NoSN_CIS.yaml` | PCI-DSS compliance with CIS controls |
| `tags_config PCI-NoSN.yaml` | PCI-DSS compliance (basic) |
| `tags_config_adm1.yaml` | Admin team 1 configuration |
| `tags_config_adm1_NoSN.yaml` | Admin team 1 (no ServiceNow) |
| `tags_config_adm2.yaml` | Admin team 2 configuration |
| `tags_config_adm2_NoSN.yaml` | Admin team 2 (no ServiceNow) |

---

*Last Updated: February 2026*
*Version: Loading Script V5.0*
