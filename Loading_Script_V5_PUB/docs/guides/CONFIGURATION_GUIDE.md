# Loading_Script_V5 — Configuration Guide

**Version**: 5.0 (Modular Architecture)
**Last Updated**: February 2026
**Path**: `Utils/Loading_Script_V5/`

---

## Table of Contents

- [Configuration Methods](#configuration-methods)
- [CLI Arguments](#cli-arguments)
- [config.ini Reference](#configini-reference)
- [Environment Variable Overrides](#environment-variable-overrides)
- [Scanner-Specific Configuration](#scanner-specific-configuration)
- [Multi-Environment Patterns](#multi-environment-patterns)
- [Synthetic Data Configuration](#synthetic-data-configuration)
- [Tag Customization](#tag-customization)
- [CI/CD Configuration](#cicd-configuration)
- [Related Documents](#related-documents)

---

## Configuration Methods

Configuration follows this precedence (highest to lowest):

1. **CLI arguments** — `--file`, `--scanner`, `--assessment`, etc.
2. **Environment variables** — `PHOENIX_CLIENT_ID`, etc.
3. **config.ini file** — `[phoenix]` section values
4. **Built-in defaults**

---

## CLI Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `--file` | string | Yes | — | Path to scanner output file |
| `--config` | string | No | `config_multi_scanner.ini` | Path to configuration file |
| `--scanner` | string | No | auto-detect | Scanner type override |
| `--assessment` | string | No | auto-generated | Assessment name in Phoenix |
| `--asset-name` | string | No | from scan data | Override asset name |
| `--import-type` | string | No | `new` | Import mode: `new`, `merge`, `delta` |
| `--asset-type` | string | No | from translator | Override asset type |
| `--fix-data` | flag | No | enabled | Auto-fix validation issues |
| `--anonymize` | flag | No | disabled | Anonymize asset data |
| `--just-tags` | flag | No | disabled | Only apply tags, skip import |
| `--create-empty-assets` | flag | No | disabled | Create assets without findings |
| `--create-inventory-assets` | flag | No | disabled | Create inventory-mode assets |
| `--max-batch-size` | int | No | 50 | Maximum assets per batch |
| `--max-payload-mb` | int | No | 15 | Maximum payload size in MB |

### Import Types

| Type | Behavior |
|------|----------|
| `new` | Creates a new assessment; all findings treated as new |
| `merge` | Merges findings into existing assessment; updates existing, adds new |
| `delta` | Compares against existing data; marks missing findings as resolved |

### Asset Types

| Value | Description |
|-------|-------------|
| `INFRA` | Infrastructure (servers, network devices) |
| `WEB` | Web applications |
| `CLOUD` | Cloud resources (AWS, Azure, GCP) |
| `CONTAINER` | Container images |
| `CODE` | Source code repositories |
| `REPOSITORY` | Code repositories |
| `BUILD` | Build artifacts |

---

## config.ini Reference

### [phoenix] Section

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `client_id` | string | — | Yes | Phoenix OAuth2 client ID |
| `client_secret` | string | — | Yes | Phoenix OAuth2 client secret (PAT) |
| `api_base_url` | string | — | Yes | Phoenix API base URL |
| `import_type` | string | `new` | No | Default import type |
| `assessment_name` | string | auto | No | Default assessment name |
| `auto_import` | boolean | `true` | No | Auto-import after processing |
| `wait_for_completion` | boolean | `true` | No | Wait for import to finish |
| `batch_delay` | integer | `5` | No | Delay between batches (seconds) |
| `timeout` | integer | `3600` | No | Import timeout (seconds) |
| `check_interval` | integer | `10` | No | Status check interval (seconds) |
| `apply_tags_after_import` | boolean | `false` | No | Apply tags post-import |

### [scanner_*] Sections

Per-scanner configuration sections. Example for Trivy:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scanner_type` | string | — | Scanner display name |
| `asset_type` | string | — | Default asset type for this scanner |
| `severity_mapping_critical` | float | `10.0` | CVSS mapping for Critical |
| `severity_mapping_high` | float | `8.0` | CVSS mapping for High |
| `severity_mapping_medium` | float | `5.0` | CVSS mapping for Medium |
| `severity_mapping_low` | float | `2.0` | CVSS mapping for Low |
| `severity_mapping_negligible` | float | `1.0` | CVSS mapping for Negligible |
| `vulnerability_filters` | string | — | Comma-separated severities to exclude |

### [logging] Section

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | string | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |
| `file` | string | `phoenix_import.log` | Log file path |
| `max_size` | string | `10MB` | Maximum log file size |
| `backup_count` | integer | `5` | Number of rotated log files to keep |

### [batch_processing] Section

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_parallel_files` | integer | `5` | Maximum concurrent file processing |
| `max_file_size` | integer | `100` | Maximum file size in MB |
| `skip_large_files` | boolean | `true` | Skip files exceeding max_file_size |
| `retry_count` | integer | `3` | Number of retries for failed imports |
| `retry_delay` | integer | `30` | Base delay between retries (seconds) |

### Complete Example

```ini
[phoenix]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
api_base_url = https://api.appsecphx.io
import_type = new
auto_import = true
wait_for_completion = true
batch_delay = 5
timeout = 3600
check_interval = 10
apply_tags_after_import = false

[scanner_trivy]
scanner_type = Trivy Scan
asset_type = CONTAINER
severity_mapping_critical = 10.0
severity_mapping_high = 8.0
severity_mapping_medium = 5.0
severity_mapping_low = 2.0
severity_mapping_negligible = 1.0

[scanner_aqua]
scanner_type = Aqua Scan
asset_type = CONTAINER
severity_mapping_critical = 10.0
severity_mapping_high = 8.0
severity_mapping_medium = 5.0
severity_mapping_low = 2.0
severity_mapping_negligible = 1.0
vulnerability_filters = info,informational,negligible

[logging]
level = INFO
file = phoenix_import.log
max_size = 10MB
backup_count = 5

[batch_processing]
max_parallel_files = 5
max_file_size = 100
skip_large_files = true
retry_count = 3
retry_delay = 30
```

---

## Environment Variable Overrides

| Environment Variable | Overrides | Description |
|---------------------|-----------|-------------|
| `PHOENIX_CLIENT_ID` | `[phoenix] client_id` | OAuth2 client identifier |
| `PHOENIX_CLIENT_SECRET` | `[phoenix] client_secret` | OAuth2 client secret |
| `PHOENIX_API_BASE_URL` | `[phoenix] api_base_url` | API base URL |

---

## Scanner-Specific Configuration

### Severity Mapping

Each scanner section can define custom severity mappings. The defaults are:

| Scanner Severity | Default CVSS |
|-----------------|-------------|
| Critical | 10.0 |
| High | 8.0 |
| Medium | 5.0 |
| Low | 2.0 |
| Negligible/Info | 1.0 |

### Vulnerability Filters

Exclude specific severity levels from import:

```ini
[scanner_aqua]
# Skip informational and negligible findings
vulnerability_filters = info,informational,negligible
```

---

## Multi-Environment Patterns

### Development

```ini
[phoenix]
client_id = DEV_CLIENT_ID
client_secret = DEV_CLIENT_SECRET
api_base_url = https://api.demo.appsecphx.io
import_type = new

[logging]
level = DEBUG

[batch_processing]
max_parallel_files = 1
retry_count = 1
```

### Staging

```ini
[phoenix]
client_id = STAGING_CLIENT_ID
client_secret = STAGING_CLIENT_SECRET
api_base_url = https://api.poc1.appsecphx.io
import_type = merge

[logging]
level = INFO

[batch_processing]
max_parallel_files = 3
retry_count = 2
```

### Production

```ini
[phoenix]
client_id = PROD_CLIENT_ID
client_secret = PROD_CLIENT_SECRET
api_base_url = https://api.appsecphx.io
import_type = delta

[logging]
level = WARNING

[batch_processing]
max_parallel_files = 5
retry_count = 3
retry_delay = 30
```

---

## Synthetic Data Configuration

### synthetic_data_config.ini

| Parameter | Section | Type | Default | Description |
|-----------|---------|------|---------|-------------|
| `total_assets` | `[general]` | integer | 100 | Total assets to generate |
| `scanner_types` | `[general]` | comma-separated | all | Scanner types to generate |
| `asset_distribution_mode` | `[asset_distribution]` | string | `standard` | `standard` or `per_class` |
| `infra_assets` | `[asset_distribution]` | integer | — | INFRA asset count (per_class) |
| `container_assets` | `[asset_distribution]` | integer | — | CONTAINER asset count (per_class) |
| `cloud_assets` | `[asset_distribution]` | integer | — | CLOUD asset count (per_class) |
| `web_assets` | `[asset_distribution]` | integer | — | WEB asset count (per_class) |
| `code_assets` | `[asset_distribution]` | integer | — | CODE asset count (per_class) |
| `{scanner}_vulns_min` | `[vulnerability_counts]` | integer | 5 | Min vulns per asset for scanner |
| `{scanner}_vulns_max` | `[vulnerability_counts]` | integer | 30 | Max vulns per asset for scanner |

See SYNTHETIC_DATA_GUIDE.md and `synthetic-data-generator/` for usage.

---

## Tag Customization

Tag configuration files are located in `customization/`:

| File | Purpose |
|------|---------|
| `infra_tags.yaml` | Tags for infrastructure assets |
| `container_tags.yaml` | Tags for container assets |
| `cloud_tags.yaml` | Tags for cloud assets |
| `web_tags.yaml` | Tags for web application assets |
| `code_tags.yaml` | Tags for code/repository assets |
| `global_tags.yaml` | Tags applied to all asset types |

### Tag File Format

```yaml
tags:
  - key: "environment"
    values: ["production", "staging", "development"]
  - key: "team"
    values: ["platform", "security", "devops"]
  - key: "business_unit"
    values: ["engineering", "finance", "operations"]
```

---

## CI/CD Configuration

### GitHub Actions

```yaml
- name: Import scan results to Phoenix
  env:
    PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
    PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
    PHOENIX_API_BASE_URL: ${{ secrets.PHOENIX_API_BASE_URL }}
  run: |
    python3 phoenix_multi_scanner_enhanced.py \
      --file trivy-results.json \
      --config my_config.ini \
      --assessment "${{ github.repository }}-${{ github.run_number }}"
```

### Jenkins

```groovy
withCredentials([
    string(credentialsId: 'phoenix-client-id', variable: 'PHOENIX_CLIENT_ID'),
    string(credentialsId: 'phoenix-client-secret', variable: 'PHOENIX_CLIENT_SECRET')
]) {
    sh '''
        python3 phoenix_multi_scanner_enhanced.py \
            --file scan-results.json \
            --config my_config.ini \
            --assessment "${JOB_NAME}-${BUILD_NUMBER}"
    '''
}
```

### GitLab CI

```yaml
import-to-phoenix:
  stage: security
  variables:
    PHOENIX_CLIENT_ID: $PHOENIX_CLIENT_ID
    PHOENIX_CLIENT_SECRET: $PHOENIX_CLIENT_SECRET
    PHOENIX_API_BASE_URL: $PHOENIX_API_BASE_URL
  script:
    - python3 phoenix_multi_scanner_enhanced.py
        --file gl-sast-report.json
        --config my_config.ini
        --scanner sarif
        --assessment "$CI_PROJECT_NAME-$CI_PIPELINE_ID"
```

---

## Related Documents

- Synthetic Data Guide — Synthetic data usage
- [README](../../README.md) — Primary documentation
- [Quick Start](../../QUICK_START.md) — 5-minute setup guide
- Architecture — Component design
- [Scanner Translator Guide](../reference/SCANNER_TRANSLATOR_GUIDE.md) — All supported scanners
- [Troubleshooting](TROUBLESHOOTING.md) — Operational runbook
- Utils Security Guide — Credential management
