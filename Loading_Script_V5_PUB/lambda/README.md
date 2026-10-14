# Phoenix Lambda Scanner Import

Serverless vulnerability import from S3 to Phoenix Security using AWS Lambda.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [S3 Folder Structure](#s3-folder-structure)
- [Supported Scanners](#supported-scanners)
- [Lambda Modes](#lambda-modes)
- [Configuration](#configuration)
- [Metadata and Tags](#metadata-and-tags)
- [Deployment](#deployment)
- [Local Testing](#local-testing)
- [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
- [API Reference](#api-reference)
- [Examples](#examples)

---

## Overview

The Phoenix Lambda Scanner Import is a serverless solution that automatically processes vulnerability scan files uploaded to S3 and imports them into Phoenix Security. It supports **205+ scanner types** with automatic detection.

### Key Features

- **Automatic Processing**: Files uploaded to S3 trigger Lambda automatically
- **Two-Folder Workflow**: Files move from `new/` to `processed/` after import
- **Scanner Auto-Detection**: Scanner type determined from folder name
- **Metadata Support**: Hierarchical tag configuration (file → scanner → global)
- **Orchestrator Mode**: Batch process all pending files on schedule
- **Secure**: Credentials via environment variables, not config files

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   S3 Bucket                                      │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │ scanners/                                                                  │  │
│  │   ├── trivy/                                                              │  │
│  │   │   ├── new/              ← Upload scan files here                      │  │
│  │   │   │   ├── scan.json                                                   │  │
│  │   │   │   └── scan_metadata.yaml (optional)                               │  │
│  │   │   ├── processed/        ← Files moved here after processing           │  │
│  │   │   └── metadata.yaml     (optional scanner-level tags)                 │  │
│  │   ├── grype/                                                              │  │
│  │   │   ├── new/                                                            │  │
│  │   │   └── processed/                                                      │  │
│  │   ├── prowler_v3/                                                         │  │
│  │   │   ├── new/                                                            │  │
│  │   │   └── processed/                                                      │  │
│  │   └── {any of 205+ scanners}/                                             │  │
│  │       ├── new/                                                            │  │
│  │       └── processed/                                                      │  │
│  ├── config/                                                                  │  │
│  │   └── lambda_config.ini     ← Lambda configuration                        │  │
│  └── metadata/                                                                │  │
│      └── global_tags.yaml      ← Global tags for all imports                 │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
            S3 Event Trigger    Scheduled Event      Manual Invoke
            (ObjectCreated)     (Every 15 min)       (API/Console)
                    │                   │                   │
                    ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           File Processor Lambda                                  │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  1. Receive S3 event or direct invocation                                 │  │
│  │  2. Download scan file from S3 to /tmp                                    │  │
│  │  3. Find & load metadata files (file → scanner → global priority)         │  │
│  │  4. Detect scanner type from folder name (e.g., scanners/trivy/...)       │  │
│  │  5. Process using MultiScannerImportManager (existing code)               │  │
│  │  6. Import assets & vulnerabilities to Phoenix Security API               │  │
│  │  7. Move file from new/ to processed/ folder                              │  │
│  │  8. Return result with import statistics                                  │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Phoenix Security API                                   │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  • Assets created/updated with tags                                       │  │
│  │  • Vulnerabilities imported with severity mapping                         │  │
│  │  • Assessment created for tracking                                        │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Orchestrator Mode Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Orchestrator Lambda                                     │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  1. Triggered by CloudWatch Events (every 15 min)                         │  │
│  │  2. List all objects under scanners/*/new/                                │  │
│  │  3. Filter out metadata files                                             │  │
│  │  4. For each scan file found:                                             │  │
│  │     └─► Invoke File Processor Lambda (async)                              │  │
│  │  5. Return summary of invocations                                         │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                    │
                    │ Async Invoke (up to N concurrent)
                    ▼
    ┌───────────────┬───────────────┬───────────────┐
    │               │               │               │
    ▼               ▼               ▼               ▼
┌───────┐      ┌───────┐      ┌───────┐      ┌───────┐
│ File  │      │ File  │      │ File  │      │ File  │
│Proc #1│      │Proc #2│      │Proc #3│      │Proc #N│
└───────┘      └───────┘      └───────┘      └───────┘
```

---

## Quick Start

### 1. Deploy the Stack

```bash
cd Utils/Loading_Script_V5/lambda/deploy

# Build the Lambda layer
./build_layer.sh

# Deploy with SAM
sam deploy --guided \
  --parameter-overrides \
    Environment=prod \
    S3BucketName=my-phoenix-scanner-data \
    PhoenixClientId=YOUR_CLIENT_ID \
    PhoenixClientSecret=YOUR_CLIENT_SECRET
```

### 2. Upload Configuration

```bash
# Customize the config template
cp ../lambda_config_template.ini lambda_config.ini
# Edit as needed...

# Upload to S3
aws s3 cp lambda_config.ini s3://my-phoenix-scanner-data-prod/config/lambda_config.ini
```

### 3. Upload a Scan File

```bash
# Upload a Trivy scan - it will be processed automatically
aws s3 cp trivy_scan.json s3://my-phoenix-scanner-data-prod/scanners/trivy/new/

# Check if it was processed (moved to processed/)
aws s3 ls s3://my-phoenix-scanner-data-prod/scanners/trivy/processed/
```

---

## S3 Folder Structure

```
s3://your-bucket/
├── config/
│   └── lambda_config.ini              # Main configuration file
│
├── metadata/
│   └── global_tags.yaml               # Global tags applied to ALL imports
│
└── scanners/
    ├── trivy/                         # Scanner name (determines type)
    │   ├── new/                       # Upload files here
    │   │   ├── scan_20240201.json     # Scan file to process
    │   │   └── scan_20240201_metadata.yaml  # Optional file-specific tags
    │   ├── processed/                 # Files moved here after success
    │   │   └── scan_20240201.json
    │   └── metadata.yaml              # Optional scanner-level tags
    │
    ├── grype/
    │   ├── new/
    │   └── processed/
    │
    ├── prowler_v3/
    │   ├── new/
    │   └── processed/
    │
    └── {scanner_name}/                # Any of 205+ supported scanners
        ├── new/
        └── processed/
```

### Folder Naming Rules

| Rule | Example | Notes |
|------|---------|-------|
| Use lowercase | `trivy` not `Trivy` | Case-sensitive matching |
| Use underscores | `prowler_v3` not `prowler-v3` | Hyphens not supported |
| Match scanner names exactly | `anchore_grype` not `grype` | See supported list |

---

## Supported Scanners

The folder name under `scanners/` must match one of the supported scanner types:

### Container Scanners
| Folder Name | Scanner |
|-------------|---------|
| `trivy` | Trivy container/SCA scanner |
| `grype` | Anchore Grype |
| `anchore_grype` | Anchore Grype (alternative) |
| `aqua` | Aqua Security |
| `clair` | CoreOS Clair |
| `harbor` | Harbor Registry |
| `docker_bench` | Docker Bench for Security |
| `sysdig` | Sysdig Secure |

### Infrastructure Scanners
| Folder Name | Scanner |
|-------------|---------|
| `qualys` | Qualys Vulnerability Scanner |
| `tenable` | Tenable.io / Nessus |
| `nexpose` | Rapid7 Nexpose |
| `openvas` | OpenVAS |
| `nmap` | Nmap Network Scanner |
| `nuclei` | Nuclei Scanner |

### Cloud Security Scanners
| Folder Name | Scanner |
|-------------|---------|
| `prowler` | AWS Prowler v2 |
| `prowler_v3` | AWS Prowler v3/v4/v5 (OCSF) |
| `scout_suite` | Scout Suite (multi-cloud) |
| `checkov` | Checkov IaC Scanner |
| `kics` | KICS IaC Scanner |
| `cloudsploit` | CloudSploit |
| `steampipe` | Steampipe |

### Code/SAST Scanners
| Folder Name | Scanner |
|-------------|---------|
| `sonarqube` | SonarQube |
| `checkmarx` | Checkmarx SAST |
| `fortify` | Fortify SAST |
| `semgrep` | Semgrep |
| `bandit` | Bandit (Python) |
| `brakeman` | Brakeman (Ruby) |
| `gosec` | GoSec (Go) |

### SCA/Dependency Scanners
| Folder Name | Scanner |
|-------------|---------|
| `snyk` | Snyk |
| `dependency_check` | OWASP Dependency Check |
| `npm_audit` | npm audit |
| `pip_audit` | pip-audit |
| `cyclonedx` | CycloneDX SBOM |
| `syft` | Syft SBOM |

### Web Application Scanners
| Folder Name | Scanner |
|-------------|---------|
| `burp` | Burp Suite |
| `burp_api` | Burp Suite API |
| `qualys_webapp` | Qualys WAS |
| `acunetix` | Acunetix |
| `nikto` | Nikto |
| `zap` | OWASP ZAP |

### Build/Artifact Scanners
| Folder Name | Scanner |
|-------------|---------|
| `jfrog_xray` | JFrog Xray |
| `blackduck` | Black Duck SCA |

### CSV Formats
| Folder Name | Scanner |
|-------------|---------|
| `phoenix_csv` | Phoenix native CSV |
| `rapid7_csv` | Rapid7 CSV export |

> **Note**: See the main `Loading_Script_V5/README.md` for the complete list of 205+ supported scanners.

---

## Lambda Modes

### Single File Mode (Default)

Processes one file at a time. Triggered by:
- S3 ObjectCreated events (automatic)
- Direct Lambda invocation (manual)

**Event Format:**
```json
{
  "mode": "single",
  "bucket": "my-phoenix-scanner-data-prod",
  "file_key": "scanners/trivy/new/scan.json",
  "config_key": "config/lambda_config.ini",
  "assessment_name": "Optional-Custom-Name",
  "import_type": "new"
}
```

**S3 Event Format (automatic):**
```json
{
  "Records": [{
    "s3": {
      "bucket": {"name": "my-phoenix-scanner-data-prod"},
      "object": {"key": "scanners/trivy/new/scan.json"}
    }
  }]
}
```

**Response:**
```json
{
  "statusCode": 200,
  "body": {
    "success": true,
    "mode": "single",
    "file_processed": "scanners/trivy/new/scan.json",
    "moved_to": "scanners/trivy/processed/scan.json",
    "scanner_type": "trivy",
    "metadata_files_loaded": [
      "scanners/trivy/metadata.yaml",
      "metadata/global_tags.yaml"
    ],
    "assets_imported": 15,
    "vulnerabilities_imported": 127,
    "assessment_name": "Lambda_trivy_20240201_143052",
    "phoenix_request_id": "req_abc123",
    "execution_time_ms": 4523
  }
}
```

### Orchestrator Mode

Scans all `new/` folders and invokes File Processor Lambda for each file.

**Event Format:**
```json
{
  "mode": "orchestrator",
  "bucket": "my-phoenix-scanner-data-prod",
  "config_key": "config/lambda_config.ini",
  "scanner_filter": ["trivy", "grype", "prowler_v3"],
  "max_concurrent": 5
}
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `mode` | Yes | Must be `"orchestrator"` |
| `bucket` | Yes | S3 bucket name |
| `config_key` | No | Path to INI config (default: `config/lambda_config.ini`) |
| `scanner_filter` | No | Array of scanner names to process (default: all) |
| `max_concurrent` | No | Max concurrent Lambda invocations (default: 10) |

**Response:**
```json
{
  "statusCode": 200,
  "body": {
    "success": true,
    "mode": "orchestrator",
    "files_found": 12,
    "lambdas_invoked": 10,
    "scanners_processed": ["trivy", "grype", "prowler_v3"],
    "invocations": [
      {"file": "scanners/trivy/new/scan1.json", "status_code": 202},
      {"file": "scanners/trivy/new/scan2.json", "status_code": 202}
    ],
    "errors": [],
    "execution_time_ms": 1234
  }
}
```

---

## Configuration

### Environment Variables

Set these in Lambda configuration (never in config files):

| Variable | Required | Description |
|----------|----------|-------------|
| `PHOENIX_CLIENT_ID` | **Yes** | Phoenix API client ID |
| `PHOENIX_CLIENT_SECRET` | **Yes** | Phoenix API client secret (PAT) |
| `PHOENIX_API_URL` | No | Override API URL |
| `S3_BUCKET` | No | Default S3 bucket |
| `LOG_LEVEL` | No | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### INI Configuration File

Upload to `s3://bucket/config/lambda_config.ini`:

```ini
[phoenix]
# API endpoint (credentials come from env vars)
api_base_url = https://api.appsecphx.io

# Import settings
import_type = new
assessment_name_prefix = Lambda-Import
wait_for_completion = true
timeout = 300
check_interval = 5

[lambda]
# S3 folder structure
scanners_prefix = scanners/
metadata_prefix = metadata/
new_folder = new
processed_folder = processed

# Cleanup
cleanup_after_processing = true

[orchestrator]
# Concurrency limits
max_concurrent_lambdas = 10
function_name = phoenix-file-processor-prod

[batch_processing]
enable_batching = true
max_batch_size = 100
max_payload_mb = 25.0
retry_count = 3

[logging]
level = INFO
include_request_details = false
```

See `lambda_config_template.ini` for full documentation.

---

## Metadata and Tags

### Priority Order

Tags are merged with the following priority (highest first):

1. **File-specific**: `scanners/trivy/new/scan_metadata.yaml`
2. **Scanner-level**: `scanners/trivy/metadata.yaml`
3. **Global**: `metadata/global_tags.yaml`

### Metadata File Format

```yaml
# Custom tags applied to all assets
custom_data:
  - key: "environment"
    value: "production"
  - key: "team"
    value: "platform-security"
  - key: "cost-center"
    value: "CC-1234"

# Tags applied to vulnerabilities
vulnerability_tags:
  - key: "source"
    value: "automated-scan"

# Tags based on severity
severity_tags:
  critical:
    - key: "priority"
      value: "P1"
    - key: "sla"
      value: "24h"
  high:
    - key: "priority"
      value: "P2"
    - key: "sla"
      value: "7d"
  medium:
    - key: "priority"
      value: "P3"
  low:
    - key: "priority"
      value: "P4"

# Tags based on asset type
asset_type_tags:
  CONTAINER:
    - key: "asset-category"
      value: "container"
  CLOUD:
    - key: "asset-category"
      value: "cloud-resource"
  CODE:
    - key: "asset-category"
      value: "repository"

# Environment-specific tags
environment_tags:
  production:
    - key: "env-criticality"
      value: "high"
  staging:
    - key: "env-criticality"
      value: "medium"

# Compliance framework tags
compliance_tags:
  - key: "compliance-framework"
    value: "SOC2"
  - key: "compliance-framework"
    value: "PCI-DSS"
```

### File-Specific Metadata Naming

Place metadata next to scan files with these naming patterns:

| Scan File | Metadata File |
|-----------|---------------|
| `scan.json` | `scan_metadata.yaml` |
| `scan_20240201.json` | `scan_20240201_metadata.yaml` |
| `report.xml` | `report_metadata.yaml` |
| `findings.csv` | `findings_tags.yaml` |

---

## Deployment

### Prerequisites

- AWS CLI configured
- AWS SAM CLI installed
- Python 3.9+ installed
- Phoenix Security API credentials

### Deploy with SAM

```bash
cd Utils/Loading_Script_V5/lambda/deploy

# Build the layer
./build_layer.sh

# Deploy (interactive)
sam deploy --guided

# Or deploy with all parameters
sam deploy \
  --stack-name phoenix-scanner-import-prod \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Environment=prod \
    S3BucketName=phoenix-scanner-data \
    PhoenixApiUrl=https://api.appsecphx.io \
    PhoenixClientId=$PHOENIX_CLIENT_ID \
    PhoenixClientSecret=$PHOENIX_CLIENT_SECRET \
    LogLevel=INFO \
    MaxConcurrentLambdas=10
```

### Manual Deployment

```bash
# 1. Build the layer
cd Utils/Loading_Script_V5/lambda/deploy
./build_layer.sh

# 2. Upload layer to S3
aws s3 cp build/phoenix-scanner-layer.zip s3://my-bucket/layers/

# 3. Publish layer
aws lambda publish-layer-version \
  --layer-name phoenix-scanner-deps \
  --content S3Bucket=my-bucket,S3Key=layers/phoenix-scanner-layer.zip \
  --compatible-runtimes python3.9 python3.10 python3.11

# 4. Create Lambda function
aws lambda create-function \
  --function-name phoenix-file-processor \
  --runtime python3.11 \
  --handler lambda.phoenix_lambda_handler.lambda_handler \
  --role arn:aws:iam::ACCOUNT:role/lambda-role \
  --layers arn:aws:lambda:REGION:ACCOUNT:layer:phoenix-scanner-deps:1 \
  --environment Variables="{PHOENIX_CLIENT_ID=xxx,PHOENIX_CLIENT_SECRET=xxx}"
```

### IAM Permissions Required

```yaml
# Minimum permissions for File Processor Lambda
- s3:GetObject      # Read scan files, config, metadata
- s3:PutObject      # Write to processed folder
- s3:DeleteObject   # Remove from new folder
- s3:ListBucket     # List objects (orchestrator only)

# Additional for Orchestrator
- lambda:InvokeFunction  # Invoke file processor
```

---

## Local Testing

### Test Single File Processing

```bash
cd Utils/Loading_Script_V5

# Set credentials
export PHOENIX_CLIENT_ID=your_client_id
export PHOENIX_CLIENT_SECRET=your_client_secret
export PHOENIX_API_URL=https://api.appsecphx.io

# Run as module
python -m lambda.phoenix_lambda_handler '{
  "mode": "single",
  "bucket": "test-bucket",
  "file_key": "scanners/trivy/new/test.json"
}'
```

### Test with LocalStack

```bash
# Start LocalStack
docker run -d -p 4566:4566 localstack/localstack

# Create test bucket
aws --endpoint-url=http://localhost:4566 s3 mb s3://test-bucket

# Upload test file
aws --endpoint-url=http://localhost:4566 s3 cp test.json s3://test-bucket/scanners/trivy/new/

# Run Lambda locally with SAM
sam local invoke FileProcessorFunction \
  --event test_event.json \
  --env-vars env.json
```

---

## Monitoring and Troubleshooting

### CloudWatch Logs

| Log Group | Contents |
|-----------|----------|
| `/aws/lambda/phoenix-file-processor-{env}` | Individual file processing |
| `/aws/lambda/phoenix-orchestrator-{env}` | Orchestrator runs |

### Common Log Patterns

```bash
# Find errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/phoenix-file-processor-prod \
  --filter-pattern "ERROR"

# Find specific file
aws logs filter-log-events \
  --log-group-name /aws/lambda/phoenix-file-processor-prod \
  --filter-pattern "scan_20240201.json"
```

### CloudWatch Metrics

| Metric | Description |
|--------|-------------|
| `Invocations` | Number of Lambda executions |
| `Errors` | Failed executions |
| `Duration` | Processing time |
| `ConcurrentExecutions` | Parallel executions |
| `Throttles` | Rate-limited invocations |

### Troubleshooting Guide

| Issue | Cause | Solution |
|-------|-------|----------|
| File not processing | Not in `new/` folder | Move to `scanners/{type}/new/` |
| File not processing | Wrong folder name | Use exact scanner name (lowercase) |
| Import failing | Invalid credentials | Check `PHOENIX_CLIENT_ID` and `PHOENIX_CLIENT_SECRET` |
| Import failing | API unreachable | Check VPC/security group settings |
| File not moving | Missing S3 permissions | Add `s3:DeleteObject` permission |
| Timeout | Large file | Increase Lambda timeout (max 15 min) |
| Out of memory | Large file | Increase Lambda memory |
| Scanner not detected | Unknown format | Check file matches scanner format |

### Debug Mode

Enable detailed logging:

```bash
# Set in Lambda environment
LOG_LEVEL=DEBUG

# Or in lambda_config.ini
[logging]
level = DEBUG
include_request_details = true
```

---

## API Reference

### phoenix_lambda_handler.lambda_handler

Main entry point for Lambda invocations.

**Parameters:**
- `event` (dict): Lambda event (S3 or direct invocation)
- `context` (object): Lambda context

**Returns:**
```python
{
    "statusCode": int,      # 200 for success, 400/500 for errors
    "body": {
        "success": bool,
        "mode": str,        # "single" or "orchestrator"
        # ... mode-specific fields
    }
}
```

### LambdaConfig

Configuration class for Lambda-specific settings.

```python
config = LambdaConfig()
config.phoenix_client_id      # From PHOENIX_CLIENT_ID env var
config.phoenix_client_secret  # From PHOENIX_CLIENT_SECRET env var
config.bucket                 # From S3_BUCKET env var
config.scanners_prefix        # Default: "scanners/"
config.new_folder             # Default: "new"
config.processed_folder       # Default: "processed"
```

### Helper Functions

```python
# Download file from S3
download_from_s3(bucket: str, key: str, local_path: str) -> bool

# Move S3 object (copy + delete)
move_s3_object(bucket: str, source_key: str, dest_key: str) -> bool

# List S3 objects with optional suffix filter
list_s3_objects(bucket: str, prefix: str, suffix: str = None) -> List[str]

# Detect scanner type from S3 path
detect_scanner_from_path(file_key: str, scanners_prefix: str) -> str

# Find metadata files for a scan
find_metadata_files(bucket: str, file_key: str, config: LambdaConfig) -> List[str]
```

---

## Examples

### Example 1: Basic Trivy Scan Import

```bash
# Upload scan file
aws s3 cp trivy_output.json s3://my-bucket/scanners/trivy/new/

# Lambda automatically:
# 1. Detects scanner type: trivy
# 2. Processes file
# 3. Imports to Phoenix
# 4. Moves to: s3://my-bucket/scanners/trivy/processed/trivy_output.json
```

### Example 2: Scan with Custom Tags

```bash
# Create metadata file
cat > scan_metadata.yaml << EOF
custom_data:
  - key: "application"
    value: "payment-service"
  - key: "team"
    value: "payments"
EOF

# Upload both files
aws s3 cp scan.json s3://my-bucket/scanners/trivy/new/
aws s3 cp scan_metadata.yaml s3://my-bucket/scanners/trivy/new/
```

### Example 3: Manual Lambda Invocation

```bash
# Invoke directly
aws lambda invoke \
  --function-name phoenix-file-processor-prod \
  --payload '{
    "mode": "single",
    "bucket": "my-bucket",
    "file_key": "scanners/trivy/new/scan.json",
    "assessment_name": "Manual-Import-2024"
  }' \
  response.json

cat response.json
```

### Example 4: Process Specific Scanners Only

```bash
# Invoke orchestrator for specific scanners
aws lambda invoke \
  --function-name phoenix-orchestrator-prod \
  --payload '{
    "mode": "orchestrator",
    "bucket": "my-bucket",
    "scanner_filter": ["trivy", "grype"],
    "max_concurrent": 5
  }' \
  response.json
```

### Example 5: Global Tags for All Imports

```bash
# Create global tags
cat > global_tags.yaml << EOF
custom_data:
  - key: "org"
    value: "acme-corp"
  - key: "imported-by"
    value: "lambda-automation"

compliance_tags:
  - key: "framework"
    value: "SOC2"
EOF

# Upload to metadata folder
aws s3 cp global_tags.yaml s3://my-bucket/metadata/global_tags.yaml

# All future imports will include these tags
```

---

## File Structure

```
Utils/Loading_Script_V5/lambda/
├── __init__.py                     # Package init
├── phoenix_lambda_handler.py       # Main Lambda handler
├── lambda_config_template.ini      # Configuration template
├── README.md                       # This documentation
└── deploy/
    ├── template.yaml               # SAM deployment template
    ├── build_layer.sh              # Layer build script
    └── README.md                   # Deployment quick reference
```

## Related Documentation

- [Main Loading Script Documentation](../README.md)
- [Tag Configuration Guide](../docs/guides/TAG_CONFIGURATION_GUIDE.md)
- [Supported Scanners](../docs/guides/QUICK_START_ALL_SCANNERS.md)
- Batching Guide
