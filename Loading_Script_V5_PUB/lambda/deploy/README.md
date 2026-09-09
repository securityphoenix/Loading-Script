# Phoenix Lambda Scanner Import - Deployment Guide

Serverless vulnerability import from S3 to Phoenix Security using AWS Lambda.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              S3 Bucket                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ scanners/                                                                ││
│  │   ├── trivy/                                                            ││
│  │   │   ├── new/          ← Upload scan files here                        ││
│  │   │   │   ├── scan.json                                                 ││
│  │   │   │   └── scan_metadata.yaml (optional)                             ││
│  │   │   ├── processed/    ← Files moved here after processing             ││
│  │   │   └── metadata.yaml (optional scanner-level tags)                   ││
│  │   ├── grype/                                                            ││
│  │   ├── prowler_v3/                                                       ││
│  │   └── {205 scanner types}/                                              ││
│  ├── config/                                                                ││
│  │   └── lambda_config.ini                                                 ││
│  └── metadata/                                                              ││
│      └── global_tags.yaml                                                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ S3 Event (ObjectCreated)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         File Processor Lambda                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Download scan file from S3                                           ││
│  │ 2. Find & load metadata files (file → scanner → global)                 ││
│  │ 3. Detect scanner type from folder name                                 ││
│  │ 4. Process using MultiScannerImportManager                              ││
│  │ 5. Import to Phoenix Security API                                       ││
│  │ 6. Move file to processed/ folder                                       ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Phoenix Security API                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Assets & Vulnerabilities imported with tags                             ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Prerequisites

- AWS CLI configured with appropriate permissions
- AWS SAM CLI installed
- Python 3.9+ installed
- Phoenix Security API credentials

### 2. Deploy with SAM

```bash
# Navigate to deploy directory
cd Utils/Loading_Script_V5/lambda/deploy

# Build the layer
./build_layer.sh

# Deploy with SAM (guided mode)
sam deploy --guided

# Or deploy with parameters
sam deploy \
  --stack-name phoenix-scanner-import \
  --parameter-overrides \
    Environment=prod \
    S3BucketName=my-scanner-bucket \
    PhoenixClientId=YOUR_CLIENT_ID \
    PhoenixClientSecret=YOUR_CLIENT_SECRET \
    PhoenixApiUrl=https://api.appsecphx.io
```

### 3. Upload Configuration

```bash
# Copy and customize the config template
cp ../lambda_config_template.ini lambda_config.ini
# Edit lambda_config.ini as needed (set your Phoenix API URL, etc.)

# Upload to S3
aws s3 cp lambda_config.ini s3://my-scanner-bucket-prod/config/lambda_config.ini
```

### 4. Upload Scan Files

```bash
# Upload a Trivy scan
aws s3 cp trivy_scan.json s3://my-scanner-bucket-prod/scanners/trivy/new/

# Upload a Prowler scan
aws s3 cp prowler_findings.json s3://my-scanner-bucket-prod/scanners/prowler_v3/new/

# Upload with metadata
aws s3 cp scan.json s3://my-scanner-bucket-prod/scanners/grype/new/
aws s3 cp scan_metadata.yaml s3://my-scanner-bucket-prod/scanners/grype/new/
```

## Supported Scanner Folder Names

Use these exact folder names under `scanners/`:

| Category | Folder Names |
|----------|--------------|
| Container | `trivy`, `grype`, `aqua`, `clair`, `harbor`, `docker_bench` |
| Infrastructure | `qualys`, `tenable`, `nexpose`, `openvas`, `nmap` |
| Cloud | `prowler`, `prowler_v3`, `scout_suite`, `checkov`, `kics` |
| Code/SAST | `sonarqube`, `checkmarx`, `fortify`, `semgrep`, `bandit` |
| SCA | `snyk`, `dependency_check`, `npm_audit`, `pip_audit`, `cyclonedx` |
| Web | `burp`, `qualys_webapp`, `acunetix`, `nikto`, `zap` |
| Build | `jfrog_xray`, `blackduck` |
| CSV | `phoenix_csv`, `rapid7_csv` |

See full list of 205+ scanners in the main README.

## Lambda Modes

### Single File Mode (Default)

Triggered automatically by S3 events when files are uploaded to `new/` folders.

```json
{
  "mode": "single",
  "bucket": "my-scanner-bucket-prod",
  "file_key": "scanners/trivy/new/scan.json",
  "config_key": "config/lambda_config.ini"
}
```

### Orchestrator Mode

Scans all `new/` folders and invokes individual Lambdas. Runs on schedule (every 15 min by default).

```json
{
  "mode": "orchestrator",
  "bucket": "my-scanner-bucket-prod",
  "config_key": "config/lambda_config.ini",
  "scanner_filter": ["trivy", "grype"],
  "max_concurrent": 5
}
```

## Metadata/Tag Configuration

### Priority Order (highest to lowest)

1. **File-specific**: `scanners/trivy/new/scan_metadata.yaml`
2. **Scanner-level**: `scanners/trivy/metadata.yaml`
3. **Global**: `metadata/global_tags.yaml`

### Metadata YAML Format

```yaml
custom_data:
  - key: "environment"
    value: "production"
  - key: "team"
    value: "security"

severity_tags:
  critical:
    - key: "priority"
      value: "P1"
  high:
    - key: "priority"
      value: "P2"

asset_type_tags:
  CONTAINER:
    - key: "asset-category"
      value: "container"

compliance_tags:
  - key: "compliance-framework"
    value: "SOC2"
```

## Environment Variables

Set these in Lambda configuration:

| Variable | Required | Description |
|----------|----------|-------------|
| `PHOENIX_CLIENT_ID` | Yes | Phoenix API client ID |
| `PHOENIX_CLIENT_SECRET` | Yes | Phoenix API client secret (PAT) |
| `PHOENIX_API_URL` | No | Override API URL (default: from INI) |
| `S3_BUCKET` | No | Override bucket from event |
| `LOG_LEVEL` | No | DEBUG, INFO, WARNING, ERROR |

## IAM Permissions Required

The Lambda needs:

```yaml
- s3:GetObject (read scan files, config, metadata)
- s3:PutObject (write to processed folder)
- s3:DeleteObject (remove from new folder)
- s3:ListBucket (orchestrator mode)
- lambda:InvokeFunction (orchestrator invoking file processor)
```

## Monitoring

### CloudWatch Logs

- `/aws/lambda/phoenix-file-processor-{env}` - Individual file processing
- `/aws/lambda/phoenix-orchestrator-{env}` - Orchestrator runs

### CloudWatch Metrics

- `Invocations` - Number of files processed
- `Errors` - Failed imports
- `Duration` - Processing time

### Alarms

The SAM template creates an alarm for >5 errors in 5 minutes.

## Troubleshooting

### File not processing

1. Check file is in `new/` folder (not root of scanner folder)
2. Verify scanner folder name matches supported scanners
3. Check CloudWatch logs for errors

### Import failing

1. Verify Phoenix credentials are correct
2. Check API URL is accessible from Lambda VPC
3. Review CloudWatch logs for API error responses

### File not moving to processed

1. Check Lambda has `s3:DeleteObject` permission
2. Verify `processed/` folder path in config

## Local Testing

```bash
# Test the Lambda handler locally
cd Utils/Loading_Script_V5

# Set environment variables
export PHOENIX_CLIENT_ID=your_client_id
export PHOENIX_CLIENT_SECRET=your_client_secret
export PHOENIX_API_URL=https://api.appsecphx.io

# Run with test event (as module)
python -m lambda.phoenix_lambda_handler '{
  "mode": "single",
  "bucket": "test-bucket",
  "file_key": "scanners/trivy/new/test.json"
}'
```

## Files Created

| File | Description |
|------|-------------|
| `lambda/phoenix_lambda_handler.py` | Main Lambda entry point |
| `lambda/lambda_config_template.ini` | Configuration template |
| `lambda/__init__.py` | Package init |
| `lambda/deploy/template.yaml` | SAM deployment template |
| `lambda/deploy/build_layer.sh` | Layer build script |
| `lambda/deploy/README.md` | This file |

## Modifications to Existing Code

Minimal changes to support S3 operations:

| File | Changes |
|------|---------|
| `phoenix_import_refactored.py` | Added `PhoenixConfig.from_s3()` classmethod |
| `phoenix_multi_scanner_import.py` | Added `process_from_s3()`, `load_tag_config_from_s3()`, `merge_tag_configs()` methods |
