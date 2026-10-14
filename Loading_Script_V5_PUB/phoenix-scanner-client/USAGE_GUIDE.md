# Phoenix Scanner Client - Usage Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Configuration](#configuration)
3. [Upload Modes](#upload-modes)
4. [Advanced Features](#advanced-features)
5. [CI/CD Integration](#cicd-integration)
6. [Best Practices](#best-practices)

## Getting Started

### Prerequisites

- Python 3.8+
- Phoenix Scanner Service running (see `../phoenix-scanner-service/`)
- Valid API credentials

### Installation

```bash
# Navigate to client directory
cd phoenix-scanner-client

# Install dependencies
pip install -r requirements.txt

# Configure
cp examples/config.example.yaml config.yaml
nano config.yaml  # Edit with your credentials
```

### Quick Test

```bash
# Test API connection
python -c "from phoenix_client import PhoenixScannerClient; \
  c = PhoenixScannerClient('http://localhost:8000', 'your-key'); \
  print('Status:', c.health_check())"

# Upload test file
python actions/upload_single.py --file test.json --scanner-type auto --verbose
```

## Configuration

### Priority Order

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Defaults** (lowest priority)

### Configuration File

Create `config.yaml`:

```yaml
# Required
api_url: http://localhost:8000
api_key: your-api-key

# Optional - Phoenix Platform
phoenix_client_id: {REDACTED}
phoenix_client_secret: {REDACTED}
phoenix_api_url: https://api.demo.appsecphx.io

# Defaults
default_scanner_type: auto
default_import_type: new
enable_batching: true
fix_data: true
timeout: 3600
verify_ssl: true
```

### Environment Variables

```bash
# Required
export PHOENIX_SCANNER_API_URL=http://localhost:8000
export PHOENIX_SCANNER_API_KEY=your-api-key

# Optional
export PHOENIX_CLIENT_ID=client-123
export PHOENIX_CLIENT_SECRET=secret-456
export PHOENIX_API_URL=https://api.demo.appsecphx.io
```

### Command-Line Override

```bash
python actions/upload_single.py \
  --api-url http://custom-api:8000 \
  --api-key custom-key \
  --file scan.json
```

## Upload Modes

### Mode 1: Single File Upload

**Use Case**: Upload one file at a time

```bash
python actions/upload_single.py \
  --file trivy-scan.json \
  --scanner-type trivy \
  --assessment "My Assessment" \
  --import-type new
```

**Options**:
- `--scanner-type`: Scanner type (auto, trivy, grype, qualys, etc.)
- `--asset-type`: Asset type (CONTAINER, INFRA, WEB, CLOUD, CODE, BUILD)
- `--assessment`: Assessment name (auto-generated if not provided)
- `--import-type`: Import strategy (new, merge, delta)
- `--wait`: Wait for processing to complete
- `--stream-logs`: Stream real-time logs via WebSocket

**When to Use**:
- One-off uploads
- Testing
- Small deployments
- Manual uploads

### Mode 2: Batch Upload

**Use Case**: Upload multiple files with different configurations

Create `batch-config.yaml`:

```yaml
batches:
  - name: "Development Scans"
    scanner_type: trivy
    asset_type: CONTAINER
    import_type: new
    files:
      - scans/dev/frontend.json
      - scans/dev/backend.json
  
  - name: "Production Scans"
    scanner_type: trivy
    asset_type: CONTAINER
    import_type: merge
    files:
      - scans/prod/api.json
      - scans/prod/worker.json
```

Upload:

```bash
python actions/upload_batch.py \
  --batch-config batch-config.yaml \
  --concurrent 5 \
  --wait \
  --report batch-report.html
```

**Options**:
- `--concurrent`: Number of concurrent uploads (default: 3)
- `--delay`: Delay between batches in seconds
- `--wait`: Wait for all jobs to complete
- `--report`: Generate report file (txt, json, or html)

**When to Use**:
- Multiple environments (dev, staging, prod)
- Different scanner types
- Organized upload campaigns
- Scheduled bulk uploads

### Mode 3: Folder Upload

**Use Case**: Upload all files matching a pattern from a folder

```bash
# Upload all JSON files
python actions/upload_folder.py \
  --folder ./scans \
  --pattern "*.json" \
  --scanner-type auto

# Recursive search
python actions/upload_folder.py \
  --folder ./all-scans \
  --pattern "trivy-*.json" \
  --recursive \
  --scanner-type trivy \
  --concurrent 3
```

**Options**:
- `--pattern`: File pattern (default: *.json)
- `--recursive`: Search subdirectories
- `--concurrent`: Number of concurrent uploads

**When to Use**:
- Mass uploads
- Nightly scan uploads
- CI/CD automated scans
- Archive processing

## Advanced Features

### Real-Time Log Streaming

Stream logs via WebSocket for immediate feedback:

```bash
python actions/upload_single.py \
  --file large-scan.json \
  --stream-logs
```

Output:
```
✓ Connected! Streaming logs...
────────────────────────────────────────────────────────
  Loading scan file: large-scan.json
  Detected scanner: trivy
  Parsing 1,523 findings...
◆ Progress: 25.0% - Validating data
◆ Progress: 50.0% - Transforming to Phoenix format
◆ Progress: 75.0% - Uploading to Phoenix API
◆ Progress: 100.0% - Import complete
────────────────────────────────────────────────────────
✓ Job completed successfully!
  Assets: 45
  Vulnerabilities: 1,523
```

### Wait for Completion

Block until job completes (useful in CI/CD):

```bash
python actions/upload_single.py \
  --file scan.json \
  --wait
```

**Exit Codes**:
- `0`: Success
- `1`: Failed
- `130`: Interrupted

### Status Monitoring

Check job status:

```bash
# Single job
python actions/check_status.py --job-id abc123

# Wait for completion
python actions/check_status.py --job-id abc123 --wait

# List all jobs
python actions/check_status.py --list

# Filter by status
python actions/check_status.py --list --status completed
```

### Report Generation

Generate upload reports:

```bash
# Text report
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --report report.txt

# JSON report
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --report report.json

# HTML report
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --report report.html
```

## CI/CD Integration

### GitHub Actions

**.github/workflows/security-scan.yml**:

```yaml
name: Security Scan Upload

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan-and-upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'json'
          output: 'trivy-results.json'
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Phoenix Client
        run: pip install -r phoenix-scanner-client/requirements.txt
      
      - name: Upload to Phoenix
        run: |
          python phoenix-scanner-client/actions/upload_single.py \
            --file trivy-results.json \
            --scanner-type trivy \
            --assessment "${{ github.repository }}-${{ github.run_number }}" \
            --wait \
            --report upload-report.txt
        env:
          PHOENIX_SCANNER_API_URL: ${{ secrets.PHOENIX_SCANNER_API_URL }}
          PHOENIX_SCANNER_API_KEY: ${{ secrets.PHOENIX_SCANNER_API_KEY }}
      
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: phoenix-report
          path: upload-report.txt
```

### Jenkins

**Jenkinsfile**:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'trivy fs --format json --output trivy-results.json .'
            }
        }
        
        stage('Upload to Phoenix') {
            environment {
                PHOENIX_SCANNER_API_URL = credentials('phoenix-api-url')
                PHOENIX_SCANNER_API_KEY = credentials('phoenix-api-key')
            }
            steps {
                sh '''
                    python3 phoenix-scanner-client/actions/upload_single.py \
                        --file trivy-results.json \
                        --scanner-type trivy \
                        --assessment "${JOB_NAME}-${BUILD_NUMBER}" \
                        --wait
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'trivy-results.json', allowEmptyArchive: true
        }
    }
}
```

### Azure DevOps

**azure-pipelines.yml**:

```yaml
trigger:
  - main

variables:
  - group: phoenix-credentials

steps:
  - task: CmdLine@2
    displayName: 'Run Trivy Scan'
    inputs:
      script: |
        trivy fs --format json --output trivy-results.json .
  
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
  
  - script: |
      pip install -r phoenix-scanner-client/requirements.txt
    displayName: 'Install Dependencies'
  
  - script: |
      python phoenix-scanner-client/actions/upload_single.py \
        --file trivy-results.json \
        --scanner-type trivy \
        --assessment "$(Build.DefinitionName)-$(Build.BuildNumber)" \
        --wait
    env:
      PHOENIX_SCANNER_API_URL: $(PHOENIX_SCANNER_API_URL)
      PHOENIX_SCANNER_API_KEY: $(PHOENIX_SCANNER_API_KEY)
    displayName: 'Upload to Phoenix'
```

## Best Practices

### 1. Credential Management

✅ **DO**:
- Use environment variables in CI/CD
- Store secrets in secure vaults
- Rotate API keys regularly
- Use minimal permissions

❌ **DON'T**:
- Commit credentials to Git
- Share API keys in logs
- Use production keys in development

### 2. Error Handling

✅ **DO**:
```bash
# Check exit code
if python actions/upload_single.py --file scan.json --wait; then
    echo "Upload successful"
else
    echo "Upload failed"
    exit 1
fi
```

❌ **DON'T**:
```bash
# Ignore errors
python actions/upload_single.py --file scan.json || true
```

### 3. Performance Optimization

✅ **DO**:
```bash
# Use concurrent uploads
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --concurrent 5

# Don't wait for large files
python actions/upload_single.py --file huge-scan.json
# Check status later
python actions/check_status.py --job-id JOB_ID
```

❌ **DON'T**:
```bash
# Sequential uploads
for file in *.json; do
    python actions/upload_single.py --file "$file" --wait
done
```

### 4. Naming Conventions

✅ **DO**:
```bash
--assessment "$(date +%Y%m%d)-ProductionScan-${BUILD_NUMBER}"
--assessment "Q4-2025-Container-Security-Audit"
```

❌ **DON'T**:
```bash
--assessment "scan"
--assessment "test123"
```

### 5. Monitoring

✅ **DO**:
```bash
# Generate reports
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --report report.html

# Monitor jobs
python actions/check_status.py --list --status failed
```

### 6. Retry Logic

Built-in automatic retries with exponential backoff:
- First failure: Wait 1 second, retry
- Second failure: Wait 2 seconds, retry
- Third failure: Wait 4 seconds, retry
- After 3 attempts: Fail

Configure timeout for slow networks:
```bash
--timeout 7200  # 2 hours
```

### 7. Large File Handling

For files > 100MB:
```bash
# Upload without waiting
python actions/upload_single.py --file huge-scan.json --verbose

# Monitor separately
python actions/check_status.py --job-id JOB_ID --wait
```

## Troubleshooting

### Issue: Connection Refused

**Cause**: API service not running

**Solution**:
```bash
cd ../phoenix-scanner-service
docker-compose up -d
curl http://localhost:8000/api/v1/health
```

### Issue: Authentication Failed

**Cause**: Invalid API key

**Solution**:
```bash
# Check environment variables
echo $PHOENIX_SCANNER_API_KEY

# Test connection
python -c "from phoenix_client import PhoenixScannerClient; \
  c = PhoenixScannerClient('http://localhost:8000', 'your-key'); \
  print(c.health_check())"
```

### Issue: Scanner Not Recognized

**Cause**: Invalid scanner type

**Solution**:
```bash
# Use auto-detection
--scanner-type auto

# Or check valid scanners
cat scanner_list_actual.txt | grep -i "scanner-name"
```

### Issue: Job Stuck

**Cause**: Worker issue or large file

**Solution**:
```bash
# Check worker logs
cd ../phoenix-scanner-service
docker-compose logs worker

# Restart worker if needed
docker-compose restart worker

# Check job status
python actions/check_status.py --job-id JOB_ID
```

## Examples by Use Case

### Use Case 1: Nightly Container Scans

```bash
#!/bin/bash
# nightly-scan.sh

# Scan containers
trivy image myapp:latest --format json > trivy-scan.json

# Upload to Phoenix
python phoenix-scanner-client/actions/upload_single.py \
  --file trivy-scan.json \
  --scanner-type trivy \
  --assessment "$(date +%Y%m%d)-NightlyScan" \
  --import-type merge \
  --wait

# Archive scan
mv trivy-scan.json archives/$(date +%Y%m%d)-scan.json
```

### Use Case 2: Multi-Environment Deployment

```yaml
# environments.yaml
batches:
  - name: "Development"
    scanner_type: trivy
    asset_type: CONTAINER
    import_type: new
    files:
      - dev/frontend.json
      - dev/backend.json
  
  - name: "Staging"
    scanner_type: trivy
    asset_type: CONTAINER
    import_type: merge
    files:
      - staging/frontend.json
      - staging/backend.json
  
  - name: "Production"
    scanner_type: trivy
    asset_type: CONTAINER
    import_type: delta
    files:
      - prod/frontend.json
      - prod/backend.json
```

```bash
python actions/upload_batch.py \
  --batch-config environments.yaml \
  --concurrent 3 \
  --delay 30 \
  --wait \
  --report deployment-report.html
```

### Use Case 3: Archive Processing

```bash
# Process old scans from archive
find ./archive -name "*.json" -mtime +7 | \
  xargs -I {} python phoenix-scanner-client/actions/upload_single.py \
    --file {} \
    --scanner-type auto
```

---

For more information, see [README.md](README.md) or contact the Phoenix Security Team.



