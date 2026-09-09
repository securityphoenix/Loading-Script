# Phoenix Scanner Client

A robust, production-ready Python client for uploading scanner results to the Phoenix Scanner Service API. Designed for CI/CD pipelines with support for batch processing, real-time progress tracking, and comprehensive error handling.

## 🎯 Features

- **Multiple Upload Modes**: Single file, batch, or entire folders
- **Scanner Auto-Detection**: Automatically detects scanner type from file content
- **Batch Processing**: Upload multiple files with configurable concurrency
- **Real-Time Progress**: Progress bars and WebSocket log streaming
- **CI/CD Ready**: Pre-built integrations for GitHub Actions, Jenkins, and Azure DevOps
- **Robust Error Handling**: Automatic retries with exponential backoff
- **Comprehensive Reports**: Generate reports in text, JSON, or HTML format
- **Flexible Configuration**: YAML files, environment variables, or command-line arguments

## 📦 Installation

```bash
# Clone the repository
cd phoenix-scanner-client

# Install dependencies
pip install -r requirements.txt

# Copy example config
cp examples/config.example.yaml config.yaml

# Edit config with your credentials
nano config.yaml
```

## ⚙️ Configuration

### Option 1: Configuration File (Recommended)

Create `config.yaml`:

```yaml
api_url: http://localhost:8000
api_key: your-api-key-here
phoenix_client_id: your-phoenix-client-id
phoenix_client_secret: your-phoenix-secret
phoenix_api_url: https://api.demo.appsecphx.io
```

### Option 2: Environment Variables

```bash
export PHOENIX_SCANNER_API_URL=http://localhost:8000
export PHOENIX_SCANNER_API_KEY=your-api-key
export PHOENIX_CLIENT_ID=your-phoenix-client-id
export PHOENIX_CLIENT_SECRET=your-phoenix-secret
export PHOENIX_API_URL=https://api.demo.appsecphx.io
```

### Option 3: Command-Line Arguments

```bash
python actions/upload_single.py \
  --api-url http://localhost:8000 \
  --api-key your-api-key \
  --file scan.json
```

## 🚀 Quick Start

### Upload a Single File

```bash
# Auto-detect scanner type
python actions/upload_single.py --file trivy-scan.json

# Specify scanner type
python actions/upload_single.py \
  --file scan.json \
  --scanner-type trivy \
  --assessment "Q4-2025-Container-Scan"

# Wait for completion with real-time logs
python actions/upload_single.py \
  --file scan.json \
  --wait \
  --stream-logs
```

### Upload Multiple Files (Batch)

Create `batch-config.yaml`:

```yaml
batches:
  - name: "Container Scans"
    scanner_type: trivy
    asset_type: CONTAINER
    files:
      - scans/trivy-frontend.json
      - scans/trivy-backend.json
  
  - name: "Infrastructure Scans"
    scanner_type: qualys
    asset_type: INFRA
    files:
      - scans/qualys-network.csv
```

Upload the batch:

```bash
python actions/upload_batch.py \
  --batch-config batch-config.yaml \
  --concurrent 5 \
  --wait \
  --report batch-report.html
```

### Upload All Files from a Folder

```bash
# Upload all JSON files
python actions/upload_folder.py \
  --folder ./scans \
  --pattern "*.json" \
  --scanner-type auto

# Recursive search
python actions/upload_folder.py \
  --folder ./all-scans \
  --pattern "*.json" \
  --recursive \
  --concurrent 3
```

### Check Job Status

```bash
# Check specific job
python actions/check_status.py --job-id abc123...

# Wait for job completion
python actions/check_status.py --job-id abc123... --wait

# Stream logs
python actions/check_status.py --job-id abc123... --stream

# List all jobs
python actions/check_status.py --list

# Filter by status
python actions/check_status.py --list --status completed
```

## 🔧 Actions Reference

### 1. Upload Single File

**File**: `actions/upload_single.py`

```bash
python actions/upload_single.py \
  --file SCAN_FILE \
  [--scanner-type TYPE] \
  [--assessment NAME] \
  [--import-type new|merge|delta] \
  [--wait] \
  [--stream-logs] \
  [--report OUTPUT_FILE]
```

**Key Options**:
- `--file`: Path to scanner output file (required)
- `--scanner-type`: Scanner type (default: auto)
- `--assessment`: Assessment name (auto-generated if not provided)
- `--import-type`: How to import data (new/merge/delta)
- `--wait`: Wait for job completion
- `--stream-logs`: Stream logs via WebSocket
- `--report`: Generate report file

### 2. Upload Batch

**File**: `actions/upload_batch.py`

```bash
python actions/upload_batch.py \
  --batch-config BATCH_CONFIG.yaml \
  [--concurrent N] \
  [--wait] \
  [--delay SECONDS] \
  [--report OUTPUT_FILE]
```

**Key Options**:
- `--batch-config`: Path to batch configuration file (required)
- `--concurrent`: Number of concurrent uploads (default: 3)
- `--wait`: Wait for all jobs to complete
- `--delay`: Delay between batches in seconds
- `--report`: Generate report file

### 3. Upload Folder

**File**: `actions/upload_folder.py`

```bash
python actions/upload_folder.py \
  --folder FOLDER_PATH \
  [--pattern "*.json"] \
  [--scanner-type TYPE] \
  [--recursive] \
  [--concurrent N]
```

**Key Options**:
- `--folder`: Folder containing scanner files (required)
- `--pattern`: File pattern to match (default: *.json)
- `--scanner-type`: Scanner type (default: auto)
- `--recursive`: Search subdirectories
- `--concurrent`: Number of concurrent uploads

### 4. Check Status

**File**: `actions/check_status.py`

```bash
python actions/check_status.py \
  --job-id JOB_ID \
  [--wait] \
  [--stream]

python actions/check_status.py \
  --list \
  [--status STATUS]
```

**Key Options**:
- `--job-id`: Check specific job
- `--wait`: Wait for job completion
- `--stream`: Stream logs via WebSocket
- `--list`: List all jobs
- `--status`: Filter by status (pending/processing/completed/failed)

## 🔄 CI/CD Integration

### GitHub Actions

Add to `.github/workflows/phoenix-scanner.yml`:

```yaml
- name: Upload to Phoenix Scanner
  run: |
    python phoenix-scanner-client/actions/upload_single.py \
      --file scan-results.json \
      --scanner-type trivy \
      --wait
  env:
    PHOENIX_SCANNER_API_URL: ${{ secrets.PHOENIX_SCANNER_API_URL }}
    PHOENIX_SCANNER_API_KEY: ${{ secrets.PHOENIX_SCANNER_API_KEY }}
```

See [ci/github/phoenix-scanner.yml](ci/github/phoenix-scanner.yml) for complete example.

### Jenkins

```groovy
stage('Upload to Phoenix') {
    steps {
        sh '''
            python3 phoenix-scanner-client/actions/upload_single.py \
                --file scan-results.json \
                --wait
        '''
    }
}
```

See [ci/jenkins/Jenkinsfile](ci/jenkins/Jenkinsfile) for complete example.

### Azure DevOps

```yaml
- script: |
    python phoenix-scanner-client/actions/upload_single.py \
      --file scan-results.json \
      --wait
  env:
    PHOENIX_SCANNER_API_URL: $(PHOENIX_SCANNER_API_URL)
    PHOENIX_SCANNER_API_KEY: $(PHOENIX_SCANNER_API_KEY)
```

See [ci/azure/azure-pipelines.yml](ci/azure/azure-pipelines.yml) for complete example.

## 📊 Supported Scanners

The client supports 200+ scanner types. Some popular ones:

**Container Scanners**:
- `trivy` - Aqua Trivy
- `grype` - Anchore Grype
- `clair` - CoreOS Clair
- `snyk` - Snyk Container

**Infrastructure Scanners**:
- `qualys` - Qualys VMDR
- `nessus` - Tenable Nessus
- `openvas` - OpenVAS

**Cloud Scanners**:
- `prowler` - AWS Prowler
- `scout_suite` - Scout Suite
- `cloudsploit` - CloudSploit

**Code Scanners**:
- `sonarqube` - SonarQube
- `semgrep` - Semgrep
- `checkmarx` - Checkmarx

**Full List**: See [scanner_list_actual.txt](scanner_list_actual.txt)

Use `auto` for automatic detection.

## 🎨 Usage Examples

### Example 1: Simple Upload with Wait

```bash
python actions/upload_single.py \
  --file trivy-scan.json \
  --scanner-type trivy \
  --wait
```

### Example 2: Batch Upload with Custom Assessment

```bash
# Create batch config
cat > my-batch.yaml << EOF
batches:
  - name: "Production Container Scans"
    scanner_type: trivy
    asset_type: CONTAINER
    import_type: merge
    files:
      - prod/frontend-scan.json
      - prod/backend-scan.json
      - prod/database-scan.json
EOF

# Upload
python actions/upload_batch.py \
  --batch-config my-batch.yaml \
  --wait \
  --report prod-scan-report.html
```

### Example 3: Folder Upload with Filtering

```bash
# Upload all Trivy scans from last week
python actions/upload_folder.py \
  --folder ./scans/2025-11 \
  --pattern "trivy-*.json" \
  --scanner-type trivy \
  --concurrent 5 \
  --wait
```

### Example 4: Monitor Job Progress

```bash
# Upload and get job ID
JOB_ID=$(python actions/upload_single.py \
  --file large-scan.json \
  --json | jq -r '.job_id')

# Monitor with live logs
python actions/check_status.py \
  --job-id $JOB_ID \
  --stream
```

## 🐛 Troubleshooting

### Common Issues

**1. Authentication Failed**
```bash
# Check credentials
python -c "from phoenix_client import PhoenixScannerClient; \
  client = PhoenixScannerClient('http://localhost:8000', 'your-key'); \
  print(client.health_check())"
```

**2. Scanner Type Not Recognized**
```bash
# List valid scanner types
cat scanner_list_actual.txt

# Use auto-detection
python actions/upload_single.py --file scan.json --scanner-type auto
```

**3. Connection Refused**
```bash
# Check if API is running
curl http://localhost:8000/api/v1/health

# Check Docker containers
cd ../phoenix-scanner-service
docker-compose ps
```

**4. Job Stuck in Processing**
```bash
# Check job status
python actions/check_status.py --job-id JOB_ID

# Check worker logs
cd ../phoenix-scanner-service
docker-compose logs worker
```

## 📈 Performance Tips

1. **Batch Processing**: Use concurrent uploads for multiple files
   ```bash
   --concurrent 5  # Upload 5 files simultaneously
   ```

2. **Large Files**: Don't wait synchronously, check status later
   ```bash
   # Upload without waiting
   python actions/upload_single.py --file large.json
   
   # Check later
   python actions/check_status.py --job-id JOB_ID
   ```

3. **Network Issues**: Increase timeout for slow connections
   ```bash
   --timeout 7200  # 2 hours
   ```

4. **API Rate Limiting**: Add delays between batches
   ```bash
   --delay 10  # 10 seconds between batches
   ```

## 🔒 Security Best Practices

1. **Never commit credentials** to version control
2. **Use environment variables** in CI/CD pipelines
3. **Rotate API keys** regularly
4. **Use HTTPS** in production
5. **Enable SSL verification** (default)
6. **Restrict API key permissions** to minimum required

## 📚 Project Structure

```
phoenix-scanner-client/
├── actions/              # Action scripts
│   ├── upload_single.py  # Upload single file
│   ├── upload_batch.py   # Upload batch
│   ├── upload_folder.py  # Upload folder
│   └── check_status.py   # Check status
├── utils/                # Utility modules
│   ├── config.py         # Configuration loader
│   └── report.py         # Report generator
├── ci/                   # CI/CD integrations
│   ├── github/           # GitHub Actions
│   ├── jenkins/          # Jenkins
│   └── azure/            # Azure DevOps
├── examples/             # Example configs
│   ├── config.example.yaml
│   └── batch_config.example.yaml
├── phoenix_client.py     # Main client library
├── requirements.txt      # Python dependencies
├── scanner_list_actual.txt  # Supported scanners
└── README.md             # This file
```

## 🤝 Integration with Phoenix Scanner Service

This client is designed to work seamlessly with the Phoenix Scanner Service API:

1. **API Service**: `phoenix-scanner-service/` (sibling directory)
2. **Start Service**:
   ```bash
   cd ../phoenix-scanner-service
   docker-compose up -d
   ```
3. **Verify Health**:
   ```bash
   curl http://localhost:8000/api/v1/health
   ```
4. **Use Client**:
   ```bash
   cd ../phoenix-scanner-client
   python actions/upload_single.py --file scan.json
   ```

## 📝 Exit Codes

- `0`: Success
- `1`: General error or upload failure
- `130`: Interrupted by user (Ctrl+C)

Useful for CI/CD pipeline control flow.

## 🆘 Support

For issues, questions, or feature requests:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review API service logs: `docker-compose logs -f worker`
3. Enable verbose mode: `--verbose`
4. Contact Phoenix Security Team

## 📄 License

Copyright © Phoenix Security Team

## 🚀 Quick Test

```bash
# 1. Start the API service
cd ../phoenix-scanner-service
docker-compose up -d

# 2. Create test config
cd ../phoenix-scanner-client
cat > config.yaml << EOF
api_url: http://localhost:8000
api_key: dev-test-key-12345
EOF

# 3. Upload a test file
python actions/upload_single.py \
  --file ../test-scan.json \
  --scanner-type auto \
  --verbose

# 4. Check status
python actions/check_status.py --list
```

---

**Built with ❤️ for the Phoenix Security Platform**


