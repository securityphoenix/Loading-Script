# User Guide

Complete guide to using the Phoenix Scanner Service.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
5. [Best Practices](#best-practices)
6. [Examples](#examples)

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- Phoenix Security API credentials
- Scanner output files (JSON, CSV, or XML)

### Installation

1. **Navigate to service directory**:
   ```bash
   cd phoenix-scanner-service
   ```

2. **Initialize service**:
   ```bash
   make init
   ```

3. **Configure environment**:
   Edit `.env` file:
   ```bash
   API_KEY=your-secure-api-key-12345
   PHOENIX_CLIENT_SECRET=your-phoenix-secret
   ```

4. **Start service**:
   ```bash
   make build
   make up
   ```

5. **Verify service is running**:
   ```bash
   make health
   ```

   You should see:
   ```json
   {
     "status": "healthy",
     "version": "1.0.0",
     ...
   }
   ```

### First Upload

Let's upload a scanner file:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-secure-api-key-12345" \
  -F "file=@trivy-scan.json" \
  -F "scanner_type=trivy" \
  -F "phoenix_client_id=your-phoenix-client-id" \
  -F "phoenix_client_secret=your-phoenix-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api"
```

Response:
```json
{
  "job_id": "job-abc123def456",
  "status": "queued",
  "message": "File uploaded successfully. Job queued for processing.",
  "created_at": "2025-11-12T10:30:00Z",
  "websocket_url": "ws://localhost:8000/ws/job-abc123def456"
}
```

Save the `job_id` - you'll need it to check status!

## Basic Usage

### Uploading Files

#### Auto-detect Scanner Type

Let the service detect the scanner type automatically:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan-results.json" \
  -F "scanner_type=auto" \
  -F "phoenix_client_id=your-client-id" \
  -F "phoenix_client_secret=your-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api"
```

#### Specify Scanner Type

For faster processing, specify the scanner type:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@grype-scan.json" \
  -F "scanner_type=grype" \
  -F "phoenix_client_id=your-client-id" \
  -F "phoenix_client_secret=your-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api"
```

**Supported Scanner Types**: 
trivy, grype, qualys, tenable, aqua, prowler, sonarqube, checkmarx, burp, snyk, jfrog, blackduck, and 200+ more!

### Checking Job Status

#### Using cURL

```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs/job-abc123def456"
```

Response:
```json
{
  "job_id": "job-abc123def456",
  "status": "processing",
  "progress": 45.5,
  "created_at": "2025-11-12T10:30:00Z",
  "started_at": "2025-11-12T10:30:15Z",
  "filename": "trivy-scan.json",
  "scanner_type": "trivy",
  "recent_logs": [
    "2025-11-12 10:30:15 - INFO - Processing file: trivy-scan.json",
    "2025-11-12 10:30:20 - INFO - Parsed 150 assets with 423 vulnerabilities"
  ]
}
```

#### Using Python

```python
import requests
import time

API_KEY = "your-api-key"
BASE_URL = "http://localhost:8000"

def check_job_status(job_id):
    headers = {"X-API-Key": API_KEY}
    response = requests.get(f"{BASE_URL}/api/v1/jobs/{job_id}", headers=headers)
    return response.json()

def wait_for_completion(job_id, poll_interval=5):
    while True:
        status = check_job_status(job_id)
        print(f"Status: {status['status']} - Progress: {status['progress']}%")
        
        if status['status'] in ['completed', 'failed', 'cancelled']:
            return status
        
        time.sleep(poll_interval)

# Usage
job_id = "job-abc123def456"
result = wait_for_completion(job_id)

if result['status'] == 'completed':
    print(f"✅ Success! Imported {result['assets_imported']} assets")
else:
    print(f"❌ Failed: {result['error_message']}")
```

### Listing Jobs

```bash
# List all jobs
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs"

# Filter by status
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs?status=completed"

# Pagination
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs?page=2&page_size=20"
```

## Advanced Features

### Real-time Log Streaming (WebSocket)

Stream logs in real-time using WebSocket:

```python
import asyncio
import websockets
import json

async def stream_job_logs(job_id):
    uri = f"ws://localhost:8000/ws/{job_id}"
    
    async with websockets.connect(uri) as websocket:
        print(f"Connected to job {job_id}")
        
        async for message in websocket:
            data = json.loads(message)
            
            if data['type'] == 'log':
                level = data['data']['level']
                msg = data['data']['message']
                print(f"[{level}] {msg}")
            
            elif data['type'] == 'progress':
                progress = data['data']['progress']
                step = data['data'].get('current_step', 'Processing')
                print(f"Progress: {progress:.1f}% - {step}")
            
            elif data['type'] == 'complete':
                assets = data['data']['assets_imported']
                vulns = data['data']['vulnerabilities_imported']
                print(f"✅ Completed! Assets: {assets}, Vulnerabilities: {vulns}")
                break
            
            elif data['type'] == 'error':
                error = data['data']['error_message']
                print(f"❌ Error: {error}")
                break
            
            elif data['type'] == 'heartbeat':
                # Just a keep-alive, ignore
                pass

# Run
asyncio.run(stream_job_logs("job-abc123def456"))
```

### Webhook Notifications

Set up a webhook to receive status updates:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "scanner_type=trivy" \
  -F "webhook_url=https://your-app.com/webhook" \
  -F 'webhook_headers={"Authorization": "Bearer your-webhook-token"}'
```

Your webhook endpoint will receive:

```json
{
  "job_id": "job-abc123",
  "status": "completed",
  "filename": "scan.json",
  "scanner_type": "trivy",
  "success": true,
  "timestamp": "2025-11-12T10:32:00Z",
  "assets_imported": 150,
  "vulnerabilities_imported": 423,
  "assessment_name": "TRIVY-scan-20251112_1032"
}
```

### Batch Processing

Process multiple files in a folder:

```bash
#!/bin/bash
API_KEY="your-api-key"
SCANNER_TYPE="trivy"

for file in scans/*.json; do
    echo "Uploading $file..."
    
    curl -X POST "http://localhost:8000/api/v1/upload" \
      -H "X-API-Key: $API_KEY" \
      -F "file=@$file" \
      -F "scanner_type=$SCANNER_TYPE" \
      -F "phoenix_client_id=your-client-id" \
      -F "phoenix_client_secret=your-secret" \
      -F "phoenix_api_url=https://phoenix.example.com/api"
    
    echo ""
done
```

### Custom Assessment Names

Provide a custom assessment name:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "scanner_type=trivy" \
  -F "assessment_name=Q4-2025-Container-Security-Scan" \
  -F "phoenix_client_id=your-client-id" \
  -F "phoenix_client_secret=your-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api"
```

### Import Types

Control how data is imported:

```bash
# New import (default) - creates new assessment
curl ... -F "import_type=new"

# Merge - merges with existing assessment
curl ... -F "import_type=merge"

# Delta - only imports new/changed vulnerabilities
curl ... -F "import_type=delta"
```

### Data Fixing

Enable/disable automatic data fixing:

```bash
# Enable data fixing (default)
curl ... -F "fix_data=true"

# Disable data fixing
curl ... -F "fix_data=false"
```

### Anonymization

Anonymize sensitive data before import:

```bash
curl ... -F "anonymize=true"
```

## Monitoring & Troubleshooting

### Check Service Health

```bash
make health
```

or

```bash
curl http://localhost:8000/api/v1/health | python -m json.tool
```

### View Logs

```bash
# All services
make logs

# API only
make logs-api

# Workers only
make logs-worker

# Follow logs (live)
docker-compose logs -f api worker
```

### Celery Flower Dashboard

Access the Flower monitoring dashboard:

```
http://localhost:5555
```

This shows:
- Active/completed tasks
- Worker status
- Task execution times
- Failures and retries

### Common Issues

#### Job stuck in "pending"

**Problem**: Job not being picked up by workers.

**Solution**:
```bash
# Check worker status
docker-compose ps worker

# Restart workers
docker-compose restart worker

# Check worker logs
make logs-worker
```

#### "Failed to connect to Phoenix API"

**Problem**: Phoenix API credentials incorrect or API unreachable.

**Solution**:
1. Verify credentials in job parameters
2. Check Phoenix API URL is accessible
3. Ensure `PHOENIX_CLIENT_SECRET` is set in `.env`

#### Upload fails with "Payload too large"

**Problem**: File exceeds maximum size.

**Solution**:
```bash
# In .env, increase limit
MAX_UPLOAD_SIZE_MB=1000
```

Then restart:
```bash
docker-compose restart api
```

#### WebSocket connection refused

**Problem**: WebSocket not accessible.

**Solution**:
- Check firewall rules
- Ensure reverse proxy supports WebSocket upgrade
- Verify job exists before connecting

## Best Practices

### 1. Use Specific Scanner Types

Always specify `scanner_type` when possible for faster processing:

```bash
-F "scanner_type=trivy"  # Good ✅
-F "scanner_type=auto"   # Works, but slower
```

### 2. Monitor with WebSockets

For long-running jobs, use WebSocket streaming instead of polling:

```python
# Good ✅ - WebSocket streaming
asyncio.run(stream_job_logs(job_id))

# Less efficient ❌ - Polling
while True:
    check_job_status(job_id)
    time.sleep(5)
```

### 3. Use Webhooks for Integration

For system integration, use webhooks instead of polling:

```bash
-F "webhook_url=https://your-system.com/scanner-webhook"
```

### 4. Batch Upload During Off-Hours

Schedule bulk uploads during off-peak hours to avoid overwhelming the system.

### 5. Clean Up Old Jobs

Periodically clean up old jobs:

```bash
make clean-jobs
```

### 6. Monitor Queue Size

Keep an eye on queue size via health endpoint:

```bash
curl http://localhost:8000/api/v1/health
```

If `pending_jobs` is consistently high, consider scaling workers.

### 7. Use Custom Assessment Names

Use descriptive assessment names for better organization:

```bash
-F "assessment_name=Q4-2025-Production-Container-Scan-TeamA"
```

## Examples

### Complete Python Client

```python
import requests
import asyncio
import websockets
import json
from pathlib import Path

class PhoenixScannerClient:
    def __init__(self, api_url, api_key, phoenix_client_id, phoenix_secret, phoenix_api_url):
        self.api_url = api_url
        self.api_key = api_key
        self.phoenix_client_id = phoenix_client_id
        self.phoenix_secret = phoenix_secret
        self.phoenix_api_url = phoenix_api_url
    
    def upload_file(self, file_path, scanner_type="auto", **kwargs):
        """Upload scanner file"""
        url = f"{self.api_url}/api/v1/upload"
        headers = {"X-API-Key": self.api_key}
        
        with open(file_path, 'rb') as f:
            files = {"file": f}
            data = {
                "scanner_type": scanner_type,
                "phoenix_client_id": self.phoenix_client_id,
                "phoenix_client_secret": self.phoenix_secret,
                "phoenix_api_url": self.phoenix_api_url,
                **kwargs
            }
            
            response = requests.post(url, headers=headers, files=files, data=data)
            response.raise_for_status()
            return response.json()
    
    def get_job_status(self, job_id):
        """Get job status"""
        url = f"{self.api_url}/api/v1/jobs/{job_id}"
        headers = {"X-API-Key": self.api_key}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    
    async def stream_logs(self, job_id, callback):
        """Stream job logs via WebSocket"""
        ws_url = self.api_url.replace('http', 'ws')
        uri = f"{ws_url}/ws/{job_id}"
        
        async with websockets.connect(uri) as websocket:
            async for message in websocket:
                data = json.loads(message)
                should_continue = callback(data)
                if not should_continue:
                    break

# Usage
client = PhoenixScannerClient(
    api_url="http://localhost:8000",
    api_key="your-api-key",
    phoenix_client_id="your-client-id",
    phoenix_secret="your-secret",
    phoenix_api_url="https://phoenix.example.com/api"
)

# Upload file
result = client.upload_file("trivy-scan.json", scanner_type="trivy")
job_id = result['job_id']
print(f"Job ID: {job_id}")

# Stream logs
def log_callback(data):
    if data['type'] == 'log':
        print(f"[{data['data']['level']}] {data['data']['message']}")
    elif data['type'] == 'complete':
        print(f"✅ Completed!")
        return False  # Stop streaming
    return True  # Continue streaming

asyncio.run(client.stream_logs(job_id, log_callback))

# Check final status
final_status = client.get_job_status(job_id)
print(f"Assets imported: {final_status['assets_imported']}")
print(f"Vulnerabilities: {final_status['vulnerabilities_imported']}")
```

### Bash Script for Automated Scanning

```bash
#!/bin/bash
# automated-scan-upload.sh

set -e

API_URL="http://localhost:8000"
API_KEY="your-api-key"
PHOENIX_CLIENT_ID="your-client-id"
PHOENIX_SECRET="your-secret"
PHOENIX_API_URL="https://phoenix.example.com/api"

SCAN_DIR="./scans"
SCANNER_TYPE="trivy"

echo "🚀 Starting automated scan upload..."

for file in "$SCAN_DIR"/*.json; do
    [ -f "$file" ] || continue
    
    filename=$(basename "$file")
    echo "📤 Uploading $filename..."
    
    response=$(curl -s -X POST "$API_URL/api/v1/upload" \
      -H "X-API-Key: $API_KEY" \
      -F "file=@$file" \
      -F "scanner_type=$SCANNER_TYPE" \
      -F "phoenix_client_id=$PHOENIX_CLIENT_ID" \
      -F "phoenix_client_secret=$PHOENIX_SECRET" \
      -F "phoenix_api_url=$PHOENIX_API_URL")
    
    job_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin)['job_id'])")
    
    echo "✅ Job created: $job_id"
    echo "$job_id" >> jobs.txt
done

echo ""
echo "📋 All files uploaded. Job IDs saved to jobs.txt"
echo "Monitor with: tail -f jobs.txt | xargs -I {} curl -H 'X-API-Key: $API_KEY' $API_URL/api/v1/jobs/{}"
```

## Need Help?

- Check [API Reference](API_REFERENCE.md) for complete endpoint documentation
- Review [Architecture Guide](ARCHITECTURE.md) to understand system design
- See [Troubleshooting Guide](../../docs/guides/TROUBLESHOOTING.md) for common issues
- Contact support: user@example.com



