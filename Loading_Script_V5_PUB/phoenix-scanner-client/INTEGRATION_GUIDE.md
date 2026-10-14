# Integration Guide: Phoenix Scanner Client + Service

This guide explains how the Phoenix Scanner Client integrates with the Phoenix Scanner Service and the Phoenix Security Platform.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     CI/CD Pipeline                               │
│  (GitHub Actions / Jenkins / Azure DevOps)                      │
└──────────────┬──────────────────────────────────────────────────┘
               │
               │ 1. Run Scanner (Trivy, Grype, etc.)
               │ 2. Generate Output File (JSON, CSV, XML)
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│              Phoenix Scanner Client                              │
│  - Parse CLI arguments                                          │
│  - Load configuration                                           │
│  - Validate scanner type                                        │
│  - Upload file to API                                           │
└──────────────┬──────────────────────────────────────────────────┘
               │
               │ HTTP/HTTPS (REST API)
               │ WebSocket (Log Streaming)
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│          Phoenix Scanner Service (Docker)                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  FastAPI     │  │    Redis     │  │   Worker     │         │
│  │   (API)      │◄─┤   (Queue)    │─►│  (Celery)    │         │
│  └──────────────┘  └──────────────┘  └──────┬───────┘         │
│         │                                     │                  │
│         │                                     │                  │
│  ┌──────▼─────────────────────────────────────▼──────┐         │
│  │         SQLite/PostgreSQL                          │         │
│  │         (Job Tracking & Status)                    │         │
│  └────────────────────────────────────────────────────┘         │
└─────────────────────────────┬───────────────────────────────────┘
                               │
                               │ Phoenix Security API
                               │ (Import Assets & Vulnerabilities)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                Phoenix Security Platform                         │
│  - Asset Management                                             │
│  - Vulnerability Tracking                                       │
│  - Assessment Management                                        │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Scanner Execution (Your CI/CD)

```bash
# Example: Run Trivy scan
trivy image myapp:latest --format json --output trivy-scan.json
```

### 2. Client Upload

```bash
# Upload to Phoenix Scanner Service
python phoenix-scanner-client/actions/upload_single.py \
  --file trivy-scan.json \
  --scanner-type trivy \
  --assessment "MyApp-Production-$(date +%Y%m%d)"
```

**What happens**:
1. Client reads `trivy-scan.json`
2. Client validates scanner type
3. Client authenticates with API key
4. Client uploads file via HTTP POST to `/api/v1/upload`
5. API returns job ID

### 3. Job Queuing (Scanner Service)

**What happens**:
1. API receives file upload
2. API saves file to temporary storage
3. API creates job record in database
4. API queues task in Redis
5. API returns job ID to client

### 4. Processing (Worker)

**What happens**:
1. Celery worker picks up task from Redis queue
2. Worker loads scanner-specific translator
3. Worker parses scan file
4. Worker validates and transforms data
5. Worker creates temporary Phoenix config
6. Worker calls `phoenix_multi_scanner_enhanced.py`
7. Scanner enhanced script:
   - Authenticates with Phoenix API
   - Batches data intelligently
   - Uploads assets and vulnerabilities
   - Handles errors and retries
8. Worker updates job status in database

### 5. Status Monitoring (Client - Optional)

```bash
# Option 1: Poll status
python actions/check_status.py --job-id abc123 --wait

# Option 2: Stream logs
python actions/check_status.py --job-id abc123 --stream
```

**What happens**:
1. Client polls API `/api/v1/jobs/{job_id}`
2. API returns current status from database
3. Client displays progress
4. When complete, client shows final results

## Configuration Hierarchy

### Client Configuration

```yaml
# config.yaml
api_url: http://localhost:8000        # Scanner Service API
api_key: your-api-key                 # Scanner Service auth

phoenix_client_id: {REDACTED}
phoenix_client_secret: {REDACTED}
phoenix_api_url: https://api.demo.appsecphx.io
```

### Scanner Service Configuration

```ini
# config_multi_scanner.ini (in Scanner Service)
[DEFAULT]
client_id = {REDACTED}
client_secret = {REDACTED}
api_base_url = https://api.demo.appsecphx.io
import_type = new
assessment_name = Default Assessment

[CONTAINER]
scan_type = CONTAINER
asset_type = CONTAINER
```

### Override Cascade

```
Client --api-params--> Scanner Service --config--> Phoenix Platform
```

Example override flow:
```bash
# Client provides specific Phoenix credentials
python actions/upload_single.py \
  --file scan.json \
  --phoenix-client-id prod-client \
  --phoenix-api-url https://api.prod.appsecphx.io

# These override Scanner Service defaults
# Final API call uses client-provided values
```

## Multi-Tenant Support

### Scenario: Multiple Clients

```yaml
# batch-multi-client.yaml
batches:
  - name: "Client A - Production"
    scanner_type: trivy
    phoenix_client_id: {REDACTED}
    phoenix_api_url: https://api.clienta.appsecphx.io
    files:
      - clienta/prod-scan.json
  
  - name: "Client B - Staging"
    scanner_type: grype
    phoenix_client_id: {REDACTED}
    phoenix_api_url: https://api.clientb.appsecphx.io
    files:
      - clientb/staging-scan.json
```

Each batch uses different Phoenix credentials, keeping data isolated.

## Security Considerations

### 1. API Key Management

**Client to Scanner Service**:
```bash
# Use environment variables
export PHOENIX_SCANNER_API_KEY=service-key-abc123

# Or secrets vault
python actions/upload_single.py \
  --api-key $(vault read -field=key secret/phoenix-scanner)
```

**Scanner Service to Phoenix Platform**:
```bash
# Set in Docker Compose
environment:
  - PHOENIX_CLIENT_SECRET=${PHOENIX_CLIENT_SECRET}

# Or mount config
volumes:
  - ./config_multi_scanner.ini:/parent/config_multi_scanner.ini:ro
```

### 2. Network Security

```yaml
# Docker Compose - Scanner Service
services:
  api:
    ports:
      - "8000:8000"  # Expose only to trusted network
    networks:
      - internal
  
  worker:
    networks:
      - internal
      - external  # Needs internet for Phoenix API
```

### 3. SSL/TLS

```python
# Client enforces SSL verification by default
client = PhoenixScannerClient(
    api_url="https://scanner-service.company.com",
    verify_ssl=True  # Default
)
```

## CI/CD Integration Patterns

### Pattern 1: Sequential (Simple)

```yaml
# GitHub Actions
jobs:
  scan-and-upload:
    steps:
      - name: Run scan
        run: trivy image app:latest -f json -o scan.json
      
      - name: Upload to Phoenix
        run: python client/actions/upload_single.py --file scan.json --wait
```

**Pros**: Simple, synchronous
**Cons**: Blocks pipeline

### Pattern 2: Async (Advanced)

```yaml
jobs:
  scan:
    steps:
      - name: Run scan
        run: trivy image app:latest -f json -o scan.json
      
      - name: Upload to Phoenix (async)
        run: python client/actions/upload_single.py --file scan.json
      
      - name: Continue with deployment
        run: kubectl apply -f deployment.yaml
  
  monitor:
    needs: scan
    steps:
      - name: Check upload status
        run: python client/actions/check_status.py --job-id $JOB_ID --wait
```

**Pros**: Non-blocking, faster pipelines
**Cons**: More complex

### Pattern 3: Batch (Multiple Environments)

```yaml
jobs:
  scan-all:
    strategy:
      matrix:
        env: [dev, staging, prod]
    steps:
      - name: Scan ${{ matrix.env }}
        run: trivy image app:${{ matrix.env }} -f json -o scan-${{ matrix.env }}.json
      
      - name: Upload all
        run: python client/actions/upload_batch.py --batch-config batch-${{ matrix.env }}.yaml
```

**Pros**: Parallel scans, organized
**Cons**: Requires batch configs

## Troubleshooting Integration Issues

### Issue: Client can't connect to Scanner Service

**Symptoms**:
```
Error: Connection refused to http://localhost:8000
```

**Solutions**:
```bash
# 1. Check if service is running
docker-compose ps

# 2. Check service logs
docker-compose logs api

# 3. Test connectivity
curl http://localhost:8000/api/v1/health

# 4. Check firewall/network
telnet localhost 8000
```

### Issue: Worker not processing jobs

**Symptoms**:
- Job stuck in "queued" status
- No progress updates

**Solutions**:
```bash
# 1. Check worker status
docker-compose logs worker

# 2. Check Redis connection
docker-compose exec api redis-cli ping

# 3. Restart worker
docker-compose restart worker

# 4. Check worker queue
docker-compose exec api redis-cli llen celery
```

### Issue: Phoenix Platform API errors

**Symptoms**:
```
Job failed: Phoenix API returned 401 Unauthorized
```

**Solutions**:
```bash
# 1. Verify credentials
curl -u client_id:client_secret https://api.demo.appsecphx.io/v1/auth/access_token

# 2. Check client config
cat config_multi_scanner.ini | grep client_id

# 3. Test with curl
curl -X POST https://api.demo.appsecphx.io/v1/import/assets/file/translate \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@scan.json"

# 4. Enable debug mode
docker-compose exec worker tail -f /logs/phoenix_import.log
```

### Issue: Scanner type not recognized

**Symptoms**:
```
Warning: 'my-scanner' not in known scanner list
```

**Solutions**:
```bash
# 1. Check valid scanners
cat scanner_list_actual.txt | grep -i scanner-name

# 2. Use auto-detection
--scanner-type auto

# 3. Check scanner name mapping
grep -i "scanner-name" scanner_field_mappings.yaml
```

## Performance Tuning

### Client Side

```bash
# Concurrent uploads
python actions/upload_batch.py --concurrent 10

# Larger timeout for big files
python actions/upload_single.py --timeout 7200  # 2 hours
```

### Service Side

```yaml
# docker-compose.yml
services:
  worker:
    deploy:
      replicas: 5  # More workers = more concurrency
  
  redis:
    command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

### Network

```yaml
# Use local Docker network for client-service communication
docker-compose.yml:
  services:
    api:
      networks:
        - scanner-net
    
    client:
      networks:
        - scanner-net
      environment:
        - PHOENIX_SCANNER_API_URL=http://api:8000  # Internal DNS
```

## Best Practices

1. **Always use environment variables** for credentials in CI/CD
2. **Enable verbose logging** during initial setup
3. **Monitor worker logs** for Phoenix API issues
4. **Use batch uploads** for multiple files
5. **Add delays** if hitting rate limits
6. **Generate reports** for audit trails
7. **Test in development** before production
8. **Use meaningful assessment names** for tracking
9. **Enable SSL** in production
10. **Rotate API keys** regularly

## Complete Example: GitHub Actions

```yaml
name: Security Scanning Pipeline

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'

jobs:
  container-scan:
    runs-on: ubuntu-latest
    steps:
      # 1. Checkout code
      - uses: actions/checkout@v4
      
      # 2. Build image
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      # 3. Run Trivy scan
      - name: Run Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: json
          output: trivy-scan.json
      
      # 4. Setup Python
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      # 5. Install Phoenix Scanner Client
      - name: Install client
        run: pip install -r phoenix-scanner-client/requirements.txt
      
      # 6. Upload to Phoenix Scanner Service
      - name: Upload scan results
        run: |
          python phoenix-scanner-client/actions/upload_single.py \
            --file trivy-scan.json \
            --scanner-type trivy \
            --asset-type CONTAINER \
            --assessment "${{ github.repository }}-${{ github.sha }}" \
            --import-type merge \
            --wait \
            --stream-logs \
            --report upload-report.html
        env:
          PHOENIX_SCANNER_API_URL: ${{ secrets.PHOENIX_SCANNER_API_URL }}
          PHOENIX_SCANNER_API_KEY: ${{ secrets.PHOENIX_SCANNER_API_KEY }}
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
          PHOENIX_API_URL: ${{ secrets.PHOENIX_API_URL }}
      
      # 7. Upload artifacts
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: phoenix-scan-report
          path: upload-report.html
      
      # 8. Check results
      - name: Fail on upload error
        if: failure()
        run: |
          echo "::error::Phoenix Scanner upload failed"
          cat upload-report.html
          exit 1
```

## Monitoring and Observability

### Client Metrics

```bash
# Generate JSON report for parsing
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --report metrics.json

# Parse metrics
jq '.summary.success_rate' metrics.json
```

### Service Metrics

```bash
# Check API health
curl http://localhost:8000/api/v1/health

# Worker status via Flower
open http://localhost:5555

# Redis queue depth
docker-compose exec redis redis-cli llen celery

# Database jobs
docker-compose exec db sqlite3 /data/phoenix_scanner.db \
  "SELECT status, COUNT(*) FROM jobs GROUP BY status;"
```

---

For more information, see:
- [README.md](README.md) - Client documentation
- [../phoenix-scanner-service/README.md](../phoenix-scanner-service/README.md) - Service documentation
- [USAGE_GUIDE.md](USAGE_GUIDE.md) - Usage examples



