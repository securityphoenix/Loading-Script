# Loading_Script_V5 — Scanner Service Guide

**Version**: 5.0
**Last Updated**: February 2026
**Path**: `Utils/Loading_Script_V5/phoenix-scanner-service/`

---

## Table of Contents

- [Overview](#overview)
- [Quick Start Deployment](#quick-start-deployment)
- [Docker Compose Deployment](#docker-compose-deployment)
- [Manual Deployment](#manual-deployment)
- [API Reference](#api-reference)
- [Queue and Worker Configuration](#queue-and-worker-configuration)
- [Production Hardening](#production-hardening)
- [Monitoring](#monitoring)
- [Related Documents](#related-documents)

---

## Overview

The **phoenix-scanner-service** is a REST API microservice that provides a programmatic interface for submitting scan files. It wraps the CLI import tool in a Docker-based service with:

- **FastAPI** REST API for file upload
- **Redis + Celery** queue for asynchronous processing
- **WebSocket** streaming for real-time logs
- **Flower** dashboard for worker monitoring
- **Multi-worker** scalability

---

## Quick Start Deployment

```bash
cd Utils/Loading_Script_V5/phoenix-scanner-service

# One-command setup (creates .env, builds images, starts services)
./start.sh
```

After startup, access:

| Service | URL |
|---------|-----|
| API | http://localhost:8001/api/v1 |
| API Docs (Swagger) | http://localhost:8001/docs |
| Flower Monitoring | http://localhost:5555 |

---

## Docker Compose Deployment

### Full docker-compose.yml

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    build:
      context: .
      target: api
    ports:
      - "8001:8000"
    environment:
      - API_KEY=${API_KEY:-phoenix-scanner-api-key}
      - SECRET_KEY=${SECRET_KEY:-change-me-in-production}
      - REDIS_URL=redis://redis:6379/0
      - PHOENIX_CLIENT_ID=${PHOENIX_CLIENT_ID}
      - PHOENIX_CLIENT_SECRET=${PHOENIX_CLIENT_SECRET}
      - PHOENIX_API_URL=${PHOENIX_API_URL:-https://api.appsecphx.io}
      - MAX_UPLOAD_SIZE_MB=${MAX_UPLOAD_SIZE_MB:-100}
      - ENABLE_AUTH=${ENABLE_AUTH:-true}
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
      - ./data:/app/data
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  worker:
    build:
      context: .
      target: worker
    deploy:
      replicas: 2
    environment:
      - REDIS_URL=redis://redis:6379/0
      - PHOENIX_CLIENT_ID=${PHOENIX_CLIENT_ID}
      - PHOENIX_CLIENT_SECRET=${PHOENIX_CLIENT_SECRET}
      - PHOENIX_API_URL=${PHOENIX_API_URL:-https://api.appsecphx.io}
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    depends_on:
      redis:
        condition: service_healthy
      api:
        condition: service_healthy

  flower:
    image: mher/flower:2.0
    ports:
      - "5555:5555"
    environment:
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - redis

volumes:
  redis_data:
```

### Environment Variables (.env)

```bash
# Phoenix API credentials (required)
PHOENIX_CLIENT_ID=YOUR_CLIENT_ID
PHOENIX_CLIENT_SECRET=YOUR_CLIENT_SECRET
PHOENIX_API_URL=https://api.appsecphx.io

# Service configuration
API_KEY=your-secure-api-key
SECRET_KEY=your-secret-key-for-jwt
ENABLE_AUTH=true
MAX_UPLOAD_SIZE_MB=100

# Worker configuration
API_WORKERS=4
```

### Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api
docker-compose logs -f worker

# Scale workers
docker-compose up -d --scale worker=5

# Stop all services
docker-compose down

# Rebuild after changes
docker-compose up -d --build
```

---

## Manual Deployment

```bash
cd Utils/Loading_Script_V5/phoenix-scanner-service

# Install dependencies
pip install -r requirements.txt

# Start Redis (must be running)
redis-server &

# Set environment variables
export PHOENIX_CLIENT_ID="YOUR_CLIENT_ID"
export PHOENIX_CLIENT_SECRET="YOUR_CLIENT_SECRET"
export REDIS_URL="redis://localhost:6379/0"

# Start the API server
./start.sh
# Or manually:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# Start Celery worker (separate terminal)
celery -A app.workers.celery_app worker --loglevel=info --concurrency=2
```

---

## API Reference

### POST /api/v1/upload — Submit Scan File

Upload a scanner output file for processing.

**Headers**:
- `X-API-Key: your-api-key` (required if auth enabled)

**Parameters** (multipart form):

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `file` | file | Yes | — | Scanner output file |
| `scanner_type` | string | No | `auto` | Scanner type (auto-detect if omitted) |
| `asset_type` | string | No | from translator | Override asset type |
| `assessment_name` | string | No | auto-generated | Assessment name in Phoenix |
| `import_type` | string | No | `new` | Import mode: new, merge, delta |
| `phoenix_client_id` | string | No | from env | Override client ID |
| `phoenix_client_secret` | string | No | from env | Override client secret |
| `phoenix_api_url` | string | No | from env | Override API URL |
| `enable_batching` | boolean | No | `true` | Enable batch processing |
| `fix_data` | boolean | No | `true` | Auto-fix validation issues |
| `anonymize` | boolean | No | `false` | Anonymize asset data |
| `max_batch_size` | integer | No | 50 | Maximum assets per batch |
| `max_payload_mb` | integer | No | 15 | Maximum payload size (MB) |
| `webhook_url` | string | No | — | URL for status notifications |

**Response** (202 Accepted):

```json
{
  "job_id": "abc123-def456",
  "status": "queued",
  "filename": "trivy-results.json",
  "websocket_url": "ws://localhost:8001/ws/abc123-def456",
  "status_url": "/api/v1/status/abc123-def456"
}
```

**Example**:

```bash
curl -X POST http://localhost:8001/api/v1/upload \
  -H "X-API-Key: your-api-key" \
  -F "file=@trivy-results.json" \
  -F "assessment_name=Container-Scan-Q4" \
  -F "import_type=new"
```

**Python client example**:

```python
import requests

response = requests.post(
    "http://localhost:8001/api/v1/upload",
    headers={"X-API-Key": "your-api-key"},
    files={"file": open("trivy-results.json", "rb")},
    data={
        "assessment_name": "Container-Scan-Q4",
        "import_type": "new"
    }
)
job = response.json()
print(f"Job ID: {job['job_id']}")
```

### GET /api/v1/status/{job_id} — Check Import Status

**Response**:

```json
{
  "job_id": "abc123-def456",
  "status": "completed",
  "filename": "trivy-results.json",
  "scanner_type": "trivy",
  "assets_imported": 23,
  "vulnerabilities_imported": 147,
  "started_at": "2026-02-01T14:30:00Z",
  "completed_at": "2026-02-01T14:30:45Z",
  "error": null
}
```

**Status values**: `queued` → `processing` → `completed` | `failed`

### GET /api/v1/health — Health Check

**Response**:

```json
{
  "status": "healthy",
  "redis": "connected",
  "workers": 2,
  "version": "5.0",
  "uptime_seconds": 3600
}
```

---

## Queue and Worker Configuration

### Worker Scaling

| Workers | Use Case | Throughput |
|---------|----------|------------|
| 1 | Development/testing | ~2 files/min |
| 2 (default) | Small team | ~4 files/min |
| 5 | Medium team | ~10 files/min |
| 10+ | Enterprise/CI/CD | ~20+ files/min |

```bash
# Scale to 5 workers
docker-compose up -d --scale worker=5
```

### Celery Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Concurrency | 2 per worker | Tasks processed simultaneously |
| Max tasks per child | 50 | Worker recycled after N tasks |
| Task timeout | 3600s | Maximum task execution time |
| Result backend | Redis | Where results are stored |

---

## Production Hardening

### Reverse Proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name scanner-service.company.com;

    ssl_certificate /etc/ssl/certs/scanner-service.crt;
    ssl_certificate_key /etc/ssl/private/scanner-service.key;

    client_max_body_size 200M;  # Match MAX_UPLOAD_SIZE_MB

    location / {
        proxy_pass http://localhost:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://localhost:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Security Checklist for Production

- [ ] Set strong `API_KEY` and `SECRET_KEY` values
- [ ] Enable authentication (`ENABLE_AUTH=true`)
- [ ] Deploy behind TLS-terminating reverse proxy
- [ ] Restrict network access to the service
- [ ] Use PostgreSQL instead of SQLite for persistence
- [ ] Set appropriate `MAX_UPLOAD_SIZE_MB`
- [ ] Configure log rotation
- [ ] Monitor Flower dashboard for worker health

---

## Monitoring

### Flower Dashboard

Access at http://localhost:5555 to monitor:
- Active workers and their status
- Task queue length
- Task success/failure rates
- Worker resource usage

### Health Check Endpoint

```bash
# Check service health
curl http://localhost:8001/api/v1/health

# Use in monitoring scripts
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/api/v1/health)
if [ "$STATUS" != "200" ]; then
  echo "Scanner service unhealthy!"
fi
```

---

## Related Documents

- [README](../../README.md) — Primary documentation
- [Quick Start](../../QUICK_START.md) — CLI quick start
- [Configuration Guide](CONFIGURATION_GUIDE.md) — CLI configuration
- [Scanner Translator Guide](../reference/SCANNER_TRANSLATOR_GUIDE.md) — Supported scanners
- Utils Security Guide — Security operations
