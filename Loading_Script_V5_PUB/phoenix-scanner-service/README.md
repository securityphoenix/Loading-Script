# Phoenix Scanner Service

A containerized REST API service for the Phoenix Security Multi-Scanner Import Tool. This service provides:

- 🚀 **REST API** for file upload and processing
- 📊 **Real-time WebSocket streaming** for logs and status updates
- 🔄 **Queue-based processing** with Redis and Celery
- 📦 **Docker containerization** for easy deployment
- 🔌 **Webhook support** for status notifications
- 🔐 **API key authentication**
- 📈 **Monitoring** via Flower dashboard

## 🎯 Features

- **Multi-Scanner Support**: 206+ scanner types including Trivy, Grype, Qualys, Tenable, Prowler, SonarQube, Checkmarx, Burp, Snyk, Phoenix CSV, Rapid7, and more
- **Asynchronous Processing**: Queue-based background processing prevents API overload
- **Real-time Updates**: WebSocket support for streaming logs and progress
- **Batch Processing**: Intelligent batching for large payloads
- **Data Validation**: Automatic data validation and fixing
- **Webhook Notifications**: Real-time status updates to external systems
- **Scalable Architecture**: Horizontal scaling of worker processes
- **Comprehensive Monitoring**: Built-in health checks and Flower dashboard

## 📋 Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Phoenix Security API credentials

## 🚀 Quick Start

### 1. Initialize Service

```bash
cd phoenix-scanner-service
make init
```

This will create:
- `.env` file from template
- Required directories (`uploads`, `logs`, `data`)

### 2. Configure

Edit `.env` file with your configuration:

```bash
# Security - CHANGE THESE!
API_KEY=your-secure-api-key-here
SECRET_KEY=your-secret-key-here

# Phoenix Platform Credentials - REQUIRED for actual imports
PHOENIX_CLIENT_ID=your-phoenix-client-id
PHOENIX_CLIENT_SECRET=your-phoenix-client-secret
PHOENIX_API_URL=https://api.demo.appsecphx.io
```

**Important**: All three Phoenix credentials (`PHOENIX_CLIENT_ID`, `PHOENIX_CLIENT_SECRET`, `PHOENIX_API_URL`) are required for the service to import data to Phoenix Security Platform. These can also be provided per-request via the upload API.

### 3. Start Service

```bash
make build
make up
```

Or use the start script:

```bash
./start.sh
```

### 4. Verify Service

```bash
make health
```

Visit:
- **API Documentation**: http://localhost:8000/docs
- **Flower Monitoring**: http://localhost:5555

## 📚 Documentation

- [API Reference](docs/API_REFERENCE.md) - Complete API endpoint documentation
- [User Guide](docs/USER_GUIDE.md) - Step-by-step usage instructions
- [Configuration Integration](docs/CONFIGURATION_INTEGRATION.md) - How API integrates with config_multi_scanner.ini
- [Configuration Quick Reference](CONFIGURATION_QUICK_REFERENCE.md) - Quick config cheat sheet
- [Architecture](docs/ARCHITECTURE.md) - System architecture and design
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment instructions
- [Configuration Guide](docs/CONFIGURATION.md) - All configuration options

## 🔧 Usage

### Upload a Scanner File

Using cURL:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan-results.json" \
  -F "scanner_type=trivy" \
  -F "phoenix_client_id=your-client-id" \
  -F "phoenix_client_secret=your-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api"
```

Using Python:

```python
import requests

url = "http://localhost:8000/api/v1/upload"
headers = {"X-API-Key": "your-api-key"}

files = {"file": open("scan-results.json", "rb")}
data = {
    "scanner_type": "trivy",
    "phoenix_client_id": "your-client-id",
    "phoenix_client_secret": "your-secret",
    "phoenix_api_url": "https://phoenix.example.com/api"
}

response = requests.post(url, headers=headers, files=files, data=data)
job = response.json()
print(f"Job ID: {job['job_id']}")
print(f"WebSocket: {job['websocket_url']}")
```

### Check Job Status

```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs/{job_id}"
```

### Stream Real-time Logs (WebSocket)

Using Python with `websockets`:

```python
import asyncio
import websockets
import json

async def stream_logs(job_id):
    uri = f"ws://localhost:8000/ws/{job_id}"
    
    async with websockets.connect(uri) as websocket:
        async for message in websocket:
            data = json.loads(message)
            
            if data['type'] == 'log':
                print(f"[{data['data']['level']}] {data['data']['message']}")
            elif data['type'] == 'progress':
                print(f"Progress: {data['data']['progress']:.1f}%")
            elif data['type'] == 'complete':
                print(f"✅ Completed! Assets: {data['data']['assets_imported']}")
                break
            elif data['type'] == 'error':
                print(f"❌ Error: {data['data']['error_message']}")
                break

asyncio.run(stream_logs("job-abc123"))
```

### Using Webhooks

Provide a webhook URL when uploading:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "scanner_type=trivy" \
  -F "webhook_url=https://your-app.com/webhook"
```

Webhook payload format:

```json
{
  "job_id": "job-abc123",
  "status": "completed",
  "filename": "scan.json",
  "scanner_type": "trivy",
  "success": true,
  "timestamp": "2025-11-12T10:30:00Z",
  "assets_imported": 150,
  "vulnerabilities_imported": 423,
  "assessment_name": "TRIVY-scan-20251112_1030"
}
```

## 🔍 Monitoring

### View Logs

```bash
# All services
make logs

# Specific service
make logs-api
make logs-worker
```

### Check Service Status

```bash
make status
```

### Flower Dashboard

Access Celery task monitoring at http://localhost:5555

## 🛠️ Management Commands

```bash
make help              # Show all available commands
make build             # Build Docker images
make up                # Start services
make down              # Stop services
make restart           # Restart services
make logs              # View logs
make health            # Check health
make clean             # Remove all data
make clean-jobs        # Clean old completed jobs
make test              # Run tests
make shell-api         # Open shell in API container
make shell-worker      # Open shell in worker container
```

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/upload` | Upload scanner file |
| `GET` | `/api/v1/jobs` | List all jobs |
| `GET` | `/api/v1/jobs/{job_id}` | Get job status |
| `DELETE` | `/api/v1/jobs/{job_id}` | Cancel job |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/ping` | Simple ping |
| `WS` | `/ws/{job_id}` | WebSocket log stream |

## 🔐 Security

### Authentication

The API uses API key authentication via the `X-API-Key` header.

To disable authentication (not recommended for production):

```bash
# In .env
ENABLE_AUTH=false
```

### HTTPS/TLS

For production, use a reverse proxy (nginx, traefik) with TLS:

```yaml
# Example nginx config
server {
    listen 443 ssl;
    server_name scanner-api.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 🐳 Production Deployment

### Using PostgreSQL

Uncomment PostgreSQL service in `docker-compose.yml` and update:

```yaml
# In docker-compose.yml
environment:
  - DATABASE_URL=postgresql://phoenix:phoenix_secure_password@postgres:5432/phoenix_scanner
```

### Scaling Workers

```bash
docker-compose up -d --scale worker=5
```

### Environment Variables

**Required Phoenix Platform Credentials:**

```bash
PHOENIX_CLIENT_ID=your-client-id          # Phoenix API client ID
PHOENIX_CLIENT_SECRET=your-client-secret  # Phoenix API client secret
PHOENIX_API_URL=https://api.demo.appsecphx.io  # Phoenix API base URL
```

**Required API Security:**

```bash
API_KEY=your-secure-api-key     # API authentication key(s)
SECRET_KEY=your-secret-key      # Session secret key
```

**Optional Settings:**

```bash
LOG_LEVEL=INFO                  # Logging level (DEBUG, INFO, WARNING, ERROR)
MAX_CONCURRENT_JOBS=5           # Maximum concurrent job processing
JOB_TIMEOUT=3600                # Job timeout in seconds
```

See [Configuration Guide](docs/CONFIGURATION.md) and [ENV_VARIABLES.md](docs/ENV_VARIABLES.md) for all available options.

## 🧪 Testing

```bash
make test              # Run all tests
make test-cov          # Run with coverage
```

## 📝 Supported Scanners

**Phoenix & Rapid7 Scanners** (NEW in v1.1.0):
- Phoenix CSV (Native) - `phoenix_csv`, `phoenix_csv_infra`, `phoenix_csv_cloud`, `phoenix_csv_web`, `phoenix_csv_software`
- Rapid7 CSV Export - `rapid7_csv`

**Container Scanners**: Trivy, Grype, Aqua, Sysdig, Trivy Operator

**Build/SCA Scanners**: npm audit, pip-audit, CycloneDX, Dependency Check, Snyk, JFrog XRay, BlackDuck, ORT, Veracode SCA

**Cloud Scanners**: AWS Prowler (v2-v5), AWS Inspector, Azure Security Center, Wiz, Scout Suite

**Code/Secret Scanners**: SonarQube, GitLab Secret Detection, GitHub Secret Scanning, TruffleHog, Checkmarx, Fortify, SARIF

**Web Scanners**: Burp Suite, Contrast, TestSSL, MicroFocus WebInspect, HackerOne, BugCrowd

**Infrastructure Scanners**: Qualys, Tenable, Kubeaudit, Microsoft Defender

...and 206+ total scanners via YAML configuration!

## 🆘 Troubleshooting

### Service won't start

```bash
# Check logs
docker-compose logs

# Reset everything
make clean
make build
make up
```

### Redis connection errors

```bash
# Check Redis is running
docker-compose ps redis

# Restart Redis
docker-compose restart redis
```

### Worker not processing jobs

```bash
# Check worker logs
make logs-worker

# Restart workers
docker-compose restart worker
```

### Database errors

```bash
# Reset database
make db-reset
```

## 🤝 Support

For issues and questions:
- Check [User Guide](docs/USER_GUIDE.md)
- Review [Troubleshooting Guide](../docs/guides/TROUBLESHOOTING.md)
- Contact: user@example.com

## 📄 License

[Your License Here]

## 🔄 Version

Current Version: 1.1.0

### What's New in v1.1.0
- ✨ Added Phoenix Native CSV support (5 scanner types)
- ✨ Added Rapid7 CSV export support
- 📊 Total supported scanners: 206+ (was 200+)
- 🔧 Enhanced API schema with new scanner types
- 📚 Updated documentation with CSV examples

See [CHANGELOG.md](CHANGELOG.md) for full release notes.

## 🏗️ Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ HTTP/WS
       ▼
┌─────────────┐      ┌─────────────┐
│  API Server │─────▶│    Redis    │
│  (FastAPI)  │      │   (Queue)   │
└─────────────┘      └──────┬──────┘
       │                    │
       │                    │
       ▼                    ▼
┌─────────────┐      ┌─────────────┐
│  Database   │      │   Workers   │
│  (SQLite/   │◀─────│  (Celery)   │
│  Postgres)  │      └─────────────┘
└─────────────┘              │
                             │
                             ▼
                      ┌─────────────┐
                      │   Phoenix   │
                      │  Security   │
                      │     API     │
                      └─────────────┘
```

See [Architecture Guide](docs/ARCHITECTURE.md) for details.

