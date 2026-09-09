# Phoenix Scanner - Complete Solution

A comprehensive, production-ready solution for automated security scanner data ingestion into the Phoenix Security Platform.

## 📦 What's Included

This directory contains two integrated components:

### 1. **Phoenix Scanner Service** 🐳
**Location**: `phoenix-scanner-service/`

A containerized API service that processes and imports scanner results.

**Features**:
- REST API for file uploads
- Asynchronous task queue (Celery + Redis)
- WebSocket real-time log streaming
- Batch processing and intelligent data fixing
- Docker-based deployment
- Supports 200+ security scanners

[→ View Service Documentation](../../phoenix-scanner-service/README.md)

### 2. **Phoenix Scanner Client** 🖥️
**Location**: `phoenix-scanner-client/`

A robust Python CLI client for uploading scanner results to the service.

**Features**:
- Single file, batch, and folder upload modes
- Real-time progress tracking
- CI/CD integration (GitHub Actions, Jenkins, Azure DevOps)
- Comprehensive error handling with retry logic
- Multiple report formats (text, JSON, HTML)

[→ View Client Documentation](../../phoenix-scanner-client/README.md)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CI/CD Pipeline                               │
│            (GitHub Actions / Jenkins / Azure)                    │
└──────────────┬──────────────────────────────────────────────────┘
               │
               │ 1. Run Security Scanner (Trivy, Grype, Qualys, etc.)
               │ 2. Generate Output File
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│              Phoenix Scanner Client (CLI)                        │
│  • Parse arguments                                              │
│  • Validate scanner type                                        │
│  • Upload file(s) to API                                        │
│  • Monitor progress                                             │
└──────────────┬──────────────────────────────────────────────────┘
               │
               │ HTTP/WebSocket
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│          Phoenix Scanner Service (Docker Containers)             │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  FastAPI     │  │    Redis     │  │   Worker     │         │
│  │   (API)      │◄─┤   (Queue)    │─►│  (Celery)    │         │
│  └──────────────┘  └──────────────┘  └──────┬───────┘         │
│                                               │                  │
│                                               │ Calls            │
│                                               ▼                  │
│                                ┌─────────────────────┐          │
│                                │phoenix_multi_scanner│          │
│                                │    _enhanced.py     │          │
│                                └──────────┬──────────┘          │
└───────────────────────────────────────────┼──────────────────────┘
                                            │
                                            │ Phoenix API
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                Phoenix Security Platform                         │
│  • Asset Inventory                                              │
│  • Vulnerability Management                                     │
│  • Assessment Tracking                                          │
│  • Risk Analysis                                                │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Step 1: Start the Service

```bash
cd phoenix-scanner-service
docker-compose up -d
```

Verify:
```bash
curl http://localhost:8000/api/v1/health
```

### Step 2: Setup the Client

```bash
cd ../phoenix-scanner-client
pip install -r requirements.txt
./setup.sh
```

### Step 3: Upload Your First Scan

```bash
python actions/upload_single.py \
  --file your-scan.json \
  --scanner-type auto \
  --wait
```

## 📚 Documentation

### Service Documentation
- [Service README](../../phoenix-scanner-service/README.md) - Complete service documentation
- [API Reference](../../phoenix-scanner-service/docs/API_REFERENCE.md) - API endpoints
- [Architecture](../../phoenix-scanner-service/docs/ARCHITECTURE.md) - System design
- [Deployment Guide](../../phoenix-scanner-service/docs/DEPLOYMENT.md) - Deployment options

### Client Documentation
- [Client README](../../phoenix-scanner-client/README.md) - Complete client documentation
- [Usage Guide](../../phoenix-scanner-client/USAGE_GUIDE.md) - Detailed examples
- [Quick Start](../../phoenix-scanner-client/QUICKSTART.md) - 5-minute setup
- [Integration Guide](../../phoenix-scanner-client/INTEGRATION_GUIDE.md) - Service integration

## 🎯 Common Use Cases

### Use Case 1: One-Off Scan Upload

```bash
# Run scanner
trivy image myapp:latest --format json --output scan.json

# Upload to Phoenix
cd phoenix-scanner-client
python actions/upload_single.py --file scan.json --wait
```

### Use Case 2: Nightly Batch Scans

```yaml
# batch-nightly.yaml
batches:
  - name: "Container Scans"
    scanner_type: trivy
    files:
      - scans/frontend.json
      - scans/backend.json
  
  - name: "Infrastructure Scans"
    scanner_type: qualys
    files:
      - scans/network.csv
```

```bash
# Upload batch
python actions/upload_batch.py \
  --batch-config batch-nightly.yaml \
  --wait \
  --report nightly-report.html
```

### Use Case 3: CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy
        run: trivy fs --format json --output scan.json .
      
      - name: Upload to Phoenix
        run: |
          pip install -r phoenix-scanner-client/requirements.txt
          python phoenix-scanner-client/actions/upload_single.py \
            --file scan.json \
            --wait
        env:
          PHOENIX_SCANNER_API_URL: ${{ secrets.PHOENIX_SCANNER_API_URL }}
          PHOENIX_SCANNER_API_KEY: ${{ secrets.PHOENIX_SCANNER_API_KEY }}
```

### Use Case 4: Folder Processing

```bash
# Upload all JSON files from a folder
python actions/upload_folder.py \
  --folder ./archive/2025-11 \
  --pattern "*.json" \
  --recursive \
  --concurrent 5
```

## 🔧 Configuration

### Service Configuration

Edit `phoenix-scanner-service/.env`:

```bash
# API Settings
API_KEYS=your-api-key-1,your-api-key-2

# Phoenix Platform Credentials
PHOENIX_CLIENT_ID=your-client-id
PHOENIX_CLIENT_SECRET=your-client-secret
PHOENIX_API_URL=https://api.demo.appsecphx.io

# Worker Settings
CELERY_WORKERS=4
```

### Client Configuration

Edit `phoenix-scanner-client/config.yaml`:

```yaml
api_url: http://localhost:8000
api_key: your-api-key
phoenix_client_id: your-client-id
phoenix_client_secret: your-client-secret
phoenix_api_url: https://api.demo.appsecphx.io
```

## 🐳 Docker Deployment

### Development

```bash
cd phoenix-scanner-service
docker-compose up -d
docker-compose logs -f
```

### Production

```bash
cd phoenix-scanner-service
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Kubernetes

```bash
cd phoenix-scanner-service
kubectl apply -f k8s/
```

[→ View Deployment Guide](../../phoenix-scanner-service/docs/DEPLOYMENT.md)

## 📊 Supported Scanners (200+)

**Container Security**:
- Trivy, Grype, Clair, Anchore, Snyk, Aqua

**Infrastructure**:
- Qualys, Nessus, OpenVAS, Nexpose

**Cloud Security**:
- Prowler, Scout Suite, CloudSploit

**Code Analysis**:
- SonarQube, Semgrep, Checkmarx, Fortify

**Web Application**:
- Burp Suite, ZAP, Acunetix, Netsparker

[→ View Complete Scanner List](../../phoenix-scanner-client/scanner_list_actual.txt)

## 🔒 Security

### API Authentication

- API key-based authentication for service access
- Phoenix Platform credentials for data import
- Configurable SSL/TLS verification
- No hardcoded credentials

### Best Practices

1. **Use environment variables** for credentials
2. **Rotate API keys** regularly
3. **Enable SSL/TLS** in production
4. **Restrict API access** to trusted networks
5. **Monitor logs** for suspicious activity

## 🧪 Testing

### Test the Service

```bash
cd phoenix-scanner-service
docker-compose up -d

# Check health
curl http://localhost:8000/api/v1/health
```

### Test the Client

```bash
cd phoenix-scanner-client
python test_client.py
```

### End-to-End Test

```bash
# 1. Start service
cd phoenix-scanner-service
docker-compose up -d

# 2. Upload test file
cd ../phoenix-scanner-client
python actions/upload_single.py \
  --file ../tests/sample-scan.json \
  --scanner-type auto \
  --verbose

# 3. Check status
python actions/check_status.py --list
```

## 📈 Monitoring

### Service Monitoring

```bash
# API health
curl http://localhost:8000/api/v1/health

# Worker dashboard (Flower)
open http://localhost:5555

# Logs
docker-compose logs -f worker
```

### Client Monitoring

```bash
# List recent jobs
python actions/check_status.py --list

# Check specific job
python actions/check_status.py --job-id abc123 --wait

# Stream logs
python actions/check_status.py --job-id abc123 --stream
```

## 🛠️ Troubleshooting

### Service Issues

**Problem**: Container won't start
```bash
docker-compose logs api
docker-compose restart api
```

**Problem**: Worker not processing
```bash
docker-compose logs worker
docker-compose restart worker
```

**Problem**: Redis connection issues
```bash
docker-compose exec redis redis-cli ping
```

### Client Issues

**Problem**: Connection refused
```bash
# Check if service is running
curl http://localhost:8000/api/v1/health

# Check Docker containers
docker-compose ps
```

**Problem**: Authentication failed
```bash
# Verify API key
cat config.yaml | grep api_key

# Test connection
python test_client.py
```

**Problem**: Scanner not recognized
```bash
# Use auto-detection
--scanner-type auto

# Check valid scanners
cat scanner_list_actual.txt | grep -i "scanner-name"
```

## 📖 Additional Resources

### Phoenix Scanner Service
- [README](../../phoenix-scanner-service/README.md)
- [API Reference](../../phoenix-scanner-service/docs/API_REFERENCE.md)
- [Architecture](../../phoenix-scanner-service/docs/ARCHITECTURE.md)
- [Deployment Guide](../../phoenix-scanner-service/docs/DEPLOYMENT.md)
- [Configuration Guide](../../phoenix-scanner-service/docs/CONFIGURATION.md)

### Phoenix Scanner Client
- [README](../../phoenix-scanner-client/README.md)
- [Usage Guide](../../phoenix-scanner-client/USAGE_GUIDE.md)
- [Quick Start](../../phoenix-scanner-client/QUICKSTART.md)
- [Integration Guide](../../phoenix-scanner-client/INTEGRATION_GUIDE.md)
- Project Summary

### CI/CD Examples
- [GitHub Actions](../../phoenix-scanner-client/ci/github/phoenix-scanner.yml)
- [Jenkins](../../phoenix-scanner-client/ci/jenkins/Jenkinsfile)
- [Azure DevOps](../../phoenix-scanner-client/ci/azure/azure-pipelines.yml)

## 🤝 Contributing

Both projects are production-ready and fully documented. For feature requests or issues:

1. Review the documentation
2. Check troubleshooting guides
3. Enable verbose logging
4. Contact the Phoenix Security Team

## 📄 License

Copyright © Phoenix Security Team

## ✨ Features at a Glance

| Feature | Service | Client |
|---------|---------|--------|
| REST API | ✅ | ✅ (Consumer) |
| WebSocket | ✅ | ✅ (Consumer) |
| Batch Processing | ✅ | ✅ |
| Async Task Queue | ✅ | - |
| Progress Tracking | ✅ | ✅ |
| Error Recovery | ✅ | ✅ |
| Docker Support | ✅ | Optional |
| CI/CD Examples | ✅ | ✅ |
| Comprehensive Docs | ✅ | ✅ |
| 200+ Scanners | ✅ | ✅ |
| Multi-tenant | ✅ | ✅ |
| SSL/TLS | ✅ | ✅ |

## 🎉 Getting Help

- **Service**: See `phoenix-scanner-service/README.md`
- **Client**: See `phoenix-scanner-client/README.md`
- **Integration**: See `phoenix-scanner-client/INTEGRATION_GUIDE.md`
- **Quick Start**: Run `./setup.sh` in client directory

---

**Version**: 1.0.0  
**Status**: Production Ready ✅  
**Last Updated**: November 12, 2025

**Built with ❤️ for the Phoenix Security Platform**




