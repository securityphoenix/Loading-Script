# 🚀 START HERE - Phoenix Scanner Solution

## 📍 You Are Here

`Utils/Loading_Script_V5/`

This directory now contains a **complete, production-ready solution** for automated security scanner data ingestion into the Phoenix Security Platform.

## 🎯 What You Have

### Two Integrated Components:

1. **📦 Phoenix Scanner Service** (Container-based API)
   - Location: `phoenix-scanner-service/`
   - Docker-based microservice
   - REST API + WebSocket
   - Background worker processing
   - [→ View Documentation](../../phoenix-scanner-service/README.md)

2. **🖥️ Phoenix Scanner Client** (Python CLI)
   - Location: `phoenix-scanner-client/`
   - Command-line upload tool
   - CI/CD ready
   - Batch processing
   - [→ View Documentation](../../phoenix-scanner-client/README.md)

## ⚡ Quick Start (5 Minutes)

### Step 1: Start the Service

```bash
cd phoenix-scanner-service
docker-compose up -d
```

**Verify it's running:**
```bash
curl http://localhost:8000/api/v1/health
```

### Step 2: Setup the Client

```bash
cd ../phoenix-scanner-client
./setup.sh
```

Follow the prompts to configure your API credentials.

### Step 3: Upload Your First Scan

```bash
# Example: Upload a Trivy scan
python actions/upload_single.py \
  --file your-scan.json \
  --scanner-type trivy \
  --wait
```

**That's it!** 🎉

## 📚 Documentation Index

### Getting Started
- **[README_PHOENIX_SCANNER.md](../scanners/README_PHOENIX_SCANNER.md)** - Master overview of both components
- **[phoenix-scanner-client/QUICKSTART.md](../../phoenix-scanner-client/QUICKSTART.md)** - 5-minute setup guide

### Service Documentation
- [Service README](../../phoenix-scanner-service/README.md) - Complete service guide
- [API Reference](../../phoenix-scanner-service/docs/API_REFERENCE.md) - All endpoints
- [Architecture](../../phoenix-scanner-service/docs/ARCHITECTURE.md) - System design
- [Deployment](../../phoenix-scanner-service/docs/DEPLOYMENT.md) - Production deployment

### Client Documentation
- [Client README](../../phoenix-scanner-client/README.md) - Complete client guide
- [Usage Guide](../../phoenix-scanner-client/USAGE_GUIDE.md) - Detailed examples
- [Integration Guide](../../phoenix-scanner-client/INTEGRATION_GUIDE.md) - How it all works together
- Project Summary - Technical details

### CI/CD Integration
- [GitHub Actions](../../phoenix-scanner-client/ci/github/phoenix-scanner.yml)
- [Jenkins Pipeline](../../phoenix-scanner-client/ci/jenkins/Jenkinsfile)
- [Azure DevOps](../../phoenix-scanner-client/ci/azure/azure-pipelines.yml)
- [Simple Direct Upload Actions](../../simple-upload-actions/README.md) - Option 2 templates for direct CI/CD upload using `phoenix_multi_scanner_enhanced.py` plus pipeline metadata tagging

## 🎯 Common Use Cases

### Use Case 1: Manual Upload

```bash
cd phoenix-scanner-client
python actions/upload_single.py --file scan.json --wait
```

### Use Case 2: Batch Processing

```yaml
# Create batch-config.yaml
batches:
  - name: "My Scans"
    scanner_type: auto
    files:
      - scan1.json
      - scan2.json
```

```bash
python actions/upload_batch.py --batch-config batch-config.yaml
```

### Use Case 3: CI/CD (GitHub Actions)

```yaml
# Add to .github/workflows/security-scan.yml
- name: Upload to Phoenix
  run: |
    python phoenix-scanner-client/actions/upload_single.py \
      --file scan.json --wait
  env:
    PHOENIX_SCANNER_API_URL: ${{ secrets.PHOENIX_SCANNER_API_URL }}
    PHOENIX_SCANNER_API_KEY: ${{ secrets.PHOENIX_SCANNER_API_KEY }}
```

### Use Case 4: Folder Processing

```bash
python actions/upload_folder.py \
  --folder ./scans \
  --pattern "*.json" \
  --recursive
```

## 🛠️ What's Included

### Phoenix Scanner Service Features
✅ REST API for file uploads
✅ WebSocket real-time log streaming
✅ Async task queue (Celery + Redis)
✅ Intelligent batching
✅ Data validation and fixing
✅ Docker Compose deployment
✅ Kubernetes manifests
✅ Health monitoring
✅ Comprehensive logging

### Phoenix Scanner Client Features
✅ Single file upload
✅ Batch upload from config
✅ Folder upload with patterns
✅ Real-time progress tracking
✅ Job status monitoring
✅ WebSocket log streaming
✅ Auto-retry with backoff
✅ Report generation (text/JSON/HTML)
✅ Scanner auto-detection (200+ types)
✅ CI/CD integrations (GitHub/Jenkins/Azure)

## 📊 Supported Scanners (200+)

- **Container**: Trivy, Grype, Clair, Anchore, Snyk, Aqua
- **Infrastructure**: Qualys, Nessus, OpenVAS, Nexpose
- **Cloud**: Prowler, Scout Suite, CloudSploit
- **Code**: SonarQube, Semgrep, Checkmarx, Fortify
- **Web**: Burp Suite, ZAP, Acunetix, Netsparker

→ View Complete List

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────┐
│             CI/CD Pipeline                         │
│     (Your GitHub Actions/Jenkins/Azure)            │
└─────────────┬──────────────────────────────────────┘
              │
              │ 1. Run Scanner (Trivy, Grype, etc.)
              │ 2. Generate Output File
              │
              ▼
┌────────────────────────────────────────────────────┐
│        Phoenix Scanner Client (CLI)                │
│  • Upload files                                    │
│  • Monitor progress                                │
│  • Generate reports                                │
└─────────────┬──────────────────────────────────────┘
              │
              │ HTTP/WebSocket
              │
              ▼
┌────────────────────────────────────────────────────┐
│     Phoenix Scanner Service (Docker)               │
│  ┌─────────┐  ┌──────┐  ┌────────┐               │
│  │   API   │→ │ Redis│→ │ Worker │               │
│  └─────────┘  └──────┘  └────┬───┘               │
└────────────────────────────────┼────────────────────┘
                                 │
                                 │ Phoenix API
                                 ▼
┌────────────────────────────────────────────────────┐
│        Phoenix Security Platform                   │
│  • Asset Management                                │
│  • Vulnerability Tracking                          │
└────────────────────────────────────────────────────┘
```

## 🔧 Configuration

### Service Configuration

Edit `phoenix-scanner-service/.env`:
```bash
API_KEYS=your-api-key
PHOENIX_CLIENT_ID=your-client-id
PHOENIX_CLIENT_SECRET=your-secret
PHOENIX_API_URL=https://api.demo.appsecphx.io
```

### Client Configuration

Edit `phoenix-scanner-client/config.yaml`:
```yaml
api_url: http://localhost:8000
api_key: your-api-key
phoenix_client_id: your-client-id
phoenix_client_secret: your-secret
phoenix_api_url: https://api.demo.appsecphx.io
```

## 🧪 Testing

### Test the Service
```bash
cd phoenix-scanner-service
docker-compose up -d
curl http://localhost:8000/api/v1/health
```

### Test the Client
```bash
cd phoenix-scanner-client
python test_client.py
```

## 🚨 Troubleshooting

### Service Not Starting?
```bash
docker-compose logs api
docker-compose restart api
```

### Client Can't Connect?
```bash
# Check service is running
curl http://localhost:8000/api/v1/health

# Check Docker
docker-compose ps
```

### Need Help?
- [Service Troubleshooting](../../phoenix-scanner-service/docs/ARCHITECTURE.md#troubleshooting)
- [Client Troubleshooting](../../phoenix-scanner-client/README.md#troubleshooting)

## 📖 Next Steps

1. **Read the Overview**: [README_PHOENIX_SCANNER.md](../scanners/README_PHOENIX_SCANNER.md)
2. **Start the Service**: `cd phoenix-scanner-service && docker-compose up -d`
3. **Setup the Client**: `cd phoenix-scanner-client && ./setup.sh`
4. **Upload First Scan**: `python actions/upload_single.py --file scan.json`
5. **Integrate with CI/CD**: Copy examples from `phoenix-scanner-client/ci/`
6. **Direct CI/CD Option (no service/client stack)**: Start from `simple-upload-actions/README.md`

## 📞 Support

- **Service Issues**: See [phoenix-scanner-service/README.md](../../phoenix-scanner-service/README.md)
- **Client Issues**: See [phoenix-scanner-client/README.md](../../phoenix-scanner-client/README.md)
- **Integration**: See [phoenix-scanner-client/INTEGRATION_GUIDE.md](../../phoenix-scanner-client/INTEGRATION_GUIDE.md)

## ✅ Delivery Summary

**What Was Built**:
- Complete containerized scanner service (Docker)
- Production-ready Python CLI client
- 3 CI/CD integrations (GitHub/Jenkins/Azure)
- Comprehensive documentation (7+ guides)
- Example configurations
- Test suites
- Setup automation

**Status**: ✅ **PRODUCTION READY**

**Date**: November 12, 2025

## 🎉 Ready to Go!

You now have everything you need to integrate security scanning into your workflow.

**Start with:**
```bash
cd phoenix-scanner-client
./setup.sh
python test_client.py
python actions/upload_single.py --file your-scan.json
```

---

**Questions?** Check the documentation or run `python actions/upload_single.py --help`

**Built with ❤️ for the Phoenix Security Platform**
