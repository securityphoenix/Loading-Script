# Phoenix Scanner Service - Quick Start

Get up and running in 5 minutes!

## 🚀 Quick Start

### 1. One-Command Setup

```bash
cd phoenix-scanner-service
./start.sh
```

This will:
- Create `.env` from template
- Create necessary directories
- Build Docker images
- Start all services
- Run health checks

### 2. Configure (Important!)

Edit `.env` with your credentials:

```bash
# REQUIRED: Change these!
API_KEY=your-secure-api-key-here
PHOENIX_CLIENT_SECRET=your-phoenix-secret-here
```

### 3. Restart Services

```bash
docker-compose restart
```

### 4. Test the API

```bash
# Check health
curl http://localhost:8000/api/v1/health

# Should return:
# {
#   "status": "healthy",
#   "version": "1.0.0",
#   ...
# }
```

## 📤 Upload Your First File

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@your-scan-file.json" \
  -F "scanner_type=trivy" \
  -F "phoenix_client_id=your-phoenix-client-id" \
  -F "phoenix_client_secret=your-phoenix-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api"
```

Response:
```json
{
  "job_id": "job-abc123",
  "status": "queued",
  "message": "File uploaded successfully...",
  "websocket_url": "ws://localhost:8000/ws/job-abc123"
}
```

## 📊 Check Job Status

```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs/job-abc123"
```

## 🌐 Access Documentation

Open your browser:

- **Interactive API Docs**: http://localhost:8000/docs
- **API Reference**: http://localhost:8000/redoc
- **Flower Dashboard**: http://localhost:5555

## 🛠️ Common Commands

```bash
# View logs
make logs

# Stop services
make down

# Restart services
make restart

# Check status
make status

# Health check
make health
```

## 📚 Next Steps

1. **Read the [User Guide](docs/USER_GUIDE.md)** - Learn all features
2. **Review [API Reference](docs/API_REFERENCE.md)** - Complete API documentation
3. **Check [Configuration](docs/CONFIGURATION.md)** - Customize settings
4. **See [Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment

## ❓ Need Help?

- **Troubleshooting**: Check service logs with `make logs`
- **Issues**: See [User Guide](docs/USER_GUIDE.md) troubleshooting section
- **Support**: user@example.com

## 🎯 Supported Scanners

**Container**: Trivy, Grype, Aqua, Sysdig  
**Cloud**: Prowler, AWS Inspector, Azure Security, Wiz  
**Code**: SonarQube, Checkmarx, Fortify, GitLab Secret Detection  
**Build/SCA**: Snyk, JFrog XRay, BlackDuck, npm audit, Dependency Check  
**Web**: Burp Suite, Qualys WebApp, Contrast  
**Infrastructure**: Qualys VM, Tenable, Microsoft Defender  

...and 200+ more! Use `scanner_type=auto` for auto-detection.

## 🔑 Key Features

✅ **200+ Scanner Support** - Comprehensive coverage  
✅ **Real-time Updates** - WebSocket streaming  
✅ **Queue-based Processing** - No API overload  
✅ **Batch Processing** - Handle large files  
✅ **Auto Data Fixing** - Intelligent validation  
✅ **Webhook Support** - Integration-ready  
✅ **Docker Containerized** - Easy deployment  
✅ **Horizontal Scaling** - Production-ready  

---

**Built for Phoenix Security Platform** 🛡️

