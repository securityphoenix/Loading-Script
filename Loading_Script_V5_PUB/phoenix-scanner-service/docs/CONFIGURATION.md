# Configuration Guide

Complete configuration reference for Phoenix Scanner Service.

## Configuration Methods

Configuration can be provided via:

1. **Environment Variables** (recommended for production)
2. **.env File** (recommended for development)
3. **Default Values** (built into application)

Priority order: Environment Variables > .env File > Defaults

## Core Configuration

### API Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `API_HOST` | string | `0.0.0.0` | API bind address |
| `API_PORT` | integer | `8000` | API port |
| `API_WORKERS` | integer | `4` | Number of Uvicorn workers |
| `API_TITLE` | string | `Phoenix Scanner Service API` | API title |
| `API_VERSION` | string | `1.0.0` | API version |

**Example**:
```bash
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
```

### Security Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `API_KEY` | string | `changeme-insecure-key` | API key for authentication |
| `SECRET_KEY` | string | `changeme-secret-key-for-jwt` | Secret key for JWT/sessions |
| `ENABLE_AUTH` | boolean | `true` | Enable/disable authentication |

**⚠️ IMPORTANT**: Change `API_KEY` and `SECRET_KEY` in production!

**Example**:
```bash
API_KEY=your-secure-random-api-key-min-32-chars
SECRET_KEY=your-secret-key-for-jwt-signing-min-32-chars
ENABLE_AUTH=true
```

**Generating Secure Keys**:
```bash
# Linux/Mac
openssl rand -hex 32

# Python
python -c "import secrets; print(secrets.token_hex(32))"
```

### Redis Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REDIS_HOST` | string | `redis` | Redis hostname |
| `REDIS_PORT` | integer | `6379` | Redis port |
| `REDIS_DB` | integer | `0` | Redis database number |
| `REDIS_PASSWORD` | string | `` | Redis password (optional) |

**Example**:
```bash
# Development (Docker Compose)
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# Production (with password)
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=your-redis-password
```

**Derived Variables** (auto-generated):
- `REDIS_URL`: `redis://[:password@]host:port/db`
- `CELERY_BROKER_URL`: Same as REDIS_URL
- `CELERY_RESULT_BACKEND`: Same as REDIS_URL

### Database Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | `sqlite:///./jobs.db` | Database connection string |

**SQLite** (development, single instance):
```bash
DATABASE_URL=sqlite:///./jobs.db
```

**PostgreSQL** (production, recommended):
```bash
DATABASE_URL=postgresql://username:password@host:5432/database
```

**Examples**:
```bash
# Local PostgreSQL
DATABASE_URL=postgresql://phoenix:phoenix123@localhost:5432/phoenix_scanner

# Cloud PostgreSQL (AWS RDS)
DATABASE_URL=postgresql://admin:user@example.com:5432/phoenix

# PostgreSQL with SSL
DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require
```

### File Storage Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_UPLOAD_SIZE_MB` | integer | `500` | Maximum upload file size (MB) |
| `UPLOAD_DIR` | string | `./uploads` | Directory for uploaded files |
| `LOG_DIR` | string | `./logs` | Directory for job logs |
| `ALLOWED_EXTENSIONS` | list | `[.json, .csv, .xml, .zip, .gz]` | Allowed file extensions |

**Example**:
```bash
MAX_UPLOAD_SIZE_MB=1000
UPLOAD_DIR=/data/uploads
LOG_DIR=/data/logs
```

**Storage Recommendations**:
- Development: Local filesystem
- Production: Shared NFS/S3/MinIO

### Worker Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_CONCURRENT_JOBS` | integer | `5` | Max concurrent jobs per worker |
| `JOB_TIMEOUT` | integer | `3600` | Job timeout in seconds (1 hour) |
| `CLEANUP_AFTER_DAYS` | integer | `7` | Days before cleaning old jobs |

**Example**:
```bash
MAX_CONCURRENT_JOBS=10
JOB_TIMEOUT=7200  # 2 hours
CLEANUP_AFTER_DAYS=30
```

**Tuning Guidelines**:
- `MAX_CONCURRENT_JOBS`: Based on available memory (est. 500MB per job)
- `JOB_TIMEOUT`: Set based on largest expected file size
- Increase timeout for files > 100MB

### Phoenix Scanner Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PHOENIX_CONFIG_FILE` | string | `../config_multi_scanner.ini` | Default Phoenix config file |
| `PHOENIX_CLIENT_SECRET` | string | `` | Default Phoenix API secret |
| `ENABLE_BATCHING` | boolean | `true` | Enable batching by default |
| `FIX_DATA` | boolean | `true` | Enable data fixing by default |
| `MAX_BATCH_SIZE` | integer | `500` | Default max batch size |
| `MAX_PAYLOAD_MB` | float | `25.0` | Default max payload size (MB) |

**Example**:
```bash
PHOENIX_CONFIG_FILE=/config/phoenix.ini
PHOENIX_CLIENT_SECRET=your-phoenix-secret
ENABLE_BATCHING=true
FIX_DATA=true
MAX_BATCH_SIZE=500
MAX_PAYLOAD_MB=25.0
```

**Note**: These are defaults. Can be overridden per-request via API parameters.

### Logging Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_LEVEL` | string | `INFO` | Logging level |
| `DEBUG_MODE` | boolean | `false` | Enable debug mode |

**Log Levels**:
- `DEBUG`: Detailed diagnostic information
- `INFO`: General informational messages
- `WARNING`: Warning messages
- `ERROR`: Error conditions only

**Example**:
```bash
# Development
LOG_LEVEL=DEBUG
DEBUG_MODE=true

# Production
LOG_LEVEL=INFO
DEBUG_MODE=false
```

### WebSocket Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `WS_HEARTBEAT_INTERVAL` | integer | `30` | WebSocket heartbeat interval (seconds) |
| `WS_MESSAGE_QUEUE_SIZE` | integer | `1000` | Max WebSocket message queue size |

**Example**:
```bash
WS_HEARTBEAT_INTERVAL=30
WS_MESSAGE_QUEUE_SIZE=1000
```

## Environment-Specific Configurations

### Development (.env.development)

```bash
# API
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=2

# Security (less strict for dev)
API_KEY={REDACTED}
ENABLE_AUTH=false

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Database
DATABASE_URL=sqlite:///./dev_jobs.db

# Storage
MAX_UPLOAD_SIZE_MB=100
UPLOAD_DIR=./uploads
LOG_DIR=./logs

# Logging
LOG_LEVEL=DEBUG
DEBUG_MODE=true

# Workers
MAX_CONCURRENT_JOBS=2
JOB_TIMEOUT=1800
```

### Production (.env.production)

```bash
# API
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=8

# Security
API_KEY=${SECURE_API_KEY}  # From secrets manager
SECRET_KEY=${SECURE_SECRET_KEY}
ENABLE_AUTH=true

# Redis
REDIS_HOST=redis-cluster.internal
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}

# Database
DATABASE_URL=postgresql://phoenix:${DB_PASSWORD}@postgres.internal:5432/phoenix_scanner

# Storage
MAX_UPLOAD_SIZE_MB=1000
UPLOAD_DIR=/mnt/shared/uploads
LOG_DIR=/mnt/shared/logs

# Logging
LOG_LEVEL=INFO
DEBUG_MODE=false

# Workers
MAX_CONCURRENT_JOBS=10
JOB_TIMEOUT=7200
CLEANUP_AFTER_DAYS=30

# Phoenix
PHOENIX_CLIENT_SECRET=${PHOENIX_SECRET}
```

### Testing (.env.test)

```bash
# API
API_HOST=localhost
API_PORT=8001
API_WORKERS=1

# Security
ENABLE_AUTH=false

# Redis
REDIS_HOST=localhost
REDIS_PORT=6380

# Database
DATABASE_URL=sqlite:///./test_jobs.db

# Storage
MAX_UPLOAD_SIZE_MB=50
UPLOAD_DIR=./test_uploads
LOG_DIR=./test_logs

# Logging
LOG_LEVEL=DEBUG
DEBUG_MODE=true

# Workers
MAX_CONCURRENT_JOBS=1
JOB_TIMEOUT=300
```

## Docker Compose Configuration

### Override Files

Create environment-specific override files:

**docker-compose.override.yml** (development):
```yaml
version: '3.8'

services:
  api:
    environment:
      - LOG_LEVEL=DEBUG
      - DEBUG_MODE=true
    volumes:
      - ./app:/app/app  # Hot reload
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
  
  worker:
    environment:
      - LOG_LEVEL=DEBUG
    command: celery -A app.workers.celery_app worker --loglevel=debug
```

**docker-compose.prod.yml** (production):
```yaml
version: '3.8'

services:
  api:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
  
  worker:
    deploy:
      replicas: 5
      resources:
        limits:
          cpus: '4'
          memory: 4G
  
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: phoenix
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: phoenix_scanner
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

### Using Override Files

```bash
# Development
docker-compose up

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Secrets Management

### Using Environment Variables

```bash
# Set environment variables
export API_KEY="your-secure-key"
export PHOENIX_CLIENT_SECRET="phoenix-secret"

# Start with environment
docker-compose up -d
```

### Using .env File

```bash
# Copy template
cp .env.example .env

# Edit .env
nano .env

# Start (automatically loads .env)
docker-compose up -d
```

### Using Docker Secrets (Swarm)

```yaml
version: '3.8'

services:
  api:
    secrets:
      - api_key
      - phoenix_secret
    environment:
      - API_KEY=/run/secrets/api_key
      - PHOENIX_CLIENT_SECRET=/run/secrets/phoenix_secret

secrets:
  api_key:
    external: true
  phoenix_secret:
    external: true
```

### Using Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: phoenix-scanner-secrets
type: Opaque
stringData:
  api-key: your-secure-key
  phoenix-secret: {REDACTED}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: phoenix-scanner-config
data:
  API_HOST: "0.0.0.0"
  API_PORT: "8000"
  LOG_LEVEL: "INFO"
```

## Performance Tuning

### API Performance

```bash
# More workers for higher throughput
API_WORKERS=16

# Adjust based on: workers = (2 * CPU_CORES) + 1
```

### Worker Performance

```bash
# More workers for parallelism
docker-compose up -d --scale worker=10

# Higher concurrency per worker
MAX_CONCURRENT_JOBS=20
```

### Redis Performance

```bash
# Increase max memory
redis:
  command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

### Database Performance

```bash
# PostgreSQL tuning
postgres:
  command: postgres -c shared_buffers=256MB -c max_connections=200
```

## Monitoring Configuration

### Prometheus Metrics (Future)

```bash
METRICS_ENABLED=true
METRICS_PORT=9090
```

### Log Aggregation

```yaml
# Fluent Bit
services:
  fluent-bit:
    image: fluent/fluent-bit
    volumes:
      - ./logs:/logs:ro
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf
```

## Troubleshooting Configuration

### Check Current Configuration

```bash
# From API container
docker-compose exec api python -c "from app.core.config import settings; import json; print(json.dumps({k: str(v) for k, v in settings.__dict__.items() if not k.startswith('_')}, indent=2))"
```

### Validate Configuration

```bash
# Test database connection
docker-compose exec api python -c "from app.models.database import engine; engine.connect(); print('✅ Database OK')"

# Test Redis connection
docker-compose exec api python -c "import redis; r = redis.from_url('redis://redis:6379/0'); r.ping(); print('✅ Redis OK')"
```

### Common Issues

**Issue**: "Redis connection refused"
```bash
# Check Redis is running
docker-compose ps redis

# Check Redis host
REDIS_HOST=redis  # Use service name in Docker Compose
```

**Issue**: "Database locked"
```bash
# Switch to PostgreSQL for production
DATABASE_URL=postgresql://...
```

**Issue**: "File too large"
```bash
# Increase limit
MAX_UPLOAD_SIZE_MB=1000
```

## Configuration Checklist

### Pre-Production Checklist

- [ ] Change `API_KEY` to secure random value
- [ ] Change `SECRET_KEY` to secure random value
- [ ] Enable authentication (`ENABLE_AUTH=true`)
- [ ] Use PostgreSQL instead of SQLite
- [ ] Configure Redis password
- [ ] Set up shared file storage
- [ ] Configure log aggregation
- [ ] Set appropriate resource limits
- [ ] Configure backup strategy
- [ ] Set up monitoring/alerting
- [ ] Review security settings
- [ ] Test failover scenarios

## References

- [FastAPI Settings](https://fastapi.tiangolo.com/advanced/settings/)
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [Celery Configuration](https://docs.celeryproject.org/en/stable/userguide/configuration.html)
- [Docker Compose Environment](https://docs.docker.com/compose/environment-variables/)



