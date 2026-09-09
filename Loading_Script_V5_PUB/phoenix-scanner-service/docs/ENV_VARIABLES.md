# Phoenix Scanner Service - Environment Variables

## Required Environment Variables

### Phoenix Platform Credentials

These credentials are used by the worker to authenticate with the Phoenix Security Platform API and import scan results.

```bash
# Phoenix API Client ID (REQUIRED for actual imports)
PHOENIX_CLIENT_ID=your-phoenix-client-id

# Phoenix API Client Secret (REQUIRED for actual imports)
PHOENIX_CLIENT_SECRET=your-phoenix-client-secret

# Phoenix API Base URL (REQUIRED for actual imports)
PHOENIX_API_URL=https://api.demo.appsecphx.io
```

**Note**: These can be overridden per API request via the upload endpoint parameters.

### API Security

```bash
# API Key for client authentication (comma-separated for multiple keys)
API_KEY=changeme-insecure-key,another-key

# Secret key for session management
SECRET_KEY=changeme-secret-key

# Enable/disable API authentication
ENABLE_AUTH=true
```

## Optional Environment Variables

### API Configuration

```bash
# API host binding
API_HOST=0.0.0.0

# API port
API_PORT=8000

# Number of API workers
API_WORKERS=4
```

### Redis Configuration

```bash
# Redis host
REDIS_HOST=redis

# Redis port
REDIS_PORT=6379

# Redis database number
REDIS_DB=0
```

### Database Configuration

```bash
# Database URL (SQLite default)
DATABASE_URL=sqlite:////app/data/jobs.db

# Or use PostgreSQL
# DATABASE_URL=postgresql://phoenix:phoenix_secure_password@postgres:5432/phoenix_scanner
```

### File Storage

```bash
# Upload directory
UPLOAD_DIR=/app/uploads

# Log directory
LOG_DIR=/app/logs

# Maximum upload size in MB
MAX_UPLOAD_SIZE_MB=500
```

### Worker Configuration

```bash
# Maximum concurrent jobs
MAX_CONCURRENT_JOBS=5

# Job timeout in seconds
JOB_TIMEOUT=3600
```

### Phoenix Scanner Configuration

```bash
# Path to config_multi_scanner.ini
PHOENIX_CONFIG_FILE=/parent/config_multi_scanner.ini
```

### Logging

```bash
# Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL=INFO

# Enable debug mode
DEBUG_MODE=false
```

## Setting Up Environment Variables

### Option 1: .env File (Recommended for Development)

Create a `.env` file in the `phoenix-scanner-service` directory:

```bash
# Copy example file
cp .env.example .env

# Edit with your values
nano .env
```

Example `.env` file:

```bash
# Phoenix Platform Credentials
PHOENIX_CLIENT_ID=my-client-id-12345
PHOENIX_CLIENT_SECRET=my-secret-key-abcdef
PHOENIX_API_URL=https://api.demo.appsecphx.io

# API Security
API_KEY={REDACTED}
SECRET_KEY=my-secret-session-key

# Logging
LOG_LEVEL=DEBUG
DEBUG_MODE=true
```

### Option 2: Export in Shell (Temporary)

```bash
export PHOENIX_CLIENT_ID=my-client-id
export PHOENIX_CLIENT_SECRET=my-secret
export PHOENIX_API_URL=https://api.demo.appsecphx.io
export API_KEY=my-api-key

docker-compose up -d
```

### Option 3: Docker Compose Override (Production)

Create `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  api:
    environment:
      - PHOENIX_CLIENT_ID=prod-client-id
      - PHOENIX_CLIENT_SECRET=prod-secret
      - PHOENIX_API_URL=https://api.prod.appsecphx.io
      - API_KEY=prod-api-key-12345
  
  worker:
    environment:
      - PHOENIX_CLIENT_ID=prod-client-id
      - PHOENIX_CLIENT_SECRET=prod-secret
      - PHOENIX_API_URL=https://api.prod.appsecphx.io
```

### Option 4: Kubernetes Secrets (Production)

```bash
# Create secret
kubectl create secret generic phoenix-scanner-secrets \
  --from-literal=phoenix-client-id=my-client-id \
  --from-literal=phoenix-client-secret=my-secret \
  --from-literal=api-key=my-api-key

# Reference in deployment
env:
  - name: PHOENIX_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: phoenix-scanner-secrets
        key: phoenix-client-id
```

## Environment Variable Priority

Configuration is loaded in this order (highest priority first):

1. **API Request Parameters** (via upload endpoint)
2. **Environment Variables** (from .env or docker-compose)
3. **config_multi_scanner.ini** (default configuration file)
4. **Built-in Defaults**

### Example Priority Flow

```
Client uploads file with:
  --phoenix-client-id prod-client-123

↓ OVERRIDES ↓

Environment variable:
  PHOENIX_CLIENT_ID={REDACTED}

↓ FALLBACK TO ↓

config_multi_scanner.ini:
  client_id = {REDACTED}
```

**Result**: Uses `prod-client-123` from API request.

## Security Best Practices

### 1. Never Commit Secrets

```bash
# Add to .gitignore
echo ".env" >> .gitignore
echo "*.env" >> .gitignore
```

### 2. Use Different Credentials per Environment

```bash
# Development
PHOENIX_CLIENT_ID={REDACTED}

# Staging
PHOENIX_CLIENT_ID={REDACTED}

# Production
PHOENIX_CLIENT_ID={REDACTED}
```

### 3. Rotate Keys Regularly

```bash
# Generate new API key
openssl rand -hex 32

# Update in environment
API_KEY={REDACTED}
```

### 4. Use Secrets Management

- **Docker Swarm**: Use Docker secrets
- **Kubernetes**: Use Kubernetes secrets
- **Cloud**: Use cloud-native secret managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)

### 5. Limit API Key Access

```bash
# Use different API keys for different clients
API_KEY={REDACTED}
```

## Validation

### Check Current Configuration

```bash
# View environment variables in running container
docker-compose exec api env | grep PHOENIX

# Check worker configuration
docker-compose exec worker env | grep PHOENIX
```

### Test Connection

```bash
# API health check
curl http://localhost:8000/api/v1/health

# Check logs for Phoenix connection
docker-compose logs worker | grep -i phoenix
```

## Troubleshooting

### Issue: "Missing PHOENIX_CLIENT_ID"

**Solution**: Set the environment variable:

```bash
export PHOENIX_CLIENT_ID=your-client-id
docker-compose up -d
```

### Issue: "Authentication failed with Phoenix API"

**Solution**: Verify credentials are correct:

```bash
# Test Phoenix API credentials
curl -u "$PHOENIX_CLIENT_ID:$PHOENIX_CLIENT_SECRET" \
  https://api.demo.appsecphx.io/v1/auth/access_token
```

### Issue: "Environment variables not loaded"

**Solution**: Recreate containers:

```bash
docker-compose down
docker-compose up -d
```

## Complete Example

### Development Setup

```bash
# 1. Create .env file
cat > .env << EOF
# Phoenix Platform
PHOENIX_CLIENT_ID={REDACTED}
PHOENIX_CLIENT_SECRET={REDACTED}
PHOENIX_API_URL=https://api.demo.appsecphx.io

# API Security
API_KEY={REDACTED}
SECRET_KEY={REDACTED}

# Logging
LOG_LEVEL=DEBUG
DEBUG_MODE=true
EOF

# 2. Start services
docker-compose up -d

# 3. Verify
curl http://localhost:8000/api/v1/health
```

### Production Setup

```bash
# 1. Use environment-specific files
cp .env.example .env.production

# 2. Edit with production values
nano .env.production

# 3. Use in deployment
docker-compose --env-file .env.production up -d
```

## Reference

For more information, see:
- [Docker Compose Documentation](../docker-compose.yml)
- [Configuration Guide](CONFIGURATION.md)
- [Security Best Practices](DEPLOYMENT.md#security)

---

**Updated**: November 12, 2025  
**Version**: 1.0.1 (Fixed missing PHOENIX_CLIENT_ID)

