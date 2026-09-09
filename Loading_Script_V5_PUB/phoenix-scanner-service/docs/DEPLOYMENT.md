# Deployment Guide

Production deployment guide for Phoenix Scanner Service.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Compose Deployment](#docker-compose-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Cloud Deployments](#cloud-deployments)
5. [Reverse Proxy Setup](#reverse-proxy-setup)
6. [Security Hardening](#security-hardening)
7. [Monitoring & Alerts](#monitoring--alerts)
8. [Backup & Recovery](#backup--recovery)
9. [Scaling](#scaling)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

**Minimum**:
- 2 CPU cores
- 4GB RAM
- 50GB disk space
- Docker 20.10+
- Docker Compose 2.0+

**Recommended**:
- 4+ CPU cores
- 8GB+ RAM
- 100GB+ SSD storage
- Docker 24.0+
- Docker Compose 2.20+

### Network Requirements

- Ports 8000 (API), 6379 (Redis), 5432 (PostgreSQL)
- Outbound access to Phoenix API
- Inbound access for clients

### External Dependencies

- Phoenix Security API endpoint
- Phoenix API credentials (client ID + secret)

## Docker Compose Deployment

### 1. Quick Start (Single Server)

```bash
# Clone/copy service directory
cd phoenix-scanner-service

# Initialize
make init

# Configure
nano .env
# Set: API_KEY, PHOENIX_CLIENT_SECRET, etc.

# Build and start
make build
make up

# Verify
make health
```

### 2. Production Configuration

Create `.env.production`:

```bash
# Security
API_KEY=your-secure-api-key-min-32-chars
SECRET_KEY=your-secret-key-min-32-chars
ENABLE_AUTH=true

# Database (PostgreSQL)
DATABASE_URL=postgresql://phoenix:secure_password@postgres:5432/phoenix_scanner

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=redis_secure_password

# Storage
MAX_UPLOAD_SIZE_MB=1000
UPLOAD_DIR=/mnt/shared/uploads
LOG_DIR=/mnt/shared/logs

# Performance
API_WORKERS=8
MAX_CONCURRENT_JOBS=10
JOB_TIMEOUT=7200

# Phoenix
PHOENIX_CLIENT_SECRET=your-phoenix-secret

# Logging
LOG_LEVEL=INFO
DEBUG_MODE=false
```

### 3. Use PostgreSQL

Uncomment PostgreSQL in `docker-compose.yml`:

```yaml
postgres:
  image: postgres:15-alpine
  container_name: phoenix-scanner-postgres
  environment:
    POSTGRES_USER: phoenix
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    POSTGRES_DB: phoenix_scanner
  ports:
    - "5432:5432"
  volumes:
    - postgres_data:/var/lib/postgresql/data
  networks:
    - phoenix-network
  restart: unless-stopped
```

Update service to use PostgreSQL:

```yaml
api:
  environment:
    - DATABASE_URL=postgresql://phoenix:${POSTGRES_PASSWORD}@postgres:5432/phoenix_scanner
```

### 4. Start Production

```bash
# Load environment
export $(cat .env.production | xargs)

# Start with production config
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Test health
curl http://localhost:8000/api/v1/health
```

### 5. Scale Workers

```bash
# Scale to 5 workers
docker-compose up -d --scale worker=5

# Verify
docker-compose ps worker
```

## Kubernetes Deployment

### 1. Create Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: phoenix-scanner
```

```bash
kubectl apply -f namespace.yaml
```

### 2. Create Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: phoenix-scanner-secrets
  namespace: phoenix-scanner
type: Opaque
stringData:
  api-key: "your-secure-api-key"
  secret-key: "your-secret-key"
  postgres-password: {REDACTED}
  redis-password: {REDACTED}
  phoenix-client-secret: {REDACTED}
```

```bash
kubectl apply -f secrets.yaml
```

### 3. Create ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: phoenix-scanner-config
  namespace: phoenix-scanner
data:
  API_HOST: "0.0.0.0"
  API_PORT: "8000"
  API_WORKERS: "8"
  REDIS_HOST: "redis-service"
  REDIS_PORT: "6379"
  DATABASE_URL: "postgresql://phoenix:password@postgres-service:5432/phoenix_scanner"
  LOG_LEVEL: "INFO"
  MAX_CONCURRENT_JOBS: "10"
```

```bash
kubectl apply -f configmap.yaml
```

### 4. Deploy Redis

```yaml
# redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: phoenix-scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command: ["redis-server", "--requirepass", "$(REDIS_PASSWORD)"]
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: phoenix-scanner-secrets
              key: redis-password
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-data
          mountPath: /data
      volumes:
      - name: redis-data
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
  namespace: phoenix-scanner
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
```

### 5. Deploy PostgreSQL

```yaml
# postgres-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: phoenix-scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_USER
          value: "phoenix"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: phoenix-scanner-secrets
              key: postgres-password
        - name: POSTGRES_DB
          value: "phoenix_scanner"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-data
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: phoenix-scanner
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

### 6. Deploy API

```yaml
# api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: phoenix-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: phoenix-scanner-service:latest
        imagePullPolicy: IfNotPresent
        envFrom:
        - configMapRef:
            name: phoenix-scanner-config
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: phoenix-scanner-secrets
              key: api-key
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: phoenix-scanner-secrets
              key: secret-key
        - name: PHOENIX_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: phoenix-scanner-secrets
              key: phoenix-client-secret
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /api/v1/ping
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        volumeMounts:
        - name: uploads
          mountPath: /app/uploads
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: uploads-pvc
      - name: logs
        persistentVolumeClaim:
          claimName: logs-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: phoenix-scanner
spec:
  type: LoadBalancer
  selector:
    app: api
  ports:
  - port: 80
    targetPort: 8000
```

### 7. Deploy Worker

```yaml
# worker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: phoenix-scanner
spec:
  replicas: 5
  selector:
    matchLabels:
      app: worker
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
      - name: worker
        image: phoenix-scanner-service:latest
        imagePullPolicy: IfNotPresent
        command: ["celery", "-A", "app.workers.celery_app", "worker", "--loglevel=info"]
        envFrom:
        - configMapRef:
            name: phoenix-scanner-config
        env:
        - name: PHOENIX_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: phoenix-scanner-secrets
              key: phoenix-client-secret
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "4000m"
        volumeMounts:
        - name: uploads
          mountPath: /app/uploads
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: uploads-pvc
      - name: logs
        persistentVolumeClaim:
          claimName: logs-pvc
```

### 8. Create PersistentVolumeClaims

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: phoenix-scanner
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: phoenix-scanner
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: uploads-pvc
  namespace: phoenix-scanner
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 100Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: logs-pvc
  namespace: phoenix-scanner
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 50Gi
```

### 9. Deploy All

```bash
# Apply all manifests
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f redis-deployment.yaml
kubectl apply -f postgres-deployment.yaml
kubectl apply -f api-deployment.yaml
kubectl apply -f worker-deployment.yaml

# Check status
kubectl get all -n phoenix-scanner

# Get service URL
kubectl get svc api-service -n phoenix-scanner
```

## Cloud Deployments

### AWS (ECS + Fargate)

**Architecture**:
- ALB → ECS Service (API) → Fargate tasks
- ElastiCache Redis
- RDS PostgreSQL
- EFS for shared storage
- ECS Service (Workers) → Fargate tasks

**Steps**:
1. Create VPC with public/private subnets
2. Create RDS PostgreSQL instance
3. Create ElastiCache Redis cluster
4. Create EFS filesystem
5. Create ECS cluster
6. Create task definitions (API + Worker)
7. Create ECS services with auto-scaling
8. Create ALB with target groups
9. Configure Route53 DNS

### Azure (AKS)

**Architecture**:
- Application Gateway → AKS Service
- Azure Cache for Redis
- Azure Database for PostgreSQL
- Azure Files for shared storage

**Steps**:
1. Create resource group
2. Create AKS cluster
3. Create PostgreSQL flexible server
4. Create Redis cache
5. Create file share
6. Deploy using Kubernetes manifests
7. Configure ingress controller

### GCP (GKE)

**Architecture**:
- Cloud Load Balancing → GKE Service
- Memorystore Redis
- Cloud SQL PostgreSQL
- Filestore for shared storage

**Steps**:
1. Create GKE cluster
2. Create Cloud SQL instance
3. Create Memorystore instance
4. Create Filestore instance
5. Deploy using Kubernetes manifests
6. Configure ingress

## Reverse Proxy Setup

### Nginx

```nginx
# /etc/nginx/sites-available/phoenix-scanner
upstream api {
    server localhost:8000;
}

server {
    listen 80;
    server_name scanner-api.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name scanner-api.example.com;

    ssl_certificate /etc/ssl/certs/scanner-api.crt;
    ssl_certificate_key /etc/ssl/private/scanner-api.key;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # File upload size
    client_max_body_size 1000M;

    # Timeouts
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    # API endpoints
    location / {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /ws/ {
        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

Enable and restart:

```bash
sudo ln -s /etc/nginx/sites-available/phoenix-scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Traefik (Docker)

```yaml
# traefik-compose.yml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=user@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./acme.json:/acme.json"
    networks:
      - phoenix-network

  api:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.api.rule=Host(`scanner-api.example.com`)"
      - "traefik.http.routers.api.entrypoints=websecure"
      - "traefik.http.routers.api.tls.certresolver=letsencrypt"
      - "traefik.http.services.api.loadbalancer.server.port=8000"
```

## Security Hardening

### 1. Enable HTTPS/TLS

Use Let's Encrypt for free SSL certificates:

```bash
# Certbot
sudo certbot --nginx -d scanner-api.example.com
```

### 2. Firewall Rules

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
sudo ufw enable

# Block direct access to backend services
sudo ufw deny 6379/tcp    # Redis
sudo ufw deny 5432/tcp    # PostgreSQL
sudo ufw deny 8000/tcp    # API (behind proxy)
```

### 3. Secure Redis

```bash
# requirepass in redis.conf
requirepass your-strong-redis-password

# Bind to localhost only
bind 127.0.0.1
```

### 4. Secure PostgreSQL

```sql
-- Create dedicated user
CREATE USER phoenix WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE phoenix_scanner TO phoenix;

-- Revoke public access
REVOKE ALL ON DATABASE phoenix_scanner FROM PUBLIC;
```

### 5. API Rate Limiting

Using nginx:

```nginx
# Define rate limit zone
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

server {
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://api;
    }
}
```

### 6. Environment Secrets

Never commit secrets! Use:
- AWS Secrets Manager
- Azure Key Vault
- HashiCorp Vault
- Kubernetes Secrets

## Monitoring & Alerts

### 1. Prometheus + Grafana

```yaml
# monitoring-compose.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

### 2. Log Aggregation (ELK Stack)

```yaml
version: '3.8'

services:
  elasticsearch:
    image: elasticsearch:8.10.0
    environment:
      - discovery.type=single-node
    ports:
      - "9200:9200"

  logstash:
    image: logstash:8.10.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf

  kibana:
    image: kibana:8.10.0
    ports:
      - "5601:5601"
```

### 3. Health Check Monitoring

```bash
#!/bin/bash
# health-check.sh

URL="https://scanner-api.example.com/api/v1/health"
WEBHOOK="https://alerts.example.com/webhook"

response=$(curl -s -o /dev/null -w "%{http_code}" $URL)

if [ $response != "200" ]; then
    curl -X POST $WEBHOOK \
      -H "Content-Type: application/json" \
      -d "{\"message\": \"Phoenix Scanner API is DOWN\", \"status\": \"$response\"}"
fi
```

Schedule with cron:

```bash
*/5 * * * * /path/to/health-check.sh
```

## Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# backup-db.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/postgres"
PGPASSWORD=your-password pg_dump \
  -h localhost \
  -U phoenix \
  -d phoenix_scanner \
  > "$BACKUP_DIR/backup_$DATE.sql"

# Compress
gzip "$BACKUP_DIR/backup_$DATE.sql"

# Keep only last 30 days
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete
```

### File Backup

```bash
#!/bin/bash
# backup-files.sh

DATE=$(date +%Y%m%d)
tar -czf /backups/uploads_$DATE.tar.gz /app/uploads
tar -czf /backups/logs_$DATE.tar.gz /app/logs
```

### Restore

```bash
# Restore database
gunzip backup_20251112.sql.gz
psql -h localhost -U phoenix -d phoenix_scanner < backup_20251112.sql

# Restore files
tar -xzf uploads_20251112.tar.gz -C /
```

## Scaling

### Horizontal Scaling

```bash
# Scale API
docker-compose up -d --scale api=5

# Scale workers
docker-compose up -d --scale worker=10

# Kubernetes
kubectl scale deployment api --replicas=10 -n phoenix-scanner
kubectl scale deployment worker --replicas=20 -n phoenix-scanner
```

### Auto-scaling (Kubernetes)

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-hpa
  namespace: phoenix-scanner
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Troubleshooting

### Check Logs

```bash
# Docker Compose
docker-compose logs -f api worker

# Kubernetes
kubectl logs -f deployment/api -n phoenix-scanner
kubectl logs -f deployment/worker -n phoenix-scanner
```

### Debug Container

```bash
# Docker
docker-compose exec api /bin/bash

# Kubernetes
kubectl exec -it deployment/api -n phoenix-scanner -- /bin/bash
```

### Database Issues

```bash
# Check connections
docker-compose exec postgres psql -U phoenix -d phoenix_scanner -c "SELECT count(*) FROM pg_stat_activity;"

# Kill idle connections
docker-compose exec postgres psql -U phoenix -d phoenix_scanner -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle';"
```

### Redis Issues

```bash
# Check Redis
docker-compose exec redis redis-cli ping
docker-compose exec redis redis-cli INFO
```

## Production Checklist

- [ ] SSL/TLS certificates configured
- [ ] Firewall rules in place
- [ ] Secrets management configured
- [ ] Database backups scheduled
- [ ] Log aggregation configured
- [ ] Monitoring dashboards setup
- [ ] Health checks configured
- [ ] Auto-scaling rules set
- [ ] Disaster recovery plan documented
- [ ] Load testing completed
- [ ] Security audit performed
- [ ] Documentation updated

## Support

For deployment issues:
- Check logs first
- Review [Troubleshooting Guide](../../docs/guides/TROUBLESHOOTING.md)
- Contact: user@example.com



