# Architecture Guide

System architecture and design documentation for Phoenix Scanner Service.

## Overview

Phoenix Scanner Service is a distributed system built with modern cloud-native patterns for scalability, reliability, and maintainability.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Client Layer                          │
│  (CLI, Web UI, CI/CD Pipelines, External Systems)           │
└────────────────┬────────────────┬──────────────────────────-─┘
                 │                │
                 │ HTTP/REST      │ WebSocket
                 ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                     API Gateway / Load Balancer              │
│                  (nginx, traefik, ALB, etc.)                 │
└────────────────┬────────────────┬──────────────────────────-─┘
                 │                │
                 ▼                ▼
┌────────────────────────────────────────────────────────────┐
│                       API Service                           │
│              FastAPI (Uvicorn workers)                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Endpoints:                                           │  │
│  │  • POST /api/v1/upload    -> Queue job               │  │
│  │  • GET  /api/v1/jobs      -> List jobs               │  │
│  │  • GET  /api/v1/jobs/:id  -> Get status              │  │
│  │  • WS   /ws/:id           -> Stream logs              │  │
│  └──────────────────────────────────────────────────────┘  │
└────┬─────────────────────┬────────────────┬───────────────┘
     │                     │                │
     │                     ▼                │
     │              ┌─────────────┐         │
     │              │   Database  │         │
     │              │  (SQLite/   │         │
     │              │  PostgreSQL)│         │
     │              └─────────────┘         │
     │                                      │
     ▼                                      ▼
┌──────────────┐                    ┌──────────────┐
│    Redis     │◀───────────────────│   Workers    │
│ (Queue/Cache)│                    │   (Celery)   │
└──────────────┘                    └──────┬───────┘
                                           │
                                           ▼
                                    ┌──────────────┐
                                    │   Phoenix    │
                                    │   Scanner    │
                                    │   Enhanced   │
                                    └──────┬───────┘
                                           │
                                           ▼
                                    ┌──────────────┐
                                    │   Phoenix    │
                                    │   Security   │
                                    │     API      │
                                    └──────────────┘
```

## Components

### 1. API Service (FastAPI)

**Responsibility**: Handle HTTP requests, manage authentication, coordinate job submission

**Technology**: 
- FastAPI (async web framework)
- Uvicorn (ASGI server)
- Pydantic (data validation)

**Key Features**:
- RESTful API endpoints
- WebSocket support for real-time streaming
- API key authentication
- Request validation
- OpenAPI documentation
- CORS handling
- GZip compression

**Scaling**:
- Stateless design allows horizontal scaling
- Multiple Uvicorn workers (default: 4)
- Can run multiple instances behind load balancer

### 2. Worker Service (Celery)

**Responsibility**: Process scanner files in background, import to Phoenix

**Technology**:
- Celery (distributed task queue)
- Python multiprocessing

**Key Features**:
- Asynchronous job processing
- Retry logic with exponential backoff
- Task timeouts and soft limits
- Worker process pooling
- Task result storage
- Progress tracking

**Scaling**:
- Horizontal scaling via replicas
- Configurable concurrency per worker
- Task routing and priorities

### 3. Message Broker (Redis)

**Responsibility**: Queue management, result backend, caching

**Technology**:
- Redis 7.x

**Usage**:
- Celery task queue
- Task result storage
- WebSocket pub/sub
- Session storage (future)
- Rate limiting (future)

**Scaling**:
- Redis Cluster for horizontal scaling
- Redis Sentinel for high availability
- AOF persistence for durability

### 4. Database (SQLite/PostgreSQL)

**Responsibility**: Job metadata, status tracking, audit logs

**Technology**:
- SQLite (development, single instance)
- PostgreSQL (production, distributed)

**Schema**:
```sql
CREATE TABLE jobs (
    job_id VARCHAR(64) PRIMARY KEY,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    filename VARCHAR(512) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    scanner_type VARCHAR(64),
    asset_type VARCHAR(32),
    assessment_name VARCHAR(256),
    import_type VARCHAR(20) NOT NULL,
    phoenix_client_id VARCHAR(256),
    phoenix_api_url VARCHAR(512),
    processing_options TEXT,
    progress FLOAT NOT NULL DEFAULT 0.0,
    current_step VARCHAR(256),
    assets_imported INTEGER,
    vulnerabilities_imported INTEGER,
    batch_summary TEXT,
    error_message TEXT,
    error_traceback TEXT,
    webhook_url VARCHAR(1024),
    webhook_headers TEXT,
    task_id VARCHAR(64),
    worker_name VARCHAR(128)
);
```

### 5. File Storage

**Responsibility**: Store uploaded scanner files and processing logs

**Structure**:
```
/app/
  ├── uploads/           # Uploaded scanner files
  │   └── job-abc123_scan.json
  ├── logs/             # Processing logs
  │   └── job-abc123.log
  └── data/             # Database files
      └── jobs.db
```

**Scaling**:
- Shared volume for multi-instance deployments
- S3/MinIO for cloud deployments
- Retention policies for cleanup

## Data Flow

### File Upload Flow

```
1. Client uploads file
   ↓
2. API validates file (type, size, format)
   ↓
3. API saves file to storage
   ↓
4. API creates job record in database
   ↓
5. API queues task in Redis
   ↓
6. API returns job ID to client
   ↓
7. Worker picks up task from queue
   ↓
8. Worker updates job status to "processing"
   ↓
9. Worker loads Phoenix Scanner Enhanced
   ↓
10. Worker processes file (parse, validate, batch)
    ↓
11. Worker imports to Phoenix API
    ↓
12. Worker updates job status with results
    ↓
13. Worker sends webhook notification (if configured)
    ↓
14. Job complete
```

### WebSocket Streaming Flow

```
1. Client connects to /ws/{job_id}
   ↓
2. API validates job exists
   ↓
3. API adds client to connection pool
   ↓
4. API starts log streaming task
   ↓
5. API reads log file continuously
   ↓
6. API broadcasts new logs to all connected clients
   ↓
7. API monitors job status in database
   ↓
8. API sends progress updates
   ↓
9. On job completion, API sends final message
   ↓
10. API closes connection after 5 seconds
```

## Communication Patterns

### Synchronous (HTTP REST)

Used for:
- File uploads
- Status queries
- Job listing
- Cancellations

**Pros**:
- Simple, well-understood
- Request-response pattern
- Easy error handling

**Cons**:
- Blocking for long operations
- Requires polling for status

### Asynchronous (Celery Tasks)

Used for:
- File processing
- Phoenix API imports
- Batch operations

**Pros**:
- Non-blocking API
- Retry logic
- Scalable processing

**Cons**:
- Eventually consistent
- Requires queue infrastructure

### Real-time (WebSocket)

Used for:
- Log streaming
- Progress updates
- Status notifications

**Pros**:
- Real-time updates
- Bidirectional communication
- Efficient (no polling)

**Cons**:
- More complex
- Connection management
- Firewall/proxy considerations

### Event-driven (Webhooks)

Used for:
- External system notifications
- Completion callbacks
- Error alerts

**Pros**:
- Decoupled systems
- Asynchronous
- Reliable delivery

**Cons**:
- Requires endpoint setup
- Retry logic needed
- Security considerations

## Design Patterns

### 1. Queue-based Processing

**Pattern**: Decouple request handling from processing

**Implementation**:
- API receives upload → Queue task → Return immediately
- Worker picks up task → Process → Update status

**Benefits**:
- Non-blocking API
- Handles traffic spikes
- Prevents resource exhaustion

### 2. Repository Pattern

**Pattern**: Abstract database operations

**Implementation**:
```python
class JobManager:
    def create_job(self, ...): ...
    def get_job(self, job_id): ...
    def update_job_status(self, job_id, status): ...
    def list_jobs(self, filters): ...
```

**Benefits**:
- Clean separation of concerns
- Easy to test
- Database-agnostic

### 3. Connection Manager

**Pattern**: Manage WebSocket connections

**Implementation**:
```python
class ConnectionManager:
    def connect(self, ws, job_id): ...
    def disconnect(self, ws, job_id): ...
    def broadcast(self, job_id, message): ...
```

**Benefits**:
- Centralized connection handling
- Easy broadcasting
- Automatic cleanup

### 4. Task Callbacks

**Pattern**: Lifecycle hooks for tasks

**Implementation**:
```python
@task_prerun.connect
def on_start(task_id, ...): ...

@task_postrun.connect
def on_success(task_id, ...): ...

@task_failure.connect
def on_failure(task_id, ...): ...
```

**Benefits**:
- Consistent logging
- Status tracking
- Error handling

## Security Architecture

### Authentication

```
Client Request
    ↓
[API Key Middleware]
    ↓
Verify key in config
    ↓
Allow/Deny access
```

### Data Protection

- **In Transit**: HTTPS/TLS (via reverse proxy)
- **At Rest**: 
  - Files: Filesystem permissions
  - Database: Encryption (PostgreSQL TDE)
  - Secrets: Environment variables / Secrets manager

### Input Validation

- File type validation
- File size limits
- Request parameter validation (Pydantic)
- SQL injection protection (SQLAlchemy ORM)

### Rate Limiting

- API Gateway level (recommended)
- Application level (future)
- Worker concurrency limits

## Monitoring & Observability

### Metrics

- **API Metrics**:
  - Request rate
  - Response times
  - Error rates
  - Active connections

- **Worker Metrics**:
  - Task throughput
  - Task duration
  - Queue depth
  - Worker utilization

- **System Metrics**:
  - CPU/Memory usage
  - Disk usage
  - Network I/O

### Logging

**Levels**:
- DEBUG: Detailed diagnostic info
- INFO: General informational messages
- WARNING: Warning messages
- ERROR: Error conditions

**Destinations**:
- Stdout/stderr (Docker logs)
- File logs per job
- Centralized logging (ELK, Loki) in production

### Health Checks

- **API Health**: `/api/v1/health`
- **Database Health**: Connection test
- **Redis Health**: Ping command
- **Worker Health**: Celery inspect

### Tracing

Future enhancement:
- Distributed tracing (OpenTelemetry)
- Request ID propagation
- Performance profiling

## Scalability Considerations

### Horizontal Scaling

**API Service**:
```bash
docker-compose up -d --scale api=3
```

**Worker Service**:
```bash
docker-compose up -d --scale worker=10
```

**Requirements**:
- Load balancer for API instances
- Shared file storage (NFS, S3)
- Centralized database (PostgreSQL)

### Vertical Scaling

- Increase Uvicorn workers
- Increase Celery concurrency
- Increase resource limits

### Performance Optimization

1. **Caching**:
   - Redis for frequent queries
   - CDN for static assets

2. **Database**:
   - Indexes on query fields
   - Connection pooling
   - Read replicas

3. **File Processing**:
   - Streaming file reads
   - Batch operations
   - Compression

## High Availability

### Redundancy

```
┌────────────┐     ┌────────────┐     ┌────────────┐
│   API-1    │     │   API-2    │     │   API-3    │
└─────┬──────┘     └─────┬──────┘     └─────┬──────┘
      │                  │                  │
      └──────────────────┴──────────────────┘
                         │
                  ┌──────▼──────┐
                  │Load Balancer│
                  └──────┬──────┘
                         │
      ┌──────────────────┴──────────────────┐
      │                                      │
┌─────▼──────┐                        ┌─────▼──────┐
│  Redis     │◀──────Replication─────▶│  Redis     │
│  Master    │                         │  Replica   │
└────────────┘                         └────────────┘
```

### Failure Recovery

- **API Failure**: Load balancer redirects to healthy instance
- **Worker Failure**: Celery requeues tasks
- **Redis Failure**: Redis Sentinel auto-failover
- **Database Failure**: PostgreSQL streaming replication

### Backup Strategy

1. **Database**: Daily PostgreSQL dumps
2. **File Storage**: Periodic S3 sync
3. **Configuration**: Version control

## Technology Stack

### Core Technologies

| Component | Technology | Version |
|-----------|------------|---------|
| Web Framework | FastAPI | 0.109+ |
| ASGI Server | Uvicorn | 0.27+ |
| Task Queue | Celery | 5.3+ |
| Message Broker | Redis | 7.0+ |
| Database | SQLite/PostgreSQL | 15+ |
| Container Runtime | Docker | 20.10+ |
| Orchestration | Docker Compose | 2.0+ |

### Python Libraries

- **pydantic**: Data validation
- **sqlalchemy**: ORM
- **alembic**: Database migrations
- **httpx**: HTTP client
- **websockets**: WebSocket support
- **redis**: Redis client
- **celery**: Task queue

## Future Enhancements

1. **Authentication**: JWT-based auth, OAuth2
2. **Multi-tenancy**: Tenant isolation
3. **API Versioning**: Multiple API versions
4. **Rate Limiting**: Per-user/tenant limits
5. **Caching**: Response caching
6. **Streaming Uploads**: Large file support
7. **Kubernetes**: K8s deployment
8. **Observability**: OpenTelemetry, metrics
9. **GraphQL**: Alternative API interface
10. **Machine Learning**: Scanner detection optimization

## References

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Celery Documentation](https://docs.celeryproject.org/)
- [Redis Documentation](https://redis.io/documentation)
- [Docker Documentation](https://docs.docker.com/)

