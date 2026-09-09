# API Reference

Complete reference for the Phoenix Scanner Service REST API.

## Base URL

```
http://localhost:8000
```

## Authentication

All API endpoints (except `/ping`) require authentication via API key.

**Header**: `X-API-Key: your-api-key`

Example:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/health
```

## Endpoints

### 1. Upload Scanner File

Upload a scanner output file for processing.

**Endpoint**: `POST /api/v1/upload`

**Headers**:
- `X-API-Key`: Your API key
- `Content-Type`: `multipart/form-data`

**Form Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `file` | File | Yes | - | Scanner output file (JSON/CSV/XML) |
| `scanner_type` | String | No | `auto` | Scanner type (e.g., trivy, grype, qualys) |
| `asset_type` | String | No | - | Asset type override (INFRA, WEB, CLOUD, CONTAINER, CODE, BUILD) |
| `assessment_name` | String | No | Auto-generated | Assessment name in Phoenix |
| `import_type` | String | No | `new` | Import type: new, merge, or delta |
| `phoenix_client_id` | String | No | - | Phoenix API client ID |
| `phoenix_client_secret` | String | No | - | Phoenix API client secret |
| `phoenix_api_url` | String | No | - | Phoenix API base URL |
| `enable_batching` | Boolean | No | `true` | Enable intelligent batching |
| `fix_data` | Boolean | No | `true` | Auto-fix data issues |
| `anonymize` | Boolean | No | `false` | Anonymize sensitive data |
| `just_tags` | Boolean | No | `false` | Only process tags |
| `create_empty_assets` | Boolean | No | `false` | Create empty assets (testing) |
| `create_inventory_assets` | Boolean | No | `false` | Create assets with no vulnerabilities |
| `max_batch_size` | Integer | No | `500` | Override max batch size |
| `max_payload_mb` | Float | No | `25.0` | Override max payload size (MB) |
| `webhook_url` | String | No | - | Webhook URL for status updates |

**Response**: `202 Accepted`

```json
{
  "job_id": "job-abc123def456",
  "status": "queued",
  "message": "File uploaded successfully. Job queued for processing.",
  "created_at": "2025-11-12T10:30:00Z",
  "websocket_url": "ws://localhost:8000/ws/job-abc123def456"
}
```

**Example**:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@trivy-results.json" \
  -F "scanner_type=trivy" \
  -F "asset_type=CONTAINER" \
  -F "assessment_name=Q4 Container Scan" \
  -F "phoenix_client_id=your-client-id" \
  -F "phoenix_client_secret=your-secret" \
  -F "phoenix_api_url=https://phoenix.example.com/api" \
  -F "webhook_url=https://your-app.com/webhook"
```

---

### 2. Get Job Status

Retrieve detailed status of a processing job.

**Endpoint**: `GET /api/v1/jobs/{job_id}`

**Headers**:
- `X-API-Key`: Your API key

**Response**: `200 OK`

```json
{
  "job_id": "job-abc123def456",
  "status": "processing",
  "progress": 65.5,
  "created_at": "2025-11-12T10:30:00Z",
  "started_at": "2025-11-12T10:30:15Z",
  "completed_at": null,
  "filename": "trivy-results.json",
  "file_size_bytes": 1048576,
  "scanner_type": "trivy",
  "assets_imported": null,
  "vulnerabilities_imported": null,
  "assessment_name": "Q4 Container Scan",
  "error_message": null,
  "error_traceback": null,
  "batch_summary": null,
  "recent_logs": [
    "2025-11-12 10:30:15 - INFO - Processing file: trivy-results.json",
    "2025-11-12 10:30:20 - INFO - Detected scanner type: trivy",
    "2025-11-12 10:30:25 - INFO - Parsed 150 assets with 423 vulnerabilities"
  ]
}
```

**Status Values**:
- `pending`: Job created, waiting to start
- `queued`: Job queued in Redis
- `processing`: Job actively processing
- `completed`: Job finished successfully
- `failed`: Job failed with errors
- `cancelled`: Job cancelled by user

**Example**:

```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs/job-abc123def456"
```

---

### 3. List Jobs

List all jobs with pagination and filtering.

**Endpoint**: `GET /api/v1/jobs`

**Headers**:
- `X-API-Key`: Your API key

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | Integer | `1` | Page number |
| `page_size` | Integer | `50` | Items per page (max 100) |
| `status` | String | - | Filter by status |

**Response**: `200 OK`

```json
{
  "total": 125,
  "jobs": [
    {
      "job_id": "job-abc123",
      "status": "completed",
      "progress": 100.0,
      "created_at": "2025-11-12T10:30:00Z",
      "started_at": "2025-11-12T10:30:15Z",
      "completed_at": "2025-11-12T10:32:45Z",
      "filename": "scan.json",
      "file_size_bytes": 1048576,
      "scanner_type": "trivy",
      "assets_imported": 150,
      "vulnerabilities_imported": 423,
      "assessment_name": "Q4 Scan",
      "error_message": null,
      "recent_logs": []
    }
  ],
  "page": 1,
  "page_size": 50
}
```

**Example**:

```bash
# Get first page
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs?page=1&page_size=20"

# Filter by status
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs?status=completed"
```

---

### 4. Cancel Job

Cancel a pending or processing job.

**Endpoint**: `DELETE /api/v1/jobs/{job_id}`

**Headers**:
- `X-API-Key`: Your API key

**Response**: `204 No Content`

**Error Response**: `400 Bad Request`

```json
{
  "error": "bad_request",
  "message": "Cannot cancel job with status completed",
  "timestamp": "2025-11-12T10:30:00Z"
}
```

**Example**:

```bash
curl -X DELETE \
  -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/jobs/job-abc123"
```

---

### 5. Health Check

Get service health and system status.

**Endpoint**: `GET /api/v1/health`

**Response**: `200 OK`

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-11-12T10:30:00Z",
  "workers": {
    "status": "healthy",
    "active_workers": 2,
    "max_concurrent_jobs": 5
  },
  "queue": {
    "redis_status": "healthy",
    "pending_jobs": 3,
    "processing_jobs": 2,
    "total_jobs": 125
  }
}
```

**Example**:

```bash
curl "http://localhost:8000/api/v1/health"
```

---

### 6. Ping

Simple connectivity test.

**Endpoint**: `GET /api/v1/ping`

**Response**: `200 OK`

```json
{
  "status": "ok",
  "timestamp": "2025-11-12T10:30:00Z"
}
```

**Example**:

```bash
curl "http://localhost:8000/api/v1/ping"
```

---

## WebSocket API

### Connect to Job Log Stream

Stream real-time logs and status updates for a job.

**Endpoint**: `WS /ws/{job_id}`

**Connection**:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/job-abc123');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log(message);
};
```

**Message Types**:

#### 1. Connected
```json
{
  "type": "connected",
  "job_id": "job-abc123",
  "timestamp": "2025-11-12T10:30:00Z",
  "data": {
    "message": "Connected to job job-abc123",
    "status": "processing",
    "progress": 35.5
  }
}
```

#### 2. Log
```json
{
  "type": "log",
  "job_id": "job-abc123",
  "timestamp": "2025-11-12T10:30:15Z",
  "data": {
    "level": "INFO",
    "message": "Processing file: scan.json"
  }
}
```

#### 3. Progress
```json
{
  "type": "progress",
  "job_id": "job-abc123",
  "timestamp": "2025-11-12T10:30:20Z",
  "data": {
    "status": "processing",
    "progress": 45.5,
    "current_step": "Importing assets"
  }
}
```

#### 4. Complete
```json
{
  "type": "complete",
  "job_id": "job-abc123",
  "timestamp": "2025-11-12T10:32:00Z",
  "data": {
    "status": "completed",
    "progress": 100.0,
    "assets_imported": 150,
    "vulnerabilities_imported": 423,
    "assessment_name": "Q4 Scan"
  }
}
```

#### 5. Error
```json
{
  "type": "error",
  "job_id": "job-abc123",
  "timestamp": "2025-11-12T10:32:00Z",
  "data": {
    "status": "failed",
    "progress": 100.0,
    "error_message": "Failed to connect to Phoenix API"
  }
}
```

#### 6. Heartbeat
```json
{
  "type": "heartbeat",
  "timestamp": "2025-11-12T10:30:30Z"
}
```

**Client Commands**:

Send JSON commands to the WebSocket:

```json
// Ping
{"command": "ping"}

// Get current status
{"command": "get_status"}
```

**Python Example**:

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
                print(f"✅ Completed!")
                break
            elif data['type'] == 'error':
                print(f"❌ Error: {data['data']['error_message']}")
                break

asyncio.run(stream_logs("job-abc123"))
```

---

## Webhook Notifications

When you provide a `webhook_url` during upload, the service will POST status updates to that URL.

**Webhook Payload**:

```json
{
  "job_id": "job-abc123",
  "status": "completed",
  "filename": "scan.json",
  "scanner_type": "trivy",
  "success": true,
  "timestamp": "2025-11-12T10:32:00Z",
  "assets_imported": 150,
  "vulnerabilities_imported": 423,
  "assessment_name": "Q4 Scan"
}
```

**Failed Job Payload**:

```json
{
  "job_id": "job-abc123",
  "status": "failed",
  "filename": "scan.json",
  "scanner_type": "trivy",
  "success": false,
  "timestamp": "2025-11-12T10:32:00Z",
  "error": "Failed to connect to Phoenix API"
}
```

**Custom Headers**:

You can provide custom webhook headers as JSON:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "webhook_url=https://your-app.com/webhook" \
  -F 'webhook_headers={"Authorization": "Bearer token123", "X-Custom": "value"}'
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "error_type",
  "message": "Human-readable error message",
  "details": {
    "additional": "context"
  },
  "timestamp": "2025-11-12T10:30:00Z"
}
```

**Common HTTP Status Codes**:

- `200 OK`: Successful GET request
- `202 Accepted`: Upload accepted, processing queued
- `204 No Content`: Successful DELETE
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Missing API key
- `403 Forbidden`: Invalid API key
- `404 Not Found`: Resource not found
- `413 Payload Too Large`: File exceeds max size
- `500 Internal Server Error`: Server error

---

## Rate Limiting

Currently no rate limiting is enforced. Consider implementing rate limiting at the reverse proxy level for production deployments.

---

## Interactive Documentation

Visit these URLs for interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json



