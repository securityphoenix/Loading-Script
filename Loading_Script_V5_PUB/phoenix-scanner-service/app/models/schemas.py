"""Pydantic models for API request/response schemas"""
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator


class JobStatus(str, Enum):
    """Job status enumeration"""
    PENDING = "pending"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerType(str, Enum):
    """Supported scanner types (extensible)"""
    AUTO = "auto"
    # Phoenix Native CSV
    PHOENIX_CSV = "phoenix_csv"
    PHOENIX_CSV_INFRA = "phoenix_csv_infra"
    PHOENIX_CSV_CLOUD = "phoenix_csv_cloud"
    PHOENIX_CSV_WEB = "phoenix_csv_web"
    PHOENIX_CSV_SOFTWARE = "phoenix_csv_software"
    # Rapid7
    RAPID7_CSV = "rapid7_csv"
    # Common Scanners
    TENABLE = "tenable"
    QUALYS = "qualys"
    AQUA = "aqua"
    TRIVY = "trivy"
    GRYPE = "grype"
    JFROG = "jfrog"
    BLACKDUCK = "blackduck"
    PROWLER = "prowler"
    SONARQUBE = "sonarqube"
    CHECKMARX = "checkmarx"
    BURP = "burp"
    SNYK = "snyk"
    # Add more as needed - supports 200+ scanners via YAML config


class AssetType(str, Enum):
    """Asset type enumeration"""
    INFRA = "INFRA"
    WEB = "WEB"
    CLOUD = "CLOUD"
    CONTAINER = "CONTAINER"
    REPOSITORY = "REPOSITORY"
    CODE = "CODE"
    BUILD = "BUILD"


class ImportType(str, Enum):
    """Import type enumeration"""
    NEW = "new"
    MERGE = "merge"
    DELTA = "delta"


class PhoenixCredentials(BaseModel):
    """Phoenix API credentials"""
    client_id: str = Field(..., description="Phoenix API client ID")
    client_secret: str = Field(..., description="Phoenix API client secret")
    api_base_url: str = Field(..., description="Phoenix API base URL")


class ScanUploadRequest(BaseModel):
    """Request model for scan file upload"""
    scanner_type: str = Field(default="auto", description="Scanner type (auto-detect or specific)")
    asset_type: Optional[AssetType] = Field(None, description="Override asset type")
    assessment_name: Optional[str] = Field(None, description="Assessment name (auto-generated if not provided)")
    import_type: ImportType = Field(default=ImportType.NEW, description="Import type")
    
    # Phoenix credentials (can be provided per request or use defaults from config)
    phoenix_client_id: Optional[str] = Field(None, description="Phoenix API client ID")
    phoenix_client_secret: Optional[str] = Field(None, description="Phoenix API client secret")
    phoenix_api_url: Optional[str] = Field(None, description="Phoenix API base URL")
    
    # Processing options
    enable_batching: bool = Field(default=True, description="Enable intelligent batching")
    fix_data: bool = Field(default=True, description="Automatically fix data issues")
    anonymize: bool = Field(default=False, description="Anonymize sensitive data")
    just_tags: bool = Field(default=False, description="Only add tags, do not import")
    create_empty_assets: bool = Field(default=False, description="Zero vulnerability risk (testing mode)")
    create_inventory_assets: bool = Field(default=False, description="Create assets with zero risk if no vulnerabilities")
    
    # Advanced options
    max_batch_size: Optional[int] = Field(None, description="Override max batch size")
    max_payload_mb: Optional[float] = Field(None, description="Override max payload size")
    
    # Webhook configuration
    webhook_url: Optional[str] = Field(None, description="Webhook URL for status updates")
    webhook_headers: Optional[Dict[str, str]] = Field(None, description="Custom headers for webhook")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scanner_type": "trivy",
                "asset_type": "CONTAINER",
                "assessment_name": "Q4 Container Scan",
                "import_type": "new",
                "phoenix_client_id": "your-client-id",
                "phoenix_client_secret": "your-secret",
                "phoenix_api_url": "https://phoenix.example.com/api",
                "enable_batching": True,
                "fix_data": True
            }
        }


class JobResponse(BaseModel):
    """Response model for job submission"""
    job_id: str = Field(..., description="Unique job identifier")
    status: JobStatus = Field(..., description="Current job status")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="Job creation timestamp")
    websocket_url: str = Field(..., description="WebSocket URL for real-time updates")


class JobStatusResponse(BaseModel):
    """Response model for job status query"""
    job_id: str
    status: JobStatus
    progress: float = Field(..., ge=0.0, le=100.0, description="Progress percentage")
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # File information
    filename: str
    file_size_bytes: int
    scanner_type: Optional[str] = None
    
    # Results (when completed)
    assets_imported: Optional[int] = None
    vulnerabilities_imported: Optional[int] = None
    assessment_name: Optional[str] = None
    
    # Error information (when failed)
    error_message: Optional[str] = None
    error_traceback: Optional[str] = None
    
    # Batch information
    batch_summary: Optional[Dict[str, Any]] = None
    
    # Logs (last N lines)
    recent_logs: List[str] = Field(default_factory=list, description="Recent log lines")


class JobListResponse(BaseModel):
    """Response model for listing jobs"""
    total: int
    jobs: List[JobStatusResponse]
    page: int = 1
    page_size: int = 50


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(..., description="Current server time")
    workers: Dict[str, Any] = Field(..., description="Worker pool status")
    queue: Dict[str, Any] = Field(..., description="Queue statistics")


class WebSocketMessage(BaseModel):
    """WebSocket message format"""
    type: str = Field(..., description="Message type: log, status, progress, error, complete")
    job_id: str = Field(..., description="Job identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = Field(..., description="Message payload")
    
    class Config:
        json_schema_extra = {
            "example": {
                "type": "log",
                "job_id": "job-123",
                "timestamp": "2025-11-12T10:30:00Z",
                "data": {
                    "level": "INFO",
                    "message": "Processing file: scan.json"
                }
            }
        }


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)



