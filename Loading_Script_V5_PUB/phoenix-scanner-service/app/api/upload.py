"""File upload API endpoints"""
import logging
from fastapi import APIRouter, Depends, File, UploadFile, Form, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Optional

from app.core.security import verify_api_key
from app.core.config import settings
from app.models.database import get_db
from app.models.schemas import (
    ScanUploadRequest, JobResponse, JobStatus, 
    AssetType, ImportType, ErrorResponse
)
from app.services.job_manager import job_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Upload"])


@router.post(
    "/upload",
    response_model=JobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload scanner file for processing",
    description="Upload a scanner output file (JSON, CSV, XML) for processing and import to Phoenix Security"
)
async def upload_scan_file(
    file: UploadFile = File(..., description="Scanner output file"),
    scanner_type: str = Form(default="auto", description="Scanner type (auto or specific type)"),
    asset_type: Optional[str] = Form(None, description="Asset type override"),
    assessment_name: Optional[str] = Form(None, description="Assessment name"),
    import_type: str = Form(default="new", description="Import type: new, merge, or delta"),
    phoenix_client_id: Optional[str] = Form(None, description="Phoenix API client ID"),
    phoenix_client_secret: Optional[str] = Form(None, description="Phoenix API client secret"),
    phoenix_api_url: Optional[str] = Form(None, description="Phoenix API URL"),
    enable_batching: bool = Form(default=True, description="Enable batching"),
    fix_data: bool = Form(default=True, description="Fix data issues"),
    anonymize: bool = Form(default=False, description="Anonymize data"),
    just_tags: bool = Form(default=False, description="Only process tags"),
    create_empty_assets: bool = Form(default=False, description="Create empty assets"),
    create_inventory_assets: bool = Form(default=False, description="Create inventory assets"),
    max_batch_size: Optional[int] = Form(None, description="Max batch size"),
    max_payload_mb: Optional[float] = Form(None, description="Max payload MB"),
    webhook_url: Optional[str] = Form(None, description="Webhook URL for status updates"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload a scanner output file for processing.
    
    The file will be queued for processing and you will receive a job ID.
    Use the job ID to:
    - Query status via GET /api/v1/jobs/{job_id}
    - Stream logs via WebSocket ws://host/ws/{job_id}
    
    **Supported scanners**: 200+ types including Trivy, Grype, Qualys, Tenable, 
    Prowler, SonarQube, Checkmarx, Burp, Snyk, and many more.
    """
    
    # Validate file size
    max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    file_size = 0
    
    # Validate file extension
    file_ext = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
    if f".{file_ext}" not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Supported: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )
    
    try:
        # Build request object
        upload_request = ScanUploadRequest(
            scanner_type=scanner_type,
            asset_type=AssetType(asset_type) if asset_type else None,
            assessment_name=assessment_name,
            import_type=ImportType(import_type),
            phoenix_client_id=phoenix_client_id,
            phoenix_client_secret=phoenix_client_secret,
            phoenix_api_url=phoenix_api_url,
            enable_batching=enable_batching,
            fix_data=fix_data,
            anonymize=anonymize,
            just_tags=just_tags,
            create_empty_assets=create_empty_assets,
            create_inventory_assets=create_inventory_assets,
            max_batch_size=max_batch_size,
            max_payload_mb=max_payload_mb,
            webhook_url=webhook_url
        )
        
        # Create job
        job = await job_manager.create_job(db, file, upload_request)
        
        # Queue job for processing with Celery
        from app.workers.tasks import process_scan_file
        task = process_scan_file.delay(job.job_id)
        
        # Update job with task ID
        job_manager.update_job_status(
            db, 
            job.job_id, 
            JobStatus.QUEUED,
            task_id=task.id
        )
        
        logger.info(f"✅ Job {job.job_id} queued with task {task.id}")
        
        # Build WebSocket URL
        ws_protocol = "wss" if "https" in settings.API_HOST else "ws"
        ws_url = f"{ws_protocol}://{settings.API_HOST}:{settings.API_PORT}/ws/{job.job_id}"
        
        return JobResponse(
            job_id=job.job_id,
            status=JobStatus(job.status),
            message=f"File uploaded successfully. Job queued for processing.",
            created_at=job.created_at,
            websocket_url=ws_url
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )
