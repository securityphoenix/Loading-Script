"""Job management API endpoints"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from app.core.security import verify_api_key
from app.models.database import get_db
from app.models.schemas import JobStatusResponse, JobListResponse, JobStatus
from app.services.job_manager import job_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/jobs", tags=["Jobs"])


@router.get(
    "/{job_id}",
    response_model=JobStatusResponse,
    summary="Get job status",
    description="Retrieve the current status and details of a processing job"
)
async def get_job_status(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Get detailed status of a job by ID.
    
    Returns:
    - Current status (pending, queued, processing, completed, failed)
    - Progress percentage
    - Timestamps
    - Results (when completed)
    - Error information (when failed)
    - Recent log lines
    """
    job = job_manager.get_job(db, job_id)
    
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found"
        )
    
    # Read recent logs
    recent_logs = []
    log_file = job_manager.get_log_file_path(job_id)
    if log_file.exists():
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                recent_logs = [line.strip() for line in lines[-50:]]  # Last 50 lines
        except Exception as e:
            logger.warning(f"Failed to read log file: {e}")
    
    return JobStatusResponse(
        job_id=job.job_id,
        status=JobStatus(job.status),
        progress=job.progress,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        filename=job.filename,
        file_size_bytes=job.file_size_bytes,
        scanner_type=job.scanner_type,
        assets_imported=job.assets_imported,
        vulnerabilities_imported=job.vulnerabilities_imported,
        assessment_name=job.assessment_name,
        error_message=job.error_message,
        error_traceback=job.error_traceback,
        batch_summary=job.to_dict().get('batch_summary'),
        recent_logs=recent_logs
    )


@router.get(
    "",
    response_model=JobListResponse,
    summary="List jobs",
    description="List all jobs with optional filtering and pagination"
)
async def list_jobs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    List all jobs with pagination.
    
    Optional filters:
    - status: Filter by job status (pending, queued, processing, completed, failed)
    """
    skip = (page - 1) * page_size
    
    jobs = job_manager.list_jobs(db, skip=skip, limit=page_size, status=status)
    total = job_manager.count_jobs(db, status=status)
    
    job_responses = []
    for job in jobs:
        job_responses.append(
            JobStatusResponse(
                job_id=job.job_id,
                status=JobStatus(job.status),
                progress=job.progress,
                created_at=job.created_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
                filename=job.filename,
                file_size_bytes=job.file_size_bytes,
                scanner_type=job.scanner_type,
                assets_imported=job.assets_imported,
                vulnerabilities_imported=job.vulnerabilities_imported,
                assessment_name=job.assessment_name,
                error_message=job.error_message,
                recent_logs=[]  # Don't load logs for list view
            )
        )
    
    return JobListResponse(
        total=total,
        jobs=job_responses,
        page=page,
        page_size=page_size
    )


@router.delete(
    "/{job_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel job",
    description="Cancel a pending or processing job"
)
async def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Cancel a job that is pending or processing.
    
    Note: Jobs that are already completed or failed cannot be cancelled.
    """
    job = job_manager.get_job(db, job_id)
    
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found"
        )
    
    if job.status in [JobStatus.COMPLETED.value, JobStatus.FAILED.value, JobStatus.CANCELLED.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job with status {job.status}"
        )
    
    # Cancel Celery task if exists
    if job.task_id:
        from app.workers.celery_app import celery_app
        celery_app.control.revoke(job.task_id, terminate=True)
    
    job_manager.update_job_status(db, job_id, JobStatus.CANCELLED)
    
    logger.info(f"Job {job_id} cancelled")
    return None



