"""Job management service"""
import os
import uuid
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from fastapi import UploadFile

from app.core.config import settings
from app.models.database import Job
from app.models.schemas import JobStatus, ScanUploadRequest

logger = logging.getLogger(__name__)


class JobManager:
    """Manages job lifecycle and database operations"""
    
    def __init__(self):
        self.upload_dir = Path(settings.UPLOAD_DIR)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_dir = Path(settings.LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    async def create_job(
        self, 
        db: Session, 
        file: UploadFile, 
        request: ScanUploadRequest
    ) -> Job:
        """Create a new job from file upload"""
        
        # Generate unique job ID
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        
        # Save uploaded file
        file_path = self.upload_dir / f"{job_id}_{file.filename}"
        file_size = 0
        
        try:
            with open(file_path, "wb") as f:
                content = await file.read()
                f.write(content)
                file_size = len(content)
        except Exception as e:
            logger.error(f"Failed to save uploaded file: {e}")
            raise
        
        # Create job record
        job = Job(
            job_id=job_id,
            status=JobStatus.PENDING.value,
            created_at=datetime.utcnow(),
            filename=file.filename,
            file_path=str(file_path),
            file_size_bytes=file_size,
            scanner_type=request.scanner_type,
            asset_type=request.asset_type.value if request.asset_type else None,
            assessment_name=request.assessment_name,
            import_type=request.import_type.value,
            phoenix_client_id=request.phoenix_client_id,
            phoenix_api_url=request.phoenix_api_url,
            processing_options=json.dumps({
                "enable_batching": request.enable_batching,
                "fix_data": request.fix_data,
                "anonymize": request.anonymize,
                "just_tags": request.just_tags,
                "create_empty_assets": request.create_empty_assets,
                "create_inventory_assets": request.create_inventory_assets,
                "max_batch_size": request.max_batch_size,
                "max_payload_mb": request.max_payload_mb,
            }),
            webhook_url=request.webhook_url,
            webhook_headers=json.dumps(request.webhook_headers) if request.webhook_headers else None,
            progress=0.0,
        )
        
        db.add(job)
        db.commit()
        db.refresh(job)
        
        logger.info(f"Created job {job_id} for file {file.filename}")
        return job
    
    def get_job(self, db: Session, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        return db.query(Job).filter(Job.job_id == job_id).first()
    
    def list_jobs(
        self, 
        db: Session, 
        skip: int = 0, 
        limit: int = 50,
        status: Optional[str] = None
    ) -> List[Job]:
        """List jobs with pagination"""
        query = db.query(Job).order_by(Job.created_at.desc())
        
        if status:
            query = query.filter(Job.status == status)
        
        return query.offset(skip).limit(limit).all()
    
    def count_jobs(self, db: Session, status: Optional[str] = None) -> int:
        """Count total jobs"""
        query = db.query(Job)
        if status:
            query = query.filter(Job.status == status)
        return query.count()
    
    def update_job_status(
        self, 
        db: Session, 
        job_id: str, 
        status: JobStatus,
        **kwargs
    ) -> Optional[Job]:
        """Update job status and other fields"""
        job = self.get_job(db, job_id)
        if not job:
            return None
        
        job.status = status.value
        
        # Update timestamp based on status
        if status == JobStatus.PROCESSING and not job.started_at:
            job.started_at = datetime.utcnow()
        elif status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            job.completed_at = datetime.utcnow()
        
        # Update other fields
        for key, value in kwargs.items():
            if hasattr(job, key):
                setattr(job, key, value)
        
        db.commit()
        db.refresh(job)
        
        logger.info(f"Updated job {job_id} status to {status.value}")
        return job
    
    def update_job_progress(
        self, 
        db: Session, 
        job_id: str, 
        progress: float,
        current_step: Optional[str] = None
    ) -> Optional[Job]:
        """Update job progress"""
        job = self.get_job(db, job_id)
        if not job:
            return None
        
        job.progress = min(max(progress, 0.0), 100.0)
        if current_step:
            job.current_step = current_step
        
        db.commit()
        db.refresh(job)
        
        return job
    
    def cleanup_old_jobs(self, db: Session, days: int = 7) -> int:
        """Clean up old completed/failed jobs"""
        from datetime import timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Delete old jobs
        deleted = db.query(Job).filter(
            Job.completed_at < cutoff_date,
            Job.status.in_([JobStatus.COMPLETED.value, JobStatus.FAILED.value])
        ).delete()
        
        db.commit()
        
        logger.info(f"Cleaned up {deleted} old jobs")
        return deleted
    
    def get_log_file_path(self, job_id: str) -> Path:
        """Get log file path for job"""
        return self.log_dir / f"{job_id}.log"


# Global job manager instance
job_manager = JobManager()



