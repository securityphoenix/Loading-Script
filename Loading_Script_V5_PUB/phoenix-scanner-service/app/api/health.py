"""Health check and monitoring endpoints"""
import logging
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.database import get_db
from app.models.schemas import HealthResponse
from app.services.job_manager import job_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check service health and get system status"
)
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint that returns:
    - Service status
    - Version information
    - Worker pool status
    - Queue statistics
    - Database connectivity
    """
    
    # Check database
    try:
        db.execute("SELECT 1")
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"
    
    # Check Redis/Celery (will be implemented in Phase 2)
    redis_status = "not_configured"
    worker_status = "not_configured"
    active_workers = 0
    
    try:
        from app.workers.celery_app import celery_app
        inspector = celery_app.control.inspect()
        
        # Check active workers
        active = inspector.active()
        if active:
            active_workers = len(active.keys())
            worker_status = "healthy"
        else:
            worker_status = "no_workers"
        
        redis_status = "healthy"
    except Exception as e:
        logger.warning(f"Worker health check failed: {e}")
        worker_status = "error"
    
    # Get queue statistics
    pending_jobs = job_manager.count_jobs(db, status="pending")
    processing_jobs = job_manager.count_jobs(db, status="processing")
    total_jobs = job_manager.count_jobs(db)
    
    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        version=settings.API_VERSION,
        timestamp=datetime.utcnow(),
        workers={
            "status": worker_status,
            "active_workers": active_workers,
            "max_concurrent_jobs": settings.MAX_CONCURRENT_JOBS
        },
        queue={
            "redis_status": redis_status,
            "pending_jobs": pending_jobs,
            "processing_jobs": processing_jobs,
            "total_jobs": total_jobs
        }
    )


@router.get(
    "/ping",
    summary="Simple ping endpoint",
    description="Basic connectivity test"
)
async def ping():
    """Simple ping endpoint for connectivity testing"""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}



