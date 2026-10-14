"""Database models for job tracking"""
import json
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

Base = declarative_base()


class Job(Base):
    """Job model for tracking scan processing jobs"""
    __tablename__ = "jobs"
    
    # Primary key
    job_id = Column(String(64), primary_key=True, index=True)
    
    # Status and timestamps
    status = Column(String(20), nullable=False, index=True, default="pending")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # File information
    filename = Column(String(512), nullable=False)
    file_path = Column(String(1024), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    
    # Scanner configuration
    scanner_type = Column(String(64), nullable=True)
    asset_type = Column(String(32), nullable=True)
    assessment_name = Column(String(256), nullable=True)
    import_type = Column(String(20), nullable=False, default="new")
    
    # Phoenix credentials (encrypted in production)
    phoenix_client_id = Column(String(256), nullable=True)
    phoenix_api_url = Column(String(512), nullable=True)
    
    # Processing options (stored as JSON)
    processing_options = Column(Text, nullable=True)
    
    # Progress tracking
    progress = Column(Float, nullable=False, default=0.0)
    current_step = Column(String(256), nullable=True)
    
    # Results (when completed)
    assets_imported = Column(Integer, nullable=True)
    vulnerabilities_imported = Column(Integer, nullable=True)
    batch_summary = Column(Text, nullable=True)  # JSON
    
    # Error information
    error_message = Column(Text, nullable=True)
    error_traceback = Column(Text, nullable=True)
    
    # Webhook configuration
    webhook_url = Column(String(1024), nullable=True)
    webhook_headers = Column(Text, nullable=True)  # JSON
    webhook_last_sent = Column(DateTime, nullable=True)
    
    # Celery task ID
    task_id = Column(String(64), nullable=True, index=True)
    
    # Worker information
    worker_name = Column(String(128), nullable=True)
    worker_hostname = Column(String(256), nullable=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary"""
        return {
            "job_id": self.job_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "filename": self.filename,
            "file_size_bytes": self.file_size_bytes,
            "scanner_type": self.scanner_type,
            "asset_type": self.asset_type,
            "assessment_name": self.assessment_name,
            "progress": self.progress,
            "current_step": self.current_step,
            "assets_imported": self.assets_imported,
            "vulnerabilities_imported": self.vulnerabilities_imported,
            "batch_summary": json.loads(self.batch_summary) if self.batch_summary else None,
            "error_message": self.error_message,
        }


# Database setup
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



