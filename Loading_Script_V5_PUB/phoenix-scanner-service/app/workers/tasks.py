"""Celery tasks for scanner file processing"""
import os
import sys
import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from celery import Task
from app.workers.celery_app import celery_app
from app.core.config import settings
from app.models.database import SessionLocal
from app.models.schemas import JobStatus
from app.services.job_manager import job_manager
from app.file_cleanup import delete_upload_file

logger = logging.getLogger(__name__)


class CallbackTask(Task):
    """Base task with callbacks for job status updates"""
    
    def __init__(self):
        super().__init__()
        self.db = None
        self.job_id = None
        self.log_file = None
    
    def before_start(self, task_id, args, kwargs):
        """Called before task starts"""
        self.db = SessionLocal()
        self.job_id = args[0] if args else None
        
        if self.job_id:
            # Set up logging to file
            log_path = job_manager.get_log_file_path(self.job_id)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            )
            
            task_logger = logging.getLogger(f"task.{self.job_id}")
            task_logger.addHandler(file_handler)
            task_logger.setLevel(logging.DEBUG)
            
            self.log_file = log_path
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called when task succeeds"""
        if self.db:
            self.db.close()
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails"""
        if self.db and self.job_id:
            job_manager.update_job_status(
                self.db,
                self.job_id,
                JobStatus.FAILED,
                error_message=str(exc),
                error_traceback=str(einfo)
            )
        
        if self.db:
            self.db.close()


@celery_app.task(base=CallbackTask, bind=True, name="process_scan_file")
def process_scan_file(self, job_id: str) -> Dict[str, Any]:
    """
    Process a scanner file and import to Phoenix Security.
    
    Args:
        job_id: The job identifier
    
    Returns:
        Dictionary with processing results
    """
    task_logger = logging.getLogger(f"task.{job_id}")
    task_logger.info(f"🚀 Starting processing for job {job_id}")

    upload_file_path = None  # captured before try so finally can always access it
    config_file = None  # captured before try so finally can always access it

    try:
        # Get job from database
        job = job_manager.get_job(self.db, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        upload_file_path = job.file_path
        
        # Update job status to processing
        job_manager.update_job_status(
            self.db,
            job_id,
            JobStatus.PROCESSING,
            task_id=self.request.id,
            worker_name=self.request.hostname
        )
        
        task_logger.info(f"📄 Processing file: {job.filename}")
        task_logger.info(f"   Scanner type: {job.scanner_type or 'auto-detect'}")
        task_logger.info(f"   Import type: {job.import_type}")
        
        # Parse processing options
        processing_options = json.loads(job.processing_options) if job.processing_options else {}
        
        # Update progress
        job_manager.update_job_progress(self.db, job_id, 10.0, "Initializing Phoenix importer")
        
        # Add /parent directory to path to import phoenix_multi_scanner_enhanced
        # The phoenix scanner files are copied to /parent during Docker build
        sys.path.insert(0, '/parent')
        
        # Import Phoenix scanner (deferred to avoid startup hang)
        task_logger.info("📦 Importing Phoenix Multi-Scanner module...")
        from phoenix_multi_scanner_enhanced import EnhancedMultiScannerImportManager
        
        # Create configuration file with Phoenix credentials
        config_file = _create_temp_config(job, task_logger)
        
        # Update progress
        job_manager.update_job_progress(self.db, job_id, 20.0, "Loading scanner configuration")
        
        # Initialize Phoenix importer
        task_logger.info("🔧 Initializing Phoenix importer...")
        manager = EnhancedMultiScannerImportManager(config_file)
        
        # Update progress
        job_manager.update_job_progress(self.db, job_id, 30.0, "Processing scanner file")
        
        # Process the file
        task_logger.info(f"🔍 Processing scanner file: {job.file_path}")
        result = manager.process_scanner_file_enhanced(
            file_path=job.file_path,
            scanner_type=job.scanner_type if job.scanner_type != 'auto' else None,
            asset_type=job.asset_type,
            assessment_name=job.assessment_name,
            import_type=job.import_type,
            anonymize=processing_options.get('anonymize', False),
            just_tags=processing_options.get('just_tags', False),
            create_empty_assets=processing_options.get('create_empty_assets', False),
            create_inventory_assets=processing_options.get('create_inventory_assets', False),
            enable_batching=processing_options.get('enable_batching', True),
            fix_data=processing_options.get('fix_data', True)
        )
        
        # Update progress
        job_manager.update_job_progress(self.db, job_id, 90.0, "Finalizing import")
        
        # Process result
        if result.get('success'):
            task_logger.info("✅ Processing completed successfully")
            task_logger.info(f"   Assets imported: {result.get('assets_imported', 0)}")
            task_logger.info(f"   Vulnerabilities: {result.get('vulnerabilities_imported', 0)}")
            
            # Update job with results
            job_manager.update_job_status(
                self.db,
                job_id,
                JobStatus.COMPLETED,
                progress=100.0,
                current_step="Completed",
                assets_imported=result.get('assets_imported', 0),
                vulnerabilities_imported=result.get('vulnerabilities_imported', 0),
                assessment_name=result.get('assessment_name'),
                scanner_type=result.get('scanner_type', job.scanner_type),
                batch_summary=json.dumps(result.get('batch_summary')) if result.get('batch_summary') else None
            )
            
            # Send webhook notification if configured
            if job.webhook_url:
                _send_webhook_notification(job, result, task_logger)
            
            return result
        else:
            # Processing failed
            error_msg = result.get('error', 'Unknown error')
            task_logger.error(f"❌ Processing failed: {error_msg}")
            
            job_manager.update_job_status(
                self.db,
                job_id,
                JobStatus.FAILED,
                error_message=error_msg,
                progress=100.0,
                current_step="Failed"
            )
            
            # Send webhook notification
            if job.webhook_url:
                _send_webhook_notification(job, result, task_logger)
            
            raise RuntimeError(error_msg)
    
    except Exception as e:
        task_logger.error(f"❌ Task failed with exception: {e}")
        task_logger.error(traceback.format_exc())
        
        # Update job status
        job_manager.update_job_status(
            self.db,
            job_id,
            JobStatus.FAILED,
            error_message=str(e),
            error_traceback=traceback.format_exc(),
            progress=100.0,
            current_step="Failed"
        )
        
        # Send webhook notification
        job = job_manager.get_job(self.db, job_id)
        if job and job.webhook_url:
            _send_webhook_notification(job, {'success': False, 'error': str(e)}, task_logger)
        
        raise

    finally:
        delete_upload_file(upload_file_path)
        if config_file and os.path.exists(config_file):
            try:
                os.unlink(config_file)
                task_logger.info(f"Deleted temporary config: {config_file}")
            except OSError as e:
                task_logger.warning(f"Could not delete temporary config {config_file}: {e}")


def _create_temp_config(job, logger) -> str:
    """
    Create temporary configuration file with Phoenix credentials.
    
    This function:
    1. Loads base config from config_multi_scanner.ini
    2. Overrides with job-specific parameters from API request
    3. Allows API parameters to override: client_id, import_type, assessment_name, api_base_url, scanner_type
    """
    import tempfile
    import configparser
    
    config = configparser.ConfigParser()
    
    # Load base config_multi_scanner.ini if exists
    base_config_path = Path(settings.PHOENIX_CONFIG_FILE)
    
    # Try multiple paths to find config file
    config_paths = [
        base_config_path,
        Path("/parent/config_multi_scanner.ini"),
        Path("../config_multi_scanner.ini"),
        Path("config_multi_scanner.ini"),
    ]
    
    config_loaded = False
    for config_path in config_paths:
        if config_path.exists():
            logger.info(f"📋 Loading base configuration from: {config_path}")
            config.read(config_path)
            config_loaded = True
            break
    
    if not config_loaded:
        logger.warning(f"⚠️ Base config file not found, using defaults")
    
    # Ensure phoenix section exists
    if 'phoenix' not in config:
        config['phoenix'] = {}
    
    # ============================================================================
    # OVERRIDE with job-specific parameters (API parameters take precedence)
    # ============================================================================
    
    # 1. Client ID - Override if provided in API request
    if job.phoenix_client_id:
        logger.info(f"   Overriding client_id from API request")
        config['phoenix']['client_id'] = job.phoenix_client_id
    elif not config['phoenix'].get('client_id'):
        logger.warning("⚠️ No client_id provided (neither in config nor API request)")
    
    # 2. API Base URL - Override if provided in API request
    if job.phoenix_api_url:
        logger.info(f"   Overriding api_base_url from API request: {job.phoenix_api_url}")
        config['phoenix']['api_base_url'] = job.phoenix_api_url
    elif not config['phoenix'].get('api_base_url'):
        logger.warning("⚠️ No api_base_url provided (neither in config nor API request)")
    
    # 3. Import Type - Override if provided in API request
    if job.import_type:
        logger.info(f"   Overriding import_type from API request: {job.import_type}")
        config['phoenix']['import_type'] = job.import_type
    else:
        # Use default from config file or fallback to 'new'
        config['phoenix'].setdefault('import_type', 'new')
    
    # 4. Assessment Name - Override if provided in API request
    if job.assessment_name:
        logger.info(f"   Overriding assessment_name from API request: {job.assessment_name}")
        config['phoenix']['assessment_name'] = job.assessment_name
    elif not config['phoenix'].get('assessment_name'):
        # Will be auto-generated by scanner if not provided
        config['phoenix']['assessment_name'] = ''
    
    # 5. Scanner Type - Use from job (already specified during upload)
    if job.scanner_type and job.scanner_type != 'auto':
        logger.info(f"   Using scanner_type from API request: {job.scanner_type}")
        # Scanner type is passed directly to phoenix_multi_scanner_enhanced.py
        # Not needed in config file
    
    # 6. Asset Type - Override if provided in API request
    if job.asset_type:
        logger.info(f"   Using asset_type from API request: {job.asset_type}")
        config['phoenix']['scan_type'] = job.asset_type
    else:
        # Use default from config or fallback
        config['phoenix'].setdefault('scan_type', 'INFRA')
    
    # Get client_secret from environment variable or job data
    # Priority: 1) Environment variable 2) Config file
    client_secret = os.getenv('PHOENIX_CLIENT_SECRET', '')
    if client_secret:
        logger.info("   Using client_secret from environment variable")
        config['phoenix']['client_secret'] = client_secret
    elif not config['phoenix'].get('client_secret'):
        logger.error("❌ No client_secret provided (neither in environment nor config)")
        raise ValueError("Phoenix client_secret is required (set PHOENIX_CLIENT_SECRET environment variable)")
    
    # Set other defaults from config_multi_scanner.ini or use sensible defaults
    config['phoenix'].setdefault('auto_import', 'true')
    config['phoenix'].setdefault('wait_for_completion', 'true')
    config['phoenix'].setdefault('batch_delay', '5')
    config['phoenix'].setdefault('timeout', '3600')
    config['phoenix'].setdefault('check_interval', '10')
    
    # Write to temporary file
    fd, temp_path = tempfile.mkstemp(suffix='.ini', prefix='phoenix_config_')
    os.close(fd)
    
    with open(temp_path, 'w') as f:
        config.write(f)
    
    logger.info(f"✅ Created temporary config: {temp_path}")
    logger.info(f"   Final configuration:")
    logger.info(f"     - client_id: {config['phoenix'].get('client_id', 'NOT SET')[:20]}...")
    logger.info(f"     - api_base_url: {config['phoenix'].get('api_base_url', 'NOT SET')}")
    logger.info(f"     - import_type: {config['phoenix'].get('import_type', 'NOT SET')}")
    logger.info(f"     - assessment_name: {config['phoenix'].get('assessment_name', 'AUTO-GENERATED')}")
    logger.info(f"     - scan_type: {config['phoenix'].get('scan_type', 'NOT SET')}")
    
    return temp_path


def _send_webhook_notification(job, result: Dict[str, Any], logger):
    """Send webhook notification about job completion"""
    import httpx
    
    try:
        webhook_url = job.webhook_url
        webhook_headers = json.loads(job.webhook_headers) if job.webhook_headers else {}
        
        payload = {
            "job_id": job.job_id,
            "status": job.status,
            "filename": job.filename,
            "scanner_type": job.scanner_type,
            "success": result.get('success', False),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if result.get('success'):
            payload.update({
                "assets_imported": result.get('assets_imported', 0),
                "vulnerabilities_imported": result.get('vulnerabilities_imported', 0),
                "assessment_name": result.get('assessment_name'),
            })
        else:
            payload['error'] = result.get('error', 'Unknown error')
        
        logger.info(f"📡 Sending webhook notification to {webhook_url}")
        
        response = httpx.post(
            webhook_url,
            json=payload,
            headers=webhook_headers,
            timeout=30.0
        )
        
        if response.status_code < 300:
            logger.info(f"✅ Webhook sent successfully (status: {response.status_code})")
        else:
            logger.warning(f"⚠️ Webhook returned status {response.status_code}: {response.text}")
    
    except Exception as e:
        logger.error(f"❌ Failed to send webhook notification: {e}")

