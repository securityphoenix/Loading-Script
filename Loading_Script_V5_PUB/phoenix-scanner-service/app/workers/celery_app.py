"""Celery application configuration"""
from celery import Celery
from celery.signals import task_prerun, task_postrun, task_failure
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "phoenix_scanner_service",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"]
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.JOB_TIMEOUT,
    task_soft_time_limit=settings.JOB_TIMEOUT - 60,  # Warn 1 minute before hard limit
    worker_prefetch_multiplier=1,  # Only fetch one task at a time
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks (prevent memory leaks)
    task_acks_late=True,  # Acknowledge task after completion
    task_reject_on_worker_lost=True,  # Requeue task if worker dies
    result_expires=86400,  # Results expire after 24 hours
    broker_connection_retry_on_startup=True,
)


# Task event handlers
@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **extra):
    """Called before task execution"""
    logger.info(f"📋 Task {task.name} [{task_id}] starting with args: {args}")


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, **extra):
    """Called after successful task execution"""
    logger.info(f"✅ Task {task.name} [{task_id}] completed successfully")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, args=None, kwargs=None, traceback=None, einfo=None, **extra):
    """Called when task fails"""
    logger.error(f"❌ Task {sender.name} [{task_id}] failed: {exception}")
    logger.debug(f"Traceback: {traceback}")



