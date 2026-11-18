"""process_scan_file must not loop on a job whose worker was killed (task_reject_on_worker_lost requeues it).

A redelivered job still in PROCESSING was started by an attempt that never finished, so it is failed.
A redelivered job that never started is not treated as a crash.

Runs the real Celery task (apply(), eager) against a temporary SQLite job database; the importer is mocked."""
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

LOADER_ROOT = Path(__file__).resolve().parents[2]
if str(LOADER_ROOT) not in sys.path:
    sys.path.insert(0, str(LOADER_ROOT))

from app.models.database import Base, Job
from app.models.schemas import JobStatus
from app.services.job_manager import job_manager
from app.workers import tasks


@pytest.fixture
def run_job(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'jobs.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(job_manager, "log_dir", tmp_path / "logs")
    (tmp_path / "logs").mkdir()
    monkeypatch.setattr(tasks, "_create_temp_config", lambda job, logger: None)

    def run(status, redelivered, progress=0.0):
        scan = tmp_path / "scan.json"
        scan.write_text("{}")
        db = session_factory()
        db.add(Job(job_id="job-1", status=status.value, created_at=datetime.utcnow(), filename=scan.name,
                   file_path=str(scan), file_size_bytes=2, import_type="new", progress=progress))
        db.commit()
        db.close()

        if redelivered:
            # apply() builds its own request and cannot set delivery_info['redelivered']
            stack = tasks.process_scan_file.request_stack
            push = stack.push

            def push_redelivered(request):
                request.delivery_info = {"redelivered": True}
                return push(request)

            monkeypatch.setattr(stack, "push", push_redelivered)

        manager = MagicMock()
        manager.return_value.process_scanner_file_enhanced.return_value = {
            "success": True, "assets_imported": 1, "vulnerabilities_imported": 2}
        with patch("phoenix_multi_scanner_enhanced.EnhancedMultiScannerImportManager", manager):
            tasks.process_scan_file.apply(args=["job-1"])

        db = session_factory()
        job = db.query(Job).filter(Job.job_id == "job-1").first()
        db.expunge(job)
        db.close()
        return job, manager.return_value.process_scanner_file_enhanced, scan

    return run


def test_redelivered_job_that_was_in_the_importer_is_failed_without_running(run_job):
    job, importer, scan = run_job(JobStatus.PROCESSING, redelivered=True, progress=30.0)
    assert job.status == JobStatus.FAILED.value
    assert "not retrying" in job.error_message
    importer.assert_not_called()
    assert not scan.exists()


@pytest.mark.parametrize("status", [JobStatus.COMPLETED, JobStatus.FAILED])
def test_redelivered_finished_job_is_not_imported_again(run_job, status):
    job, importer, _ = run_job(status, redelivered=True)
    assert job.status == status.value
    importer.assert_not_called()


@pytest.mark.parametrize("status, progress", [(JobStatus.PENDING, 0.0), (JobStatus.PROCESSING, 10.0)])
def test_redelivered_job_that_never_reached_the_importer_runs_normally(run_job, status, progress):
    job, importer, _ = run_job(status, redelivered=True, progress=progress)
    assert job.status == JobStatus.COMPLETED.value
    importer.assert_called_once()
