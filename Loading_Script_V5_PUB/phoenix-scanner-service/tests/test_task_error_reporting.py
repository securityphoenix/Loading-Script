"""process_scan_file keeps the importer's real error on the job (never "Unknown error"), writes the
importer's log lines into the job log, and releases the job log handler after success and failure.

Runs the real Celery task (apply(), eager) against a temporary SQLite job database and the real
loader; only the Phoenix HTTP calls are intercepted."""
import json
import logging
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

GRYPE = {
    "descriptor": {"name": "grype"},
    "source": {"type": "image", "target": {"userInput": "registry.example.com/app:1.0"}},
    "matches": [{
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "x",
                          "fix": {"versions": ["2.0"], "state": "fixed"}},
        "artifact": {"name": "openssl", "version": "1.0.0", "type": "deb"},
    }],
}


def http_response(status_code, body):
    response = MagicMock(status_code=status_code, text=json.dumps(body))
    response.json.return_value = body
    return response


@pytest.fixture
def run_job(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'jobs.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(job_manager, "log_dir", tmp_path / "logs")
    (tmp_path / "logs").mkdir()
    base_config = tmp_path / "base.ini"
    base_config.write_text("[phoenix]\nwait_for_completion = false\n")
    monkeypatch.setattr(tasks.settings, "PHOENIX_CONFIG_FILE", str(base_config))
    monkeypatch.setenv("PHOENIX_CLIENT_SECRET", "synthetic")
    monkeypatch.chdir(tmp_path)  # the loader writes logs/ and errors/ into the working directory

    def run(job_id, response):
        scan = tmp_path / f"{job_id}.json"
        scan.write_text(json.dumps(GRYPE))
        db = session_factory()
        db.add(Job(job_id=job_id, status=JobStatus.PENDING.value, created_at=datetime.utcnow(),
                   filename=scan.name, file_path=str(scan), file_size_bytes=scan.stat().st_size,
                   scanner_type="grype", import_type="merge",
                   assessment_name="error-reporting", phoenix_client_id="synthetic",
                   phoenix_api_url="https://phoenix.example.invalid",
                   processing_options=json.dumps({"enable_batching": True}), progress=0.0))
        db.commit()
        db.close()
        from phoenix_import_refactored import PhoenixAPIClient
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response), \
                patch("phoenix_import_enhanced.time.sleep"):
            tasks.process_scan_file.apply(args=[job_id])
        db = session_factory()
        job = db.query(Job).filter(Job.job_id == job_id).first()
        db.expunge(job)
        db.close()
        return job, tmp_path / "logs" / f"{job_id}.log"

    return run


def open_handlers_for(log_path):
    names = list(tasks._JOB_FILE_LOGGERS) if hasattr(tasks, "_JOB_FILE_LOGGERS") else []
    names += [n for n in logging.Logger.manager.loggerDict if n.startswith("task.")]
    return [h for n in names for h in logging.getLogger(n).handlers
            if isinstance(h, logging.FileHandler) and Path(h.baseFilename) == log_path]


def test_http_failure_is_stored_on_the_job(run_job):
    job, _ = run_job("job-http400", http_response(400, {"detail": "Synthetic validation failure"}))
    assert job.status == JobStatus.FAILED.value
    assert "Phoenix API 400: Synthetic validation failure" in job.error_message
    assert "Unknown error" not in job.error_message


def test_importer_errors_reach_the_job_log(run_job):
    _, log_path = run_job("job-log400", http_response(400, {"detail": "Synthetic validation failure"}))
    assert "Phoenix API 400: Synthetic validation failure" in log_path.read_text()


def test_job_log_handler_is_released_after_failure(run_job):
    _, log_path = run_job("job-release-fail", http_response(400, {"detail": "Synthetic validation failure"}))
    assert open_handlers_for(log_path) == []


def test_job_log_handler_is_released_after_success(run_job):
    job, log_path = run_job("job-release-ok", http_response(200, {"id": "r1"}))
    assert job.status == JobStatus.COMPLETED.value
    assert open_handlers_for(log_path) == []
