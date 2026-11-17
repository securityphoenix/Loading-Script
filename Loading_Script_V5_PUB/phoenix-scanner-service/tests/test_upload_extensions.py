"""The upload route accepts .nessus files (any case), refuses .nessus with anonymize, and refuses unknown types."""
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.security import verify_api_key
from app.main import app
from app.models.database import get_db


@pytest.fixture
def client_and_job_manager():
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[verify_api_key] = lambda: "test"
    job_manager = MagicMock()
    job_manager.create_job = AsyncMock(
        return_value=SimpleNamespace(
            job_id="job-1", status="pending", created_at=datetime(2026, 11, 11)
        )
    )
    try:
        with patch("app.api.upload.job_manager", job_manager), patch(
            "app.workers.tasks.process_scan_file.delay"
        ):
            yield TestClient(app), job_manager
    finally:
        app.dependency_overrides.clear()


def _post(client, filename, **form):
    return client.post(
        "/api/v1/upload",
        files={"file": (filename, b"<NessusClientData_v2/>", "application/xml")},
        data={"scanner_type": "auto", **form},
    )


@pytest.mark.parametrize("filename", ["scan.nessus", "scan.NESSUS"])
def test_nessus_upload_is_accepted(client_and_job_manager, filename):
    client, job_manager = client_and_job_manager
    before = job_manager.create_job.await_count
    response = _post(client, filename)
    assert 200 <= response.status_code < 300, response.text
    assert job_manager.create_job.await_count == before + 1


def test_unknown_extension_is_refused(client_and_job_manager):
    client, job_manager = client_and_job_manager
    response = _post(client, "scan.exe")
    assert response.status_code == 400
    assert "File type not allowed" in response.json()["detail"]
    job_manager.create_job.assert_not_awaited()


@pytest.mark.parametrize("filename", ["scan.nessus", "scan.NESSUS"])
def test_nessus_upload_with_anonymize_is_refused_before_queueing(client_and_job_manager, filename):
    client, job_manager = client_and_job_manager
    with patch("app.workers.tasks.process_scan_file.delay") as delay:
        response = _post(client, filename, anonymize="true")
    assert response.status_code == 400
    assert "anonymize is not supported" in response.json()["detail"]
    job_manager.create_job.assert_not_awaited()
    delay.assert_not_called()


@pytest.mark.parametrize("filename", ["scan.xml", "scan.json"])
def test_anonymize_still_accepted_for_other_uploads(client_and_job_manager, filename):
    client, job_manager = client_and_job_manager
    response = _post(client, filename, anonymize="true")
    assert 200 <= response.status_code < 300, response.text
    assert job_manager.create_job.await_count == 1


def test_nessus_upload_without_anonymize_is_accepted(client_and_job_manager):
    client, job_manager = client_and_job_manager
    response = _post(client, "scan.nessus", anonymize="false")
    assert 200 <= response.status_code < 300, response.text
    assert job_manager.create_job.await_count == 1
