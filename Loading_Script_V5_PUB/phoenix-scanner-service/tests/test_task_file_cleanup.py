"""Tests for upload file cleanup after job completion."""
from app.file_cleanup import delete_upload_file


def test_deletes_file_after_completed_job(tmp_path):
    """File is deleted when job completes successfully."""
    upload_file = tmp_path / "job-abc123_scan.json"
    upload_file.write_text("{}")

    delete_upload_file(str(upload_file))

    assert not upload_file.exists()



def test_no_error_when_file_already_gone(tmp_path):
    """No exception raised if upload file was already deleted."""
    missing = tmp_path / "already_gone.json"

    delete_upload_file(str(missing))  # must not raise


def test_no_error_when_path_is_none():
    """No exception raised when file_path is None (job never reached file assignment)."""
    delete_upload_file(None)  # must not raise


def test_logs_warning_when_unlink_raises_os_error(tmp_path, caplog):
    """OSError during deletion is caught and logged as a warning."""
    from unittest.mock import patch
    upload_file = tmp_path / "error_file.json"
    upload_file.write_text("{}")
    with patch("app.file_cleanup.Path.unlink") as mocked_unlink:
        mocked_unlink.side_effect = OSError("Permission denied")
        delete_upload_file(str(upload_file))
    assert upload_file.exists()
    assert "Could not delete upload file" in caplog.text
