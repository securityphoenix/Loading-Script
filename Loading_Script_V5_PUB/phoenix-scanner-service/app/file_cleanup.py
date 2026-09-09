"""Upload file cleanup after job completion."""
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def delete_upload_file(file_path: Optional[str]) -> None:
    """Delete upload file from disk after a job reaches a terminal state."""
    if file_path is None:
        return
    p = Path(file_path)
    if p.exists():
        try:
            p.unlink()
            logger.info(f"Deleted upload file: {p.name}")
        except OSError as e:
            logger.warning(f"Could not delete upload file {p}: {e}")
