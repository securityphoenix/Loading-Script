#!/usr/bin/env python3
"""Turn import failures into one user-visible, groupable error string."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, List, Optional

MAX_ERROR_CHARS = 1200
_WHITESPACE = re.compile(r"\s+")


def clip_error_text(text: str, limit: int = MAX_ERROR_CHARS) -> str:
    compact = _WHITESPACE.sub(" ", (text or "").strip())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def compact_api_body(body: str) -> str:
    """Prefer a JSON message/detail field over a raw HTML or dump body."""
    raw = (body or "").strip()
    if not raw:
        return "empty response body"
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return clip_error_text(raw, 600)
    if isinstance(data, dict):
        for key in ("message", "error", "detail", "title", "error_message"):
            value = data.get(key)
            if value:
                if isinstance(value, (dict, list)):
                    return clip_error_text(json.dumps(value, ensure_ascii=False), 600)
                return clip_error_text(str(value), 600)
        return clip_error_text(json.dumps(data, ensure_ascii=False), 600)
    return clip_error_text(raw, 600)


def format_phoenix_http_error(status_code: int, body: str) -> str:
    return clip_error_text(f"Phoenix API {status_code}: {compact_api_body(body)}")


def format_batch_session_error(session: Any) -> Optional[str]:
    """Build a single error line from failed batches, or None if all succeeded."""
    results = getattr(session, "batch_results", None) or []
    failed = [item for item in results if not getattr(item, "success", True)]
    if not failed:
        return None

    unique: List[str] = []
    seen = set()
    for item in failed:
        message = clip_error_text(str(getattr(item, "error_message", "") or ""), 500)
        if not message or message in seen:
            continue
        seen.add(message)
        unique.append(message)

    total = getattr(session, "total_batches", len(results)) or len(results)
    failed_count = getattr(session, "failed_batches", len(failed)) or len(failed)
    details = "; ".join(unique) if unique else "no batch error details"
    return clip_error_text(
        f"Phoenix import failed ({failed_count}/{total} batches): {details}"
    )


def error_message_from_result(result: Optional[dict], fallback: str = "") -> str:
    """Pick the best error string from a process_scanner_file_enhanced result."""
    if not isinstance(result, dict):
        return clip_error_text(fallback or "Import failed without an error message")

    direct = result.get("error")
    if direct:
        return clip_error_text(str(direct))

    batch_errors: Iterable[Any] = result.get("batch_errors") or []
    unique: List[str] = []
    seen = set()
    for item in batch_errors:
        if isinstance(item, dict):
            message = str(item.get("error") or "").strip()
        else:
            message = str(item).strip()
        if not message or message in seen:
            continue
        seen.add(message)
        unique.append(message)
    if unique:
        summary = result.get("batch_summary") or {}
        failed = summary.get("failed_batches", len(unique))
        total = summary.get("total_batches", failed)
        return clip_error_text(
            f"Phoenix import failed ({failed}/{total} batches): " + "; ".join(unique)
        )

    return clip_error_text(fallback or "Import failed without an error message")
