#!/usr/bin/env python3
"""Shared Grype source.target helpers (no scanner package imports)."""

import base64
import json
from typing import Any, Dict, List, Optional


def normalize_image_digest(value: str) -> Optional[str]:
    """Extract algorithm-prefixed digest (e.g. sha256:...) from a repo digest reference."""
    text = value.strip()
    if not text:
        return None
    if "@" in text:
        text = text.rsplit("@", 1)[-1].strip()
    if not text or ":" not in text:
        return None
    return text


def resolve_image_digest_from_grype_target(target_info: Any) -> Optional[str]:
    """Derive Phoenix imageDigest from Grype source.target.repoDigests.

    Selection rules:
    - One repoDigest  -> use it
    - Multiple        -> exact match with userInput, else no imageDigest
    - None / empty    -> no imageDigest
    """
    if not isinstance(target_info, dict):
        return None

    raw_digests = target_info.get("repoDigests")
    if not raw_digests:
        return None

    repo_digests: List[str] = []
    if isinstance(raw_digests, str):
        text = raw_digests.strip()
        if text:
            repo_digests.append(text)
    elif isinstance(raw_digests, (list, tuple)):
        for item in raw_digests:
            text = str(item).strip() if item is not None else ""
            if text:
                repo_digests.append(text)

    if not repo_digests:
        return None

    if len(repo_digests) == 1:
        selected = repo_digests[0]
    else:
        user_input = str(target_info.get("userInput") or "").strip()
        matched = next((digest for digest in repo_digests if digest == user_input), None)
        if not matched:
            return None
        selected = matched

    return normalize_image_digest(selected)


def grype_manifest_annotations(target_info: Any) -> Dict[str, Any]:
    """Return the OCI annotations in Grype's base64 source.target.manifest, or {}."""
    try:
        annotations = json.loads(base64.b64decode(target_info["manifest"])).get("annotations")
    except (AttributeError, KeyError, TypeError, ValueError):
        return {}
    return annotations if isinstance(annotations, dict) else {}
