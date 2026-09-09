#!/usr/bin/env python3
"""
Normalize Phoenix finding reference fields before import.

Phoenix BE expects:
  - referenceIds: CVE, GHSA, and other vulnerability identifiers
  - cwes: CWE identifiers in the form CWE-<number>

Legacy fields cve/cwe are accepted as fallback only when the new fields are empty.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Set

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
CWE_NUMERIC_PATTERN = re.compile(r"^\d+$")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if item is not None and str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def normalize_cwe(value: str) -> Optional[str]:
    """Normalize a single CWE value to CWE-<number> uppercase form."""
    text = str(value).strip()
    if not text:
        return None

    match = CWE_PATTERN.search(text)
    if match:
        number = match.group(0).split("-", 1)[1]
        return f"CWE-{number}"

    if CWE_NUMERIC_PATTERN.match(text):
        return f"CWE-{text}"

    return None


def is_cwe_reference(value: str) -> bool:
    text = str(value).strip()
    return bool(CWE_PATTERN.fullmatch(text) or CWE_NUMERIC_PATTERN.fullmatch(text))


def extract_vulnerability_ids_from_text(text: str) -> List[str]:
    """Extract CVE/GHSA identifiers embedded in free text or URLs."""
    if not text:
        return []

    found: List[str] = []
    for match in CVE_PATTERN.finditer(str(text)):
        found.append(match.group(0).upper())
    for match in GHSA_PATTERN.finditer(str(text)):
        found.append(match.group(0))
    return _dedupe_preserve_order(found)


def extract_cwes_from_text(text: str) -> List[str]:
    """Extract CWE identifiers embedded in free text."""
    if not text:
        return []
    return normalize_cwe_list(CWE_PATTERN.findall(str(text)))


def extract_vulnerability_ids_from_urls(urls: Iterable[Any]) -> List[str]:
    """Extract CVE/GHSA identifiers from advisory or reference URLs."""
    refs: List[str] = []
    for url in urls or []:
        refs.extend(extract_vulnerability_ids_from_text(str(url)))
    return _dedupe_preserve_order(refs)


def normalize_cwe_list(values: Any) -> List[str]:
    """Normalize a scalar or list of CWE values to CWE-<number> form."""
    normalized: List[str] = []
    for value in _as_list(values):
        cwe = normalize_cwe(value)
        if cwe:
            normalized.append(cwe)
    return _dedupe_preserve_order(normalized)


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _split_cwes_from_refs(reference_values: Iterable[str]) -> tuple[List[str], List[str]]:
    refs: List[str] = []
    cwes: List[str] = []
    for value in reference_values:
        text = value.strip()
        if not text:
            continue

        if CWE_PATTERN.fullmatch(text) or CWE_NUMERIC_PATTERN.fullmatch(text):
            normalized = normalize_cwe(text)
            if normalized:
                cwes.append(normalized)
            continue

        refs.append(text)

    return refs, cwes


def normalize_finding_reference_fields(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize referenceIds and cwes on a finding dict for Phoenix import.

    Merges reference_ids/referenceIds/cwes, splits misplaced CWEs, strips legacy
    cve/cwe fields, and omits empty arrays from the output.
    """
    refs: List[str] = []
    cwes: List[str] = []

    refs.extend(_as_list(finding.pop("reference_ids", None)))
    refs.extend(_as_list(finding.pop("referenceIds", None)))
    cwes.extend(_as_list(finding.pop("cwes", None)))

    legacy_cve = finding.pop("cve", None)
    legacy_cwe = finding.pop("cwe", None)

    if not refs and legacy_cve:
        refs.extend(_as_list(legacy_cve))
    if not cwes and legacy_cwe:
        cwes.extend(_as_list(legacy_cwe))

    clean_refs, extracted_cwes = _split_cwes_from_refs(refs)

    normalized_cwes: List[str] = []
    for value in cwes + extracted_cwes:
        normalized = normalize_cwe(value)
        if normalized:
            normalized_cwes.append(normalized)

    clean_refs = _dedupe_preserve_order(clean_refs)
    normalized_cwes = _dedupe_preserve_order(normalized_cwes)

    if clean_refs:
        finding["referenceIds"] = clean_refs
    else:
        finding.pop("referenceIds", None)

    if normalized_cwes:
        finding["cwes"] = normalized_cwes
    else:
        finding.pop("cwes", None)

    return finding