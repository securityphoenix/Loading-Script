#!/usr/bin/env python3
"""
Wazuh Translator
================

Translator for Wazuh vulnerability exports. Handles both shapes produced by
Wazuh deployments in the wild:

1. Wazuh Indexer (OpenSearch) export — Wazuh 4.8+
   Root: {"took": ..., "hits": {"hits": [{"_source": {...}}]}}
   Vulnerabilities live under hits.hits[]._source.vulnerability.*
   Host identity under hits.hits[]._source.agent.name

2. Wazuh Manager REST API response — legacy (pre-4.8)
   Root: {"data": {"affected_items": [...]}, "error": 0, "message": "..."}
   Vulnerabilities under data.affected_items[]
   Host identity via ip_address / hostname at root, or fqdn override

Since 4.8 the vulnerability detector was moved into the Wazuh Indexer, so
shape (1) is what modern deployments actually produce.

Asset Type: INFRA
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator


# Phoenix's import endpoint expects date-times in bare ISO-8601 without a
# trailing "Z" or ±HH:MM offset (e.g. "2024-11-12T10:15:30"). Wazuh emits
# timestamps with "Z" ("2026-04-10T16:16:33Z") which the API rejects with
# 400 "Invalid date format". Strip the timezone suffix defensively.
_TZ_SUFFIX_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def _normalize_iso_datetime(value: Any) -> Optional[str]:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    s = _TZ_SUFFIX_RE.sub("", s)
    # Also strip fractional seconds if present ("...:33.689" → "...:33").
    if "." in s:
        head, _, tail = s.partition(".")
        # Only drop the fractional part if it looks numeric.
        if tail and tail[0].isdigit():
            s = head
    return s

logger = logging.getLogger(__name__)


# Wazuh severities are already textual (Critical / High / Medium / Low),
# but exports occasionally carry "-" for un-triaged entries. Keep the base
# class severity_mapping as the default; only override the sentinel.
_SEVERITY_FALLBACK = {
    "-": "5.0",
    "": "5.0",
    "unknown": "5.0",
    "none": "1.0",
}


class WazuhTranslator(ScannerTranslator):
    """Translator for Wazuh vulnerability exports (Indexer + legacy Manager)."""

    # --------------------------------------------------------------
    # Detection
    # --------------------------------------------------------------
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith(".json"):
            return False

        try:
            if file_content is None:
                with open(file_path, "r") as f:
                    file_content = json.load(f)
        except Exception as e:
            logger.debug(f"WazuhTranslator.can_handle failed to load JSON: {e}")
            return False

        if not isinstance(file_content, dict):
            return False

        return self._detect_shape(file_content) is not None

    @staticmethod
    def _detect_shape(data: Dict[str, Any]) -> Optional[str]:
        """Return 'indexer' or 'manager_api' if the payload matches Wazuh."""
        # Shape 1: Wazuh Indexer (OpenSearch) — hits.hits[]._source.vulnerability
        hits_root = data.get("hits")
        if isinstance(hits_root, dict):
            inner = hits_root.get("hits")
            if isinstance(inner, list) and inner:
                first = inner[0]
                if isinstance(first, dict):
                    src = first.get("_source")
                    idx = first.get("_index", "")
                    if isinstance(src, dict) and isinstance(idx, str) and (
                        "wazuh" in idx.lower()
                        or "vulnerability" in src
                        or "agent" in src
                    ):
                        return "indexer"

        # Shape 2: Wazuh Manager REST API — data.affected_items[]
        payload = data.get("data")
        if isinstance(payload, dict) and "error" in data:
            items = payload.get("affected_items")
            if isinstance(items, list):
                if not items:
                    # Empty but well-formed Manager response — still Wazuh.
                    return "manager_api"
                first = items[0]
                if isinstance(first, dict) and (
                    "cve" in first or "vuln" in first or "name" in first
                ):
                    return "manager_api"

        return None

    # --------------------------------------------------------------
    # Parsing
    # --------------------------------------------------------------
    def parse_file(self, file_path: str, asset_name_override: str = None) -> List[AssetData]:
        logger.info(f"Parsing Wazuh scan file: {file_path}")

        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse Wazuh file: {e}")
            raise

        shape = self._detect_shape(data)
        if shape == "indexer":
            logger.info("🔎 Wazuh shape detected: Indexer (OpenSearch)")
            return self._parse_indexer(data, asset_name_override)
        if shape == "manager_api":
            logger.info("🔎 Wazuh shape detected: Manager REST API (legacy)")
            return self._parse_manager_api(data, asset_name_override)

        logger.error("Wazuh file did not match any known shape after load")
        return []

    # ---- Indexer (OpenSearch) shape ------------------------------
    def _parse_indexer(
        self,
        data: Dict[str, Any],
        asset_name_override: Optional[str],
    ) -> List[AssetData]:
        hits = data.get("hits", {}).get("hits", []) or []
        if not hits:
            logger.warning("Wazuh Indexer export contains 0 hits")
            return []

        total = data.get("hits", {}).get("total")
        if isinstance(total, dict):
            rel = total.get("relation", "eq")
            val = total.get("value")
            if rel == "gte" and isinstance(val, int) and len(hits) >= val:
                logger.warning(
                    f"⚠️ Wazuh Indexer export appears truncated at {val} hits "
                    "(OpenSearch default cap). Use scroll / search_after to paginate."
                )

        # Group findings by host so we produce one AssetData per agent.
        assets_by_host: Dict[str, Dict[str, Any]] = {}
        for hit in hits:
            source = hit.get("_source") or {}
            if not isinstance(source, dict):
                continue

            agent = source.get("agent") or {}
            host = source.get("host") or {}
            pkg = source.get("package") or {}
            vuln = source.get("vulnerability") or {}
            if not isinstance(vuln, dict) or not vuln:
                continue

            host_key = asset_name_override or agent.get("name") or agent.get("id") or "wazuh-unknown-host"
            bucket = assets_by_host.get(host_key)
            if bucket is None:
                bucket = {
                    "hostname": host_key,
                    "ip": host.get("ip") or source.get("ip_address") or "",
                    "os": (host.get("os") or {}).get("full", "") if isinstance(host.get("os"), dict) else "",
                    "agent_id": agent.get("id", ""),
                    "agent_version": agent.get("version", ""),
                    "findings": [],
                }
                assets_by_host[host_key] = bucket

            finding = self._build_finding_indexer(vuln, pkg)
            if finding is not None:
                bucket["findings"].append(finding)

        return self._buckets_to_assets(assets_by_host, source_label="wazuh-indexer")

    def _build_finding_indexer(
        self,
        vuln: Dict[str, Any],
        pkg: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        cve = (vuln.get("id") or "").strip()
        description = (vuln.get("description") or "").strip()
        severity_raw = vuln.get("severity") or ""
        remedy = ""
        scanner_meta = vuln.get("scanner")
        if isinstance(scanner_meta, dict):
            remedy = scanner_meta.get("condition") or ""
        pkg_name = (pkg.get("name") or "").strip()
        pkg_version = (pkg.get("version") or "").strip()
        location = f"{pkg_name} {pkg_version}".strip() or "package"

        name = cve or (description[:80] if description else "wazuh-finding")
        if not name:
            return None

        details: Dict[str, Any] = {}
        score = vuln.get("score")
        if isinstance(score, dict):
            base = score.get("base")
            if base is not None:
                details["cvss_base_score"] = base
            if score.get("version"):
                details["cvss_version"] = score.get("version")
        if vuln.get("detected_at"):
            details["detected_at"] = vuln["detected_at"]
        if pkg.get("architecture"):
            details["package_architecture"] = pkg["architecture"]
        if pkg.get("type"):
            details["package_type"] = pkg["type"]

        reference_ids: List[str] = []
        if cve:
            reference_ids.append(cve)
        raw_ref = vuln.get("reference")
        if isinstance(raw_ref, str) and raw_ref:
            reference_ids.extend([r.strip() for r in raw_ref.split(",") if r.strip()])

        finding = {
            "name": name,
            "description": description or name,
            "remedy": remedy or "See Wazuh scanner output for remediation guidance",
            "severity": self._normalize_wazuh_severity(severity_raw),
            "location": location,
            "reference_ids": reference_ids,
            "cwes": self.extract_cwes(description),
            "published_date_time": _normalize_iso_datetime(
                vuln.get("published_at") or vuln.get("detected_at")
            ),
            "details": details,
        }
        return finding

    # ---- Manager REST API shape ---------------------------------
    def _parse_manager_api(
        self,
        data: Dict[str, Any],
        asset_name_override: Optional[str],
    ) -> List[AssetData]:
        payload = data.get("data") or {}
        items = payload.get("affected_items") if isinstance(payload, dict) else []
        if not isinstance(items, list):
            items = []

        host_key = (
            asset_name_override
            or data.get("hostname")
            or data.get("ip_address")
            or data.get("fqdn")
            or "wazuh-unknown-host"
        )
        bucket = {
            "hostname": host_key,
            "ip": data.get("ip_address", ""),
            "os": "",
            "agent_id": "",
            "agent_version": "",
            "findings": [],
        }

        for item in items:
            if not isinstance(item, dict):
                continue
            cve = (item.get("cve") or item.get("vuln") or item.get("name") or "").strip()
            description = (item.get("description") or "").strip()
            severity_raw = item.get("severity") or ""
            remedy = item.get("fix") or ""
            location = item.get("package") or item.get("location") or "package"

            name = cve or (description[:80] if description else "wazuh-finding")
            if not name:
                continue

            bucket["findings"].append({
                "name": name,
                "description": description or name,
                "remedy": remedy or "See Wazuh scanner output for remediation guidance",
                "severity": self._normalize_wazuh_severity(severity_raw),
                "location": location,
                "reference_ids": [cve] if cve else [],
                "cwes": self.extract_cwes(description),
                "published_date_time": _normalize_iso_datetime(
                    item.get("published") or item.get("detected_at")
                ),
                "details": {k: v for k, v in item.items() if k not in {
                    "cve", "vuln", "name", "description", "severity", "fix",
                    "package", "location", "published", "detected_at",
                }},
            })

        return self._buckets_to_assets({host_key: bucket}, source_label="wazuh-manager-api")

    # --------------------------------------------------------------
    # Shared plumbing
    # --------------------------------------------------------------
    def _buckets_to_assets(
        self,
        buckets: Dict[str, Dict[str, Any]],
        source_label: str,
    ) -> List[AssetData]:
        assets: List[AssetData] = []
        tag_config_tags = self.tag_config.get_all_tags() if self.tag_config else []

        for host_key, bucket in buckets.items():
            if not bucket["findings"] and not self.create_inventory_assets:
                # Nothing to import for this host and we are not in inventory mode.
                continue

            attributes: Dict[str, str] = {"hostname": bucket["hostname"]}
            if bucket.get("ip"):
                attributes["ip"] = bucket["ip"]
            if bucket.get("os"):
                attributes["operatingSystem"] = bucket["os"]

            wazuh_tags = [
                {"key": "scanner", "value": "wazuh"},
                {"key": "wazuh-source", "value": source_label},
            ]
            if bucket.get("agent_id"):
                wazuh_tags.append({"key": "wazuh-agent-id", "value": str(bucket["agent_id"])})
            if bucket.get("agent_version"):
                wazuh_tags.append({"key": "wazuh-agent-version", "value": str(bucket["agent_version"])})

            all_tags = tag_config_tags + wazuh_tags
            filtered_tags = [t for t in all_tags if t.get("value") and str(t.get("value")).strip()]

            asset = AssetData(
                asset_type="INFRA",
                attributes=attributes,
                tags=filtered_tags,
            )
            for f in bucket["findings"]:
                asset.findings.append(VulnerabilityData(**f).__dict__)

            assets.append(self.ensure_asset_has_findings(asset))

        logger.info(
            f"Parsed {len(assets)} Wazuh asset(s) with "
            f"{sum(len(a.findings) for a in assets)} vulnerabilities from {source_label}"
        )
        return assets

    def _normalize_wazuh_severity(self, severity_raw: Any) -> str:
        s = (str(severity_raw) if severity_raw is not None else "").strip().lower()
        if s in _SEVERITY_FALLBACK:
            return _SEVERITY_FALLBACK[s]
        return self.normalize_severity(s)
