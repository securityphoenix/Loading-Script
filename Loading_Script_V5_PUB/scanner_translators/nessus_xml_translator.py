#!/usr/bin/env python3
"""
Nessus XML (.nessus) Translator
===============================

Reads Tenable Nessus ``NessusClientData_v2`` exports. The file is untrusted
input, so it is parsed with ``defusedxml`` (no entity expansion, no external
entities) and as a stream, so large scans do not sit in memory.
"""

import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from phoenix_import_refactored import AssetData, VulnerabilityData
from tag_utils import get_tags_safely

from .base_translator import ScannerTranslator

logger = logging.getLogger(__name__)

ROOT_TAG = "NessusClientData_v2"
_HEAD_BYTES = 4096
_SKIP_PROLOG = re.compile(
    rb"\s*(?:<\?.*?\?>|<!--.*?-->|<!DOCTYPE(?:[^\[>]|\[.*?\])*>)", re.DOTALL | re.IGNORECASE
)
SEVERITY_MAP = {4: "10.0", 3: "8.0", 2: "5.0", 1: "3.0"}
SCANNER_TAG = {"key": "scanner", "value": "tenable-nessus"}
_FIRST_ELEMENT = re.compile(rb"\s*<([A-Za-z_][\w.\-]*)")


class NessusParseError(ValueError):
    """The file is not valid, safe Nessus XML."""


class NessusEmptyScan(Exception):
    """The file is valid but holds no importable finding."""

    def __init__(self, message: str = "", stats: Dict[str, int] = None):
        super().__init__(message)
        self.stats: Dict[str, int] = stats if stats is not None else {}


class NessusXMLTranslator(ScannerTranslator):
    """Translator for Nessus v2 XML exports."""

    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if Path(file_path).suffix.lower() not in (".nessus", ".xml"):
            return False
        try:
            with open(file_path, "rb") as handle:
                head = handle.read(_HEAD_BYTES)
        except OSError:
            return False
        if head.startswith(b"\xef\xbb\xbf"):
            head = head[3:]
        pos = 0
        while True:
            match = _SKIP_PROLOG.match(head, pos)
            if not match:
                break
            pos = match.end()
        first = _FIRST_ELEMENT.match(head, pos)
        return bool(first) and first.group(1).decode("ascii", "replace") == ROOT_TAG

    def _release(self, elem) -> None:
        """Free an element the translator is done with."""
        elem.clear()

    def _events(self, file_path: str) -> Iterator[Tuple[str, Any]]:
        name = Path(file_path).name
        try:
            from defusedxml import ElementTree as safe_et
        except ImportError as exc:
            raise NessusParseError(
                f"Nessus XML parse failed for {name}: the defusedxml package is missing: "
                "run pip install defusedxml"
            ) from exc
        for _event, elem in safe_et.iterparse(file_path, events=("end",)):
            yield elem.tag, elem

    @staticmethod
    def _first_line(value: Any) -> str:
        for line in str(value or "").splitlines():
            if line.strip():
                return line.strip()
        return ""

    def _host_attributes(self, report_host_name: str, props: Dict[str, str]) -> Dict[str, str]:
        """Map HostProperties tags (and the ReportHost name as a fallback) to asset attributes."""
        clean = {k: self._first_line(v) for k, v in props.items()}
        attrs: Dict[str, str] = {}
        if clean.get("host-ip"):
            attrs["ip"] = clean["host-ip"]
        if clean.get("host-fqdn"):
            attrs["fqdn"] = clean["host-fqdn"]
            attrs["hostname"] = clean["host-fqdn"]
        if clean.get("netbios-name"):
            attrs["netbios"] = clean["netbios-name"]
            attrs.setdefault("hostname", clean["netbios-name"])
        if clean.get("mac-address"):
            attrs["macAddress"] = clean["mac-address"]
        if clean.get("operating-system"):
            attrs["operatingSystem"] = clean["operating-system"]
        fallback = (report_host_name or "").strip()
        if fallback and "ip" not in attrs and "hostname" not in attrs:
            try:
                ipaddress.ip_address(fallback)
                attrs["ip"] = fallback
            except ValueError:
                attrs["hostname"] = fallback
        return attrs

    def _item_findings(self, item) -> List[Dict[str, Any]]:
        """Minimal finding for one ReportItem (Task 3 replaces this body)."""
        try:
            severity = SEVERITY_MAP.get(int(item.get("severity", "0")))
        except ValueError:
            severity = None
        if severity is None:
            return []
        plugin_name = item.get("pluginName", "")
        vuln = VulnerabilityData(
            name=f"Plugin-{item.get('pluginID', '')}",
            description=plugin_name,
            remedy=plugin_name,
            severity=severity,
            location=f"{item.get('protocol', '')}/{item.get('port', '')}",
            reference_ids=[f"Plugin-{item.get('pluginID', '')}"],
        )
        return [vuln.__dict__]

    @staticmethod
    def _asset_key(attrs: Dict[str, str]) -> str:
        return attrs.get("ip") or attrs.get("fqdn") or attrs.get("hostname") or ""

    def parse_file(self, file_path: str) -> List[AssetData]:
        name = Path(file_path).name
        try:
            from defusedxml import DefusedXmlException
        except ImportError as exc:
            raise NessusParseError(
                f"Nessus XML parse failed for {name}: the defusedxml package is missing: "
                "run pip install defusedxml"
            ) from exc
        stats = {"hosts": 0, "invalid_hosts": 0, "assets_without_findings": 0}
        assets: Dict[str, AssetData] = {}
        props: Dict[str, str] = {}
        findings: List[Dict[str, Any]] = []
        try:
            for tag, elem in self._events(file_path):
                if tag == "attachment":
                    # The parser still reads the text of one attachment into memory once.
                    self._release(elem)
                elif tag == "HostProperties":
                    for child in elem.iter("tag"):
                        if child.get("name") and child.get("name") not in props:
                            props[child.get("name")] = child.text or ""
                    self._release(elem)
                elif tag == "ReportItem":
                    findings.extend(self._item_findings(elem))
                    self._release(elem)
                elif tag == "ReportHost":
                    stats["hosts"] += 1
                    attrs = self._host_attributes(elem.get("name", ""), props)
                    key = self._asset_key(attrs)
                    if not key:
                        stats["invalid_hosts"] += 1
                    else:
                        asset = assets.get(key)
                        if asset is None:
                            asset = AssetData(
                                asset_type="INFRA",
                                attributes=attrs,
                                tags=get_tags_safely(self.tag_config) + [dict(SCANNER_TAG)],
                            )
                            assets[key] = asset
                        else:
                            for k, v in attrs.items():
                                asset.attributes.setdefault(k, v)
                        asset.findings.extend(findings)
                    props, findings = {}, []
                    self._release(elem)
        except (DefusedXmlException, ET.ParseError) as exc:
            raise NessusParseError(f"Nessus XML parse failed for {name}: {exc}") from exc
        result: List[AssetData] = []
        for asset in assets.values():
            asset = self.ensure_asset_has_findings(asset)
            if asset.findings:
                result.append(asset)
            else:
                stats["assets_without_findings"] += 1
        if not result:
            raise NessusEmptyScan(f"Nessus file {name} holds no importable finding", stats)
        return result
