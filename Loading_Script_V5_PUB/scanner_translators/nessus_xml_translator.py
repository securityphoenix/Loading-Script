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

    def _option(self, name: str) -> bool:
        options = getattr(self.scanner_config, "custom_options", None) or {}
        return str(options.get(name, "")).strip().lower() in ("true", "yes", "1")

    @staticmethod
    def _cut(text: str) -> str:
        return text if len(text) <= 500 else text[:497] + "..."

    @staticmethod
    def _child_text(item, tag: str) -> str:
        child = item.find(tag)
        return (child.text or "").strip() if child is not None else ""

    def _invalid(self, item, reason: str) -> List[Dict[str, Any]]:
        self._counts["invalid_items"] += 1
        logger.debug("Nessus item skipped: pluginID=%r reason=%s", item.get("pluginID"), reason)
        return []

    def _item_findings(self, item) -> List[Dict[str, Any]]:
        """Findings for one ReportItem: one per CVE, or one named after the plugin."""
        sev_text = (item.get("severity") or "").strip()
        plugin_id = (item.get("pluginID") or "").strip()
        if sev_text not in ("0", "1", "2", "3", "4"):
            return self._invalid(item, "severity is not 0 to 4")
        if not (plugin_id.isascii() and plugin_id.isdigit()):
            return self._invalid(item, "pluginID is not numeric")
        if sev_text == "0":
            if not self._option("include_informational"):
                self._counts["informational_skipped"] += 1
                return []
            severity = "1.0"
        else:
            severity = SEVERITY_MAP[int(sev_text)]
        port = (item.get("port") or "").strip()
        port = port if port.isascii() and port.isdigit() else "0"
        protocol = (item.get("protocol") or "").strip() or "tcp"
        plugin_name = item.get("pluginName") or ""
        synopsis = self._child_text(item, "synopsis")
        description = self._child_text(item, "description")
        if synopsis and description:
            text = f"{synopsis}\n\n{description}"
        else:
            text = synopsis or description or plugin_name
        remedy = self._child_text(item, "solution") or "See scanner output for remediation"
        cwes = []
        for cwe in item.findall("cwe"):
            value = (cwe.text or "").strip()
            if value.isascii() and value.isdigit():
                cwes.append(f"CWE-{value}")
        published = None
        match = re.fullmatch(r"(\d{4})/(\d{2})/(\d{2})", self._child_text(item, "vuln_publication_date"))
        if match:
            published = "%s-%s-%sT00:00:00" % match.groups()
        details = {
            "plugin_id": plugin_id, "plugin_name": plugin_name,
            "plugin_family": item.get("pluginFamily"), "port": port, "protocol": protocol,
            "svc_name": item.get("svc_name"),
            "cvss_score": self._child_text(item, "cvss_base_score"),
            "cvss3_score": self._child_text(item, "cvss3_base_score"),
            "exploit_available": self._child_text(item, "exploit_available"),
        }
        if self._option("include_plugin_output"):
            details["plugin_output"] = self._cut(self._child_text(item, "plugin_output"))
        details = {k: v for k, v in details.items() if v}
        cves = [c.text.strip() for c in item.findall("cve") if c.text and c.text.strip()]
        names = cves or [f"Plugin-{plugin_id}"]
        return [
            VulnerabilityData(
                name=name, description=self._cut(text), remedy=self._cut(remedy), severity=severity,
                location=f"{protocol}/{port}", reference_ids=[name], cwes=list(cwes),
                published_date_time=published, details=dict(details),
            ).__dict__
            for name in names
        ]

    def _add_findings(self, asset: AssetData, index: Dict[Tuple[str, str], Dict[str, Any]],
                      findings: List[Dict[str, Any]]) -> None:
        """Add findings to an asset, unique by (name, location), keeping the higher severity."""
        for finding in findings:
            ident = (finding["name"], finding["location"])
            kept = index.get(ident)
            if kept is None:
                index[ident] = finding
                asset.findings.append(finding)
                continue
            self._counts["duplicates_merged"] += 1
            kept_ids = kept["details"].get("plugin_ids") or [kept["details"].get("plugin_id")]
            new_id = finding["details"].get("plugin_id")
            if float(finding["severity"]) > float(kept["severity"]):
                winner, ids = finding, [new_id] + kept_ids
                position = asset.findings.index(kept)
                asset.findings[position] = finding
                index[ident] = finding
            else:
                winner, ids = kept, kept_ids + [new_id]
            unique = []
            for pid in ids:
                if pid and pid not in unique:
                    unique.append(pid)
            winner["details"]["plugin_ids"] = unique

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
        self._counts = {k: 0 for k in (
            "hosts", "items", "informational_skipped", "invalid_items", "invalid_hosts",
            "duplicates_merged", "findings", "assets", "assets_without_findings")}
        stats = self._counts
        self.last_stats = stats
        assets: Dict[str, AssetData] = {}
        indexes: Dict[str, Dict[Tuple[str, str], Dict[str, Any]]] = {}
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
                    stats["items"] += 1
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
                            indexes[key] = {}
                        else:
                            for k, v in attrs.items():
                                asset.attributes.setdefault(k, v)
                        self._add_findings(asset, indexes[key], findings)
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
        stats["assets"] = len(result)
        stats["findings"] = sum(len(a.findings) for a in result)
        logger.info(
            "Nessus XML %s: hosts=%d items=%d informational_skipped=%d invalid_items=%d "
            "invalid_hosts=%d duplicates_merged=%d findings=%d assets=%d",
            name, stats["hosts"], stats["items"], stats["informational_skipped"],
            stats["invalid_items"], stats["invalid_hosts"], stats["duplicates_merged"],
            stats["findings"], stats["assets"],
        )
        if not result:
            raise NessusEmptyScan(f"Nessus file {name} holds no importable finding", stats)
        return result
