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
from datetime import datetime
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from phoenix_import_refactored import AssetData, VulnerabilityData
from tag_utils import get_tags_safely

from .base_translator import ScannerTranslator

logger = logging.getLogger(__name__)

ROOT_TAG = "NessusClientData_v2"
_HEAD_BYTES = 4096
_XML_SPACE = b" \t\r\n"
SEVERITY_MAP = {4: "10.0", 3: "8.0", 2: "5.0", 1: "3.0"}
_STAT_KEYS = (
    "hosts", "items", "informational_skipped", "invalid_items", "invalid_hosts",
    "duplicates_merged", "findings", "assets",
)
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._reset_counts()

    def _reset_counts(self) -> None:
        self._counts = {k: 0 for k in _STAT_KEYS}
        self.last_stats = self._counts

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
        first = _FIRST_ELEMENT.match(head, self._skip_prolog(head))
        return bool(first) and first.group(1).decode("ascii", "replace") == ROOT_TAG

    @staticmethod
    def _skip_prolog(head: bytes) -> int:
        """Offset after the XML declaration, comments, processing instructions and DOCTYPE.

        One forward pass over ``head`` (no backtracking): each construct is closed with a plain
        search from the current offset. An unclosed construct stops the scan there, so the root
        check that follows fails.
        """
        pos, size = 0, len(head)
        while True:
            while pos < size and head[pos] in _XML_SPACE:
                pos += 1
            if head.startswith(b"<?", pos):
                end = head.find(b"?>", pos + 2)
                if end < 0:
                    return pos
                pos = end + 2
            elif head.startswith(b"<!--", pos):
                end = head.find(b"-->", pos + 4)
                if end < 0:
                    return pos
                pos = end + 3
            elif head[pos:pos + 9].upper() == b"<!DOCTYPE":
                i, in_subset = pos + 9, False
                while i < size:
                    char = head[i]
                    if in_subset:
                        if char == 0x5D:  # ]
                            in_subset = False
                    elif char == 0x5B:  # [
                        in_subset = True
                    elif char == 0x3E:  # >
                        break
                    i += 1
                if i >= size:
                    return pos
                pos = i + 1
            else:
                return pos

    def _release(self, elem, parent=None) -> None:
        """Free an element the translator is done with and detach it from its parent."""
        elem.clear()
        if parent is not None:
            parent.remove(elem)

    def _events(self, file_path: str) -> Iterator[Tuple[str, str, Any]]:
        name = Path(file_path).name
        try:
            from defusedxml import ElementTree as safe_et
        except ImportError as exc:
            raise NessusParseError(
                f"Nessus XML parse failed for {name}: the defusedxml package is missing: "
                "run pip install defusedxml"
            ) from exc
        for event, elem in safe_et.iterparse(file_path, events=("start", "end")):
            yield event, elem.tag, elem

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
        if fallback and "ip" not in attrs:
            try:
                ipaddress.ip_address(fallback)
                # A valid IP in the ReportHost name is kept even when an FQDN gave the hostname,
                # so the asset key is the IP, as for reports of the same host with a host-ip tag.
                attrs["ip"] = fallback
            except ValueError:
                attrs.setdefault("hostname", fallback)
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
            text = synopsis or description or plugin_name or f"Plugin-{plugin_id}"
        remedy = self._child_text(item, "solution") or "See scanner output for remediation"
        cwes = []
        for cwe in item.findall("cwe"):
            value = (cwe.text or "").strip()
            if value.isascii() and value.isdigit():
                cwes.append(f"CWE-{value}")
        published = None
        try:
            published = datetime.strptime(
                self._child_text(item, "vuln_publication_date"), "%Y/%m/%d"
            ).strftime("%Y-%m-%dT00:00:00")
        except ValueError:
            pass
        details = {
            "plugin_id": plugin_id, "plugin_name": self._cut(plugin_name),
            "plugin_family": item.get("pluginFamily"), "port": port, "protocol": protocol,
            "svc_name": self._cut(item.get("svc_name") or ""),
            "cvss_score": self._child_text(item, "cvss_base_score"),
            "cvss3_score": self._child_text(item, "cvss3_base_score"),
            "exploit_available": self._child_text(item, "exploit_available"),
        }
        if self._option("include_plugin_output"):
            details["plugin_output"] = self._cut(self._child_text(item, "plugin_output"))
        details = {k: v for k, v in details.items() if v}
        cves = [c.text.strip() for c in item.findall("cve") if c.text and c.text.strip()]
        cves = list(dict.fromkeys(cves))
        names = cves or [f"Plugin-{plugin_id}"]
        return [
            VulnerabilityData(
                name=name, description=self._cut(text), remedy=self._cut(remedy), severity=severity,
                location=f"{protocol}/{port}", reference_ids=[name], cwes=list(cwes),
                published_date_time=published, details=dict(details),
            ).__dict__
            for name in names
        ]

    def _add_findings(self, asset: AssetData,
                      index: Dict[Tuple[str, str], Tuple[int, Dict[str, Any]]],
                      findings: List[Dict[str, Any]]) -> None:
        """Add findings to an asset, unique by (name, location), keeping the higher severity.

        The index maps each (name, location) to its position in ``asset.findings`` and the kept
        finding, so a merge never searches the list.
        """
        for finding in findings:
            ident = (finding["name"], finding["location"])
            entry = index.get(ident)
            if entry is None:
                index[ident] = (len(asset.findings), finding)
                asset.findings.append(finding)
                continue
            position, kept = entry
            self._counts["duplicates_merged"] += 1
            kept_ids = kept["details"].get("plugin_ids") or [kept["details"].get("plugin_id")]
            new_id = finding["details"].get("plugin_id")
            if float(finding["severity"]) > float(kept["severity"]):
                winner, ids = finding, [new_id] + kept_ids
                asset.findings[position] = finding
                index[ident] = (position, finding)
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
        self._reset_counts()
        stats = self._counts
        without_findings = 0
        assets: Dict[str, AssetData] = {}
        indexes: Dict[str, Dict[Tuple[str, str], Tuple[int, Dict[str, Any]]]] = {}
        props: Dict[str, str] = {}
        findings: List[Dict[str, Any]] = []
        in_host = False
        root_tag = ""
        conflicts = 0
        # Open elements, so each finished element is detached from its own parent.
        open_elems: List[Any] = []
        try:
            for event, tag, elem in self._events(file_path):
                if event == "start":
                    open_elems.append(elem)
                    if tag == "ReportHost":
                        in_host = True
                    continue
                open_elems.pop()
                parent = open_elems[-1] if open_elems else None
                root_tag = tag
                if tag == "attachment":
                    # The parser still reads the text of one attachment into memory once.
                    self._release(elem, parent)
                elif tag == "HostProperties":
                    for child in elem.iter("tag"):
                        if child.get("name") and child.get("name") not in props:
                            props[child.get("name")] = child.text or ""
                    self._release(elem, parent)
                elif tag == "ReportItem":
                    stats["items"] += 1
                    if in_host:
                        findings.extend(self._item_findings(elem))
                    else:
                        self._invalid(elem, "item outside ReportHost")
                    self._release(elem, parent)
                elif tag == "ReportHost":
                    in_host = False
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
                            if any(k in asset.attributes and asset.attributes[k] != v
                                   for k, v in attrs.items()):
                                conflicts += 1
                            for k, v in attrs.items():
                                asset.attributes.setdefault(k, v)
                        self._add_findings(asset, indexes[key], findings)
                    props, findings = {}, []
                    self._release(elem, parent)
                elif tag == "Report":
                    self._release(elem, parent)
        except (DefusedXmlException, ET.ParseError) as exc:
            raise NessusParseError(f"Nessus XML parse failed for {name}: {exc}") from exc
        if root_tag != ROOT_TAG:
            raise NessusParseError(
                f"Nessus XML parse failed for {name}: root element is <{root_tag}>, not {ROOT_TAG}"
            )
        result: List[AssetData] = []
        for asset in assets.values():
            if not asset.findings and not self.create_inventory_assets:
                without_findings += 1
                continue
            # Inventory mode: a host with no finding gets the base translator's placeholder.
            result.append(self.ensure_asset_has_findings(asset))
        stats["assets"] = len(result)
        stats["findings"] = sum(len(a.findings) for a in result)
        logger.info(
            "Nessus XML %s: hosts=%d items=%d informational_skipped=%d invalid_items=%d "
            "invalid_hosts=%d duplicates_merged=%d findings=%d assets=%d",
            name, stats["hosts"], stats["items"], stats["informational_skipped"],
            stats["invalid_items"], stats["invalid_hosts"], stats["duplicates_merged"],
            stats["findings"], stats["assets"],
        )
        if conflicts:
            logger.info("Nessus XML %s: merged hosts with conflicting attributes=%d", name, conflicts)
        if not result:
            raise NessusEmptyScan(
                f"Nessus file {name} holds no importable finding",
                {**stats, "assets_without_findings": without_findings},
            )
        return result
