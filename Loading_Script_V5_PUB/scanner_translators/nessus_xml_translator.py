#!/usr/bin/env python3
"""
Nessus XML (.nessus) Translator
===============================

Reads Tenable Nessus ``NessusClientData_v2`` exports. The file is untrusted
input, so it is parsed with ``defusedxml`` (no entity expansion, no external
entities) and as a stream, so large scans do not sit in memory.
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from phoenix_import_refactored import AssetData

from .base_translator import ScannerTranslator

logger = logging.getLogger(__name__)

ROOT_TAG = "NessusClientData_v2"
_HEAD_BYTES = 4096
_SKIP_PROLOG = re.compile(
    rb"\s*(?:<\?.*?\?>|<!--.*?-->|<!DOCTYPE(?:[^\[>]|\[.*?\])*>)", re.DOTALL | re.IGNORECASE
)
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

    def parse_file(self, file_path: str) -> List[AssetData]:
        name = Path(file_path).name
        try:
            from defusedxml import DefusedXmlException
        except ImportError as exc:
            raise NessusParseError(
                f"Nessus XML parse failed for {name}: the defusedxml package is missing: "
                "run pip install defusedxml"
            ) from exc
        try:
            for tag, elem in self._events(file_path):
                if tag == "attachment":
                    # The parser still reads the text of one attachment into memory once.
                    self._release(elem)
                elif tag == "ReportItem":
                    # Task 3 reads the finding here, then releases it.
                    self._release(elem)
                elif tag == "ReportHost":
                    # Task 2 finishes the host here, then releases it.
                    self._release(elem)
        except (DefusedXmlException, ET.ParseError) as exc:
            raise NessusParseError(f"Nessus XML parse failed for {name}: {exc}") from exc
        return []
