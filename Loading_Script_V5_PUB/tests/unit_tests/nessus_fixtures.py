"""String builders for Nessus (.nessus) XML test files, shared by all Nessus tests."""

import os
import shutil
import tempfile
from html import escape
from typing import Dict, Optional, Sequence

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<NessusClientData_v2><Report name="r1"><ReportHost name="&lol4;"/></Report></NessusClientData_v2>
"""

XXE_FILE = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<NessusClientData_v2><Report name="r1"><ReportHost name="&xxe;"/></Report></NessusClientData_v2>
"""


def _attr(value) -> str:
    return escape(str(value), quote=True)


def item(severity=2, plugin_id=42, port="443", protocol="tcp", svc_name="www",
         plugin_name="Test plugin", cves: Sequence[str] = (), cwes: Sequence[str] = (),
         synopsis="Short.", description="Long.", solution="Fix it.", plugin_output=None,
         attachment=None, cvss_base_score=None, cvss3_base_score=None,
         vuln_publication_date=None, extra_attrs: Optional[Dict] = None) -> str:
    attrs = {
        "port": port, "svc_name": svc_name, "protocol": protocol, "severity": severity,
        "pluginID": plugin_id, "pluginName": plugin_name, "pluginFamily": "General",
    }
    for key, value in (extra_attrs or {}).items():
        attrs[key] = value
    attr_text = " ".join(f'{k}="{_attr(v)}"' for k, v in attrs.items() if v is not None)
    children = []

    def child(name, value):
        if value is not None:
            children.append(f"<{name}>{escape(str(value))}</{name}>")

    child("description", description)
    child("synopsis", synopsis)
    child("solution", solution)
    child("cvss_base_score", cvss_base_score)
    child("cvss3_base_score", cvss3_base_score)
    child("vuln_publication_date", vuln_publication_date)
    for cve in cves:
        child("cve", cve)
    for cwe in cwes:
        child("cwe", cwe)
    child("plugin_output", plugin_output)
    child("attachment", attachment)
    return f"<ReportItem {attr_text}>{''.join(children)}</ReportItem>"


def tags(**props) -> str:
    return "".join(f'<tag name="{_attr(k)}">{escape(str(v))}</tag>' for k, v in props.items())


def one_host(name="10.0.0.5", props=None, items="") -> str:
    if props is None:
        props = tags(**{"host-ip": name})
    properties = f"<HostProperties>{props}</HostProperties>" if props != "" else ""
    return f'<ReportHost name="{_attr(name)}">{properties}{items}</ReportHost>'


def nessus(*report_bodies: str) -> str:
    reports = "".join(f'<Report name="r{n}">{body}</Report>'
                      for n, body in enumerate(report_bodies, start=1))
    return f'<?xml version="1.0" ?><NessusClientData_v2>{reports}</NessusClientData_v2>'


def write(suffix: str, text: str) -> str:
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return handle.name


class TempFiles:
    """TestCase mixin: temp files and folders that are removed when the test ends."""

    def write(self, suffix: str, text: str) -> str:
        path = write(suffix, text)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def tmp_dir(self) -> str:
        path = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, path, True)
        return path
