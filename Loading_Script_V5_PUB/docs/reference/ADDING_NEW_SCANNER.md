# Loading_Script_V5 — Adding a New Scanner

**Version**: 5.0 (Modular Architecture)
**Last Updated**: February 2026
**Path**: `Utils/Loading_Script_V5/`

---

## Table of Contents

- [Overview](#overview)
- [Option 1: YAML-Only Scanner (Quick)](#option-1-yaml-only-scanner-quick)
- [Option 2: Hard-Coded Translator (Full Control)](#option-2-hard-coded-translator-full-control)
- [Phoenix Vulnerability Schema](#phoenix-vulnerability-schema)
- [Testing Your Translator](#testing-your-translator)
- [Related Documents](#related-documents)

---

## Overview

There are two ways to add support for a new scanner:

| Method | Effort | When to Use |
|--------|--------|-------------|
| **YAML mapping** | ~15 minutes | Scanner has straightforward JSON/CSV with simple field mapping |
| **Hard-coded translator** | ~2 hours | Scanner has complex nesting, multiple formats, or requires custom logic |

---

## Option 1: YAML-Only Scanner (Quick)

Add an entry to `scanner_field_mappings.yaml`:

```yaml
scanners:
  my_new_scanner:
    formats:
      - name: my_new_scanner_json
        file_patterns: ["*.json"]
        format_type: json
        asset_type: INFRA
        detection:
          json_keys: ["my_scanner_results", "version"]
          required_keys: ["my_scanner_results"]
          confidence: 0.90
        field_mappings:
          asset:
            - source: "target.hostname"
              target: "asset_name"
            - source: "target.ip"
              target: "ip_address"
          vulnerability:
            - source: "finding.title"
              target: "name"
            - source: "finding.description"
              target: "description"
            - source: "finding.remediation"
              target: "remedy"
            - source: "finding.cvss_score"
              target: "severity"
            - source: "finding.location"
              target: "location"
            - source: "finding.cve_id"
              target: "referenceIds"
```

### Detection Configuration

| Field | Purpose | Example |
|-------|---------|---------|
| `json_keys` | Top-level keys that identify this scanner | `["Results", "SchemaVersion"]` |
| `required_keys` | Keys that must be present (subset of json_keys) | `["Results"]` |
| `confidence` | Detection confidence (0.0–1.0) | `0.90` |

---

## Option 2: Hard-Coded Translator (Full Control)

### Step 1: Create the Translator File

Create `scanner_translators/my_scanner_translator.py`:

```python
"""
My Scanner Translator for Phoenix Security.

Translates My Scanner JSON output to Phoenix vulnerability format.
"""

from typing import Any, List
from .base_translator import ScannerTranslator, AssetData, ScannerConfig


class MyScannerTranslator(ScannerTranslator):
    """Translator for My Scanner vulnerability output."""

    def __init__(self):
        config = ScannerConfig(
            name="My Scanner",
            scanner_type="my_scanner",
            default_asset_type="INFRA",
            supported_formats=["json"],
        )
        super().__init__(config)

    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this file is from My Scanner."""
        if file_content is None:
            return False
        if isinstance(file_content, dict):
            # Check for scanner-specific keys
            return "my_scanner_results" in file_content
        return False

    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse My Scanner output and return Phoenix-format assets."""
        import json

        with open(file_path, "r") as f:
            data = json.load(f)

        assets = []
        for result in data.get("my_scanner_results", []):
            # Build asset record
            asset_name = result.get("target", {}).get("hostname", "unknown")
            findings = []

            for finding in result.get("findings", []):
                # Normalize severity to 1.0-10.0 range
                severity = self.normalize_severity(finding.get("severity", "medium"))

                # Extract CVE identifiers
                cves = self.extract_cves(finding.get("references", ""))

                findings.append({
                    "name": finding.get("title", "Untitled Finding"),
                    "description": finding.get("description", "No description"),
                    "remedy": finding.get("remediation", "No remediation available"),
                    "severity": severity,
                    "location": finding.get("location", asset_name),
                    "referenceIds": cves,
                    "cwes": finding.get("cwe_ids", []),
                })

            asset = self.create_asset(
                name=asset_name,
                asset_type=self.config.default_asset_type,
                findings=findings,
            )
            assets.append(asset)

        return assets
```

### Step 2: Register in `__init__.py`

Add the import to `scanner_translators/__init__.py`:

```python
from .my_scanner_translator import MyScannerTranslator
```

### Step 3: Test

```bash
# Run with a sample file
python3 phoenix_multi_scanner_enhanced.py \
  --file sample-my-scanner-output.json \
  --scanner my_scanner \
  --config my_config.ini \
  --assessment "Test-My-Scanner"
```

---

## Phoenix Vulnerability Schema

### Required Fields

Every vulnerability finding must include these fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `name` | string | Vulnerability title | `"CVE-2024-1234: SQL Injection in login"` |
| `description` | string | Detailed description | `"SQL injection vulnerability in..."` |
| `remedy` | string | Remediation steps | `"Update to version 2.1.0 or later"` |
| `severity` | float | CVSS score (1.0–10.0) | `8.5` |
| `location` | string | Where the vulnerability exists | `"/usr/lib/libssl.so"` |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `referenceIds` | list[string] | CVE identifiers |
| `cwes` | list[string] | CWE identifiers |
| `publishedDateTime` | string | CVE publication date (ISO 8601) |
| `details` | string | Additional details |

### Asset Record

| Field | Type | Description |
|-------|------|-------------|
| `asset_name` | string | Asset identifier (hostname, image name, repo) |
| `asset_type` | string | One of: INFRA, WEB, CLOUD, CONTAINER, CODE, REPOSITORY, BUILD |
| `attributes` | dict | Asset-specific attributes (ip_address, fqdn, etc.) |
| `findings` | list | List of vulnerability findings |
| `tags` | list | Tags for asset categorization |

### Severity Normalization

The base class provides `normalize_severity()` for common mappings:

| Input | Output |
|-------|--------|
| `"critical"` | 10.0 |
| `"high"` | 8.0 |
| `"medium"` | 5.0 |
| `"low"` | 2.0 |
| `"info"` / `"negligible"` | 1.0 |
| Numeric string `"7.5"` | 7.5 |

---

## Testing Your Translator

### Unit Test Template

```python
import json
import pytest
from scanner_translators.my_scanner_translator import MyScannerTranslator


def test_can_handle():
    translator = MyScannerTranslator()
    valid_data = {"my_scanner_results": []}
    invalid_data = {"other_scanner": []}

    assert translator.can_handle("test.json", valid_data) is True
    assert translator.can_handle("test.json", invalid_data) is False


def test_parse_file(tmp_path):
    translator = MyScannerTranslator()

    sample_data = {
        "my_scanner_results": [{
            "target": {"hostname": "server-01"},
            "findings": [{
                "title": "Test Finding",
                "description": "A test vulnerability",
                "remediation": "Apply patch",
                "severity": "high",
                "location": "/usr/bin/app",
                "references": "CVE-2024-1234"
            }]
        }]
    }

    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps(sample_data))

    assets = translator.parse_file(str(test_file))
    assert len(assets) == 1
    assert len(assets[0].findings) == 1
    assert assets[0].findings[0]["severity"] == 8.0
```

### Checklist

- [ ] `can_handle()` correctly identifies your scanner's output
- [ ] `can_handle()` returns `False` for other scanners' output
- [ ] All five required fields are populated for every finding
- [ ] Severity is normalized to 1.0–10.0 range
- [ ] CVE identifiers are extracted correctly
- [ ] Empty/missing fields have sensible defaults
- [ ] Large files (10,000+ findings) process without errors

---

## Related Documents

- [Scanner Translator Guide](SCANNER_TRANSLATOR_GUIDE.md) — All supported scanners
- [Architecture](ARCHITECTURE.md) — System design
- [README](../../README.md) — Primary documentation
- [REFERENCE_DOCUMENTATION/JUNIOR_DEVELOPER_GUIDE.md](../guides/JUNIOR_DEVELOPER_GUIDE.md) — Developer onboarding
