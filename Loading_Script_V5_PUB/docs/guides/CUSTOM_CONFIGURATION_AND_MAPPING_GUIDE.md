# Custom Configuration and Import Mapping Guide

**Tool:** Phoenix Multi-Scanner Import (`phoenix_multi_scanner_enhanced.py`)  
**Version:** 5.0  
**Applies to:** `Utils/Loading_Script_V5/`

---

## Overview

The Phoenix Multi-Scanner Import Tool uses a **two-layer configuration model**:

| Layer | File | Purpose |
|-------|------|---------|
| **Connection & Behavior** | `config_multi_scanner.ini` | API credentials, import behavior, per-scanner overrides |
| **Field Mapping** | `scanner_field_mappings.yaml` | How each scanner's output fields map to Phoenix Security fields |

To support a new scanner or customize an existing one, you work with both files. The INI file controls _how_ the import runs; the YAML file controls _what_ gets imported and _how_ fields are translated.

---

## Part 1 — Connection & Behavior Configuration (`config_multi_scanner.ini`)

### 1.1 Required Phoenix Section

Every `config_multi_scanner.ini` must begin with a `[phoenix]` section:

```ini
[phoenix]
client_id     = your-client-id
client_secret = pat1_your-personal-access-token

# Choose one environment:
api_base_url  = https://api.appsecphx.io           # Production
# api_base_url = https://api.demo.appsecphx.io     # Demo
# api_base_url = https://api.poc1.appsecphx.io     # POC
```

**Credential precedence (highest to lowest):**
1. CLI flags (`--client-id`, `--client-secret`)
2. Environment variables (`PHOENIX_CLIENT_ID`, `PHOENIX_CLIENT_SECRET`, `PHOENIX_API_BASE_URL`)
3. `config_multi_scanner.ini` values
4. Built-in defaults

### 1.2 Import Behavior Settings

```ini
[phoenix]
# Import mode: new | merge | delta
#   new   — closes all existing vulnerabilities, replaces with imported set
#   merge — adds new findings, does not close existing ones
#   delta — only updates differences (safest for testing)
import_type = new

# Assessment name (auto-generated if empty)
assessment_name = Q2-2026-Trivy-Scan

# Wait for the API to confirm import completion
auto_import          = true
wait_for_completion  = true
timeout              = 3600   # seconds
check_interval       = 10     # seconds

# Apply tags to imported assets after import finishes
apply_tags_after_import = false
```

### 1.3 Per-Scanner Sections

Add a `[scanner_<name>]` section to override defaults for a specific scanner type. The `scanner_type` value must match the Phoenix Security scanner type string exactly.

```ini
[scanner_trivy]
scanner_type              = Trivy Scan
asset_type                = CONTAINER
severity_mapping_critical = 10.0
severity_mapping_high     = 8.0
severity_mapping_medium   = 5.0
severity_mapping_low      = 2.0
severity_mapping_negligible = 1.0

[scanner_bandit]
scanner_type              = Bandit Scan
asset_type                = CODE
severity_mapping_high     = 8.0
severity_mapping_medium   = 5.0
severity_mapping_low      = 2.0

[scanner_my_custom_tool]
scanner_type              = My Custom Tool
asset_type                = INFRA
severity_mapping_critical = 10.0
severity_mapping_high     = 8.0
severity_mapping_medium   = 5.0
severity_mapping_low      = 2.0
# Filter out noise
vulnerability_filters     = info,informational,negligible
```

### 1.4 Batch Processing Settings

```ini
[batch_processing]
max_parallel_files = 5      # Files processed concurrently
max_file_size      = 100    # MB; files larger than this are skipped or split
skip_large_files   = true
retry_count        = 3
retry_delay        = 30     # Seconds between retries
```

### 1.5 Logging Settings

```ini
[logging]
level        = INFO   # DEBUG | INFO | WARNING | ERROR
file         = phoenix_import.log
max_size     = 10MB
backup_count = 5
```

---

## Part 2 — Field Mapping Configuration (`scanner_field_mappings.yaml`)

This YAML file defines every scanner the tool knows about. Each scanner entry specifies:
- How to **detect** that a file came from this scanner
- How to **map** the scanner's fields to the Phoenix Security API format
- How to **translate** severity values

### 2.1 Top-Level Structure

```yaml
phoenix_fields:        # Global Phoenix API field definitions (do not modify)
  asset_attributes: ...
  findings: ...

default_severity_mappings:   # Fallback severity table (optional)
  ...

scanners:              # Your scanner definitions go here
  <scanner_key>:
    formats:
      - name: ...
```

### 2.2 Asset Types and Required Fields

Choose the correct `asset_type` for each scanner. The field marked as required must appear in your `field_mappings.asset` block.

| Asset Type | Required Field(s) | Optional Fields |
|------------|-------------------|-----------------|
| `INFRA` | `ip` or `hostname` (one is enough) | `network`, `fqdn`, `os`, `netbios`, `macAddress` |
| `WEB` | `ip` or `fqdn` (one is enough) | — |
| `CLOUD` | `providerType`, `providerAccountId`, `region` | `vpc`, `subnet`, `providerAccountName`, `providerResourceId`, `resourceGroup` |
| `CONTAINER` | `dockerfile` | `repository`, `origin` |
| `REPOSITORY` | `repository` | `origin` |
| `CODE` | `scannerSource` | `origin` |
| `BUILD` | `buildFile` | `repository`, `origin` |

### 2.3 Phoenix Vulnerability Fields

Every vulnerability record must supply these fields. If a field cannot be mapped from the source data, provide a static fallback string.

| Field | Required | Notes |
|-------|----------|-------|
| `name` | Yes | Vulnerability title |
| `description` | Yes | Detailed description |
| `remedy` | Yes | Remediation guidance |
| `severity` | Yes | Must resolve to a float string `"1.0"` – `"10.0"` |
| `location` | Yes | File path, IP:port, package name, URL, etc. |
| `reference_ids` | No | CVE IDs (extracted automatically from text) |
| `cwes` | No | CWE identifiers |
| `published_date_time` | No | Formatted as `YYYY-MM-DD HH:MM:SS` |
| `details` | No | Free-form key/value object for extra metadata |

---

## Part 3 — Writing a Scanner Entry

### 3.1 Minimal Template

```yaml
scanners:
  my_scanner:                          # Unique key, lowercase with underscores
    formats:
      - name: "my_scanner_json"        # Unique format name
        file_patterns: ["*.json"]      # Glob patterns to pre-filter files
        format_type: "json"            # json | xml | csv
        asset_type: "INFRA"            # See asset type table above
        detection:                     # Rules to confirm this is the right scanner
          json_keys: ["hosts", "vulnerabilities"]
          required_keys: ["hosts"]
        field_mappings:
          asset:
            ip: "host_ip"
            hostname: "host_name"
            origin: "my-scanner"       # Static string — wrap in quotes
          vulnerability:
            name: "vulnerabilities[].title"
            description: "vulnerabilities[].detail"
            remedy: "vulnerabilities[].fix"
            severity: "vulnerabilities[].risk"
            location: "host_ip"
            reference_ids: "vulnerabilities[].cve_id"
        severity_mapping:
          "critical": "10.0"
          "high": "8.0"
          "medium": "5.0"
          "low": "2.0"
          "info": "1.0"
```

### 3.2 Detection Rules

The detector reads a file and checks it against every scanner's `detection` block. The first scanner that passes all checks wins. Be specific enough to avoid false positives.

#### JSON Detection

```yaml
detection:
  json_keys:     ["key1", "key2"]   # Keys that must exist anywhere in the JSON root
  required_keys: ["key1"]           # Keys that must be non-null/non-empty
  is_array_root: true               # Set true if the JSON root is an array, not an object
```

Example — matches a file that has `{"matches": [...], "source": {...}}`:

```yaml
detection:
  json_keys:     ["matches", "source"]
  required_keys: ["matches"]
```

Example — matches a file that is a root-level array containing objects with `rule` and `severity` keys:

```yaml
detection:
  json_keys:     ["rule", "severity", "message"]
  required_keys: ["rule", "severity"]
  is_array_root: true
```

#### XML Detection

```yaml
detection:
  xml_root:          "RootElementName"     # Tag name of the XML document root
  required_elements: ["ChildTag1", "ChildTag2"]
```

#### CSV Detection

```yaml
detection:
  csv_headers:      ["Col1", "Col2", "Col3"]  # Headers that should exist in the CSV
  required_headers: ["Col1", "Col2"]           # Headers that must not be empty
```

#### File Pattern Hints

`file_patterns` is a secondary hint. It narrows which files are even considered:

```yaml
file_patterns: ["*trivy*.json"]         # Only files whose name contains "trivy"
file_patterns: ["*.xml"]                # Any XML file
file_patterns: ["report-*.csv"]         # CSV files starting with "report-"
```

---

## Part 4 — Field Path Notation

All paths in `field_mappings` use dot notation to navigate JSON or XML structure.

### 4.1 Simple Dot Notation

```yaml
# JSON: {"target": {"url": "https://example.com"}}
fqdn: "target.url"

# JSON: {"scan": {"metadata": {"host": "10.0.0.1"}}}
ip: "scan.metadata.host"
```

### 4.2 Array Notation (`[]`)

Use `[]` to indicate that a field is inside an array. The tool iterates over every element in the array and creates one vulnerability record per element.

```yaml
# JSON: {"results": [{"id": "CVE-2024-1234", "severity": "High"}, ...]}
name:     "results[].id"
severity: "results[].severity"
```

For nested arrays (e.g., hosts each containing a list of vulnerabilities):

```yaml
# JSON: {"resources": [{"resource": {"name": "openssl"}, "vulnerabilities": [{"name": "CVE-..."}]}]}
name:     "resources[].vulnerabilities[].name"
location: "resources[].resource.name"
```

For a specific index:

```yaml
# JSON: {"AffectedItems": [{"Url": "https://..."}, ...]}
location: "AffectedItems[0].Url"     # First element only
```

### 4.3 Static Values

Wrap a value in double quotes inside the YAML string to inject a constant regardless of source data:

```yaml
origin:  "trivy-scan"       # Always sets origin to the literal string "trivy-scan"
remedy:  "Update package to latest version"   # Hardcoded fallback text
severity: "5.0"             # Always map to medium (useful when the scanner has no severity field)
```

### 4.4 Composite Paths (Concatenated Fields)

Combine two paths with a colon `:` to concatenate them with a separator. Useful for building `location` strings:

```yaml
# Produces "10.0.0.1:8080"
location: "host_ip:port"

# Produces "/app/main.py:42"
location: "results[].filename:results[].line_number"
```

---

## Part 5 — Severity Mapping

Map the scanner's raw severity strings to Phoenix's numeric scale (`1.0` – `10.0`).

```yaml
severity_mapping:
  "Critical":   "10.0"
  "High":        "8.0"
  "Medium":      "5.0"
  "Low":         "2.0"
  "Negligible":  "1.0"
  "Info":        "1.0"
```

**Rules:**
- Matching is case-insensitive — `"high"` matches `"High"` and `"HIGH"`
- If the scanner outputs a numeric CVSS score (e.g., `7.5`), the tool passes it through directly
- If no match is found, the tool defaults to `"5.0"` (medium)
- Numeric scanner values (e.g., Qualys 1–5) map to Phoenix scale:

```yaml
severity_mapping:
  "1": "2.0"
  "2": "2.0"
  "3": "5.0"
  "4": "8.0"
  "5": "10.0"
```

---

## Part 6 — The `details` Object

Use `details` to carry scanner-specific metadata that does not fit the standard Phoenix fields. This data is stored as a structured object and is searchable within Phoenix.

```yaml
vulnerability:
  name:        "results[].test_name"
  description: "results[].issue_text"
  severity:    "results[].issue_severity"
  location:    "results[].filename"
  details:
    test_id:    "results[].test_id"
    line_number: "results[].line_number"
    confidence:  "results[].issue_confidence"
    code_snippet: "results[].code"
    cvss_score:  "results[].cvss_v3_score"
```

---

## Part 7 — Complete Examples

### Example 1 — Custom JSON Scanner (INFRA)

**Input file** (`internal-vuln-scanner.json`):

```json
{
  "scan_id": "scan-2026-001",
  "scanned_host": "db-server-01",
  "host_ip": "10.1.2.30",
  "issues": [
    {
      "id": "CVE-2024-12345",
      "title": "OpenSSL Buffer Overflow",
      "detail": "OpenSSL 3.0.x before 3.0.7 is vulnerable",
      "fix": "Upgrade OpenSSL to 3.0.7 or later",
      "risk_level": "high",
      "package": "openssl:3.0.1",
      "cvss": 8.1
    }
  ]
}
```

**YAML mapping:**

```yaml
scanners:
  internal_vuln_scanner:
    formats:
      - name: "ivs_json"
        file_patterns: ["internal-vuln-*.json", "ivs-*.json"]
        format_type: "json"
        asset_type: "INFRA"
        detection:
          json_keys: ["scan_id", "scanned_host", "issues"]
          required_keys: ["scanned_host", "issues"]
        field_mappings:
          asset:
            hostname: "scanned_host"
            ip:       "host_ip"
            origin:   "internal-vuln-scanner"
          vulnerability:
            name:          "issues[].title"
            description:   "issues[].detail"
            remedy:        "issues[].fix"
            severity:      "issues[].risk_level"
            location:      "issues[].package"
            reference_ids: "issues[].id"
            details:
              cvss_score: "issues[].cvss"
              scan_id:    "scan_id"
        severity_mapping:
          "critical": "10.0"
          "high":      "8.0"
          "medium":    "5.0"
          "low":       "2.0"
          "info":      "1.0"
```

**INI section:**

```ini
[scanner_internal_vuln_scanner]
scanner_type              = Internal Vuln Scanner
asset_type                = INFRA
severity_mapping_critical = 10.0
severity_mapping_high     = 8.0
severity_mapping_medium   = 5.0
severity_mapping_low      = 2.0
```

---

### Example 2 — Custom CSV Scanner (WEB)

**Input file** (`webapp-scan.csv`):

```csv
URL,Finding,Details,Remediation,Risk
https://app.example.com/login,SQL Injection,Login form susceptible to SQLi,Use parameterized queries,HIGH
https://app.example.com/api,Missing HSTS,HSTS header not set,Add Strict-Transport-Security header,MEDIUM
```

**YAML mapping:**

```yaml
scanners:
  custom_web_scanner:
    formats:
      - name: "custom_web_csv"
        file_patterns: ["webapp-scan*.csv"]
        format_type: "csv"
        asset_type: "WEB"
        detection:
          csv_headers:      ["URL", "Finding", "Details", "Remediation", "Risk"]
          required_headers: ["URL", "Finding"]
        field_mappings:
          asset:
            fqdn:   "URL"
            origin: "custom-web-scanner"
          vulnerability:
            name:        "Finding"
            description: "Details"
            remedy:      "Remediation"
            severity:    "Risk"
            location:    "URL"
        severity_mapping:
          "CRITICAL": "10.0"
          "HIGH":      "8.0"
          "MEDIUM":    "5.0"
          "LOW":       "2.0"
          "INFO":      "1.0"
```

---

### Example 3 — Custom XML Scanner (CONTAINER)

**Input file** (`container-audit.xml`):

```xml
<ScanReport>
  <image>myapp:v2.1.0</image>
  <findings>
    <finding>
      <cve>CVE-2024-99999</cve>
      <package>libssl1.1</package>
      <version>1.1.1f</version>
      <severity>HIGH</severity>
      <summary>SSL library with known exploit</summary>
      <fix>Upgrade to libssl 1.1.1w</fix>
    </finding>
  </findings>
</ScanReport>
```

**YAML mapping:**

```yaml
scanners:
  custom_container_scanner:
    formats:
      - name: "container_audit_xml"
        file_patterns: ["container-audit*.xml"]
        format_type: "xml"
        asset_type: "CONTAINER"
        detection:
          xml_root:          "ScanReport"
          required_elements: ["image", "findings"]
        field_mappings:
          asset:
            dockerfile: "image"
            repository: "image"
            origin:     "custom-container-scanner"
          vulnerability:
            name:          "findings.finding.cve"
            description:   "findings.finding.summary"
            remedy:        "findings.finding.fix"
            severity:      "findings.finding.severity"
            location:      "findings.finding.package"
            reference_ids: "findings.finding.cve"
            details:
              package:  "findings.finding.package"
              version:  "findings.finding.version"
        severity_mapping:
          "HIGH":   "8.0"
          "MEDIUM": "5.0"
          "LOW":    "2.0"
```

---

### Example 4 — Generic JSON Importer (object root with `findings[]`)

For tools that export a generic findings format:

**Input file:**

```json
{
  "ip_address": "10.0.0.30",
  "hostname": "worker-node-02",
  "findings": [
    {
      "vuln": "Outdated OpenSSL package",
      "description": "OpenSSL version contains known vulnerabilities",
      "fix": "Upgrade OpenSSL to latest supported patch level",
      "severity": "High",
      "package": "openssl",
      "cve": "CVE-2024-12345"
    }
  ]
}
```

**YAML mapping:**

```yaml
scanners:
  generic:
    formats:
      - name: "generic_json"
        format_type: "json"
        asset_type: "INFRA"
        detection:
          json_keys:     ["findings"]
          required_keys: ["findings"]
        field_mappings:
          asset:
            ip:       "ip_address"
            hostname: "hostname"
            origin:   "generic"
          vulnerability:
            name:          "findings[].vuln"
            description:   "findings[].description"
            remedy:        "findings[].fix"
            severity:      "findings[].severity"
            location:      "findings[].package"
            reference_ids: "findings[].cve"
        severity_mapping:
          "Critical": "10.0"
          "High":      "8.0"
          "Medium":    "5.0"
          "Low":       "2.0"
          "Negligible": "1.0"
```

---

## Part 8 — Running an Import

### Basic Usage

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan-output.json \
  --config config_multi_scanner.ini \
  --assessment "Q2-2026-Custom-Scan"
```

### Specify Scanner Explicitly

Use `--scanner` when auto-detection might be ambiguous:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file webapp-scan.csv \
  --scanner custom_web_scanner \
  --asset-type WEB \
  --import-type delta \
  --config config_multi_scanner.ini
```

### Test Without Importing (Dry Run / Debug)

Use `delta` import mode and `--debug` during development to see translated payloads without risking production data:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan-output.json \
  --scanner my_scanner \
  --import-type delta \
  --debug \
  --config config_multi_scanner.ini
```

### Import Mode Reference

| Mode | Effect | When to Use |
|------|--------|-------------|
| `new` | Closes all existing vulnerabilities, replaces with this import | Full replacement scan |
| `merge` | Adds new findings, leaves existing open ones untouched | Supplemental scan |
| `delta` | Only processes the difference from the last import | CI/CD incremental pipelines, testing |

---

## Part 9 — Validation and Troubleshooting

### Pre-Import Validation Checklist

Before running an import with a new mapping:

- [ ] The scanner key in the YAML is unique (no conflicts with existing scanners)
- [ ] `format_type` matches the actual file format (`json`, `xml`, or `csv`)
- [ ] `asset_type` is one of the seven valid values
- [ ] At least one required asset field is mapped (`ip`/`hostname` for INFRA, `fqdn` for WEB, etc.)
- [ ] All five required vulnerability fields are mapped: `name`, `description`, `remedy`, `severity`, `location`
- [ ] Severity values in the scanner output match keys in `severity_mapping` (case-insensitive)
- [ ] Array paths use `[]` notation consistently
- [ ] Static strings are wrapped in double quotes inside the YAML value string

### YAML Validation (Built-in)

The tool validates the YAML before applying it. To force a reload during a running session:

```python
field_mapper.reload_config()   # Returns True on success, False on error
```

### Detection Debugging

List all candidate scanners for a given file with their confidence scores:

```python
from scanner_field_mapper import FieldMapper, ScannerFormatDetector

fm = FieldMapper("scanner_field_mappings.yaml")
detector = ScannerFormatDetector(fm)
results = detector.get_all_possible_formats("my-scan.json")
for r in results:
    print(r['scanner'], r['format'], r['confidence'])
```

### Common Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Scanner not detected | Detection keys too generic or missing from file | Add more `required_keys`; check `is_array_root` for array-root JSON |
| Wrong scanner detected | Detection rules conflict with another scanner | Add file-pattern hints or more specific `required_keys` |
| Severity always `5.0` | Severity string not in `severity_mapping` | Print raw severity values from file, add the exact strings to the map |
| Missing asset fields | Required field path wrong | Use `--debug` to inspect the raw parsed record |
| Empty `location` field | Path doesn't exist or is nested differently | Trace the path manually; check for `[]` notation errors |
| `YAML validation failed` | Missing required YAML key | Ensure `name`, `format_type`, `asset_type`, `field_mappings` all present |
| Auto-detection ambiguous | Two scanners share detection keys | Override with `--scanner` flag; tighten `required_keys` |

### Log Locations

```
logs/                        # Standard import logs
errors/                      # Error logs (created when --debug is set)
debug/YYYYMMDD/              # Debug logs with full payloads
phoenix_import.log           # Default log file (configurable in INI)
```

---

## Part 10 — Hot-Reload Support

The `FieldMapper` class watches `scanner_field_mappings.yaml` for changes. In a long-running session (e.g., the scanner service), edits to the YAML are picked up automatically without restarting:

```python
# Called periodically by the service loop
was_reloaded = field_mapper.check_and_reload_config()
```

If the new YAML is invalid, the previous valid configuration is kept and an error is logged. The service never runs with a broken mapping.

---

## Quick Reference Card

```
scanner_field_mappings.yaml entry shape
═══════════════════════════════════════
scanners:
  <key>:                           # Lowercase, underscores
    formats:
      - name: "<unique_name>"      # Required
        file_patterns: ["*.ext"]   # Optional glob hints
        format_type: "json|xml|csv"# Required
        asset_type: "INFRA|WEB|CLOUD|CONTAINER|REPOSITORY|CODE|BUILD"
        detection:
          # JSON:  json_keys, required_keys, is_array_root
          # XML:   xml_root, required_elements
          # CSV:   csv_headers, required_headers
        field_mappings:
          asset:
            <phoenix_field>: "<path>"    # dot.notation or "static string"
          vulnerability:
            name:        "<path>"        # Required
            description: "<path>"        # Required
            remedy:      "<path|string>" # Required
            severity:    "<path|value>"  # Required → resolved via severity_mapping
            location:    "<path>"        # Required
            reference_ids: "<path>"      # Optional (CVEs extracted automatically)
            cwes:          "<path>"      # Optional
            details:                     # Optional free-form metadata
              <key>: "<path>"
        severity_mapping:
          "<scanner_value>": "<1.0–10.0>"

Path notation cheat-sheet
══════════════════════════
  field              → top-level key
  parent.child       → nested key
  array[].field      → iterate array, pick field from each element
  array[0].field     → specific index
  "static string"    → literal value injected into every record
  field1:field2      → concatenate two values with separator
```
