# JSON Importer and Generic Importer Mapping Guide

## Purpose

This guide explains how to configure and verify field mappings for:

- `drheader` (JSON Importer)
- `generic` (Generic Importer)

Both importers are configured in `scanner_field_mappings.yaml` and translated through the YAML-based mapping engine.

---

## Quick Comparison

- `drheader` (JSON Importer): array-root JSON with DrHeader-specific keys
- `generic` (Generic Importer): object-root JSON with `findings[]`

---

## JSON Importer (`drheader`)

### Detection Rules for `drheader`

The importer activates when JSON content contains:

- `json_keys`: `rule`, `severity`, `message`, `expected`, `delimiter`
- `required_keys`: `rule`, `severity`
- `is_array_root`: `true`

### Field Mapping for `drheader`

Asset fields:

- `ip` <- `ip_address`
- `hostname` <- `hostname`
- `origin` <- static value `drheader`

Vulnerability fields:

- `name` <- `vuln`
- `description` <- `description`
- `remedy` <- `fix`
- `severity` <- `severity`
- `location` <- `package`
- `reference_ids` <- `cve`

### Severity Mapping for `drheader`

- `Critical` -> `10.0`
- `High` -> `8.0`
- `Medium` -> `5.0`
- `Low` -> `2.0`
- `Negligible` -> `1.0`

### Example Input (DrHeader)

```json
[
  {
    "ip_address": "10.0.0.20",
    "hostname": "api-gateway-01",
    "vuln": "Missing X-Content-Type-Options header",
    "description": "Response is missing security header",
    "fix": "Set X-Content-Type-Options to nosniff",
    "severity": "Medium",
    "package": "https://example.local/api",
    "cve": "N/A",
    "rule": "x-content-type-options",
    "message": "header missing",
    "expected": "nosniff",
    "delimiter": ":"
  }
]
```

---

## Generic Importer (`generic`)

### Detection Rules for `generic`

The importer activates when JSON content contains:

- `json_keys`: `findings`
- `required_keys`: `findings`

### Field Mapping for `generic`

Asset fields:

- `ip` <- `ip_address`
- `hostname` <- `hostname`
- `origin` <- static value `generic`

Vulnerability fields:

- `name` <- `findings[].vuln`
- `description` <- `findings[].description`
- `remedy` <- `findings[].fix`
- `severity` <- `findings[].severity`
- `location` <- `findings[].package`
- `reference_ids` <- `findings[].cve`

### Severity Mapping for `generic`

- `Critical` -> `10.0`
- `High` -> `8.0`
- `Medium` -> `5.0`
- `Low` -> `2.0`
- `Negligible` -> `1.0`

### Example Input (Generic)

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

---

## YAML Snippet Reference

These are the mapping blocks used by the importers:

```yaml
drheader:
  formats:
    - name: "drheader_json"
      format_type: "json"
      asset_type: "INFRA"
      detection:
        json_keys: ["rule", "severity", "message", "expected", "delimiter"]
        required_keys: ["rule", "severity"]
        is_array_root: true
      field_mappings:
        asset:
          ip: "ip_address"
          hostname: "hostname"
          origin: "drheader"
        vulnerability:
          name: "vuln"
          description: "description"
          remedy: "fix"
          severity: "severity"
          location: "package"
          reference_ids: "cve"

generic:
  formats:
    - name: "generic_json"
      format_type: "json"
      asset_type: "INFRA"
      detection:
        json_keys: ["findings"]
        required_keys: ["findings"]
      field_mappings:
        asset:
          ip: "ip_address"
          hostname: "hostname"
          origin: "generic"
        vulnerability:
          name: "findings[].vuln"
          description: "findings[].description"
          remedy: "findings[].fix"
          severity: "findings[].severity"
          location: "findings[].package"
          reference_ids: "findings[].cve"
```

---

## Validation Checklist

Before running an import:

- Input JSON matches one of the two shapes described above
- `severity` values map to configured levels (`Critical`, `High`, `Medium`, `Low`, `Negligible`)
- Asset identity fields are present (`ip_address` and/or `hostname`)
- Finding fields are present (`vuln`, `description`, `severity`)

---

## Test Commands

Use explicit scanner selection during validation:

```bash
python3 phoenix_multi_scanner_enhanced.py --file drheader-sample.json --scanner drheader --asset-type INFRA --import-type delta --debug
python3 phoenix_multi_scanner_enhanced.py --file generic-sample.json --scanner generic --asset-type INFRA --import-type delta --debug
```

Use `delta` while testing to avoid unintentionally closing vulnerabilities.
