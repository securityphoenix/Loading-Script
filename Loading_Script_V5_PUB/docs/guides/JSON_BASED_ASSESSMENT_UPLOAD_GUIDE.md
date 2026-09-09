# JSON-Based Assessment Upload Guide

This guide explains how to upload JSON scanner output into Phoenix assessments using the tools in `Loading_Script_V5_PUB`.

If you meant "jsob", this guide covers the JSON flow.

---

## What This Covers

- Uploading JSON results with `phoenix_multi_scanner_enhanced.py`
- JSON importer shapes supported by this repo (`generic`, `drheader`)
- Choosing the right `--import-type` for assessment safety
- Baseline vs incremental (delta) upload workflows
- Optional upload via `phoenix-scanner-client` (service-based pattern)

---

## Prerequisites

From `Loading_Script_V5_PUB`:

```bash
python3 -m pip install -r requirements.txt
```

You also need valid Phoenix credentials in your config or environment variables (do not hardcode secrets in files).

---

## Step 1: Prepare Your JSON Input

The project supports many JSON scanner formats, but for custom JSON-based assessments the two most relevant mappings are:

1. `generic` scanner mapping (`findings` array model)
2. `drheader` scanner mapping (array-root model)

## JSON Format Specification

Use one of the following formats exactly.

### Format 1: `generic` (`--scanner generic`)

- Root type: JSON object
- Required top-level key:
  - `findings` (array)
- Common top-level asset keys:
  - `ip_address` (recommended)
  - `hostname` (recommended)
- Required fields per `findings[]` item:
  - `vuln`
  - `description`
  - `severity`
- Recommended fields per `findings[]` item:
  - `fix`
  - `package`
  - `cve`

Minimal valid `generic` example:

```json
{
  "ip_address": "10.0.0.30",
  "hostname": "worker-node-02",
  "findings": [
    {
      "vuln": "Outdated OpenSSL package",
      "description": "OpenSSL version contains known vulnerabilities",
      "severity": "High"
    }
  ]
}
```

Extended `generic` example:

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

### Format 2: `drheader` (`--scanner drheader`)

- Root type: JSON array
- Required keys in each array item:
  - `rule`
  - `severity`
- Recommended keys in each array item:
  - `ip_address`
  - `hostname`
  - `vuln`
  - `description`
  - `fix`
  - `package`
  - `cve`
  - `message`
  - `expected`
  - `delimiter`

Minimal valid `drheader` example:

```json
[
  {
    "rule": "x-content-type-options",
    "severity": "Medium"
  }
]
```

Extended `drheader` example:

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

### Severity Values

Use one of these severity values for best mapping:

- `Critical`
- `High`
- `Medium`
- `Low`
- `Negligible`

### Format Validation Notes

- If your file does not match either model, set `--scanner` explicitly and reshape the JSON.
- For custom pipelines, start with the minimal examples, then add extended fields.
- Keep key names exactly as shown (case-sensitive).

---

## Step 2: Choose Assessment and Import Strategy

Use a clear assessment name (examples):

- `Weekly-Infrastructure-JSON-Scan`
- `Q2-Web-Headers-Assessment`
- `Container-Security-Baseline`

Pick import mode carefully:

- `new`: full refresh of assessment data (baseline or scheduled full scan)
- `merge`: combine/update in existing assessment (multi-scanner on same assets)
- `delta`: safest for partial uploads (does not close missing findings)

For most CI or incremental JSON imports, use `delta`.

---

## Incremental Uploads: Baseline vs Delta

Phoenix assessments are long-lived containers. JSON uploads can follow a **baseline + incremental** pattern using the same `--assessment` name across runs.

### Import type behavior (summary)

| Import type | Creates/updates assets | Adds new findings | Closes missing findings | Safe for partial data |
|-------------|------------------------|-------------------|-------------------------|------------------------|
| `new`       | Yes                    | Yes               | Yes                     | No                     |
| `merge`     | Yes                    | Yes               | Yes                     | No                     |
| `delta`     | Yes                    | Yes               | No                      | Yes                    |

### Pattern A: Baseline then incremental delta (recommended for CI)

Use this when each pipeline run may produce **partial** JSON (subset of assets or findings).

**Run 1 — baseline (first upload)**

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file baseline-scan.json \
  --scanner generic \
  --asset-type INFRA \
  --assessment "Weekly-Infrastructure-JSON-Scan" \
  --import-type new \
  --asset-name "infra-json-scan" \
  --fix-data \
  --enable-batching \
  --verify-import
```

**Run 2+ — incremental delta (same assessment name)**

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file incremental-scan.json \
  --scanner generic \
  --asset-type INFRA \
  --assessment "Weekly-Infrastructure-JSON-Scan" \
  --import-type delta \
  --asset-name "infra-json-scan" \
  --fix-data \
  --enable-batching
```

What happens:

- Run 1 creates the assessment and loads the initial finding set.
- Run 2+ adds or updates findings only; findings **not** in the new JSON are **not** auto-closed.

### Pattern B: Baseline then weekly full refresh (`new`)

Use this when every scheduled run is a **complete** scan of all in-scope assets and you want missing findings marked as fixed.

**Run 1 — baseline**

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file week-01-full.json \
  --scanner generic \
  --assessment "Weekly-Infrastructure-JSON-Scan" \
  --import-type new
```

**Run 2+ — full refresh (same assessment)**

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file week-02-full.json \
  --scanner generic \
  --assessment "Weekly-Infrastructure-JSON-Scan" \
  --import-type new
```

What happens:

- Each run replaces assessment content against the latest full payload.
- Findings absent from the new file can be closed (intended for complete scans only).

### Pattern C: Multi-scanner on one assessment

Use when combining JSON from different tools into one assessment view.

**Scanner 1 — establish baseline**

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file generic-scan.json \
  --scanner generic \
  --assessment "Q2-Complete-Security-Review" \
  --import-type new
```

**Scanner 2 — add findings to same assessment**

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file drheader-scan.json \
  --scanner drheader \
  --assessment "Q2-Complete-Security-Review" \
  --import-type merge
```

Use `merge` (not `delta`) when the second scanner represents another complete source you want combined with existing assessment data.

### Decision guide

```text
Is this the first upload for the assessment?
├─ YES → Use --import-type new (baseline)
└─ NO  → Is the JSON a complete scan of all in-scope assets?
          ├─ YES → Use --import-type new (full refresh) or merge (multi-scanner)
          └─ NO  → Use --import-type delta (incremental, safest)
```

### CI/CD safe defaults

- Nightly/PR partial JSON uploads: `--import-type delta`
- Weekly full inventory scan with closure semantics: `--import-type new`
- Additional scanner on same assessment: first `new`, then `merge`
- Always reuse the same `--assessment` value when continuing a workflow

### How to implement baseline + incremental (step by step)

1. **Pick one stable assessment name** for the lifecycle (do not change it between runs).
2. **Run baseline once** with `--import-type new` to create the assessment and load initial findings.
3. **Run all follow-up uploads** to the same assessment with `--import-type delta` (partial) or `new` (full refresh).
4. **Keep scanner and asset context consistent** (`--scanner`, `--asset-type`, `--asset-name`) so Phoenix maps updates to the same assets.
5. **Validate in Phoenix UI** after baseline, then after the first delta run, before automating further.

Example lifecycle:

```text
Day 0 (baseline):  assessment="Prod-JSON-Weekly", import-type=new   → creates assessment
Day 1 (partial):   assessment="Prod-JSON-Weekly", import-type=delta → adds/updates only
Day 2 (partial):   assessment="Prod-JSON-Weekly", import-type=delta → adds/updates only
Day 7 (full scan): assessment="Prod-JSON-Weekly", import-type=new   → refresh + close missing
```

### CI/CD implementation examples

#### GitHub Actions: baseline on schedule, delta on every push

```yaml
name: JSON Scanner Upload

on:
  schedule:
    - cron: "0 6 * * 1"   # Monday 06:00 UTC baseline
  push:
    branches: [main]

jobs:
  upload-json:
    runs-on: ubuntu-latest
    env:
      PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
      PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
      PHOENIX_API_BASE_URL: ${{ secrets.PHOENIX_API_BASE_URL }}
      ASSESSMENT_NAME: prod-json-security-weekly
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        working-directory: Loading_Script_V5_PUB
        run: pip install -r requirements.txt

      - name: Upload JSON (baseline on schedule, delta on push)
        working-directory: Loading_Script_V5_PUB
        run: |
          if [ "${{ github.event_name }}" = "schedule" ]; then
            IMPORT_TYPE="new"
          else
            IMPORT_TYPE="delta"
          fi

          python3 phoenix_multi_scanner_enhanced.py \
            --file scan-results.json \
            --scanner generic \
            --asset-type INFRA \
            --assessment "${ASSESSMENT_NAME}" \
            --import-type "${IMPORT_TYPE}" \
            --asset-name "prod-json-scan" \
            --fix-data \
            --enable-batching \
            --verify-import
```

#### Jenkins: explicit baseline stage, then delta stage

```groovy
pipeline {
  agent any
  environment {
    ASSESSMENT_NAME = 'prod-json-security-weekly'
  }
  stages {
    stage('Baseline Upload (first run only)') {
      when { expression { params.RUN_BASELINE == true } }
      steps {
        sh '''
          python3 phoenix_multi_scanner_enhanced.py \
            --file baseline-scan.json \
            --scanner generic \
            --assessment "${ASSESSMENT_NAME}" \
            --import-type new \
            --asset-name prod-json-scan
        '''
      }
    }
    stage('Incremental Delta Upload') {
      when { expression { params.RUN_BASELINE != true } }
      steps {
        sh '''
          python3 phoenix_multi_scanner_enhanced.py \
            --file incremental-scan.json \
            --scanner generic \
            --assessment "${ASSESSMENT_NAME}" \
            --import-type delta \
            --asset-name prod-json-scan
        '''
      }
    }
  }
}
```

Trigger baseline manually once (`RUN_BASELINE=true`), then run incremental uploads with default parameters.

#### Service client path (baseline + delta)

```bash
# Baseline
python3 phoenix-scanner-client/actions/upload_single.py \
  --file baseline-scan.json \
  --scanner-type generic \
  --assessment "Prod-JSON-Weekly" \
  --import-type new \
  --wait

# Incremental
python3 phoenix-scanner-client/actions/upload_single.py \
  --file incremental-scan.json \
  --scanner-type generic \
  --assessment "Prod-JSON-Weekly" \
  --import-type delta \
  --wait
```

### Folder-based incremental uploads

Process multiple JSON files into one assessment over time:

```bash
# Baseline folder import
python3 phoenix_multi_scanner_enhanced.py \
  --folder ./baseline-scans/ \
  --file-types json \
  --scanner generic \
  --assessment "Prod-JSON-Weekly" \
  --import-type new

# Later incremental folder import (same assessment)
python3 phoenix_multi_scanner_enhanced.py \
  --folder ./delta-scans/ \
  --file-types json \
  --scanner generic \
  --assessment "Prod-JSON-Weekly" \
  --import-type delta
```

### Common mistakes to avoid

| Mistake | Impact | Fix |
|---------|--------|-----|
| Changing `--assessment` between runs | Creates a new assessment instead of updating | Reuse the exact same assessment name |
| Using `new`/`merge` on partial JSON | Closes findings not present in payload | Use `delta` for partial uploads |
| Skipping baseline (`delta` on first run) | Assessment context may be incomplete | First run should use `new` |
| Different `--asset-name` per run | Updates may not map to same asset | Keep asset naming stable in CI |
| Mixed scanners without plan | Unexpected merge/closure behavior | Use Pattern C (`new` then `merge`) |

---

## Step 3: Run Direct Upload (No Service Required)

### Generic JSON upload

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file generic-scan.json \
  --scanner generic \
  --asset-type INFRA \
  --assessment "Weekly-Infrastructure-JSON-Scan" \
  --import-type delta \
  --asset-name "infra-json-scan" \
  --fix-data \
  --enable-batching \
  --verify-import
```

### DrHeader JSON upload

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file drheader-scan.json \
  --scanner drheader \
  --asset-type WEB \
  --assessment "Weekly-Header-Assessment" \
  --import-type delta \
  --asset-name "web-header-scan" \
  --fix-data \
  --enable-batching \
  --verify-import
```

### Auto-detect JSON scanner

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan-results.json \
  --scanner auto \
  --assessment "Auto-Detected-JSON-Assessment" \
  --import-type delta
```

---

## Step 4 (Optional): Service-Based Upload with Client

If you are using the scanner service stack, upload JSON with:

```bash
python3 phoenix-scanner-client/actions/upload_single.py \
  --file scan-results.json \
  --scanner-type auto \
  --assessment "JSON-Assessment-Service-Path" \
  --import-type delta \
  --wait
```

Use this path when you want centralized queueing/job tracking.

For baseline + incremental via client, keep the same `--assessment` and switch `--import-type` the same way as direct upload (`new` first, then `delta` or `merge`).

---

## CI/CD Notes

- Keep credentials in CI secret stores only.
- Prefer `--import-type delta` for pipeline safety after baseline is established.
- Use one stable `ASSESSMENT_NAME` environment variable across pipeline stages.
- For direct CI uploads with metadata tags, see `simple-upload-actions/README.md`.
- Minimal direct-upload workflow template: `simple-upload-actions/github-actions-direct-upload-minimal.yml`.

---

## Troubleshooting Checklist

- Scanner not detected: set `--scanner generic` or `--scanner drheader` explicitly.
- Wrong asset categorization: add `--asset-type`.
- Unexpected closures of old findings: switch to `--import-type delta`.
- Interactive prompt in automation: pass `--asset-name` to avoid input prompts.
- Mapping mismatch: validate JSON shape against `scanner_field_mappings.yaml`.
- Incremental uploads not appearing: confirm `--assessment` name matches the baseline run exactly.

---

## Related Docs

- `JSON_AND_GENERIC_IMPORTER_MAPPING_GUIDE.md`
- `CLIENT_SERVER_VS_DIRECT_UPLOAD_GUIDE.md`
- `README.md`
- `simple-upload-actions/README.md`
