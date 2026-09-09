# Phoenix API Interaction Guide

**Version:** 1.0  
**Last Updated:** February 2026  
**Scope:** Loading Script V5 (PUB)

---

## Overview

This guide describes **all supported interaction paths** with the Phoenix API:

1. **Direct CLI** using `phoenix_multi_scanner_enhanced.py`
2. **Client → Server** via `phoenix-scanner-client` and `phoenix-scanner-service`
3. **Wrapper-based CLI** around `phoenix_multi_scanner_enhanced.py` (for pipelines)

It also explains **when to use each path**, how they differ, and the **exact commands** to invoke at:

- **Pipeline level (CI/CD actions)**
- **CLI (direct)**
- **CLI via client/server**

---

## Interaction Models

### 1) Direct CLI (Local Import)

**Flow:**  
`scan file` → `phoenix_multi_scanner_enhanced.py` → `Phoenix API`

**Best for:**  
- Local testing and ad‑hoc imports  
- Simple pipelines that can run Python directly  
- No server deployment required  

**Key properties:**  
- Reads scan file locally  
- Translates to Phoenix JSON  
- Calls API `/v1/import/assets` directly  

---

### 2) Client → Server (Remote Import)

**Flow:**  
`scan file` → `phoenix-scanner-client` → `phoenix-scanner-service` → `Phoenix API`

**Best for:**  
- Centralized imports  
- Multiple teams using the same import service  
- Environments where scanners run outside Phoenix network  

**Key properties:**  
- Client uploads file to service  
- Service runs translation and Phoenix import  
- Consistent server-side configuration and logging  

---

### 3) Wrapper CLI (Pipeline Abstraction)

**Flow:**  
`scan file` → `wrapper script` → `phoenix_multi_scanner_enhanced.py` → `Phoenix API`

**Best for:**  
- Standardized pipeline usage  
- Reduced command-line complexity  
- Organization-level defaults (assessment, asset type, scanner)

**Key properties:**  
- Uses local CLI under the hood  
- Adds guardrails and defaults  
- Ideal for CI/CD actions  

---

## Direct CLI — How It Works

### Core Command

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file /path/to/scan.json \
  --config config_test.ini \
  --assessment "My-Assessment" \
  --scanner auto \
  --asset-type CLOUD
```

### What Happens Internally

1. **Detects scanner** (or uses `--scanner`)
2. **Translates** scan data into Phoenix JSON
3. **Batches** payload if needed
4. **POST** to `/v1/import/assets`

### Common Flags

| Flag | Purpose |
|------|---------|
| `--file` | Scan file to import |
| `--config` | Phoenix API credentials |
| `--assessment` | Assessment name |
| `--scanner` | Force scanner type (optional) |
| `--asset-type` | Override asset type |
| `--import-type` | `new`, `merge`, `delta` |

---

## Client → Server — How It Works

### High-Level Flow

1. Client sends file + metadata to service
2. Service validates input
3. Service runs importer
4. Service forwards results to Phoenix

### Example: Upload via Client

```bash
python3 phoenix-scanner-client/actions/upload_single.py \
  --file /path/to/scan.json \
  --scanner-type prowler \
  --assessment "AWS-Prowler-Scan"
```

### Expected Behavior

- Client uploads the file and metadata  
- Server processes and imports  
- Server logs the import result  

---

## Pipeline-Level Commands (Actions)

### A) Pipeline: Direct CLI (Recommended for Simple CI)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --config config_test.ini \
  --assessment "CI-Scan-${GITHUB_SHA}" \
  --scanner auto \
  --asset-type CLOUD \
  --import-type new
```

### B) Pipeline: Client → Server (Centralized)

```bash
python3 phoenix-scanner-client/actions/upload_single.py \
  --file scan.json \
  --scanner-type prowler \
  --assessment "CI-Scan-${GITHUB_SHA}"
```

### C) Pipeline: Wrapper Script (Standardized)

```bash
./scripts/phoenix_import_wrapper.sh \
  --file scan.json \
  --scanner prowler \
  --asset-type CLOUD \
  --assessment "CI-Scan-${GITHUB_SHA}"
```

> If you don't already have a wrapper, use the direct CLI command above.

---

## CLI Usage — Full Examples

### Direct CLI (Local Import)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-output.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-Audit" \
  --asset-type CLOUD \
  --scanner auto
```

### Client → Server CLI

```bash
python3 phoenix-scanner-client/actions/upload_single.py \
  --file prowler-output.json \
  --scanner-type prowler \
  --assessment "AWS-Prowler-Audit"
```

### Wrapper CLI

```bash
./scripts/phoenix_import_wrapper.sh \
  --file prowler-output.json \
  --scanner prowler \
  --asset-type CLOUD \
  --assessment "AWS-Prowler-Audit"
```

---

## Handling Large Files

### Preferred: Enable Batching

Use smaller batches and payload limits for large imports:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file large-scan.json \
  --config config_test.ini \
  --assessment "Large-Scan" \
  --enable-batching \
  --max-batch-size 50 \
  --max-payload-mb 10.0
```

### Optional: Split and Merge

If batching is not enough, split the file and import parts with `merge` or `delta`.

#### CSV

```bash
split -l 5000 scan.csv scan_part_
```

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan_part_aa \
  --assessment "Large-Scan" \
  --import-type merge
```

#### JSON (array-based)

```bash
jq -c '.[]' scan.json | split -l 2000 - scan_part_
```

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan_part_aa \
  --assessment "Large-Scan" \
  --import-type merge
```

> If your JSON is not an array, prefer **batching** instead of manual splitting.

---

## Choosing the Right Interaction

| Scenario | Best Option | Why |
|---------|-------------|-----|
| Local testing | Direct CLI | Fast, minimal setup |
| Centralized org usage | Client → Server | Shared config, consistent imports |
| CI/CD with standard flags | Wrapper CLI | Simpler and repeatable |
| Air‑gapped server | Direct CLI | No service dependency |

---

## Authentication and Configuration

All methods require **Phoenix API credentials**, either via:

1. **Config file** (`config_test.ini` or `config_multi_scanner.ini`)
2. **Environment variables**

### Example Config

```ini
[phoenix]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
api_base_url = https://api.demo.appsecphx.io
```

---

## Notes on Import Types

| Import Type | Behavior | When to Use |
|------------|----------|-------------|
| `new` | Replaces assessment | Full scan, first import |
| `merge` | Combines results | Multiple scanners |
| `delta` | Adds only | Partial scans |

---

## Related Documentation

- `README.md` — Primary usage documentation  
- `QUICK_START_ALL_SCANNERS.md` — Scanner examples  
- `REFERENCE_DOCUMENTATION/PHOENIX_PLATFORM_ARCHITECTURE.md` — Platform architecture  
- `REFERENCE_DOCUMENTATION/FUNCTION_CALL_FLOW_GUIDE.md` — Internal call flow  
- `phoenix-scanner-client/README.md` — Client usage  
- `phoenix-scanner-service/README.md` — Service usage  

