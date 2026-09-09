# Prowler Upload Guide (v2, v3, v4, v5)

**Version:** 5.0  
**Last Updated:** February 2026  
**Status:** Production Ready

---

## Overview

This guide explains how to upload **AWS Prowler** scan results into Phoenix using
`phoenix_multi_scanner_enhanced.py`. It covers:

- Prowler version differences (v2 vs v3/v4/v5)
- Supported file formats (JSON/OCSF and CSV)
- Scanner type flags you can use
- Recommended import commands
- Common troubleshooting steps

Phoenix supports Prowler across **all versions** via consolidated translators.

---

## Supported Versions and Scanner Types

Use these scanner names with the `--scanner` flag:

| Prowler Version | Output Format | Recommended Scanner Type | Notes |
|----------------|---------------|--------------------------|-------|
| **v2.x** | JSON (legacy) | `aws_prowler_v2` | Legacy Prowler output |
| **v2.x** | CSV | `aws_prowler_csv` | CSV output for v2 |
| **v3.x** | JSON (OCSF) | `aws_prowler_v3` | OCSF format |
| **v4.x** | JSON (OCSF) | `aws_prowler_v4` | OCSF format |
| **v5.x** | JSON (OCSF) | `aws_prowler_v5` | Uses v4 translator |
| **Any** | JSON (auto) | `prowler` / `aws_prowler` | Auto-detects version |

**Asset type:** Always use `--asset-type CLOUD` for Prowler scans.

---

## Recommended Upload Workflow

### 1) Run Prowler and Export Results

Use your normal Prowler command to export results. Examples:

```bash
# Example: Prowler JSON output
prowler aws --output-modes json --output-file prowler-output.json

# Example: Prowler CSV output (v2)
prowler aws --output-modes csv --output-file prowler-output.csv
```

If you are unsure of the version or format, use auto-detection on upload.

---

### 2) Upload with Auto-Detection (Recommended)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-output.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-Audit" \
  --asset-type CLOUD \
  --scanner auto
```

Auto-detection is safe for most environments and will route to the correct translator.

---

### 3) Upload with Explicit Version

Use explicit version flags if you need deterministic behavior.

#### Prowler v2 (Legacy JSON)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v2.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-v2-Scan" \
  --asset-type CLOUD \
  --scanner aws_prowler_v2
```

#### Prowler v2 (CSV)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v2.csv \
  --config config_test.ini \
  --assessment "AWS-Prowler-v2-CSV" \
  --asset-type CLOUD \
  --scanner aws_prowler_csv
```

#### Prowler v3 (OCSF JSON)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v3.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-v3-Scan" \
  --asset-type CLOUD \
  --scanner aws_prowler_v3
```

#### Prowler v4 (OCSF JSON)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v4.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-v4-Scan" \
  --asset-type CLOUD \
  --scanner aws_prowler_v4
```

#### Prowler v5 (OCSF JSON)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v5.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-v5-Scan" \
  --asset-type CLOUD \
  --scanner aws_prowler_v5
```

---

## Common Upload Patterns

### Single Assessment (Merge Multiple Versions)

```bash
# v3 scan
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v3.json \
  --assessment "AWS-Prowler-Baseline" \
  --asset-type CLOUD \
  --scanner aws_prowler_v3 \
  --import-type new

# v4 scan (merge into same assessment)
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v4.json \
  --assessment "AWS-Prowler-Baseline" \
  --asset-type CLOUD \
  --scanner aws_prowler_v4 \
  --import-type merge
```

### Separate Assessments per Version

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v3.json \
  --assessment "AWS-Prowler-v3-Scan" \
  --asset-type CLOUD \
  --scanner aws_prowler_v3 \
  --import-type new

python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-v4.json \
  --assessment "AWS-Prowler-v4-Scan" \
  --asset-type CLOUD \
  --scanner aws_prowler_v4 \
  --import-type new
```

---

## Handling Large Files (Batching and Splitting)

### ✅ Preferred: Use Built-in Batching

For large Prowler exports, **enable batching** and lower limits:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-large.json \
  --config config_test.ini \
  --assessment "AWS-Prowler-Large" \
  --asset-type CLOUD \
  --scanner prowler \
  --enable-batching \
  --max-batch-size 50 \
  --max-payload-mb 10.0
```

### Optional: Split the File

If the file is too large for your environment, split it and import in **merge** or **delta** mode:

#### CSV (row-based split)

```bash
split -l 5000 prowler.csv prowler_part_
```

Then import each part:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler_part_aa \
  --assessment "AWS-Prowler-Large" \
  --asset-type CLOUD \
  --scanner aws_prowler_csv \
  --import-type merge
```

#### JSON (array-based split)

If the JSON output is an array, you can split it with `jq`:

```bash
jq -c '.[]' prowler.json | split -l 2000 - prowler_part_
```

Then import each part as JSON:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler_part_aa \
  --assessment "AWS-Prowler-Large" \
  --asset-type CLOUD \
  --scanner prowler \
  --import-type merge
```

> If your JSON is not an array, prefer **batching** instead of manual splitting.

---

## Troubleshooting

### 1) Auto-detect fails

Try explicit scanner types in this order:

```bash
--scanner aws_prowler_v5
--scanner aws_prowler_v4
--scanner aws_prowler_v3
--scanner aws_prowler_v2
--scanner aws_prowler_csv
```

### 2) Wrong asset type

Prowler is **always CLOUD**. Ensure:

```bash
--asset-type CLOUD
```

### 3) CSV parse issues

If JSON works but CSV fails, switch to JSON output:

```bash
prowler aws --output-modes json --output-file prowler-output.json
```

### 4) Partial scan results

If your scan is incomplete, use `delta` to avoid closing findings:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-partial.json \
  --assessment "AWS-Prowler-Partial" \
  --asset-type CLOUD \
  --scanner prowler \
  --import-type delta
```

---

## Quick Reference

| Scenario | Scanner | Asset Type |
|----------|---------|------------|
| Auto-detect any JSON | `auto` | `CLOUD` |
| Prowler v2 JSON | `aws_prowler_v2` | `CLOUD` |
| Prowler v2 CSV | `aws_prowler_csv` | `CLOUD` |
| Prowler v3 JSON (OCSF) | `aws_prowler_v3` | `CLOUD` |
| Prowler v4 JSON (OCSF) | `aws_prowler_v4` | `CLOUD` |
| Prowler v5 JSON (OCSF) | `aws_prowler_v5` | `CLOUD` |
| Generic Prowler | `prowler` / `aws_prowler` | `CLOUD` |

---

## Related Documentation

- `README.md` - Main guide with usage examples
- `QUICK_START_ALL_SCANNERS.md` - Quick examples by category
- `SCANNER_SUPPORT_MATRIX.md` - Complete scanner list

