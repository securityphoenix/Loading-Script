# Phoenix & Rapid7 CSV - Quick Reference Card

## 🚀 Quick Start

```bash
# Phoenix CSV (auto-detect)
python phoenix_multi_scanner_enhanced.py --file demo_infra.csv --scanner phoenix_csv --assessment "My Scan"

# Rapid7 CSV
python phoenix_multi_scanner_enhanced.py --file vuln_report.csv --scanner rapid7_csv --assessment "My Scan"

# With custom asset name
python phoenix_multi_scanner_enhanced.py --file demo_infra.csv --scanner phoenix_csv --asset-name "my-server-01" --assessment "My Scan"
```

---

## 📋 Scanner Types

| Scanner | Description | Asset Type |
|---------|-------------|------------|
| `phoenix_csv` | Auto-detect | Auto |
| `phoenix_csv_infra` | Infrastructure | INFRA |
| `phoenix_csv_cloud` | Cloud | CLOUD |
| `phoenix_csv_web` | Web | WEB |
| `phoenix_csv_software` | Software/Build | BUILD |
| `rapid7_csv` | Rapid7 VM | INFRA |

---

## 🔧 Common Flags

```bash
--file FILE                    # Single CSV file
--folder FOLDER                # Process entire folder
--scanner TYPE                 # Scanner type (see table above)
--asset-type TYPE              # Force asset type (INFRA/CLOUD/WEB/BUILD)
--asset-name NAME              # Override asset identifier
--assessment NAME              # Assessment name
--import-type TYPE             # new/merge/delta (default: new)
--import-csv-force             # Force CSV upload (not JSON)
--enable-batching              # Enable batching (default: true)
--debug                        # Debug mode
--error-log FILE               # Error log file
```

---

## 📊 CSV Format Cheatsheet

### Phoenix INFRA CSV
```csv
a_id,a_subtype,at_ip,at_hostname,at_network,...,v_name,v_severity,v_cve,...
,,10.0.1.50,server-01,Production,...,CVE-2024-12345,10,CVE-2024-12345,...
```
**Required**: `at_ip` OR `at_hostname`, `v_name`, `v_severity`

### Phoenix CLOUD CSV
```csv
a_id,at_provider_type,at_provider_resource_id,at_region,...,v_name,v_severity,...
,,AWS,arn:aws:...,us-east-1,...,S3 Public Access,8,...
```
**Required**: `at_provider_type`, `at_provider_resource_id`, `at_region`, `v_name`, `v_severity`

### Phoenix WEB CSV
```csv
a_id,at_ip,at_fqdn,...,v_name,v_location,v_severity,...
,,203.0.113.50,example.com,...,SQL Injection,/login.php,10,...
```
**Required**: `at_ip` OR `at_fqdn`, `v_name`, `v_location`, `v_severity`

### Rapid7 CSV
```csv
Asset IP Address,Service Port,Vulnerability ID,Vulnerability CVE IDs,Vulnerability Severity Level,Vulnerability Title
10.22.1.61,0,debian-cve-2025-38420,CVE-2025-38420,5,"Debian: CVE-2025-38420"
```
**Required**: `Asset IP Address`, `Vulnerability Title`, `Vulnerability Severity Level`

---

## 🎯 Common Use Cases

### 1. Empty Asset Fields → Generic Assets
```bash
python phoenix_multi_scanner_enhanced.py \
  --file vulnerabilities.csv \
  --scanner phoenix_csv
```
**Result**: Creates one asset per vulnerability with placeholders

### 2. Empty Asset Fields → One Custom Asset
```bash
python phoenix_multi_scanner_enhanced.py \
  --file vulnerabilities.csv \
  --scanner phoenix_csv \
  --asset-name "staging-server"
```
**Result**: ALL vulnerabilities → "staging-server"

### 3. Multiple CSV Files
```bash
python phoenix_multi_scanner_enhanced.py \
  --folder /path/to/csvs/ \
  --scanner phoenix_csv \
  --import-type delta
```
**Result**: Processes all CSVs in folder

### 4. Debug Mode
```bash
python phoenix_multi_scanner_enhanced.py \
  --file demo_infra.csv \
  --scanner phoenix_csv \
  --debug \
  --error-log errors.log
```
**Result**: Verbose logging + error file

---

## 🔍 Placeholder Values

When required fields are empty:

| Asset Type | Field | Placeholder |
|------------|-------|-------------|
| INFRA | ip | 0.0.0.0 |
| INFRA | hostname | Phoenix-import |
| CLOUD | providerType | AWS |
| CLOUD | providerAccountId | arn:aws:unknown::... |
| CLOUD | region | us-east-1 |
| WEB | fqdn | phoenix-import.local |
| SOFTWARE | repository | phoenix-import/unknown |

**Tag**: `{"key": "incomplete_asset", "value": "true"}`

---

## ⚡ Import Types

| Type | Behavior |
|------|----------|
| `new` | Create new assessment, close missing vulns |
| `merge` | Update existing, close missing vulns |
| `delta` | Add/update only (don't close missing) |

---

## 📖 Full Documentation

- **Complete Guide**: `PHOENIX_CSV_README.md`
- **Implementation Details**: `PHOENIX_CSV_IMPLEMENTATION_SUMMARY.md`
- **Examples**: `examples/phoenix_csv_examples.sh`

---

## 🆘 Troubleshooting

### "No assets parsed"
→ Check CSV format, use `--asset-name` flag

### "Missing required fields"
→ Provide required fields or use `--asset-name`

### "Could not detect scanner type"
→ Use explicit `--scanner phoenix_csv_infra`

### Debug any issue
→ Add `--debug --error-log errors.log`

---

**Version**: v3.1.0 | **Date**: 2025-11-18


