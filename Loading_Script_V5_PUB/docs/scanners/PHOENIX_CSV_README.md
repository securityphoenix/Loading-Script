# Phoenix & Rapid7 CSV Import Support

## Overview

Phoenix Security Multi-Scanner Enhanced now supports **native Phoenix CSV format** and **Rapid7 VM CSV exports** for vulnerability imports. This feature enables direct import of vulnerability data from:

1. **Phoenix Security native CSV exports** (INFRA, CLOUD, WEB, SOFTWARE/BUILD)
2. **Rapid7 vulnerability scanner CSV exports**

## Features

### ✅ Supported Import Methods

1. **JSON API (Default)** - Convert CSV → JSON → Phoenix API
2. **Native CSV Upload** - Direct CSV upload with batching (5MB chunks)

### ✅ Asset Creation Strategies

- **Auto-detection**: Automatically group vulnerabilities by asset (IP, hostname, ARN, etc.)
- **User-specified**: All vulnerabilities attached to one user-provided asset name
- **Generic placeholders**: Auto-generate asset identifiers when CSV has empty fields

### ✅ Supported Asset Types

- **INFRA** - Infrastructure assets (servers, hosts)
- **CLOUD** - Cloud resources (AWS, Azure, GCP)
- **WEB** - Web applications
- **SOFTWARE/BUILD** - Software components, containers, repositories

---

## Usage Examples

### 1. Phoenix Native CSV Import (INFRA)

```bash
# Auto-detect asset type from filename
python phoenix_multi_scanner_enhanced.py \
  --file demo_infra.csv \
  --scanner phoenix_csv \
  --assessment "Q4 Infrastructure Scan"

# Specify asset type explicitly
python phoenix_multi_scanner_enhanced.py \
  --file vulnerabilities.csv \
  --scanner phoenix_csv_infra \
  --asset-type INFRA \
  --assessment "Production Servers"
```

### 2. Phoenix CSV with Asset Name Override

When CSV has empty asset fields (IP, hostname), provide a custom asset name:

```bash
# All vulnerabilities attached to "prod-server-01"
python phoenix_multi_scanner_enhanced.py \
  --file demo_infra.csv \
  --scanner phoenix_csv \
  --asset-name "prod-server-01" \
  --assessment "Production Server Scan"
```

### 3. Cloud Asset Import

```bash
python phoenix_multi_scanner_enhanced.py \
  --file demo_cloud.csv \
  --scanner phoenix_csv_cloud \
  --asset-type CLOUD \
  --assessment "AWS Infrastructure"
```

### 4. Web Application Import

```bash
python phoenix_multi_scanner_enhanced.py \
  --file demo_web.csv \
  --scanner phoenix_csv_web \
  --asset-type WEB \
  --assessment "Web App Security Scan"
```

### 5. Rapid7 VM CSV Import

```bash
python phoenix_multi_scanner_enhanced.py \
  --file vuln_report_2_hosts.csv \
  --scanner rapid7_csv \
  --assessment "Rapid7 Vulnerability Scan"
```

### 6. Force Native CSV Upload (Batched)

Use Phoenix's native CSV import endpoint instead of JSON conversion:

```bash
python phoenix_multi_scanner_enhanced.py \
  --file demo_infra.csv \
  --scanner phoenix_csv \
  --import-csv-force \
  --assessment "Direct CSV Import"
```

---

## CSV Format Requirements

### Phoenix Native CSV Format

#### INFRA Assets
```csv
a_id,a_subtype,at_ip,at_network,at_hostname,at_netbios,at_os,at_mac,at_fqdn,a_tags,v_name,v_description,v_remedy,v_severity,v_cve,v_cwe,v_published_datetime,v_tags,v_details
,,10.0.1.50,Production,server-01,NETBIOS1,Ubuntu 20.04,aa:bb:cc:dd:ee:ff,server-01.example.com,"[{""key"": ""env"", ""value"": ""prod""}]",CVE-2024-12345: Critical Vuln,Description here,Apply patch XYZ,10,CVE-2024-12345,CWE-79,2024-01-15 10:30:00,"[{""key"": ""severity"", ""value"": ""critical""}]","{""cvss_v3"": ""9.8""}"
```

**Required Fields**:
- Either `at_ip` OR `at_hostname` (at least one)
- `v_name`, `v_description`, `v_remedy`, `v_severity` (1-10)

**Optional Fields**:
- `at_network`, `at_fqdn`, `at_os`, `at_netbios`, `at_mac`
- `v_cve`, `v_cwe`, `v_published_datetime`, `v_tags`, `v_details`, `v_location`

#### CLOUD Assets
```csv
a_id,a_subtype,at_provider_type,at_provider_resource_id,at_vpc,at_subnet,at_region,at_resource_group,at_provider_asset_id,a_tags,v_name,v_description,v_remedy,v_severity,v_cve,v_cwe,v_published_datetime,v_tags,v_details
,,AWS,arn:aws:service:region:{AWS_ACCOUNT_ID}:instance/i-1234567890abcdef0,vpc-12345,subnet-67890,us-east-1,MyResourceGroup,i-1234567890abcdef0,"[{""key"": ""env"", ""value"": ""prod""}]",S3 Bucket Public Access,S3 bucket allows public access,Restrict bucket ACLs,8,,,2024-01-15 10:30:00,"[{""key"": ""cloud"", ""value"": ""aws""}]","{""finding_type"": ""config""}"
```

**Required Fields**:
- `at_provider_type` (AWS, AZURE, GCP)
- `at_provider_resource_id` (ARN, Resource ID)
- `at_region`

#### WEB Assets
```csv
a_id,a_subtype,at_ip,at_fqdn,a_tags,v_name,v_description,v_remedy,v_severity,v_location,v_cve,v_cwe,v_published_datetime,v_tags,v_details
,,203.0.113.50,example.com,"[{""key"": ""app"", ""value"": ""web-portal""}]",SQL Injection in Login,SQL injection vulnerability,Sanitize user input,10,/login.php,CVE-2024-99999,CWE-89,2024-01-15 10:30:00,"[{""key"": ""vuln_type"", ""value"": ""injection""}]","{""cvss_v3"": ""10.0""}"
```

**Required Fields**:
- Either `at_ip` OR `at_fqdn` (at least one)
- `v_location` (file/resource path)

#### SOFTWARE/BUILD Assets
```csv
a_id,a_subtype,a_resource_type,at_origin,at_repository,at_build,at_dockerfile,at_scanner_source,at_image_digest,at_image_name,at_registry,a_tags,v_name,v_description,v_remedy,v_severity,v_location,v_cve,v_cwe,v_published_datetime,v_tags,v_details
,,,github,myorg/myrepo,pom.xml,,myorg/myrepo:pom.xml,,,,"[{""key"": ""team"", ""value"": ""backend""}]",log4j vulnerability,Apache Log4j RCE,Upgrade to 2.17.1,10,src/main/java/App.java,CVE-2021-44228,CWE-502,2021-12-10 00:00:00,"[{""key"": ""component"", ""value"": ""log4j""}]","{""package"": ""log4j-core:2.14.1""}"
```

**Required Fields**:
- `at_repository` (for Repository assets)
- `at_build` (for Build assets)
- `at_dockerfile` (for Container assets)
- `at_scanner_source` (for Code assets)

### Rapid7 CSV Format

```csv
Asset IP Address,Service Port,Vulnerability Test Result Code,Vulnerability ID,Vulnerability CVE IDs,Vulnerability Severity Level,Vulnerability Title
10.22.1.61,0,vv,debian-cve-2025-38420,CVE-2025-38420,5,"Debian: CVE-2025-38420: linux, linux-6.1 -- security update"
10.22.1.44,443,ve,ssl-weak-ciphers,,8,TLS/SSL Server Supports Weak Cipher Suites
```

**Format Notes**:
- First row may contain "report" metadata (automatically skipped)
- **Required Fields**: `Asset IP Address`, `Vulnerability Title`, `Vulnerability Severity Level`
- **Optional Fields**: `Service Port`, `Vulnerability CVE IDs`, `Vulnerability ID`
- Severity: 1-10 scale (or text: Critical, High, Medium, Low)

---

## Asset Creation Logic

### When Asset Fields Are Empty

The script follows this priority order:

1. **User-provided name** (`--asset-name` flag) - All vulnerabilities go to one asset
2. **Extracted from CSV** - IP, hostname, ARN, etc.
3. **Generic auto-generated** - One asset per vulnerability with placeholder

#### Default Placeholder Values

When required fields are missing:

- **INFRA**:
  - `ip`: `0.0.0.0`
  - `hostname`: `Phoenix-import` (or user-provided name)
  - Tag: `{"key": "incomplete_asset", "value": "true"}`

- **CLOUD**:
  - `providerType`: `AWS`
  - `providerAccountId`: `arn:aws:unknown::{asset_name}`
  - `region`: `us-east-1`

- **WEB**:
  - `fqdn`: `phoenix-import.local` (or user-provided name)

- **SOFTWARE**:
  - `repository`: `phoenix-import/unknown` (or user-provided name)

### Example: Empty Asset Fields

```bash
# CSV has empty IP/hostname fields - create generic asset per vulnerability
python phoenix_multi_scanner_enhanced.py \
  --file vulnerabilities.csv \
  --scanner phoenix_csv

# Override: Attach ALL vulnerabilities to "staging-server"
python phoenix_multi_scanner_enhanced.py \
  --file vulnerabilities.csv \
  --scanner phoenix_csv \
  --asset-name "staging-server"
```

---

## Scanner Types

| Scanner Type | Description | Asset Type | Format |
|-------------|-------------|------------|--------|
| `phoenix_csv` | Phoenix native CSV (auto-detect) | Auto | Phoenix CSV |
| `phoenix_csv_infra` | Phoenix CSV - Infrastructure | INFRA | Phoenix CSV |
| `phoenix_csv_cloud` | Phoenix CSV - Cloud | CLOUD | Phoenix CSV |
| `phoenix_csv_web` | Phoenix CSV - Web | WEB | Phoenix CSV |
| `phoenix_csv_software` | Phoenix CSV - Software/Build | BUILD | Phoenix CSV |
| `rapid7` or `rapid7_csv` | Rapid7 VM CSV export | INFRA | Rapid7 CSV |

---

## Import Options

### Import Types

- **`new`** (default) - Create new assessment, close missing vulnerabilities
- **`merge`** - Update existing assessment, close missing vulnerabilities
- **`delta`** - Add/update only (don't close missing vulnerabilities)

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--scanner` | Scanner type (see table above) | `auto` |
| `--asset-type` | Override asset type | Auto-detect |
| `--asset-name` | Custom asset identifier | None |
| `--assessment` | Assessment name | Auto-generated |
| `--import-type` | Import type (new/merge/delta) | `new` |
| `--import-csv-force` | Force CSV upload (not JSON) | `false` |
| `--enable-batching` | Enable payload batching | `true` |
| `--create-inventory-assets` | Create assets even without vulns | `false` |

---

## Batching & Performance

### JSON Import (Default)

- Automatically batches large payloads
- Max batch size: 500 items
- Max payload: 25MB
- Retry logic with exponential backoff

### CSV Import (`--import-csv-force`)

- Batches CSV in 5MB chunks
- Uses Phoenix native CSV endpoint (if available)
- Preserves CSV structure

---

## Examples: Complex Scenarios

### 1. Multiple CSV Files in Folder

```bash
python phoenix_multi_scanner_enhanced.py \
  --folder /scans/phoenix-csvs/ \
  --scanner phoenix_csv \
  --import-type delta \
  --enable-batching
```

### 2. Rapid7 with Custom Assessment Name

```bash
python phoenix_multi_scanner_enhanced.py \
  --file vuln_report_prod.csv \
  --scanner rapid7_csv \
  --assessment "Production Network - Q4 2025" \
  --import-type new
```

### 3. Phoenix Cloud CSV with Specific Asset

```bash
python phoenix_multi_scanner_enhanced.py \
  --file aws_findings.csv \
  --scanner phoenix_csv_cloud \
  --asset-name "arn:aws:service:region:{AWS_ACCOUNT_ID}:instance/i-prod" \
  --assessment "AWS Production Instance"
```

### 4. Debug Mode with Error Logging

```bash
python phoenix_multi_scanner_enhanced.py \
  --file demo_infra.csv \
  --scanner phoenix_csv \
  --debug \
  --error-log errors_$(date +%Y%m%d).log
```

---

## Troubleshooting

### Issue: "No assets parsed from file"

**Solution**: 
- Check CSV format matches templates
- Verify headers are present
- Use `--asset-name` flag to provide generic asset

### Issue: "Missing required fields"

**Solution**:
- For INFRA: Provide either `at_ip` or `at_hostname`
- For CLOUD: Provide `at_provider_type`, `at_provider_resource_id`, `at_region`
- For WEB: Provide either `at_ip` or `at_fqdn`
- Use `--asset-name` flag for placeholder

### Issue: "Could not detect scanner type"

**Solution**:
```bash
# Explicitly specify scanner type
python phoenix_multi_scanner_enhanced.py \
  --file myfile.csv \
  --scanner phoenix_csv_infra \
  --asset-type INFRA
```

---

## API Reference

### Phoenix Import Endpoint

**POST** `/v1/import/assets`

**Payload (JSON)**:
```json
{
  "importType": "new",
  "assessment": {
    "assetType": "INFRA",
    "name": "Q4 Infrastructure Scan"
  },
  "assets": [
    {
      "attributes": {
        "ip": "10.0.1.50",
        "hostname": "server-01"
      },
      "tags": [{"key": "env", "value": "prod"}],
      "findings": [
        {
          "name": "CVE-2024-12345",
          "description": "Critical vulnerability",
          "remedy": "Apply patch",
          "severity": "10.0",
          "referenceIds": ["CVE-2024-12345"],
          "cwes": ["CWE-79"]
        }
      ]
    }
  ]
}
```

---

## Support

For issues or questions:
1. Check templates: `/Utils/csv_translator/template/`
2. Review API docs: `Documentation/Phoenix Security API - Enterprise v1.22.md`
3. Enable debug mode: `--debug`
4. Check logs: `--error-log errors.log`

---

## Version History

- **v3.1.0** - Added Phoenix CSV and Rapid7 CSV support (2025-11-18)
- **v3.0.0** - Consolidated 42 scanner translators


