# Asset Naming Guide

## Overview
This guide explains how asset names are determined in the Phoenix import scripts and how you can control them.

## Asset Name Determination by Asset Type

### 1. CONTAINER Assets
**Primary Identifier:** `repository` attribute

**Source Hierarchy (in order of preference):**
1. `image` field (root level)
2. `resource.name` field (for NPM/package scans)
3. Falls back to `"unknown-image"`

**With Version:** If `resource.version` exists, it's appended as `name:version`

**Example JSON structures:**

#### Standard Docker Image
```json
{
  "image": "nginx:1.21.0",
  "digest": "sha256:...",
  "vulnerabilities": [...]
}
```
**Result:** Asset named `nginx:1.21.0`

#### NPM Package (like your Aqua scan)
```json
{
  "resource": {
    "name": "react-server-dom-webpack",
    "version": "19.2.2"
  },
  "vulnerabilities": [...]
}
```
**Result:** Asset named `react-server-dom-webpack:19.2.2`

---

### 2. INFRA Assets
**Primary Identifiers (in priority order):**
1. `ip` - IP address
2. `hostname` - DNS hostname
3. `fqdn` - Fully qualified domain name

**Required:** At least one of the above must be present

**Example:**
```json
{
  "IP Address": "192.168.1.100",
  "DNS Name": "webserver.example.com",
  "NetBIOS Name": "WEBSERVER01"
}
```
**Result:** Asset identified by IP `192.168.1.100` and hostname `webserver.example.com`

---

### 3. WEB Assets
**Primary Identifiers:**
1. `fqdn` - Website URL/domain
2. `ip` - IP address (if FQDN not available)

**Example:**
```json
{
  "fqdn": "https://app.example.com",
  "ip": "203.0.113.42"
}
```
**Result:** Asset named by FQDN `https://app.example.com`

---

### 4. CLOUD Assets
**Primary Identifiers:**
- `providerType` - Cloud provider (AWS, Azure, GCP)
- `providerAccountId` - Account/Subscription ID
- `region` - Cloud region

**Example:**
```json
{
  "provider_type": "AWS",
  "account_id": "123456789012",
  "region": "us-east-1"
}
```

---

### 5. BUILD Assets
**Primary Identifier:** `buildFile` attribute

**Source:** Build file path or name

**Example:**
```json
{
  "build_file": "package.json",
  "origin": "npm-audit"
}
```
**Result:** Asset named by `package.json`

---

### 6. CODE Assets
**Primary Identifier:** `scannerSource` attribute

**Source:** Scanner name or code repository

**Example:**
```json
{
  "scanner_source": "sonarqube-myproject",
  "origin": "sonarqube"
}
```

---

### 7. REPOSITORY Assets
**Primary Identifier:** `repository` attribute

**Source:** Repository name/URL

**Example:**
```json
{
  "repository": "github.com/myorg/myrepo"
}
```

---

## How to Customize Asset Names

### Method 1: Modify Your Source JSON
Add the appropriate field to your JSON file:

**For Aqua/Container scans:**
```json
{
  "image": "my-custom-asset-name:v1.0",
  "resource": { ... },
  "vulnerabilities": [ ... ]
}
```

### Method 2: Use Command-Line Options
Override the asset type to change how the asset is identified:

```bash
# Force asset as BUILD type (uses buildFile instead of repository)
python phoenix_multi_scanner_enhanced.py \
  --file aqua_scan.json \
  --scanner aqua \
  --asset-type BUILD \
  --assessment "my-scan"
```

### Method 3: Modify the Translator
Edit the specific scanner translator in `phoenix_multi_scanner_import.py`:

```python
# In AquaScanTranslator.parse_file():
image_name = "MyCustomAssetName"  # Hard-coded
# OR
image_name = data.get('custom_field', 'default-name')  # From JSON field
```

---

## Assessment Names

Assessment names (scan names) can be specified in two ways:

### 1. Command Line
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --assessment "Q4-2024-Security-Scan"
```

### 2. Auto-Generated (Default)
If not specified, format is: `{scanner}_{filename}_{timestamp}`

Example: `aqua_react2shell_20241214_192455`

---

## Best Practices

1. **Be Specific:** Include version numbers for packages/images
   - Good: `nginx:1.21.0`
   - Bad: `nginx`

2. **Use Consistent Naming:** Maintain naming conventions across scans
   - Example: `{app}-{environment}:{version}`
   - `webapp-prod:1.2.3`

3. **Include Context:** Add origin information
   ```json
   {
     "image": "webapp:1.2.3",
     "origin": "production-eks-cluster"
   }
   ```

4. **Assessment Names:** Use descriptive assessment names that include:
   - Date/Quarter
   - Environment (prod/staging/dev)
   - Scanner type
   - Example: `Q4-2024-PROD-Aqua-Scan`

---

## Troubleshooting

### Issue: Assets showing as "unknown-image"
**Cause:** No `image` field in JSON, and no `resource.name` field

**Solution:** Add one of these to your JSON:
```json
{
  "image": "my-asset-name",
  ...
}
```
OR modify the script to use a different field (see Method 3 above)

### Issue: Multiple scans creating different assets
**Cause:** Asset name/identifier changes between scans

**Solution:** Ensure consistent naming. Use `--import-type merge` to merge with existing assets:
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --import-type merge
```

### Issue: Want to specify asset name from command line
**Current Limitation:** Asset names come from the scan file, not command line

**Workaround:** 
1. Pre-process JSON to add the desired name
2. Or modify the JSON file before import
3. Or use a wrapper script to inject the name

---

## Command-Line Reference

```bash
python phoenix_multi_scanner_enhanced.py \
  --file <scan-file> \
  --scanner <scanner-type> \
  --assessment <assessment-name> \
  --asset-type <asset-type> \
  --import-type <new|merge|delta>
```

**Key Options:**
- `--file`: Scanner output file
- `--scanner`: Scanner type (aqua, trivy, etc.) or 'auto'
- `--assessment`: Name for this scan/assessment
- `--asset-type`: Override asset type (CONTAINER, INFRA, WEB, etc.)
- `--import-type`: 
  - `new`: Create new assets
  - `merge`: Merge with existing assets
  - `delta`: Only import new/changed findings

---

## Updated Script Features

The script has been enhanced to automatically:
1. Extract asset names from `resource.name` if `image` is not present
2. Append version numbers when available (`name:version`)
3. Convert dates to ISO-8601 format automatically

**Your current file** (`aqua_react2shell.json`) will now be imported as:
- Asset Name: `react-server-dom-webpack:19.2.2`
- Asset Type: CONTAINER
- Vulnerabilities: 24 CVEs properly formatted

---

## Testing Your Asset Name

To see what asset name will be generated without importing:

```bash
# Run with debug mode
python phoenix_multi_scanner_enhanced.py \
  --file aqua_react2shell.json \
  --scanner aqua \
  --debug
```

Check the log file for: `"repository": "your-asset-name"`





