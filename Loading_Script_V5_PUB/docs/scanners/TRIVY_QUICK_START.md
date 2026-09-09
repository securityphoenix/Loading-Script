# Trivy Scanner - Quick Start Guide

## ✅ Ready to Use!

The Phoenix Multi-Scanner Import Tool now has **full support for all Trivy formats** including complex double-nested arrays!

## Supported Trivy Formats

### 1. Legacy Format (Array Root)
```json
[
  {
    "Target": "debian (debian 10.8)",
    "Type": "debian",
    "Vulnerabilities": [
      {
        "VulnerabilityID": "CVE-2011-3374",
        "PkgName": "apt",
        "Severity": "LOW",
        ...
      }
    ]
  }
]
```

### 2. New Format (Results Array)
```json
{
  "ArtifactName": "myapp:latest",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "app.jar",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-12345",
          ...
        }
      ]
    }
  ]
}
```

### 3. Kubernetes Format (Resources → Results)
```json
{
  "ClusterName": "production",
  "Resources": [
    {
      "Namespace": "default",
      "Kind": "Service",
      "Name": "kubernetes",
      "Results": [
        {
          "Target": "Service/kubernetes",
          "Misconfigurations": [
            {
              "ID": "KSV116",
              "Severity": "LOW",
              ...
            }
          ]
        }
      ]
    }
  ]
}
```

## Quick Commands

### Basic Import
```bash
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file path/to/trivy-scan.json \
    --assessment "My Trivy Scan" \
    --import-type new
```

### Folder Import (Multiple Trivy Files)
```bash
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --folder path/to/trivy/scans/ \
    --assessment "Trivy Batch Import" \
    --import-type merge
```

### With Debug Logging
```bash
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file path/to/trivy-scan.json \
    --assessment "Debug Trivy" \
    --import-type new \
    --debug
```

## Import Types

### `new` (Recommended for Weekly/Monthly Scans)
- Removes existing vulnerabilities
- Imports fresh data
- Closes vulnerabilities NOT in scan

```bash
--import-type new
```

### `merge` (For Incremental Updates)
- Keeps existing vulnerabilities
- Adds new vulnerabilities
- Does NOT close old vulnerabilities

```bash
--import-type merge
```

### `delta` (For Change Detection)
- Imports only NEW vulnerabilities
- Skips duplicates
- Efficient for large datasets

```bash
--import-type delta
```

## Configuration

### No Special Config Required!
The tool **auto-detects** Trivy format. Just use your existing config:

```ini
[phoenix]
client_id = your-client-id
client_secret = your-client-secret
api_base_url = https://api.poc1.appsecphx.io

[scanner_trivy]
scanner_name = Trivy
asset_type = CONTAINER
```

## What Gets Imported?

### Container Scans
- **Asset Type:** CONTAINER
- **Attributes:**
  - `repository`: Image name or target
  - `dockerfile`: Dockerfile or artifact name
  - `origin`: trivy

### Kubernetes Scans
- **Asset Type:** INFRA
- **Attributes:**
  - `hostname`: {resource}.{namespace}.k8s
  - `repository`: {namespace}/{kind}/{name}
  - `dockerfile`: {kind}/{name}
  - `origin`: trivy-kubernetes

### Vulnerabilities
- **Name:** CVE ID or Vulnerability ID
- **Description:** Full description
- **Remedy:** Fix version or resolution steps
- **Severity:** Normalized to Phoenix scale (1.0-10.0)
- **Location:** Package name + version
- **Reference IDs:** CVE IDs
- **Published Date:** ISO-8601 format
- **Details:**
  - Package name, version, fixed version
  - Severity source
  - Primary URL, references
  - CWE IDs
  - Last modified date

### Misconfigurations (Kubernetes)
- **Name:** Configuration ID (e.g., KSV116)
- **Description:** Configuration issue description
- **Remedy:** Resolution steps
- **Severity:** Normalized severity
- **Location:** Target resource
- **Details:**
  - Type, title, message
  - Primary URL, references
  - Status, namespace, query

## Examples

### Example 1: Container Vulnerability Scan
```bash
# Scan a container image with Trivy
trivy image myapp:latest -f json -o trivy-scan.json

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file trivy-scan.json \
    --assessment "MyApp Container Scan" \
    --import-type new
```

### Example 2: Kubernetes Cluster Scan
```bash
# Scan Kubernetes cluster
trivy k8s --report=summary --format=json --output=k8s-scan.json cluster

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file k8s-scan.json \
    --assessment "K8s Security Audit" \
    --import-type new
```

### Example 3: Filesystem Scan
```bash
# Scan a filesystem
trivy fs /path/to/code --format json --output fs-scan.json

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file fs-scan.json \
    --assessment "Code Filesystem Scan" \
    --import-type new
```

## Troubleshooting

### Issue: "Could not detect scanner type"
**Solution:** Ensure your JSON file is valid Trivy output
```bash
# Validate JSON
cat trivy-scan.json | jq . > /dev/null
```

### Issue: "Invalid date format"
**Solution:** Update to latest version - date formatting is now fixed!

### Issue: "Asset attribute Dockerfile is required"
**Solution:** Update to latest version - all required attributes are now included!

### Issue: No vulnerabilities imported
**Check:**
1. Does your scan actually have vulnerabilities?
   ```bash
   cat trivy-scan.json | jq '.Results[].Vulnerabilities | length'
   ```
2. Try with `--debug` flag to see parsing details

## Success Indicators

When import is successful, you'll see:
```
✅ Successfully processed trivy-scan.json
   Scanner: trivy
   Assets: 1
   Vulnerabilities: 93
   Batches: 1/1 successful
   Success Rate: 100.0%
```

## Testing Your Setup

### Test Files Available:
```bash
# Legacy format
scanner_test_files/scans/trivy/legacy_many_vulns.json

# New format
scanner_test_files/scans/trivy/issue_10991.json

# Kubernetes format
scanner_test_files/scans/trivy/kubernetes.json
```

### Quick Test:
```bash
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file scanner_test_files/scans/trivy/legacy_many_vulns.json \
    --assessment "Trivy-Test" \
    --import-type new
```

Expected output: **93 vulnerabilities imported successfully**

## Performance Tips

### For Large Scans (1000+ vulnerabilities):
```bash
# Enable batching (already default)
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --file large-scan.json \
    --assessment "Large Scan" \
    --import-type new \
    --enable-batching \
    --max-batch-size 500
```

### For Multiple Files:
```bash
# Use folder import
python3 phoenix_multi_scanner_enhanced.py \
    --config config_multi_scanner.ini \
    --folder /path/to/trivy/scans/ \
    --assessment "Batch Import" \
    --import-type merge
```

## Integration with CI/CD

### GitLab CI Example:
```yaml
trivy_scan:
  stage: security
  script:
    - trivy image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -f json -o trivy-scan.json
    - python3 phoenix_multi_scanner_enhanced.py 
        --config config.ini 
        --file trivy-scan.json 
        --assessment "$CI_PROJECT_NAME-$CI_COMMIT_SHORT_SHA"
        --import-type new
  artifacts:
    paths:
      - trivy-scan.json
```

### GitHub Actions Example:
```yaml
- name: Run Trivy Scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:latest'
    format: 'json'
    output: 'trivy-scan.json'

- name: Import to Phoenix
  run: |
    python3 phoenix_multi_scanner_enhanced.py \
      --config config.ini \
      --file trivy-scan.json \
      --assessment "${{ github.repository }}-${{ github.sha }}" \
      --import-type new
```

## Support

### Supported Trivy Versions:
- ✅ Trivy v0.18+
- ✅ Trivy v0.40+
- ✅ Trivy v0.50+ (latest)

### Supported Scan Types:
- ✅ Container images (`trivy image`)
- ✅ Filesystem (`trivy fs`)
- ✅ Kubernetes (`trivy k8s`)
- ✅ SBOM (`trivy sbom`)
- ✅ Repository (`trivy repo`)
- ✅ Config files (`trivy config`)

## Need Help?

1. Check the detailed summary: `TRIVY_ENHANCEMENT_SUMMARY.md`
2. Review the main README: `README.md`
3. Enable debug logging: `--debug`
4. Check the error log: `error_log.txt`

---
**Status:** ✅ **Production Ready**
**Last Updated:** November 11, 2025

