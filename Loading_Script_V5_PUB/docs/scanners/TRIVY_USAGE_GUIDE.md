# Trivy Scanner Usage Guide

**Version:** 5.0  
**Last Updated:** February 2026  
**Status:** ✅ Production Ready

---

## Overview

This guide explains how to use **Aqua Security Trivy** with the Phoenix Multi-Scanner Import Tool. Trivy is a versatile security scanner that can scan:

- 🐳 **Container Images** - Vulnerabilities in container images
- 📦 **Filesystems/SCA** - Software Composition Analysis (dependencies)
- 🔧 **Infrastructure as Code** - Misconfigurations in Terraform, Kubernetes, etc.
- 📚 **Git Repositories** - Complete repository scanning
- ☸️ **Kubernetes Clusters** - Live cluster scanning

The Phoenix import tool supports **all Trivy scan types** using the same translator with different asset type overrides.

---

## Quick Reference

| Trivy Scan Type | Command | Asset Type | Use Case |
|-----------------|---------|------------|----------|
| Container Image | `trivy image` | `CONTAINER` | Docker/OCI image vulnerabilities |
| Filesystem/SCA | `trivy filesystem` | `BUILD` | Application dependencies (npm, pip, etc.) |
| Repository | `trivy repo` | `BUILD` | Git repository dependencies |
| Config/IaC | `trivy config` | `INFRA` | Kubernetes, Terraform misconfigurations |
| Kubernetes | `trivy k8s` | `INFRA` | Live cluster scanning |

---

## Installation & Setup

### 1. Install Trivy

```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Docker
docker pull aquasec/trivy:latest
```

### 2. Configure Phoenix Import Tool

Ensure you have `config_test.ini` or similar configuration file:

```ini
[phoenix]
client_id = your-client-id
client_secret = your-client-secret
api_base_url = https://api.demo.appsecphx.io

[batch_processing]
enable_batching = true
max_batch_size = 500
max_payload_mb = 25.0
```

---

## Usage Examples

### 1. Container Image Scanning (Default)

Scan Docker/OCI container images for vulnerabilities.

#### Run Trivy Scan

```bash
# Scan a local image
trivy image myapp:latest --format json --output trivy-container.json

# Scan a remote image
trivy image nginx:latest --format json --output trivy-nginx.json

# Scan with severity filter
trivy image myapp:latest --severity HIGH,CRITICAL --format json --output trivy-critical.json
```

#### Import to Phoenix

```bash
# Default behavior - auto-detected as CONTAINER
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-container.json \
  --config config_test.ini \
  --assessment "Container-Security-Scan" \
  --scanner trivy

# Explicit asset type (optional)
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-container.json \
  --config config_test.ini \
  --assessment "Container-Security-Scan" \
  --scanner trivy \
  --asset-type CONTAINER
```

**Result:** Vulnerabilities imported as CONTAINER asset type with image name as identifier.

---

### 2. Filesystem/SCA Scanning (Software Composition Analysis) 🎯

Scan application source code for dependency vulnerabilities (npm, pip, Maven, Go modules, etc.).

#### Run Trivy Scan

```bash
# Scan current directory
trivy filesystem . --format json --output trivy-sca.json

# Scan specific project directory
trivy filesystem /path/to/project --format json --output trivy-project-sca.json

# Scan only specific package managers
trivy filesystem . --scanners vuln --format json --output trivy-deps.json

# Scan with security checks
trivy filesystem . --security-checks vuln,secret --format json --output trivy-full.json
```

#### Import to Phoenix

```bash
# Import as BUILD asset type for SCA
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-sca.json \
  --config config_test.ini \
  --assessment "SCA-Dependency-Scan" \
  --scanner trivy \
  --asset-type BUILD
```

**Key Point:** The `--asset-type BUILD` flag is **required** for SCA scans. Without it, Trivy defaults to CONTAINER type.

**Result:** Dependency vulnerabilities imported as BUILD asset type, showing package names, versions, and CVEs.

---

### 3. Repository Scanning

Scan entire Git repositories for vulnerabilities.

#### Run Trivy Scan

```bash
# Scan remote repository
trivy repo https://github.com/myorg/myrepo --format json --output trivy-repo.json

# Scan local repository
trivy repo /path/to/local/repo --format json --output trivy-local-repo.json

# Scan specific branch
trivy repo https://github.com/myorg/myrepo --branch develop --format json --output trivy-develop.json
```

#### Import to Phoenix

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-repo.json \
  --config config_test.ini \
  --assessment "Repository-Security-Scan" \
  --scanner trivy \
  --asset-type BUILD
```

**Result:** Repository vulnerabilities imported as BUILD asset type.

---

### 4. Infrastructure as Code (IaC) Scanning

Scan Kubernetes manifests, Terraform, CloudFormation, Dockerfile, etc. for misconfigurations.

#### Run Trivy Scan

```bash
# Scan Kubernetes manifests
trivy config /path/to/k8s/manifests --format json --output trivy-k8s-config.json

# Scan Terraform files
trivy config /path/to/terraform --format json --output trivy-terraform.json

# Scan Dockerfile
trivy config /path/to/Dockerfile --format json --output trivy-dockerfile.json

# Scan Helm charts
trivy config /path/to/helm/chart --format json --output trivy-helm.json
```

#### Import to Phoenix

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-k8s-config.json \
  --config config_test.ini \
  --assessment "IaC-Security-Scan" \
  --scanner trivy \
  --asset-type INFRA
```

**Result:** Misconfigurations imported as INFRA asset type.

---

### 5. Kubernetes Cluster Scanning

Scan live Kubernetes clusters for vulnerabilities and misconfigurations.

#### Run Trivy Scan

```bash
# Scan entire cluster
trivy k8s --report summary --format json --output trivy-k8s-cluster.json

# Scan specific namespace
trivy k8s --namespace production --format json --output trivy-k8s-prod.json

# Scan with compliance checks
trivy k8s --compliance k8s-cis --format json --output trivy-k8s-cis.json
```

#### Import to Phoenix

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-k8s-cluster.json \
  --config config_test.ini \
  --assessment "K8s-Cluster-Scan" \
  --scanner trivy \
  --asset-type INFRA
```

**Result:** Kubernetes findings imported as INFRA asset type.

---

## Combined Scanning Workflow

Perform comprehensive security scanning across all layers in a single assessment.

### Complete Security Review

```bash
#!/bin/bash
# Complete security scan workflow

ASSESSMENT="Q4-2026-Security-Review"
CONFIG="config_test.ini"

# Step 1: Scan container image
echo "🐳 Scanning container image..."
trivy image myapp:latest --format json --output trivy-container.json
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-container.json \
  --config $CONFIG \
  --assessment $ASSESSMENT \
  --scanner trivy \
  --asset-type CONTAINER \
  --import-type new

# Step 2: Scan application dependencies (SCA)
echo "📦 Scanning dependencies..."
trivy filesystem ./app --format json --output trivy-sca.json
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-sca.json \
  --config $CONFIG \
  --assessment $ASSESSMENT \
  --scanner trivy \
  --asset-type BUILD \
  --import-type merge

# Step 3: Scan infrastructure as code
echo "🔧 Scanning IaC..."
trivy config ./terraform --format json --output trivy-iac.json
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-iac.json \
  --config $CONFIG \
  --assessment $ASSESSMENT \
  --scanner trivy \
  --asset-type INFRA \
  --import-type merge

# Step 4: Scan Kubernetes cluster
echo "☸️  Scanning K8s cluster..."
trivy k8s --report summary --format json --output trivy-k8s.json
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-k8s.json \
  --config $CONFIG \
  --assessment $ASSESSMENT \
  --scanner trivy \
  --asset-type INFRA \
  --import-type merge

echo "✅ Complete security review imported to assessment: $ASSESSMENT"
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Install Trivy
      - name: Install Trivy
        run: |
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
          sudo apt-get update
          sudo apt-get install trivy
      
      # Scan container image
      - name: Scan Container
        run: |
          trivy image ${{ env.IMAGE_NAME }}:${{ github.sha }} \
            --format json \
            --output trivy-container.json
      
      # Scan dependencies
      - name: Scan Dependencies
        run: |
          trivy filesystem . \
            --format json \
            --output trivy-sca.json
      
      # Import to Phoenix
      - name: Import to Phoenix
        env:
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
        run: |
          # Container scan
          python3 phoenix_multi_scanner_enhanced.py \
            --file trivy-container.json \
            --assessment "CI-Scan-${{ github.sha }}" \
            --scanner trivy \
            --asset-type CONTAINER \
            --import-type new
          
          # SCA scan
          python3 phoenix_multi_scanner_enhanced.py \
            --file trivy-sca.json \
            --assessment "CI-Scan-${{ github.sha }}" \
            --scanner trivy \
            --asset-type BUILD \
            --import-type merge
```

---

## Asset Type Reference

| Asset Type | When to Use | Trivy Command | Phoenix Fields |
|------------|-------------|---------------|----------------|
| **CONTAINER** | Container image vulnerabilities | `trivy image` | `dockerfile`, `repository` |
| **BUILD** | Dependency/SCA vulnerabilities | `trivy filesystem`, `trivy repo` | `buildFile`, `origin` |
| **INFRA** | IaC misconfigurations, K8s issues | `trivy config`, `trivy k8s` | `hostname`, `ip` |

---

## Import Types Explained

### `new` - Replace All Data

```bash
# First import - creates new assessment
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-scan.json \
  --assessment "Security-Scan" \
  --import-type new
```

**Behavior:** Replaces all existing data in the assessment. Closes vulnerabilities not in the scan.

**Use When:** Starting fresh, complete scan results.

---

### `merge` - Combine Results

```bash
# Second import - adds to existing assessment
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-sca.json \
  --assessment "Security-Scan" \
  --import-type merge
```

**Behavior:** Adds new findings, updates existing ones. Closes vulnerabilities not in combined results.

**Use When:** Combining multiple scanner results in one assessment.

---

### `delta` - Add Only (Safest)

```bash
# Incremental import - only adds/updates
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-partial.json \
  --assessment "Security-Scan" \
  --import-type delta
```

**Behavior:** Only adds or updates. Never closes vulnerabilities.

**Use When:** Partial scans, incremental updates, testing.

---

## Troubleshooting

### Issue: Scan imported as wrong asset type

**Problem:** Trivy filesystem scan imported as CONTAINER instead of BUILD.

**Solution:** Always specify `--asset-type BUILD` for SCA scans:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-sca.json \
  --scanner trivy \
  --asset-type BUILD  # ← Required for SCA
```

---

### Issue: No vulnerabilities found

**Problem:** Trivy scan shows vulnerabilities but Phoenix import shows 0.

**Solution:** Check Trivy output format:

```bash
# Ensure JSON format
trivy filesystem . --format json --output scan.json

# Verify file has vulnerabilities
cat scan.json | jq '.Results[].Vulnerabilities | length'
```

---

### Issue: Asset name not descriptive

**Problem:** Assets imported with generic names like "Dockerfile" or "unknown".

**Solution:** Use `--asset-name` override:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-sca.json \
  --scanner trivy \
  --asset-type BUILD \
  --asset-name "myapp-v2.1.0-dependencies"
```

---

## Advanced Options

### Batching Configuration

For large Trivy scans (1000+ vulnerabilities), enable batching:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file large-trivy-scan.json \
  --scanner trivy \
  --asset-type BUILD \
  --enable-batching \
  --max-batch-size 50 \
  --max-payload-mb 10.0
```

### Severity Filtering

Filter Trivy results before import:

```bash
# Only scan for HIGH and CRITICAL
trivy filesystem . \
  --severity HIGH,CRITICAL \
  --format json \
  --output trivy-critical-only.json

python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-critical-only.json \
  --scanner trivy \
  --asset-type BUILD
```

### Custom Tags

Add custom tags to imported assets:

```bash
# Create tag config file
cat > tags.yaml <<EOF
tags:
  - key: environment
    value: production
  - key: team
    value: platform
  - key: scanner
    value: trivy
EOF

# Import with tags
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-scan.json \
  --scanner trivy \
  --asset-type BUILD \
  --tag-file tags.yaml
```

---

## Best Practices

### 1. Use Descriptive Assessment Names

```bash
# ✅ Good
--assessment "Q4-2026-Production-Container-Scan"

# ❌ Bad
--assessment "scan1"
```

### 2. Separate Asset Types in Different Assessments

```bash
# Option A: Separate assessments per type
trivy image myapp:latest --format json --output container.json
python3 phoenix_multi_scanner_enhanced.py \
  --file container.json \
  --assessment "Q4-Container-Security" \
  --asset-type CONTAINER

trivy filesystem ./app --format json --output sca.json
python3 phoenix_multi_scanner_enhanced.py \
  --file sca.json \
  --assessment "Q4-SCA-Dependencies" \
  --asset-type BUILD

# Option B: Combined assessment with merge
# (Use the combined workflow example above)
```

### 3. Regular Scanning Schedule

```bash
# Daily container scans
0 2 * * * trivy image myapp:latest --format json --output /scans/daily-container.json && \
  python3 phoenix_multi_scanner_enhanced.py --file /scans/daily-container.json \
  --assessment "Daily-Container-Scan-$(date +%Y%m%d)" --scanner trivy --asset-type CONTAINER

# Weekly SCA scans
0 3 * * 0 trivy filesystem /app --format json --output /scans/weekly-sca.json && \
  python3 phoenix_multi_scanner_enhanced.py --file /scans/weekly-sca.json \
  --assessment "Weekly-SCA-Scan-$(date +%Y%m%d)" --scanner trivy --asset-type BUILD
```

### 4. Version Control Scan Results

```bash
# Save scan results with timestamps
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
trivy filesystem . --format json --output "scans/trivy-sca-${TIMESTAMP}.json"

# Import with versioned assessment
python3 phoenix_multi_scanner_enhanced.py \
  --file "scans/trivy-sca-${TIMESTAMP}.json" \
  --assessment "SCA-Scan-${TIMESTAMP}" \
  --scanner trivy \
  --asset-type BUILD
```

---

## Related Documentation

- 📖 [Main README](../../README.md) - Complete tool documentation
- 📖 [Quick Start Guide](../guides/QUICK_START_ALL_SCANNERS.md) - All scanner types
- 📖 [Batching Guide](../guides/BATCHING_AND_IMPORT_TYPES.md) - Import types and batching
- 📖 [Asset Name Customization](../guides/ASSET_NAME_CUSTOMIZATION.md) - Custom asset naming

---

## Support

For issues or questions:

1. Check [Troubleshooting](#troubleshooting) section above
2. Review [README.md](../../README.md) for general usage
3. Check Trivy documentation: https://aquasecurity.github.io/trivy/

---

**Last Updated:** February 2026  
**Version:** 5.0  
**Status:** ✅ Production Ready
