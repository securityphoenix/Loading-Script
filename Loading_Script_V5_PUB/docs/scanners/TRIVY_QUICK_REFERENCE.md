# Trivy Quick Reference Card

**One-page reference for Trivy scanner with Phoenix Multi-Scanner Import Tool**

---

## 🎯 Asset Type Override - The Key to SCA Scanning

```bash
# Container Scan (default)
--asset-type CONTAINER  # or omit (auto-detected)

# SCA/Dependency Scan (IMPORTANT!)
--asset-type BUILD      # ← Required for filesystem/SCA scans

# IaC/Config Scan
--asset-type INFRA      # For Kubernetes, Terraform, etc.
```

---

## 📋 Quick Commands

### Container Scanning
```bash
trivy image myapp:latest --format json --output scan.json
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy \
  --assessment "Container-Scan"
```

### SCA/Dependency Scanning 🎯
```bash
trivy filesystem /path/to/project --format json --output scan.json
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy \
  --asset-type BUILD \
  --assessment "SCA-Scan"
```

### Repository Scanning
```bash
trivy repo https://github.com/org/repo --format json --output scan.json
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy \
  --asset-type BUILD \
  --assessment "Repo-Scan"
```

### IaC/Config Scanning
```bash
trivy config /path/to/configs --format json --output scan.json
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy \
  --asset-type INFRA \
  --assessment "IaC-Scan"
```

---

## 🔄 Combined Workflow

```bash
ASSESSMENT="Q4-Security-Review"

# 1. Container
trivy image myapp:latest --format json --output container.json
python3 phoenix_multi_scanner_enhanced.py \
  --file container.json --scanner trivy --asset-type CONTAINER \
  --assessment $ASSESSMENT --import-type new

# 2. SCA
trivy filesystem ./app --format json --output sca.json
python3 phoenix_multi_scanner_enhanced.py \
  --file sca.json --scanner trivy --asset-type BUILD \
  --assessment $ASSESSMENT --import-type merge

# 3. IaC
trivy config ./terraform --format json --output iac.json
python3 phoenix_multi_scanner_enhanced.py \
  --file iac.json --scanner trivy --asset-type INFRA \
  --assessment $ASSESSMENT --import-type merge
```

---

## 📊 Asset Type Reference

| Scan Type | Trivy Command | Asset Type | Required? |
|-----------|---------------|------------|-----------|
| Container | `trivy image` | CONTAINER | No (default) |
| SCA | `trivy filesystem` | BUILD | **YES** ⚠️ |
| Repository | `trivy repo` | BUILD | **YES** |
| IaC/Config | `trivy config` | INFRA | **YES** |
| Kubernetes | `trivy k8s` | INFRA | **YES** |

---

## ⚠️ Common Mistakes

### ❌ Wrong - SCA without asset type
```bash
trivy filesystem . --format json --output scan.json
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy
# Result: Imported as CONTAINER (wrong!)
```

### ✅ Correct - SCA with asset type
```bash
trivy filesystem . --format json --output scan.json
python3 phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --scanner trivy \
  --asset-type BUILD
# Result: Imported as BUILD (correct!)
```

---

## 🚀 Import Types

| Type | Behavior | Use When |
|------|----------|----------|
| `new` | Replace all | First import, complete scan |
| `merge` | Combine results | Adding to existing assessment |
| `delta` | Add only (safest) | Partial scan, testing |

---

## 📖 Full Documentation

- **Complete Guide:** [`TRIVY_USAGE_GUIDE.md`](TRIVY_USAGE_GUIDE.md)
- **Main README:** [`README.md`](../../README.md)
- **Quick Start:** [`QUICK_START_ALL_SCANNERS.md`](../guides/QUICK_START_ALL_SCANNERS.md)

---

**Last Updated:** February 2026 | **Version:** 5.0
