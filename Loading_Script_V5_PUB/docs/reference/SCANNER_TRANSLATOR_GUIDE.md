# Loading_Script_V5 — Scanner Translator Guide

**Version**: 5.0 (Modular Architecture)
**Last Updated**: February 2026
**Path**: `Utils/Loading_Script_V5/`

---

## Table of Contents

- [Overview](#overview)
- [Container Scanners](#container-scanners)
- [Cloud Scanners](#cloud-scanners)
- [SAST Scanners](#sast-scanners)
- [SCA Scanners](#sca-scanners)
- [DAST Scanners](#dast-scanners)
- [Secrets Scanners](#secrets-scanners)
- [Bug Bounty Platforms](#bug-bounty-platforms)
- [Infrastructure Scanners](#infrastructure-scanners)
- [Standard Formats](#standard-formats)
- [Specialized Scanners](#specialized-scanners)
- [Related Documents](#related-documents)

---

## Overview

Loading_Script_V5 supports **205+ scanner types** through a two-tier translation system:

- **47 hard-coded translators** in `scanner_translators/` — for complex scanners requiring custom parsing logic
- **191 YAML-defined mappings** in `scanner_field_mappings.yaml` — for scanners with straightforward field mapping

Scanner type is **auto-detected** from file structure. Use `--scanner <type>` to override auto-detection.

---

## Container Scanners

### Aqua Security

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner aqua` |
| Translator | `aqua_translator.py` |
| Supported formats | JSON |
| Default asset type | CONTAINER |
| Key detection fields | `resources`, `resource.vulnerabilities` |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file aqua-scan.json \
  --config my_config.ini \
  --assessment "Container-Aqua-Scan"
```

### Grype (Anchore)

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner grype` |
| Translator | `grype_translator.py` |
| Supported formats | JSON |
| Default asset type | CONTAINER |
| Key detection fields | `matches`, `source`, `distro` |

```bash
# Generate Grype output
grype myimage:latest -o json > grype-results.json

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
  --file grype-results.json \
  --config my_config.ini \
  --assessment "SCA-Grype"
```

### Trivy

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner trivy` |
| Translator | `trivy_translator.py` |
| Supported formats | JSON |
| Default asset type | CONTAINER |
| Key detection fields | `Results`, `Vulnerabilities`, `SchemaVersion` |

```bash
# Generate Trivy output
trivy image --format json -o trivy-results.json myimage:latest

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-results.json \
  --config my_config.ini \
  --assessment "Container-Trivy"
```

**Known quirks**: Trivy JSON schema changed between v0.38 and v0.50. Both schemas are supported.

### Trivy Operator

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner trivy-operator` |
| Translator | `trivy_operator_translator.py` |
| Supported formats | JSON |
| Default asset type | CONTAINER |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-operator-report.json \
  --scanner trivy-operator \
  --config my_config.ini \
  --assessment "K8s-Trivy-Operator"
```

### Sysdig

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner sysdig` |
| Translator | `sysdig_translator.py` |
| Supported formats | JSON |
| Default asset type | CONTAINER |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file sysdig-results.json \
  --config my_config.ini \
  --assessment "Container-Sysdig"
```

---

## Cloud Scanners

### AWS Inspector

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner aws-inspector` |
| Translator | `aws_inspector_translator.py` |
| Supported formats | JSON |
| Default asset type | CLOUD |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file inspector-findings.json \
  --config my_config.ini \
  --assessment "AWS-Inspector-Scan"
```

### Azure Security Center

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner azure-security-center` |
| Translator | `azure_security_center_translator.py` |
| Supported formats | JSON |
| Default asset type | CLOUD |

### MS Defender

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner msdefender` |
| Translator | `msdefender_translator.py` |
| Supported formats | JSON |
| Default asset type | CLOUD |

### Prowler (v2–v5)

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner prowler` |
| Translator | `prowler_translator.py` (consolidated — handles v2, v3, v4, v5) |
| Supported formats | JSON, CSV |
| Default asset type | CLOUD |

```bash
# Prowler v4 JSON output
python3 phoenix_multi_scanner_enhanced.py \
  --file prowler-output.json \
  --config my_config.ini \
  --assessment "Cloud-Prowler-v4"
```

**Known quirks**: Prowler v2 CSV format differs from v3+ JSON. The consolidated translator handles all versions automatically.

### Scout Suite

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner scout-suite` |
| Translator | `scout_suite_translator.py` |
| Supported formats | JSON |
| Default asset type | CLOUD |

### Wiz

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner wiz` |
| Translator | `wiz_translator.py` (consolidated — 2 formats merged) |
| Supported formats | JSON, CSV |
| Default asset type | CLOUD |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file wiz-vulnerabilities.json \
  --config my_config.ini \
  --assessment "Cloud-Wiz-Scan"
```

---

## SAST Scanners

### Checkmarx

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner checkmarx` |
| Translator | `checkmarx_translator.py` |
| Supported formats | JSON, XML |
| Default asset type | CODE |

### Fortify

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner fortify` |
| Translator | `fortify_translator.py` |
| Supported formats | XML (FPR) |
| Default asset type | CODE |

### Kiuwan

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner kiuwan` |
| Translator | `kiuwan_translator.py` |
| Supported formats | CSV |
| Default asset type | CODE |

### SonarQube

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner sonarqube` |
| Translator | `sonarqube_translator.py` |
| Supported formats | JSON |
| Default asset type | CODE |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file sonarqube-issues.json \
  --config my_config.ini \
  --assessment "SAST-SonarQube"
```

---

## SCA Scanners

### Blackduck

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner blackduck` |
| Translator | `blackduck_translator.py` (consolidated — 5 formats merged) |
| Supported formats | JSON, CSV |
| Default asset type | REPOSITORY |

### CycloneDX

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner cyclonedx` |
| Translator | `cyclonedx_translator.py` |
| Supported formats | JSON, XML (SBOM) |
| Default asset type | REPOSITORY |

### Dependency Check (OWASP)

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner dependency-check` |
| Translator | `dependency_check_translator.py` |
| Supported formats | JSON, XML |
| Default asset type | REPOSITORY |

### JFrog Xray

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner jfrog-xray` |
| Translator | `jfrog_xray_translator.py` (consolidated — 5 formats merged) |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

### npm audit

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner npm-audit` |
| Translator | `npm_audit_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

```bash
# Generate npm audit output
npm audit --json > npm-audit.json

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
  --file npm-audit.json \
  --config my_config.ini \
  --assessment "SCA-npm-audit"
```

### ORT (OSS Review Toolkit)

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner ort` |
| Translator | `ort_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

### pip audit

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner pip-audit` |
| Translator | `pip_audit_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

```bash
pip-audit --format json -o pip-audit.json
python3 phoenix_multi_scanner_enhanced.py \
  --file pip-audit.json \
  --config my_config.ini \
  --assessment "SCA-pip-audit"
```

### Snyk CLI

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner snyk` |
| Translator | `snyk_cli_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

### Veracode SCA

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner veracode-sca` |
| Translator | `veracode_sca_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

---

## DAST Scanners

### Burp Suite

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner burp` |
| Translator | `burp_translator.py` |
| Supported formats | JSON, XML |
| Default asset type | WEB |

### MicroFocus WebInspect

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner webinspect` |
| Translator | `webinspect_translator.py` |
| Supported formats | XML |
| Default asset type | WEB |

---

## Secrets Scanners

### GitHub Secret Scanning

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner github-secret-scanning` |
| Translator | `github_secret_scanning_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

### GitLab Secret Detection

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner gitlab-secret-detection` |
| Translator | `gitlab_secret_detection_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

### Nosey Parker

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner noseyparker` |
| Translator | `noseyparker_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

### TruffleHog

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner trufflehog` |
| Translator | `trufflehog_translator.py` |
| Supported formats | JSON |
| Default asset type | REPOSITORY |

```bash
trufflehog filesystem --json . > trufflehog-results.json
python3 phoenix_multi_scanner_enhanced.py \
  --file trufflehog-results.json \
  --config my_config.ini \
  --assessment "Secrets-TruffleHog"
```

---

## Bug Bounty Platforms

### Bugcrowd

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner bugcrowd` |
| Translator | `bugcrowd_translator.py` |
| Supported formats | CSV |
| Default asset type | WEB |

### HackerOne

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner hackerone` |
| Translator | `hackerone_translator.py` |
| Supported formats | CSV |
| Default asset type | WEB |

---

## Infrastructure Scanners

### Qualys

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner qualys` |
| Translator | `qualys_translator.py` |
| Supported formats | JSON, XML, CSV |
| Default asset type | INFRA |

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file qualys-report.xml \
  --config my_config.ini \
  --assessment "Infra-Qualys-Q4"
```

### Rapid7

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner rapid7` |
| Translator | `rapid7_csv_translator.py` |
| Supported formats | CSV |
| Default asset type | INFRA |

### Tenable

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner tenable` |
| Translator | `tenable_translator.py` |
| Supported formats | JSON, CSV |
| Default asset type | INFRA |

---

## Standard Formats

### SARIF (Static Analysis Results Interchange Format)

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner sarif` |
| Translator | `sarif_translator.py` |
| Supported formats | JSON (SARIF 2.1.0) |
| Default asset type | CODE |

```bash
# Any scanner that produces SARIF output
python3 phoenix_multi_scanner_enhanced.py \
  --file results.sarif \
  --scanner sarif \
  --config my_config.ini \
  --assessment "SAST-SARIF"
```

### Phoenix CSV

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner phoenix-csv` |
| Translator | `phoenix_csv_translator.py` |
| Supported formats | CSV |
| Default asset type | varies |

For importing pre-formatted Phoenix CSV files. See [PHOENIX_CSV_README.md](../scanners/PHOENIX_CSV_README.md).

---

## Specialized Scanners

### Chef InSpec

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner inspec` |
| Supported formats | JSON |
| Default asset type | INFRA |

### KubeAudit

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner kubeaudit` |
| Translator | `kubeaudit_translator.py` |
| Supported formats | JSON |
| Default asset type | CONTAINER |

### OpenSCAP

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner openscap` |
| Supported formats | XML (XCCDF) |
| Default asset type | INFRA |

### Solar AppScreener

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner solar-appscreener` |
| Translator | `solar_appscreener_translator.py` |
| Supported formats | JSON |
| Default asset type | CODE |

### TestSSL

| Property | Value |
|----------|-------|
| Scanner flag | `--scanner testssl` |
| Translator | `testssl_translator.py` |
| Supported formats | JSON |
| Default asset type | WEB |

```bash
# Generate TestSSL output
testssl --jsonfile testssl-results.json example.com

# Import to Phoenix
python3 phoenix_multi_scanner_enhanced.py \
  --file testssl-results.json \
  --config my_config.ini \
  --assessment "TLS-Scan"
```

---

## Related Documents

- [README](../../README.md) — Primary documentation
- [Quick Start](../../QUICK_START.md) — 5-minute setup guide
- [Configuration Guide](../guides/CONFIGURATION_GUIDE.md) — All configuration options
- [Adding New Scanner](ADDING_NEW_SCANNER.md) — Developer guide for new translators
- [Scanner Service Guide](../guides/SCANNER_SERVICE_GUIDE.md) — REST API service deployment
- [Troubleshooting](../guides/TROUBLESHOOTING.md) — Operational runbook
