# Loading_Script_V5 — Troubleshooting

**Version**: 5.0 (Full Version)
**Last Updated**: February 2026
**Path**: `Utils/Loading_Script_V5/`

---

## Core Import Issues

Import troubleshooting (authentication, API connectivity, scanner detection, input format, output/upload, performance) is covered in the sections below.

---

## Synthetic Data Generator Issues

### Symptom: `CVE database not found`

**Root Cause**: Real CVE data files are missing.

**Fix**:
```bash
cd synthetic-data-generator
# Ensure CVE data files exist in the expected location
ls -la *.json  # Check for CVE data files
```

### Symptom: `No scanner types configured`

**Root Cause**: `scanner_types` parameter is empty in config.

**Fix**: Specify scanner types in `synthetic_data_config.ini`:
```ini
[general]
scanner_types = trivy,grype,qualys,snyk
```

### Symptom: Zero vulnerabilities generated

**Root Cause**: Vulnerability count range is set to 0.

**Fix**: Ensure min/max values are greater than 0:
```ini
[vulnerability_counts]
trivy_vulns_min = 5
trivy_vulns_max = 25
```

### Symptom: `Permission denied` writing generated files

**Root Cause**: Output directory not writable.

**Fix**:
```bash
mkdir -p generated
chmod 755 generated
```

---

## Tag Customization Issues

### Symptom: Tags not applied after import

**Root Cause**: `apply_tags_after_import` is set to `false` in config.

**Fix**:
```ini
[phoenix]
apply_tags_after_import = true
```

### Symptom: Tag file not found

**Root Cause**: Tag configuration file missing from `customization/` directory.

**Fix**: Verify tag files exist:
```bash
ls customization/*.yaml
```

---

## Related Documents

- [Configuration Guide](CONFIGURATION_GUIDE.md) — Configuration reference
- [README](../../README.md) — Primary documentation
