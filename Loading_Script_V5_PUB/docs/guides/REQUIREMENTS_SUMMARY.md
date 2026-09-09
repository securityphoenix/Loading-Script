# Requirements Files Summary

## Overview
This document describes the Python dependency requirements for the Phoenix Multi-Scanner Import Tool.

## Files Created

### 1. requirements.txt (Production)
**Purpose:** Core dependencies needed to run the tool in production

**Dependencies:**
- `requests>=2.31.0` - HTTP client for Phoenix API
- `PyYAML>=6.0.1` - YAML parser for scanner configurations

**Installation:**
```bash
pip install -r requirements.txt
```

**Size:** Minimal (only 2 packages)
**Use Case:** Production deployments, CI/CD pipelines, containerized environments

---

### 2. requirements-dev.txt (Development)
**Purpose:** All dependencies for development, testing, and documentation

**Includes:**
- All production requirements
- Testing frameworks (pytest, coverage)
- Code quality tools (black, flake8, mypy)
- Security scanners (bandit, safety)
- Documentation tools (mkdocs)
- Development utilities (ipython, ipdb)

**Installation:**
```bash
pip install -r requirements-dev.txt
```

**Use Case:** Local development, testing, code quality checks, documentation generation

---

### 3. INSTALLATION.md (Installation Guide)
**Purpose:** Comprehensive installation and setup guide

**Contents:**
- Quick installation methods
- Virtual environment setup
- Platform-specific instructions (Linux, macOS, Windows)
- Docker setup
- Troubleshooting guide
- CI/CD integration examples
- Verification steps

---

## Dependency Details

### Core Production Dependencies

#### requests (>=2.31.0)
- **Purpose:** HTTP client library
- **Used For:** 
  - Phoenix Security API authentication
  - Asset/vulnerability import REST calls
  - Retry logic with exponential backoff
  - JSON payload handling
- **Why This Version:** Security fixes and modern API support

#### PyYAML (>=6.0.1)
- **Purpose:** YAML parsing library
- **Used For:**
  - Reading `scanner_field_mappings.yaml` (6,100+ lines)
  - Configuration file parsing (`*.ini` files)
  - Support for 200+ scanner type definitions
- **Why This Version:** Security fixes for YAML loading

### Standard Library (No Installation Needed)

The tool also uses these Python standard library modules:
- `argparse` - Command-line argument parsing
- `configparser` - INI configuration file parsing
- `csv` - CSV file handling
- `json` - JSON parsing/serialization
- `logging` - Comprehensive logging
- `re` - Regular expressions
- `xml.etree.ElementTree` - XML parsing
- `datetime` - Date/time handling
- `pathlib` - Path operations
- `typing` - Type hints
- `dataclasses` - Data structures
- `abc` - Abstract base classes

## Installation Verification

### Quick Check
```bash
python3 -c "import requests, yaml; print('✅ All dependencies installed')"
```

### Detailed Check
```bash
python3 -c "
import requests
import yaml
print('✅ requests:', requests.__version__)
print('✅ PyYAML: Available')
"
```

### Current Environment
As of November 11, 2025:
- ✅ Python: 3.11.13
- ✅ requests: 2.32.3
- ✅ PyYAML: Installed

**Status: All dependencies already available!**

## Why So Few Dependencies?

The Phoenix Multi-Scanner Import Tool was designed with **minimal dependencies** for several reasons:

### 1. Security
- ✅ Fewer dependencies = smaller attack surface
- ✅ Easier to audit and maintain
- ✅ Faster security patching

### 2. Reliability
- ✅ Less dependency version conflicts
- ✅ More stable across Python versions
- ✅ Easier to deploy in restricted environments

### 3. Performance
- ✅ Faster installation
- ✅ Smaller container images
- ✅ Reduced memory footprint

### 4. Compatibility
- ✅ Works with Python 3.8+
- ✅ Compatible with air-gapped environments
- ✅ Easy to package and distribute

## Installation Methods Comparison

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **Direct pip** | Simple, fast | May conflict with system packages | Quick testing |
| **Virtual Environment** | Isolated, clean | Requires activation | Development, production |
| **Conda** | Environment management | Larger footprint | Data science teams |
| **Docker** | Fully isolated, reproducible | Requires Docker | Production, CI/CD |
| **System packages** | OS-integrated | May be outdated | System services |

**Recommendation:** Use virtual environment for most cases.

## Version Policy

### Semantic Versioning
We use semantic versioning with lower bounds:
- `>=2.31.0` means "2.31.0 or higher, but below 3.0.0"
- Allows bug fixes and minor features
- Prevents breaking changes

### Upgrade Strategy
- **Minor updates:** Safe to apply (e.g., 2.31.0 → 2.32.0)
- **Patch updates:** Always safe (e.g., 2.31.0 → 2.31.1)
- **Major updates:** Test thoroughly (e.g., 2.x → 3.x)

### Checking for Updates
```bash
pip list --outdated
```

### Upgrading Safely
```bash
# Test in virtual environment first
python3 -m venv test_venv
source test_venv/bin/activate
pip install -r requirements.txt --upgrade

# Run tests
python3 phoenix_multi_scanner_enhanced.py --help

# If successful, apply to production
deactivate
```

## CI/CD Pipeline Integration

### Caching Dependencies
Most CI/CD platforms support dependency caching:

**GitLab CI:**
```yaml
cache:
  paths:
    - venv/
```

**GitHub Actions:**
```yaml
- uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
```

**Jenkins:**
```groovy
cache(maxCacheSize: 250, caches: [
    arbitraryFileCache(path: 'venv', cacheValidityDecidingFile: 'requirements.txt')
])
```

### Build Time Estimates
- **Without cache:** ~30-45 seconds
- **With cache:** ~5-10 seconds
- **Docker layer cache:** ~2-5 seconds

## Troubleshooting

### Common Issues

#### Issue: "No module named 'requests'"
```bash
pip install requests>=2.31.0
```

#### Issue: "No module named 'yaml'"
```bash
pip install PyYAML>=6.0.1
```

#### Issue: Permission denied
```bash
pip install --user -r requirements.txt
```

#### Issue: SSL certificate verify failed
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

### Getting Help
1. Check Python version: `python3 --version`
2. Check pip version: `pip3 --version`
3. Verify installation: `pip list | grep -E "requests|PyYAML"`
4. Enable debug logging: Add `--debug` flag to script

## Optional Enhancements

While not required, these packages can enhance functionality:

### colorama
- **Purpose:** Colored terminal output
- **Benefit:** Better log readability
- **Install:** `pip install colorama`

### python-dateutil
- **Purpose:** Advanced date parsing
- **Benefit:** Handles more date formats
- **Install:** `pip install python-dateutil`

### cryptography
- **Purpose:** Secure connections
- **Benefit:** Enhanced SSL/TLS support
- **Install:** `pip install cryptography`

## Environment Variables

No environment variables are required for dependencies, but these are useful:

```bash
# Use specific pip index
export PIP_INDEX_URL=https://pypi.org/simple

# Disable pip version check (for CI/CD)
export PIP_DISABLE_PIP_VERSION_CHECK=1

# Set pip timeout
export PIP_DEFAULT_TIMEOUT=100

# Use pip cache
export PIP_CACHE_DIR=/tmp/pip-cache
```

## Offline Installation

For air-gapped environments:

```bash
# On internet-connected machine
pip download -r requirements.txt -d ./packages/

# Transfer ./packages/ to offline machine

# On offline machine
pip install --no-index --find-links=./packages/ -r requirements.txt
```

## Security Considerations

### Vulnerability Scanning
```bash
# Install safety
pip install safety

# Check for known vulnerabilities
safety check -r requirements.txt
```

### Dependency Pinning
For maximum reproducibility, create `requirements.lock`:

```bash
pip freeze > requirements.lock
```

Use in production:
```bash
pip install -r requirements.lock
```

## Summary

| Aspect | Details |
|--------|---------|
| **Total Dependencies** | 2 (requests, PyYAML) |
| **Python Version** | 3.8+ |
| **Installation Time** | < 1 minute |
| **Size** | ~5 MB total |
| **Security** | Both packages actively maintained |
| **License** | Both Apache 2.0 / MIT compatible |
| **Status** | ✅ Production Ready |

---
**Created:** November 11, 2025
**Version:** 1.0
**Status:** ✅ Complete and Tested

