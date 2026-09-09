# Unit Tests

This directory contains all unit tests for Phoenix Multi-Scanner Enhanced.

## Test Files

### Comprehensive Tests
- **`test_all_scanners_comprehensive.py`** - Full test suite for all 205 scanners
  - Tests each scanner with real test files
  - Validates import success, asset counts, vulnerability counts
  - Generates detailed logs and reports

### Basic Tests
- **`test_all_scanners.py`** - Basic scanner validation tests

### Critical Path Tests
- **`test_phase2_critical.py`** - Phase 2 critical functionality tests

### Quick Tests by Tier
- **`test_tier1_quick.py`** - Quick tests for Tier 1 translators
- **`test_tier2_quick.py`** - Quick tests for Tier 2 translators
- **`test_tier3_quick.py`** - Quick tests for Tier 3 translators

## Running Tests

### From Unit Tests Directory
```bash
cd /path/to/Loading_Script_V4/tests/unit_tests

# Run comprehensive test (all 205 scanners)
python test_all_scanners_comprehensive.py

# Run tier tests
python test_tier1_quick.py
python test_tier2_quick.py
python test_tier3_quick.py
```

### From Project Root
```bash
cd /path/to/Loading_Script_V4

# Run comprehensive test
python tests/unit_tests/test_all_scanners_comprehensive.py

# Run specific tier test
python tests/unit_tests/test_tier1_quick.py
```

## Import Path Handling

Tests that need to import from the main codebase (parent directory) should add:

```python
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
```

This ensures proper module imports regardless of where the test is run from.

## Test Configuration

Tests use configuration from:
- `../../config_test.ini` - Test API credentials
- `../../config_multi_scanner.ini` - Main configuration

## Test Data

Scanner test files are located at:
- `../../scanner_test_files/scans/` - 205 scanner directories with test files

## Output

Test logs and reports are saved to:
- Current directory (where test is run)
- `../archives/` - For archiving old test results

## Current Test Status

✅ **100% Coverage** - 205/205 Active Scanners Working

### Test Statistics
- Total Scanners: 205 active (208 total, 3 excluded per user request)
- Success Rate: 100%
- Translators: 63 specialized + 1 universal YAML fallback

## Notes

- Tests may take 30-60 minutes to complete all 205 scanners
- Requires valid Phoenix API credentials in config files
- Test results include asset counts, vulnerability counts, and error details
- Failed tests provide detailed error messages for debugging

