# Utility Scripts

This directory contains utility and shell scripts for Phoenix Multi-Scanner Enhanced.

## Python Utility Scripts

### Translation Generator Scripts
- **`batch_create_translators.py`** - Batch creates translator modules
- **`create_all_mappings.py`** - Creates YAML mappings for all scanners
- **`create_tier1_translators.py`** - Generates Tier 1 translator code
- **`generate_yaml_mappings.py`** - Generates YAML field mappings

### Usage
```bash
cd /path/to/Loading_Script_V4/scripts

# Generate YAML mappings for all scanners
python create_all_mappings.py

# Generate Tier 1 translators
python create_tier1_translators.py

# Generate YAML field mappings
python generate_yaml_mappings.py
```

## Shell Scripts

### Monitoring Scripts
- **`monitor_progress.sh`** - Monitors test/import progress in real-time
- **`monitor_test.sh`** - Monitors test execution

### Testing Scripts
- **`run_pilot_test.sh`** - Runs pilot tests for validation
- **`test_prowler_scanner.sh`** - Tests Prowler scanner specifically

### Usage
```bash
cd /path/to/Loading_Script_V4/scripts

# Make scripts executable
chmod +x *.sh

# Monitor progress
./monitor_progress.sh

# Monitor tests
./monitor_test.sh

# Run pilot test
./run_pilot_test.sh

# Test Prowler
./test_prowler_scanner.sh
```

## Notes

### For Python Scripts
- These scripts are typically run once during development
- They generate code or configuration based on scanner test files
- Require access to `../scanner_test_files/scans/` directory
- May need to adjust sys.path to import from parent directory

### For Shell Scripts
- Monitoring scripts watch log files in real-time
- Testing scripts may require configuration files in parent directory
- Scripts assume they're in the `scripts/` subdirectory

## Import Path Handling

Python scripts that need to import from the main codebase should add:

```python
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
```

## Related Documentation

See parent directory for:
- `README.md` - Main project documentation
- `QUICK_START_ALL_SCANNERS.md` - Quick start guide
- `REQUIREMENTS_SUMMARY.md` - Requirements and dependencies

