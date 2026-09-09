# Configuration File Guide

## Overview

Each Phoenix Security import tool now uses its own dedicated configuration file to avoid conflicts and provide better organization.

## Default Configuration Files

### 🔧 Basic Import Tool (`phoenix_import_refactored.py`)
- **Default**: `config_refactored.ini`
- **Fallback Chain**: `config.ini` → `config_refactored EXAMPLE.ini`
- **Override**: Use `--config <file>` to specify custom config

### 🔧 Multi-Scanner Import Tool (`phoenix_multi_scanner_import.py`)
- **Default**: `config_multi_scanner.ini`
- **Fallback Chain**: `config.ini` → `config_multi_scanner EXAMPLE.ini` → `config_refactored.ini`
- **Override**: Use `--config <file>` to specify custom config

### 🔧 Data Anonymizer (`data_anonymizer.py`)
- **Configuration**: Not required (standalone utility)
- **Settings**: All options available via command-line arguments

## Configuration File Structure

Both import tools use the same INI format:

```ini
[phoenix]
# Phoenix API Configuration
client_id = your_client_id_here
client_secret = your_client_secret_here
api_base_url = https://api.demo.appsecphx.io

# Import Settings
scan_type = Generic Scan
import_type = new
assessment_name = 
scan_target = 
auto_import = true
wait_for_completion = true
batch_delay = 10
timeout = 3600
check_interval = 10
```

## Benefits of Separate Config Files

### ✅ **Conflict Prevention**
- No more configuration conflicts between tools
- Each tool has its own dedicated settings
- Clear separation of concerns

### ✅ **Better Organization**
- Tool-specific configurations are isolated
- Easier to manage multiple environments
- Reduced configuration errors

### ✅ **Fallback Safety**
- Automatic fallback to common config files
- Graceful degradation if default config missing
- Clear logging of which config file is being used

### ✅ **Flexibility**
- Override with `--config` for custom setups
- Support for existing `config.ini` files
- Backward compatibility maintained

## Migration Guide

### From Single `config.ini`

If you currently use a single `config.ini` file:

1. **Option 1: Keep using `config.ini`** (Recommended for simple setups)
   ```bash
   # Both tools will automatically fall back to config.ini
   python phoenix_import_refactored.py --file data.csv
   python phoenix_multi_scanner_import.py --file scan.json
   ```

2. **Option 2: Create tool-specific configs** (Recommended for complex setups)
   ```bash
   # Copy your existing config to tool-specific files
   cp config.ini config_refactored.ini
   cp config.ini config_multi_scanner.ini
   
   # Customize each file for specific tool needs
   # Then use without --config flag
   python phoenix_import_refactored.py --file data.csv
   python phoenix_multi_scanner_import.py --file scan.json
   ```

3. **Option 3: Use explicit config files**
   ```bash
   # Specify config explicitly
   python phoenix_import_refactored.py --config my_config.ini --file data.csv
   python phoenix_multi_scanner_import.py --config my_config.ini --file scan.json
   ```

## Environment Variables

Both tools support environment variable overrides:

```bash
export PHOENIX_CLIENT_ID="your_client_id"
export PHOENIX_CLIENT_SECRET="your_client_secret"  
export PHOENIX_API_BASE_URL="https://api.demo.appsecphx.io"

# Environment variables take precedence over config files
python phoenix_import_refactored.py --file data.csv
```

## Command-Line Overrides

Both tools support command-line credential overrides:

```bash
# Override specific credentials
python phoenix_import_refactored.py \
  --client-id "your_id" \
  --client-secret "your_secret" \
  --api-url "https://api.demo.appsecphx.io" \
  --file data.csv

python phoenix_multi_scanner_import.py \
  --client-id "your_id" \
  --client-secret "your_secret" \
  --api-url "https://api.demo.appsecphx.io" \
  --file scan.json
```

## Configuration Priority

The configuration loading priority (highest to lowest):

1. **Command-line arguments** (`--client-id`, `--client-secret`, `--api-url`)
2. **Environment variables** (`PHOENIX_CLIENT_ID`, `PHOENIX_CLIENT_SECRET`, `PHOENIX_API_BASE_URL`)
3. **Configuration file** (default or specified with `--config`)
4. **Fallback configuration files** (in fallback chain order)

## Troubleshooting

### Configuration File Not Found
```
INFO - Default config not found, using fallback: config.ini
```
This is normal behavior. The tool will automatically use the best available config file.

### Missing Credentials
```
ERROR - Missing required configuration: client_id, client_secret
```
Ensure your configuration file contains all required Phoenix API credentials.

### Config File Validation
```bash
# Test configuration loading
python phoenix_import_refactored.py --help
python phoenix_multi_scanner_import.py --help
```

The tools will validate configuration when starting and report any issues.

## Best Practices

### 🎯 **Development Environment**
```bash
# Use tool-specific configs for development
config_refactored.ini      # For basic import testing
config_multi_scanner.ini   # For scanner integration testing
```

### 🎯 **Production Environment**
```bash
# Use environment variables for production
export PHOENIX_CLIENT_ID="prod_client_id"
export PHOENIX_CLIENT_SECRET="prod_client_secret"
export PHOENIX_API_BASE_URL="https://api.prod.appsecphx.io"
```

### 🎯 **CI/CD Pipeline**
```bash
# Use explicit config files in automation
python phoenix_multi_scanner_import.py \
  --config /etc/phoenix/production.ini \
  --folder /scan_results/
```

## Summary

The new configuration file system provides:
- ✅ Better organization and conflict prevention
- ✅ Automatic fallback for seamless migration
- ✅ Flexible override options
- ✅ Backward compatibility
- ✅ Clear logging and error messages

Choose the approach that best fits your workflow and environment!
