# Phoenix Security Asset Import Tool - Refactored Version

A comprehensive, enterprise-grade tool for importing assets and vulnerabilities into Phoenix Security from JSON and CSV data sources.

## 🚀 Quick Start

### Basic Commands
```bash
# Import CSV file as infrastructure assets
python phoenix_import_refactored.py --file scan_results.csv --asset-type INFRA

# Import JSON file as web assets with anonymization
python phoenix_import_refactored.py --file webapp_scan.json --asset-type WEB --anonymize

# Process entire folder
python phoenix_import_refactored.py --folder /scan_results/ --asset-type CLOUD

# Only add tags to existing assets
python phoenix_import_refactored.py --file assets.json --just-tags

# Create anonymized test data
python phoenix_import_refactored.py --anonymize-file production_scan.csv --output test_scan.csv
```

### Command Options Quick Reference
| Option | Description | Example |
|--------|-------------|---------|
| `--file` | Process single file | `--file scan.csv` |
| `--folder` | Process folder | `--folder /scans/` |
| `--asset-type` | Asset type | `--asset-type INFRA` |
| `--anonymize` | Anonymize data | `--anonymize` |
| `--just-tags` | Only add tags | `--just-tags` |
| `--create-empty-assets` | Create assets with zero risk | `--create-empty-assets` |
| `--verify-import` | Verify imported data | `--verify-import` |
| `--anonymize-file` | Create anonymized copy | `--anonymize-file input.csv` |

## 🚀 Features

### Core Functionality
- **Multi-format Support**: Import from JSON and CSV files
- **Folder Processing**: Batch process entire directories
- **Asset Type Support**: INFRA, WEB, CLOUD, CONTAINER, REPOSITORY, CODE, BUILD
- **Flexible Data Mapping**: Intelligent mapping from various data formats to Phoenix structures

### Security & Privacy
- **Data Anonymization**: Scramble IP addresses and hostnames while preserving structure
- **Configurable Anonymization**: Reproducible results with seed values
- **Privacy-First Design**: No sensitive data logged or cached

### Tag Management
- **Advanced Tagging**: Apply tags during import or separately with `--just-tags`
- **YAML Configuration**: Flexible tag configuration with environment-specific tags
- **Post-Import Tagging**: Add tags to assets after successful import

### Enterprise Features
- **Robust Authentication**: Token-based authentication with automatic refresh
- **Error Handling**: Comprehensive error handling and logging
- **Batch Processing**: Configurable delays and timeout handling
- **Status Monitoring**: Real-time import status tracking

## 📋 Requirements

- Python 3.8+
- Required packages: `requests`, `pyyaml`
- Phoenix Security API credentials

## 🛠️ Installation

1. Install required packages:
```bash
pip install requests pyyaml
```

2. Copy configuration files:
```bash
cp config_refactored.ini config.ini
cp customization/tags_config.yaml customization/custom_tags.yaml
```

3. Configure your Phoenix API credentials in `config.ini`

## ⚙️ Configuration

**Default Configuration File**: `config_refactored.ini`
- If not found, falls back to: `config.ini` → `config_refactored EXAMPLE.ini`
- Use `--config` to specify a custom configuration file

### Phoenix API Configuration (`config.ini`)

```ini
[phoenix]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
api_base_url = https://api.poc1.appsecphx.io
scan_type = Tenable Scan
import_type = new
batch_delay = 10
```

### Tag Configuration (`customization/tags_config.yaml`)

```yaml
custom_data:
  - key: "environment"
    value: "production"
  - key: "team"
    value: "security"
```

## 🎯 Usage Examples

### Basic Usage

#### Process a Single CSV File
```bash
python phoenix_import_refactored.py --file data/nessus-import.csv --asset-type INFRA
```

#### Process a Single JSON File
```bash
python phoenix_import_refactored.py --file data/vulnerabilities.json --asset-type WEB
```

### Folder Processing

#### Process All Files in a Folder
```bash
python phoenix_import_refactored.py --folder /path/to/data --asset-type INFRA
```

#### Process Only JSON Files
```bash
python phoenix_import_refactored.py --folder /path/to/data --file-types json --asset-type CLOUD
```

#### Process Multiple File Types
```bash
python phoenix_import_refactored.py --folder /path/to/data --file-types json csv --asset-type CONTAINER
```

### Advanced Features

#### Data Anonymization
```bash
# Anonymize during import
python phoenix_import_refactored.py --file sensitive_data.csv --anonymize --asset-type INFRA

# Create anonymized copy of a file
python phoenix_import_refactored.py --anonymize-file sensitive_data.csv --output anonymized_data.csv
```

#### Tag Management
```bash
# Only add tags to existing assets (no import)
python phoenix_import_refactored.py --file data.json --just-tags

# Create assets even if no vulnerabilities found (asset inventory)
python phoenix_import_refactored.py --file clean_scan.csv --create-empty-assets

# Verify import success by checking assets and vulnerabilities in Phoenix
python phoenix_import_refactored.py --file data.csv --asset-type INFRA --verify-import

# Use custom tag configuration
python phoenix_import_refactored.py --file data.csv --tag-file custom_tags.yaml --asset-type WEB
```

#### Configuration Override
```bash
# Override configuration via command line
python phoenix_import_refactored.py \
  --file data.csv \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_SECRET \
  --api-url https://api.demo.appsecphx.io \
  --asset-type INFRA
```

## 📊 Asset Types and Data Mapping

### Infrastructure Assets (INFRA)
**Required Fields**: `ip` OR `hostname`
**Optional Fields**: `fqdn`, `netbios`, `macAddress`, `network`, `os`

**CSV Mapping**:
- `IP Address` → `ip`
- `DNS Name` → `hostname`, `fqdn`
- `NetBIOS Name` → `netbios`
- `MAC Address` → `macAddress`

### Web Assets (WEB)
**Required Fields**: `ip` OR `fqdn`

**CSV Mapping**:
- `IP Address` → `ip`
- `DNS Name` → `fqdn`

### Cloud Assets (CLOUD)
**Required Fields**: `providerType`, `providerAccountId`
**Optional Fields**: `region`, `vpc`, `subnet`, `providerAccountName`

**JSON Mapping**:
- `provider_type` → `providerType`
- `account_id` → `providerAccountId`
- `region` → `region`

### Container/Repository/Code/Build Assets
**Asset-Specific Requirements**:
- **REPOSITORY**: `repository` (required)
- **BUILD**: `buildFile` (required)
- **CONTAINER**: `dockerfile` (required)
- **CODE**: `scannerSource` (required)

## 🔒 Data Anonymization

The tool provides intelligent data anonymization that preserves data structure while protecting sensitive information:

### IP Address Anonymization
- **Private IPs**: Maintains private IP ranges (10.x.x.x → 10.y.y.y)
- **Public IPs**: Maps to different private ranges
- **IPv6**: Supports IPv6 anonymization
- **Consistency**: Same input always produces same anonymized output

### Hostname Anonymization
- **Structure Preservation**: `server.domain.com` → `host-abc123.domain.com`
- **Hash-Based**: Uses MD5 hash for consistent anonymization
- **Domain Retention**: Optionally preserves domain structure

### Example
```bash
# Create anonymized version with seed for reproducibility
python phoenix_import_refactored.py \
  --anonymize-file production_scan.csv \
  --output anonymized_scan.csv \
  --seed 12345
```

## 🔍 Import Verification

The tool provides comprehensive import verification to ensure data integrity and confirm successful imports.

### Verification Features
- **Asset Verification**: Confirms all imported assets exist in Phoenix
- **Vulnerability Verification**: Validates all vulnerabilities were created for each asset
- **Success Rate Reporting**: Provides detailed statistics on verification results
- **Error Reporting**: Identifies and reports any missing or failed imports

### Usage
```bash
# Verify import after completion
python phoenix_import_refactored.py --file scan_data.csv --asset-type INFRA --verify-import

# Verification output example:
# ✅ Successfully processed scan_data.csv
#    Assessment: scan_data_20250930_143022
#    Assets: 25
#    Vulnerabilities: 147
#    Request ID: abc-123-def
#    🔍 Verification Results:
#       Assets: 25/25 (100.0%)
#       Vulnerabilities: 147/147 (100.0%)
```

### Verification Process
1. **Asset Retrieval**: Uses `GET /v1/assets/<asset-id>` to verify each imported asset
2. **Vulnerability Query**: Uses `POST /v1/vulnerabilities` to check vulnerabilities per asset
3. **Data Matching**: Compares expected vs. actual counts for comprehensive validation
4. **Error Tracking**: Reports any assets or vulnerabilities that couldn't be verified

## 🏷️ Tag Management

### Tag Application Modes

1. **During Import**: Tags applied as part of asset creation
2. **Post-Import**: Tags added after successful import using Phoenix API
3. **Tag-Only Mode**: Only add tags to existing assets (no import)

### Tag Configuration Structure

```yaml
# Basic tags applied to all assets
custom_data:
  - key: "team"
    value: "security"

# Environment-specific tags
environment_tags:
  production:
    - key: "criticality"
      value: "high"

# Asset type specific tags
asset_type_tags:
  INFRA:
    - key: "scan-type"
      value: "network-scan"
```

### Tag-Only Operations

Use `--just-tags` to only add tags without importing data:

```bash
# Add tags to assets identified in the data file
python phoenix_import_refactored.py --file asset_list.json --just-tags
```

## 📈 Monitoring and Logging

### Logging Configuration
- **File Logging**: All operations logged to `phoenix_import.log`
- **Console Output**: Real-time progress and status updates
- **Log Levels**: DEBUG, INFO, WARNING, ERROR

### Status Tracking
- **Import Progress**: Real-time status updates during import
- **Batch Processing**: Progress tracking for folder operations
- **Error Reporting**: Detailed error messages and troubleshooting info

### Example Output
```
2025-09-30 10:15:23 - INFO - Loading CSV data from data/nessus-import.csv
2025-09-30 10:15:24 - INFO - Loaded 1500 records from CSV file
2025-09-30 10:15:25 - INFO - Mapping 1500 CSV records to INFRA assets
2025-09-30 10:15:26 - INFO - Created 45 unique assets
2025-09-30 10:15:27 - INFO - Importing 45 assets to Phoenix...
2025-09-30 10:15:28 - INFO - Successfully initiated import with request ID: abc-123-def
2025-09-30 10:15:29 - INFO - Import status: TRANSLATING
2025-09-30 10:15:39 - INFO - Import status: IMPORTED
2025-09-30 10:15:39 - INFO - Import completed successfully!
```

## 🔧 Troubleshooting

### Common Issues

#### Authentication Errors
```
❌ Failed to obtain access token: 401 - Unauthorized
```
**Solution**: Verify `client_id` and `client_secret` in configuration

#### File Format Issues
```
❌ No suitable data loader found for file: data.txt
```
**Solution**: Ensure file has `.csv` or `.json` extension

#### Missing Required Fields
```
❌ No assets created from data
```
**Solution**: Verify data contains required fields for the specified asset type

#### Import Timeout
```
⚠️ Import timed out after 3600 seconds
```
**Solution**: Increase `timeout` value in configuration or check Phoenix API status

### Debug Mode
Enable debug logging for detailed troubleshooting:
```bash
python phoenix_import_refactored.py --file data.csv --log-level DEBUG
```

### Configuration Validation
The tool validates configuration on startup and provides clear error messages for missing or invalid settings.

## 🔄 Migration from Legacy Scripts

### Key Differences
1. **Modular Architecture**: Separate classes for data loading, mapping, and API interaction
2. **Enhanced Error Handling**: Comprehensive error handling and recovery
3. **Flexible Input**: Support for various data formats and structures
4. **Advanced Features**: Anonymization, tag management, folder processing

### Migration Steps
1. Update configuration file format
2. Adjust command-line arguments (see examples above)
3. Update tag configuration to YAML format
4. Test with small datasets before full migration

## 📚 API Reference

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--file` | Process single file | `--file data.csv` |
| `--folder` | Process folder | `--folder /path/to/data` |
| `--file-types` | File types to process | `--file-types json csv` |
| `--asset-type` | Asset type | `--asset-type INFRA` |
| `--anonymize` | Anonymize data | `--anonymize` |
| `--just-tags` | Only add tags | `--just-tags` |
| `--create-empty-assets` | Create assets with zero risk | `--create-empty-assets` |
| `--verify-import` | Verify imported data | `--verify-import` |
| `--tag-file` | Tag configuration | `--tag-file tags.yaml` |
| `--config` | Configuration file | `--config config_refactored.ini` |
| `--log-level` | Logging level | `--log-level DEBUG` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PHOENIX_CLIENT_ID` | Phoenix API client ID |
| `PHOENIX_CLIENT_SECRET` | Phoenix API client secret |
| `PHOENIX_API_BASE_URL` | Phoenix API base URL |

## 🤝 Contributing

1. Follow PEP 8 style guidelines
2. Add comprehensive docstrings
3. Include unit tests for new features
4. Update documentation for changes

## 📄 License

This tool is provided as-is for use with Phoenix Security platform integration.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files for detailed error information
3. Verify configuration and data format requirements
4. Contact your Phoenix Security administrator for API-related issues
