# Data Anonymization Utility - Comprehensive Guide

A powerful standalone utility for anonymizing sensitive data in CSV and JSON files while preserving data structure and relationships for testing and development.

## 🚀 Quick Start

### Essential Commands
```bash
# Anonymize single file
python data_anonymizer.py --file sensitive_data.csv --output anonymized_data.csv

# Anonymize entire folder
python data_anonymizer.py --folder /prod_scans/ --output-folder /test_scans/

# Reproducible anonymization with seed
python data_anonymizer.py --file data.csv --output anon.csv --seed 12345

# Export mappings for reuse
python data_anonymizer.py --file data.csv --output anon.csv --export-mappings mappings.json
```

### Command Options Quick Reference
| Option | Description | Example |
|--------|-------------|---------|
| `--file` | Input file to anonymize | `--file sensitive.csv` |
| `--folder` | Input folder to anonymize | `--folder /prod_data/` |
| `--output` | Output file (single file mode) | `--output anonymized.csv` |
| `--output-folder` | Output folder (folder mode) | `--output-folder /test_data/` |
| `--seed` | Random seed for reproducible results | `--seed 12345` |
| `--export-mappings` | Export anonymization mappings | `--export-mappings map.json` |
| `--field-mapping` | Custom field mapping file | `--field-mapping custom.json` |

## 🔒 Anonymization Features

### IP Address Anonymization
- **Structure Preservation**: Maintains network relationships and ranges
- **Private IP Handling**: Keeps private IPs in private ranges
- **Consistency**: Same input always produces same anonymized output

**Examples:**
```
10.0.1.100     → 10.245.123.87    (preserves 10.x.x.x range)
192.168.1.50   → 192.168.234.156  (preserves 192.168.x.x range)
203.0.113.45   → 203.0.87.123     (public IP → different range)
```

### Hostname Anonymization
- **Domain Preservation**: Maintains domain structure while anonymizing hostnames
- **Hash-Based**: Uses consistent hashing for reproducible results
- **Structure Retention**: Preserves meaningful domain hierarchies

**Examples:**
```
web-server.company.com     → host-abc123.company.com
db-01.internal.corp.net    → host-def456.internal.corp.net
mail.example.org           → host-789xyz.example.org
```

### Text Content Anonymization
- **Embedded IP Detection**: Finds and anonymizes IPs within text fields
- **Hostname Pattern Matching**: Identifies and anonymizes hostnames in descriptions
- **Selective Processing**: Only processes fields likely to contain sensitive data

## 📋 Detailed Command Options

### Input Options (Mutually Exclusive)

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `--file` | String | Single file to anonymize | `--file scan_results.csv` |
| `--folder` | String | Folder to anonymize recursively | `--folder /production_scans/` |

### Output Options

| Option | Type | Description | Default | Example |
|--------|------|-------------|---------|---------|
| `--output` | String | Output file for single file mode | Auto-generated | `--output anonymized_scan.csv` |
| `--output-folder` | String | Output folder for folder mode | `{input}_anonymized` | `--output-folder /test_data/` |

### Processing Options

| Option | Type | Values | Default | Description |
|--------|------|--------|---------|-------------|
| `--file-types` | List | `csv`, `json` | `['csv', 'json']` | File types to process |
| `--seed` | Integer | Any integer | Random | Random seed for reproducible results |
| `--no-preserve-domains` | Flag | - | False | Don't preserve domain structure |
| `--no-consistent-ranges` | Flag | - | False | Don't use consistent IP ranges |

### Mapping Options

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `--field-mapping` | String | Custom field mapping JSON file | `--field-mapping custom_fields.json` |
| `--export-mappings` | String | Export anonymization mappings | `--export-mappings mappings.json` |
| `--import-mappings` | String | Import existing mappings | `--import-mappings mappings.json` |

### Logging Options

| Option | Type | Values | Default | Description |
|--------|------|--------|---------|-------------|
| `--log-level` | String | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` | Logging verbosity |
| `--quiet` | Flag | - | False | Suppress console output |

## 💻 Usage Examples

### Basic Anonymization

```bash
# Anonymize single CSV file
python data_anonymizer.py --file production_scan.csv --output test_scan.csv

# Anonymize single JSON file
python data_anonymizer.py --file vulnerability_data.json --output anon_vulns.json

# Auto-generate output filename
python data_anonymizer.py --file sensitive_data.csv
# Creates: sensitive_data_anonymized.csv
```

### Folder Processing

```bash
# Anonymize entire folder
python data_anonymizer.py --folder /production_scans/ --output-folder /test_data/

# Process only CSV files
python data_anonymizer.py --folder /scans/ --output-folder /anon_scans/ --file-types csv

# Process only JSON files
python data_anonymizer.py --folder /api_exports/ --output-folder /test_exports/ --file-types json

# Process both CSV and JSON
python data_anonymizer.py --folder /mixed_data/ --output-folder /anon_data/ --file-types csv json
```

### Reproducible Anonymization

```bash
# Use seed for consistent results
python data_anonymizer.py --file data.csv --output anon1.csv --seed 12345
python data_anonymizer.py --file data.csv --output anon2.csv --seed 12345
# anon1.csv and anon2.csv will be identical

# Different seed produces different anonymization
python data_anonymizer.py --file data.csv --output anon3.csv --seed 67890
# anon3.csv will have different anonymized values
```

### Custom Field Mapping

```bash
# Create custom field mapping
cat > custom_fields.json << EOF
{
  "server_ip": "ip",
  "host_name": "hostname", 
  "machine_name": "hostname",
  "client_address": "ip"
}
EOF

# Use custom mapping
python data_anonymizer.py --file data.csv --output anon.csv --field-mapping custom_fields.json
```

### Mapping Export and Import

```bash
# Export mappings for reuse
python data_anonymizer.py --file prod_data.csv --output test_data.csv --export-mappings ip_mappings.json

# Reuse mappings for consistency across files
python data_anonymizer.py --file more_prod_data.csv --output more_test_data.csv --import-mappings ip_mappings.json

# This ensures the same IP addresses get the same anonymized values across files
```

### Advanced Options

```bash
# Don't preserve domain structure
python data_anonymizer.py --file data.csv --output anon.csv --no-preserve-domains

# Don't use consistent IP ranges
python data_anonymizer.py --file data.csv --output anon.csv --no-consistent-ranges

# Quiet mode for automation
python data_anonymizer.py --file data.csv --output anon.csv --quiet

# Debug mode for troubleshooting
python data_anonymizer.py --file data.csv --output anon.csv --log-level DEBUG
```

## 🔧 Configuration and Customization

### Custom Field Mapping

Create a JSON file to specify which fields contain IP addresses or hostnames:

**File:** `custom_field_mapping.json`
```json
{
  "server_address": "ip",
  "client_ip": "ip",
  "source_ip": "ip",
  "destination_ip": "ip",
  "machine_name": "hostname",
  "server_fqdn": "hostname",
  "dns_name": "hostname"
}
```

**Usage:**
```bash
python data_anonymizer.py --file data.csv --field-mapping custom_field_mapping.json
```

### Default Field Detection

The anonymizer automatically detects common field names:

**IP Address Fields:**
- `IP Address`, `ip`, `ip_address`, `host_ip`, `target_ip`, `source_ip`
- `destination_ip`, `client_ip`, `server_ip`, `remote_ip`, `local_ip`

**Hostname Fields:**
- `DNS Name`, `hostname`, `host_name`, `dns_name`, `fqdn`, `NetBIOS Name`
- `server_name`, `host`, `domain`, `computer_name`, `machine_name`

### Anonymization Settings

```bash
# Preserve domain structure (default)
python data_anonymizer.py --file data.csv --output anon.csv

# Don't preserve domains (flatten all hostnames)
python data_anonymizer.py --file data.csv --output anon.csv --no-preserve-domains

# Use consistent IP ranges (default)
python data_anonymizer.py --file data.csv --output anon.csv

# Use random IP ranges
python data_anonymizer.py --file data.csv --output anon.csv --no-consistent-ranges
```

## 📊 Anonymization Statistics

The tool provides detailed statistics after processing:

```
📊 Anonymization Statistics:
   Files processed: 5
   Records processed: 1,247
   IP addresses anonymized: 342
   Hostnames anonymized: 189
   Unique IP mappings: 87
   Unique hostname mappings: 45
   Seed used: 12345
```

### Exporting Statistics

```bash
# Export detailed mappings and statistics
python data_anonymizer.py --file data.csv --output anon.csv --export-mappings detailed_stats.json
```

**Exported JSON Structure:**
```json
{
  "seed": 12345,
  "ip_mappings": {
    "10.0.1.100": "10.245.123.87",
    "192.168.1.50": "192.168.234.156"
  },
  "hostname_mappings": {
    "web-server.company.com": "host-abc123.company.com",
    "db-01.internal.net": "host-def456.internal.net"
  },
  "statistics": {
    "files_processed": 1,
    "records_processed": 150,
    "ips_anonymized": 25,
    "hostnames_anonymized": 18
  }
}
```

## 🚀 Automation and Integration

### Bash Scripts

**Daily Anonymization Script:**
```bash
#!/bin/bash
DATE=$(date +%Y%m%d)
PROD_DIR="/production_scans/$DATE"
TEST_DIR="/test_data/$DATE"

python data_anonymizer.py \
  --folder "$PROD_DIR" \
  --output-folder "$TEST_DIR" \
  --seed "$DATE" \
  --export-mappings "/mappings/mapping_$DATE.json" \
  --quiet
```

**Consistent Anonymization Across Environments:**
```bash
#!/bin/bash
# Use same seed for consistency across test environments
SEED=12345

for env in staging dev qa; do
  python data_anonymizer.py \
    --folder "/prod_data/" \
    --output-folder "/test_data/$env/" \
    --seed $SEED
done
```

### Cron Jobs

```bash
# Anonymize production data daily at 2 AM
0 2 * * * /usr/bin/python3 /path/to/data_anonymizer.py --folder /prod_scans/daily/ --output-folder /test_data/daily/ --quiet

# Weekly full anonymization with mapping export
0 0 * * 0 /usr/bin/python3 /path/to/data_anonymizer.py --folder /prod_scans/weekly/ --output-folder /test_data/weekly/ --export-mappings /mappings/weekly_$(date +\%Y\%m\%d).json
```

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: Anonymize Test Data
  run: |
    python data_anonymizer.py \
      --folder ./production_exports/ \
      --output-folder ./test_data/ \
      --seed ${{ github.run_number }} \
      --export-mappings ./anonymization_mappings.json
```

**Jenkins Pipeline:**
```groovy
stage('Anonymize Data') {
    steps {
        sh '''
            python data_anonymizer.py \
              --folder production_data/ \
              --output-folder test_data/ \
              --seed ${BUILD_NUMBER}
        '''
    }
}
```

## 🔍 Troubleshooting

### Common Issues

**File Format Issues:**
```bash
# Error: Unsupported file type
python data_anonymizer.py --file data.txt --output anon.txt
# Solution: Use supported formats (.csv, .json)
python data_anonymizer.py --file data.csv --output anon.csv
```

**Memory Issues with Large Files:**
```bash
# For very large files, process in smaller batches
python data_anonymizer.py --folder /large_files/ --output-folder /anon_files/ --file-types csv
```

**Inconsistent Anonymization:**
```bash
# Use same seed for consistent results
python data_anonymizer.py --file data1.csv --output anon1.csv --seed 12345
python data_anonymizer.py --file data2.csv --output anon2.csv --seed 12345
```

### Debug Mode

```bash
# Enable debug logging for detailed information
python data_anonymizer.py --file data.csv --output anon.csv --log-level DEBUG
```

**Debug Output Example:**
```
2025-09-30 10:15:23 - DEBUG - Initializing anonymizer with seed: 12345
2025-09-30 10:15:23 - DEBUG - Processing CSV file: data.csv
2025-09-30 10:15:24 - DEBUG - Anonymizing IP: 10.0.1.100 → 10.245.123.87
2025-09-30 10:15:24 - DEBUG - Anonymizing hostname: web-server.com → host-abc123.com
2025-09-30 10:15:25 - INFO - Anonymized data saved to anon.csv
```

## 📈 Performance Guidelines

### File Size Recommendations

| File Size | Processing Time | Memory Usage | Recommendation |
|-----------|----------------|--------------|----------------|
| < 1MB | < 1 second | < 10MB | Direct processing |
| 1-10MB | 1-10 seconds | 10-50MB | Normal processing |
| 10-100MB | 10-60 seconds | 50-200MB | Monitor progress |
| > 100MB | 1+ minutes | 200MB+ | Consider splitting |

### Optimization Tips

```bash
# Process only necessary file types
python data_anonymizer.py --folder /data/ --file-types csv  # Skip JSON files

# Use quiet mode for better performance in automation
python data_anonymizer.py --folder /data/ --output-folder /anon/ --quiet

# Process files in parallel (manual approach)
python data_anonymizer.py --file data1.csv --output anon1.csv &
python data_anonymizer.py --file data2.csv --output anon2.csv &
wait
```

This comprehensive guide provides everything needed to effectively use the Data Anonymization Utility for creating secure test data from production security scans.
