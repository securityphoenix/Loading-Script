# Debug and Error Logging Guide

## 🔍 Enhanced Debug and Error Logging Features

Both Phoenix Security import tools now include comprehensive debug and error logging capabilities for troubleshooting and monitoring.

## 🚀 New Command Line Options

### `--debug`
Enables comprehensive debug mode with detailed logging:
- **HTTP Request/Response Logging**: Full details of all API calls
- **Data Transformation Logging**: Step-by-step data processing details
- **File Processing Logging**: Detailed file parsing information
- **Enhanced Error Tracebacks**: Full stack traces for debugging

### `--error-log <filename>`
Saves all errors to a dedicated error log file:
- **Structured Error Reports**: Detailed error information with context
- **File-Specific Error Tracking**: Errors grouped by file being processed
- **Operation Context**: Which operation was being performed when error occurred
- **Timestamp and Traceback**: Full error details for troubleshooting

## 📋 Usage Examples

### Basic Phoenix Import Tool

```bash
# Enable debug mode (creates debug/YYYYMMDD/HHMM/ structure)
python phoenix_import_refactored.py --file scan.csv --asset-type INFRA --debug

# Save errors to errors/ directory (auto-named if not specified)
python phoenix_import_refactored.py --file scan.csv --asset-type INFRA --error-log errors/custom_errors.log

# Both debug and error logging (uses default directories)
python phoenix_import_refactored.py --file scan.csv --asset-type INFRA --debug

# Debug mode with folder processing
python phoenix_import_refactored.py --folder /scans/ --asset-type INFRA --debug
```

### Multi-Scanner Import Tool

```bash
# Debug mode with auto-detection
python phoenix_multi_scanner_import.py --file scan.json --debug

# Error logging for batch processing
python phoenix_multi_scanner_import.py --folder /scans/ --error-log scanner_errors.log

# Full debug and error logging
python phoenix_multi_scanner_import.py --file aqua_scan.json --scanner aqua --debug --error-log aqua_errors.log

# Debug mode with verification
python phoenix_multi_scanner_import.py --file scan.csv --scanner tenable --debug --verify-import --error-log tenable_errors.log
```

## 📁 Organized Log Directory Structure

The tools now automatically create and organize logs in a structured directory hierarchy:

```
project_root/
├── logs/                           # Main execution logs
│   ├── phoenix_import_refactored_20250930_2230.log
│   └── phoenix_multi_scanner_20250930_2235.log
├── errors/                         # Error logs and reports
│   ├── phoenix_import_refactored_errors_20250930_2230.log
│   ├── phoenix_multi_scanner_errors_20250930_2235.log
│   └── error_report_20250930_223015.json
└── debug/                          # Debug logs organized by date and run
    └── 20250930/                   # Date folder (YYYYMMDD)
        ├── 2230/                   # Run ID folder (HHMM)
        │   ├── phoenix_import_refactored_debug.log
        │   ├── request_223001_authentication.json
        │   ├── response_223002_authentication.json
        │   ├── file_processing_223005_scan_csv_CSV_Load_Start.json
        │   └── file_processing_223010_scan_csv_CSV_Load_Complete.json
        └── 2235/                   # Another run
            ├── phoenix_multi_scanner_debug.log
            ├── request_223501_import_test-scan.json
            └── response_223502_import_test-scan.json
```

### Directory Structure Details

#### `logs/` Directory
- **Purpose**: Main execution logs for monitoring and troubleshooting
- **Naming**: `{tool_name}_{YYYYMMDD}_{HHMM}.log`
- **Content**: Standard INFO level logging with detailed function context
- **Always Created**: Yes, for every run

#### `errors/` Directory  
- **Purpose**: Error-specific logs and comprehensive error reports
- **Naming**: 
  - Error logs: `{tool_name}_errors_{YYYYMMDD}_{HHMM}.log`
  - Error reports: `error_report_{YYYYMMDD}_{HHMMSS}.json`
- **Content**: Detailed error information with context and stack traces
- **Created When**: Errors occur or `--error-log` is specified

#### `debug/` Directory
- **Purpose**: Detailed debug information organized by date and run
- **Structure**: `debug/{YYYYMMDD}/{HHMM}/`
- **Content**: 
  - Main debug log: `{tool_name}_debug.log`
  - Individual debug files for requests, responses, file processing
- **Created When**: `--debug` flag is used

## 🔍 Debug Logging Features

### HTTP Request/Response Logging
```
🌐 HTTP REQUEST [authentication]
   Method: GET
   URL: https://api.demo.appsecphx.io/v1/auth/access_token
   Headers: {
     "Authorization": "Bearer ***MASKED***"
   }

📡 HTTP RESPONSE [authentication]
   Status Code: 200
   Status Text: OK
   Headers: {"content-type": "application/json", ...}
   Response Body: {"token": "...", ...}
```

### Data Transformation Logging
```
🔄 DATA TRANSFORMATION [assessment: test-scan]
   Stage: Asset Conversion
   Input Count: 25
   Output Count: 25
```

### File Processing Logging
```
📁 FILE PROCESSING
   File: /path/to/scan.csv
   Operation: CSV Load Complete
   Details: {
     "total_rows": 1500,
     "delimiter": ",",
     "fields": ["IP Address", "DNS Name", "Plugin Name", ...]
   }
```

## ❌ Error Tracking Features

### Structured Error Information
```json
{
  "timestamp": "2025-09-30T22:30:15.123456",
  "file_path": "/path/to/scan.csv",
  "operation": "import_assets",
  "context": "Asset Import",
  "error_type": "ConnectionError",
  "error_message": "Failed to connect to Phoenix API",
  "traceback": "Traceback (most recent call last):\n..."
}
```

### Error Summary Report
```
📊 Error Summary:
   Total Errors: 3
   Files with Errors: 2
   Error Types: ConnectionError, ValidationError
```

### Per-File Error Tracking
- Errors grouped by file being processed
- Operation context for each error
- Full traceback information (in debug mode)

## 🛠️ Troubleshooting Workflows

### Authentication Issues
```bash
# Debug authentication problems
python phoenix_import_refactored.py --file test.csv --debug --error-log auth_errors.log

# Check debug log for:
# - HTTP request details
# - Response status codes
# - Token expiration issues
```

### Data Processing Issues
```bash
# Debug data parsing problems
python phoenix_multi_scanner_import.py --file scan.json --debug --error-log parse_errors.log

# Check debug log for:
# - File format detection
# - Data transformation steps
# - Field mapping issues
```

### Large File Processing
```bash
# Monitor large file processing
python phoenix_import_refactored.py --folder /large_scans/ --debug --error-log batch_errors.log

# Debug log shows:
# - Progress indicators every 1000 rows
# - Memory usage patterns
# - Processing bottlenecks
```

## 📊 Error Report Analysis

### Automatic Error Reports
When errors occur, detailed JSON reports are automatically generated:

```json
{
  "session_info": {
    "start_time": "2025-09-30T22:25:00.000000",
    "end_time": "2025-09-30T22:30:15.123456",
    "duration": "0:05:15.123456"
  },
  "summary": {
    "total_errors": 5,
    "files_with_errors": 3,
    "error_types": ["ConnectionError", "ValidationError"],
    "session_duration": "0:05:15.123456"
  },
  "detailed_errors": [...],
  "file_errors": {
    "scan1.csv": [...],
    "scan2.json": [...]
  }
}
```

### Error Pattern Analysis
- **Connection Errors**: Network or authentication issues
- **Validation Errors**: Data format or content issues
- **Processing Errors**: File parsing or transformation issues
- **API Errors**: Phoenix API response issues

## 🎯 Best Practices

### Development and Testing
```bash
# Always use debug mode during development
python phoenix_import_refactored.py --file test.csv --debug --error-log dev_errors.log
```

### Production Monitoring
```bash
# Use error logging for production monitoring
python phoenix_multi_scanner_import.py --folder /prod_scans/ --error-log prod_errors.log
```

### Batch Processing
```bash
# Monitor large batch operations
python phoenix_multi_scanner_import.py --folder /daily_scans/ --debug --error-log daily_errors.log
```

### Performance Analysis
```bash
# Analyze performance with debug logging
python phoenix_import_refactored.py --folder /large_data/ --debug --log-level DEBUG
```

## 🔧 Integration with Monitoring Systems

### Log File Monitoring
- Monitor error log files with log aggregation systems
- Set up alerts for specific error patterns
- Track error rates and trends over time

### Automated Error Reporting
- Parse JSON error reports for automated analysis
- Integrate with incident management systems
- Generate daily/weekly error summaries

### Performance Monitoring
- Track processing times from debug logs
- Monitor API response times
- Identify performance bottlenecks

## 📈 Troubleshooting Common Issues

### Authentication Failures
**Symptoms**: 401 Unauthorized errors
**Debug Command**: `--debug --error-log auth_debug.log`
**Look For**: 
- Token request/response details
- Credential validation
- API endpoint accessibility

### Data Format Issues
**Symptoms**: Parsing errors, no assets created
**Debug Command**: `--debug --error-log format_debug.log`
**Look For**:
- File format detection results
- Field mapping details
- Data transformation logs

### Network Connectivity
**Symptoms**: Connection timeouts, network errors
**Debug Command**: `--debug --error-log network_debug.log`
**Look For**:
- HTTP request timing
- Response status codes
- Network-level errors

### Large File Processing
**Symptoms**: Memory issues, slow processing
**Debug Command**: `--debug --log-level DEBUG`
**Look For**:
- Progress indicators
- Memory usage patterns
- Processing bottlenecks

This comprehensive debug and error logging system provides complete visibility into the import process, making troubleshooting and monitoring significantly easier and more effective.
