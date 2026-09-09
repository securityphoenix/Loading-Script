# Changelog

All notable changes to the Phoenix Scanner Client will be documented in this file.

## [1.1.0] - 2025-11-18

### Added
- **Phoenix Native CSV Support**: Added 5 new Phoenix CSV scanner types
  - `phoenix_csv` - Generic Phoenix CSV with auto-detection
  - `phoenix_csv_infra` - Phoenix CSV for INFRA assets
  - `phoenix_csv_cloud` - Phoenix CSV for CLOUD assets
  - `phoenix_csv_web` - Phoenix CSV for WEB assets
  - `phoenix_csv_software` - Phoenix CSV for SOFTWARE/BUILD assets
- **Rapid7 Integration**: Added Rapid7 CSV export scanner support
  - `rapid7_csv` - Rapid7 vulnerability report CSV format
- Updated `scanner_list_actual.txt` with 6 new scanner types
- Support for custom asset name override via API
- Support for forced CSV import method via API

### Changed
- Total supported scanners: **206+** (was 200+)
- Enhanced scanner validation to include new Phoenix and Rapid7 CSV types
- Improved scanner type auto-detection for CSV files

### Documentation
- Updated README.md with new scanner examples
- Added Phoenix CSV usage examples
- Enhanced troubleshooting section for CSV imports

## [1.0.0] - 2025-11-12

### Added
- Initial release of Phoenix Scanner Client
- Single file upload with `upload_single.py`
- Batch upload with `upload_batch.py`
- Folder upload with `upload_folder.py`
- Job status checking with `check_status.py`
- Real-time log streaming via WebSocket
- Progress tracking with rich terminal output
- Automatic retry logic with exponential backoff
- Scanner type validation against 200+ supported scanners
- Report generation in text, JSON, and HTML formats
- Configuration via YAML, environment variables, or CLI args
- CI/CD integrations:
  - GitHub Actions workflow
  - Jenkins pipeline
  - Azure DevOps pipeline
- Comprehensive documentation:
  - README.md with complete feature overview
  - USAGE_GUIDE.md with detailed examples
  - QUICKSTART.md for fast setup
- Test script for client validation
- Example configuration files

### Features
- **Scanner Auto-Detection**: Automatically detects scanner type from file content
- **Concurrent Uploads**: Upload multiple files simultaneously
- **Smart Batching**: Intelligent file batching for optimal performance
- **Exit Codes**: Proper exit codes for CI/CD integration
- **SSL Verification**: Configurable SSL certificate verification
- **Timeout Control**: Configurable timeouts for large files
- **Verbose Logging**: Detailed logging for debugging
- **Error Handling**: Comprehensive error messages and recovery

### Security
- API key authentication
- Support for Phoenix Platform credentials
- No hardcoded secrets
- Environment variable support
- SSL/TLS support

### Performance
- Concurrent uploads (configurable)
- Automatic retry with backoff
- Progress tracking
- Async support for WebSocket streams

### Compatibility
- Python 3.8+
- Works with Phoenix Scanner Service v1.0.0+
- Compatible with 200+ scanner types
- Cross-platform (Linux, macOS, Windows)

### Documentation
- Complete README with examples
- Detailed usage guide
- Quick start guide
- CI/CD integration examples
- Troubleshooting section
- API reference

## [Unreleased]

### Planned Features
- Async upload support for even faster batch processing
- Configurable retry strategies
- Advanced filtering for folder uploads
- Webhook support for completion notifications
- Enhanced reporting with charts
- Docker container for client
- Shell completion for CLI
- Interactive mode for manual uploads



