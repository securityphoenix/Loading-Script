# Changelog

All notable changes to the Phoenix Scanner Service will be documented in this file.

## [1.1.0] - 2025-11-18

### Added
- **Phoenix Native CSV Support**: Added 5 new Phoenix CSV scanner types to API schema
  - `PHOENIX_CSV` - Generic Phoenix CSV with auto-detection
  - `PHOENIX_CSV_INFRA` - Phoenix CSV for INFRA assets
  - `PHOENIX_CSV_CLOUD` - Phoenix CSV for CLOUD assets
  - `PHOENIX_CSV_WEB` - Phoenix CSV for WEB assets
  - `PHOENIX_CSV_SOFTWARE` - Phoenix CSV for SOFTWARE/BUILD assets
- **Rapid7 Integration**: Added Rapid7 CSV export scanner support
  - `RAPID7_CSV` - Rapid7 vulnerability report CSV format
- Updated `ScannerType` enum in `app/models/schemas.py` with 6 new scanner types
- Enhanced OpenAPI/Swagger documentation with new scanner types
- API now accepts custom asset name parameter for CSV imports
- API now supports forced CSV import method flag

### Changed
- Total supported scanners in API: **206+** (was 200+)
- Enhanced scanner type validation in API endpoints
- Improved CSV file handling in worker processes
- Updated API documentation with Phoenix CSV examples

### Fixed
- Enhanced CSV parsing for Phoenix native format
- Improved error handling for malformed CSV files
- Better validation messages for CSV-specific scanner types

### Documentation
- Updated README.md with new scanner types
- Added Phoenix CSV and Rapid7 CSV examples to API documentation
- Enhanced troubleshooting guide with CSV import scenarios

### API Schema Changes
```python
# app/models/schemas.py - New ScannerType enum values
class ScannerType(str, Enum):
    # ... existing scanner types ...
    PHOENIX_CSV = "phoenix_csv"
    PHOENIX_CSV_INFRA = "phoenix_csv_infra"
    PHOENIX_CSV_CLOUD = "phoenix_csv_cloud"
    PHOENIX_CSV_WEB = "phoenix_csv_web"
    PHOENIX_CSV_SOFTWARE = "phoenix_csv_software"
    RAPID7_CSV = "rapid7_csv"
```

### Upgrade Notes
- No breaking changes
- Existing scanner types remain fully functional
- New scanner types are automatically available via API
- No database schema changes required
- No container rebuild required (unless updating to latest)

### Performance
- CSV import performance optimized for large files (1000+ vulnerabilities)
- Improved memory usage for CSV parsing
- Enhanced batching for Phoenix CSV imports

## [1.0.0] - 2025-11-12

### Added
- Initial release of Phoenix Scanner Service
- REST API for scanner file upload and processing
- Real-time WebSocket streaming for logs and status updates
- Queue-based processing with Redis and Celery
- Docker containerization for easy deployment
- Webhook support for status notifications
- API key authentication
- Monitoring via Flower dashboard
- Support for 200+ scanner types including:
  - Container scanners (Trivy, Grype, Aqua, Sysdig)
  - Build/SCA scanners (npm audit, pip-audit, Snyk, BlackDuck)
  - Cloud scanners (Prowler, Inspector, Scout Suite)
  - Code/Secret scanners (SonarQube, TruffleHog, Checkmarx)
  - Web scanners (Burp Suite, Contrast, TestSSL)
  - Infrastructure scanners (Qualys, Tenable, Kubeaudit)

### Features
- Asynchronous background processing
- Intelligent batching for large payloads
- Automatic data validation and fixing
- Health checks and monitoring
- Horizontal scaling support
- PostgreSQL and SQLite database support
- Comprehensive logging
- Error recovery mechanisms

### Security
- API key authentication via X-API-Key header
- Support for Phoenix Platform credentials
- SSL/TLS support
- Configurable authentication (can be disabled for internal use)

### Documentation
- Complete API reference
- User guide with examples
- Architecture documentation
- Deployment guide
- Configuration guide
- Troubleshooting guide

### Deployment
- Docker Compose for orchestration
- Production-ready configuration
- Environment-based configuration
- Makefile for common operations
- Health check endpoints
- Graceful shutdown handling

## [Unreleased]

### Planned Features
- GraphQL API support
- Advanced analytics dashboard
- Scheduled imports
- Custom translator plugins
- S3/blob storage integration
- Multi-tenant support
- Rate limiting per API key
- Import history and audit logs
- Automatic scanner version detection
- Scanner result caching
- Batch API for multiple file uploads
- Advanced filtering and search
- Export functionality for processed data


