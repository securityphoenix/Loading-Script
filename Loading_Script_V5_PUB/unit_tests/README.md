# Phoenix Scanner - Unit Tests

Comprehensive test suite for the Phoenix Scanner Client and Service covering multiple scanner types: SAST, Infrastructure, Container, Web, and Cloud security scanners.

## 📦 Test Coverage

### Scanner Types Tested

1. **SAST (Static Application Security Testing)**
   - Checkmarx: XML reports with multiple findings and aggregated results

2. **Infrastructure**
   - Qualys: CSV and XML reports
   - Nessus/Tenable: XML reports with vulnerabilities

3. **Container Security**
   - Trivy: JSON reports with various statuses and CVSS scoring

4. **Web Application Security**
   - Acunetix: JSON reports with single/multiple findings

5. **Cloud Security**
   - AWS Prowler: JSON and CSV reports

### Test Files Included

```
unit_tests/
├── test_data/
│   ├── checkmarx/                # SAST test files
│   │   ├── multiple_findings_same_file_different_line_number.xml
│   │   └── many_aggregated_findings.xml
│   ├── qualys/                   # Infrastructure test files
│   │   ├── Qualys_Sample_Report.csv
│   │   └── Qualys_Sample_Report.xml
│   ├── nessus/                   # Infrastructure test files
│   │   ├── nessus_many_vuln.xml
│   │   ├── nessus_with_cvssv3.xml
│   │   └── tenable_many_vuln.csv
│   ├── trivy/                    # Container test files
│   │   ├── all_statuses.json
│   │   ├── cvss_severity_source.json
│   │   └── issue_10991.json
│   ├── acunetix/                 # Web test files
│   │   ├── acunetix360_many_findings.json
│   │   ├── acunetix360_one_finding.json
│   │   └── acunetix360_multiple_cwe.json
│   └── prowler/                  # Cloud test files
│       ├── many_vuln.json
│       └── many_vuln.csv
├── reports/                      # Test reports (generated)
├── logs/                         # Test logs (generated)
├── test_config.yaml             # Test configuration
├── run_tests.py                  # Main test runner
├── quick_test.py                 # Quick smoke test
└── README.md                     # This file
```

## 🚀 Quick Start

### Prerequisites

1. **Start the Phoenix Scanner Service**:
   ```bash
   cd ../phoenix-scanner-service
   docker-compose up -d
   ```

2. **Verify service is running**:
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

3. **Install dependencies** (if not already installed):
   ```bash
   cd ../phoenix-scanner-client
   pip install -r requirements.txt
   ```

### Run Quick Smoke Test (30 seconds)

```bash
cd unit_tests
python3 quick_test.py
```

This runs a fast validation test with one file from each scanner category.

### Run Full Test Suite (5-10 minutes)

```bash
python3 run_tests.py
```

This runs all configured test cases with full validation.

## 📋 Test Commands

### 1. Quick Smoke Test

**Purpose**: Fast validation that service is running and responsive

```bash
python3 quick_test.py
```

**Output**: Status for 5 quick tests (one per scanner type)

### 2. Full Test Suite

**Purpose**: Comprehensive testing of all scanner types and configurations

```bash
python3 run_tests.py
```

**Output**: Detailed results for all test cases + JSON report

### 3. Specific Test Types

Run only individual tests (skip batch tests):
```bash
python3 run_tests.py --tests-only
```

Run only batch tests:
```bash
python3 run_tests.py --batch-only
```

### 4. Verbose Mode

```bash
python3 run_tests.py --verbose
```

### 5. Custom Configuration

```bash
python3 run_tests.py --config my_custom_config.yaml
```

## ⚙️ Configuration

### Test Configuration File

Edit `test_config.yaml` to customize tests:

```yaml
# API Configuration
api_url: http://localhost:8000
api_key: test-api-key-12345

# Optional: Phoenix Platform credentials
# phoenix_client_id: your-client-id
# phoenix_client_secret: your-secret
# phoenix_api_url: https://api.demo.appsecphx.io

# Test Settings
test_settings:
  timeout: 300
  concurrent_uploads: 2
  wait_for_completion: true
  enable_verbose: true

# Test Cases
test_cases:
  - name: "SAST - Checkmarx"
    scanner_type: checkmarx
    asset_type: CODE
    file_path: test_data/checkmarx/multiple_findings.xml
    expected_status: completed
```

### Adding New Test Cases

1. Copy your test file to appropriate `test_data/` subdirectory
2. Add test case to `test_config.yaml`:

```yaml
test_cases:
  - name: "My New Test"
    scanner_type: scanner_name
    asset_type: ASSET_TYPE
    import_type: new
    file_path: test_data/scanner_name/my_test_file.json
    expected_status: completed
    min_findings: 1
```

## 📊 Test Reports

### Report Locations

- **JSON Reports**: `reports/test_report_YYYYMMDD_HHMMSS.json`
- **Console Output**: Real-time progress and summary

### Report Format

```json
{
  "timestamp": "20251112_120000",
  "total_tests": 15,
  "passed": 14,
  "failed": 1,
  "duration": 285.42,
  "results": [
    {
      "name": "SAST - Checkmarx",
      "success": true,
      "message": "Completed successfully",
      "duration": 12.5,
      "job_id": "abc123..."
    }
  ]
}
```

## 🔍 Troubleshooting

### Service Not Running

**Error**: `Connection refused to http://localhost:8000`

**Solution**:
```bash
cd ../phoenix-scanner-service
docker-compose up -d
curl http://localhost:8000/api/v1/health
```

### Authentication Failed

**Error**: `401 Unauthorized`

**Solution**: Check `api_key` in `test_config.yaml` matches service configuration

### Test File Not Found

**Error**: `Test file not found: test_data/...`

**Solution**: Ensure test files are copied to `test_data/` directories

### Worker Not Processing

**Error**: Job stuck in "queued" status

**Solution**:
```bash
cd ../phoenix-scanner-service
docker-compose logs worker
docker-compose restart worker
```

### Timeout Errors

**Error**: `Job did not complete within 300 seconds`

**Solution**: Increase timeout in `test_config.yaml`:
```yaml
test_settings:
  timeout: 600  # 10 minutes
```

## 🧪 Test Scenarios

### Scenario 1: Verify Service Health

```bash
python3 quick_test.py
```

**Expected**: All 5 tests pass

### Scenario 2: Test All Scanner Types

```bash
python3 run_tests.py --tests-only
```

**Expected**: 15+ tests pass

### Scenario 3: Test Batch Processing

```bash
python3 run_tests.py --batch-only
```

**Expected**: Batch test completes with multiple files processed

### Scenario 4: Integration Test

```bash
# Start service
cd ../phoenix-scanner-service
docker-compose up -d

# Wait for service
sleep 5

# Run tests
cd ../unit_tests
python3 run_tests.py

# Check results
cat reports/test_report_*.json | jq '.passed'
```

## 🔧 Advanced Usage

### Run Specific Test

Edit `test_config.yaml` and comment out unwanted tests, then run:
```bash
python3 run_tests.py
```

### Parallel Testing

The test runner supports concurrent uploads via configuration:
```yaml
test_settings:
  concurrent_uploads: 5  # Process up to 5 files simultaneously
```

### CI/CD Integration

#### GitHub Actions

```yaml
- name: Run Phoenix Scanner Tests
  run: |
    cd unit_tests
    python3 run_tests.py --verbose
  env:
    PHOENIX_SCANNER_API_URL: http://localhost:8000
    PHOENIX_SCANNER_API_KEY: ${{ secrets.API_KEY }}
```

#### Jenkins

```groovy
stage('Test') {
    steps {
        sh '''
            cd unit_tests
            python3 run_tests.py
        '''
    }
}
```

#### Azure DevOps

```yaml
- script: |
    cd unit_tests
    python3 run_tests.py
  displayName: 'Run Tests'
```

## 📈 Performance Benchmarks

Expected test durations (with service running locally):

| Test Type | Files | Expected Duration |
|-----------|-------|-------------------|
| Quick Test | 5 | 30-60 seconds |
| Individual Tests | 15 | 5-10 minutes |
| Batch Tests | 5 | 2-3 minutes |
| Full Suite | 20 | 8-13 minutes |

*Note: Durations depend on file sizes and whether `wait_for_completion` is enabled.*

## 🎯 Success Criteria

Tests are considered successful if:

- ✅ Service health check passes
- ✅ File uploads complete without errors
- ✅ Jobs reach expected status (typically "completed")
- ✅ No critical exceptions occur
- ✅ Reports are generated successfully

## 📚 Additional Resources

- [Client Documentation](../phoenix-scanner-client/README.md)
- [Service Documentation](../phoenix-scanner-service/README.md)
- [Integration Guide](../phoenix-scanner-client/INTEGRATION_GUIDE.md)
- [Supported Scanners](../scanner_list_actual.txt)

## 🆘 Getting Help

If tests fail:

1. **Check service logs**:
   ```bash
   cd ../phoenix-scanner-service
   docker-compose logs -f
   ```

2. **Verify configuration**:
   ```bash
   cat test_config.yaml
   ```

3. **Run with verbose mode**:
   ```bash
   python3 run_tests.py --verbose
   ```

4. **Check test reports**:
   ```bash
   cat reports/test_report_*.json
   ```

## 🔄 Continuous Testing

### Run tests automatically after code changes:

```bash
# Watch mode (requires entr or similar)
ls *.py | entr -r python3 run_tests.py
```

### Schedule periodic tests:

```bash
# Crontab example: Run tests daily at 2 AM
0 2 * * * cd /path/to/unit_tests && python3 run_tests.py
```

## ✅ Verification Commands

Quick verification checklist:

```bash
# 1. Service running?
curl http://localhost:8000/api/v1/health

# 2. Test files present?
ls -la test_data/*/

# 3. Client installed?
python3 -c "import sys; sys.path.insert(0, '../phoenix-scanner-client'); from phoenix_client import PhoenixScannerClient; print('OK')"

# 4. Configuration valid?
python3 -c "import yaml; print(yaml.safe_load(open('test_config.yaml'))['api_url'])"

# 5. Run quick test
python3 quick_test.py
```

---

**Version**: 1.0.0  
**Last Updated**: November 12, 2025  
**Status**: Production Ready ✅

For questions or issues, refer to the main documentation or check service logs.

