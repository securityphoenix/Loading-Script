# Phoenix Scanner - Test Commands Quick Reference

## 🚀 Quick Start

### 1. Start Service
```bash
cd ../phoenix-scanner-service
docker-compose up -d
curl http://localhost:8000/api/v1/health
```

### 2. Run Quick Test (30 seconds)
```bash
cd ../unit_tests
python3 quick_test.py
```

### 3. Run Full Tests (5-10 minutes)
```bash
python3 run_tests.py
```

## 📋 All Commands

### Quick Tests
```bash
# Fastest smoke test
python3 quick_test.py
```

### Individual Tests
```bash
# Run all individual tests
python3 run_tests.py --tests-only

# With verbose output
python3 run_tests.py --tests-only --verbose
```

### Batch Tests
```bash
# Run batch tests only
python3 run_tests.py --batch-only
```

### Full Test Suite
```bash
# All tests (individual + batch)
python3 run_tests.py

# With verbose output
python3 run_tests.py --verbose

# Custom config
python3 run_tests.py --config my_config.yaml
```

### Automated Test Runner
```bash
# Complete test with service validation
./run_all_tests.sh
```

## 🔍 Check Results

### View Reports
```bash
# Latest JSON report
cat reports/test_report_*.json

# With formatting (requires jq)
cat reports/test_report_*.json | jq '.'

# Summary only
cat reports/test_report_*.json | jq '{total: .total_tests, passed: .passed, failed: .failed}'
```

### Check Service
```bash
# Health check
curl http://localhost:8000/api/v1/health

# Service logs
cd ../phoenix-scanner-service
docker-compose logs -f api
docker-compose logs -f worker
```

## 🛠️ Troubleshooting Commands

### Service Issues
```bash
# Restart service
cd ../phoenix-scanner-service
docker-compose restart

# View logs
docker-compose logs --tail=50 -f

# Check containers
docker-compose ps
```

### Test Issues
```bash
# Run with verbose mode
python3 run_tests.py --verbose

# Check test files
ls -la test_data/*/

# Verify client
python3 -c "import sys; sys.path.insert(0, '../phoenix-scanner-client'); from phoenix_client import PhoenixScannerClient; print('OK')"
```

## 📊 CI/CD Examples

### GitHub Actions
```yaml
- run: cd unit_tests && python3 run_tests.py
```

### Jenkins
```groovy
sh 'cd unit_tests && python3 run_tests.py'
```

### Azure DevOps
```yaml
- script: cd unit_tests && python3 run_tests.py
```

## ⚡ One-Liners

```bash
# Complete test from scratch
cd ../phoenix-scanner-service && docker-compose up -d && sleep 5 && cd ../unit_tests && ./run_all_tests.sh

# Quick validation
python3 quick_test.py && echo "✓ Tests passed" || echo "✗ Tests failed"

# Run tests and check report
python3 run_tests.py && cat reports/test_report_*.json | jq '.passed'
```

---

For detailed documentation, see README.md
