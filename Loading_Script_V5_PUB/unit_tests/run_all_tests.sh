#!/bin/bash
#
# Phoenix Scanner - Comprehensive Test Runner
# Runs full test suite with service validation
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}    Phoenix Scanner - Comprehensive Test Suite${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo ""

# Step 1: Check if service is running
echo -e "${CYAN}Step 1: Checking Phoenix Scanner Service...${NC}"
if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Service is running"
else
    echo -e "${RED}✗${NC} Service is not running"
    echo -e "${YELLOW}Starting service...${NC}"
    
    cd ../phoenix-scanner-service
    docker-compose up -d
    
    echo "Waiting for service to be ready..."
    sleep 10
    
    if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Service started successfully"
    else
        echo -e "${RED}✗${NC} Failed to start service"
        exit 1
    fi
    
    cd ../unit_tests
fi

# Step 2: Verify test files exist
echo ""
echo -e "${CYAN}Step 2: Verifying test files...${NC}"
TEST_FILE_COUNT=$(find test_data -type f | wc -l | tr -d ' ')
echo -e "${GREEN}✓${NC} Found $TEST_FILE_COUNT test file(s)"

# Step 3: Run quick smoke test
echo ""
echo -e "${CYAN}Step 3: Running quick smoke test...${NC}"
if python3 quick_test.py; then
    echo -e "${GREEN}✓${NC} Quick test passed"
else
    echo -e "${YELLOW}⚠${NC} Quick test failed, but continuing..."
fi

# Step 4: Run full test suite
echo ""
echo -e "${CYAN}Step 4: Running full test suite...${NC}"
python3 run_tests.py

# Step 5: Display summary
echo ""
echo -e "${CYAN}Step 5: Test Summary${NC}"
LATEST_REPORT=$(ls -t reports/test_report_*.json 2>/dev/null | head -1)

if [ -f "$LATEST_REPORT" ]; then
    echo -e "${GREEN}✓${NC} Test report: $LATEST_REPORT"
    
    if command -v jq &> /dev/null; then
        TOTAL=$(jq '.total_tests' "$LATEST_REPORT")
        PASSED=$(jq '.passed' "$LATEST_REPORT")
        FAILED=$(jq '.failed' "$LATEST_REPORT")
        
        echo ""
        echo "  Total tests: $TOTAL"
        echo -e "  ${GREEN}Passed: $PASSED${NC}"
        if [ "$FAILED" -gt 0 ]; then
            echo -e "  ${RED}Failed: $FAILED${NC}"
        else
            echo -e "  ${GREEN}Failed: $FAILED${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠${NC} No test report found"
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Tests completed!${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo ""



