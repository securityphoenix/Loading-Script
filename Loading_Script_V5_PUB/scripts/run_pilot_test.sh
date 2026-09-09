#!/bin/bash
# Pilot Test - Test first 10 scanners to validate methodology
#
# This script runs a quick pilot test on the first 10 scanners
# to verify the testing approach before running all 203 scanners.

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                          PILOT TEST - 10 Scanners                            ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "This pilot test will validate the testing methodology before"
echo "running the full 203-scanner test suite."
echo ""
echo "Testing scanners:"
echo "  1. acunetix"
echo "  2. anchore_engine"  
echo "  3. anchore_enterprise"
echo "  4. anchore_grype (already tested)"
echo "  5. api_sonarqube"
echo "  6. aqua"
echo "  7. bandit"
echo "  8. brakeman"
echo "  9. checkmarx"
echo "  10. snyk"
echo ""
echo "Estimated duration: 10-15 minutes"
echo ""
read -p "Press Enter to start pilot test..." 

# Array of scanners to test
scanners=(
    "acunetix"
    "anchore_engine"
    "anchore_enterprise"
    "anchore_grype"
    "api_sonarqube"
    "aqua"
    "bandit"
    "brakeman"
    "checkmarx"
    "snyk"
)

# Test each scanner
count=0
success=0
failed=0

for scanner in "${scanners[@]}"; do
    count=$((count + 1))
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "[$count/10] Testing: $scanner"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Find first JSON file
    test_file=$(find "scanner_test_files/scans/$scanner" -name "*.json" -type f | head -1)
    
    if [ -z "$test_file" ]; then
        echo "⚠️  No test files found for $scanner"
        failed=$((failed + 1))
        continue
    fi
    
    echo "Test file: $(basename $test_file)"
    echo ""
    
    # Run test
    python3 phoenix_multi_scanner_enhanced.py \
        --config config_multi_scanner.ini \
        --file "$test_file" \
        --assessment "Pilot-Test-$scanner" \
        --import-type new 2>&1 | tail -30
    
    # Check result
    if [ $? -eq 0 ]; then
        echo "✅ SUCCESS"
        success=$((success + 1))
    else
        echo "❌ FAILED"
        failed=$((failed + 1))
    fi
    
    # Small delay between tests
    sleep 2
done

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                         PILOT TEST COMPLETE                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Results:"
echo "  Total Tested: $count"
echo "  ✅ Success: $success"
echo "  ❌ Failed: $failed"
echo "  Success Rate: $(awk "BEGIN {printf \"%.1f\", ($success/$count)*100}")%"
echo ""

if [ $success -gt 5 ]; then
    echo "✅ Pilot test shows good success rate!"
    echo "   Ready to proceed with full test of all 203 scanners."
    echo ""
    echo "To run full test:"
    echo "  python3 test_all_scanners_comprehensive.py"
else
    echo "⚠️  Pilot test shows low success rate."
    echo "   Review failures before running full test."
fi
echo ""

