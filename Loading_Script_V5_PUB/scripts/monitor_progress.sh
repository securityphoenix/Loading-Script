#!/bin/bash
# Monitor test progress from log file

clear
echo "════════════════════════════════════════════════════════════════"
echo "   📊 COMPREHENSIVE TEST PROGRESS"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ ! -f comprehensive_test_run.log ]; then
    echo "❌ Log file not found"
    exit 1
fi

# Extract progress from log
TOTAL_SCANNERS=203
CURRENT=$(grep -c "^.*Testing scanner:" comprehensive_test_run.log 2>/dev/null || echo "0")
SUCCESS=$(grep -c "✅ Success:" comprehensive_test_run.log 2>/dev/null || echo "0")
FAILED=$(grep -c "❌ Failed:" comprehensive_test_run.log 2>/dev/null || echo "0")

PERCENT=$(echo "scale=1; $CURRENT * 100 / $TOTAL_SCANNERS" | bc 2>/dev/null || echo "0")

echo "📈 Scanners tested: $CURRENT / $TOTAL_SCANNERS ($PERCENT%)"
echo ""
echo "Results so far:"
echo "  ✅ Successful file uploads: $SUCCESS"
echo "  ❌ Failed file uploads:     $FAILED"
echo ""

# Show last 10 scanners tested
echo "Last 10 scanners tested:"
grep "Testing scanner:" comprehensive_test_run.log | tail -10 | while read line; do
    scanner=$(echo "$line" | sed 's/.*Testing scanner: //')
    echo "  • $scanner"
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Latest activity:"
tail -5 comprehensive_test_run.log

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Monitor continuously: watch -n 10 ./monitor_progress.sh"
echo "View full log:       tail -f comprehensive_test_run.log"

