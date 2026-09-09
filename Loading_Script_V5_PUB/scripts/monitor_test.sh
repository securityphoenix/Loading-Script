#!/bin/bash
# Monitor comprehensive test progress

while true; do
  clear
  echo "════════════════════════════════════════════════════════════════"
  echo "   📊 COMPREHENSIVE TEST PROGRESS - All 203 Scanners"
  echo "════════════════════════════════════════════════════════════════"
  echo ""
  
  if [ -f test_results.csv ]; then
    python3 << 'PYEOF'
import csv
from datetime import datetime

try:
    with open('test_results.csv', 'r') as f:
        reader = csv.DictReader(f)
        results = list(reader)
    
    total = len(results)
    success = sum(1 for r in results if r['Success'] == 'Yes')
    failed = total - success
    
    print(f"⏱️  Testing started: Check log for start time")
    print(f"📈 Progress: {total} / 203 scanners ({total/203*100:.1f}%)")
    print(f"")
    print(f"✅ Success: {success:3d} ({success/max(1,total)*100:5.1f}%)")
    print(f"❌ Failed:  {failed:3d} ({failed/max(1,total)*100:5.1f}%)")
    print(f"")
    
    if total > 0:
        # Show last 5 tested
        print("Last 5 tested:")
        for r in results[-5:]:
            status = "✅" if r['Success'] == 'Yes' else "❌"
            print(f"  {status} {r['Scanner']}")
        
        print("")
        
        # Show recent failures
        recent_failures = [r for r in results[-10:] if r['Success'] != 'Yes']
        if recent_failures:
            print(f"Recent failures ({len(recent_failures)}):")
            for r in recent_failures[:3]:
                error = r['Error'][:60] + "..." if len(r['Error']) > 60 else r['Error']
                print(f"  ❌ {r['Scanner']}: {error}")
    
except Exception as e:
    print(f"Error: {e}")
PYEOF
  else
    echo "⏳ Test initializing..."
  fi
  
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "Press Ctrl+C to stop monitoring"
  echo ""
  
  sleep 15
done
