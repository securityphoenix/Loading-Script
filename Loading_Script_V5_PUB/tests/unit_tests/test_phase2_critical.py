#!/usr/bin/env python3
"""
Quick Test - Phase 2 Critical Scanners Only
===========================================

Tests only the scanners that now have hard-coded translators:
- Grype (already working)
- Trivy (already working)  
- JFrog XRay (4 variants - NEW)
- BlackDuck (2 variants - NEW)

Quick validation instead of full 203 scanner test.
"""

import json
import subprocess
import sys
from pathlib import Path

# Scanners with hard-coded translators
CRITICAL_SCANNERS = [
    'anchore_grype',
    'aqua_trivy',
    'jfrog_xray_api_summary_artifact',
    'jfrog_xray_unified',
    'jfrog_xray_on_demand_binary_scan',
    'jfrogxray',
    'blackduck_binary_analysis',
    'api_blackduck'
]

def test_scanner(scanner_name: str, scan_file: Path) -> dict:
    """Test a single scanner file"""
    cmd = [
        'python3', 'phoenix_multi_scanner_enhanced.py',
        '--config', 'config_multi_scanner.ini',
        '--file', str(scan_file),
        '--assessment', f"Test-{scanner_name}",
        '--import-type', 'new'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        
        success = 'Success Rate: 100' in output
        detected = 'Detected scanner type:' in output
        
        return {
            'scanner': scanner_name,
            'file': scan_file.name,
            'success': success,
            'detected': detected,
            'output': output[-500:] if len(output) > 500 else output
        }
    except subprocess.TimeoutExpired:
        return {
            'scanner': scanner_name,
            'file': scan_file.name,
            'success': False,
            'detected': False,
            'output': 'TIMEOUT'
        }
    except Exception as e:
        return {
            'scanner': scanner_name,
            'file': scan_file.name,
            'success': False,
            'detected': False,
            'output': str(e)
        }

def main():
    scans_dir = Path('scanner_test_files/scans')
    results = []
    
    print("="*80)
    print("PHASE 2 CRITICAL SCANNERS - QUICK TEST")
    print("="*80)
    print(f"\nTesting {len(CRITICAL_SCANNERS)} scanners with hard-coded translators...\n")
    
    for i, scanner_name in enumerate(CRITICAL_SCANNERS, 1):
        scanner_dir = scans_dir / scanner_name
        
        if not scanner_dir.exists():
            print(f"[{i}/{len(CRITICAL_SCANNERS)}] ⚠️  {scanner_name}: Directory not found")
            continue
        
        # Get first test file
        test_files = list(scanner_dir.glob('*.json')) + list(scanner_dir.glob('*.csv'))
        if not test_files:
            print(f"[{i}/{len(CRITICAL_SCANNERS)}] ⚠️  {scanner_name}: No test files")
            continue
        
        print(f"[{i}/{len(CRITICAL_SCANNERS)}] Testing {scanner_name}...")
        result = test_scanner(scanner_name, test_files[0])
        results.append(result)
        
        if result['success']:
            print(f"    ✅ SUCCESS - File: {result['file']}")
        elif result['detected']:
            print(f"    🔶 DETECTED but failed import - File: {result['file']}")
        else:
            print(f"    ❌ FAILED - Not detected - File: {result['file']}")
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    successful = sum(1 for r in results if r['success'])
    detected = sum(1 for r in results if r['detected'])
    failed = len(results) - successful
    
    print(f"\nTotal Tested: {len(results)}")
    print(f"✅ Successful: {successful} ({successful/len(results)*100:.1f}%)")
    print(f"🔶 Detected: {detected} ({detected/len(results)*100:.1f}%)")
    print(f"❌ Failed: {failed} ({failed/len(results)*100:.1f}%)")
    
    # Details
    print("\nDETAILED RESULTS:")
    for r in results:
        status = "✅" if r['success'] else ("🔶" if r['detected'] else "❌")
        print(f"  {status} {r['scanner']}: {r['file']}")
    
    # Save results
    with open('phase2_critical_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: phase2_critical_test_results.json")
    print("="*80)

if __name__ == '__main__':
    main()

