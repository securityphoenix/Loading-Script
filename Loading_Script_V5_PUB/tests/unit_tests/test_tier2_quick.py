#!/usr/bin/env python3
"""
Quick test for Tier 2 Translators
"""

import sys
from pathlib import Path
import subprocess

# Test files
TEST_FILES = {
    'cyclonedx': 'scanner_test_files/scans/cyclonedx/log4j.json',
    'npm_audit': 'scanner_test_files/scans/npm_audit/many_vuln_with_groups_different_titles.json',
    'pip_audit': 'scanner_test_files/scans/pip_audit/empty.json',  # Empty file - should handle gracefully
    'qualys_webapp': 'scanner_test_files/scans/qualys_webapp/qualys_webapp_one_vuln.xml'
}

def test_scanner(scanner_name, file_path, assessment_name):
    """Test a single scanner file"""
    
    print(f"\n{'='*80}")
    print(f"Testing: {scanner_name}")
    print(f"File: {file_path}")
    print(f"{'='*80}\n")
    
    cmd = [
        'python3',
        'phoenix_multi_scanner_enhanced.py',
        '--config', 'config_multi_scanner.ini',
        '--file', file_path,
        '--assessment', assessment_name,
        '--import-type', 'new'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    
    print("STDOUT:")
    print(result.stdout)
    
    if result.returncode != 0:
        print("\nSTDERR:")
        print(result.stderr)
        return False
    
    # Check for success indicators
    if '✅' in result.stdout or 'successfully' in result.stdout.lower():
        print(f"\n✅ {scanner_name} test PASSED")
        return True
    else:
        print(f"\n❌ {scanner_name} test FAILED")
        return False

def main():
    print("\n" + "="*80)
    print("TIER 2 TRANSLATORS - QUICK TEST")
    print("="*80)
    print("\nTesting 4 new translators:")
    print("  1. CycloneDX (SBOM standard)")
    print("  2. npm audit (Node.js packages)")
    print("  3. pip-audit (Python packages)")
    print("  4. Qualys WebApp (Enterprise scanner)")
    print()
    
    results = {}
    
    for scanner, file_path in TEST_FILES.items():
        if not Path(file_path).exists():
            print(f"\n❌ {scanner}: File not found: {file_path}")
            results[scanner] = False
            continue
        
        assessment_name = f"Test-Tier2-{scanner}"
        
        try:
            results[scanner] = test_scanner(scanner, file_path, assessment_name)
        except Exception as e:
            print(f"\n❌ {scanner}: Exception: {e}")
            results[scanner] = False
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    for scanner, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status:12} | {scanner}")
    
    total = len(results)
    passed = sum(1 for r in results.values() if r)
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\n🎉 All Tier 2 translators working!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} translator(s) need fixes")
        return 1

if __name__ == '__main__':
    sys.exit(main())

