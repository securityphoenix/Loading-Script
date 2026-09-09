#!/usr/bin/env python3
"""
Quick test for Tier 1 Additional Translators
"""

import sys
import os
from pathlib import Path

# Add parent directory (project root) to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Test files (relative to project root, which is two levels up)
TEST_FILES = {
    'tenable': 'scanner_test_files/scans/tenable/tenable_many_vuln.csv',
    'dependency_check': 'scanner_test_files/scans/dependency_check/single_vuln.xml',
    'sonarqube': 'scanner_test_files/scans/sonarqube/sonar-6-findings.json'
}

def test_scanner(scanner_name, file_path, assessment_name):
    """Test a single scanner file"""
    import subprocess
    
    print(f"\n{'='*80}")
    print(f"Testing: {scanner_name}")
    print(f"File: {file_path}")
    print(f"{'='*80}\n")
    
    # Change to project root (two levels up from tests/unit_tests/)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    
    cmd = [
        'python3',
        'phoenix_multi_scanner_enhanced.py',
        '--config', 'config_multi_scanner.ini',
        '--file', file_path,
        '--assessment', assessment_name,
        '--import-type', 'new'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=project_root)
    
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
    print("TIER 1 ADDITIONAL TRANSLATORS - QUICK TEST")
    print("="*80)
    print("\nTesting 3 new translators:")
    print("  1. Tenable Nessus (CSV)")
    print("  2. Dependency Check (XML)")
    print("  3. SonarQube (JSON)")
    print()
    
    # Get project root
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    
    results = {}
    
    for scanner, file_path in TEST_FILES.items():
        # Check file existence from project root
        full_path = os.path.join(project_root, file_path)
        if not Path(full_path).exists():
            print(f"\n❌ {scanner}: File not found: {full_path}")
            results[scanner] = False
            continue
        
        assessment_name = f"Test-Tier1-{scanner}"
        
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
        print("\n🎉 All Tier 1 translators working!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} translator(s) need fixes")
        return 1

if __name__ == '__main__':
    sys.exit(main())

