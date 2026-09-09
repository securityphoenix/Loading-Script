#!/usr/bin/env python3
"""
Comprehensive Test Script for ALL 203 Phoenix Security Scanner Types
Tests import functionality for every scanner using sample files
"""

import os
import sys
from pathlib import Path
import json
import time
from datetime import datetime

def test_all_scanners():
    """Test import for all 203 scanner types"""
    
    scans_dir = Path("{PROJECT_ROOT}")
    config_file = "config_test.ini"
    
    # Get all scanner directories
    scanner_dirs = sorted([d for d in scans_dir.iterdir() if d.is_dir()])
    
    print("=" * 100)
    print(f"🧪 COMPREHENSIVE SCANNER TEST - ALL {len(scanner_dirs)} SCANNER TYPES")
    print(f"   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Config: {config_file}")
    print("=" * 100)
    print()
    
    results = {
        'total': len(scanner_dirs),
        'tested': 0,
        'passed': 0,
        'failed': 0,
        'no_files': 0,
        'details': []
    }
    
    for i, scanner_dir in enumerate(scanner_dirs, 1):
        scanner_name = scanner_dir.name
        
        print(f"\n📋 Test {i}/{len(scanner_dirs)}: {scanner_name}")
        print("-" * 100)
        
        # Find a sample file
        sample_files = (
            list(scanner_dir.glob("*.json"))[:1] +
            list(scanner_dir.glob("*.xml"))[:1] +
            list(scanner_dir.glob("*.csv"))[:1]
        )
        
        if not sample_files:
            print(f"   ⚠️  No sample files found")
            results['no_files'] += 1
            results['details'].append({
                'scanner': scanner_name,
                'status': 'no_files',
                'file': None,
                'error': 'No sample files found'
            })
            continue
        
        sample_file = sample_files[0]
        results['tested'] += 1
        
        print(f"   📄 Testing file: {sample_file.name}")
        print(f"   🔧 Running import...")
        
        # Run import
        import subprocess
        cmd = [
            'python3',
            'phoenix_multi_scanner_enhanced.py',
            '--file', str(sample_file),
            '--config', config_file,
            '--assessment', f'TEST-{scanner_name}-{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                cwd="{PROJECT_ROOT}",
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse output
            output = result.stdout + result.stderr
            
            # Check for success indicators
            if result.returncode == 0 and ('Successfully processed' in output or 'Success Rate: 100' in output):
                print(f"   ✅ PASSED")
                results['passed'] += 1
                
                # Extract metrics
                assets = 0
                vulns = 0
                for line in output.split('\n'):
                    if 'Assets:' in line:
                        try:
                            assets = int(line.split('Assets:')[1].split()[0])
                        except:
                            pass
                    if 'Vulnerabilities:' in line:
                        try:
                            vulns = int(line.split('Vulnerabilities:')[1].split()[0])
                        except:
                            pass
                
                print(f"      Assets: {assets}, Vulnerabilities: {vulns}")
                
                results['details'].append({
                    'scanner': scanner_name,
                    'status': 'passed',
                    'file': sample_file.name,
                    'assets': assets,
                    'vulns': vulns
                })
            else:
                print(f"   ❌ FAILED")
                results['failed'] += 1
                
                # Extract error
                error_msg = "Unknown error"
                if 'Could not detect scanner type' in output:
                    error_msg = "Could not detect scanner type"
                elif 'Failed to import' in output:
                    error_msg = "Failed to import to Phoenix API"
                elif 'validation issues' in output:
                    error_msg = "Data validation failed"
                elif result.returncode != 0:
                    error_msg = f"Exit code {result.returncode}"
                
                print(f"      Error: {error_msg}")
                
                results['details'].append({
                    'scanner': scanner_name,
                    'status': 'failed',
                    'file': sample_file.name,
                    'error': error_msg
                })
        
        except subprocess.TimeoutExpired:
            print(f"   ⏱️  TIMEOUT (> 60s)")
            results['failed'] += 1
            results['details'].append({
                'scanner': scanner_name,
                'status': 'failed',
                'file': sample_file.name,
                'error': 'Timeout (>60s)'
            })
        
        except Exception as e:
            print(f"   ❌ EXCEPTION: {str(e)}")
            results['failed'] += 1
            results['details'].append({
                'scanner': scanner_name,
                'status': 'failed',
                'file': sample_file.name,
                'error': str(e)
            })
    
    # Print summary
    print("\n" + "=" * 100)
    print("📊 TEST SUMMARY")
    print("=" * 100)
    print(f"Total Scanner Types: {results['total']}")
    print(f"Tested: {results['tested']}")
    print(f"✅ Passed: {results['passed']}")
    print(f"❌ Failed: {results['failed']}")
    print(f"⚠️  No Files: {results['no_files']}")
    print(f"Success Rate: {(results['passed'] / results['tested'] * 100) if results['tested'] > 0 else 0:.1f}%")
    print()
    
    # Print failed scanners
    if results['failed'] > 0:
        print("\n" + "=" * 100)
        print("❌ FAILED SCANNERS")
        print("=" * 100)
        for detail in results['details']:
            if detail['status'] == 'failed':
                print(f"   {detail['scanner']}: {detail['error']}")
    
    # Print scanners without files
    if results['no_files'] > 0:
        print("\n" + "=" * 100)
        print("⚠️  SCANNERS WITHOUT SAMPLE FILES")
        print("=" * 100)
        for detail in results['details']:
            if detail['status'] == 'no_files':
                print(f"   {detail['scanner']}")
    
    # Save results to JSON
    results_file = f"test_results_all_scanners_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Results saved to: {results_file}")
    print()
    
    return results

if __name__ == "__main__":
    results = test_all_scanners()
    sys.exit(0 if results['failed'] == 0 else 1)

