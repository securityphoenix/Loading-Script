#!/usr/bin/env python3
"""
Comprehensive Scanner Testing Suite
====================================

Tests all 203 scanner types systematically and tracks results.
Creates hard-coded translators as fallback for failed YAML mappings.

Usage:
    python3 test_all_scanners_comprehensive.py
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import csv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('comprehensive_test_results.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ScannerTestResult:
    """Represents the result of testing a single scanner"""
    
    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.files_tested = []
        self.success = False
        self.error_message = None
        self.assets_created = 0
        self.vulnerabilities_found = 0
        self.translator_used = None  # 'yaml', 'hardcoded', or specific translator name
        self.duration = 0.0
        self.needs_hardcoded = False
        self.error_type = None  # 'detection', 'parsing', 'validation', 'import', None


class ComprehensiveScannerTester:
    """Systematic tester for all scanner types"""
    
    def __init__(self, scans_dir: str, config_file: str):
        self.scans_dir = Path(scans_dir)
        self.config_file = config_file
        self.results: Dict[str, ScannerTestResult] = {}
        self.test_start_time = datetime.now()
        
    def get_scanner_directories(self) -> List[Path]:
        """Get all scanner directories to test"""
        scanner_dirs = [d for d in self.scans_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
        scanner_dirs.sort()
        return scanner_dirs
    
    def get_test_files(self, scanner_dir: Path) -> List[Path]:
        """Get test files from a scanner directory"""
        test_files = []
        
        # Look for proven standard formats first (priority order)
        # JSON, XML, CSV, HTML are well-tested and stable
        # SARIF, LOG, JS are now supported with dedicated translators
        # XLSX (Excel) for DSOP, ZIP for BlackDuck Component Risk
        for ext in ['*.json', '*.xml', '*.csv', '*.html', '*.sarif', '*.log', '*.js', '*.xlsx', '*.xls', '*.zip']:
            test_files.extend(scanner_dir.glob(ext))
        
        # Limit to first 3 files per scanner for initial testing
        return sorted(test_files)[:3]
    
    def test_scanner_file(self, scanner_name: str, file_path: Path) -> Tuple[bool, Dict]:
        """Test a single scanner file"""
        assessment_name = f"Test-{scanner_name}-{file_path.stem}"
        
        # ALWAYS specify scanner type (priority over auto-detect per user request)
        cmd = [
            'python3',
            'phoenix_multi_scanner_enhanced.py',
            '--config', self.config_file,
            '--scanner', scanner_name,  # ✅ SPECIFY SCANNER TYPE
            '--file', str(file_path),
            '--assessment', assessment_name,
            '--import-type', 'new'
        ]
        
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout per file
            )
            duration = time.time() - start_time
            
            # Parse output
            output = result.stdout + result.stderr
            
            # Check for success indicators
            success = result.returncode == 0 and 'Successfully processed' in output
            
            # Extract details
            details = {
                'success': success,
                'duration': duration,
                'return_code': result.returncode,
                'output': output,
                'assets': 0,
                'vulnerabilities': 0
            }
            
            # Extract scanner type detected
            if 'Detected scanner type:' in output:
                for line in output.split('\n'):
                    if 'Detected scanner type:' in line:
                        details['detected_scanner'] = line.split('Detected scanner type:')[1].strip()
                        break
            
            # Extract assets and vulnerabilities
            # They appear on separate lines like:
            #   Assets: 1
            #   Vulnerabilities: 6
            assets_found = False
            vulns_found = False
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('Assets:') and not assets_found:
                    try:
                        details['assets'] = int(line.split('Assets:')[1].strip())
                        assets_found = True
                    except:
                        pass
                elif line.startswith('Vulnerabilities:') and not vulns_found:
                    try:
                        details['vulnerabilities'] = int(line.split('Vulnerabilities:')[1].strip())
                        vulns_found = True
                    except:
                        pass
                if assets_found and vulns_found:
                    break
            
            # Only consider it a TRUE success if we actually imported data
            # Success with 0 assets and 0 vulns means nothing was imported
            if success and details['assets'] == 0 and details['vulnerabilities'] == 0:
                success = False
                details['success'] = False
            
            # Detect error type
            if not success:
                if 'Could not detect scanner type' in output:
                    details['error_type'] = 'detection'
                elif 'validation issues found' in output or 'validation failed' in output:
                    details['error_type'] = 'validation'
                elif 'Failed to import assets' in output:
                    details['error_type'] = 'import'
                elif 'Error parsing' in output or 'Failed to parse' in output:
                    details['error_type'] = 'parsing'
                else:
                    details['error_type'] = 'unknown'
            
            return success, details
            
        except subprocess.TimeoutExpired:
            return False, {'error_type': 'timeout', 'duration': 120}
        except Exception as e:
            return False, {'error_type': 'exception', 'error': str(e)}
    
    def test_scanner(self, scanner_dir: Path) -> ScannerTestResult:
        """Test a complete scanner type"""
        scanner_name = scanner_dir.name
        logger.info(f"Testing scanner: {scanner_name}")
        
        result = ScannerTestResult(scanner_name)
        test_files = self.get_test_files(scanner_dir)
        
        if not test_files:
            logger.warning(f"No test files found for {scanner_name}")
            result.error_message = "No test files found"
            return result
        
        result.files_tested = [f.name for f in test_files]
        
        # Test each file
        for test_file in test_files:
            logger.info(f"  Testing file: {test_file.name}")
            
            success, details = self.test_scanner_file(scanner_name, test_file)
            result.duration += details.get('duration', 0)
            
            if success:
                result.success = True
                result.assets_created += details.get('assets', 0)
                result.vulnerabilities_found += details.get('vulnerabilities', 0)
                result.translator_used = details.get('detected_scanner', 'unknown')
                logger.info(f"    ✅ Success: {details.get('assets', 0)} assets, {details.get('vulnerabilities', 0)} vulns")
                break  # One success is enough
            else:
                result.error_type = details.get('error_type', 'unknown')
                result.error_message = details.get('output', '')[:200]  # First 200 chars
                logger.warning(f"    ❌ Failed: {result.error_type}")
        
        # Determine if needs hard-coded translator
        if not result.success and result.error_type in ['detection', 'parsing', 'validation']:
            result.needs_hardcoded = True
        
        return result
    
    def run_all_tests(self):
        """Run tests for all scanners"""
        scanner_dirs = self.get_scanner_directories()
        total_scanners = len(scanner_dirs)
        
        logger.info(f"Starting comprehensive test of {total_scanners} scanners")
        logger.info("=" * 80)
        
        for idx, scanner_dir in enumerate(scanner_dirs, 1):
            logger.info(f"\n[{idx}/{total_scanners}] Testing: {scanner_dir.name}")
            logger.info("-" * 80)
            
            result = self.test_scanner(scanner_dir)
            self.results[scanner_dir.name] = result
            
            # Save incremental results
            if idx % 10 == 0:
                self.save_results(intermediate=True)
        
        logger.info("\n" + "=" * 80)
        logger.info("All tests completed!")
        self.save_results()
        self.generate_reports()
    
    def save_results(self, intermediate=False):
        """Save results to JSON file"""
        filename = 'test_results_intermediate.json' if intermediate else 'test_results_final.json'
        
        results_data = {
            'test_start_time': self.test_start_time.isoformat(),
            'test_end_time': datetime.now().isoformat(),
            'total_scanners': len(self.results),
            'results': {}
        }
        
        for scanner_name, result in self.results.items():
            results_data['results'][scanner_name] = {
                'success': result.success,
                'files_tested': result.files_tested,
                'assets_created': result.assets_created,
                'vulnerabilities_found': result.vulnerabilities_found,
                'translator_used': result.translator_used,
                'duration': result.duration,
                'needs_hardcoded': result.needs_hardcoded,
                'error_type': result.error_type,
                'error_message': result.error_message[:200] if result.error_message else None
            }
        
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        logger.info(f"Results saved to {filename}")
    
    def generate_reports(self):
        """Generate comprehensive test reports"""
        total = len(self.results)
        successful = sum(1 for r in self.results.values() if r.success)
        failed = total - successful
        needs_hardcoded = sum(1 for r in self.results.values() if r.needs_hardcoded)
        
        # Summary report
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    COMPREHENSIVE SCANNER TEST REPORT                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Test Duration: {datetime.now() - self.test_start_time}
Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
═══════
Total Scanners Tested:        {total}
✅ Successful:                  {successful} ({successful/total*100:.1f}%)
❌ Failed:                      {failed} ({failed/total*100:.1f}%)
🔧 Need Hard-Coded Translator: {needs_hardcoded} ({needs_hardcoded/total*100:.1f}%)

SUCCESS BREAKDOWN
═════════════════
"""
        
        # Successful scanners
        report += "\n✅ SUCCESSFUL SCANNERS ({}):\n".format(successful)
        report += "-" * 80 + "\n"
        for name, result in sorted(self.results.items()):
            if result.success:
                report += f"  • {name:40} | Assets: {result.assets_created:4} | Vulns: {result.vulnerabilities_found:4} | {result.translator_used}\n"
        
        # Failed scanners needing hard-coded translators
        report += "\n\n🔧 SCANNERS NEEDING HARD-CODED TRANSLATORS ({}):\n".format(needs_hardcoded)
        report += "-" * 80 + "\n"
        for name, result in sorted(self.results.items()):
            if result.needs_hardcoded:
                report += f"  • {name:40} | Error: {result.error_type}\n"
        
        # Failed scanners (other reasons)
        other_failures = [r for r in self.results.values() if not r.success and not r.needs_hardcoded]
        report += f"\n\n❌ OTHER FAILURES ({len(other_failures)}):\n"
        report += "-" * 80 + "\n"
        for name, result in sorted(self.results.items()):
            if not result.success and not result.needs_hardcoded:
                report += f"  • {name:40} | Error: {result.error_type or 'unknown'}\n"
        
        # Save report
        with open('COMPREHENSIVE_TEST_REPORT.md', 'w') as f:
            f.write(report)
        
        print(report)
        
        # Generate CSV for easy analysis
        self.generate_csv_report()
    
    def generate_csv_report(self):
        """Generate CSV report for analysis"""
        with open('test_results.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Scanner Name', 'Success', 'Assets', 'Vulnerabilities', 
                'Translator Used', 'Duration (s)', 'Needs Hardcoded', 
                'Error Type', 'Files Tested'
            ])
            
            for name, result in sorted(self.results.items()):
                writer.writerow([
                    name,
                    'Yes' if result.success else 'No',
                    result.assets_created,
                    result.vulnerabilities_found,
                    result.translator_used or 'N/A',
                    f"{result.duration:.2f}",
                    'Yes' if result.needs_hardcoded else 'No',
                    result.error_type or 'N/A',
                    ', '.join(result.files_tested)
                ])
        
        logger.info("CSV report saved to test_results.csv")


def main():
    """Main entry point"""
    # Configuration
    scans_dir = 'scanner_test_files/scans'
    config_file = 'config_multi_scanner.ini'
    
    # Verify paths exist
    if not Path(scans_dir).exists():
        logger.error(f"Scans directory not found: {scans_dir}")
        sys.exit(1)
    
    if not Path(config_file).exists():
        logger.error(f"Config file not found: {config_file}")
        sys.exit(1)
    
    # Run comprehensive tests
    tester = ComprehensiveScannerTester(scans_dir, config_file)
    
    try:
        tester.run_all_tests()
    except KeyboardInterrupt:
        logger.info("\n\nTest interrupted by user. Saving partial results...")
        tester.save_results(intermediate=True)
        tester.generate_reports()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error during testing: {e}")
        import traceback
        traceback.print_exc()
        tester.save_results(intermediate=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

