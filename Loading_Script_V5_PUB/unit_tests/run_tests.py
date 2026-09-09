#!/usr/bin/env python3
"""
Phoenix Scanner Client - Unit Test Runner

Comprehensive test suite for the Phoenix Scanner Client and Service.
Tests multiple scanner types: SAST, Infrastructure, Container, Web, Cloud.
"""

import sys
import os
import yaml
import json
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Add parent directory to path to import client
sys.path.insert(0, str(Path(__file__).parent.parent / 'phoenix-scanner-client'))

from phoenix_client import PhoenixScannerClient, console
from rich.table import Table
from rich.panel import Panel


class TestResult:
    """Test result container"""
    def __init__(self, name: str, success: bool, message: str, duration: float, job_id: str = None):
        self.name = name
        self.success = success
        self.message = message
        self.duration = duration
        self.job_id = job_id


class PhoenixTestRunner:
    """Test runner for Phoenix Scanner Client"""
    
    def __init__(self, config_file: str = "test_config.yaml"):
        self.config_file = Path(config_file)
        self.config = self.load_config()
        self.client = None
        self.results: List[TestResult] = []
        self.start_time = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load test configuration"""
        if not self.config_file.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_file}")
        
        with open(self.config_file, 'r') as f:
            return yaml.safe_load(f)
    
    def setup(self):
        """Setup test environment"""
        console.print("\n[cyan]═══ Phoenix Scanner Test Suite ═══[/cyan]\n")
        
        # Initialize client
        api_url = self.config['api_url']
        api_key = self.config['api_key']
        
        phoenix_creds = {}
        if 'phoenix_client_id' in self.config:
            phoenix_creds['phoenix_client_id'] = self.config['phoenix_client_id']
        if 'phoenix_client_secret' in self.config:
            phoenix_creds['phoenix_client_secret'] = self.config['phoenix_client_secret']
        if 'phoenix_api_url' in self.config:
            phoenix_creds['phoenix_api_url'] = self.config['phoenix_api_url']
        
        self.client = PhoenixScannerClient(
            api_url=api_url,
            api_key=api_key,
            **phoenix_creds,
            verbose=self.config.get('test_settings', {}).get('enable_verbose', False)
        )
        
        # Test API connection
        console.print("[cyan]Testing API connection...[/cyan]")
        health = self.client.health_check()
        
        # Check if core services are operational
        status = health.get('status')
        workers_ok = health.get('workers', {}).get('status') == 'healthy'
        queue_ok = health.get('queue', {}).get('redis_status') == 'healthy'
        
        if status == 'healthy':
            console.print("[green]✓[/green] API is healthy\n")
        elif status == 'degraded' and workers_ok and queue_ok:
            console.print("[yellow]⚠[/yellow] API status is degraded (Phoenix global credentials not set)")
            console.print("[green]✓[/green] Workers and queue are healthy - tests can proceed\n")
        else:
            console.print(f"[red]✗[/red] API health check failed: {health}\n")
            raise Exception("API is not healthy")
        
        self.start_time = time.time()
    
    def run_test_case(self, test_case: Dict[str, Any]) -> TestResult:
        """Run a single test case"""
        test_name = test_case['name']
        file_path = Path(test_case['file_path'])
        
        # Check if file exists
        if not file_path.exists():
            return TestResult(
                name=test_name,
                success=False,
                message=f"Test file not found: {file_path}",
                duration=0
            )
        
        console.print(f"\n[cyan]Running:[/cyan] {test_name}")
        console.print(f"  File: {file_path.name}")
        console.print(f"  Scanner: {test_case['scanner_type']}")
        console.print(f"  Asset Type: {test_case.get('asset_type', 'N/A')}")
        
        test_start = time.time()
        
        try:
            # Upload file
            result = self.client.upload_file(
                file_path=str(file_path),
                scanner_type=test_case['scanner_type'],
                asset_type=test_case.get('asset_type'),
                import_type=test_case.get('import_type', 'new'),
                assessment_name=f"UnitTest-{test_case['scanner_type']}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            job_id = result.get('job_id')
            console.print(f"  Job ID: {job_id}")
            
            # Wait for completion if configured
            if self.config.get('test_settings', {}).get('wait_for_completion', True):
                console.print("  Waiting for completion...")
                status = self.client.wait_for_completion(
                    job_id,
                    show_progress=False,
                    poll_interval=2
                )
                
                duration = time.time() - test_start
                
                if status['status'] == test_case.get('expected_status', 'completed'):
                    console.print(f"[green]✓[/green] Test passed ({duration:.2f}s)")
                    return TestResult(
                        name=test_name,
                        success=True,
                        message=f"Completed successfully. Status: {status['status']}",
                        duration=duration,
                        job_id=job_id
                    )
                else:
                    console.print(f"[red]✗[/red] Test failed: Unexpected status {status['status']}")
                    return TestResult(
                        name=test_name,
                        success=False,
                        message=f"Expected {test_case.get('expected_status')}, got {status['status']}",
                        duration=duration,
                        job_id=job_id
                    )
            else:
                duration = time.time() - test_start
                console.print(f"[green]✓[/green] Upload successful ({duration:.2f}s)")
                return TestResult(
                    name=test_name,
                    success=True,
                    message="Upload completed successfully (not waited for processing)",
                    duration=duration,
                    job_id=job_id
                )
        
        except Exception as e:
            duration = time.time() - test_start
            console.print(f"[red]✗[/red] Test failed: {e}")
            return TestResult(
                name=test_name,
                success=False,
                message=str(e),
                duration=duration
            )
    
    def run_all_tests(self):
        """Run all configured test cases"""
        test_cases = self.config.get('test_cases', [])
        
        console.print(f"\n[cyan]Running {len(test_cases)} test case(s)...[/cyan]\n")
        console.print("─" * 60)
        
        for i, test_case in enumerate(test_cases, 1):
            console.print(f"\n[bold]Test {i}/{len(test_cases)}[/bold]")
            result = self.run_test_case(test_case)
            self.results.append(result)
            
            # Small delay between tests
            if i < len(test_cases):
                time.sleep(1)
    
    def run_batch_tests(self):
        """Run batch tests"""
        batch_tests = self.config.get('batch_tests', [])
        
        if not batch_tests:
            return
        
        console.print(f"\n[cyan]Running {len(batch_tests)} batch test(s)...[/cyan]\n")
        
        for batch_test in batch_tests:
            console.print(f"\n[bold cyan]Batch Test:[/bold cyan] {batch_test['name']}")
            console.print(f"Description: {batch_test.get('description', 'N/A')}")
            
            # Get test cases for this batch
            test_case_names = batch_test.get('test_cases', [])
            all_test_cases = self.config.get('test_cases', [])
            
            batch_cases = [tc for tc in all_test_cases if tc['name'] in test_case_names]
            
            console.print(f"Running {len(batch_cases)} test cases in batch...")
            
            for test_case in batch_cases:
                result = self.run_test_case(test_case)
                self.results.append(result)
                time.sleep(0.5)
    
    def generate_report(self):
        """Generate test report"""
        duration = time.time() - self.start_time
        
        console.print("\n" + "═" * 60)
        console.print("[bold cyan]Test Results Summary[/bold cyan]")
        console.print("═" * 60 + "\n")
        
        # Create results table
        table = Table(title="Test Results")
        table.add_column("Test Name", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Duration", style="yellow")
        table.add_column("Job ID", style="dim")
        
        passed = 0
        failed = 0
        
        for result in self.results:
            status = "[green]✓ PASS[/green]" if result.success else "[red]✗ FAIL[/red]"
            
            if result.success:
                passed += 1
            else:
                failed += 1
            
            table.add_row(
                result.name[:50],
                status,
                f"{result.duration:.2f}s",
                result.job_id[:12] + "..." if result.job_id else "N/A"
            )
        
        console.print(table)
        
        # Summary
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Total tests: {len(self.results)}")
        console.print(f"  [green]Passed: {passed}[/green]")
        console.print(f"  [red]Failed: {failed}[/red]")
        console.print(f"  Success rate: {passed/len(self.results)*100:.1f}%")
        console.print(f"  Total duration: {duration:.2f}s")
        
        # Failed tests details
        if failed > 0:
            console.print("\n[red]Failed Tests:[/red]")
            for result in self.results:
                if not result.success:
                    console.print(f"  • {result.name}")
                    console.print(f"    Error: {result.message}")
        
        # Save report
        self.save_report()
        
        return failed == 0
    
    def save_report(self):
        """Save test report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = Path("reports") / f"test_report_{timestamp}.json"
        report_file.parent.mkdir(exist_ok=True)
        
        report = {
            'timestamp': timestamp,
            'total_tests': len(self.results),
            'passed': sum(1 for r in self.results if r.success),
            'failed': sum(1 for r in self.results if not r.success),
            'duration': time.time() - self.start_time,
            'results': [
                {
                    'name': r.name,
                    'success': r.success,
                    'message': r.message,
                    'duration': r.duration,
                    'job_id': r.job_id
                }
                for r in self.results
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"\n[dim]Report saved to: {report_file}[/dim]")


def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Phoenix Scanner Test Runner')
    parser.add_argument('--config', default='test_config.yaml', help='Test configuration file')
    parser.add_argument('--tests-only', action='store_true', help='Run only individual tests')
    parser.add_argument('--batch-only', action='store_true', help='Run only batch tests')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        runner = PhoenixTestRunner(config_file=args.config)
        runner.setup()
        
        # Run tests
        if not args.batch_only:
            runner.run_all_tests()
        
        if not args.tests_only:
            runner.run_batch_tests()
        
        # Generate report
        success = runner.generate_report()
        
        sys.exit(0 if success else 1)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Test runner error: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()

