#!/usr/bin/env python3
"""
Phoenix Scanner Client Test Script

Quick test to verify the client is working correctly.
"""

import sys
import json
import tempfile
from pathlib import Path
from phoenix_client import PhoenixScannerClient, console


def create_test_scan_file():
    """Create a minimal test scan file"""
    test_data = {
        "scanner": "test",
        "scan_time": "2025-11-12T10:00:00Z",
        "findings": [
            {
                "vulnerability_id": "CVE-2023-12345",
                "severity": "HIGH",
                "package": "test-package",
                "version": "1.0.0"
            }
        ]
    }
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(test_data, temp_file)
    temp_file.close()
    return temp_file.name


def test_health_check(client):
    """Test API health check"""
    console.print("\n[cyan]Test 1: Health Check[/cyan]")
    try:
        health = client.health_check()
        if health.get('status') == 'healthy':
            console.print("[green]✓[/green] API is healthy")
            return True
        else:
            console.print(f"[yellow]⚠[/yellow] API status: {health}")
            return False
    except Exception as e:
        console.print(f"[red]✗[/red] Health check failed: {e}")
        return False


def test_upload(client, test_file):
    """Test file upload"""
    console.print("\n[cyan]Test 2: File Upload[/cyan]")
    try:
        result = client.upload_file(
            file_path=test_file,
            scanner_type="test",
            assessment_name="TestAssessment",
            import_type="new"
        )
        
        job_id = result.get('job_id')
        if job_id:
            console.print(f"[green]✓[/green] Upload successful! Job ID: {job_id}")
            return job_id
        else:
            console.print(f"[red]✗[/red] No job ID in response: {result}")
            return None
    except Exception as e:
        console.print(f"[red]✗[/red] Upload failed: {e}")
        return None


def test_status_check(client, job_id):
    """Test status check"""
    console.print("\n[cyan]Test 3: Status Check[/cyan]")
    try:
        status = client.get_job_status(job_id)
        console.print(f"[green]✓[/green] Status: {status['status']}")
        console.print(f"  Progress: {status['progress']:.1f}%")
        console.print(f"  Filename: {status['filename']}")
        return True
    except Exception as e:
        console.print(f"[red]✗[/red] Status check failed: {e}")
        return False


def test_list_jobs(client):
    """Test job listing"""
    console.print("\n[cyan]Test 4: List Jobs[/cyan]")
    try:
        result = client.list_jobs(page=1, page_size=5)
        console.print(f"[green]✓[/green] Found {result['total']} jobs")
        return True
    except Exception as e:
        console.print(f"[red]✗[/red] List jobs failed: {e}")
        return False


def main():
    """Run all tests"""
    console.print("[bold cyan]Phoenix Scanner Client Test Suite[/bold cyan]")
    console.print("=" * 60)
    
    # Get configuration
    api_url = input("API URL [http://localhost:8000]: ").strip() or "http://localhost:8000"
    api_key = input("API Key [dev-test-key-12345]: ").strip() or "dev-test-key-12345"
    
    console.print(f"\nTesting with:")
    console.print(f"  API URL: {api_url}")
    console.print(f"  API Key: {api_key[:10]}...")
    
    # Initialize client
    client = PhoenixScannerClient(
        api_url=api_url,
        api_key=api_key,
        verbose=True
    )
    
    # Run tests
    results = []
    
    # Test 1: Health check
    results.append(("Health Check", test_health_check(client)))
    
    # Test 2: Upload
    test_file = create_test_scan_file()
    console.print(f"\n[dim]Created test file: {test_file}[/dim]")
    
    try:
        job_id = test_upload(client, test_file)
        results.append(("File Upload", job_id is not None))
        
        # Test 3: Status check (if upload succeeded)
        if job_id:
            results.append(("Status Check", test_status_check(client, job_id)))
        else:
            results.append(("Status Check", False))
        
        # Test 4: List jobs
        results.append(("List Jobs", test_list_jobs(client)))
    
    finally:
        # Cleanup
        import os
        if Path(test_file).exists():
            os.unlink(test_file)
            console.print(f"\n[dim]Cleaned up test file[/dim]")
    
    # Summary
    console.print("\n" + "=" * 60)
    console.print("[bold cyan]Test Summary[/bold cyan]")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "[green]✓ PASS[/green]" if result else "[red]✗ FAIL[/red]"
        console.print(f"  {name}: {status}")
    
    console.print(f"\n[bold]Result: {passed}/{total} tests passed[/bold]")
    
    if passed == total:
        console.print("[green]✓ All tests passed![/green]")
        sys.exit(0)
    else:
        console.print(f"[yellow]⚠ {total - passed} test(s) failed[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Test suite error: {e}[/red]")
        sys.exit(1)



