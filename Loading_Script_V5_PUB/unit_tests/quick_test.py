#!/usr/bin/env python3
"""
Phoenix Scanner Client - Quick Smoke Test

Quick validation test to verify the service is running and responsive.
Tests one file from each scanner category.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'phoenix-scanner-client'))

from phoenix_client import PhoenixScannerClient, console


def main():
    """Run quick smoke tests"""
    console.print("\n[bold cyan]Phoenix Scanner - Quick Smoke Test[/bold cyan]\n")
    
    # Configuration
    api_url = "http://localhost:8000"
    api_key = "test-api-key-12345"
    
    # Initialize client
    console.print("[cyan]Initializing client...[/cyan]")
    client = PhoenixScannerClient(
        api_url=api_url,
        api_key=api_key,
        verbose=True
    )
    
    # Test 1: Health Check
    console.print("\n[cyan]Test 1: Health Check[/cyan]")
    try:
        health = client.health_check()
        if health.get('status') == 'healthy':
            console.print("[green]✓[/green] API is healthy")
        else:
            console.print(f"[yellow]⚠[/yellow] API status: {health}")
    except Exception as e:
        console.print(f"[red]✗[/red] Health check failed: {e}")
        sys.exit(1)
    
    # Test 2: Upload Sample Files (one from each category)
    test_files = [
        ("checkmarx", "test_data/checkmarx/multiple_findings_same_file_different_line_number.xml", "CODE"),
        ("qualys", "test_data/qualys/Qualys_Sample_Report.csv", "INFRA"),
        ("trivy", "test_data/trivy/all_statuses.json", "CONTAINER"),
        ("acunetix", "test_data/acunetix/acunetix360_one_finding.json", "WEB"),
        ("prowler", "test_data/prowler/many_vuln.json", "CLOUD"),
    ]
    
    results = []
    
    for scanner_type, file_path, asset_type in test_files:
        console.print(f"\n[cyan]Test: Uploading {scanner_type} scan[/cyan]")
        
        if not Path(file_path).exists():
            console.print(f"[yellow]⚠[/yellow] Test file not found: {file_path}")
            results.append(False)
            continue
        
        try:
            result = client.upload_file(
                file_path=file_path,
                scanner_type=scanner_type,
                asset_type=asset_type,
                import_type="new"
            )
            
            job_id = result.get('job_id')
            console.print(f"[green]✓[/green] Upload successful! Job ID: {job_id}")
            results.append(True)
        
        except Exception as e:
            console.print(f"[red]✗[/red] Upload failed: {e}")
            results.append(False)
    
    # Summary
    console.print("\n" + "═" * 60)
    console.print("[bold]Quick Test Summary[/bold]")
    console.print("═" * 60)
    
    passed = sum(results)
    total = len(results)
    
    console.print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        console.print("[green]✓ All quick tests passed![/green]")
        sys.exit(0)
    else:
        console.print(f"[yellow]⚠ {total - passed} test(s) failed[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)



