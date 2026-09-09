#!/usr/bin/env python3
"""
Check Status Action

Check the status of one or more jobs.
"""

import sys
import os
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from phoenix_client import PhoenixScannerClient, console
from utils.config import load_config
from rich.table import Table


def main():
    parser = argparse.ArgumentParser(description='Check job status')
    
    parser.add_argument('--job-id', help='Single job ID to check')
    parser.add_argument('--list', action='store_true', help='List all jobs')
    parser.add_argument('--status', choices=['pending', 'queued', 'processing', 'completed', 'failed'],
                       help='Filter by status')
    parser.add_argument('--wait', action='store_true', help='Wait for job completion')
    parser.add_argument('--stream', action='store_true', help='Stream logs')
    parser.add_argument('--config', help='Config file')
    parser.add_argument('--verbose', action='store_true')
    
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        api_url = config.get('api_url') or os.getenv('PHOENIX_SCANNER_API_URL')
        api_key = config.get('api_key') or os.getenv('PHOENIX_SCANNER_API_KEY')
        
        if not api_url or not api_key:
            console.print("[red]Error:[/red] API URL and key required")
            sys.exit(1)
        
        client = PhoenixScannerClient(
            api_url=api_url,
            api_key=api_key,
            verbose=args.verbose
        )
        
        if args.list:
            # List jobs
            result = client.list_jobs(status=args.status)
            
            table = Table(title="Jobs")
            table.add_column("Job ID", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Progress", style="green")
            table.add_column("File", style="white")
            
            for job in result['jobs']:
                table.add_row(
                    job['job_id'][:12] + "...",
                    job['status'],
                    f"{job['progress']:.0f}%",
                    job['filename']
                )
            
            console.print(table)
            console.print(f"\nTotal: {result['total']} jobs")
        
        elif args.job_id:
            # Check specific job
            if args.stream:
                import asyncio
                asyncio.run(client.stream_logs(args.job_id))
            elif args.wait:
                status = client.wait_for_completion(args.job_id)
                console.print(f"\n[green]✓[/green] Job {status['status']}")
                if status['status'] == 'completed':
                    console.print(f"  Assets: {status.get('assets_imported', 0)}")
                    console.print(f"  Vulnerabilities: {status.get('vulnerabilities_imported', 0)}")
            else:
                status = client.get_job_status(args.job_id)
                console.print(f"Job ID: {status['job_id']}")
                console.print(f"Status: {status['status']}")
                console.print(f"Progress: {status['progress']:.1f}%")
                console.print(f"File: {status['filename']}")
                
                if status['status'] == 'completed':
                    console.print(f"Assets: {status.get('assets_imported', 0)}")
                    console.print(f"Vulnerabilities: {status.get('vulnerabilities_imported', 0)}")
                elif status['status'] == 'failed':
                    console.print(f"Error: {status.get('error_message', 'Unknown')}")
        else:
            console.print("[yellow]Specify --job-id or --list[/yellow]")
            sys.exit(1)
        
        sys.exit(0)
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()



