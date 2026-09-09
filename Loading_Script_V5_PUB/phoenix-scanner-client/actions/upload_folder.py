#!/usr/bin/env python3
"""
Upload Folder Action

Uploads all scanner files from a folder with pattern matching.
"""

import sys
import os
import argparse
import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from phoenix_client import PhoenixScannerClient, console, validate_scanner_type
from utils.config import load_config
from utils.report import generate_report


def main():
    parser = argparse.ArgumentParser(description='Upload all scanner files from a folder')
    
    parser.add_argument('--folder', required=True, help='Folder containing scanner files')
    parser.add_argument('--pattern', default='*.json', help='File pattern (default: *.json)')
    parser.add_argument('--scanner-type', default='auto', help='Scanner type')
    parser.add_argument('--recursive', action='store_true', help='Search recursively')
    parser.add_argument('--concurrent', type=int, default=3, help='Concurrent uploads')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--wait', action='store_true', help='Wait for completion')
    parser.add_argument('--report', help='Report output file')
    parser.add_argument('--verbose', action='store_true')
    
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        api_url = config.get('api_url') or os.getenv('PHOENIX_SCANNER_API_URL')
        api_key = config.get('api_key') or os.getenv('PHOENIX_SCANNER_API_KEY')
        
        if not api_url or not api_key:
            console.print("[red]Error:[/red] API URL and key required")
            sys.exit(1)
        
        # Find files
        folder = Path(args.folder)
        if args.recursive:
            pattern = f"**/{args.pattern}"
        else:
            pattern = args.pattern
        
        files = list(folder.glob(pattern))
        
        if not files:
            console.print(f"[yellow]No files found matching pattern:[/yellow] {args.pattern}")
            sys.exit(0)
        
        console.print(f"[cyan]Found {len(files)} file(s)[/cyan]")
        
        client = PhoenixScannerClient(
            api_url=api_url,
            api_key=api_key,
            phoenix_client_id=config.get('phoenix_client_id') or os.getenv('PHOENIX_CLIENT_ID'),
            phoenix_client_secret=config.get('phoenix_client_secret') or os.getenv('PHOENIX_CLIENT_SECRET'),
            phoenix_api_url=config.get('phoenix_api_url') or os.getenv('PHOENIX_API_URL'),
            verbose=args.verbose
        )
        
        scanner_type = validate_scanner_type(args.scanner_type)
        
        results = client.upload_batch(
            file_paths=[str(f) for f in files],
            scanner_type=scanner_type,
            concurrent=args.concurrent
        )
        
        # Wait if requested
        if args.wait:
            console.print("\n[cyan]Waiting for completion...[/cyan]")
            for result in results:
                if result['success']:
                    try:
                        final_status = client.wait_for_completion(result['job_id'], show_progress=False)
                        result['final_status'] = final_status['status']
                    except Exception as e:
                        result['final_status'] = 'error'
        
        # Summary
        successful = sum(1 for r in results if r['success'])
        console.print(f"\n[cyan]Summary:[/cyan] {successful}/{len(results)} successful")
        
        if args.report:
            generate_report(results, args.report)
        
        sys.exit(0 if successful == len(results) else 1)
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()



