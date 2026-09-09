#!/usr/bin/env python3
"""
Upload Batch Files Action

Uploads multiple scanner output files using a batch configuration file.
Supports sequential and concurrent processing with progress tracking.
"""

import sys
import os
import argparse
import yaml
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phoenix_client import PhoenixScannerClient, console, validate_scanner_type
from utils.config import load_config
from utils.report import generate_report


def load_batch_config(config_file: str) -> List[Dict[str, Any]]:
    """Load batch configuration from YAML file"""
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    return config.get('batches', [])


def main():
    parser = argparse.ArgumentParser(
        description='Upload multiple scanner files in batch to Phoenix Scanner Service',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload batch from config file
  python upload_batch.py --batch-config batch.yaml

  # Upload with custom concurrency
  python upload_batch.py --batch-config batch.yaml --concurrent 5

  # Upload with wait for completion
  python upload_batch.py --batch-config batch.yaml --wait
        """
    )
    
    # Required arguments
    parser.add_argument('--batch-config', required=True, help='Path to batch configuration file')
    
    # Client configuration
    parser.add_argument('--config', help='Path to client config file (default: config.yaml)')
    parser.add_argument('--api-url', help='API URL (overrides config)')
    parser.add_argument('--api-key', help='API key (overrides config)')
    
    # Processing options
    parser.add_argument('--concurrent', type=int, default=3, help='Number of concurrent uploads (default: 3)')
    parser.add_argument('--wait', action='store_true', help='Wait for all jobs to complete')
    parser.add_argument('--timeout', type=int, default=3600, help='Job timeout in seconds')
    parser.add_argument('--delay', type=int, default=0, help='Delay between batches in seconds')
    
    # Output options
    parser.add_argument('--report', help='Save report to file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        batch_config = load_batch_config(args.batch_config)
        
        # Override with command line arguments
        api_url = args.api_url or config.get('api_url') or os.getenv('PHOENIX_SCANNER_API_URL')
        api_key = args.api_key or config.get('api_key') or os.getenv('PHOENIX_SCANNER_API_KEY')
        
        if not api_url or not api_key:
            console.print("[red]Error:[/red] API URL and API key are required")
            sys.exit(1)
        
        # Phoenix credentials from config
        phoenix_client_id = config.get('phoenix_client_id') or os.getenv('PHOENIX_CLIENT_ID')
        phoenix_client_secret = config.get('phoenix_client_secret') or os.getenv('PHOENIX_CLIENT_SECRET')
        phoenix_api_url = config.get('phoenix_api_url') or os.getenv('PHOENIX_API_URL')
        
        # Initialize client
        client = PhoenixScannerClient(
            api_url=api_url,
            api_key=api_key,
            phoenix_client_id=phoenix_client_id,
            phoenix_client_secret=phoenix_client_secret,
            phoenix_api_url=phoenix_api_url,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        console.print(f"[cyan]Starting batch upload[/cyan]")
        console.print(f"  Batches: {len(batch_config)}")
        console.print(f"  Concurrency: {args.concurrent}")
        
        all_results = []
        
        for i, batch in enumerate(batch_config, 1):
            batch_name = batch.get('name', f'Batch {i}')
            console.print(f"\n[cyan]═══ {batch_name} ({i}/{len(batch_config)}) ═══[/cyan]")
            
            file_paths = batch.get('files', [])
            if not file_paths:
                console.print("[yellow]Warning:[/yellow] No files specified in batch")
                continue
            
            # Get batch-specific settings
            scanner_type = validate_scanner_type(batch.get('scanner_type', 'auto'))
            asset_type = batch.get('asset_type')
            import_type = batch.get('import_type', 'new')
            
            console.print(f"  Files: {len(file_paths)}")
            console.print(f"  Scanner: {scanner_type}")
            
            # Upload files
            results = client.upload_batch(
                file_paths=file_paths,
                scanner_type=scanner_type,
                asset_type=asset_type,
                import_type=import_type,
                concurrent=args.concurrent
            )
            
            # Add batch name to results
            for result in results:
                result['batch'] = batch_name
            
            all_results.extend(results)
            
            # Summary
            successful = sum(1 for r in results if r['success'])
            failed = len(results) - successful
            console.print(f"\n  ✓ Successful: {successful}/{len(results)}")
            if failed > 0:
                console.print(f"  ✗ Failed: {failed}")
            
            # Delay between batches
            if i < len(batch_config) and args.delay > 0:
                import time
                console.print(f"  Waiting {args.delay}s before next batch...")
                time.sleep(args.delay)
        
        # Wait for completion if requested
        if args.wait:
            console.print("\n[cyan]Waiting for all jobs to complete...[/cyan]")
            for result in all_results:
                if result['success']:
                    try:
                        final_status = client.wait_for_completion(
                            result['job_id'],
                            show_progress=args.verbose
                        )
                        result['final_status'] = final_status['status']
                        result['assets_imported'] = final_status.get('assets_imported', 0)
                        result['vulnerabilities_imported'] = final_status.get('vulnerabilities_imported', 0)
                    except Exception as e:
                        result['final_status'] = 'error'
                        result['error'] = str(e)
        
        # Overall summary
        console.print("\n[cyan]═══ Overall Summary ═══[/cyan]")
        total_successful = sum(1 for r in all_results if r['success'])
        total_failed = len(all_results) - total_successful
        
        console.print(f"  Total files: {len(all_results)}")
        console.print(f"  ✓ Successful: {total_successful}")
        console.print(f"  ✗ Failed: {total_failed}")
        
        if len(all_results) > 0:
            success_rate = total_successful / len(all_results) * 100
            console.print(f"  Success rate: {success_rate:.1f}%")
        
        # Generate report
        if args.report:
            generate_report(all_results, args.report)
            console.print(f"\n[green]✓[/green] Report saved to: {args.report}")
        
        # Exit code based on results
        sys.exit(0 if total_failed == 0 else 1)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()



