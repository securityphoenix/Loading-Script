#!/usr/bin/env python3
"""
Upload Single File Action

Uploads a single scanner output file to the Phoenix Scanner Service.
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phoenix_client import PhoenixScannerClient, console, validate_scanner_type
from utils.config import load_config
from utils.report import generate_report


def main():
    parser = argparse.ArgumentParser(
        description='Upload a single scanner file to Phoenix Scanner Service',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload with auto-detection
  python upload_single.py --file scan.json

  # Upload with specific scanner type
  python upload_single.py --file trivy-results.json --scanner-type trivy

  # Upload with custom assessment
  python upload_single.py --file scan.json --scanner-type grype \\
      --assessment "Q4-2025-Container-Scan"
        """
    )
    
    # Required arguments
    parser.add_argument('--file', required=True, help='Path to scanner output file')
    
    # Scanner configuration
    parser.add_argument('--scanner-type', default='auto', help='Scanner type (default: auto)')
    parser.add_argument('--asset-type', choices=['INFRA', 'WEB', 'CLOUD', 'CONTAINER', 'CODE', 'BUILD'],
                       help='Asset type override')
    parser.add_argument('--assessment', help='Assessment name (auto-generated if not provided)')
    parser.add_argument('--import-type', choices=['new', 'merge', 'delta'], default='new',
                       help='Import type (default: new)')
    
    # Client configuration
    parser.add_argument('--config', help='Path to config file (default: config.yaml)')
    parser.add_argument('--api-url', help='API URL (overrides config)')
    parser.add_argument('--api-key', help='API key (overrides config)')
    
    # Phoenix configuration (optional overrides)
    parser.add_argument('--phoenix-client-id', help='Phoenix client ID')
    parser.add_argument('--phoenix-client-secret', help='Phoenix client secret')
    parser.add_argument('--phoenix-api-url', help='Phoenix API URL')
    
    # Processing options
    parser.add_argument('--no-batching', action='store_true', help='Disable intelligent batching')
    parser.add_argument('--no-fix-data', action='store_true', help='Disable automatic data fixing')
    parser.add_argument('--webhook-url', help='Webhook URL for status updates')
    
    # Behavior options
    parser.add_argument('--wait', action='store_true', help='Wait for job completion')
    parser.add_argument('--stream-logs', action='store_true', help='Stream logs via WebSocket')
    parser.add_argument('--poll-interval', type=int, default=5, help='Status poll interval in seconds')
    parser.add_argument('--timeout', type=int, default=3600, help='Job timeout in seconds')
    
    # Output options
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--report', help='Save report to file')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override with command line arguments
        api_url = args.api_url or config.get('api_url') or os.getenv('PHOENIX_SCANNER_API_URL')
        api_key = args.api_key or config.get('api_key') or os.getenv('PHOENIX_SCANNER_API_KEY')
        
        if not api_url or not api_key:
            console.print("[red]Error:[/red] API URL and API key are required")
            console.print("Provide via --api-url/--api-key, config file, or environment variables")
            sys.exit(1)
        
        # Phoenix credentials
        phoenix_client_id = args.phoenix_client_id or config.get('phoenix_client_id') or os.getenv('PHOENIX_CLIENT_ID')
        phoenix_client_secret = args.phoenix_client_secret or config.get('phoenix_client_secret') or os.getenv('PHOENIX_CLIENT_SECRET')
        phoenix_api_url = args.phoenix_api_url or config.get('phoenix_api_url') or os.getenv('PHOENIX_API_URL')
        
        # Validate scanner type
        scanner_type = validate_scanner_type(args.scanner_type)
        
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
        
        # Upload file
        console.print(f"[cyan]Uploading file:[/cyan] {args.file}")
        console.print(f"[cyan]Scanner type:[/cyan] {scanner_type}")
        
        result = client.upload_file(
            file_path=args.file,
            scanner_type=scanner_type,
            asset_type=args.asset_type,
            assessment_name=args.assessment,
            import_type=args.import_type,
            enable_batching=not args.no_batching,
            fix_data=not args.no_fix_data,
            webhook_url=args.webhook_url
        )
        
        job_id = result['job_id']
        console.print(f"[green]✓[/green] Upload successful!")
        console.print(f"  Job ID: {job_id}")
        console.print(f"  Status: {result['status']}")
        
        # Wait for completion if requested
        if args.wait or args.stream_logs:
            if args.stream_logs:
                import asyncio
                final_status = asyncio.run(client.stream_logs(job_id))
            else:
                final_status = client.wait_for_completion(job_id, poll_interval=args.poll_interval)
            
            # Display final results
            if final_status['status'] == 'completed':
                console.print("\n[green]✓ Job completed successfully![/green]")
                console.print(f"  Assets imported: {final_status.get('assets_imported', 0)}")
                console.print(f"  Vulnerabilities: {final_status.get('vulnerabilities_imported', 0)}")
                console.print(f"  Assessment: {final_status.get('assessment_name', 'N/A')}")
                
                # Generate report if requested
                if args.report:
                    generate_report([{
                        'file': args.file,
                        'job_id': job_id,
                        'status': 'completed',
                        'success': True,
                        **final_status
                    }], args.report)
                
                sys.exit(0)
            else:
                console.print(f"\n[red]✗ Job failed[/red]")
                console.print(f"  Error: {final_status.get('error_message', 'Unknown error')}")
                sys.exit(1)
        else:
            console.print(f"\n[cyan]Use this command to check status:[/cyan]")
            console.print(f"  python actions/check_status.py --job-id {job_id}")
            sys.exit(0)
    
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



