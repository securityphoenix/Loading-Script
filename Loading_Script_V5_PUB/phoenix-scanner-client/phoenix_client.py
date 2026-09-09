#!/usr/bin/env python3
"""
Phoenix Scanner API Client

A robust, production-ready client for the Phoenix Scanner Service API.
Supports single file uploads, batch processing, and folder scanning with
real-time progress tracking and comprehensive error handling.

Author: Phoenix Security Team
Version: 1.0.0
"""

import os
import sys
import time
import json
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import websockets
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rprint

console = Console()


class PhoenixScannerClient:
    """
    Client for interacting with Phoenix Scanner Service API.
    
    Features:
    - Single file and batch uploads
    - Real-time progress tracking
    - WebSocket log streaming
    - Automatic retry logic
    - CI/CD friendly (exit codes, JSON output)
    """
    
    def __init__(
        self,
        api_url: str,
        api_key: str,
        phoenix_client_id: Optional[str] = None,
        phoenix_client_secret: Optional[str] = None,
        phoenix_api_url: Optional[str] = None,
        timeout: int = 3600,
        max_retries: int = 3,
        verify_ssl: bool = True,
        verbose: bool = False
    ):
        """
        Initialize Phoenix Scanner Client.
        
        Args:
            api_url: Phoenix Scanner Service API URL
            api_key: API key for authentication
            phoenix_client_id: Phoenix Security API client ID (optional)
            phoenix_client_secret: Phoenix Security API client secret (optional)
            phoenix_api_url: Phoenix Security API URL (optional)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Verify SSL certificates
            verbose: Enable verbose logging
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.phoenix_client_id = phoenix_client_id
        self.phoenix_client_secret = phoenix_client_secret
        self.phoenix_api_url = phoenix_api_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key})
        self.session.verify = verify_ssl
        
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check API health status.
        
        Returns:
            Health status response
        """
        try:
            response = self.session.get(
                f"{self.api_url}/api/v1/health",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def upload_file(
        self,
        file_path: str,
        scanner_type: str = "auto",
        asset_type: Optional[str] = None,
        assessment_name: Optional[str] = None,
        import_type: str = "new",
        enable_batching: bool = True,
        fix_data: bool = True,
        webhook_url: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Upload a scanner file for processing.
        
        Args:
            file_path: Path to scanner output file
            scanner_type: Scanner type (auto, trivy, grype, etc.)
            asset_type: Asset type (INFRA, WEB, CLOUD, CONTAINER, CODE, BUILD)
            assessment_name: Assessment name (auto-generated if not provided)
            import_type: Import type (new, merge, delta)
            enable_batching: Enable intelligent batching
            fix_data: Automatically fix data issues
            webhook_url: Webhook URL for status updates
            **kwargs: Additional parameters
        
        Returns:
            Upload response with job_id
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Prepare form data
        data = {
            "scanner_type": scanner_type,
            "import_type": import_type,
            "enable_batching": str(enable_batching).lower(),
            "fix_data": str(fix_data).lower(),
        }
        
        # Add optional parameters
        if asset_type:
            data["asset_type"] = asset_type
        if assessment_name:
            data["assessment_name"] = assessment_name
        if webhook_url:
            data["webhook_url"] = webhook_url
        
        # Add Phoenix credentials if provided
        if self.phoenix_client_id:
            data["phoenix_client_id"] = self.phoenix_client_id
        if self.phoenix_client_secret:
            data["phoenix_client_secret"] = self.phoenix_client_secret
        if self.phoenix_api_url:
            data["phoenix_api_url"] = self.phoenix_api_url
        
        # Add any additional parameters
        data.update(kwargs)
        
        # Prepare file
        with open(file_path, 'rb') as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            
            if self.verbose:
                console.print(f"[cyan]Uploading {file_path.name}...[/cyan]")
            
            # Upload with retry logic
            for attempt in range(self.max_retries):
                try:
                    response = self.session.post(
                        f"{self.api_url}/api/v1/upload",
                        files=files,
                        data=data,
                        timeout=self.timeout
                    )
                    response.raise_for_status()
                    
                    result = response.json()
                    
                    if self.verbose:
                        console.print(f"[green]✓[/green] Upload successful: {result['job_id']}")
                    
                    return result
                
                except requests.exceptions.RequestException as e:
                    if attempt < self.max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff
                        if self.verbose:
                            console.print(f"[yellow]Retry {attempt + 1}/{self.max_retries} after {wait_time}s...[/yellow]")
                        time.sleep(wait_time)
                    else:
                        raise Exception(f"Upload failed after {self.max_retries} attempts: {e}")
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get job status.
        
        Args:
            job_id: Job identifier
        
        Returns:
            Job status response
        """
        response = self.session.get(
            f"{self.api_url}/api/v1/jobs/{job_id}",
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def list_jobs(
        self,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """
        List jobs with optional filtering.
        
        Args:
            status: Filter by status (pending, processing, completed, failed)
            page: Page number
            page_size: Items per page
        
        Returns:
            List of jobs with pagination info
        """
        params = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        
        response = self.session.get(
            f"{self.api_url}/api/v1/jobs",
            params=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a job.
        
        Args:
            job_id: Job identifier
        
        Returns:
            True if cancelled successfully
        """
        response = self.session.delete(
            f"{self.api_url}/api/v1/jobs/{job_id}",
            timeout=30
        )
        return response.status_code == 204
    
    def wait_for_completion(
        self,
        job_id: str,
        poll_interval: int = 5,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        """
        Wait for job to complete by polling status.
        
        Args:
            job_id: Job identifier
            poll_interval: Seconds between status checks
            show_progress: Show progress bar
        
        Returns:
            Final job status
        """
        start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            disable=not show_progress
        ) as progress:
            
            task = progress.add_task(f"Processing {job_id[:12]}...", total=100)
            
            while True:
                status = self.get_job_status(job_id)
                
                current_progress = status.get('progress', 0)
                progress.update(task, completed=current_progress)
                
                if status['status'] in ['completed', 'failed', 'cancelled']:
                    progress.update(task, completed=100)
                    return status
                
                # Check timeout
                if time.time() - start_time > self.timeout:
                    raise TimeoutError(f"Job did not complete within {self.timeout} seconds")
                
                time.sleep(poll_interval)
    
    async def stream_logs(
        self,
        job_id: str,
        show_logs: bool = True
    ) -> Dict[str, Any]:
        """
        Stream job logs via WebSocket.
        
        Args:
            job_id: Job identifier
            show_logs: Print logs to console
        
        Returns:
            Final status
        """
        ws_url = self.api_url.replace('http://', 'ws://').replace('https://', 'wss://')
        uri = f"{ws_url}/ws/{job_id}"
        
        if self.verbose:
            console.print(f"[cyan]Connecting to WebSocket: {uri}[/cyan]")
        
        try:
            async with websockets.connect(uri) as websocket:
                if show_logs:
                    console.print("[green]✓[/green] Connected! Streaming logs...")
                    console.print("─" * 60)
                
                async for message in websocket:
                    data = json.loads(message)
                    msg_type = data['type']
                    
                    if msg_type == 'log' and show_logs:
                        level = data['data']['level']
                        msg = data['data']['message']
                        
                        if level == 'ERROR':
                            console.print(f"[red]✗[/red] {msg}")
                        elif level == 'WARNING':
                            console.print(f"[yellow]⚠[/yellow] {msg}")
                        else:
                            console.print(f"  {msg}")
                    
                    elif msg_type == 'progress' and show_logs:
                        progress = data['data']['progress']
                        step = data['data'].get('current_step', 'Processing')
                        console.print(f"[cyan]◆[/cyan] Progress: {progress:.1f}% - {step}")
                    
                    elif msg_type == 'complete':
                        if show_logs:
                            console.print("─" * 60)
                            console.print("[green]✓[/green] Job completed successfully!")
                            console.print(f"  Assets: {data['data'].get('assets_imported', 0)}")
                            console.print(f"  Vulnerabilities: {data['data'].get('vulnerabilities_imported', 0)}")
                        return data['data']
                    
                    elif msg_type == 'error':
                        if show_logs:
                            console.print("─" * 60)
                            console.print(f"[red]✗[/red] Job failed: {data['data'].get('error_message', 'Unknown error')}")
                        raise Exception(data['data'].get('error_message', 'Unknown error'))
        
        except Exception as e:
            console.print(f"[red]✗[/red] WebSocket error: {e}")
            raise
    
    def upload_batch(
        self,
        file_paths: List[str],
        scanner_type: str = "auto",
        concurrent: int = 3,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Upload multiple files concurrently.
        
        Args:
            file_paths: List of file paths
            scanner_type: Scanner type
            concurrent: Number of concurrent uploads
            **kwargs: Additional parameters for upload_file
        
        Returns:
            List of upload results
        """
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("Uploading files...", total=len(file_paths))
            
            with ThreadPoolExecutor(max_workers=concurrent) as executor:
                future_to_file = {
                    executor.submit(
                        self.upload_file,
                        file_path,
                        scanner_type=scanner_type,
                        **kwargs
                    ): file_path
                    for file_path in file_paths
                }
                
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        results.append({
                            'file': file_path,
                            'success': True,
                            'job_id': result['job_id'],
                            'status': result['status']
                        })
                    except Exception as e:
                        results.append({
                            'file': file_path,
                            'success': False,
                            'error': str(e)
                        })
                    
                    progress.update(task, advance=1)
        
        return results


def validate_scanner_type(scanner_type: str, scanner_list_file: Optional[str] = None) -> str:
    """
    Validate scanner type against known scanners.
    
    Args:
        scanner_type: Scanner type to validate
        scanner_list_file: Path to scanner list file
    
    Returns:
        Validated scanner type
    """
    if scanner_type == "auto":
        return scanner_type
    
    if not scanner_list_file:
        scanner_list_file = Path(__file__).parent / "scanner_list_actual.txt"
    
    if not Path(scanner_list_file).exists():
        console.print(f"[yellow]Warning:[/yellow] Scanner list not found, using '{scanner_type}' without validation")
        return scanner_type
    
    with open(scanner_list_file, 'r') as f:
        valid_scanners = [line.strip() for line in f if line.strip()]
    
    if scanner_type in valid_scanners:
        return scanner_type
    
    # Find close matches
    import difflib
    matches = difflib.get_close_matches(scanner_type, valid_scanners, n=3, cutoff=0.6)
    
    if matches:
        console.print(f"[yellow]Warning:[/yellow] '{scanner_type}' not found. Did you mean:")
        for match in matches:
            console.print(f"  • {match}")
        console.print(f"[yellow]Using '{scanner_type}' anyway...[/yellow]")
    else:
        console.print(f"[yellow]Warning:[/yellow] '{scanner_type}' not in known scanner list")
    
    return scanner_type


