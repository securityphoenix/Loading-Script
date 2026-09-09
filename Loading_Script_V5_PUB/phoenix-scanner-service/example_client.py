#!/usr/bin/env python3
"""
Example Python client for Phoenix Scanner Service

This script demonstrates how to:
1. Upload a scanner file
2. Monitor progress via WebSocket
3. Check final status
4. Handle errors
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

import requests
import websockets


class PhoenixScannerClient:
    """Python client for Phoenix Scanner Service API"""
    
    def __init__(
        self, 
        api_url: str = "http://localhost:8000",
        api_key: str = "your-api-key",
        phoenix_client_id: Optional[str] = None,
        phoenix_client_secret: Optional[str] = None,
        phoenix_api_url: Optional[str] = None
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.phoenix_client_id = phoenix_client_id
        self.phoenix_client_secret = phoenix_client_secret
        self.phoenix_api_url = phoenix_api_url
        
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key})
    
    def upload_file(
        self,
        file_path: str,
        scanner_type: str = "auto",
        **kwargs
    ) -> dict:
        """
        Upload a scanner file for processing
        
        Args:
            file_path: Path to scanner output file
            scanner_type: Scanner type (auto, trivy, grype, etc.)
            **kwargs: Additional parameters (assessment_name, asset_type, etc.)
        
        Returns:
            dict: Job information with job_id and websocket_url
        """
        url = f"{self.api_url}/api/v1/upload"
        
        # Prepare form data
        data = {
            "scanner_type": scanner_type,
        }
        
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
            files = {"file": (Path(file_path).name, f)}
            
            print(f"📤 Uploading {file_path}...")
            response = self.session.post(url, files=files, data=data)
            response.raise_for_status()
        
        result = response.json()
        print(f"✅ Upload successful!")
        print(f"   Job ID: {result['job_id']}")
        print(f"   Status: {result['status']}")
        
        return result
    
    def get_job_status(self, job_id: str) -> dict:
        """
        Get current status of a job
        
        Args:
            job_id: Job identifier
        
        Returns:
            dict: Job status information
        """
        url = f"{self.api_url}/api/v1/jobs/{job_id}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def list_jobs(
        self, 
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 50
    ) -> dict:
        """
        List all jobs with optional filtering
        
        Args:
            status: Filter by status (pending, processing, completed, failed)
            page: Page number
            page_size: Items per page
        
        Returns:
            dict: List of jobs with pagination info
        """
        url = f"{self.api_url}/api/v1/jobs"
        params = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or processing job
        
        Args:
            job_id: Job identifier
        
        Returns:
            bool: True if cancelled successfully
        """
        url = f"{self.api_url}/api/v1/jobs/{job_id}"
        response = self.session.delete(url)
        return response.status_code == 204
    
    def wait_for_completion(
        self,
        job_id: str,
        poll_interval: int = 5,
        timeout: int = 3600
    ) -> dict:
        """
        Wait for job to complete by polling status
        
        Args:
            job_id: Job identifier
            poll_interval: Seconds between status checks
            timeout: Maximum time to wait
        
        Returns:
            dict: Final job status
        """
        start_time = time.time()
        
        print(f"⏳ Waiting for job {job_id} to complete...")
        
        while True:
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Job did not complete within {timeout} seconds")
            
            status = self.get_job_status(job_id)
            
            print(f"   Status: {status['status']} - Progress: {status['progress']:.1f}%")
            
            if status['status'] in ['completed', 'failed', 'cancelled']:
                return status
            
            time.sleep(poll_interval)
    
    async def stream_logs(self, job_id: str, callback=None):
        """
        Stream job logs in real-time via WebSocket
        
        Args:
            job_id: Job identifier
            callback: Optional callback function for each message
        """
        # Convert http to ws
        ws_url = self.api_url.replace('http://', 'ws://').replace('https://', 'wss://')
        uri = f"{ws_url}/ws/{job_id}"
        
        print(f"🔌 Connecting to WebSocket: {uri}")
        
        try:
            async with websockets.connect(uri) as websocket:
                print("✅ Connected! Streaming logs...")
                print("-" * 60)
                
                async for message in websocket:
                    data = json.loads(message)
                    
                    # Call callback if provided
                    if callback:
                        should_continue = callback(data)
                        if not should_continue:
                            break
                        continue
                    
                    # Default message handling
                    msg_type = data['type']
                    
                    if msg_type == 'connected':
                        print(f"📡 {data['data']['message']}")
                    
                    elif msg_type == 'log':
                        level = data['data']['level']
                        msg = data['data']['message']
                        
                        # Color code by level
                        if level == 'ERROR':
                            print(f"🔴 [{level}] {msg}")
                        elif level == 'WARNING':
                            print(f"🟡 [{level}] {msg}")
                        else:
                            print(f"   [{level}] {msg}")
                    
                    elif msg_type == 'progress':
                        progress = data['data']['progress']
                        step = data['data'].get('current_step', 'Processing')
                        print(f"📊 Progress: {progress:.1f}% - {step}")
                    
                    elif msg_type == 'complete':
                        print("-" * 60)
                        print("✅ Job completed successfully!")
                        print(f"   Assets imported: {data['data'].get('assets_imported', 0)}")
                        print(f"   Vulnerabilities: {data['data'].get('vulnerabilities_imported', 0)}")
                        print(f"   Assessment: {data['data'].get('assessment_name', 'N/A')}")
                        break
                    
                    elif msg_type == 'error':
                        print("-" * 60)
                        print(f"❌ Job failed: {data['data'].get('error_message', 'Unknown error')}")
                        break
                    
                    elif msg_type == 'heartbeat':
                        # Ignore heartbeats
                        pass
        
        except Exception as e:
            print(f"❌ WebSocket error: {e}")
            raise


def example_upload_and_wait(client: PhoenixScannerClient, file_path: str):
    """Example: Upload file and wait for completion (polling)"""
    print("\n" + "=" * 60)
    print("Example 1: Upload and Wait (Polling)")
    print("=" * 60)
    
    # Upload file
    result = client.upload_file(
        file_path=file_path,
        scanner_type="auto",
        assessment_name="Test Assessment"
    )
    
    job_id = result['job_id']
    
    # Wait for completion
    final_status = client.wait_for_completion(job_id)
    
    # Print results
    print("\n📋 Final Results:")
    print(f"   Status: {final_status['status']}")
    
    if final_status['status'] == 'completed':
        print(f"   Assets: {final_status['assets_imported']}")
        print(f"   Vulnerabilities: {final_status['vulnerabilities_imported']}")
        print(f"   Assessment: {final_status['assessment_name']}")
    else:
        print(f"   Error: {final_status.get('error_message', 'Unknown')}")


async def example_upload_and_stream(client: PhoenixScannerClient, file_path: str):
    """Example: Upload file and stream logs via WebSocket"""
    print("\n" + "=" * 60)
    print("Example 2: Upload and Stream Logs (WebSocket)")
    print("=" * 60)
    
    # Upload file
    result = client.upload_file(
        file_path=file_path,
        scanner_type="auto"
    )
    
    job_id = result['job_id']
    
    # Wait a moment for job to start
    await asyncio.sleep(1)
    
    # Stream logs
    await client.stream_logs(job_id)


def example_list_jobs(client: PhoenixScannerClient):
    """Example: List recent jobs"""
    print("\n" + "=" * 60)
    print("Example 3: List Recent Jobs")
    print("=" * 60)
    
    # Get completed jobs
    result = client.list_jobs(status="completed", page=1, page_size=10)
    
    print(f"\n📋 Found {result['total']} completed jobs")
    print(f"   Showing page {result['page']} ({len(result['jobs'])} jobs)\n")
    
    for job in result['jobs']:
        print(f"   • {job['job_id']}")
        print(f"     File: {job['filename']}")
        print(f"     Scanner: {job['scanner_type']}")
        print(f"     Assets: {job['assets_imported']}")
        print(f"     Created: {job['created_at']}")
        print()


def main():
    """Main example runner"""
    
    # Configuration
    API_URL = "http://localhost:8000"
    API_KEY = "your-api-key"
    
    # Phoenix credentials (optional - can be set per upload)
    PHOENIX_CLIENT_ID = "your-phoenix-client-id"
    PHOENIX_CLIENT_SECRET = "your-phoenix-secret"
    PHOENIX_API_URL = "https://phoenix.example.com/api"
    
    # Create client
    client = PhoenixScannerClient(
        api_url=API_URL,
        api_key=API_KEY,
        phoenix_client_id=PHOENIX_CLIENT_ID,
        phoenix_client_secret=PHOENIX_CLIENT_SECRET,
        phoenix_api_url=PHOENIX_API_URL
    )
    
    # Check if file provided
    if len(sys.argv) < 2:
        print("Usage: python example_client.py <scanner-file.json>")
        print("\nRunning list jobs example only...")
        example_list_jobs(client)
        sys.exit(0)
    
    file_path = sys.argv[1]
    
    if not Path(file_path).exists():
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    # Run examples
    try:
        # Example 1: Upload and poll
        example_upload_and_wait(client, file_path)
        
        # Example 2: Upload and stream (async)
        print("\n" + "=" * 60)
        print("Example 2: Upload and Stream (press Ctrl+C to skip)")
        print("=" * 60)
        input("Press Enter to continue or Ctrl+C to skip...")
        asyncio.run(example_upload_and_stream(client, file_path))
        
        # Example 3: List jobs
        example_list_jobs(client)
        
        print("\n✅ All examples completed!")
    
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()



