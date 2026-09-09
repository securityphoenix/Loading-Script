#!/usr/bin/env python3
"""
Phoenix Multi-Scanner Import Script
Imports scan results from multiple scanner types (Aqua, Snyk, Trivy) to Phoenix Security Platform.
Reads credentials from config.ini and prompts for client name to generate scan targets.
"""

import requests
from requests.auth import HTTPBasicAuth
import json
import os
import sys
import configparser
import time
from pathlib import Path

class PhoenixImporter:
    def __init__(self, config_file='config.ini'):
        """Initialize the importer with configuration."""
        self.config = configparser.ConfigParser()
        self.script_dir = Path(__file__).parent
        config_path = self.script_dir / config_file
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        self.config.read(config_path)
        
        # Load Phoenix API configuration
        self.api_url = self.config.get('phoenix', 'api_url')
        self.client_id = self.config.get('phoenix', 'client_id')
        self.client_secret = self.config.get('phoenix', 'client_secret')
        
        # Load scan file paths
        self.aqua_file = self.config.get('scan_files', 'aqua_file')
        self.snyk_file = self.config.get('scan_files', 'snyk_file')
        self.trivy_file = self.config.get('scan_files', 'trivy_file')
        
        # Load scan settings
        self.import_type = self.config.get('scan_settings', 'import_type', fallback='new')
        self.auto_import = self.config.getboolean('scan_settings', 'auto_import', fallback=True)
        
        self.token = None
        self.client_name = None
    
    def get_access_token(self):
        """
        Obtain an access token from the Phoenix API using client credentials.
        
        :return: Access token string if successful, None otherwise
        """
        url = f"{self.api_url}/v1/auth/access_token"
        
        print(f"Authenticating with Phoenix API...")
        response = requests.get(url, auth=HTTPBasicAuth(self.client_id, self.client_secret))
        
        if response.status_code == 200:
            self.token = response.json()['token']
            print("✓ Authentication successful")
            return self.token
        else:
            print(f"✗ Authentication failed (Status: {response.status_code})")
            print(f"Error: {response.text}")
            return None
    
    def send_results(self, file_path, scan_type, assessment_name, scan_target):
        """
        Send scan results to Phoenix API.
        
        :param file_path: Path to the scan result file
        :param scan_type: Type of scan (e.g., 'Aqua Scan', 'Snyk Scan')
        :param assessment_name: Name for the assessment
        :param scan_target: Target identifier (container name, repository, etc.)
        :return: True if successful, False otherwise
        """
        if self.token is None:
            print("✗ No authentication token. Please authenticate first.")
            return False
        
        # Resolve file path relative to script directory
        full_path = self.script_dir / file_path
        
        # Check if file exists
        if not full_path.exists():
            print(f"✗ Error: File '{file_path}' not found at {full_path}")
            return False
        
        url = f"{self.api_url}/v1/import/assets/file/translate"
        
        headers = {
            'Authorization': f'Bearer {self.token}'
        }
        
        try:
            with open(full_path, 'rb') as file:
                files = {
                    'file': (os.path.basename(file_path), file, 'application/octet-stream')
                }
                data = {
                    'scanType': scan_type,
                    'assessmentName': assessment_name,
                    'importType': self.import_type,
                    'scanTarget': scan_target,
                    'autoImport': 'true' if self.auto_import else 'false'
                }
                
                print(f"\n→ Importing {scan_type}...")
                print(f"  Assessment: {assessment_name}")
                print(f"  Target: {scan_target}")
                
                response = requests.post(url, headers=headers, files=files, data=data)
                
                if response.status_code == 200:
                    result = response.json()
                    print(f"✓ Import successful (ID: {result.get('id', 'N/A')})")
                    print(f"  Status: {result.get('status', 'N/A')}")
                    return True
                else:
                    print(f"✗ Import failed (Status: {response.status_code})")
                    print(f"  Response: {response.text}")
                    return False
                    
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            return False
    
    def prompt_client_name(self):
        """Prompt user for client name."""
        print("\n" + "="*60)
        print("Phoenix Multi-Scanner Import")
        print("="*60)
        
        while True:
            client_name = input("\nEnter client name (e.g., TV, EPIC, Q2): ").strip()
            if client_name:
                self.client_name = client_name
                print(f"✓ Client name set to: {client_name}")
                return client_name
            else:
                print("✗ Client name cannot be empty. Please try again.")
    
    def generate_scan_targets(self, scanner_type, component_type=None):
        """
        Generate scan targets based on client name and scanner type.
        
        :param scanner_type: Type of scanner ('aqua', 'snyk', 'trivy')
        :param component_type: For aqua scans: 'backend' or 'frontend'
        :return: List of tuples (assessment_name, scan_target)
        """
        if not self.client_name:
            raise ValueError("Client name not set. Call prompt_client_name() first.")
        
        client_lower = self.client_name.lower()
        client_upper = self.client_name.upper()
        
        targets = []
        
        if scanner_type == 'aqua':
            # Aqua container scan targets - backend
            if component_type == 'backend' or component_type is None:
                targets = [
                    (f'Container_pipeline_{client_upper}_backend_1', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_backend:latest'),
                    (f'Container_pipeline_{client_upper}_backend_2', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_backend:3_2'),
                    (f'Container_pipeline_{client_upper}_backend_3', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_backend:3_1'),
                    (f'Container_pipeline_{client_upper}_backend_4', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_backend:3_3'),
                    (f'Container_pipeline_{client_upper}_backend_5', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_backend:3_0'),
                ]
            # Aqua container scan targets - frontend
            elif component_type == 'frontend':
                targets = [
                    (f'Container_pipeline_{client_upper}_frontend_6', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_frontend:latest'),
                    (f'Container_pipeline_{client_upper}_frontend_7', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_frontend:3_2'),
                    (f'Container_pipeline_{client_upper}_frontend_8', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_frontend:3_1'),
                    (f'Container_pipeline_{client_upper}_frontend_9', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_frontend:3_3'),
                    (f'Container_pipeline_{client_upper}_frontend_10', f'TST.PHX.TEST/POC1_CD_{client_upper}_poc_app_frontend:3_0'),
                ]
        elif scanner_type == 'snyk':
            # Snyk repository scan targets
            targets = [
                (f'Snyk_{client_upper}_Frontend', f'com.{client_lower}.phx.test/Frontend/subrepo:latest'),
                (f'Snyk_{client_upper}_Backend', f'com.{client_lower}.phx.test/backend/subrepo2:latest'),
            ]
        elif scanner_type == 'trivy':
            # Trivy scan targets
            targets = [
                (f'Trivy_{client_upper}_Container', f'com.{client_lower}.tests/example:latest'),
            ]
        
        return targets
    
    def run_aqua_import(self):
        """Import Aqua scan results for both backend and frontend."""
        print("\n" + "="*60)
        print("Starting Aqua Scan Import (Backend + Frontend)")
        print("="*60)
        
        total_success = 0
        total_targets = 0
        
        # Import Backend containers
        print("\n" + "-"*60)
        print("Phase 1: Backend Containers")
        print("-"*60)
        
        backend_targets = self.generate_scan_targets('aqua', 'backend')
        backend_success = 0
        
        for assessment_name, scan_target in backend_targets:
            if self.send_results(self.aqua_file, 'Aqua Scan', assessment_name, scan_target):
                backend_success += 1
        
        total_success += backend_success
        total_targets += len(backend_targets)
        
        print(f"\nBackend Import: {backend_success}/{len(backend_targets)} successful")
        
        # Pause between backend and frontend imports
        pause_time = 3
        print(f"\n⏸️  Pausing for {pause_time} seconds before frontend import...")
        time.sleep(pause_time)
        
        # Import Frontend containers
        print("\n" + "-"*60)
        print("Phase 2: Frontend Containers")
        print("-"*60)
        
        frontend_targets = self.generate_scan_targets('aqua', 'frontend')
        frontend_success = 0
        
        for assessment_name, scan_target in frontend_targets:
            if self.send_results(self.aqua_file, 'Aqua Scan', assessment_name, scan_target):
                frontend_success += 1
        
        total_success += frontend_success
        total_targets += len(frontend_targets)
        
        print(f"\nFrontend Import: {frontend_success}/{len(frontend_targets)} successful")
        print(f"\nTotal Aqua Import Summary: {total_success}/{total_targets} successful")
        print(f"  - Backend: {backend_success}/{len(backend_targets)}")
        print(f"  - Frontend: {frontend_success}/{len(frontend_targets)}")
        
        return total_success == total_targets
    
    def run_snyk_import(self):
        """Import Snyk scan results."""
        print("\n" + "-"*60)
        print("Starting Snyk Scan Import")
        print("-"*60)
        
        targets = self.generate_scan_targets('snyk')
        success_count = 0
        
        for assessment_name, scan_target in targets:
            if self.send_results(self.snyk_file, 'Snyk Scan', assessment_name, scan_target):
                success_count += 1
        
        print(f"\nSnyk Import Summary: {success_count}/{len(targets)} successful")
        return success_count == len(targets)
    
    def run_trivy_import(self):
        """Import Trivy scan results."""
        print("\n" + "-"*60)
        print("Starting Trivy Scan Import")
        print("-"*60)
        
        targets = self.generate_scan_targets('trivy')
        success_count = 0
        
        for assessment_name, scan_target in targets:
            if self.send_results(self.trivy_file, 'Trivy Scan', assessment_name, scan_target):
                success_count += 1
        
        print(f"\nTrivy Import Summary: {success_count}/{len(targets)} successful")
        return success_count == len(targets)
    
    def run_all_imports(self):
        """Run all scanner imports."""
        # Authenticate
        if not self.get_access_token():
            print("\n✗ Authentication failed. Exiting.")
            return False
        
        # Prompt for client name
        self.prompt_client_name()
        
        # Run imports
        aqua_success = self.run_aqua_import()
        snyk_success = self.run_snyk_import()
        trivy_success = self.run_trivy_import()
        
        # Summary
        print("\n" + "="*60)
        print("Import Summary")
        print("="*60)
        print(f"Aqua Scan:  {'✓ Success (10 assessments)' if aqua_success else '✗ Failed'}")
        print(f"  - Backend:  5 assessments")
        print(f"  - Frontend: 5 assessments")
        print(f"Snyk Scan:  {'✓ Success (2 assessments)' if snyk_success else '✗ Failed'}")
        print(f"Trivy Scan: {'✓ Success (1 assessment)' if trivy_success else '✗ Failed'}")
        print(f"\nTotal Assessments Imported: 13")
        print("="*60)
        
        return aqua_success and snyk_success and trivy_success

def main():
    """Main entry point."""
    try:
        importer = PhoenixImporter()
        
        # Check if user wants to run specific scanner or all
        if len(sys.argv) > 1:
            scanner = sys.argv[1].lower()
            
            if not importer.get_access_token():
                sys.exit(1)
            
            importer.prompt_client_name()
            
            if scanner == 'aqua':
                success = importer.run_aqua_import()
            elif scanner == 'snyk':
                success = importer.run_snyk_import()
            elif scanner == 'trivy':
                success = importer.run_trivy_import()
            else:
                print(f"Unknown scanner type: {scanner}")
                print("Usage: python phoenix_multi_import.py [aqua|snyk|trivy]")
                sys.exit(1)
        else:
            # Run all imports
            success = importer.run_all_imports()
        
        sys.exit(0 if success else 1)
        
    except FileNotFoundError as e:
        print(f"\n✗ Error: {e}")
        print("\nPlease ensure config.ini exists with the required settings.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

