#!/usr/bin/env python3
"""
Phoenix Security Lambda Handler
===============================

Thin Lambda wrapper for the Phoenix Multi-Scanner Import Tool.
Supports two modes:
- Single file processing (triggered by S3 events or direct invocation)
- Orchestrator mode (scans all new/ folders and invokes individual Lambdas)

S3 Folder Structure:
    s3://bucket/scanners/{scanner_name}/new/     - Files to process
    s3://bucket/scanners/{scanner_name}/processed/ - Completed files
    s3://bucket/config/lambda_config.ini         - Configuration
    s3://bucket/metadata/global_tags.yaml        - Global metadata

Author: Phoenix Security
Version: 1.0.0
"""

import json
import logging
import os
import re
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

# Configure logging for CloudWatch
logger = logging.getLogger()
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logger.setLevel(getattr(logging, log_level, logging.INFO))

# S3 client (reused across invocations)
s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')


class LambdaConfig:
    """Lambda-specific configuration loaded from INI and environment"""
    
    def __init__(self):
        # From environment variables (secrets)
        self.phoenix_client_id = os.environ.get('PHOENIX_CLIENT_ID', '')
        self.phoenix_client_secret = os.environ.get('PHOENIX_CLIENT_SECRET', '')
        self.phoenix_api_url = os.environ.get('PHOENIX_API_URL', '')
        
        # From INI or defaults
        self.bucket = os.environ.get('S3_BUCKET', '')
        self.config_key = 'config/lambda_config.ini'
        self.scanners_prefix = 'scanners/'
        self.metadata_prefix = 'metadata/'
        self.new_folder = 'new'
        self.processed_folder = 'processed'
        self.temp_dir = '/tmp'
        self.cleanup_after_processing = True
        
        # Orchestrator settings
        self.max_concurrent_lambdas = 10
        self.function_name = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'phoenix-file-processor')
    
    def load_from_ini(self, ini_content: str):
        """Load settings from INI content"""
        import configparser
        from io import StringIO
        
        parser = configparser.ConfigParser()
        parser.read_string(ini_content)
        
        if 'lambda' in parser:
            section = parser['lambda']
            self.scanners_prefix = section.get('scanners_prefix', self.scanners_prefix)
            self.metadata_prefix = section.get('metadata_prefix', self.metadata_prefix)
            self.new_folder = section.get('new_folder', self.new_folder)
            self.processed_folder = section.get('processed_folder', self.processed_folder)
            self.cleanup_after_processing = section.getboolean('cleanup_after_processing', True)
        
        if 'orchestrator' in parser:
            section = parser['orchestrator']
            self.max_concurrent_lambdas = section.getint('max_concurrent_lambdas', 10)
            self.function_name = section.get('function_name', self.function_name)
        
        # Phoenix settings can override env vars if not set
        if 'phoenix' in parser:
            section = parser['phoenix']
            if not self.phoenix_api_url:
                self.phoenix_api_url = section.get('api_base_url', '')


def download_from_s3(bucket: str, key: str, local_path: str) -> bool:
    """Download a file from S3 to local path"""
    try:
        logger.info(f"Downloading s3://{bucket}/{key} to {local_path}")
        s3_client.download_file(bucket, key, local_path)
        return True
    except ClientError as e:
        logger.error(f"Failed to download s3://{bucket}/{key}: {e}")
        return False


def upload_to_s3(local_path: str, bucket: str, key: str) -> bool:
    """Upload a local file to S3"""
    try:
        logger.info(f"Uploading {local_path} to s3://{bucket}/{key}")
        s3_client.upload_file(local_path, bucket, key)
        return True
    except ClientError as e:
        logger.error(f"Failed to upload to s3://{bucket}/{key}: {e}")
        return False


def move_s3_object(bucket: str, source_key: str, dest_key: str) -> bool:
    """Move an S3 object from source to destination"""
    try:
        logger.info(f"Moving s3://{bucket}/{source_key} to s3://{bucket}/{dest_key}")
        # Copy then delete
        s3_client.copy_object(
            Bucket=bucket,
            CopySource={'Bucket': bucket, 'Key': source_key},
            Key=dest_key
        )
        s3_client.delete_object(Bucket=bucket, Key=source_key)
        return True
    except ClientError as e:
        logger.error(f"Failed to move s3://{bucket}/{source_key}: {e}")
        return False


def list_s3_objects(bucket: str, prefix: str, suffix: str = None) -> List[str]:
    """List objects in S3 with optional suffix filter"""
    try:
        keys = []
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                if suffix is None or key.endswith(suffix):
                    keys.append(key)
        return keys
    except ClientError as e:
        logger.error(f"Failed to list s3://{bucket}/{prefix}: {e}")
        return []


def detect_scanner_from_path(file_key: str, scanners_prefix: str = 'scanners/') -> str:
    """
    Extract scanner type from S3 path.
    
    Path format: scanners/{scanner_name}/new/{filename}
    
    Examples:
        scanners/trivy/new/scan.json -> trivy
        scanners/prowler_v3/new/findings.json -> prowler_v3
    """
    # Remove the prefix if present
    if file_key.startswith(scanners_prefix):
        file_key = file_key[len(scanners_prefix):]
    
    parts = file_key.split('/')
    if len(parts) >= 2:
        return parts[0]  # scanner_name
    
    return 'auto'


def find_metadata_files(bucket: str, file_key: str, config: LambdaConfig) -> List[str]:
    """
    Find metadata files for a scan file.
    
    Search order:
    1. Same-name metadata: scan_metadata.yaml next to scan.json
    2. Scanner-level metadata: scanners/trivy/metadata.yaml
    3. Global metadata: metadata/global_tags.yaml
    """
    metadata_keys = []
    
    # 1. Same-name metadata (e.g., scan_20240201_metadata.yaml for scan_20240201.json)
    base_name = Path(file_key).stem
    parent_dir = str(Path(file_key).parent)
    
    # Try common metadata naming patterns
    metadata_patterns = [
        f"{parent_dir}/{base_name}_metadata.yaml",
        f"{parent_dir}/{base_name}_metadata.yml",
        f"{parent_dir}/{base_name}_tags.yaml",
        f"{parent_dir}/{base_name}_tags.yml",
    ]
    
    for pattern in metadata_patterns:
        try:
            s3_client.head_object(Bucket=bucket, Key=pattern)
            metadata_keys.append(pattern)
            logger.info(f"Found file-level metadata: {pattern}")
            break  # Only use first match
        except ClientError:
            pass
    
    # 2. Scanner-level metadata
    scanner_name = detect_scanner_from_path(file_key, config.scanners_prefix)
    scanner_metadata = f"{config.scanners_prefix}{scanner_name}/metadata.yaml"
    try:
        s3_client.head_object(Bucket=bucket, Key=scanner_metadata)
        metadata_keys.append(scanner_metadata)
        logger.info(f"Found scanner-level metadata: {scanner_metadata}")
    except ClientError:
        pass
    
    # 3. Global metadata
    global_metadata = f"{config.metadata_prefix}global_tags.yaml"
    try:
        s3_client.head_object(Bucket=bucket, Key=global_metadata)
        metadata_keys.append(global_metadata)
        logger.info(f"Found global metadata: {global_metadata}")
    except ClientError:
        pass
    
    return metadata_keys


def get_processed_key(file_key: str, config: LambdaConfig) -> str:
    """Convert a new/ path to processed/ path"""
    return file_key.replace(f"/{config.new_folder}/", f"/{config.processed_folder}/")


def process_single_file(event: Dict, config: LambdaConfig) -> Dict[str, Any]:
    """
    Process a single scan file from S3.
    
    1. Download config INI
    2. Download scan file
    3. Find and download metadata files
    4. Detect scanner type from path
    5. Process using MultiScannerImportManager
    6. Move file to processed/ on success
    """
    start_time = time.time()
    
    bucket = event.get('bucket', config.bucket)
    file_key = event.get('file_key', '')
    config_key = event.get('config_key', config.config_key)
    assessment_name = event.get('assessment_name', '')
    import_type = event.get('import_type', 'new')
    
    # Handle S3 event format
    if 'Records' in event:
        record = event['Records'][0]
        bucket = record['s3']['bucket']['name']
        file_key = record['s3']['object']['key']
    
    if not file_key:
        return {
            'statusCode': 400,
            'body': {'success': False, 'error': 'No file_key provided'}
        }
    
    # Skip if not in new/ folder
    if f"/{config.new_folder}/" not in file_key:
        logger.info(f"Skipping {file_key} - not in {config.new_folder}/ folder")
        return {
            'statusCode': 200,
            'body': {'success': True, 'skipped': True, 'reason': 'Not in new/ folder'}
        }
    
    logger.info(f"Processing file: s3://{bucket}/{file_key}")
    
    # Create temp directory for this invocation
    temp_dir = tempfile.mkdtemp(dir=config.temp_dir)
    local_files = []
    
    try:
        # 1. Download and load config INI
        local_config_path = os.path.join(temp_dir, 'config.ini')
        if download_from_s3(bucket, config_key, local_config_path):
            with open(local_config_path, 'r') as f:
                config.load_from_ini(f.read())
            local_files.append(local_config_path)
        
        # 2. Download scan file
        file_name = os.path.basename(file_key)
        local_scan_path = os.path.join(temp_dir, file_name)
        if not download_from_s3(bucket, file_key, local_scan_path):
            return {
                'statusCode': 500,
                'body': {'success': False, 'error': f'Failed to download {file_key}'}
            }
        local_files.append(local_scan_path)
        
        # 3. Find and download metadata files
        metadata_keys = find_metadata_files(bucket, file_key, config)
        local_metadata_paths = []
        for i, meta_key in enumerate(metadata_keys):
            meta_name = f"metadata_{i}.yaml"
            local_meta_path = os.path.join(temp_dir, meta_name)
            if download_from_s3(bucket, meta_key, local_meta_path):
                local_metadata_paths.append(local_meta_path)
                local_files.append(local_meta_path)
        
        # 4. Detect scanner type from path
        scanner_type = detect_scanner_from_path(file_key, config.scanners_prefix)
        logger.info(f"Detected scanner type: {scanner_type}")
        
        # 5. Generate assessment name if not provided
        if not assessment_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            assessment_name = f"Lambda_{scanner_type}_{timestamp}"
        
        # 6. Import and use MultiScannerImportManager
        # Import here to avoid loading heavy modules if not needed
        # Add parent directory to path for imports when running from lambda subfolder
        import sys
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        from phoenix_multi_scanner_import import MultiScannerImportManager
        
        # Create a temporary INI config for the manager
        manager_config_path = os.path.join(temp_dir, 'manager_config.ini')
        with open(manager_config_path, 'w') as f:
            f.write(f"""[phoenix]
client_id = {config.phoenix_client_id}
client_secret = {config.phoenix_client_secret}
api_base_url = {config.phoenix_api_url}
import_type = {import_type}
auto_import = true
wait_for_completion = true
batch_delay = 1
timeout = 300
check_interval = 5
""")
        local_files.append(manager_config_path)
        
        # Initialize manager
        manager = MultiScannerImportManager(manager_config_path)
        manager.load_configuration()
        
        # Load metadata/tags if available
        if local_metadata_paths:
            # Load the first (most specific) metadata file as tag config
            tag_config = manager.load_tag_configuration(local_metadata_paths[0])
            manager.tag_config = tag_config
            manager._initialize_translators()
        
        # Process the file
        result = manager.process_scanner_file(
            local_scan_path,
            scanner_type=scanner_type if scanner_type != 'auto' else None,
            assessment_name=assessment_name,
            import_type=import_type
        )
        
        # 7. Move to processed/ on success
        if result.get('success'):
            processed_key = get_processed_key(file_key, config)
            if move_s3_object(bucket, file_key, processed_key):
                result['moved_to'] = processed_key
                
                # Also move metadata file if it was file-specific
                for meta_key in metadata_keys:
                    if f"/{config.new_folder}/" in meta_key:
                        processed_meta_key = get_processed_key(meta_key, config)
                        move_s3_object(bucket, meta_key, processed_meta_key)
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return {
            'statusCode': 200 if result.get('success') else 500,
            'body': {
                'success': result.get('success', False),
                'mode': 'single',
                'file_processed': file_key,
                'moved_to': result.get('moved_to', ''),
                'scanner_type': result.get('scanner_type', scanner_type),
                'metadata_files_loaded': metadata_keys,
                'assets_imported': result.get('assets_imported', 0),
                'vulnerabilities_imported': result.get('vulnerabilities_imported', 0),
                'assessment_name': result.get('assessment_name', assessment_name),
                'phoenix_request_id': result.get('request_id', ''),
                'execution_time_ms': execution_time,
                'error': result.get('error', '')
            }
        }
        
    except Exception as e:
        logger.exception(f"Error processing {file_key}")
        return {
            'statusCode': 500,
            'body': {
                'success': False,
                'error': str(e),
                'file_key': file_key
            }
        }
    
    finally:
        # Cleanup temp files
        if config.cleanup_after_processing:
            for f in local_files:
                try:
                    os.remove(f)
                except:
                    pass
            try:
                os.rmdir(temp_dir)
            except:
                pass


def process_orchestrator(event: Dict, config: LambdaConfig) -> Dict[str, Any]:
    """
    Orchestrator mode: scan all new/ folders and invoke Lambdas for each file.
    """
    start_time = time.time()
    
    bucket = event.get('bucket', config.bucket)
    config_key = event.get('config_key', config.config_key)
    scanner_filter = event.get('scanner_filter', [])  # Optional: only these scanners
    max_concurrent = event.get('max_concurrent', config.max_concurrent_lambdas)
    
    # Load config from S3
    try:
        response = s3_client.get_object(Bucket=bucket, Key=config_key)
        config.load_from_ini(response['Body'].read().decode('utf-8'))
    except ClientError as e:
        logger.warning(f"Could not load config from S3: {e}")
    
    # Find all scanner folders
    scanners_found = set()
    files_to_process = []
    
    # List all objects under scanners prefix
    all_keys = list_s3_objects(bucket, config.scanners_prefix)
    
    for key in all_keys:
        # Check if it's in a new/ folder
        if f"/{config.new_folder}/" not in key:
            continue
        
        # Skip metadata files
        if key.endswith('_metadata.yaml') or key.endswith('_metadata.yml'):
            continue
        if key.endswith('_tags.yaml') or key.endswith('_tags.yml'):
            continue
        if key.endswith('/metadata.yaml'):
            continue
        
        # Extract scanner name
        scanner = detect_scanner_from_path(key, config.scanners_prefix)
        
        # Apply scanner filter if specified
        if scanner_filter and scanner not in scanner_filter:
            continue
        
        scanners_found.add(scanner)
        files_to_process.append(key)
    
    logger.info(f"Found {len(files_to_process)} files to process across {len(scanners_found)} scanners")
    
    # Invoke Lambda for each file (with concurrency limit)
    invocation_ids = []
    errors = []
    
    for i, file_key in enumerate(files_to_process):
        if i >= max_concurrent:
            logger.warning(f"Reached max concurrent limit ({max_concurrent}), stopping")
            break
        
        try:
            payload = {
                'mode': 'single',
                'bucket': bucket,
                'file_key': file_key,
                'config_key': config_key
            }
            
            response = lambda_client.invoke(
                FunctionName=config.function_name,
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(payload)
            )
            
            invocation_ids.append({
                'file': file_key,
                'status_code': response['StatusCode']
            })
            
        except Exception as e:
            logger.error(f"Failed to invoke Lambda for {file_key}: {e}")
            errors.append({'file': file_key, 'error': str(e)})
    
    execution_time = int((time.time() - start_time) * 1000)
    
    return {
        'statusCode': 200,
        'body': {
            'success': len(errors) == 0,
            'mode': 'orchestrator',
            'files_found': len(files_to_process),
            'lambdas_invoked': len(invocation_ids),
            'scanners_processed': list(scanners_found),
            'invocations': invocation_ids,
            'errors': errors,
            'execution_time_ms': execution_time
        }
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda entry point.
    
    Supports two modes:
    - single: Process one file (default, triggered by S3 events)
    - orchestrator: Scan all new/ folders and invoke Lambdas
    
    Event formats:
    
    1. S3 Event (auto-detected):
        {"Records": [{"s3": {"bucket": {"name": "..."}, "object": {"key": "..."}}}]}
    
    2. Direct single file:
        {"mode": "single", "bucket": "...", "file_key": "scanners/trivy/new/scan.json"}
    
    3. Orchestrator:
        {"mode": "orchestrator", "bucket": "...", "scanner_filter": ["trivy", "grype"]}
    """
    logger.info(f"Lambda invoked with event: {json.dumps(event)[:500]}...")
    
    # Initialize config
    config = LambdaConfig()
    
    # Detect mode
    mode = event.get('mode', 'single')
    
    # S3 events are always single file mode
    if 'Records' in event:
        mode = 'single'
    
    # Route to appropriate handler
    if mode == 'orchestrator':
        return process_orchestrator(event, config)
    else:
        return process_single_file(event, config)


# For local testing
if __name__ == '__main__':
    import sys
    
    # Test event
    test_event = {
        'mode': 'single',
        'bucket': 'phoenix-scanner-data',
        'file_key': 'scanners/trivy/new/test_scan.json',
        'config_key': 'config/lambda_config.ini'
    }
    
    if len(sys.argv) > 1:
        test_event = json.loads(sys.argv[1])
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
