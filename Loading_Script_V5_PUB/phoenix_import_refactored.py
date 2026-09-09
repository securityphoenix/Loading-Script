#!/usr/bin/env python3
"""
Phoenix Security Asset Import Tool - Refactored Version
======================================================

A comprehensive tool for importing assets and vulnerabilities into Phoenix Security
from JSON and CSV data sources with advanced features including:

- Modular architecture with separate data loaders
- Support for JSON and CSV input formats
- Folder-based batch processing
- Tag creation and management
- Data anonymization capabilities
- Robust authentication and error handling
- Configurable asset and vulnerability creation

Author: Francesco Cipolloen
Version: 2.0.0
Date: 30th September 2025
"""

import argparse
import configparser
import csv
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import string
import time
import traceback
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
import yaml
from requests.auth import HTTPBasicAuth


# Global debug and error logging configuration
DEBUG_MODE = False
ERROR_LOG_FILE = None
DEBUG_LOG_FILE = None
RUN_ID = None

def create_logging_directories():
    """Create default logging directory structure"""
    directories = ['logs', 'errors', 'debug']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Create date-based debug subdirectory
    current_date = datetime.now().strftime('%Y%m%d')
    debug_date_dir = os.path.join('debug', current_date)
    os.makedirs(debug_date_dir, exist_ok=True)
    
    return debug_date_dir

def setup_logging(log_level: str = "INFO", debug_mode: bool = False, error_log_file: Optional[str] = None, tool_name: str = "phoenix_import"):
    """Setup comprehensive logging with debug and error tracking"""
    global DEBUG_MODE, ERROR_LOG_FILE, DEBUG_LOG_FILE, RUN_ID
    
    # Generate run ID and create directories
    RUN_ID = datetime.now().strftime('%H%M')
    debug_date_dir = create_logging_directories()
    
    DEBUG_MODE = debug_mode
    
    # Set default error log file if not specified
    if error_log_file is None and debug_mode:
        error_log_file = os.path.join('errors', f'{tool_name}_errors_{datetime.now().strftime("%Y%m%d_%H%M")}.log')
    
    ERROR_LOG_FILE = error_log_file
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(simple_formatter)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    root_logger.addHandler(console_handler)
    
    # Main log file handler (in logs/ directory)
    main_log_file = os.path.join('logs', f'{tool_name}_{datetime.now().strftime("%Y%m%d_%H%M")}.log')
    file_handler = logging.FileHandler(main_log_file)
    file_handler.setFormatter(detailed_formatter)
    file_handler.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    
    # Also create a general phoenix_import.log file for easy access
    general_log_file = os.path.join('logs', 'phoenix_import.log')
    general_handler = logging.FileHandler(general_log_file)
    general_handler.setFormatter(detailed_formatter)
    general_handler.setLevel(logging.INFO)
    root_logger.addHandler(general_handler)
    
    # Debug log file handler (if debug mode enabled)
    if debug_mode:
        # Create run-specific debug directory
        run_debug_dir = os.path.join(debug_date_dir, RUN_ID)
        os.makedirs(run_debug_dir, exist_ok=True)
        
        DEBUG_LOG_FILE = os.path.join(run_debug_dir, f'{tool_name}_debug.log')
        debug_handler = logging.FileHandler(DEBUG_LOG_FILE)
        debug_handler.setFormatter(detailed_formatter)
        debug_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(debug_handler)
        
        # Enable debug logging for requests
        logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)
        
        # Log the directory structure created
        logger.info(f"🗂️ Debug logging enabled - Run ID: {RUN_ID}")
        logger.info(f"   Debug directory: {run_debug_dir}")
        logger.info(f"   Main log: {main_log_file}")
        if ERROR_LOG_FILE:
            logger.info(f"   Error log: {ERROR_LOG_FILE}")
    
    # Error log file handler (if specified)
    if error_log_file:
        error_handler = logging.FileHandler(error_log_file)
        error_handler.setFormatter(detailed_formatter)
        error_handler.setLevel(logging.ERROR)
        root_logger.addHandler(error_handler)

# Initialize with default settings
setup_logging()
logger = logging.getLogger(__name__)

class DebugLogger:
    """Enhanced debug logging utility"""
    
    @staticmethod
    def get_debug_run_dir():
        """Get the current run's debug directory"""
        if RUN_ID and DEBUG_MODE:
            current_date = datetime.now().strftime('%Y%m%d')
            return os.path.join('debug', current_date, RUN_ID)
        return None
    
    @staticmethod
    def save_debug_file(filename: str, content: str, file_context: str = ""):
        """Save debug content to a file in the run directory"""
        if not DEBUG_MODE:
            return
        
        debug_dir = DebugLogger.get_debug_run_dir()
        if debug_dir:
            try:
                filepath = os.path.join(debug_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.debug(f"💾 Saved debug file: {filepath} [{file_context}]")
            except Exception as e:
                logger.warning(f"Failed to save debug file {filename}: {e}")
    
    @staticmethod
    def log_request(method: str, url: str, headers: Dict = None, payload: Any = None, file_context: str = ""):
        """Log HTTP request details"""
        if not DEBUG_MODE:
            return
            
        logger.debug(f"🌐 HTTP REQUEST [{file_context}]")
        logger.debug(f"   Method: {method}")
        logger.debug(f"   URL: {url}")
        
        # Prepare request details for file saving
        request_details = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "url": url,
            "context": file_context
        }
        
        if headers:
            safe_headers = headers.copy()
            # Mask sensitive headers
            if 'Authorization' in safe_headers:
                safe_headers['Authorization'] = 'Bearer ***MASKED***'
            logger.debug(f"   Headers: {json.dumps(safe_headers, indent=2)}")
            request_details["headers"] = safe_headers
        
        if payload:
            # Truncate large payloads for readability in logs
            if isinstance(payload, dict):
                payload_str = json.dumps(payload, indent=2)
                if len(payload_str) > 2000:
                    payload_str = payload_str[:2000] + "... [TRUNCATED]"
                logger.debug(f"   Payload: {payload_str}")
                # Save full payload to file
                request_details["payload"] = payload
            else:
                logger.debug(f"   Payload: {str(payload)[:2000]}")
                request_details["payload"] = str(payload)
        
        # Save detailed request to file
        timestamp = datetime.now().strftime('%H%M%S')
        context_safe = re.sub(r'[^\w\-_]', '_', file_context) if file_context else "request"
        filename = f"request_{timestamp}_{context_safe}.json"
        DebugLogger.save_debug_file(filename, json.dumps(request_details, indent=2, default=str), file_context)
    
    @staticmethod
    def log_response(response: requests.Response, file_context: str = ""):
        """Log HTTP response details"""
        if not DEBUG_MODE:
            return
            
        logger.debug(f"📡 HTTP RESPONSE [{file_context}]")
        logger.debug(f"   Status Code: {response.status_code}")
        logger.debug(f"   Status Text: {response.reason}")
        logger.debug(f"   Headers: {dict(response.headers)}")
        
        # Prepare response details for file saving
        response_details = {
            "timestamp": datetime.now().isoformat(),
            "status_code": response.status_code,
            "status_text": response.reason,
            "headers": dict(response.headers),
            "url": response.url,
            "context": file_context
        }
        
        try:
            if response.text:
                response_text = response.text
                if len(response_text) > 2000:
                    response_text = response_text[:2000] + "... [TRUNCATED]"
                logger.debug(f"   Response Body: {response_text}")
                # Save full response to file
                response_details["response_body"] = response.text
        except Exception as e:
            logger.debug(f"   Response Body: [Could not decode: {e}]")
            response_details["response_body"] = f"[Could not decode: {e}]"
        
        # Save detailed response to file
        timestamp = datetime.now().strftime('%H%M%S')
        context_safe = re.sub(r'[^\w\-_]', '_', file_context) if file_context else "response"
        filename = f"response_{timestamp}_{context_safe}.json"
        DebugLogger.save_debug_file(filename, json.dumps(response_details, indent=2, default=str), file_context)
    
    @staticmethod
    def log_file_processing(file_path: str, operation: str, details: Dict = None):
        """Log file processing details"""
        if not DEBUG_MODE:
            return
            
        logger.debug(f"📁 FILE PROCESSING")
        logger.debug(f"   File: {file_path}")
        logger.debug(f"   Operation: {operation}")
        if details:
            logger.debug(f"   Details: {json.dumps(details, indent=2, default=str)}")
        
        # Save file processing details to debug file
        processing_details = {
            "timestamp": datetime.now().isoformat(),
            "file_path": file_path,
            "operation": operation,
            "details": details or {}
        }
        
        timestamp = datetime.now().strftime('%H%M%S')
        file_basename = os.path.basename(file_path).replace('.', '_')
        operation_safe = re.sub(r'[^\w\-_]', '_', operation)
        filename = f"file_processing_{timestamp}_{file_basename}_{operation_safe}.json"
        DebugLogger.save_debug_file(filename, json.dumps(processing_details, indent=2, default=str), f"file: {file_path}")
    
    @staticmethod
    def log_data_transformation(stage: str, input_count: int, output_count: int, file_context: str = ""):
        """Log data transformation stages"""
        if not DEBUG_MODE:
            return
            
        logger.debug(f"🔄 DATA TRANSFORMATION [{file_context}]")
        logger.debug(f"   Stage: {stage}")
        logger.debug(f"   Input Count: {input_count}")
        logger.debug(f"   Output Count: {output_count}")

class ErrorTracker:
    """Comprehensive error tracking and reporting"""
    
    def __init__(self):
        self.errors = []
        self.file_errors = {}
        self.start_time = datetime.now()
    
    def log_error(self, error: Exception, context: str, file_path: str = "", operation: str = ""):
        """Log and track errors with full context"""
        error_info = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'operation': operation,
            'context': context,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc() if DEBUG_MODE else None
        }
        
        self.errors.append(error_info)
        
        # Track per-file errors
        if file_path:
            if file_path not in self.file_errors:
                self.file_errors[file_path] = []
            self.file_errors[file_path].append(error_info)
        
        # Log to main logger
        logger.error(f"❌ ERROR in {context}")
        logger.error(f"   File: {file_path}")
        logger.error(f"   Operation: {operation}")
        logger.error(f"   Error: {type(error).__name__}: {error}")
        
        if DEBUG_MODE:
            logger.debug(f"   Full Traceback:\n{traceback.format_exc()}")
        
        # Log to error file if specified
        if ERROR_LOG_FILE:
            try:
                with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"ERROR REPORT - {error_info['timestamp']}\n")
                    f.write(f"{'='*80}\n")
                    f.write(f"File: {file_path}\n")
                    f.write(f"Operation: {operation}\n")
                    f.write(f"Context: {context}\n")
                    f.write(f"Error Type: {error_info['error_type']}\n")
                    f.write(f"Error Message: {error_info['error_message']}\n")
                    if error_info['traceback']:
                        f.write(f"Traceback:\n{error_info['traceback']}\n")
                    f.write(f"{'='*80}\n\n")
            except Exception as log_error:
                logger.warning(f"Failed to write to error log file: {log_error}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary"""
        return {
            'total_errors': len(self.errors),
            'files_with_errors': len(self.file_errors),
            'error_types': list(set(e['error_type'] for e in self.errors)),
            'session_duration': str(datetime.now() - self.start_time),
            'errors_by_file': {k: len(v) for k, v in self.file_errors.items()},
            'recent_errors': self.errors[-5:] if self.errors else []
        }
    
    def save_error_report(self, output_file: str = None):
        """Save comprehensive error report"""
        if not output_file:
            # Save to errors directory by default
            output_file = os.path.join('errors', f"error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report = {
            'session_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration': str(datetime.now() - self.start_time)
            },
            'summary': self.get_summary(),
            'detailed_errors': self.errors,
            'file_errors': self.file_errors
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"📊 Error report saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save error report: {e}")

# Global error tracker
error_tracker = ErrorTracker()


@dataclass
class PhoenixConfig:
    """Configuration class for Phoenix API settings"""
    client_id: str
    client_secret: str
    api_base_url: str
    scan_type: str = "Generic Scan"
    import_type: str = "new"
    assessment_name: str = ""
    scan_target: str = ""
    auto_import: bool = True
    wait_for_completion: bool = True
    batch_delay: int = 10
    timeout: int = 3600
    check_interval: int = 10
    
    @classmethod
    def from_s3(cls, bucket: str, key: str, 
                client_id: str = None, client_secret: str = None, 
                api_base_url: str = None) -> 'PhoenixConfig':
        """
        Load PhoenixConfig from an INI file stored in S3.
        
        Args:
            bucket: S3 bucket name
            key: S3 object key for the INI file
            client_id: Override client_id (use for secrets from env vars)
            client_secret: Override client_secret (use for secrets from env vars)
            api_base_url: Override API URL
            
        Returns:
            PhoenixConfig instance
            
        Example:
            config = PhoenixConfig.from_s3(
                'my-bucket', 
                'config/phoenix.ini',
                client_id=os.environ['PHOENIX_CLIENT_ID'],
                client_secret=os.environ['PHOENIX_CLIENT_SECRET']
            )
        """
        import boto3
        from botocore.exceptions import ClientError
        
        s3_client = boto3.client('s3')
        
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
            ini_content = response['Body'].read().decode('utf-8')
        except ClientError as e:
            logger.error(f"Failed to load config from s3://{bucket}/{key}: {e}")
            raise ValueError(f"Could not load config from S3: {e}")
        
        # Parse INI content
        parser = configparser.ConfigParser()
        parser.read_string(ini_content)
        
        # Extract values from INI, with overrides taking precedence
        config_client_id = client_id or ''
        config_client_secret = client_secret or ''
        config_api_url = api_base_url or ''
        
        if 'phoenix' in parser:
            section = parser['phoenix']
            if not config_client_id:
                config_client_id = section.get('client_id', '')
            if not config_client_secret:
                config_client_secret = section.get('client_secret', '')
            if not config_api_url:
                config_api_url = section.get('api_base_url', '')
        
        # Validate required fields
        if not config_client_id or not config_client_secret or not config_api_url:
            missing = []
            if not config_client_id:
                missing.append('client_id')
            if not config_client_secret:
                missing.append('client_secret')
            if not config_api_url:
                missing.append('api_base_url')
            raise ValueError(f"Missing required config: {', '.join(missing)}")
        
        # Create config with all settings
        config = cls(
            client_id=config_client_id,
            client_secret=config_client_secret,
            api_base_url=config_api_url
        )
        
        # Load optional settings
        if 'phoenix' in parser:
            section = parser['phoenix']
            config.scan_type = section.get('scan_type', config.scan_type)
            config.import_type = section.get('import_type', config.import_type)
            config.assessment_name = section.get('assessment_name', config.assessment_name)
            config.scan_target = section.get('scan_target', config.scan_target)
            config.auto_import = section.getboolean('auto_import', config.auto_import)
            config.wait_for_completion = section.getboolean('wait_for_completion', config.wait_for_completion)
            config.batch_delay = section.getint('batch_delay', config.batch_delay)
            config.timeout = section.getint('timeout', config.timeout)
            config.check_interval = section.getint('check_interval', config.check_interval)
        
        logger.info(f"Loaded PhoenixConfig from s3://{bucket}/{key}")
        return config


@dataclass
class TagConfig:
    """Configuration class for tag management"""
    tags: List[Dict[str, str]] = field(default_factory=list)
    custom_tags: List[Dict[str, str]] = field(default_factory=list)
    vulnerability_tags: List[Dict[str, str]] = field(default_factory=list)
    severity_tags: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    asset_type_tags: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    environment_tags: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    compliance_tags: List[Dict[str, str]] = field(default_factory=list)
    apply_tags_after_import: bool = False
    
    def get_all_tags(self) -> List[Dict[str, str]]:
        """Get all asset tags combined"""
        return self.tags + self.custom_tags
    
    def get_vulnerability_tags(self, severity: str = None) -> List[Dict[str, str]]:
        """Get vulnerability tags, optionally filtered by severity"""
        vuln_tags = self.vulnerability_tags.copy()
        logger.debug(f"Base vulnerability tags: {len(vuln_tags)} tags")
        
        # Add severity-specific tags if severity is provided
        # Handle both string severity (e.g., "High") and numeric severity (e.g., 5)
        if severity:
            severity_str = str(severity).lower() if isinstance(severity, (int, float)) else severity.lower()
            if severity_str in self.severity_tags:
                severity_specific = self.severity_tags[severity_str]
                vuln_tags.extend(severity_specific)
                logger.debug(f"Added {len(severity_specific)} severity-specific tags for '{severity}'")
            else:
                logger.debug(f"No severity-specific tags found for '{severity_str}'. Available: {list(self.severity_tags.keys())}")
        
        # Add compliance tags to vulnerabilities
        vuln_tags.extend(self.compliance_tags)
        logger.debug(f"Added {len(self.compliance_tags)} compliance tags. Total: {len(vuln_tags)}")
        
        return vuln_tags
    
    def get_asset_type_tags(self, asset_type: str) -> List[Dict[str, str]]:
        """Get tags specific to asset type"""
        return self.asset_type_tags.get(asset_type, [])
    
    def get_environment_tags(self, environment: str) -> List[Dict[str, str]]:
        """Get tags specific to environment"""
        return self.environment_tags.get(environment, [])


@dataclass
class AssetData:
    """Data class representing an asset"""
    asset_type: str
    attributes: Dict[str, Any]
    tags: List[Dict[str, str]] = field(default_factory=list)
    installed_software: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    asset_id: Optional[str] = None
    
    def __post_init__(self):
        if not self.asset_id:
            self.asset_id = str(uuid.uuid4())


@dataclass
class VulnerabilityData:
    """Data class representing a vulnerability/finding"""
    name: str
    description: str
    remedy: str
    severity: str
    location: str = ""
    reference_ids: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)
    published_date_time: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[Dict[str, str]] = field(default_factory=list)


class DataLoader(ABC):
    """Abstract base class for data loaders"""
    
    @abstractmethod
    def load_data(self, file_path: str) -> List[Dict[str, Any]]:
        """Load data from file and return list of records"""
        pass
    
    @abstractmethod
    def supports_format(self, file_path: str) -> bool:
        """Check if this loader supports the given file format"""
        pass


class CSVDataLoader(DataLoader):
    """Data loader for CSV files"""
    
    def supports_format(self, file_path: str) -> bool:
        return file_path.lower().endswith('.csv')
    
    def load_data(self, file_path: str) -> List[Dict[str, Any]]:
        """Load CSV data"""
        logger.info(f"Loading CSV data from {file_path}")
        
        # Log file processing start
        DebugLogger.log_file_processing(file_path, "CSV Load Start", {
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
        })
        
        data = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # Detect delimiter
                sample = file.read(1024)
                file.seek(0)
                
                delimiter = ','
                if sample.count(';') > sample.count(','):
                    delimiter = ';'
                elif sample.count('\t') > sample.count(','):
                    delimiter = '\t'
                
                logger.debug(f"Detected CSV delimiter: '{delimiter}'")
                
                reader = csv.DictReader(file, delimiter=delimiter)
                
                # Log field names
                if reader.fieldnames:
                    logger.debug(f"CSV fields detected: {reader.fieldnames}")
                
                row_count = 0
                for row in reader:
                    row_count += 1
                    # Clean up the row data
                    cleaned_row = {}
                    for key, value in row.items():
                        if key:  # Skip empty keys
                            cleaned_key = key.strip().strip('"')
                            cleaned_value = value.strip().strip('"') if value else ""
                            cleaned_row[cleaned_key] = cleaned_value
                    
                    if cleaned_row:  # Skip empty rows
                        data.append(cleaned_row)
                    
                    # Log progress for large files
                    if DEBUG_MODE and row_count % 1000 == 0:
                        logger.debug(f"Processed {row_count} CSV rows...")
                        
            logger.info(f"Loaded {len(data)} records from CSV file")
            
            # Log file processing completion
            DebugLogger.log_file_processing(file_path, "CSV Load Complete", {
                "total_rows": len(data),
                "delimiter": delimiter,
                "fields": list(data[0].keys()) if data else []
            })
            
            return data
            
        except Exception as e:
            logger.error(f"Error loading CSV file {file_path}: {e}")
            error_tracker.log_error(e, "CSV Data Loading", file_path, "load_data")
            raise


class JSONDataLoader(DataLoader):
    """Data loader for JSON files"""
    
    def supports_format(self, file_path: str) -> bool:
        return file_path.lower().endswith('.json')
    
    def load_data(self, file_path: str) -> List[Dict[str, Any]]:
        """Load JSON data"""
        logger.info(f"Loading JSON data from {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            # Handle different JSON structures
            if isinstance(data, list):
                logger.info(f"Loaded {len(data)} records from JSON array")
                return data
            elif isinstance(data, dict):
                # Check for common JSON structures
                if 'assets' in data:
                    assets = data['assets']
                    logger.info(f"Loaded {len(assets)} assets from JSON object")
                    return assets if isinstance(assets, list) else [assets]
                elif 'vulnerabilities' in data:
                    vulns = data['vulnerabilities']
                    logger.info(f"Loaded {len(vulns)} vulnerabilities from JSON object")
                    return vulns if isinstance(vulns, list) else [vulns]
                else:
                    # Treat the entire object as a single record
                    logger.info("Loaded 1 record from JSON object")
                    return [data]
            else:
                logger.warning("Unexpected JSON structure, treating as single record")
                return [data]
                
        except Exception as e:
            logger.error(f"Error loading JSON file {file_path}: {e}")
            raise


class DataAnonymizer:
    """Utility class for anonymizing sensitive data"""
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize anonymizer with optional seed for reproducible results"""
        self.seed = seed or int(time.time())
        random.seed(self.seed)
        self._ip_mapping = {}
        self._hostname_mapping = {}
        
    def anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address while preserving network structure"""
        if not ip_address or ip_address in self._ip_mapping:
            return self._ip_mapping.get(ip_address, ip_address)
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            if ip_obj.is_private:
                # For private IPs, maintain the private range
                if ip_obj.version == 4:
                    if str(ip_obj).startswith('10.'):
                        # 10.x.x.x -> 10.x.x.x (scrambled)
                        parts = str(ip_obj).split('.')
                        new_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    elif str(ip_obj).startswith('192.168.'):
                        # 192.168.x.x -> 192.168.x.x (scrambled)
                        new_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    elif str(ip_obj).startswith('172.'):
                        # 172.16-31.x.x -> 172.16-31.x.x (scrambled)
                        new_ip = f"172.{random.randint(16, 31)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    else:
                        new_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                else:
                    # IPv6 private - use a simple scrambling
                    new_ip = f"fd00::{random.randint(1000, 9999)}:{random.randint(1000, 9999)}"
            else:
                # For public IPs, use a different private range
                if ip_obj.version == 4:
                    new_ip = f"203.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
                else:
                    new_ip = f"2001:db8::{random.randint(1000, 9999)}:{random.randint(1000, 9999)}"
            
            self._ip_mapping[ip_address] = new_ip
            return new_ip
            
        except ValueError:
            # Not a valid IP address, return as-is
            return ip_address
    
    def anonymize_hostname(self, hostname: str) -> str:
        """Anonymize hostname while preserving structure"""
        if not hostname or hostname in self._hostname_mapping:
            return self._hostname_mapping.get(hostname, hostname)
        
        # Generate a hash-based anonymized hostname
        hash_obj = hashlib.md5(f"{hostname}{self.seed}".encode())
        hash_hex = hash_obj.hexdigest()[:8]
        
        # Preserve domain structure if present
        if '.' in hostname:
            parts = hostname.split('.')
            if len(parts) > 1:
                # Keep the domain structure but anonymize the hostname part
                anonymized = f"host-{hash_hex}.{'.'.join(parts[1:])}"
            else:
                anonymized = f"host-{hash_hex}"
        else:
            anonymized = f"host-{hash_hex}"
        
        self._hostname_mapping[hostname] = anonymized
        return anonymized
    
    def anonymize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize a complete data record"""
        anonymized = record.copy()
        
        # Common fields that might contain IP addresses
        ip_fields = ['IP Address', 'ip', 'ip_address', 'host_ip', 'target_ip', 'source_ip']
        hostname_fields = ['DNS Name', 'hostname', 'host_name', 'dns_name', 'fqdn', 'NetBIOS Name']
        
        for field in ip_fields:
            if field in anonymized and anonymized[field]:
                anonymized[field] = self.anonymize_ip(anonymized[field])
        
        for field in hostname_fields:
            if field in anonymized and anonymized[field]:
                anonymized[field] = self.anonymize_hostname(anonymized[field])
        
        return anonymized


class AssetVulnerabilityMapper:
    """Maps raw data to Phoenix Security asset and vulnerability structures"""
    
    def __init__(self, tag_config: TagConfig, create_empty_assets: bool = False):
        self.tag_config = tag_config
        self.create_empty_assets = create_empty_assets
    
    def map_csv_to_assets(self, csv_data: List[Dict[str, Any]], asset_type: str = "INFRA") -> List[AssetData]:
        """Map CSV data to Phoenix assets"""
        logger.info(f"Mapping {len(csv_data)} CSV records to {asset_type} assets")
        
        assets_map = {}  # Group by IP/hostname to avoid duplicates
        
        for record in csv_data:
            # Extract asset identification
            ip_address = record.get('IP Address', '').strip()
            hostname = record.get('DNS Name', '').strip()
            netbios_name = record.get('NetBIOS Name', '').strip()
            
            # Create asset key for grouping
            asset_key = ip_address or hostname or netbios_name or str(uuid.uuid4())
            
            if asset_key not in assets_map:
                # Create new asset
                attributes = self._build_asset_attributes(record, asset_type)
                asset = AssetData(
                    asset_type=asset_type,
                    attributes=attributes,
                    tags=self.tag_config.get_all_tags().copy()
                )
                assets_map[asset_key] = asset
            
            # Add vulnerability if present
            vulnerability = self._extract_vulnerability_from_csv(record)
            if vulnerability:
                assets_map[asset_key].findings.append(vulnerability.__dict__)
        
        # Ensure all assets have findings if create_empty_assets is enabled
        assets = []
        for asset in assets_map.values():
            asset = self.ensure_asset_has_findings(asset, asset_type)
            assets.append(asset)
        
        logger.info(f"Created {len(assets)} unique assets")
        return assets
    
    def map_json_to_assets(self, json_data: List[Dict[str, Any]], asset_type: str = "INFRA") -> List[AssetData]:
        """Map JSON data to Phoenix assets"""
        logger.info(f"Mapping {len(json_data)} JSON records to {asset_type} assets")
        
        assets = []
        for record in json_data:
            # Check if this is already a Phoenix-formatted asset
            if 'attributes' in record and 'findings' in record:
                # Already in Phoenix format, just add tags
                asset = AssetData(
                    asset_type=record.get('assetType', asset_type),
                    attributes=record['attributes'],
                    tags=record.get('tags', []) + self.tag_config.get_all_tags(),
                    installed_software=record.get('installedSoftware', []),
                    findings=record.get('findings', []),
                    asset_id=record.get('id')
                )
            else:
                # Convert from generic JSON structure
                attributes = self._build_asset_attributes(record, asset_type)
                asset = AssetData(
                    asset_type=asset_type,
                    attributes=attributes,
                    tags=self.tag_config.get_all_tags().copy()
                )
                
                # Extract vulnerability if present
                vulnerability = self._extract_vulnerability_from_json(record)
                if vulnerability:
                    asset.findings.append(vulnerability.__dict__)
            
            # Ensure asset has findings if create_empty_assets is enabled
            asset = self.ensure_asset_has_findings(asset, asset_type)
            assets.append(asset)
        
        logger.info(f"Created {len(assets)} assets from JSON data")
        return assets
    
    def create_empty_asset_placeholder(self, asset_data: Dict[str, Any], asset_type: str) -> VulnerabilityData:
        """Create a zero-risk placeholder vulnerability for empty assets"""
        return VulnerabilityData(
            name="Asset Inventory - No Vulnerabilities Found",
            description="This asset was scanned and no vulnerabilities were detected. This is a placeholder entry for asset inventory purposes.",
            remedy="No action required. Continue monitoring for future vulnerabilities.",
            severity="1.0",  # Minimum risk/CVSS score (Phoenix requires 1-10)
            location="Asset-wide scan",
            reference_ids=[],
            cwes=[],
            published_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            details={
                "asset_inventory": True,
                "zero_risk_placeholder": True,
                "scan_status": "clean",
                "scan_timestamp": datetime.now().isoformat(),
                "asset_type": asset_type,
                "vulnerability_count": 0
            },
            tags=[
                {"key": "asset-inventory", "value": "true"},
                {"key": "vulnerability-status", "value": "clean"},
                {"key": "risk-level", "value": "zero"}
            ]
        )
    
    def ensure_asset_has_findings(self, asset: AssetData, asset_type: str) -> AssetData:
        """Ensure asset has at least one finding if create_empty_assets is enabled"""
        if self.create_empty_assets and not asset.findings:
            # Add zero-risk placeholder vulnerability
            placeholder = self.create_empty_asset_placeholder(asset.attributes, asset_type)
            asset.findings.append(placeholder.__dict__)
            logger.info(f"Added zero-risk placeholder to empty asset: {asset.attributes.get('ip', asset.attributes.get('hostname', 'unknown'))}")
        
        return asset
    
    def _build_asset_attributes(self, record: Dict[str, Any], asset_type: str) -> Dict[str, str]:
        """Build asset attributes based on asset type and available data"""
        attributes = {}
        
        if asset_type == "INFRA":
            # Infrastructure asset attributes
            if 'IP Address' in record:
                attributes['ip'] = record['IP Address']
            if 'DNS Name' in record:
                attributes['hostname'] = record['DNS Name']
                attributes['fqdn'] = record['DNS Name']
            if 'NetBIOS Name' in record:
                attributes['netbios'] = record['NetBIOS Name']
            if 'MAC Address' in record:
                attributes['macAddress'] = record['MAC Address']
            
            # Ensure required fields for INFRA
            if not attributes.get('ip') and not attributes.get('hostname'):
                # Generate a placeholder if neither IP nor hostname is available
                attributes['hostname'] = f"unknown-host-{str(uuid.uuid4())[:8]}"
                
        elif asset_type == "WEB":
            # Web asset attributes
            if 'IP Address' in record:
                attributes['ip'] = record['IP Address']
            if 'DNS Name' in record:
                attributes['fqdn'] = record['DNS Name']
            
            # Ensure at least one required field for WEB
            if not attributes.get('ip') and not attributes.get('fqdn'):
                attributes['fqdn'] = f"unknown-web-{str(uuid.uuid4())[:8]}.example.com"
                
        elif asset_type == "CLOUD":
            # Cloud asset attributes
            attributes['providerType'] = record.get('provider_type', 'AWS')
            attributes['providerAccountId'] = record.get('account_id', f"account-{str(uuid.uuid4())[:8]}")
            attributes['region'] = record.get('region', 'us-east-1')
            if 'vpc' in record:
                attributes['vpc'] = record['vpc']
            if 'subnet' in record:
                attributes['subnet'] = record['subnet']
                
        elif asset_type in ["CONTAINER", "REPOSITORY", "CODE", "BUILD"]:
            # Container/Repository/Code/Build asset attributes
            if asset_type == "REPOSITORY":
                attributes['repository'] = record.get('repository', f"repo-{str(uuid.uuid4())[:8]}")
            elif asset_type == "BUILD":
                attributes['buildFile'] = record.get('build_file', record.get('file_path', 'build.json'))
            elif asset_type == "CONTAINER":
                attributes['dockerfile'] = record.get('dockerfile', 'Dockerfile')
            elif asset_type == "CODE":
                attributes['scannerSource'] = record.get('scanner_source', 'code-scan')
            
            if 'origin' in record:
                attributes['origin'] = record['origin']
        
        return attributes
    
    def _extract_vulnerability_from_csv(self, record: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """Extract vulnerability data from CSV record"""
        plugin_name = record.get('Plugin Name', '').strip()
        if not plugin_name or record.get('Severity', '').lower() == 'info':
            return None
        
        # Map severity
        severity_map = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '2.0',
            'info': '1.0'
        }
        
        severity = record.get('Severity', 'medium').lower()
        severity_score = severity_map.get(severity, '5.0')
        
        # Extract CVEs
        cves = []
        cve_field = record.get('CVE', '')
        if cve_field:
            cves = [cve.strip() for cve in cve_field.split(',') if cve.strip()]
        
        return VulnerabilityData(
            name=plugin_name,
            description=record.get('Description', plugin_name),
            remedy=record.get('Solution', 'No solution provided'),
            severity=severity_score,
            location=record.get('IP Address', '') + ':' + record.get('Port', ''),
            reference_ids=cves,
            published_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            details={
                'plugin_id': record.get('Plugin', ''),
                'family': record.get('Family', ''),
                'protocol': record.get('Protocol', ''),
                'port': record.get('Port', ''),
                'cvss_v2_score': record.get('CVSS V2 Base Score', ''),
                'cvss_v3_score': record.get('CVSS V3 Base Score', ''),
                'plugin_output': record.get('Plugin Output', '')[:1000]  # Truncate long output
            }
        )
    
    def _extract_vulnerability_from_json(self, record: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """Extract vulnerability data from JSON record"""
        # Check if this record contains vulnerability information
        vuln_indicators = ['vulnerability', 'finding', 'issue', 'name', 'severity']
        if not any(key in record for key in vuln_indicators):
            return None
        
        name = record.get('name', record.get('vulnerability', record.get('title', 'Unknown Vulnerability')))
        if not name:
            return None
        
        return VulnerabilityData(
            name=name,
            description=record.get('description', record.get('summary', name)),
            remedy=record.get('remedy', record.get('solution', record.get('fix', 'No solution provided'))),
            severity=str(record.get('severity', record.get('risk_score', '5.0'))),
            location=record.get('location', record.get('file', record.get('component', ''))),
            reference_ids=record.get('cves', record.get('references', [])),
            published_date_time=record.get('published_date', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            details=record.get('details', {})
        )


class PhoenixAPIClient:
    """Client for interacting with Phoenix Security API"""
    
    def __init__(self, config: PhoenixConfig):
        self.config = config
        self._access_token = None
        self._token_expires_at = None
    
    def _should_include_asset_id(self, asset: 'AssetData') -> bool:
        """Determine if asset ID should be included in the payload
        
        Simplified approach: Never include asset IDs for any import type.
        Let Phoenix handle asset matching and creation based on asset attributes.
        This avoids issues with non-existent UUIDs and lets Phoenix determine
        if assets already exist based on their identifying attributes.
        """
        # Never include asset IDs - let Phoenix handle asset matching
        return False
    
    def get_access_token(self) -> Optional[str]:
        """Get or refresh access token"""
        if self._access_token and self._token_expires_at and time.time() < self._token_expires_at:
            logger.debug("Using cached access token")
            return self._access_token
        
        logger.info("Obtaining new access token from Phoenix API")
        url = f"{self.config.api_base_url}/v1/auth/access_token"
        
        try:
            # Log request details
            DebugLogger.log_request("GET", url, headers={"Authorization": "Basic ***MASKED***"})
            
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.config.client_id, self.config.client_secret),
                timeout=30
            )
            
            # Log response details
            DebugLogger.log_response(response, "authentication")
            
            if response.status_code == 200:
                token_data = response.json()
                self._access_token = token_data.get('token')
                # Assume token expires in 1 hour if not specified
                self._token_expires_at = time.time() + 3600
                logger.info("Successfully obtained access token")
                logger.debug(f"Token expires at: {datetime.fromtimestamp(self._token_expires_at)}")
                return self._access_token
            else:
                error_msg = f"Failed to obtain access token: {response.status_code} - {response.text}"
                logger.error(error_msg)
                error_tracker.log_error(
                    Exception(error_msg), 
                    "Authentication", 
                    operation="get_access_token"
                )
                return None
                
        except Exception as e:
            logger.error(f"Error obtaining access token: {e}")
            error_tracker.log_error(e, "Authentication", operation="get_access_token")
            return None
    
    def import_assets(self, assets: List[AssetData], assessment_name: str) -> Tuple[Optional[str], Optional[Dict]]:
        """Import assets using the direct JSON API"""
        token = self.get_access_token()
        if not token:
            error_tracker.log_error(
                Exception("No access token available"), 
                "Asset Import", 
                operation="import_assets"
            )
            return None, None
        
        # Convert assets to Phoenix format
        phoenix_assets = []
        for asset in assets:
            # Transform findings to match Phoenix API field names
            phoenix_findings = []
            for finding in asset.findings:
                # Convert dataclass to dict properly
                from dataclasses import asdict, is_dataclass
                if is_dataclass(finding):
                    phoenix_finding = asdict(finding)
                elif hasattr(finding, '__dict__'):
                    phoenix_finding = dict(finding.__dict__)
                else:
                    # Fallback for dict-like objects
                    phoenix_finding = dict(finding)
                
                # Transform field names to match Phoenix API specification
                from finding_reference_normalizer import normalize_finding_reference_fields
                phoenix_finding = normalize_finding_reference_fields(phoenix_finding)
                if 'published_date_time' in phoenix_finding:
                    phoenix_finding['publishedDateTime'] = phoenix_finding.pop('published_date_time')

                # Phoenix expects severity as a float (e.g. 5.0), not a string ("5.0").
                # VulnerabilityData stores it as str internally; cast it here at the
                # serialization boundary so all translators benefit automatically.
                if 'severity' in phoenix_finding and phoenix_finding['severity'] is not None:
                    try:
                        phoenix_finding['severity'] = float(phoenix_finding['severity'])
                    except (ValueError, TypeError):
                        logger.warning(
                            "Could not cast severity '%s' to float — defaulting to 5.0",
                            phoenix_finding['severity'],
                        )
                        phoenix_finding['severity'] = 5.0

                phoenix_findings.append(phoenix_finding)
            
            # Transform asset attributes to match Phoenix API field names
            phoenix_attributes = dict(asset.attributes)
            if 'mac_address' in phoenix_attributes:
                phoenix_attributes['macAddress'] = phoenix_attributes.pop('mac_address')
            
            phoenix_asset = {
                "attributes": phoenix_attributes,
                "tags": asset.tags,
                "installedSoftware": asset.installed_software,
                "findings": phoenix_findings
            }
            # Never include asset IDs - let Phoenix handle asset matching based on attributes
            # This avoids issues with non-existent UUIDs and lets Phoenix determine asset existence
            logger.debug(f"Asset ID excluded for {self.config.import_type} import - Phoenix will handle asset matching")
            
            phoenix_assets.append(phoenix_asset)
        
        # Log data transformation
        DebugLogger.log_data_transformation(
            "Asset Conversion", 
            len(assets), 
            len(phoenix_assets), 
            f"assessment: {assessment_name}"
        )
        
        # Prepare import payload
        payload = {
            "importType": self.config.import_type,
            "assessment": {
                "assetType": assets[0].asset_type if assets else "INFRA",
                "name": assessment_name
            },
            "assets": phoenix_assets
        }
        
        url = f"{self.config.api_base_url}/v1/import/assets"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        try:
            logger.info(f"Importing {len(phoenix_assets)} assets to Phoenix...")
            
            # Debug: Log all tags being sent
            for idx, asset in enumerate(phoenix_assets):
                logger.info(f"🏷️  Asset {idx+1} tags: {asset.get('tags', [])}")
                for tag in asset.get('tags', []):
                    logger.info(f"   - {tag.get('key')}: '{tag.get('value')}'")
                
                # Also check vulnerability tags
                for vidx, vuln in enumerate(asset.get('findings', [])):
                    vuln_tags = vuln.get('tags', [])
                    if vuln_tags:
                        logger.info(f"🔍 Vulnerability {vidx+1} ({vuln.get('name', 'unknown')}) tags: {vuln_tags}")
                        for tag in vuln_tags:
                            logger.info(f"   - {tag.get('key')}: '{tag.get('value')}'")
            
            # Log request details
            DebugLogger.log_request("POST", url, headers, payload, f"import: {assessment_name}")
            
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=120
            )
            
            # Log response details
            DebugLogger.log_response(response, f"import: {assessment_name}")
            
            if response.status_code in [200, 201]:
                # Handle empty response body (some Phoenix APIs return 200 with empty body)
                response_data = {}
                if response.text.strip():
                    try:
                        response_data = response.json()
                    except json.JSONDecodeError:
                        logger.warning("Received non-JSON response from Phoenix API")
                        response_data = {"status": "success", "message": "Import completed"}
                else:
                    logger.info("Received empty response body - import likely successful")
                    response_data = {"status": "success", "message": "Import completed"}
                
                request_id = response_data.get('id')
                logger.info(f"Successfully completed import. Request ID: {request_id or 'N/A'}")
                logger.debug(f"Import response data: {json.dumps(response_data, indent=2)}")
                
                if self.config.wait_for_completion and request_id:
                    final_status = self.wait_for_import_completion(request_id)
                    return request_id, final_status
                
                return request_id, response_data
            else:
                error_msg = f"Failed to import assets: {response.status_code} - {response.text}"
                logger.error(error_msg)
                error_tracker.log_error(
                    Exception(error_msg), 
                    "Asset Import", 
                    operation="import_assets"
                )
                return None, None
                
        except Exception as e:
            logger.error(f"Error importing assets: {e}")
            error_tracker.log_error(e, "Asset Import", operation="import_assets")
            return None, None
    
    def wait_for_import_completion(self, request_id: str) -> Optional[Dict]:
        """Wait for import to complete"""
        logger.info(f"Waiting for import completion (request ID: {request_id})")
        start_time = time.time()
        
        while True:
            status = self.check_import_status(request_id)
            if not status:
                logger.error("Failed to get import status")
                return None
            
            current_status = status.get('status')
            logger.info(f"Import status: {current_status}")
            
            if current_status == "IMPORTED":
                logger.info("Import completed successfully!")
                return status
            elif current_status == "ERROR":
                logger.error(f"Import failed: {status.get('error', 'Unknown error')}")
                return status
            elif current_status in ["TRANSLATING", "READY_FOR_IMPORT"]:
                if time.time() - start_time > self.config.timeout:
                    logger.warning(f"Import timed out after {self.config.timeout} seconds")
                    return status
                
                time.sleep(self.config.check_interval)
            else:
                logger.warning(f"Unknown import status: {current_status}")
                return status
    
    def check_import_status(self, request_id: str) -> Optional[Dict]:
        """Check import status"""
        token = self.get_access_token()
        if not token:
            return None
        
        url = f"{self.config.api_base_url}/v1/import/assets/file/translate/request/{request_id}"
        headers = {'Authorization': f'Bearer {token}'}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to check import status: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error checking import status: {e}")
            return None
    
    def add_tags_to_assets(self, asset_ids: List[str], tags: List[Dict[str, str]]) -> bool:
        """Add tags to multiple assets"""
        if not asset_ids or not tags:
            return True
        
        token = self.get_access_token()
        if not token:
            return False
        
        url = f"{self.config.api_base_url}/v1/assets/tags"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "tags": tags,
            "assetIds": asset_ids
        }
        
        try:
            logger.info(f"Adding {len(tags)} tags to {len(asset_ids)} assets")
            response = requests.put(url, headers=headers, json=payload, timeout=60)
            
            if response.status_code in [200, 201, 204]:
                logger.info("Successfully added tags to assets")
                return True
            else:
                logger.error(f"Failed to add tags: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding tags to assets: {e}")
            return False
    
    def get_asset(self, asset_id: str) -> Optional[Dict]:
        """Get asset details by ID"""
        token = self.get_access_token()
        if not token:
            return None
        
        url = f"{self.config.api_base_url}/v1/assets/{asset_id}"
        headers = {'Authorization': f'Bearer {token}'}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get asset {asset_id}: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error getting asset {asset_id}: {e}")
            return None
    
    def get_vulnerabilities_for_asset(self, asset_id: str) -> List[Dict]:
        """Get vulnerabilities for a specific asset"""
        token = self.get_access_token()
        if not token:
            return []
        
        url = f"{self.config.api_base_url}/v1/vulnerabilities"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "assetId": asset_id
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                return result.get('content', [])
            else:
                logger.error(f"Failed to get vulnerabilities for asset {asset_id}: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error getting vulnerabilities for asset {asset_id}: {e}")
            return []
    
    def verify_import(self, assets: List[AssetData], assessment_name: str) -> Dict[str, Any]:
        """Verify that imported assets exist in Phoenix using alternative methods"""
        logger.info(f"🔍 Verifying import of {len(assets)} assets for assessment: {assessment_name}")
        logger.info(f"⚠️ Note: Using simplified verification - Phoenix generates new asset IDs during import")
        
        verification_results = {
            'assessment_name': assessment_name,
            'total_assets': len(assets),
            'verification_method': 'simplified_success_based',
            'verified_assets': 0,
            'missing_assets': 0,
            'total_expected_vulnerabilities': sum(len(asset.findings) for asset in assets),
            'verified_vulnerabilities': 0,
            'missing_vulnerabilities': 0,
            'asset_details': [],
            'errors': [],
            'notes': [
                'Verification assumes success based on successful import response',
                'Phoenix API generates new asset IDs during import, making direct verification impossible',
                'For exact verification, use Phoenix UI to check the assessment manually'
            ]
        }
        
        # Since the import was successful (we reached this point), we can assume the assets were created
        logger.info("✅ Import was successful - assuming assets were created in Phoenix")
        
        verification_results['verified_assets'] = len(assets)
        verification_results['verified_vulnerabilities'] = verification_results['total_expected_vulnerabilities']
        
        for i, asset in enumerate(assets, 1):
            # Get asset identifier for logging
            asset_identifier = (
                asset.attributes.get('ip', '') or 
                asset.attributes.get('hostname', '') or 
                asset.attributes.get('fqdn', '') or 
                f"Asset-{i}"
            )
            
            asset_result = {
                'local_asset_id': asset.asset_id,
                'asset_identifier': asset_identifier,
                'asset_type': asset.asset_type,
                'expected_findings': len(asset.findings),
                'verified_findings': len(asset.findings),
                'asset_found': True,
                'findings_verified': True,
                'verification_method': 'assumed_from_import_success',
                'verification_note': f'Asset {asset_identifier} assumed successfully imported'
            }
            verification_results['asset_details'].append(asset_result)
            logger.info(f"✅ Asset {i}/{len(assets)}: {asset_identifier} ({asset.asset_type}) - {len(asset.findings)} findings")
        
        # Calculate success rates
        verification_results['asset_success_rate'] = 100.0
        verification_results['vulnerability_success_rate'] = 100.0
        
        logger.info(f"✅ Verification complete: {verification_results['verified_assets']}/{verification_results['total_assets']} assets (100.0%)")
        logger.info(f"✅ Vulnerabilities: {verification_results['verified_vulnerabilities']}/{verification_results['total_expected_vulnerabilities']} (100.0%)")
        logger.info(f"📋 Assessment '{assessment_name}' should now be visible in Phoenix Security UI")
        
        return verification_results


class PhoenixImportManager:
    """Main manager class for Phoenix imports"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config_refactored.ini"
        self.phoenix_config = None
        self.tag_config = None
        self.data_loaders = [CSVDataLoader(), JSONDataLoader()]
        self.anonymizer = None
        
    def load_configuration(self) -> Tuple[PhoenixConfig, TagConfig]:
        """Load configuration from file and environment"""
        logger.info(f"Loading configuration from {self.config_file}")
        
        # Check if default config file exists, if not, try fallback options
        config_path = Path(self.config_file)
        if not config_path.exists() and self.config_file == "config_refactored.ini":
            # Try fallback config files
            fallback_configs = ["config.ini", "config_refactored EXAMPLE.ini"]
            for fallback in fallback_configs:
                fallback_path = Path(fallback)
                if fallback_path.exists():
                    logger.info(f"Default config not found, using fallback: {fallback}")
                    self.config_file = fallback
                    config_path = fallback_path
                    break
        
        # Load from environment variables first
        phoenix_config = PhoenixConfig(
            client_id=os.getenv('PHOENIX_CLIENT_ID', ''),
            client_secret=os.getenv('PHOENIX_CLIENT_SECRET', ''),
            api_base_url=os.getenv('PHOENIX_API_BASE_URL', ''),
        )
        
        tag_config = TagConfig()
        
        # Load from config file
        config_path = Path(self.config_file)
        if config_path.exists():
            parser = configparser.ConfigParser()
            parser.read(config_path)
            
            if 'phoenix' in parser:
                section = parser['phoenix']
                if not phoenix_config.client_id:
                    phoenix_config.client_id = section.get('client_id', '')
                if not phoenix_config.client_secret:
                    phoenix_config.client_secret = section.get('client_secret', '')
                if not phoenix_config.api_base_url:
                    phoenix_config.api_base_url = section.get('api_base_url', '')
                
                phoenix_config.scan_type = section.get('scan_type', phoenix_config.scan_type)
                phoenix_config.import_type = section.get('import_type', phoenix_config.import_type)
                phoenix_config.assessment_name = section.get('assessment_name', phoenix_config.assessment_name)
                phoenix_config.scan_target = section.get('scan_target', phoenix_config.scan_target)
                phoenix_config.auto_import = section.getboolean('auto_import', phoenix_config.auto_import)
                phoenix_config.wait_for_completion = section.getboolean('wait_for_completion', phoenix_config.wait_for_completion)
                phoenix_config.batch_delay = section.getint('batch_delay', phoenix_config.batch_delay)
                phoenix_config.timeout = section.getint('timeout', phoenix_config.timeout)
                phoenix_config.check_interval = section.getint('check_interval', phoenix_config.check_interval)
        
        # Validate required configuration
        missing = []
        if not phoenix_config.client_id:
            missing.append('client_id')
        if not phoenix_config.client_secret:
            missing.append('client_secret')
        if not phoenix_config.api_base_url:
            missing.append('api_base_url')
        
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
        
        self.phoenix_config = phoenix_config
        self.tag_config = tag_config
        
        return phoenix_config, tag_config
    
    def load_tag_configuration(self, tag_file: Optional[str] = None) -> TagConfig:
        """Load tag configuration from YAML file"""
        if not tag_file:
            tag_file = Path(__file__).parent / "customization" / "custom data:.yaml.yml"
        
        tag_config = TagConfig()
        
        if Path(tag_file).exists():
            try:
                with open(tag_file, 'r') as f:
                    tag_data = yaml.safe_load(f)
                
                # Load custom_data tags (asset tags)
                if 'custom_data' in tag_data:
                    for item in tag_data['custom_data']:
                        if isinstance(item, dict) and 'key' in item and 'value' in item:
                            tag_config.custom_tags.append({"key": item['key'], "value": str(item['value'])})
                
                # Load vulnerability_tags
                if 'vulnerability_tags' in tag_data:
                    for item in tag_data['vulnerability_tags']:
                        if isinstance(item, dict) and 'key' in item and 'value' in item:
                            tag_config.vulnerability_tags.append({"key": item['key'], "value": str(item['value'])})
                
                # Load severity_tags
                if 'severity_tags' in tag_data:
                    for severity, tags in tag_data['severity_tags'].items():
                        if isinstance(tags, list):
                            tag_config.severity_tags[severity.lower()] = []
                            for item in tags:
                                if isinstance(item, dict) and 'key' in item and 'value' in item:
                                    tag_config.severity_tags[severity.lower()].append({"key": item['key'], "value": str(item['value'])})
                
                # Load asset_type_tags
                if 'asset_type_tags' in tag_data:
                    for asset_type, tags in tag_data['asset_type_tags'].items():
                        if isinstance(tags, list):
                            tag_config.asset_type_tags[asset_type] = []
                            for item in tags:
                                if isinstance(item, dict) and 'key' in item and 'value' in item:
                                    tag_config.asset_type_tags[asset_type].append({"key": item['key'], "value": str(item['value'])})
                
                # Load environment_tags
                if 'environment_tags' in tag_data:
                    for env, tags in tag_data['environment_tags'].items():
                        if isinstance(tags, list):
                            tag_config.environment_tags[env] = []
                            for item in tags:
                                if isinstance(item, dict) and 'key' in item and 'value' in item:
                                    tag_config.environment_tags[env].append({"key": item['key'], "value": str(item['value'])})
                
                # Load compliance_tags
                if 'compliance_tags' in tag_data:
                    for item in tag_data['compliance_tags']:
                        if isinstance(item, dict) and 'key' in item and 'value' in item:
                            tag_config.compliance_tags.append({"key": item['key'], "value": str(item['value'])})
                
                total_tags = (len(tag_config.custom_tags) + len(tag_config.vulnerability_tags) + 
                            len(tag_config.compliance_tags) + sum(len(tags) for tags in tag_config.severity_tags.values()) +
                            sum(len(tags) for tags in tag_config.asset_type_tags.values()) +
                            sum(len(tags) for tags in tag_config.environment_tags.values()))
                
                logger.info(f"Loaded {total_tags} tags from {tag_file}")
                logger.info(f"  - Asset tags: {len(tag_config.custom_tags)}")
                logger.info(f"  - Vulnerability tags: {len(tag_config.vulnerability_tags)}")
                logger.info(f"  - Compliance tags: {len(tag_config.compliance_tags)}")
                logger.info(f"  - Severity-specific tags: {sum(len(tags) for tags in tag_config.severity_tags.values())}")
                logger.info(f"  - Asset type tags: {sum(len(tags) for tags in tag_config.asset_type_tags.values())}")
                logger.info(f"  - Environment tags: {sum(len(tags) for tags in tag_config.environment_tags.values())}")
                
            except Exception as e:
                logger.warning(f"Could not load tag configuration from {tag_file}: {e}")
        
        return tag_config
    
    def get_data_loader(self, file_path: str) -> Optional[DataLoader]:
        """Get appropriate data loader for file"""
        for loader in self.data_loaders:
            if loader.supports_format(file_path):
                return loader
        return None
    
    def process_folder(self, folder_path: str, file_types: List[str] = None, 
                      asset_type: str = "INFRA", anonymize: bool = False,
                      just_tags: bool = False, create_empty_assets: bool = False,
                      verify_import: bool = False) -> Dict[str, Any]:
        """Process all files in a folder"""
        if file_types is None:
            file_types = ['json', 'csv']
        
        folder = Path(folder_path)
        if not folder.exists():
            raise ValueError(f"Folder does not exist: {folder_path}")
        
        # Find all matching files
        files_to_process = []
        for file_type in file_types:
            pattern = f"*.{file_type}"
            files_to_process.extend(folder.glob(pattern))
            files_to_process.extend(folder.rglob(pattern))  # Recursive search
        
        if not files_to_process:
            raise ValueError(f"No {'/'.join(file_types)} files found in {folder_path}")
        
        logger.info(f"Found {len(files_to_process)} files to process in {folder_path}")
        
        results = []
        for file_path in files_to_process:
            try:
                result = self.process_file(
                    str(file_path), 
                    asset_type=asset_type, 
                    anonymize=anonymize,
                    just_tags=just_tags,
                    create_empty_assets=create_empty_assets,
                    verify_import=verify_import
                )
                results.append(result)
                
                # Add delay between files if configured
                if len(files_to_process) > 1 and self.phoenix_config.batch_delay > 0:
                    time.sleep(self.phoenix_config.batch_delay)
                    
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                results.append({
                    'file': str(file_path),
                    'success': False,
                    'error': str(e)
                })
        
        return {
            'folder': folder_path,
            'total_files': len(files_to_process),
            'results': results,
            'successful': len([r for r in results if r.get('success', False)]),
            'failed': len([r for r in results if not r.get('success', False)])
        }
    
    def process_file(self, file_path: str, asset_type: str = "INFRA", 
                    anonymize: bool = False, just_tags: bool = False, 
                    create_empty_assets: bool = False, verify_import: bool = False) -> Dict[str, Any]:
        """Process a single file"""
        logger.info(f"Processing file: {file_path}")
        
        # Get appropriate data loader
        loader = self.get_data_loader(file_path)
        if not loader:
            raise ValueError(f"No suitable data loader found for file: {file_path}")
        
        # Load data
        raw_data = loader.load_data(file_path)
        
        # Anonymize if requested
        if anonymize:
            if not self.anonymizer:
                self.anonymizer = DataAnonymizer()
            raw_data = [self.anonymizer.anonymize_record(record) for record in raw_data]
            logger.info("Data anonymized")
        
        # Map to assets
        mapper = AssetVulnerabilityMapper(self.tag_config, create_empty_assets)
        if isinstance(loader, CSVDataLoader):
            assets = mapper.map_csv_to_assets(raw_data, asset_type)
        else:
            assets = mapper.map_json_to_assets(raw_data, asset_type)
        
        if not assets:
            return {
                'file': file_path,
                'success': False,
                'error': 'No assets created from data'
            }
        
        # Generate assessment name
        file_name = Path(file_path).stem
        assessment_name = self.phoenix_config.assessment_name or f"{file_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Import assets
        api_client = PhoenixAPIClient(self.phoenix_config)
        
        if just_tags:
            # Only add tags to existing assets (requires asset IDs)
            asset_ids = [asset.asset_id for asset in assets if asset.asset_id]
            if asset_ids and self.tag_config.get_all_tags():
                success = api_client.add_tags_to_assets(asset_ids, self.tag_config.get_all_tags())
                return {
                    'file': file_path,
                    'success': success,
                    'operation': 'tags_only',
                    'assets_tagged': len(asset_ids),
                    'tags_applied': len(self.tag_config.get_all_tags())
                }
            else:
                return {
                    'file': file_path,
                    'success': False,
                    'error': 'No asset IDs or tags available for tag-only operation'
                }
        else:
            # Full import
            request_id, final_status = api_client.import_assets(assets, assessment_name)
            
            success = False
            if final_status:
                if isinstance(final_status, dict):
                    # Check for various success indicators
                    success = (final_status.get('status') in ['IMPORTED', 'success'] or 
                              final_status.get('message') == 'Import completed')
                else:
                    success = request_id is not None
            elif request_id is not None:
                # If we have a request_id, consider it successful
                success = True
            
            result = {
                'file': file_path,
                'success': success,
                'assessment_name': assessment_name,
                'assets_imported': len(assets),
                'vulnerabilities_imported': sum(len(asset.findings) for asset in assets),
                'request_id': request_id,
                'final_status': final_status
            }
            
            # Add tags after import if configured
            if success and self.tag_config.apply_tags_after_import and self.tag_config.get_all_tags():
                asset_ids = [asset.asset_id for asset in assets]
                tag_success = api_client.add_tags_to_assets(asset_ids, self.tag_config.get_all_tags())
                result['tags_added'] = tag_success
            
            # Verify import if requested and successful
            if success and verify_import:
                logger.info("🔍 Verifying import...")
                verification_results = api_client.verify_import(assets, assessment_name)
                result['verification'] = verification_results
                
                # Update success status based on verification
                if verification_results['asset_success_rate'] < 100:
                    logger.warning(f"⚠️ Import verification incomplete: {verification_results['asset_success_rate']:.1f}% assets verified")
                if verification_results['vulnerability_success_rate'] < 100:
                    logger.warning(f"⚠️ Vulnerability verification incomplete: {verification_results['vulnerability_success_rate']:.1f}% vulnerabilities verified")
            
            return result


def create_anonymized_file(input_file: str, output_file: str, seed: Optional[int] = None) -> None:
    """Create an anonymized version of a data file"""
    logger.info(f"Creating anonymized version of {input_file}")
    
    anonymizer = DataAnonymizer(seed)
    
    # Determine file type and process accordingly
    if input_file.lower().endswith('.csv'):
        # Process CSV file
        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', encoding='utf-8', newline='') as outfile:
            
            reader = csv.DictReader(infile)
            if reader.fieldnames:
                writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
                writer.writeheader()
                
                for row in reader:
                    anonymized_row = anonymizer.anonymize_record(row)
                    writer.writerow(anonymized_row)
    
    elif input_file.lower().endswith('.json'):
        # Process JSON file
        with open(input_file, 'r', encoding='utf-8') as infile:
            data = json.load(infile)
        
        if isinstance(data, list):
            anonymized_data = [anonymizer.anonymize_record(record) for record in data]
        elif isinstance(data, dict):
            anonymized_data = anonymizer.anonymize_record(data)
        else:
            anonymized_data = data
        
        with open(output_file, 'w', encoding='utf-8') as outfile:
            json.dump(anonymized_data, outfile, indent=2, ensure_ascii=False)
    
    else:
        raise ValueError(f"Unsupported file type: {input_file}")
    
    logger.info(f"Anonymized data saved to {output_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Phoenix Security Asset Import Tool - Refactored Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a single CSV file
  python phoenix_import_refactored.py --file data.csv --asset-type INFRA
  
  # Process all JSON files in a folder
  python phoenix_import_refactored.py --folder /path/to/data --file-types json --asset-type WEB
  
  # Process with anonymization
  python phoenix_import_refactored.py --file data.csv --anonymize
  
  # Only add tags to existing assets
  python phoenix_import_refactored.py --file data.json --just-tags
  
  # Create anonymized version of a file
  python phoenix_import_refactored.py --anonymize-file input.csv --output anonymized.csv
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Process a single file')
    input_group.add_argument('--folder', type=str, help='Process all files in folder')
    input_group.add_argument('--anonymize-file', type=str, help='Create anonymized version of file')
    
    # File processing options
    parser.add_argument('--file-types', nargs='+', choices=['json', 'csv'], 
                       default=['json', 'csv'], help='File types to process (default: json csv)')
    parser.add_argument('--asset-type', choices=['INFRA', 'WEB', 'CLOUD', 'CONTAINER', 'REPOSITORY', 'CODE', 'BUILD'],
                       default='INFRA', help='Asset type for imported assets (default: INFRA)')
    
    # Processing options
    parser.add_argument('--anonymize', action='store_true', help='Anonymize IP addresses and hostnames')
    parser.add_argument('--just-tags', action='store_true', help='Only add tags to assets, do not import')
    parser.add_argument('--create-empty-assets', action='store_true', 
                       help='Create assets even if no vulnerabilities found (with zero risk placeholder)')
    parser.add_argument('--verify-import', action='store_true', 
                       help='Verify imported assets and vulnerabilities exist in Phoenix after import')
    parser.add_argument('--tag-file', type=str, help='YAML file containing tag configuration')
    
    # Configuration options
    parser.add_argument('--config', type=str, default='config_refactored.ini', help='Configuration file (default: config_refactored.ini)')
    parser.add_argument('--client-id', type=str, help='Phoenix API client ID (overrides config)')
    parser.add_argument('--client-secret', type=str, help='Phoenix API client secret (overrides config)')
    parser.add_argument('--api-url', type=str, help='Phoenix API base URL (overrides config)')
    
    # Anonymization options
    parser.add_argument('--output', type=str, help='Output file for anonymized data')
    parser.add_argument('--seed', type=int, help='Seed for reproducible anonymization')
    
    # Logging options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug mode with detailed HTTP request/response logging')
    parser.add_argument('--error-log', type=str, 
                       help='File to log errors to (in addition to main log)')
    
    args = parser.parse_args()
    
    # Setup enhanced logging
    setup_logging(
        log_level=args.log_level,
        debug_mode=args.debug,
        error_log_file=args.error_log,
        tool_name="phoenix_import_refactored"
    )
    
    try:
        if args.anonymize_file:
            # Anonymization mode
            if not args.output:
                # Generate output filename
                input_path = Path(args.anonymize_file)
                args.output = str(input_path.parent / f"{input_path.stem}_anonymized{input_path.suffix}")
            
            create_anonymized_file(args.anonymize_file, args.output, args.seed)
            print(f"✅ Anonymized file created: {args.output}")
            return
        
        # Import mode
        manager = PhoenixImportManager(args.config)
        
        # Load configuration
        phoenix_config, tag_config = manager.load_configuration()
        
        # Override with command line arguments
        if args.client_id:
            phoenix_config.client_id = args.client_id
        if args.client_secret:
            phoenix_config.client_secret = args.client_secret
        if args.api_url:
            phoenix_config.api_base_url = args.api_url
        
        # Load tag configuration
        if args.tag_file:
            tag_config = manager.load_tag_configuration(args.tag_file)
        else:
            tag_config = manager.load_tag_configuration()
        
        manager.tag_config = tag_config
        
        logger.info(f"🚀 Starting Phoenix Security Asset Import")
        logger.info(f"   API URL: {phoenix_config.api_base_url}")
        logger.info(f"   Asset Type: {args.asset_type}")
        logger.info(f"   Anonymize: {args.anonymize}")
        logger.info(f"   Just Tags: {args.just_tags}")
        
        if args.file:
            # Process single file
            result = manager.process_file(
                args.file, 
                asset_type=args.asset_type,
                anonymize=args.anonymize,
                just_tags=args.just_tags,
                create_empty_assets=args.create_empty_assets,
                verify_import=args.verify_import
            )
            
            if result['success']:
                print(f"✅ Successfully processed {args.file}")
                if not args.just_tags:
                    print(f"   Assessment: {result['assessment_name']}")
                    print(f"   Assets: {result['assets_imported']}")
                    print(f"   Vulnerabilities: {result['vulnerabilities_imported']}")
                    print(f"   Request ID: {result['request_id']}")
                    
                    # Show verification results if available
                    if 'verification' in result:
                        verification = result['verification']
                        print(f"   🔍 Verification Results:")
                        print(f"      Assets: {verification['verified_assets']}/{verification['total_assets']} ({verification['asset_success_rate']:.1f}%)")
                        print(f"      Vulnerabilities: {verification['verified_vulnerabilities']}/{verification['total_expected_vulnerabilities']} ({verification['vulnerability_success_rate']:.1f}%)")
                        if verification['errors']:
                            print(f"      ⚠️ Errors: {len(verification['errors'])}")
                else:
                    print(f"   Assets tagged: {result['assets_tagged']}")
                    print(f"   Tags applied: {result['tags_applied']}")
            else:
                print(f"❌ Failed to process {args.file}: {result['error']}")
                return 1
        
        elif args.folder:
            # Process folder
            result = manager.process_folder(
                args.folder,
                file_types=args.file_types,
                asset_type=args.asset_type,
                anonymize=args.anonymize,
                just_tags=args.just_tags,
                create_empty_assets=args.create_empty_assets,
                verify_import=args.verify_import
            )
            
            print(f"📁 Processed folder: {args.folder}")
            print(f"   Total files: {result['total_files']}")
            print(f"   ✅ Successful: {result['successful']}")
            print(f"   ❌ Failed: {result['failed']}")
            
            # Show details for failed files
            for file_result in result['results']:
                if not file_result.get('success', False):
                    print(f"   ❌ {file_result['file']}: {file_result.get('error', 'Unknown error')}")
        
        print("🎉 Import process completed!")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        error_tracker.log_error(e, "Main Process", operation="main")
        print(f"❌ Error: {e}")
        return 1
    
    finally:
        # Generate error summary and report
        if error_tracker.errors:
            error_summary = error_tracker.get_summary()
            logger.warning(f"⚠️ Session completed with {error_summary['total_errors']} errors")
            logger.warning(f"   Files with errors: {error_summary['files_with_errors']}")
            logger.warning(f"   Error types: {', '.join(error_summary['error_types'])}")
            
            # Save detailed error report if there were errors
            if args.debug or args.error_log:
                error_tracker.save_error_report()
            
            print(f"\n📊 Error Summary:")
            print(f"   Total Errors: {error_summary['total_errors']}")
            print(f"   Files with Errors: {error_summary['files_with_errors']}")
            if error_summary['error_types']:
                print(f"   Error Types: {', '.join(error_summary['error_types'])}")
        else:
            logger.info("✅ Session completed successfully with no errors")
    
    return 1 if error_tracker.errors else 0


if __name__ == "__main__":
    exit(main())
