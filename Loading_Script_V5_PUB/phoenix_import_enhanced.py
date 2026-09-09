#!/usr/bin/env python3
"""
Enhanced Phoenix Security Import Manager with Batching and Retry Logic
Handles large payloads, automatic batching, retry logic, and comprehensive validation

Author: Francesco Cipolloen
Version: 2.0.0
Date: 14th Dec 2025
"""

import json
import logging
import time
import math
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import requests
from pathlib import Path
import traceback

from phoenix_import_refactored import PhoenixImportManager, AssetData, VulnerabilityData
from data_validator_enhanced import EnhancedDataValidator, ValidationResult, ValidationIssue

logger = logging.getLogger(__name__)

@dataclass
class BatchResult:
    """Result of a batch import operation"""
    batch_number: int
    success: bool
    assets_processed: int
    vulnerabilities_processed: int
    request_id: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    processing_time: float = 0.0

@dataclass
class ImportSession:
    """Tracks an import session with multiple batches"""
    session_id: str
    total_batches: int
    completed_batches: int = 0
    failed_batches: int = 0
    total_assets: int = 0
    total_vulnerabilities: int = 0
    batch_results: List[BatchResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        if self.total_batches == 0:
            return 0.0
        return (self.completed_batches / self.total_batches) * 100
    
    @property
    def is_complete(self) -> bool:
        return (self.completed_batches + self.failed_batches) >= self.total_batches

class EnhancedPhoenixImportManager(PhoenixImportManager):
    """Enhanced import manager with batching, retry logic, and validation"""
    
    def __init__(self, config_file: str = "config_multi_scanner.ini"):
        super().__init__(config_file)
        self.validator = EnhancedDataValidator()
        
        # Batching configuration - more conservative for high-vulnerability datasets
        self.max_payload_size_mb = 20.0  # More conservative limit
        self.max_batch_size = 100  # Reduced maximum items per batch
        self.min_batch_size = 5   # Reduced minimum items per batch
        
        # Retry configuration
        self.max_retries = 3
        self.base_retry_delay = 2.0  # Base delay in seconds
        self.max_retry_delay = 60.0  # Maximum delay in seconds
        self.retry_backoff_factor = 2.0  # Exponential backoff multiplier
        
        # Rate limiting
        self.requests_per_minute = 30
        self.last_request_time = 0
        self.request_interval = 60.0 / self.requests_per_minute
    
    def import_assets_with_batching(self, assets: List[AssetData], 
                                  assessment_name: str,
                                  import_type: str = "new",
                                  validate_data: bool = True) -> ImportSession:
        """Import assets with automatic batching and retry logic"""
        
        session_id = f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(f"🚀 Starting enhanced import session: {session_id}")
        logger.info(f"   Total assets: {len(assets)}")
        logger.info(f"   Assessment: {assessment_name}")
        logger.info(f"   Import type: {import_type}")
        
        # Pre-import validation
        if validate_data:
            validation_result = self._validate_assets_batch(assets)
            if not validation_result.is_valid:
                logger.error("❌ Pre-import validation failed")
                self._log_validation_issues(validation_result.issues)
                # Continue with warnings, fail only on critical issues
                critical_issues = validation_result.get_critical_issues()
                if critical_issues:
                    raise ValueError(f"Critical validation issues found: {len(critical_issues)}")
        
        # Calculate optimal batching
        batches = self._create_batches(assets)
        total_batches = len(batches)
        
        logger.info(f"📦 Created {total_batches} batches (avg size: {len(assets)//total_batches if total_batches > 0 else 0})")
        
        # Initialize session
        session = ImportSession(
            session_id=session_id,
            total_batches=total_batches,
            total_assets=len(assets),
            total_vulnerabilities=sum(len(asset.findings) for asset in assets)
        )
        
        # Process each batch
        for batch_num, batch_assets in enumerate(batches, 1):
            logger.info(f"🔄 Processing batch {batch_num}/{total_batches} ({len(batch_assets)} assets)")
            
            batch_result = self._process_batch_with_retry(
                batch_assets, assessment_name, import_type, batch_num
            )
            
            session.batch_results.append(batch_result)
            
            if batch_result.success:
                session.completed_batches += 1
                logger.info(f"✅ Batch {batch_num} completed successfully")
            else:
                session.failed_batches += 1
                logger.error(f"❌ Batch {batch_num} failed: {batch_result.error_message}")
            
            # Rate limiting between batches
            if batch_num < total_batches:
                self._rate_limit_delay()
        
        # Log session summary
        self._log_session_summary(session)
        
        return session
    
    def _validate_assets_batch(self, assets: List[AssetData]) -> ValidationResult:
        """Validate a batch of assets before import"""
        issues = []
        
        for i, asset in enumerate(assets):
            # Validate asset structure
            if not asset.asset_type:
                issues.append(ValidationIssue(
                    severity="ERROR",
                    field="asset_type",
                    message=f"Asset {i+1}: Missing asset_type",
                    row_number=i+1
                ))
            
            if not asset.attributes:
                issues.append(ValidationIssue(
                    severity="ERROR", 
                    field="attributes",
                    message=f"Asset {i+1}: Missing attributes",
                    row_number=i+1
                ))
            
            # Validate vulnerabilities
            for j, vuln in enumerate(asset.findings):
                # Handle both dict and object formats
                vuln_name = vuln.get('name') if isinstance(vuln, dict) else getattr(vuln, 'name', None)
                vuln_description = vuln.get('description') if isinstance(vuln, dict) else getattr(vuln, 'description', None)
                
                if not vuln_name:
                    issues.append(ValidationIssue(
                        severity="CRITICAL",
                        field="vulnerability.name",
                        message=f"Asset {i+1}, Vuln {j+1}: Missing vulnerability name",
                        row_number=i+1
                    ))
                
                if not vuln_description:
                    issues.append(ValidationIssue(
                        severity="CRITICAL",
                        field="vulnerability.description", 
                        message=f"Asset {i+1}, Vuln {j+1}: Missing vulnerability description",
                        row_number=i+1
                    ))
                
                # Validate severity format
                vuln_severity = vuln.get('severity') if isinstance(vuln, dict) else getattr(vuln, 'severity', None)
                if vuln_severity:
                    try:
                        severity_float = float(vuln_severity)
                        if not (1.0 <= severity_float <= 10.0):
                            issues.append(ValidationIssue(
                                severity="WARNING",
                                field="vulnerability.severity",
                                message=f"Asset {i+1}, Vuln {j+1}: Severity {vuln_severity} outside range 1.0-10.0",
                                row_number=i+1
                            ))
                    except ValueError:
                        issues.append(ValidationIssue(
                            severity="ERROR",
                            field="vulnerability.severity",
                            message=f"Asset {i+1}, Vuln {j+1}: Invalid severity format: {vuln_severity}",
                            row_number=i+1
                        ))
        
        # Check payload size
        payload_validation = self.validator.validate_payload_size(
            [asset.__dict__ for asset in assets], 
            self.max_payload_size_mb
        )
        issues.extend(payload_validation.issues)
        
        critical_issues = [i for i in issues if i.severity == "CRITICAL"]
        return ValidationResult(is_valid=len(critical_issues) == 0, issues=issues)
    
    def _create_batches(self, assets: List[AssetData]) -> List[List[AssetData]]:
        """Create optimal batches based on payload size and item count"""
        
        if len(assets) <= self.min_batch_size:
            return [assets]  # Don't batch small datasets
        
        # Calculate optimal batch size based on vulnerability density
        total_vulnerabilities = sum(len(asset.findings) for asset in assets)
        avg_vulnerabilities_per_asset = total_vulnerabilities / len(assets) if assets else 1
        
        logger.info(f"📊 Dataset analysis:")
        logger.info(f"   Total assets: {len(assets)}")
        logger.info(f"   Total vulnerabilities: {total_vulnerabilities}")
        logger.info(f"   Avg vulnerabilities per asset: {avg_vulnerabilities_per_asset:.1f}")
        
        optimal_batch_size = self.validator.calculate_optimal_batch_size(
            len(assets), self.max_payload_size_mb, int(avg_vulnerabilities_per_asset)
        )
        
        # Ensure batch size is within bounds
        batch_size = max(self.min_batch_size, min(optimal_batch_size, self.max_batch_size))
        
        # Create batches
        batches = []
        for i in range(0, len(assets), batch_size):
            batch = assets[i:i + batch_size]
            
            # Validate batch size
            batch_validation = self.validator.validate_payload_size(
                [asset.__dict__ for asset in batch],
                self.max_payload_size_mb
            )
            
            # If batch is still too large, split it further
            if not batch_validation.is_valid:
                # Calculate how much smaller we need to go
                current_vulns = sum(len(asset.findings) for asset in batch)
                target_vulns = int(current_vulns * 0.5)  # Aim for 50% of current size
                
                # Calculate new batch size based on vulnerability density
                avg_vulns_per_asset = current_vulns / len(batch) if batch else 1
                new_batch_size = max(1, int(target_vulns / avg_vulns_per_asset))
                
                logger.warning(f"⚠️ Batch too large ({len(batch)} assets, {current_vulns} vulns)")
                logger.warning(f"   Splitting to smaller batches of ~{new_batch_size} assets")
                
                for j in range(0, len(batch), new_batch_size):
                    smaller_batch = batch[j:j + new_batch_size]
                    # Validate the smaller batch too
                    smaller_validation = self.validator.validate_payload_size(
                        [asset.__dict__ for asset in smaller_batch],
                        self.max_payload_size_mb
                    )
                    if smaller_validation.is_valid:
                        batches.append(smaller_batch)
                    else:
                        # If still too large, split to individual assets
                        logger.error(f"❌ Even smaller batch too large, splitting to individual assets")
                        for asset in smaller_batch:
                            batches.append([asset])
            else:
                batches.append(batch)
        
        return batches
    
    def _process_batch_with_retry(self, batch_assets: List[AssetData], 
                                assessment_name: str, import_type: str, 
                                batch_number: int) -> BatchResult:
        """Process a single batch with retry logic"""
        
        start_time = time.time()
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Rate limiting
                self._rate_limit_delay()
                
                # Attempt import using API client
                from phoenix_import_refactored import PhoenixAPIClient
                api_client = PhoenixAPIClient(self.phoenix_config)
                result = api_client.import_assets(batch_assets, assessment_name)
                
                processing_time = time.time() - start_time
                
                # Handle tuple response from import_assets
                request_id = None
                response_data = None
                if isinstance(result, tuple) and len(result) >= 2:
                    request_id, response_data = result
                elif isinstance(result, dict):
                    request_id = result.get('request_id')
                    response_data = result

                # Check if import actually succeeded
                # Phoenix API can return success without a request ID for synchronous imports
                if request_id is None and response_data is None:
                    # No request ID and no response data means failure
                    raise Exception("Import failed: No response from API")
                
                # Check if response_data indicates failure
                if isinstance(response_data, dict):
                    status = response_data.get('status', '').lower()
                    if status in ['error', 'failed']:
                        error_msg = response_data.get('message', 'Unknown error')
                        raise Exception(f"Import failed: {error_msg}")

                return BatchResult(
                    batch_number=batch_number,
                    success=True,
                    assets_processed=len(batch_assets),
                    vulnerabilities_processed=sum(len(asset.findings) for asset in batch_assets),
                    request_id=request_id,
                    retry_count=attempt,
                    processing_time=processing_time
                )
                
            except Exception as e:
                last_error = e
                
                if attempt < self.max_retries:
                    # Calculate retry delay with exponential backoff
                    delay = min(
                        self.base_retry_delay * (self.retry_backoff_factor ** attempt),
                        self.max_retry_delay
                    )
                    
                    logger.warning(f"⚠️ Batch {batch_number} attempt {attempt + 1} failed: {str(e)}")
                    logger.info(f"🔄 Retrying in {delay:.1f} seconds...")
                    
                    time.sleep(delay)
                else:
                    logger.error(f"❌ Batch {batch_number} failed after {self.max_retries + 1} attempts")
        
        processing_time = time.time() - start_time
        
        return BatchResult(
            batch_number=batch_number,
            success=False,
            assets_processed=len(batch_assets),
            vulnerabilities_processed=sum(len(asset.findings) for asset in batch_assets),
            error_message=str(last_error),
            retry_count=self.max_retries,
            processing_time=processing_time
        )
    
    def _rate_limit_delay(self):
        """Apply rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.request_interval:
            delay = self.request_interval - time_since_last
            logger.debug(f"⏱️ Rate limiting: waiting {delay:.2f}s")
            time.sleep(delay)
        
        self.last_request_time = time.time()
    
    def _log_validation_issues(self, issues: List[ValidationIssue]):
        """Log validation issues with appropriate severity"""
        
        by_severity = {}
        for issue in issues:
            if issue.severity not in by_severity:
                by_severity[issue.severity] = []
            by_severity[issue.severity].append(issue)
        
        for severity in ['CRITICAL', 'ERROR', 'WARNING', 'INFO']:
            if severity in by_severity:
                count = len(by_severity[severity])
                logger.log(
                    logging.ERROR if severity in ['CRITICAL', 'ERROR'] else logging.WARNING,
                    f"📋 {severity} validation issues: {count}"
                )
                
                # Log first few issues
                for issue in by_severity[severity][:3]:
                    row_info = f" (Row {issue.row_number})" if issue.row_number else ""
                    logger.log(
                        logging.ERROR if severity in ['CRITICAL', 'ERROR'] else logging.WARNING,
                        f"   • {issue.field}: {issue.message}{row_info}"
                    )
                
                if count > 3:
                    logger.log(
                        logging.ERROR if severity in ['CRITICAL', 'ERROR'] else logging.WARNING,
                        f"   ... and {count - 3} more {severity.lower()} issues"
                    )
    
    def _log_session_summary(self, session: ImportSession):
        """Log comprehensive session summary"""
        
        duration = datetime.now() - session.start_time
        
        logger.info(f"📊 Import Session Summary ({session.session_id})")
        logger.info(f"   Duration: {duration}")
        logger.info(f"   Total Batches: {session.total_batches}")
        logger.info(f"   ✅ Successful: {session.completed_batches}")
        logger.info(f"   ❌ Failed: {session.failed_batches}")
        logger.info(f"   📈 Success Rate: {session.success_rate:.1f}%")
        logger.info(f"   📦 Total Assets: {session.total_assets}")
        logger.info(f"   🔍 Total Vulnerabilities: {session.total_vulnerabilities}")
        
        # Log retry statistics
        total_retries = sum(result.retry_count for result in session.batch_results)
        if total_retries > 0:
            logger.info(f"   🔄 Total Retries: {total_retries}")
        
        # Log performance metrics
        total_processing_time = sum(result.processing_time for result in session.batch_results)
        avg_batch_time = total_processing_time / len(session.batch_results) if session.batch_results else 0
        logger.info(f"   ⏱️ Avg Batch Time: {avg_batch_time:.2f}s")
        
        # Log failed batches details
        failed_batches = [r for r in session.batch_results if not r.success]
        if failed_batches:
            logger.error(f"❌ Failed Batch Details:")
            for batch in failed_batches:
                logger.error(f"   Batch {batch.batch_number}: {batch.error_message}")
    
    def fix_csv_and_import(self, csv_file_path: str, assessment_name: str, 
                          asset_type: str = "INFRA", import_type: str = "new") -> ImportSession:
        """Complete workflow: fix CSV data and import with batching"""
        
        logger.info(f"🔧 Starting CSV fix and import workflow")
        logger.info(f"   File: {csv_file_path}")
        logger.info(f"   Assessment: {assessment_name}")
        
        # Step 1: Validate and fix CSV
        fixed_csv_path = csv_file_path.replace('.csv', '_fixed.csv')
        validation_result = self.validator.validate_and_fix_csv(csv_file_path, fixed_csv_path)
        
        if not validation_result.is_valid:
            critical_issues = validation_result.get_critical_issues()
            if critical_issues:
                raise ValueError(f"Critical CSV validation issues: {len(critical_issues)}")
        
        logger.info(f"✅ CSV validation and fixing completed")
        logger.info(f"   Issues found: {len(validation_result.issues)}")
        logger.info(f"   Fixed file: {fixed_csv_path}")
        
        # Step 2: Parse fixed CSV to assets
        try:
            assets = self.parse_csv_file(fixed_csv_path, asset_type)
            logger.info(f"📋 Parsed {len(assets)} assets from fixed CSV")
        except Exception as e:
            logger.error(f"❌ Failed to parse fixed CSV: {e}")
            raise
        
        # Step 3: Import with batching
        return self.import_assets_with_batching(assets, assessment_name, import_type)

def main():
    """Command line interface for enhanced import"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Phoenix Security Import with Batching and Retry Logic"
    )
    parser.add_argument('--file', required=True, help='CSV file to import')
    parser.add_argument('--assessment', required=True, help='Assessment name')
    parser.add_argument('--asset-type', default='INFRA', 
                       choices=['INFRA', 'WEB', 'CLOUD', 'CONTAINER', 'REPOSITORY', 'CODE', 'BUILD'],
                       help='Asset type (default: INFRA)')
    parser.add_argument('--import-type', default='new', choices=['new', 'merge', 'delta'],
                       help='Import type (default: new)')
    parser.add_argument('--config', default='config_multi_scanner.ini', 
                       help='Configuration file')
    parser.add_argument('--max-batch-size', type=int, default=500,
                       help='Maximum batch size (default: 500)')
    parser.add_argument('--max-payload-mb', type=float, default=25.0,
                       help='Maximum payload size in MB (default: 25.0)')
    
    args = parser.parse_args()
    
    # Initialize enhanced import manager
    manager = EnhancedPhoenixImportManager(args.config)
    manager.max_batch_size = args.max_batch_size
    manager.max_payload_size_mb = args.max_payload_mb
    
    try:
        # Run complete workflow
        session = manager.fix_csv_and_import(
            args.file, args.assessment, args.asset_type, args.import_type
        )
        
        if session.success_rate >= 80.0:
            print(f"✅ Import completed successfully ({session.success_rate:.1f}% success rate)")
            return 0
        else:
            print(f"⚠️ Import completed with issues ({session.success_rate:.1f}% success rate)")
            return 1
            
    except Exception as e:
        logger.error(f"❌ Import failed: {e}")
        logger.debug(traceback.format_exc())
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
