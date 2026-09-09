# Phoenix Security Platform - Function Call Flow Guide

## 📋 Table of Contents
1. [Function Call Hierarchy](#function-call-hierarchy)
2. [Module Interaction Patterns](#module-interaction-patterns)
3. [Data Flow Sequences](#data-flow-sequences)
4. [Error Handling Flows](#error-handling-flows)
5. [Security Operation Flows](#security-operation-flows)
6. [Performance Optimization Flows](#performance-optimization-flows)

---

## 🔄 Function Call Hierarchy

### 1. Basic Import Flow (phoenix_import_refactored.py)

```
main()
├── PhoenixImportManager.__init__(config_file)
├── manager.load_configuration()
│   ├── configparser.ConfigParser().read(config_file)
│   ├── manager.load_tag_configuration(tag_file)
│   │   ├── yaml.safe_load(tag_file)
│   │   └── TagConfig(**tag_data)
│   └── return (PhoenixConfig, TagConfig)
├── manager.process_file(file_path, asset_type, **options)
│   ├── manager.get_data_loader(file_path)
│   │   ├── CSVDataLoader.supports_format(file_path) OR
│   │   └── JSONDataLoader.supports_format(file_path)
│   ├── data_loader.load_data(file_path)
│   │   ├── csv.DictReader(file) OR
│   │   └── json.load(file)
│   ├── AssetVulnerabilityMapper.map_to_assets(data, asset_type)
│   │   ├── mapper._build_asset_attributes(record, asset_type)
│   │   ├── mapper._extract_vulnerability_from_csv/json(record)
│   │   └── AssetData(asset_type, attributes, findings)
│   ├── DataAnonymizer.anonymize_record(asset) [if anonymize=True]
│   ├── PhoenixAPIClient.import_assets(assets, assessment_name)
│   │   ├── client.get_access_token()
│   │   │   └── requests.get(token_url, auth=HTTPBasicAuth)
│   │   ├── requests.post(import_url, json=payload, headers=headers)
│   │   ├── client.wait_for_import_completion(request_id) [if wait=True]
│   │   │   └── client.check_import_status(request_id) [polling loop]
│   │   └── return (request_id, final_status)
│   └── return import_result
└── print_results()
```

### 2. Multi-Scanner Import Flow (phoenix_multi_scanner_import.py)

```
main()
├── MultiScannerImportManager.__init__(config_file)
│   ├── super().__init__(config_file)  # Calls PhoenixImportManager.__init__
│   └── manager._initialize_translators()
│       ├── AquaScanTranslator(scanner_config, tag_config)
│       ├── JFrogXrayTranslator(scanner_config, tag_config)
│       ├── QualysTranslator(scanner_config, tag_config)
│       ├── SonarQubeTranslator(scanner_config, tag_config)
│       └── TenableTranslator(scanner_config, tag_config)
├── manager.detect_scanner_type(file_path)
│   ├── For each translator in translators:
│   │   ├── translator.can_handle(file_path, file_content)
│   │   │   ├── AquaScanTranslator.can_handle() checks JSON indicators
│   │   │   ├── QualysTranslator.can_handle() checks CSV/XML headers
│   │   │   └── etc. for each scanner type
│   │   └── return first matching translator
│   └── return detected_translator OR None
├── manager.process_scanner_file(file_path, **options)
│   ├── translator = manager.detect_scanner_type(file_path)
│   ├── translator.parse_file(file_path)
│   │   ├── Scanner-specific parsing logic:
│   │   │   ├── AquaScanTranslator.parse_file()
│   │   │   │   ├── json.load(file_path)
│   │   │   │   ├── Extract image and vulnerability data
│   │   │   │   └── Create AssetData with findings
│   │   │   ├── QualysTranslator._parse_csv_format() OR _parse_xml_format()
│   │   │   │   ├── csv.DictReader() OR ET.parse()
│   │   │   │   ├── Group vulnerabilities by asset
│   │   │   │   └── Create AssetData per unique asset
│   │   │   └── etc. for each scanner
│   │   └── return List[AssetData]
│   ├── translator.ensure_asset_has_findings(asset) [for each asset]
│   │   ├── Apply create_empty_assets logic if enabled
│   │   ├── Apply create_inventory_assets logic if enabled
│   │   └── translator.apply_vulnerability_tags(finding)
│   ├── DataAnonymizer.anonymize_record(asset) [if anonymize=True]
│   ├── PhoenixAPIClient.import_assets(assets, assessment_name)
│   └── return import_result
└── print_results()
```

### 3. Enhanced Import Flow (phoenix_import_enhanced.py)

```
main()
├── EnhancedPhoenixImportManager.__init__(config_file)
│   ├── super().__init__(config_file)  # Calls PhoenixImportManager.__init__
│   └── self.validator = EnhancedDataValidator()
├── manager.fix_csv_and_import(csv_file, assessment_name, **options)
│   ├── validator.validate_and_fix_csv(csv_file, fixed_csv_path)
│   │   ├── csv.DictReader(csv_file)
│   │   ├── For each row:
│   │   │   ├── validator._fix_csv_row(row, row_num, issues)
│   │   │   │   ├── Fix missing descriptions
│   │   │   │   ├── Fix severity formats
│   │   │   │   ├── Generate missing remedies
│   │   │   │   └── Validate required fields
│   │   │   └── Collect ValidationIssue objects
│   │   ├── validator._write_fixed_csv(fixed_rows, headers, output_path)
│   │   └── return ValidationResult(is_valid, issues)
│   ├── manager.parse_csv_file(fixed_csv_path, asset_type)
│   └── manager.import_assets_with_batching(assets, assessment_name, **options)
│       ├── manager._validate_assets_batch(assets)
│       │   ├── Validate asset structure
│       │   ├── Validate vulnerability data
│       │   └── validator.validate_payload_size(assets, max_size_mb)
│       ├── manager._create_batches(assets)
│       │   ├── validator.calculate_optimal_batch_size(len(assets), max_size_mb)
│       │   ├── Split assets into optimal batches
│       │   └── Validate each batch size
│       ├── For each batch:
│       │   ├── manager._process_batch_with_retry(batch, assessment_name, import_type, batch_num)
│       │   │   ├── For attempt in range(max_retries + 1):
│       │   │   │   ├── manager._rate_limit_delay()
│       │   │   │   ├── super().import_assets(batch, assessment_name, import_type)
│       │   │   │   └── return BatchResult(success=True) OR retry with exponential backoff
│       │   │   └── return BatchResult(success=False) after max retries
│       │   └── session.batch_results.append(batch_result)
│       ├── manager._log_session_summary(session)
│       └── return ImportSession
└── print_results()
```

### 4. Enhanced Multi-Scanner Flow (phoenix_multi_scanner_enhanced.py)

```
main()
├── EnhancedMultiScannerImportManager.__init__(config_file)
│   ├── super().__init__(config_file)  # Calls MultiScannerImportManager.__init__
│   └── self.enhanced_manager = EnhancedPhoenixImportManager(config_file)
├── manager.process_scanner_file_enhanced(file_path, **options)
│   ├── IF fix_data AND file_path.endswith('.csv'):
│   │   └── fixed_file_path = manager._fix_csv_data(file_path)
│   │       └── enhanced_manager.validator.validate_and_fix_csv(file_path, fixed_path)
│   ├── assets = manager._parse_file_to_assets(file_path, scanner_type, asset_type)
│   │   ├── translator = manager.detect_scanner_type(file_path)
│   │   └── translator.parse_file(file_path)
│   ├── IF just_tags:
│   │   └── return manager._process_tags_only(assets, file_path)
│   ├── assessment_name = manager._generate_assessment_name(file_path, scanner_type)
│   ├── IF enable_batching:
│   │   ├── session = enhanced_manager.import_assets_with_batching(assets, assessment_name, **options)
│   │   └── return manager._convert_session_to_result(session, file_path, scanner_type, assessment_name)
│   ├── ELSE:
│   │   └── return super().process_scanner_file(file_path, **options)
└── print_results()
```

### 5. Secure Import Flow (phoenix_multi_scanner_import_secure.py)

```
main()
├── authenticate_user()
│   ├── getpass.getuser()
│   ├── getpass.getpass("Password: ")
│   └── return (user_id, AccessLevel.ADMIN)  # Simplified for demo
├── SecureMultiScannerImportManager.__init__(config_file, user_id)
│   ├── self.security_manager = SecurityManager()
│   ├── self.access_control = AccessControlManager()
│   ├── self.audit_logger = AuditLogger()
│   └── self.rate_limiter = RateLimiter()
├── @secure_operation(permission="upload_scans")
│   manager.process_scanner_files(file_paths, user_id, source_ip)
│   ├── access_control.check_permission(user_id, "upload_scans")
│   ├── rate_limiter.is_allowed(user_id, "file_upload")
│   ├── For each file_path:
│   │   ├── InputSanitizer.sanitize_file_path(file_path)
│   │   ├── FileSignatureVerifier.verify_file_signature(file_path) [if required]
│   │   ├── SecureScannerProcessor.process_scanner_file(file_path, user_id, source_ip)
│   │   │   ├── SecureFieldMapper.detect_scanner_format(file_path)
│   │   │   ├── SecureUniversalScannerTranslator.parse_file(file_path, scanner_info)
│   │   │   │   ├── InputSanitizer.sanitize_json_data(raw_data)
│   │   │   │   └── Create sanitized AssetData objects
│   │   │   └── AuditLogger.log_file_access(user_id, file_path, "process", "success")
│   │   └── results.append(processing_result)
│   ├── AuditLogger.log_event(SecurityEvent(...))
│   └── return results
├── @secure_operation(permission="upload_scans")
│   manager.import_to_phoenix(assets, assessment_name, user_id, source_ip)
│   ├── SecurePhoenixAPIClient.authenticate(user_id, source_ip)
│   ├── SecurePhoenixAPIClient.import_assets(assets, assessment_name, user_id, source_ip)
│   │   ├── InputSanitizer.sanitize_string(assessment_name)
│   │   ├── For each asset: InputSanitizer.sanitize_json_data(asset)
│   │   ├── RateLimiter.is_allowed(user_id, "api_scan")
│   │   ├── requests.post(phoenix_api_url, json=sanitized_payload)
│   │   └── AuditLogger.log_event(SecurityEvent(...))
│   └── return import_success
└── print_security_summary()
```

---

## 🔗 Module Interaction Patterns

### 1. Inheritance Chain
```
PhoenixImportManager (Base)
├── MultiScannerImportManager (Extends Base)
│   └── EnhancedMultiScannerImportManager (Extends Multi + Enhanced)
└── EnhancedPhoenixImportManager (Extends Base)

SecureMultiScannerImportManager (Composition-based, not inheritance)
├── Uses SecurityManager
├── Uses SecureScannerProcessor
└── Uses SecurePhoenixAPIClient
```

### 2. Composition Patterns
```
PhoenixImportManager
├── Contains: PhoenixAPIClient
├── Contains: AssetVulnerabilityMapper
├── Contains: DataAnonymizer (optional)
└── Uses: DataLoader (CSV/JSON)

MultiScannerImportManager
├── Inherits: PhoenixImportManager
├── Contains: List[ScannerTranslator]
└── Uses: ConfigurableScannerTranslator

EnhancedPhoenixImportManager
├── Inherits: PhoenixImportManager
├── Contains: EnhancedDataValidator
└── Creates: ImportSession, BatchResult objects

SecureMultiScannerImportManager
├── Contains: SecurityManager
├── Contains: AccessControlManager
├── Contains: AuditLogger
├── Contains: RateLimiter
└── Uses: SecureScannerProcessor
```

### 3. Factory Patterns
```
DataLoader Factory (in PhoenixImportManager.get_data_loader())
├── IF file_path.endswith('.csv'): return CSVDataLoader()
└── IF file_path.endswith('.json'): return JSONDataLoader()

ScannerTranslator Factory (in MultiScannerImportManager.detect_scanner_type())
├── For each translator in self.translators:
│   ├── IF translator.can_handle(file_path): return translator
└── return None (or fallback translator)

Validator Factory (in scanner_validation.py)
├── IF format_type == 'JSON': return JSONValidator()
├── IF format_type == 'XML': return XMLValidator()
└── IF format_type == 'CSV': return CSVValidator()
```

---

## 📊 Data Flow Sequences

### 1. Asset Creation Sequence
```
Raw Scanner Data
    ↓ [ScannerTranslator.parse_file()]
Scanner-Specific Parsed Data
    ↓ [AssetVulnerabilityMapper.map_to_assets()]
AssetData Objects
    ↓ [DataAnonymizer.anonymize_record()] (optional)
Anonymized AssetData Objects
    ↓ [EnhancedDataValidator.validate_assets_batch()] (enhanced mode)
Validated AssetData Objects
    ↓ [Batching Logic._create_batches()] (enhanced mode)
Batched AssetData Objects
    ↓ [PhoenixAPIClient.import_assets()]
Phoenix API Payload
    ↓ [HTTP POST to Phoenix API]
Import Response
```

### 2. Configuration Loading Sequence
```
CLI Arguments
    ↓ [argparse.parse_args()]
Parsed Arguments
    ↓ [PhoenixImportManager.load_configuration()]
Config File Reading
    ├── [configparser.ConfigParser().read(config.ini)]
    └── [yaml.safe_load(tags.yaml)]
Configuration Objects
    ├── PhoenixConfig (API settings)
    └── TagConfig (tag settings)
```

### 3. Error Handling Sequence
```
Exception Occurs
    ↓ [@handle_scanner_error decorator OR ErrorHandler.handle_error()]
StandardError Object Creation
    ↓ [ErrorHandler._attempt_recovery()]
Recovery Strategy Selection
    ├── SkipAndContinueStrategy.recover()
    ├── RetryStrategy.recover()
    └── FallbackValueStrategy.recover()
Recovery Attempt
    ↓ [ErrorHandler._log_error()]
Error Logging & Reporting
```

---

## ⚠️ Error Handling Flows

### 1. File Processing Error Flow
```
File Processing Error
├── IF FileNotFoundError:
│   ├── Log error with context
│   ├── Skip file and continue
│   └── Add to error summary
├── IF PermissionError:
│   ├── Log security event (secure mode)
│   ├── Attempt alternative path
│   └── Fail with clear message
├── IF JSON/CSV ParseError:
│   ├── Attempt data fixing (enhanced mode)
│   ├── Use fallback parser
│   └── Skip malformed records
└── IF Unknown Error:
    ├── Log full stack trace
    ├── Attempt generic recovery
    └── Continue with remaining files
```

### 2. API Communication Error Flow
```
Phoenix API Error
├── IF Authentication Error (401):
│   ├── Refresh access token
│   ├── Retry request once
│   └── Fail if still unauthorized
├── IF Rate Limited (429):
│   ├── Extract retry-after header
│   ├── Wait specified time
│   └── Retry request
├── IF Server Error (5xx):
│   ├── Exponential backoff retry
│   ├── Log detailed error info
│   └── Fail after max retries
└── IF Network Error:
    ├── Check connectivity
    ├── Retry with timeout increase
    └── Fail with network diagnostic info
```

### 3. Data Validation Error Flow
```
Validation Error
├── IF Critical Error (missing required fields):
│   ├── Log critical issue
│   ├── Attempt data repair (enhanced mode)
│   └── Skip record if unfixable
├── IF Format Error (invalid severity, dates):
│   ├── Apply format correction
│   ├── Use fallback values
│   └── Log warning
├── IF Business Logic Error:
│   ├── Apply business rules
│   ├── Generate missing data
│   └── Continue processing
└── IF Payload Size Error:
    ├── Split into smaller batches
    ├── Retry with reduced batch size
    └── Process incrementally
```

---

## 🔐 Security Operation Flows

### 1. Authentication Flow (Secure Mode)
```
User Authentication Request
    ↓ [authenticate_user()]
Credential Collection
    ├── getpass.getuser() (username)
    └── getpass.getpass() (password)
Credential Validation
    ↓ [AccessControlManager.authenticate()]
Role Assignment
    ↓ [AccessControlManager.assign_role()]
Permission Matrix Setup
    ↓ [AuditLogger.log_authentication()]
Security Event Logging
```

### 2. File Security Validation Flow
```
File Access Request
    ↓ [InputSanitizer.sanitize_file_path()]
Path Sanitization
    ↓ [FileSignatureVerifier.verify_file_signature()]
Signature Verification
    ↓ [SandboxedParser.validate_file_safety()]
Safety Validation
    ↓ [AccessControlManager.check_permission()]
Permission Check
    ↓ [AuditLogger.log_file_access()]
Security Event Logging
```

### 3. API Security Flow
```
API Operation Request
    ↓ [@secure_operation decorator]
Permission Validation
    ├── AccessControlManager.check_permission(user_id, operation)
    └── RateLimiter.is_allowed(user_id, operation)
Rate Limiting Check
    ↓ [InputSanitizer.sanitize_json_data()]
Input Sanitization
    ↓ [SecurePhoenixAPIClient.import_assets()]
Secure API Call
    ↓ [AuditLogger.log_event()]
Security Event Logging
```

---

## ⚡ Performance Optimization Flows

### 1. Large File Processing Flow
```
Large File Detected
    ↓ [FileTypeDetector.detect_file_type()]
Format Detection
    ↓ [StreamingParser Selection]
Streaming Parser Selection
    ├── StreamingJSONParser.parse_large_json_array()
    ├── StreamingXMLParser.parse_large_xml()
    └── StreamingCSVParser.parse_large_csv()
Memory-Efficient Parsing
    ↓ [AssetBatch/VulnerabilityBatch]
Batch Processing
    ↓ [ParallelFileProcessor.process_files_parallel()]
Parallel Processing (if multiple files)
```

### 2. Batch Optimization Flow
```
Asset Collection
    ↓ [EnhancedDataValidator.validate_payload_size()]
Payload Size Validation
    ↓ [EnhancedDataValidator.calculate_optimal_batch_size()]
Optimal Batch Size Calculation
    ├── Consider total items
    ├── Consider target payload size
    └── Consider API limits
Batch Creation
    ↓ [_create_batches()]
Batch Size Validation
    ├── IF batch too large: split further
    └── IF batch acceptable: proceed
Batch Processing
```

### 3. Parallel Processing Flow
```
Multiple Files/Batches
    ↓ [ParallelFileProcessor.__init__()]
Worker Pool Creation
    ├── ThreadPoolExecutor (I/O bound)
    └── ProcessPoolExecutor (CPU bound)
Task Submission
    ↓ [executor.submit() for each task]
Concurrent Execution
    ↓ [as_completed() iterator]
Progress Tracking
    ├── ProcessingProgress updates
    ├── ProgressReporter.print_progress()
    └── Error collection
Result Aggregation
```

---

## 🎯 Key Integration Points

### 1. Configuration Integration
```
All modules read from:
├── config.ini / config_multi_scanner.ini (Phoenix API settings)
├── tags.yaml (Tag configuration)
├── scanner_field_mappings.yaml (Scanner mappings)
└── security_config.yaml (Security settings)
```

### 2. Logging Integration
```
All modules log to:
├── phoenix_import.log (Main operations)
├── security_audit.log (Security events)
├── error_report_*.json (Error summaries)
└── Console output (Real-time status)
```

### 3. Data Structure Integration
```
Common data structures used across modules:
├── AssetData (Core asset representation)
├── VulnerabilityData (Core vulnerability representation)
├── PhoenixConfig (API configuration)
├── TagConfig (Tag configuration)
├── ValidationResult (Validation outcomes)
└── SecurityEvent (Security audit events)
```

This function call flow guide provides detailed insight into how the Phoenix Security Platform components interact at the code level, helping junior developers understand the execution paths and integration patterns.
