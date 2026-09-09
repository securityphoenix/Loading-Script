# Phoenix Multi-Scanner Enhanced - Architecture Flow

## Module Relationships and Data Flow

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  phoenix_multi_scanner_enhanced.py                       │
│                    (Main Orchestrator / Entry Point)                     │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  EnhancedMultiScannerImportManager                               │   │
│  │  - Combines all capabilities                                     │   │
│  │  - Manages scanner detection and translation                     │   │
│  │  │  - Orchestrates the entire import workflow                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                    │
                    │ Uses / Imports from
                    ▼
    ┌───────────────────────────────────────────────────┐
    │                                                     │
    │  ┌──────────────────────────────────────────┐     │
    │  │  phoenix_import_refactored.py           │     │
    │  │  (Core Base Module)                      │     │
    │  │                                           │     │
    │  │  • PhoenixConfig                         │     │
    │  │  • TagConfig                             │     │
    │  │  • AssetData                             │     │
    │  │  • VulnerabilityData                     │     │
    │  │  • PhoenixAPIClient ◄────────────────────┼─────┼── API Calls
    │  │  • PhoenixImportManager (base class)     │     │
    │  │  • Logging & Error Tracking              │     │
    │  └──────────────────────────────────────────┘     │
    │                                                     │
    │  ┌──────────────────────────────────────────┐     │
    │  │  phoenix_import_enhanced.py              │     │
    │  │  (Batching & Retry Logic)                │     │
    │  │                                           │     │
    │  │  • EnhancedPhoenixImportManager          │     │
    │  │  • ImportSession                         │     │
    │  │  • BatchResult                           │     │
    │  │  • Intelligent batching algorithm        │     │
    │  │  • Retry with exponential backoff        │     │
    │  │  • Data validation                       │     │
    │  └──────────────────────────────────────────┘     │
    │                                                     │
    │  ┌──────────────────────────────────────────┐     │
    │  │  phoenix_multi_scanner_import.py         │     │
    │  │  (Scanner Translation Layer)             │     │
    │  │                                           │     │
    │  │  • ScannerTranslator (abstract base)     │     │
    │  │  • AnchoreGrypeTranslator                │     │
    │  │  • TrivyTranslator                       │     │
    │  │  • AquaScanTranslator                    │     │
    │  │  • JFrogXrayTranslator                   │     │
    │  │  • QualysTranslator                      │     │
    │  │  • SonarQubeTranslator                   │     │
    │  │  • TenableTranslator                     │     │
    │  │  • ConfigurableScannerTranslator (YAML)  │     │
    │  └──────────────────────────────────────────┘     │
    │                                                     │
    │  ┌──────────────────────────────────────────┐     │
    │  │  scanner_translators/ module             │     │
    │  │  (42 Consolidated Translators)           │     │
    │  │                                           │     │
    │  │  • Container scanners (5)                │     │
    │  │  • Build/SCA scanners (11)               │     │
    │  │  • Cloud scanners (5)                    │     │
    │  │  • Code/Secret scanners (8)              │     │
    │  │  • Web scanners (6)                      │     │
    │  │  • Infrastructure scanners (5)           │     │
    │  │  • Format handlers (2)                   │     │
    │  └──────────────────────────────────────────┘     │
    │                                                     │
    └───────────────────────────────────────────────────┘
```

---

## Detailed Component Flow

### 1. Initialization Flow

```
User runs: python phoenix_multi_scanner_enhanced.py --file scan.json

    ↓
┌─────────────────────────────────────────────────────────────┐
│ main() function                                              │
│ - Parse command line arguments                              │
│ - Setup logging (from phoenix_import_refactored)            │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ EnhancedMultiScannerImportManager.__init__()                │
│                                                              │
│ Step 1: Initialize base class                               │
│    PhoenixImportManager.__init__(config_file)               │
│    └─ from phoenix_import_refactored                        │
│                                                              │
│ Step 2: Load configuration                                  │
│    self._load_configuration_safe()                          │
│    └─ Creates PhoenixConfig & TagConfig                     │
│        (from phoenix_import_refactored)                     │
│                                                              │
│ Step 3: Create enhanced importer for batching               │
│    self.enhanced_importer =                                 │
│        EnhancedPhoenixImportManager(config_file)            │
│    └─ from phoenix_import_enhanced                          │
│                                                              │
│ Step 4: Create data validator                               │
│    self.validator = EnhancedDataValidator()                 │
│                                                              │
│ Step 5: Defer translator initialization                     │
│    self._translators_initialized = False                    │
└─────────────────────────────────────────────────────────────┘
```

---

### 2. Scanner Detection & Translation Flow

```
User File: scan-results.json
    ↓
┌─────────────────────────────────────────────────────────────┐
│ process_scanner_file_enhanced()                             │
│                                                              │
│ Step 1: Initialize translators (lazy loading)               │
│    _ensure_translators_initialized()                        │
│    ├─ Import from phoenix_multi_scanner_import:             │
│    │  • ScannerConfig                                       │
│    │  • TenableTranslator                                   │
│    │  • QualysTranslator                                    │
│    │  • etc.                                                │
│    │                                                         │
│    ├─ Import from scanner_translators/:                     │
│    │  • GrypeTranslator                                     │
│    │  • TrivyTranslator                                     │
│    │  • ProwlerTranslator                                   │
│    │  • etc. (42 translators)                               │
│    │                                                         │
│    └─ Build self.translators list:                          │
│       [Translator1, Translator2, ..., Translator42,         │
│        ConfigurableScannerTranslator (YAML fallback)]       │
│                                                              │
│ Step 2: Detect scanner type                                 │
│    detect_scanner_type(file_path)                           │
│    ├─ Try each translator.can_handle(file_path)             │
│    ├─ First match wins (priority order)                     │
│    └─ Returns translator object                             │
│                                                              │
│ Step 3: Parse file                                          │
│    _parse_file_to_assets(file_path, translator, asset_type) │
│    ├─ translator.parse_file(file_path)                      │
│    └─ Returns List[AssetData]                               │
│        (AssetData from phoenix_import_refactored)           │
└─────────────────────────────────────────────────────────────┘
```

---

### 3. Data Processing & Import Flow

```
Parsed Assets: List[AssetData]
    ↓
┌─────────────────────────────────────────────────────────────┐
│ IF enable_batching = True:                                  │
│                                                              │
│ Step 1: Validate data                                       │
│    validator.validate_and_fix_csv() [if CSV]                │
│    └─ from data_validator_enhanced                          │
│                                                              │
│ Step 2: Import with batching                                │
│    enhanced_importer.import_assets_with_batching(           │
│        assets, assessment_name, import_type                 │
│    )                                                         │
│    └─ from phoenix_import_enhanced                          │
│                                                              │
│    ┌─────────────────────────────────────────────────┐     │
│    │ EnhancedPhoenixImportManager                     │     │
│    │                                                  │     │
│    │ • Pre-import validation                          │     │
│    │ • Calculate optimal batch size                   │     │
│    │ • Create batches                                 │     │
│    │                                                  │     │
│    │ FOR each batch:                                  │     │
│    │   ├─ Rate limiting                               │     │
│    │   ├─ Retry logic (3 attempts)                    │     │
│    │   ├─ Call PhoenixAPIClient.import_assets()       │     │
│    │   │   └─ from phoenix_import_refactored          │     │
│    │   └─ Track BatchResult                           │     │
│    │                                                  │     │
│    │ Returns: ImportSession                           │     │
│    └─────────────────────────────────────────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ IF enable_batching = False:                                 │
│                                                              │
│ Single-request import:                                      │
│    api_client = PhoenixAPIClient(config)                    │
│    └─ from phoenix_import_refactored                        │
│                                                              │
│    api_client.import_assets(assets, assessment_name)        │
│    └─ POST to /v1/import/assets                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ Phoenix Security API                                         │
│ - Receives JSON payload                                     │
│ - Processes assets and vulnerabilities                      │
│ - Returns request_id                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Class Inheritance Hierarchy

```
phoenix_import_refactored.py
    │
    ├─ PhoenixImportManager (base class)
    │       │
    │       ├─ MultiScannerImportManager
    │       │   └─ (in phoenix_multi_scanner_import.py)
    │       │       • Adds scanner detection
    │       │       • Adds translator management
    │       │
    │       └─ EnhancedPhoenixImportManager
    │           └─ (in phoenix_import_enhanced.py)
    │               • Adds batching logic
    │               • Adds retry logic
    │               • Adds validation
    │
    └─ EnhancedMultiScannerImportManager
        └─ (in phoenix_multi_scanner_enhanced.py)
            • Inherits from PhoenixImportManager (base)
            • Composes with EnhancedPhoenixImportManager (batching)
            • Uses MultiScannerImportManager translators (scanning)
            • COMBINES all capabilities
```

---

## Data Class Usage

```
phoenix_import_refactored.py defines:

    ┌─────────────────────────────────────────────────────────┐
    │ @dataclass PhoenixConfig                                 │
    │ - client_id, client_secret, api_base_url                │
    │ - import_type, assessment_name, etc.                    │
    └─────────────────────────────────────────────────────────┘
            │
            │ Used by all modules for configuration
            ▼
    ┌─────────────────────────────────────────────────────────┐
    │ @dataclass TagConfig                                     │
    │ - tags, vulnerability_tags, severity_tags               │
    │ - compliance_tags, asset_type_tags                      │
    └─────────────────────────────────────────────────────────┘
            │
            │ Used by translators to apply tags
            ▼
    ┌─────────────────────────────────────────────────────────┐
    │ @dataclass AssetData                                     │
    │ - asset_type: str                                       │
    │ - attributes: Dict                                      │
    │ - tags: List[Dict]                                      │
    │ - findings: List[Dict]                                  │
    └─────────────────────────────────────────────────────────┘
            │
            │ Created by translators, consumed by API client
            ▼
    ┌─────────────────────────────────────────────────────────┐
    │ @dataclass VulnerabilityData                            │
    │ - name, description, remedy, severity                   │
    │ - location, reference_ids, cwes                         │
    │ - published_date_time, details, tags                    │
    └─────────────────────────────────────────────────────────┘
            │
            │ Converted to dict and added to AssetData.findings
            ▼
    ┌─────────────────────────────────────────────────────────┐
    │ Phoenix API JSON Payload                                 │
    │ {                                                        │
    │   "importType": "new",                                  │
    │   "assessment": { ... },                                │
    │   "assets": [ ... ]                                     │
    │ }                                                        │
    └─────────────────────────────────────────────────────────┘
```

---

## API Client Flow (phoenix_import_refactored.py)

```
┌─────────────────────────────────────────────────────────────┐
│ PhoenixAPIClient                                             │
│                                                              │
│ Step 1: Authentication                                       │
│    get_access_token()                                        │
│    ├─ GET /v1/auth/access_token                             │
│    ├─ HTTPBasicAuth(client_id, client_secret)               │
│    └─ Cache token (expires in 1 hour)                       │
│                                                              │
│ Step 2: Import Assets                                       │
│    import_assets(assets, assessment_name)                   │
│    ├─ Convert AssetData → Phoenix JSON format               │
│    │  • Transform field names (snake_case → camelCase)      │
│    │  • Never include asset IDs                             │
│    │  • Build payload structure                             │
│    │                                                         │
│    ├─ POST /v1/import/assets                                │
│    │  Headers:                                              │
│    │    - Authorization: Bearer {token}                     │
│    │    - Content-Type: application/json                    │
│    │  Body: {importType, assessment, assets}                │
│    │                                                         │
│    └─ Return (request_id, response_data)                    │
│                                                              │
│ Step 3: Check Status (optional)                             │
│    wait_for_import_completion(request_id)                   │
│    ├─ Poll GET /v1/import/assets/file/translate/request/ID  │
│    ├─ Check status: TRANSLATING → READY → IMPORTED          │
│    └─ Return final status                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Batching Logic Flow (phoenix_import_enhanced.py)

```
┌─────────────────────────────────────────────────────────────┐
│ EnhancedPhoenixImportManager.import_assets_with_batching()  │
│                                                              │
│ INPUT: List[AssetData] (could be 1000s of assets)           │
│                                                              │
│ Step 1: Pre-import validation                               │
│    _validate_assets_batch(assets)                           │
│    ├─ Check required fields                                 │
│    ├─ Validate severity format                              │
│    ├─ Check payload size                                    │
│    └─ Return ValidationResult                               │
│                                                              │
│ Step 2: Calculate optimal batching                          │
│    _create_batches(assets)                                  │
│    ├─ Analyze vulnerability density                         │
│    │  • avg_vulns = total_vulns / total_assets              │
│    │                                                         │
│    ├─ Calculate batch size                                  │
│    │  • Consider max_payload_size_mb (20MB default)         │
│    │  • Consider max_batch_size (100 assets default)        │
│    │  • Adjust based on vuln density                        │
│    │                                                         │
│    ├─ Create batches                                        │
│    │  • Split assets into optimal chunks                    │
│    │  • Validate each batch size                            │
│    │  • Re-split if batch too large                         │
│    │                                                         │
│    └─ Returns: List[List[AssetData]]                        │
│                                                              │
│ Step 3: Process each batch                                  │
│    FOR batch_num, batch_assets in batches:                  │
│                                                              │
│        _process_batch_with_retry(batch_assets, ...)         │
│        │                                                     │
│        ├─ Attempt 1 (immediate)                             │
│        │  └─ PhoenixAPIClient.import_assets()               │
│        │                                                     │
│        ├─ IF FAILED: Attempt 2 (after 2s delay)             │
│        │  └─ PhoenixAPIClient.import_assets()               │
│        │                                                     │
│        ├─ IF FAILED: Attempt 3 (after 4s delay)             │
│        │  └─ PhoenixAPIClient.import_assets()               │
│        │                                                     │
│        └─ IF FAILED: Attempt 4 (after 8s delay)             │
│           └─ PhoenixAPIClient.import_assets()               │
│                                                              │
│        Returns: BatchResult                                 │
│          - success: bool                                    │
│          - assets_processed: int                            │
│          - vulnerabilities_processed: int                   │
│          - request_id: str                                  │
│          - error_message: str                               │
│          - retry_count: int                                 │
│                                                              │
│        Rate limiting delay (2s between batches)             │
│                                                              │
│ Step 4: Build ImportSession summary                         │
│    ImportSession                                            │
│      - session_id                                           │
│      - total_batches                                        │
│      - completed_batches                                    │
│      - failed_batches                                       │
│      - batch_results: List[BatchResult]                     │
│      - success_rate: float                                  │
│                                                              │
│ OUTPUT: ImportSession                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Complete Request Flow Example

```
User Command:
  python phoenix_multi_scanner_enhanced.py \
    --file trivy-scan.json \
    --assessment "Q4-Container-Scan" \
    --enable-batching

    ↓
┌──────────────────────────────────────────────────────────────┐
│ 1. INITIALIZATION                                             │
│    EnhancedMultiScannerImportManager                         │
│    ├─ Load config (PhoenixConfig from refactored)            │
│    ├─ Create API client (PhoenixAPIClient from refactored)   │
│    ├─ Create enhanced importer (from enhanced)               │
│    └─ Defer translator loading                               │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 2. TRANSLATOR INITIALIZATION (lazy)                          │
│    _ensure_translators_initialized()                         │
│    ├─ Import 42 hardcoded translators                        │
│    │  from scanner_translators/ module                       │
│    ├─ Import legacy translators                              │
│    │  from phoenix_multi_scanner_import                      │
│    └─ Add ConfigurableScannerTranslator (YAML)               │
│       from phoenix_multi_scanner_import                      │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 3. SCANNER DETECTION                                         │
│    detect_scanner_type("trivy-scan.json")                    │
│    ├─ Try TrivyTranslator.can_handle() → ✅ Match!           │
│    └─ Return TrivyTranslator instance                        │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 4. FILE PARSING                                              │
│    TrivyTranslator.parse_file("trivy-scan.json")            │
│    ├─ Read JSON file                                         │
│    ├─ Detect Trivy format (new/legacy/k8s)                   │
│    ├─ Extract vulnerabilities                                │
│    ├─ Create AssetData objects                               │
│    │  └─ AssetData(asset_type="CONTAINER", ...)             │
│    │      └─ findings=[VulnerabilityData(...), ...]          │
│    └─ Return List[AssetData]                                 │
│       Example: [Asset1 (50 vulns), Asset2 (30 vulns)]       │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 5. DATA VALIDATION (if fix_data=True)                       │
│    EnhancedDataValidator.validate_and_fix_csv()              │
│    ├─ Check required fields                                  │
│    ├─ Validate date formats                                  │
│    ├─ Fix common issues                                      │
│    └─ Return ValidationResult                                │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 6. BATCHING & IMPORT                                         │
│    enhanced_importer.import_assets_with_batching(            │
│        assets=[Asset1, Asset2],                              │
│        assessment_name="Q4-Container-Scan",                  │
│        import_type="new"                                     │
│    )                                                         │
│                                                              │
│    ┌────────────────────────────────────────────────┐       │
│    │ Calculate batches:                              │       │
│    │   Total: 2 assets, 80 vulnerabilities           │       │
│    │   Batch size: 50 assets (within limits)         │       │
│    │   Result: 1 batch                                │       │
│    └────────────────────────────────────────────────┘       │
│                                                              │
│    ┌────────────────────────────────────────────────┐       │
│    │ Process Batch 1:                                │       │
│    │   PhoenixAPIClient.import_assets(               │       │
│    │       [Asset1, Asset2],                         │       │
│    │       "Q4-Container-Scan"                       │       │
│    │   )                                              │       │
│    │   ├─ Get access token                           │       │
│    │   ├─ Build JSON payload                         │       │
│    │   ├─ POST /v1/import/assets                     │       │
│    │   └─ Return (request_id="abc123", response)     │       │
│    └────────────────────────────────────────────────┘       │
│                                                              │
│    Returns: ImportSession                                    │
│      - session_id: "import_20251113_1430"                   │
│      - total_batches: 1                                     │
│      - completed_batches: 1                                 │
│      - failed_batches: 0                                    │
│      - success_rate: 100.0%                                 │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 7. RESULT CONVERSION                                         │
│    _convert_session_to_result(session, ...)                 │
│    └─ Build result dictionary:                               │
│       {                                                      │
│         'success': True,                                     │
│         'scanner_type': 'Trivy',                             │
│         'assessment_name': 'Q4-Container-Scan',              │
│         'assets_imported': 2,                                │
│         'vulnerabilities_imported': 80,                      │
│         'batching_used': True,                               │
│         'batch_summary': { ... }                             │
│       }                                                      │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ 8. OUTPUT TO USER                                            │
│    ✅ Successfully processed trivy-scan.json                 │
│       Scanner: Trivy                                         │
│       Assessment: Q4-Container-Scan                          │
│       Assets: 2                                              │
│       Vulnerabilities: 80                                    │
│       Batches: 1/1 successful                                │
│       Success Rate: 100.0%                                   │
└──────────────────────────────────────────────────────────────┘
```

---

## Summary: How The 3 Modules Work Together

| Module | Role | What It Provides | Used By Enhanced Manager |
|--------|------|------------------|--------------------------|
| **phoenix_import_refactored.py** | **Foundation** | Core data classes, API client, base manager, logging | • Inherits from PhoenixImportManager<br>• Uses PhoenixConfig, TagConfig<br>• Uses AssetData, VulnerabilityData<br>• Uses PhoenixAPIClient for API calls |
| **phoenix_import_enhanced.py** | **Batching Layer** | Smart batching, retry logic, validation | • Creates EnhancedPhoenixImportManager instance<br>• Delegates batched imports to it<br>• Uses ImportSession & BatchResult |
| **phoenix_multi_scanner_import.py** | **Translation Layer** | Scanner translators, format detection | • Imports ScannerTranslator base class<br>• Imports 7+ legacy translators<br>• Imports ConfigurableScannerTranslator |

### Key Design Pattern: **Composition over Inheritance**

```python
class EnhancedMultiScannerImportManager:
    def __init__(self, config_file):
        # Inherit from base
        PhoenixImportManager.__init__(self, config_file)
        
        # Compose with enhanced importer (for batching)
        self.enhanced_importer = EnhancedPhoenixImportManager(config_file)
        
        # Compose with translators (for scanning)
        self.translators = [
            # 42 from scanner_translators/
            # 7+ from phoenix_multi_scanner_import
            # 1 ConfigurableScannerTranslator (YAML)
        ]
```

This design gives `phoenix_multi_scanner_enhanced.py` **all the capabilities** while keeping modules **loosely coupled** and **independently maintainable**.

