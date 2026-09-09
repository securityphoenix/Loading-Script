# Batching and Import Types - Detailed Explanation

## Table of Contents
1. [Batch Processing Mechanism](#batch-processing-mechanism)
2. [Import Types Explained](#import-types-explained)
3. [How to Prevent Data Overwrite](#how-to-prevent-data-overwrite)
4. [Code Examples](#code-examples)

---

## 1. Batch Processing Mechanism

### Overview

The batching system in `phoenix_import_enhanced.py` intelligently splits large payloads into smaller chunks to prevent API timeouts and memory issues.

### Step-by-Step Batch Flow

```python
# Location: phoenix_import_enhanced.py
# Class: EnhancedPhoenixImportManager

def import_assets_with_batching(self, assets, assessment_name, import_type="new"):
    """Main batching orchestration method"""
```

#### Step 1: Calculate Optimal Batch Size

```python
# Lines 221-284 in phoenix_import_enhanced.py

def _create_batches(self, assets: List[AssetData]) -> List[List[AssetData]]:
    """Create optimal batches based on payload size and item count"""
    
    # Don't batch if dataset is small
    if len(assets) <= self.min_batch_size:
        return [assets]  # Return all assets in single batch
    
    # Calculate vulnerability density
    total_vulnerabilities = sum(len(asset.findings) for asset in assets)
    avg_vulnerabilities_per_asset = total_vulnerabilities / len(assets)
    
    # Example:
    # 100 assets with 5000 vulnerabilities
    # avg_vulnerabilities_per_asset = 50
    
    # Calculate optimal batch size
    optimal_batch_size = self.validator.calculate_optimal_batch_size(
        len(assets),
        self.max_payload_size_mb,  # Default: 20 MB
        int(avg_vulnerabilities_per_asset)
    )
    
    # Ensure batch size is within bounds
    batch_size = max(
        self.min_batch_size,  # Default: 5 assets
        min(optimal_batch_size, self.max_batch_size)  # Default: 100 assets
    )
```

**Key Configuration Parameters:**
```python
# Default values in EnhancedPhoenixImportManager.__init__()
self.max_payload_size_mb = 20.0     # Maximum 20MB per request
self.max_batch_size = 100           # Maximum 100 assets per batch
self.min_batch_size = 5             # Minimum 5 assets per batch
```

**Intelligent Batch Sizing Algorithm:**
```
IF assets have HIGH vulnerability density (e.g., 100 vulns/asset):
   → Use SMALLER batches (e.g., 10 assets/batch)
   → Prevents payload from exceeding 20MB limit

IF assets have LOW vulnerability density (e.g., 2 vulns/asset):
   → Use LARGER batches (e.g., 100 assets/batch)
   → Maximizes throughput

IF batch still too large after calculation:
   → Re-split into smaller sub-batches
   → Continue until each batch is within limits
```

#### Step 2: Validate Each Batch

```python
# Lines 248-282 in phoenix_import_enhanced.py

for i in range(0, len(assets), batch_size):
    batch = assets[i:i + batch_size]
    
    # Validate batch size doesn't exceed payload limit
    batch_validation = self.validator.validate_payload_size(
        [asset.__dict__ for asset in batch],
        self.max_payload_size_mb
    )
    
    if not batch_validation.is_valid:
        # Batch is TOO LARGE - split it further
        current_vulns = sum(len(asset.findings) for asset in batch)
        target_vulns = int(current_vulns * 0.5)  # Reduce by 50%
        
        # Calculate new smaller batch size
        avg_vulns_per_asset = current_vulns / len(batch)
        new_batch_size = max(1, int(target_vulns / avg_vulns_per_asset))
        
        # Recursively split into smaller batches
        for j in range(0, len(batch), new_batch_size):
            smaller_batch = batch[j:j + new_batch_size]
            batches.append(smaller_batch)
    else:
        # Batch is within limits - add it
        batches.append(batch)
```

#### Step 3: Process Each Batch with Retry Logic

```python
# Lines 286-350 in phoenix_import_enhanced.py

def _process_batch_with_retry(self, batch_assets, assessment_name, 
                             import_type, batch_number) -> BatchResult:
    """Process a single batch with exponential backoff retry"""
    
    for attempt in range(self.max_retries + 1):  # 0, 1, 2, 3 (4 total attempts)
        try:
            # Rate limiting - wait before making request
            self._rate_limit_delay()
            
            # Attempt import using API client
            api_client = PhoenixAPIClient(self.phoenix_config)
            result = api_client.import_assets(batch_assets, assessment_name)
            
            # SUCCESS - return immediately
            return BatchResult(
                batch_number=batch_number,
                success=True,
                assets_processed=len(batch_assets),
                vulnerabilities_processed=sum(len(asset.findings) for asset in batch_assets),
                request_id=request_id,
                retry_count=attempt
            )
            
        except Exception as e:
            if attempt < self.max_retries:
                # Calculate exponential backoff delay
                delay = min(
                    self.base_retry_delay * (self.retry_backoff_factor ** attempt),
                    self.max_retry_delay
                )
                # delay = 2.0 * (2.0 ** attempt)
                # Attempt 0: 2s
                # Attempt 1: 4s
                # Attempt 2: 8s
                # Attempt 3: 16s (capped at max_retry_delay=60s)
                
                logger.warning(f"Batch {batch_number} attempt {attempt+1} failed")
                logger.info(f"Retrying in {delay:.1f} seconds...")
                time.sleep(delay)
            else:
                # All retries exhausted - return failure
                return BatchResult(
                    batch_number=batch_number,
                    success=False,
                    error_message=str(e),
                    retry_count=self.max_retries
                )
```

**Retry Configuration:**
```python
self.max_retries = 3                    # Total 4 attempts (1 initial + 3 retries)
self.base_retry_delay = 2.0             # Start with 2 second delay
self.max_retry_delay = 60.0             # Maximum 60 second delay
self.retry_backoff_factor = 2.0         # Double the delay each time
```

#### Step 4: Rate Limiting Between Batches

```python
# Lines 352-362 in phoenix_import_enhanced.py

def _rate_limit_delay(self):
    """Apply rate limiting between requests"""
    current_time = time.time()
    time_since_last = current_time - self.last_request_time
    
    if time_since_last < self.request_interval:
        delay = self.request_interval - time_since_last
        time.sleep(delay)
    
    self.last_request_time = time.time()

# Configuration
self.requests_per_minute = 30           # Maximum 30 requests per minute
self.request_interval = 60.0 / 30       # 2 seconds between requests
```

#### Step 5: Track Results and Build Session

```python
# Lines 112-145 in phoenix_import_enhanced.py

session = ImportSession(
    session_id=f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
    total_batches=len(batches),
    total_assets=len(assets),
    total_vulnerabilities=sum(len(asset.findings) for asset in assets)
)

# Process each batch
for batch_num, batch_assets in enumerate(batches, 1):
    batch_result = self._process_batch_with_retry(
        batch_assets, assessment_name, import_type, batch_num
    )
    
    session.batch_results.append(batch_result)
    
    if batch_result.success:
        session.completed_batches += 1
    else:
        session.failed_batches += 1

# Calculate success rate
session.success_rate = (session.completed_batches / session.total_batches) * 100
```

### Batching Example

```
INPUT:
  - 500 assets
  - 10,000 vulnerabilities
  - Average: 20 vulnerabilities per asset

BATCH CALCULATION:
  1. Check min_batch_size (5) - exceeded, continue
  2. Calculate optimal size based on payload limit (20MB)
  3. Estimate: ~25 assets per batch (keeps payload < 20MB)
  4. Result: 20 batches of 25 assets each

PROCESSING:
  Batch 1:  25 assets, 500 vulns → POST /v1/import/assets → ✅ Success (request_id: abc123)
  Batch 2:  25 assets, 500 vulns → POST /v1/import/assets → ✅ Success (request_id: def456)
  Batch 3:  25 assets, 500 vulns → POST /v1/import/assets → ❌ Failed → Retry → ✅ Success
  ...
  Batch 20: 25 assets, 500 vulns → POST /v1/import/assets → ✅ Success (request_id: xyz789)

RESULT:
  ImportSession:
    - total_batches: 20
    - completed_batches: 20
    - failed_batches: 0
    - success_rate: 100.0%
    - total_assets: 500
    - total_vulnerabilities: 10,000
```

---

## 2. Import Types Explained

### Critical Concept: How Import Types Affect Data

The `import_type` parameter controls **how Phoenix handles existing data** in an assessment when new data arrives.

```python
# Location: phoenix_import_refactored.py, lines 1076-1083
payload = {
    "importType": self.config.import_type,  # "new", "merge", or "delta"
    "assessment": {
        "assetType": assets[0].asset_type,
        "name": assessment_name
    },
    "assets": phoenix_assets
}
```

### Three Import Types

#### Type 1: `"new"` - Complete Replacement

**Behavior:** Remove existing vulnerabilities first, then import new data

```python
import_type = "new"  # DEFAULT

# Phoenix API Logic (pseudo-code):
def process_import_new(assessment, new_data):
    # Step 1: Mark ALL existing vulnerabilities as CLOSED/FIXED
    for existing_vuln in assessment.vulnerabilities:
        existing_vuln.status = "FIXED"
        existing_vuln.closed_date = now()
    
    # Step 2: Import new vulnerabilities
    for new_vuln in new_data.vulnerabilities:
        if vuln_exists_in_assessment(new_vuln):
            # Re-open existing vulnerability
            existing_vuln.status = "OPEN"
            existing_vuln.updated_date = now()
        else:
            # Create new vulnerability
            create_vulnerability(new_vuln)
    
    # Result: Only vulnerabilities in new_data are OPEN
    #         Everything else is marked FIXED
```

**Example:**
```
BEFORE Import (Assessment "Q4-Scan"):
  Asset-1: CVE-2024-0001 (OPEN), CVE-2024-0002 (OPEN), CVE-2024-0003 (OPEN)
  Asset-2: CVE-2024-0004 (OPEN), CVE-2024-0005 (OPEN)

IMPORT with type="new":
  Asset-1: CVE-2024-0001, CVE-2024-0002, CVE-2024-0099  # CVE-0003 missing!
  Asset-2: CVE-2024-0004                                 # CVE-0005 missing!

AFTER Import:
  Asset-1: CVE-2024-0001 (OPEN), CVE-2024-0002 (OPEN), CVE-2024-0003 (FIXED ✓), CVE-2024-0099 (OPEN ✓)
  Asset-2: CVE-2024-0004 (OPEN), CVE-2024-0005 (FIXED ✓)

📋 Summary:
  - CVE-2024-0003: Marked FIXED (was OPEN, not in new scan)
  - CVE-2024-0005: Marked FIXED (was OPEN, not in new scan)
  - CVE-2024-0099: Created NEW (was not in assessment)
```

**Use Cases:**
- ✅ Complete full scans (all assets, all vulnerabilities)
- ✅ Weekly/monthly scheduled scans
- ✅ Want to track what was FIXED since last scan
- ❌ Partial scans (will incorrectly close active vulnerabilities!)

#### Type 2: `"merge"` - Combine with Existing

**Behavior:** Update existing data, add new data, preserve other data

```python
import_type = "merge"

# Phoenix API Logic (pseudo-code):
def process_import_merge(assessment, new_data):
    # Step 1: Update vulnerabilities for assets in new_data
    for new_asset in new_data.assets:
        existing_asset = find_asset_in_assessment(new_asset)
        
        if existing_asset:
            # Mark existing vulnerabilities as FIXED if not in new data
            for existing_vuln in existing_asset.vulnerabilities:
                if not vuln_in_new_data(existing_vuln, new_asset.vulnerabilities):
                    existing_vuln.status = "FIXED"
            
            # Add/update vulnerabilities from new data
            for new_vuln in new_asset.vulnerabilities:
                if vuln_exists(new_vuln):
                    update_vulnerability(new_vuln)
                else:
                    create_vulnerability(new_vuln)
        else:
            # Create new asset with all vulnerabilities
            create_asset(new_asset)
    
    # Step 2: PRESERVE assets NOT in new_data (key difference from "new")
    # Assets not mentioned in new_data remain unchanged
```

**Example:**
```
BEFORE Import (Assessment "Multi-Scanner-Scan"):
  Asset-1: CVE-2024-0001 (OPEN, from Trivy)
  Asset-2: CVE-2024-0004 (OPEN, from Trivy)
  Asset-3: CVE-2024-0010 (OPEN, from Trivy)

IMPORT with type="merge" (Grype scan only Asset-1 and Asset-2):
  Asset-1: CVE-2024-0001, CVE-2024-0099
  Asset-2: CVE-2024-0004, CVE-2024-0088

AFTER Import:
  Asset-1: CVE-2024-0001 (OPEN), CVE-2024-0099 (OPEN ✓)
  Asset-2: CVE-2024-0004 (OPEN), CVE-2024-0088 (OPEN ✓)
  Asset-3: CVE-2024-0010 (OPEN) ← PRESERVED! Not touched by Grype import

📋 Summary:
  - Asset-1, Asset-2: Updated with Grype results
  - Asset-3: PRESERVED unchanged (not scanned by Grype)
  - Good for combining multiple scanner results
```

**Use Cases:**
- ✅ Combining results from multiple scanners
- ✅ Updating specific assets without affecting others
- ✅ Incremental updates to assessment
- ❌ Still closes vulnerabilities if not in new data for scanned assets!

#### Type 3: `"delta"` - Add Only, Never Close (SAFEST)

**Behavior:** Add new findings, update existing findings, NEVER mark anything as FIXED

```python
import_type = "delta"  # SAFEST OPTION

# Phoenix API Logic (pseudo-code):
def process_import_delta(assessment, new_data):
    # Add or update vulnerabilities ONLY
    # NEVER mark anything as FIXED
    
    for new_asset in new_data.assets:
        existing_asset = find_asset_in_assessment(new_asset)
        
        if existing_asset:
            # Add/update vulnerabilities from new data
            for new_vuln in new_asset.vulnerabilities:
                if vuln_exists(new_vuln):
                    # Update if newer/different
                    update_vulnerability(new_vuln)
                else:
                    # Add as new vulnerability
                    create_vulnerability(new_vuln)
            
            # CRITICAL: DO NOT touch vulnerabilities not in new_data
            # They remain OPEN
        else:
            # Create new asset with vulnerabilities
            create_asset(new_asset)
```

**Example:**
```
BEFORE Import (Assessment "Incremental-Scan"):
  Asset-1: CVE-2024-0001 (OPEN), CVE-2024-0002 (OPEN), CVE-2024-0003 (OPEN)

IMPORT with type="delta" (partial scan of Asset-1 only):
  Asset-1: CVE-2024-0001, CVE-2024-0099  # Only scanned for these 2

AFTER Import:
  Asset-1: CVE-2024-0001 (OPEN), CVE-2024-0002 (OPEN ✓), CVE-2024-0003 (OPEN ✓), CVE-2024-0099 (OPEN ✓)

📋 Summary:
  - CVE-2024-0001: Updated (was already there)
  - CVE-2024-0002: PRESERVED OPEN (even though not in scan)
  - CVE-2024-0003: PRESERVED OPEN (even though not in scan)
  - CVE-2024-0099: Added NEW
  - NO vulnerabilities marked FIXED
```

**Use Cases:**
- ✅ **Partial/incomplete scans** (SAFEST)
- ✅ Testing and development
- ✅ When unsure if scan data is complete
- ✅ Incremental vulnerability discovery
- ✅ **Default recommendation when in doubt**

### Comparison Table

| Feature | `new` | `merge` | `delta` |
|---------|-------|---------|---------|
| Creates new assets | ✓ | ✓ | ✓ |
| Updates existing assets | ✓ | ✓ | ✓ |
| Adds new vulnerabilities | ✓ | ✓ | ✓ |
| Updates existing vulnerabilities | ✓ | ✓ | ✓ |
| **Closes missing vulnerabilities** | **✓** | **✓** | **✗** |
| Removes vulnerabilities first | ✓ | ✗ | ✗ |
| Preserves assets not in scan | ✗ | ✓ | ✓ |
| Safe for partial data | ✗ | ✗ | **✓** |
| Requires complete scan data | ✓ | ✓ | ✗ |

---

## 3. How to Prevent Data Overwrite

### Problem: Accidental Vulnerability Closure

**Scenario:** You have a complete scan with 100 vulnerabilities. You run a partial scan that only checks 10 assets and finds 5 vulnerabilities. If you use `import_type="new"`, Phoenix will mark the other 95 vulnerabilities as FIXED!

### Solution 1: Use `"delta"` for Partial Scans (Recommended)

```bash
# SAFE: Will NOT close existing vulnerabilities
python3 phoenix_multi_scanner_enhanced.py \
  --file partial-scan.json \
  --assessment "My-Assessment" \
  --import-type delta  # ← SAFEST option
```

**Code Location:**
```python
# phoenix_multi_scanner_enhanced.py, line 1032
parser.add_argument('--import-type', 
                   choices=['new', 'merge', 'delta'], 
                   default='new',  # ← Default, but can override
                   help='Import type (default: new)')
```

### Solution 2: Use Different Assessments for Different Scans

```bash
# Assessment 1: Complete monthly scan
python3 phoenix_multi_scanner_enhanced.py \
  --file monthly-complete-scan.json \
  --assessment "Monthly-Complete-Scan-Nov2024" \
  --import-type new  # Safe because it's complete

# Assessment 2: Daily incremental scan
python3 phoenix_multi_scanner_enhanced.py \
  --file daily-partial-scan.json \
  --assessment "Daily-Incremental-Nov13" \
  --import-type delta  # Safe because it's partial
```

### Solution 3: Combine Multiple Scanners with `"merge"`

```bash
# First scanner: Trivy (complete scan)
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-results.json \
  --assessment "Q4-Security-Review" \
  --import-type new  # Fresh start

# Second scanner: Grype (additional findings)
python3 phoenix_multi_scanner_enhanced.py \
  --file grype-results.json \
  --assessment "Q4-Security-Review" \
  --import-type merge  # ← Combine results

# Third scanner: Aqua (more findings)
python3 phoenix_multi_scanner_enhanced.py \
  --file aqua-results.json \
  --assessment "Q4-Security-Review" \
  --import-type merge  # ← Continue combining
```

### Decision Tree

```
┌─────────────────────────────────────────────────────────────┐
│ Do you have COMPLETE scan results for ALL assets?          │
└─────────────────────────────────────────────────────────────┘
           │
           ├─ YES → Do you want to replace ALL existing data?
           │         │
           │         ├─ YES → Use "new"
           │         │         • Marks missing vulns as FIXED
           │         │         • Complete refresh
           │         │
           │         └─ NO  → Use "merge"
           │                  • Combines with existing data
           │                  • Preserves other assets
           │
           └─ NO (partial/incomplete data)
                     │
                     └─ Use "delta" (SAFEST)
                        • Never closes vulnerabilities
                        • Safe for any scenario
```

---

## 4. Code Examples

### Example 1: Large Scan with Batching

```python
# Scenario: 1000 assets, 50,000 vulnerabilities
# File: large-trivy-scan.json

# Command
python3 phoenix_multi_scanner_enhanced.py \
  --file large-trivy-scan.json \
  --assessment "Q4-Container-Security" \
  --import-type new \
  --enable-batching \
  --max-batch-size 50 \
  --max-payload-mb 15.0

# What Happens:
# 1. Calculate batch size: 50 assets/batch (based on vuln density)
# 2. Create 20 batches
# 3. Process each batch:
#    Batch 1/20: 50 assets, 2500 vulns → POST → ✅ Success (2s delay)
#    Batch 2/20: 50 assets, 2500 vulns → POST → ✅ Success (2s delay)
#    ...
#    Batch 20/20: 50 assets, 2500 vulns → POST → ✅ Success
# 4. Return ImportSession with success_rate: 100.0%
```

### Example 2: Retry Logic in Action

```python
# Scenario: Network issues cause temporary failures

# Batch 5/20: First attempt
#   → POST /v1/import/assets
#   → ❌ Connection timeout

# Batch 5/20: Retry 1 (after 2 seconds)
#   → POST /v1/import/assets
#   → ❌ 503 Service Unavailable

# Batch 5/20: Retry 2 (after 4 seconds)
#   → POST /v1/import/assets
#   → ✅ Success!

# Result: Batch completed successfully after 2 retries
```

### Example 3: Preventing Overwrite with Delta

```python
# Scenario: Weekly full scan + daily partial scans

# Monday: Full scan (1000 assets)
python3 phoenix_multi_scanner_enhanced.py \
  --file monday-full-scan.json \
  --assessment "Weekly-Security-Review" \
  --import-type new  # ✅ Safe (complete data)

# Result:
# Assessment "Weekly-Security-Review": 1000 assets, 5000 vulnerabilities

# Tuesday: Partial scan (100 assets)
python3 phoenix_multi_scanner_enhanced.py \
  --file tuesday-critical-assets.json \
  --assessment "Weekly-Security-Review" \
  --import-type delta  # ✅ Safe (partial data)

# Result:
# Assessment "Weekly-Security-Review": 1000 assets, 5050 vulnerabilities
# - 100 assets updated
# - 900 assets unchanged (not rescanned)
# - 50 new vulnerabilities added
# - 0 vulnerabilities closed ← Key benefit!

# Wednesday: Another partial scan (50 assets)
python3 phoenix_multi_scanner_enhanced.py \
  --file wednesday-new-assets.json \
  --assessment "Weekly-Security-Review" \
  --import-type delta  # ✅ Safe (partial data)

# Result:
# Assessment "Weekly-Security-Review": 1000 assets, 5075 vulnerabilities
# - Continues accumulating findings safely
```

### Example 4: Combining Multiple Scanners

```python
# Scenario: Use Trivy + Grype + Aqua for comprehensive coverage

# Step 1: Trivy scan (baseline)
python3 phoenix_multi_scanner_enhanced.py \
  --file trivy-scan.json \
  --assessment "Multi-Scanner-Audit" \
  --import-type new

# Assessment: 200 assets, 1000 vulnerabilities (from Trivy)

# Step 2: Grype scan (additional coverage)
python3 phoenix_multi_scanner_enhanced.py \
  --file grype-scan.json \
  --assessment "Multi-Scanner-Audit" \
  --import-type merge  # ← Combine with Trivy

# Assessment: 200 assets, 1500 vulnerabilities (Trivy + Grype)
# - Grype found 500 additional vulnerabilities
# - Overlapping vulnerabilities deduplicated by Phoenix

# Step 3: Aqua scan (final coverage)
python3 phoenix_multi_scanner_enhanced.py \
  --file aqua-scan.json \
  --assessment "Multi-Scanner-Audit" \
  --import-type merge  # ← Combine with Trivy + Grype

# Assessment: 200 assets, 1800 vulnerabilities (Trivy + Grype + Aqua)
# - Aqua found 300 additional vulnerabilities
# - Comprehensive multi-scanner coverage
```

### Example 5: Batch Failure Handling

```python
# Scenario: 10 batches, 1 fails completely after all retries

# ImportSession Results:
{
    'session_id': 'import_20241113_1430',
    'total_batches': 10,
    'completed_batches': 9,
    'failed_batches': 1,
    'success_rate': 90.0,
    'batch_results': [
        BatchResult(batch_number=1, success=True, assets_processed=50, ...),
        BatchResult(batch_number=2, success=True, assets_processed=50, ...),
        ...
        BatchResult(batch_number=7, success=False, error_message='Connection timeout', retry_count=3),
        ...
        BatchResult(batch_number=10, success=True, assets_processed=50, ...)
    ]
}

# Result:
# - 450 assets successfully imported (9 batches × 50 assets)
# - 50 assets failed (1 batch)
# - Success rate: 90%
# - User can retry failed batch manually or investigate errors
```

---

## Summary

### Batching Mechanism
1. **Intelligently splits** large payloads based on size and vulnerability density
2. **Validates** each batch before sending
3. **Retries** failed batches with exponential backoff (up to 4 attempts)
4. **Rate limits** to avoid overwhelming the API (2s between requests)
5. **Tracks** detailed results for each batch

### Import Type Safety
1. **Use `"new"`** for complete scans when you want to track fixes
2. **Use `"merge"`** for combining multiple scanner results
3. **Use `"delta"`** for partial scans or when unsure (SAFEST)
4. **Never use `"new"` or `"merge"`** with incomplete data
5. **Always use `"delta"`** for incremental updates

### Best Practices
- ✅ Enable batching for scans with >100 assets
- ✅ Use `delta` by default unless you're certain data is complete
- ✅ Use separate assessments for different environments
- ✅ Monitor batch success rates and retry failed batches
- ✅ Adjust `max_batch_size` and `max_payload_mb` based on data density

