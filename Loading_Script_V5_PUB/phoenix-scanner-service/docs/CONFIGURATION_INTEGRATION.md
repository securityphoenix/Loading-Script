# Configuration Integration with config_multi_scanner.ini

## Overview

The Phoenix Scanner Service integrates seamlessly with the existing `config_multi_scanner.ini` configuration file while allowing API requests to override specific parameters.

## Configuration Layers

The service uses a **three-tier configuration system**:

```
┌─────────────────────────────────────────────────────────┐
│ Priority 1: API Request Parameters (Highest Priority)   │
│ - phoenix_client_id                                     │
│ - phoenix_client_secret                                 │
│ - phoenix_api_url                                       │
│ - scanner_type                                          │
│ - import_type                                           │
│ - assessment_name                                       │
│ - asset_type                                            │
└─────────────────────────────────────────────────────────┘
                         ↓ (if not provided)
┌─────────────────────────────────────────────────────────┐
│ Priority 2: Environment Variables (.env file)           │
│ - PHOENIX_CLIENT_SECRET                                 │
│ - PHOENIX_CONFIG_FILE                                   │
│ - Other service settings                                │
└─────────────────────────────────────────────────────────┘
                         ↓ (fallback)
┌─────────────────────────────────────────────────────────┐
│ Priority 3: config_multi_scanner.ini (Base Config)      │
│ - client_id                                             │
│ - client_secret (if not in environment)                 │
│ - api_base_url                                          │
│ - import_type                                           │
│ - assessment_name                                       │
│ - scanner-specific settings                             │
│ - batch_delay, timeout, etc.                            │
└─────────────────────────────────────────────────────────┘
```

## Configuration File Location

The service expects `config_multi_scanner.ini` to be mounted at:

```bash
/parent/config_multi_scanner.ini
```

This is configured in the Docker Compose volumes:

```yaml
services:
  worker:
    volumes:
      - ../:/parent:ro  # Mounts parent directory as /parent
```

## config_multi_scanner.ini Integration

### What Gets Used from config_multi_scanner.ini

The service reads and uses the following from `config_multi_scanner.ini`:

#### [phoenix] Section
- `client_id` - Used if not provided in API request
- `client_secret` - Used if PHOENIX_CLIENT_SECRET env var not set
- `api_base_url` - Used if not provided in API request
- `import_type` - Used if not provided in API request (new/merge/delta)
- `assessment_name` - Used if not provided in API request
- `auto_import` - Always used from config
- `wait_for_completion` - Always used from config
- `batch_delay` - Always used from config
- `timeout` - Always used from config
- `check_interval` - Always used from config

#### Scanner-Specific Sections
All scanner-specific sections are preserved and used:
- `[scanner_aqua]`
- `[scanner_anchore_grype]`
- `[scanner_trivy]`
- etc.

#### Other Sections
- `[logging]` - Log configuration
- `[batch_processing]` - Batch processing settings

### Example config_multi_scanner.ini

```ini
[phoenix]
client_id = your-default-client-id
client_secret = your-default-secret
api_base_url = https://api.demo.appsecphx.io
import_type = new
assessment_name = 
auto_import = true
wait_for_completion = true
batch_delay = 5
timeout = 3600

[scanner_trivy]
scanner_type = Trivy Scan
asset_type = CONTAINER
severity_mapping_critical = 10.0
severity_mapping_high = 8.0
```

## API Request Override Examples

### Example 1: Use config_multi_scanner.ini defaults

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json"
```

**Result**: Uses all settings from `config_multi_scanner.ini`

### Example 2: Override client_id and api_base_url

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "phoenix_client_id=different-client-id" \
  -F "phoenix_api_url=https://api.poc1.appsecphx.io"
```

**Result**: 
- Uses `different-client-id` instead of config file's client_id
- Uses `poc1` API instead of config file's api_base_url
- Other settings from config file remain

### Example 3: Override import type and assessment name

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "import_type=merge" \
  -F "assessment_name=Q4-2025-Security-Scan"
```

**Result**:
- Uses `merge` instead of config file's `import_type = new`
- Uses custom assessment name instead of auto-generated
- client_id and api_base_url from config file

### Example 4: Completely override all Phoenix settings

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "scanner_type=trivy" \
  -F "asset_type=CONTAINER" \
  -F "phoenix_client_id=custom-client-id" \
  -F "phoenix_client_secret=custom-secret" \
  -F "phoenix_api_url=https://api.appsecphx.io" \
  -F "import_type=delta" \
  -F "assessment_name=Custom Assessment"
```

**Result**: API parameters completely override config file

## Environment Variable Configuration

### Required Environment Variables

```bash
# .env file
PHOENIX_CLIENT_SECRET=your-phoenix-secret
PHOENIX_CONFIG_FILE=/parent/config_multi_scanner.ini
```

### Optional Environment Variables

```bash
# Override defaults from config file
ENABLE_BATCHING=true
FIX_DATA=true
MAX_BATCH_SIZE=500
MAX_PAYLOAD_MB=25.0
```

## Configuration Flow in Worker

When a job is processed, the worker:

1. **Loads base config** from `config_multi_scanner.ini`
2. **Checks environment variables** for PHOENIX_CLIENT_SECRET
3. **Applies job parameters** from API request (overrides)
4. **Creates temporary config** with merged settings
5. **Passes to phoenix_multi_scanner_enhanced.py**

### Worker Log Output

```
📋 Loading base configuration from: /parent/config_multi_scanner.ini
   Overriding client_id from API request
   Overriding api_base_url from API request: https://api.poc1.appsecphx.io
   Overriding import_type from API request: merge
   Using client_secret from environment variable
✅ Created temporary config: /tmp/phoenix_config_abc123.ini
   Final configuration:
     - client_id: custom-client-id...
     - api_base_url: https://api.poc1.appsecphx.io
     - import_type: merge
     - assessment_name: AUTO-GENERATED
     - scan_type: CONTAINER
```

## Common Scenarios

### Scenario 1: Development (Multiple Environments)

**config_multi_scanner.ini**:
```ini
[phoenix]
client_id = {REDACTED}
api_base_url = https://api.demo.appsecphx.io
```

**API Request for Production**:
```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -F "file=@scan.json" \
  -F "phoenix_client_id=prod-client-id" \
  -F "phoenix_api_url=https://api.appsecphx.io"
```

### Scenario 2: Multi-Tenant (Different Clients)

**config_multi_scanner.ini** (base template):
```ini
[phoenix]
api_base_url = https://api.appsecphx.io
import_type = new
```

**API Requests per Tenant**:
```bash
# Tenant A
curl ... -F "phoenix_client_id=tenant-a-id" -F "phoenix_client_secret=tenant-a-secret"

# Tenant B
curl ... -F "phoenix_client_id=tenant-b-id" -F "phoenix_client_secret=tenant-b-secret"
```

### Scenario 3: Different Import Strategies

**config_multi_scanner.ini** (default: new):
```ini
[phoenix]
import_type = new
```

**API Requests**:
```bash
# New assessment (default)
curl ... -F "file=@scan1.json"

# Merge with existing
curl ... -F "file=@scan2.json" -F "import_type=merge"

# Delta import only
curl ... -F "file=@scan3.json" -F "import_type=delta"
```

## Troubleshooting

### Issue: "No client_id provided"

**Problem**: Neither config file nor API request has client_id

**Solution**:
1. Add to `config_multi_scanner.ini`:
   ```ini
   [phoenix]
   client_id = your-client-id
   ```
2. Or provide in API request:
   ```bash
   -F "phoenix_client_id=your-client-id"
   ```

### Issue: "No client_secret provided"

**Problem**: Missing PHOENIX_CLIENT_SECRET environment variable

**Solution**:
```bash
# In .env file
PHOENIX_CLIENT_SECRET=your-phoenix-secret

# Restart services
docker-compose restart
```

### Issue: Config file not found

**Problem**: Worker can't find `config_multi_scanner.ini`

**Solution**: Check Docker Compose volumes:
```yaml
worker:
  volumes:
    - ../:/parent:ro  # Must mount parent directory
```

### Issue: Wrong API URL used

**Problem**: Using wrong Phoenix environment

**Solution**: Override in API request:
```bash
# For demo environment
-F "phoenix_api_url=https://api.demo.appsecphx.io"

# For poc1 environment
-F "phoenix_api_url=https://api.poc1.appsecphx.io"

# For production environment
-F "phoenix_api_url=https://api.appsecphx.io"
```

## Best Practices

### 1. Use config_multi_scanner.ini for Defaults

Store common/default values in `config_multi_scanner.ini`:
- Default client_id
- Default api_base_url
- Scanner configurations
- Timeouts and intervals

### 2. Use Environment Variables for Secrets

Store sensitive data in environment variables:
- PHOENIX_CLIENT_SECRET
- API_KEY
- Database passwords

### 3. Use API Parameters for Per-Request Overrides

Override via API for:
- Multi-tenant scenarios (different client_ids)
- Environment switching (dev/poc/prod)
- Custom assessment names
- Different import strategies

### 4. Document Your Configuration

Create a README documenting:
- Which values are in config_multi_scanner.ini
- Which values are in .env
- Which values should be provided via API

## Summary

✅ **Base Configuration**: `config_multi_scanner.ini` provides defaults  
✅ **Security**: `PHOENIX_CLIENT_SECRET` via environment variable  
✅ **Flexibility**: API parameters override any setting  
✅ **Backward Compatible**: Works with existing Phoenix Scanner configurations  
✅ **Multi-Tenant Ready**: Support multiple clients via API overrides  

The service seamlessly integrates with your existing `config_multi_scanner.ini` while providing the flexibility to override settings per API request!



