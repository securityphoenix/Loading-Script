# Configuration Quick Reference

## 🎯 Configuration Priority

```
API Request Parameters (Highest)
         ↓
Environment Variables (.env)
         ↓
config_multi_scanner.ini (Base)
```

## 📋 What Can Be Overridden

| Parameter | config_multi_scanner.ini | Environment Variable | API Request |
|-----------|-------------------------|---------------------|-------------|
| **client_id** | ✅ `[phoenix] client_id` | ❌ | ✅ `phoenix_client_id` |
| **client_secret** | ✅ `[phoenix] client_secret` | ✅ `PHOENIX_CLIENT_SECRET` | ✅ `phoenix_client_secret` |
| **api_base_url** | ✅ `[phoenix] api_base_url` | ❌ | ✅ `phoenix_api_url` |
| **scanner_type** | ✅ `[scanner_*]` sections | ❌ | ✅ `scanner_type` |
| **import_type** | ✅ `[phoenix] import_type` | ❌ | ✅ `import_type` |
| **assessment_name** | ✅ `[phoenix] assessment_name` | ❌ | ✅ `assessment_name` |
| **asset_type** | ✅ `[scanner_*] asset_type` | ❌ | ✅ `asset_type` |

## 🚀 Quick Examples

### Use config defaults
```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json"
```
→ Uses all settings from `config_multi_scanner.ini`

### Override client and environment
```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "phoenix_client_id=prod-client-id" \
  -F "phoenix_api_url=https://api.appsecphx.io"
```
→ Uses production client and API, other settings from config

### Override import strategy
```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -H "X-API-Key: your-api-key" \
  -F "file=@scan.json" \
  -F "import_type=merge" \
  -F "assessment_name=Q4-Scan"
```
→ Merges with existing assessment

## 📁 File Locations

| File | Location (in container) | Purpose |
|------|------------------------|---------|
| `config_multi_scanner.ini` | `/parent/config_multi_scanner.ini` | Base Phoenix configuration |
| `.env` | `/app/.env` | Service environment variables |
| Uploaded files | `/app/uploads/` | Scanner output files |
| Logs | `/app/logs/` | Job processing logs |

## 🔑 Required Settings

### Minimum in config_multi_scanner.ini
```ini
[phoenix]
client_id = your-client-id
api_base_url = https://api.demo.appsecphx.io
```

### Minimum in .env
```bash
PHOENIX_CLIENT_SECRET=your-phoenix-secret
API_KEY=your-api-key
```

### OR provide via API
```bash
-F "phoenix_client_id=your-id"
-F "phoenix_client_secret=your-secret"
-F "phoenix_api_url=https://api.demo.appsecphx.io"
```

## 🎨 Common Patterns

### Pattern 1: Dev/Staging/Prod Environments

**config_multi_scanner.ini** (dev defaults):
```ini
[phoenix]
client_id = {REDACTED}
api_base_url = https://api.demo.appsecphx.io
```

**Switch to Production** (API override):
```bash
-F "phoenix_client_id=prod-client-id"
-F "phoenix_api_url=https://api.appsecphx.io"
```

### Pattern 2: Multi-Tenant

**config_multi_scanner.ini** (template):
```ini
[phoenix]
api_base_url = https://api.appsecphx.io
```

**Per-Tenant** (API override):
```bash
# Tenant A
-F "phoenix_client_id=tenant-a-id"

# Tenant B  
-F "phoenix_client_id=tenant-b-id"
```

### Pattern 3: Different Import Modes

**config_multi_scanner.ini** (default):
```ini
[phoenix]
import_type = new
```

**Per-Request** (API override):
```bash
# New assessment (default)
curl ... -F "file=@scan.json"

# Merge
curl ... -F "file=@scan.json" -F "import_type=merge"

# Delta
curl ... -F "file=@scan.json" -F "import_type=delta"
```

## 🛠️ Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| "No client_id provided" | Missing in both config and API | Add to config OR provide in API request |
| "No client_secret provided" | Missing PHOENIX_CLIENT_SECRET | Set in .env file |
| "Config file not found" | Volume mount issue | Check docker-compose.yml volumes |
| Wrong API used | Using wrong environment | Override with `phoenix_api_url` |

## 📚 Full Documentation

- **Complete Guide**: [CONFIGURATION_INTEGRATION.md](docs/CONFIGURATION_INTEGRATION.md)
- **All Settings**: [CONFIGURATION.md](docs/CONFIGURATION.md)
- **API Reference**: [API_REFERENCE.md](docs/API_REFERENCE.md)

## ✅ Key Takeaways

1. **Base config in INI file** → `config_multi_scanner.ini`
2. **Secrets in environment** → `.env` file
3. **Override via API** → Request parameters
4. **Priority**: API > Environment > Config file
5. **Flexible**: Use what works for your workflow!



