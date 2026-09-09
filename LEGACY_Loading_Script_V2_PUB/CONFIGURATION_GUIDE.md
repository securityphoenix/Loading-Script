# Loading Script_V2 — Configuration Guide

**Last Updated**: February 2026 | **Path**: `Utils/Loading Script_V2/`

---

> **Note**: This is the legacy V2 full version. See Loading_Script_V5 Configuration Guide for the current version.

## Configuration

Refer to `README.md` for V2-specific configuration. The credential pattern is the same as V5:

```ini
[phoenix]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
api_base_url = https://api.appsecphx.io
```

## Key Features (V2)

- Basic batch import with simple file processing
- Super script for multi-file imports
- Multi-import support

## Migration to V5

See Loading_Script_V5 for the current version with:
- 205+ scanner support (vs limited V2 support)
- Auto-detection of scanner type
- YAML-based field mapping
- Docker scanner service

## Related Documents

- [Readme](README.md) · [Quick Start](QUICK_START.md) · Loading_Script_V5 · Utils Master Index
