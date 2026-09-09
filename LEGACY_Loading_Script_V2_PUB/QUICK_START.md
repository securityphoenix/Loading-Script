# Quick Start Guide

## 🚀 Running the Phoenix Multi-Import Script

### One-Time Setup

1. **Ensure config.ini exists with your credentials**
   ```bash
   # Already configured with your credentials
   cat config.ini
   ```

2. **Install required dependencies** (if not already installed)
   ```bash
   pip install requests
   ```

### Usage Examples

#### Import All Scanners (Aqua, Snyk, Trivy)
```bash
python phoenix_multi_import.py
```
Then enter your client name when prompted (e.g., `TV`, `EPIC`, `Q2`)

#### Import Only Aqua Scans
```bash
python phoenix_multi_import.py aqua
```

#### Import Only Snyk Scans
```bash
python phoenix_multi_import.py snyk
```

#### Import Only Trivy Scans
```bash
python phoenix_multi_import.py trivy
```

### Client Name Examples

When you enter different client names, the script automatically generates appropriate targets:

**Client: TV**
- Aqua: `TST.PHX.TEST/POC1_CD_TV_app_backend:latest`
- Snyk: `com.tv.phx.test/Frontend/subrepo:latest`

**Client: EPIC**
- Aqua: `TST.PHX.TEST/POC1_CD_EPIC_app_backend:latest`
- Snyk: `com.epic.phx.test/Frontend/subrepo:latest`

**Client: Q2**
- Aqua: `TST.PHX.TEST/POC1_CD_Q2_app_backend:latest`
- Snyk: `com.q2.phx.test/Frontend/subrepo:latest`

### Expected Output

```
============================================================
Phoenix Multi-Scanner Import
============================================================

Enter client name (e.g., TV, EPIC, Q2): TV
✓ Client name set to: TV

Authenticating with Phoenix API...
✓ Authentication successful

------------------------------------------------------------
Starting Aqua Scan Import
------------------------------------------------------------

→ Importing Aqua Scan...
  Assessment: Container_pipeline_TV_1
  Target: TST.PHX.TEST/POC1_CD_TV_app_backend:latest
✓ Import successful (ID: 019a9758-d299-7ed2-b38f-0a3b6f9498be)
  Status: TRANSLATING

[... more imports ...]

============================================================
Import Summary
============================================================
Aqua Scan:  ✓ Success
Snyk Scan:  ✓ Success
Trivy Scan: ✓ Success
============================================================
```

### Number of Assessments per Scanner

- **Aqua**: 5 assessments (5 different container versions)
- **Snyk**: 2 assessments (Frontend + Backend)
- **Trivy**: 1 assessment (Container scan)
- **Total**: 8 assessments per run

### Troubleshooting

❌ **"File not found" error**
```
Solution: Check that files exist in scanner-sample/ directory:
- aqua_example2.json
- snyk_example.json
- trivy_mix.json
```

❌ **"Authentication failed"**
```
Solution: Verify credentials in config.ini
```

❌ **"Configuration file not found"**
```
Solution: Ensure config.ini exists in the same directory as the script
```

### Files Overview

```
Loading Script_V2/
├── phoenix_multi_import.py    # Main script (use this!)
├── config.ini                 # Your credentials (keep secure!)
├── config.ini.example         # Template for new users
├── scanner-sample/            # Scanner result files
│   ├── aqua_example2.json
│   ├── snyk_example.json
│   └── trivy_mix.json
├── QUICK_START.md            # This file
└── README_MULTI_IMPORT.md    # Detailed documentation
```

### 🎯 Recommended Workflow

1. **First time**: Run all scanners to test
   ```bash
   python phoenix_multi_import.py
   ```

2. **Regular use**: Run specific scanner as needed
   ```bash
   python phoenix_multi_import.py aqua
   ```

3. **Check results** in Phoenix Security Platform

### 🔐 Security Note

The `config.ini` file contains your API credentials. Keep it secure:
- ✅ DO: Keep file permissions restricted (`chmod 600 config.ini`)
- ❌ DON'T: Commit to version control
- ❌ DON'T: Share with unauthorized users

---

**Need more details?** See `README_MULTI_IMPORT.md` for comprehensive documentation.


