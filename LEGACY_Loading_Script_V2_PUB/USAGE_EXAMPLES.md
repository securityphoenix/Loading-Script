# Phoenix Multi-Import - Usage Examples

## 🎯 Common Use Cases

### Use Case 1: Import Everything for TV Client

**Command:**
```bash
python phoenix_multi_import.py
```

**What happens:**
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

→ Importing Aqua Scan...
  Assessment: Container_pipeline_TV_2
  Target: TST.PHX.TEST/POC1_CD_TV_app_backend:3_2
✓ Import successful
...

------------------------------------------------------------
Starting Snyk Scan Import
------------------------------------------------------------
→ Importing Snyk Scan...
  Assessment: Snyk_TV_Frontend
  Target: com.tv.phx.test/Frontend/subrepo:latest
✓ Import successful
...

------------------------------------------------------------
Starting Trivy Scan Import
------------------------------------------------------------
→ Importing Trivy Scan...
  Assessment: Trivy_TV_Container
  Target: com.tv.tests/example:latest
✓ Import successful

============================================================
Import Summary
============================================================
Aqua Scan:  ✓ Success
Snyk Scan:  ✓ Success
Trivy Scan: ✓ Success
============================================================
```

**Result:**
- 5 Aqua assessments imported
- 2 Snyk assessments imported
- 1 Trivy assessment imported
- **Total: 8 assessments**

---

### Use Case 2: Import Only Aqua Scans for EPIC Client

**Command:**
```bash
python phoenix_multi_import.py aqua
```

**Input:**
```
Enter client name (e.g., TV, EPIC, Q2): EPIC
```

**Result:**
- ✅ Container_pipeline_EPIC_1 → TST.PHX.TEST/POC1_CD_EPIC_app_backend:latest
- ✅ Container_pipeline_EPIC_2 → TST.PHX.TEST/POC1_CD_EPIC_app_backend:3_2
- ✅ Container_pipeline_EPIC_3 → TST.PHX.TEST/POC1_CD_EPIC_app_backend:3_1
- ✅ Container_pipeline_EPIC_4 → TST.PHX.TEST/POC1_CD_EPIC_app_backend:3_3
- ✅ Container_pipeline_EPIC_5 → TST.PHX.TEST/POC1_CD_EPIC_app_backend:3_0

---

### Use Case 3: Import Only Snyk Scans for Q2 Client

**Command:**
```bash
python phoenix_multi_import.py snyk
```

**Input:**
```
Enter client name (e.g., TV, EPIC, Q2): Q2
```

**Result:**
- ✅ Snyk_Q2_Frontend → com.q2.phx.test/Frontend/subrepo:latest
- ✅ Snyk_Q2_Backend → com.q2.phx.test/backend/subrepo2:latest

---

### Use Case 4: Import Only Trivy Scans for VOLVO Client

**Command:**
```bash
python phoenix_multi_import.py trivy
```

**Input:**
```
Enter client name (e.g., TV, EPIC, Q2): VOLVO
```

**Result:**
- ✅ Trivy_VOLVO_Container → com.volvo.tests/example:latest

---

## 📋 Quick Reference Table

| Want to... | Command | Client Input | Result |
|------------|---------|--------------|--------|
| Import all scanners | `python phoenix_multi_import.py` | TV | 8 assessments for TV |
| Import all scanners | `python phoenix_multi_import.py` | EPIC | 8 assessments for EPIC |
| Import only Aqua | `python phoenix_multi_import.py aqua` | TV | 5 Aqua assessments |
| Import only Snyk | `python phoenix_multi_import.py snyk` | Q2 | 2 Snyk assessments |
| Import only Trivy | `python phoenix_multi_import.py trivy` | VOLVO | 1 Trivy assessment |

---

## 🔄 Daily Workflow Examples

### Morning Routine: Import All Scans for TV

```bash
cd "{PROJECT_ROOT} Script_V2"
python phoenix_multi_import.py
# Enter: TV
```

### Quick Update: Just Snyk for EPIC

```bash
cd "{PROJECT_ROOT} Script_V2"
python phoenix_multi_import.py snyk
# Enter: EPIC
```

### Multiple Clients: Run for Different Clients

```bash
# Import for TV
python phoenix_multi_import.py
# Enter: TV

# Import for EPIC
python phoenix_multi_import.py
# Enter: EPIC

# Import for Q2
python phoenix_multi_import.py
# Enter: Q2
```

---

## 🎯 Target Patterns Reference

### How Client Names Transform

| Client Input | Uppercase Usage | Lowercase Usage | Example Target |
|--------------|-----------------|-----------------|----------------|
| TV | Container_pipeline_TV_1 | com.tv.phx.test | TST.PHX.TEST/POC1_CD_TV_app_backend:latest |
| EPIC | Container_pipeline_EPIC_1 | com.epic.phx.test | com.epic.phx.test/Frontend/subrepo:latest |
| Q2 | Container_pipeline_Q2_1 | com.q2.phx.test | TST.PHX.TEST/POC1_CD_Q2_app_backend:latest |
| volvo | Container_pipeline_VOLVO_1 | com.volvo.phx.test | com.volvo.tests/example:latest |
| MimeCast | Container_pipeline_MIMECAST_1 | com.mimecast.phx.test | TST.PHX.TEST/POC1_CD_MIMECAST_app_backend:latest |

**Note:** The script automatically handles uppercase/lowercase conversion for each target type.

---

## 🔍 Understanding the Output

### Status Indicators

```
✓ Success indicator
✗ Failure indicator
→ Action in progress
```

### Import Status Values

- **TRANSLATING**: Phoenix is processing the import
- **COMPLETED**: Import finished successfully
- **FAILED**: Import encountered an error

### Assessment ID

Each import receives a unique ID:
```
✓ Import successful (ID: 019a9758-d299-7ed2-b38f-0a3b6f9498be)
```

Use this ID to track the import in Phoenix Platform.

---

## 🛠️ Troubleshooting Examples

### Problem: File Not Found

```
✗ Error: File 'scanner-sample/aqua_example2.json' not found
```

**Solution:**
```bash
# Check if file exists
ls scanner-sample/aqua_example2.json

# If not, update config.ini with correct path
nano config.ini
```

---

### Problem: Authentication Failed

```
✗ Authentication failed (Status: 401)
Error: Invalid credentials
```

**Solution:**
```bash
# Update credentials in config.ini
nano config.ini

# Verify credentials are correct
# Check [phoenix] section
```

---

### Problem: Import Failed

```
✗ Import failed (Status: 400)
Response: Invalid scan format
```

**Solution:**
1. Verify scanner file format is correct
2. Check Phoenix API documentation for format requirements
3. Validate JSON file:
   ```bash
   python -m json.tool scanner-sample/aqua_example2.json > /dev/null
   ```

---

## 📊 Real-World Scenarios

### Scenario 1: Weekly Security Scan Import

**Goal:** Import all scans for TV client every Monday

**Solution:**
```bash
#!/bin/bash
# weekly_import.sh

cd "{PROJECT_ROOT} Script_V2"

# Import for TV
echo "TV" | python phoenix_multi_import.py

echo "Weekly import completed"
```

Make it executable:
```bash
chmod +x weekly_import.sh
```

Run weekly:
```bash
./weekly_import.sh
```

---

### Scenario 2: Client Onboarding

**Goal:** Set up scans for new client "NEWCLIENT"

**Solution:**
```bash
# Just run with new client name
python phoenix_multi_import.py
# Enter: NEWCLIENT

# Script automatically generates:
# - Container_pipeline_NEWCLIENT_1, _2, _3, _4, _5
# - Snyk_NEWCLIENT_Frontend, Snyk_NEWCLIENT_Backend
# - Trivy_NEWCLIENT_Container
```

---

### Scenario 3: Re-import After Scan Update

**Goal:** Re-import Aqua scans after new scan results

**Solution:**
```bash
# 1. Update scanner file
cp new_aqua_results.json scanner-sample/aqua_example2.json

# 2. Re-import
python phoenix_multi_import.py aqua
# Enter: TV
```

---

## 🎓 Tips & Tricks

### Tip 1: Consistent Naming
Use UPPERCASE for client names for consistency:
- ✅ TV, EPIC, Q2
- ❌ tv, Epic, q2

The script handles case conversion, but UPPERCASE input is clearer.

### Tip 2: Test First
Test with a single scanner before running all:
```bash
# Test with Snyk (only 2 imports)
python phoenix_multi_import.py snyk
```

### Tip 3: Check Scanner Files First
Verify files exist before running:
```bash
ls -lh scanner-sample/
```

### Tip 4: Use Absolute Paths in Config
For reliability, use absolute paths in config.ini:
```ini
aqua_file = /full/path/to/scanner-sample/aqua_example2.json
```

### Tip 5: Create Aliases for Common Commands
Add to your `.bashrc` or `.zshrc`:
```bash
alias phx-import='cd "{PROJECT_ROOT} Script_V2" && python phoenix_multi_import.py'
alias phx-aqua='cd "{PROJECT_ROOT} Script_V2" && python phoenix_multi_import.py aqua'
alias phx-snyk='cd "{PROJECT_ROOT} Script_V2" && python phoenix_multi_import.py snyk'
```

Then use:
```bash
phx-import    # Import all scanners
phx-aqua      # Import only Aqua
phx-snyk      # Import only Snyk
```

---

## ✅ Success Checklist

After running the script, verify:

- [ ] Authentication successful message shown
- [ ] Client name accepted
- [ ] All imports show success indicators
- [ ] Import IDs displayed for each assessment
- [ ] Summary shows all scanners successful
- [ ] Assessments appear in Phoenix Platform (verify in UI)

---

## 📞 Need More Help?

1. **Quick reference**: See `QUICK_START.md`
2. **Detailed docs**: See `README_MULTI_IMPORT.md`
3. **Comparison with old scripts**: See `MIGRATION_GUIDE.md`
4. **Overview**: See `SUPER_SCRIPT_SUMMARY.md`

---

**Happy Importing!** 🚀


