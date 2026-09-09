# Migration Guide: Old Scripts → New Super Script

## 📊 Comparison

### Before (Old Scripts)

**Problems:**
- ❌ Hardcoded credentials in each script
- ❌ Hardcoded scan targets
- ❌ Need to modify code for different clients
- ❌ No file validation
- ❌ Poor error handling
- ❌ Separate scripts for each scanner
- ❌ Manual file handle management

**Old Way - aqua_import2-1.py:**
```python
# Hardcoded credentials
client_id = {REDACTED}
client_secret = "{REDACTED_PHOENIX_PAT}"

# Hardcoded targets - must edit code for each client
send_results('aqua_example2.json', 'Aqua Scan', 'Container_pipeline_assesm1', 'new', 
             client_id, client_secret, "TST.PHX.TEST/POC1_CD_sosafe_poc_app_backend:latest")
# Repeat 5 times with different targets...
```

**Old Way - snyk_import.py:**
```python
# Duplicate credentials again
client_id = {REDACTED}
client_secret = "{REDACTED_PHOENIX_PAT}"

# More hardcoded targets
send_results('scanner-sample/Snyk_example.json', 'Snyk Scan', 'SnykTestAssessment3', 
             'new', client_id, client_secret, "com.tv.phx.test/Frontend/subrepo:latest")
# Repeat for each target...
```

### After (New Super Script)

**Benefits:**
- ✅ Credentials in configuration file
- ✅ Dynamic target generation
- ✅ Easy client switching (just enter name)
- ✅ File validation and error handling
- ✅ Professional error messages
- ✅ Single unified script
- ✅ Proper resource management

**New Way:**
```bash
# Just run the script
python phoenix_multi_import.py

# Enter client name when prompted
Enter client name (e.g., TV, EPIC, Q2): TV

# Script automatically:
# - Authenticates with API
# - Generates all scan targets for "TV"
# - Imports all 8 assessments
# - Shows progress and results
```

## 🔄 Migration Steps

### Step 1: No Code Changes Required!

The new script is **ready to use** with your existing credentials and files.

### Step 2: Compare Execution

#### Old Way: Multiple Scripts
```bash
# Edit aqua_import2-1.py, change hardcoded targets
python aqua_import2-1.py

# Edit snyk_import.py, change hardcoded targets  
python snyk_import.py

# Edit thrivi_Scan.py, change hardcoded targets
python thrivi_Scan.py
```

#### New Way: Single Script
```bash
# Just run once and enter client name
python phoenix_multi_import.py
> TV
```

### Step 3: Run Specific Scanner (Optional)

```bash
# Old way: Run aqua_import2-1.py
python aqua_import2-1.py

# New way: Use argument
python phoenix_multi_import.py aqua
```

## 📋 Feature Comparison Table

| Feature | Old Scripts | New Super Script |
|---------|------------|------------------|
| Credentials Storage | ❌ Hardcoded in each file | ✅ config.ini file |
| Client Switching | ❌ Edit code manually | ✅ Prompt at runtime |
| Scanner Support | ❌ One script per scanner | ✅ All in one |
| File Validation | ❌ Crashes if missing | ✅ Checks before import |
| Error Messages | ❌ Stack traces | ✅ User-friendly messages |
| Progress Tracking | ❌ Basic prints | ✅ Structured output |
| Summary Report | ❌ None | ✅ Complete summary |
| Resource Management | ❌ Manual file handling | ✅ Context managers |
| Target Generation | ❌ Hardcoded | ✅ Dynamic patterns |
| Configuration | ❌ Edit Python code | ✅ Edit config.ini |

## 🎯 Usage Examples

### Example 1: Import for TV Client

**Old Way (3 steps):**
1. Edit `aqua_import2-1.py` line 92-96, change all targets to TV
2. Edit `snyk_import.py` line 48-49, change all targets to TV
3. Edit `thrivi_Scan.py` line 46, change target to TV
4. Run each script separately

**New Way (1 step):**
```bash
python phoenix_multi_import.py
> TV
```

### Example 2: Import for EPIC Client

**Old Way:**
- Edit all 3 files again, change TV → EPIC everywhere
- Run each script separately

**New Way:**
```bash
python phoenix_multi_import.py
> EPIC
```

### Example 3: Import for Q2 Client

**Old Way:**
- Edit all 3 files again, change EPIC → Q2 everywhere
- Run each script separately

**New Way:**
```bash
python phoenix_multi_import.py
> Q2
```

## 🔍 Target Pattern Comparison

### Aqua Scan Targets

**Old (Hardcoded):**
```python
"TST.PHX.TEST/POC1_CD_sosafe_poc_app_backend:latest"
# Must manually edit "sosafe" to client name
```

**New (Dynamic):**
```python
f'TST.PHX.TEST/POC1_CD_{client_upper}_app_backend:latest'
# Automatically uses entered client name
# TV → TST.PHX.TEST/POC1_CD_TV_app_backend:latest
# EPIC → TST.PHX.TEST/POC1_CD_EPIC_app_backend:latest
```

### Snyk Scan Targets

**Old (Hardcoded):**
```python
"com.tv.phx.test/Frontend/subrepo:latest"
# Must manually edit "tv" to client name
```

**New (Dynamic):**
```python
f'com.{client_lower}.phx.test/Frontend/subrepo:latest'
# Automatically uses entered client name
# TV → com.tv.phx.test/Frontend/subrepo:latest
# EPIC → com.epic.phx.test/Frontend/subrepo:latest
```

## 🚀 Benefits in Action

### Time Savings

**Scenario:** Import scans for 5 different clients (TV, EPIC, Q2, VOLVO, MIMECAST)

**Old Way:**
- Edit aqua_import2-1.py: 5 times × 5 targets = 25 edits
- Edit snyk_import.py: 5 times × 2 targets = 10 edits
- Edit thrivi_Scan.py: 5 times × 1 target = 5 edits
- Run scripts: 5 clients × 3 scripts = 15 executions
- **Total: 40+ manual edits, 15 script executions**

**New Way:**
- Run script 5 times, enter different client name each time
- **Total: 5 script executions, 5 name inputs (no edits)**

### Error Reduction

**Old Scripts:**
- Easy to forget updating a target
- Easy to make typos in targets
- No validation until API call fails

**New Script:**
- All targets generated consistently
- Pattern ensures correct format
- File validation before API calls

## 🔐 Security Improvement

**Old Scripts:**
```python
# Credentials visible in each script
client_id = {REDACTED}
client_secret = "{REDACTED_PHOENIX_PAT}"
```

**New Script:**
- Credentials in `config.ini` (one place)
- Can use `.gitignore` to prevent commits
- Easy to use environment variables if needed
- Can set file permissions: `chmod 600 config.ini`

## 📝 Configuration File Benefits

**config.ini:**
```ini
[phoenix]
api_url = https://api.poc1.appsecphx.io
client_id = {REDACTED}
client_secret = {REDACTED_PHOENIX_PAT}

[scan_files]
aqua_file = scanner-sample/aqua_example2.json
snyk_file = scanner-sample/snyk_example.json
trivy_file = scanner-sample/trivy_mix.json

[scan_settings]
import_type = new
auto_import = true
```

**Benefits:**
- ✅ Change credentials in one place
- ✅ Easy to switch between environments (dev/prod)
- ✅ No Python knowledge required to configure
- ✅ Can be managed by configuration management tools

## 🎓 Learning Curve

**Old Scripts:**
- Must understand Python code
- Must locate all hardcoded values
- Must understand target format
- Must edit multiple files

**New Script:**
- Just run the command
- Enter client name when asked
- Done!

## 🔧 Maintenance

**Old Scripts:**
- Add new client? Edit 3 files
- Change API URL? Edit 3 files
- Update credentials? Edit 3 files
- Add new assessment? Edit code and understand Python

**New Script:**
- Add new client? Just enter the name
- Change API URL? Edit config.ini
- Update credentials? Edit config.ini
- Add new assessment? Modify pattern in one place

## 📊 Output Comparison

**Old Output:**
```
Status Code: 200
Response: {'id': '019a9753-36b5-7184-a1d6-20f403afafb0', ...}
Status Code: 200
Response: {'id': '019a9753-39bc-72c0-a9d4-0d71fdad562a', ...}
```

**New Output:**
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
✓ Import successful (ID: 019a9753-36b5-7184-a1d6-20f403afafb0)
  Status: TRANSLATING

[... clear progress for all imports ...]

============================================================
Import Summary
============================================================
Aqua Scan:  ✓ Success
Snyk Scan:  ✓ Success
Trivy Scan: ✓ Success
============================================================
```

## ✅ Recommendation

**Use the new `phoenix_multi_import.py` script!**

The old scripts are still functional but require manual editing for each use. The new script provides:
- Better user experience
- Fewer errors
- Less maintenance
- Faster workflow
- Professional output

---

**Questions?** See `QUICK_START.md` for usage or `README_MULTI_IMPORT.md` for detailed documentation.


