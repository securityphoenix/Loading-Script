# Asset Name Customization Guide

## Overview
You now have **3 ways** to specify custom asset names for your imports:
1. **Add `image` field to JSON file** (Persistent)
2. **Command-line argument** (Quick override)
3. **Interactive prompt** (User-friendly)

---

## Method 1: Add `image` Field to JSON File ✅ DONE

**Best for:** Permanent, reusable configurations

Your `aqua_react2shell.json` file now includes the `image` field:

```json
{
  "image": "react-server-dom-webpack:19.2.2",
  "resource": {
    "name": "react-server-dom-webpack",
    "version": "19.2.2"
  },
  "vulnerabilities": [...]
}
```

**Result:** Every time you import this file, the asset will be named `react-server-dom-webpack:19.2.2`

**Run import:**
```bash
python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --assessment "react-security-scan"
```

---

## Method 2: Command-Line Argument

**Best for:** One-time overrides, scripting, automation

Use the `--asset-name` parameter to specify a custom name:

```bash
python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --assessment "react-test" \
  --asset-name "my-custom-react-app:v1.0"
```

**Priority:** Command-line argument overrides any `image` field in the JSON file.

### Examples:

#### Container Asset
```bash
python phoenix_multi_scanner_enhanced.py \
  --file aqua_scan.json \
  --scanner aqua \
  --asset-name "production-webapp:2024.12"
```

#### Infrastructure Asset
```bash
python phoenix_multi_scanner_enhanced.py \
  --file qualys_scan.csv \
  --scanner qualys \
  --asset-name "webserver-prod-01.company.com"
```

#### Build Asset
```bash
python phoenix_multi_scanner_enhanced.py \
  --file npm_audit.json \
  --scanner npm_audit \
  --asset-name "frontend-application-v2.5"
```

---

## Method 3: Interactive Prompt ✨ NEW!

**Best for:** Manual imports, exploratory testing

When you run the script **without** `--asset-name`, you'll be prompted:

```bash
python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --assessment "react-scan"
```

**You'll see:**
```
======================================================================
🏷️  ASSET NAME CONFIGURATION
======================================================================
You can specify a custom asset name for this import.
This is particularly useful for:
  • Container scans without an 'image' field
  • Infrastructure scans where you want a specific hostname
  • Build scans where you want a custom identifier

Leave blank to use the default name from the scan file.
----------------------------------------------------------------------
Enter custom asset name (or press Enter to skip): 
```

**Options:**
- **Enter a custom name:** `my-production-app:v1.2.3` → Uses your custom name
- **Press Enter:** → Uses the name from the JSON file (`react-server-dom-webpack:19.2.2`)

---

## Priority Order

When multiple naming methods are present, the priority is:

1. **Command-line `--asset-name`** (highest priority)
2. **Interactive prompt** (if no command-line argument)
3. **JSON `image` field**
4. **Auto-detected from `resource.name`**
5. **Fallback to `unknown-image`** (lowest priority)

### Example Priority Flow:

```bash
# JSON has: "image": "react-server-dom-webpack:19.2.2"
# Command: --asset-name "custom-app:v1.0"
# Interactive: user enters "prompted-name:v2.0"

Result: Uses "custom-app:v1.0" (command-line wins)
```

```bash
# JSON has: "image": "react-server-dom-webpack:19.2.2"
# Interactive: user enters "prompted-name:v2.0"

Result: Uses "prompted-name:v2.0" (interactive prompt)
```

```bash
# JSON has: "image": "react-server-dom-webpack:19.2.2"
# Interactive: user presses Enter (skip)

Result: Uses "react-server-dom-webpack:19.2.2" (from JSON)
```

---

## Disable Interactive Prompt

To skip the interactive prompt (useful for automation):

### Option 1: Provide `--asset-name`
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --asset-name "my-asset" \
  --assessment "test"
```

### Option 2: Use `--just-tags` mode
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --just-tags
```

### Option 3: Pipe input (for automation)
```bash
echo "" | python phoenix_multi_scanner_enhanced.py --file scan.json --assessment "test"
```

---

## Scanner-Specific Support

### ✅ Full Support (All 3 Methods)
- **Aqua** - Container scans
- **Phoenix CSV** - Infrastructure/multi-asset
- **Rapid7 CSV** - Infrastructure/multi-asset

### 🔄 Partial Support (JSON field + auto-detection)
- **Trivy** - Uses `ArtifactName` → `repository`
- **Grype** - Uses target `userInput` → `repository`
- **JFrog Xray** - Uses artifact `name` → `repository`
- **Qualys** - Uses IP/hostname → `hostname`
- **Tenable** - Uses IP/hostname → `hostname`

### 📝 Note for Other Scanners
To add `--asset-name` support to other translators, modify their `parse_file()` method similar to `AquaScanTranslator`.

---

## Complete Examples

### Example 1: Production Container with Command-Line
```bash
python phoenix_multi_scanner_enhanced.py \
  --file aqua_production_scan.json \
  --scanner aqua \
  --asset-name "ecommerce-frontend:prod-2024.12.14" \
  --assessment "PROD-Q4-Security-Scan" \
  --import-type merge
```

### Example 2: Development Container with Interactive Prompt
```bash
python phoenix_multi_scanner_enhanced.py \
  --file aqua_dev_scan.json \
  --scanner aqua \
  --assessment "DEV-Weekly-Scan"

# Prompt appears, enter: "ecommerce-frontend:dev-feature-xyz"
```

### Example 3: Using JSON Field (No Override)
```bash
# JSON already has: "image": "my-app:v1.0.0"
python phoenix_multi_scanner_enhanced.py \
  --file aqua_scan.json \
  --scanner aqua \
  --assessment "Baseline-Scan"
  
# Uses: "my-app:v1.0.0" from JSON
```

### Example 4: Infrastructure Scan with Custom Hostname
```bash
python phoenix_multi_scanner_enhanced.py \
  --file qualys_scan.csv \
  --scanner qualys \
  --asset-name "webserver-dmz-01.company.com" \
  --assessment "DMZ-Quarterly-Scan"
```

### Example 5: Batch Processing (No Prompts)
```bash
# Process entire folder - prompts disabled in folder mode
python phoenix_multi_scanner_enhanced.py \
  --folder scans/ \
  --scanner aqua \
  --assessment "Bulk-Import-2024-Q4"
```

---

## Best Practices

### 1. Naming Conventions

**Containers:**
```
{app-name}:{environment}-{version}
Examples:
  - webapp:prod-2024.12.14
  - api-service:staging-v1.2.3
  - backend:dev-feature-auth
```

**Infrastructure:**
```
{hostname}.{domain}
Examples:
  - webserver-01.prod.company.com
  - db-primary.internal.aws.com
  - jumpbox.dmz.company.net
```

**Build/Code:**
```
{project-name}-{component}:{version}
Examples:
  - ecommerce-frontend:v2.5.1
  - auth-service:main-branch
  - mobile-app:release-candidate
```

### 2. Include Environment Indicators
```bash
--asset-name "myapp:production-v1.0"   # ✅ Good
--asset-name "myapp:v1.0"              # ⚠️ Ambiguous - which environment?
```

### 3. Use Consistent Versioning
```bash
--asset-name "myapp:2024.12.14"        # Semantic/Date
--asset-name "myapp:v1.2.3"            # Semantic
--asset-name "myapp:build-12345"       # Build number
```

### 4. Avoid Special Characters
```bash
--asset-name "myapp-prod:v1.0"         # ✅ Good (dash, colon)
--asset-name "myapp@prod#v1.0"         # ❌ Avoid (@, #, etc.)
```

---

## Troubleshooting

### Issue: Interactive prompt doesn't appear
**Cause:** Using `--just-tags` or folder mode
**Solution:** Remove `--just-tags` or use single file mode

### Issue: Command-line asset name not being used
**Cause:** Typo in parameter name
**Solution:** Ensure you use `--asset-name` (with dash)
```bash
# ✅ Correct
--asset-name "my-asset"

# ❌ Wrong
--assetname "my-asset"
--asset_name "my-asset"
```

### Issue: Want to use JSON name but prompt appears
**Solution:** Press Enter at the prompt to skip

### Issue: Asset name still shows "unknown-image"
**Possible causes:**
1. Scanner doesn't support asset name override yet
2. Check if name is in `--asset-name` parameter
3. Verify JSON `image` field is present

---

## Testing Your Configuration

### Test 1: Verify JSON Field
```bash
# Check your JSON has the image field
cat reference_source/react2shell/aqua_react2shell.json | grep -A 1 "image"

# Expected output:
#   "image": "react-server-dom-webpack:19.2.2",
```

### Test 2: Test Command-Line Override
```bash
python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --asset-name "TEST-ASSET-NAME" \
  --assessment "test-scan" \
  --debug
  
# Check log for: "🏷️ Using custom asset name: TEST-ASSET-NAME"
```

### Test 3: Test Interactive Prompt
```bash
python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --assessment "interactive-test"
  
# Prompt should appear
# Enter: "INTERACTIVE-TEST-NAME"
# Check log for usage
```

---

## Quick Reference

| Method | When to Use | Priority | Example |
|--------|-------------|----------|---------|
| JSON `image` field | Permanent naming | 3 | `{"image": "app:v1.0"}` |
| `--asset-name` CLI | One-time override | 1 | `--asset-name "app:v2.0"` |
| Interactive prompt | Manual/exploration | 2 | User enters at runtime |

---

## Your Updated File

✅ **Your `aqua_react2shell.json` now has the `image` field added!**

Next time you import, it will use: `react-server-dom-webpack:19.2.2`

**Test it now:**
```bash
cd {PROJECT_ROOT}

python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --assessment "aqua-test-with-name"
```

Expected result:
- ✅ No date format errors
- ✅ Asset named: `react-server-dom-webpack:19.2.2`
- ✅ 24 vulnerabilities imported





