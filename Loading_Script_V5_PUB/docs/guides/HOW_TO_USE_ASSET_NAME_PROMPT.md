# How to Use the Asset Name Interactive Prompt

## 📖 Quick Answer

When you run the script **without** `--asset-name`, you'll see this prompt:

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
Enter custom asset name (or press Enter to skip): _
```

**Your options:**
1. **Type a custom name** → Press Enter → Uses your custom name
2. **Press Enter (blank)** → Uses the name from your JSON file or auto-detected

---

## ✨ Example Session

### Example 1: Enter a Custom Name

```bash
$ python phoenix_multi_scanner_enhanced.py \
    --file aqua_react2shell.json \
    --scanner aqua \
    --assessment "test-scan"

======================================================================
🏷️  ASSET NAME CONFIGURATION
======================================================================
You can specify a custom asset name for this import.
...
----------------------------------------------------------------------
Enter custom asset name (or press Enter to skip): my-production-app:v2024.12
✅ Using custom asset name: my-production-app:v2024.12
======================================================================

🔧 Setting up logging...
✅ Logging setup complete
...
Asset Name Override: my-production-app:v2024.12
...
✅ Successfully processed aqua_react2shell.json
```

**Result:** Asset created with name `my-production-app:v2024.12`

---

### Example 2: Press Enter to Use Default

```bash
$ python phoenix_multi_scanner_enhanced.py \
    --file aqua_react2shell.json \
    --scanner aqua \
    --assessment "test-scan"

======================================================================
🏷️  ASSET NAME CONFIGURATION
======================================================================
You can specify a custom asset name for this import.
...
----------------------------------------------------------------------
Enter custom asset name (or press Enter to skip): [pressed Enter]
ℹ️  Using default asset name from scan file
======================================================================

🔧 Setting up logging...
✅ Logging setup complete
...
✅ Successfully processed aqua_react2shell.json
```

**Result:** Asset created with name from JSON file (`react-server-dom-webpack:19.2.2`)

---

## 🎯 When Does the Prompt Appear?

### ✅ Prompt WILL Appear:
- Single file mode (`--file`)
- No `--asset-name` parameter provided
- Not using `--just-tags` mode

```bash
# These will show the prompt:
python phoenix_multi_scanner_enhanced.py --file scan.json --assessment "test"
python phoenix_multi_scanner_enhanced.py --file scan.json --scanner aqua
```

### ❌ Prompt Will NOT Appear:
- Folder mode (`--folder`)
- `--asset-name` parameter provided
- `--just-tags` mode enabled

```bash
# These will NOT show prompt:
python phoenix_multi_scanner_enhanced.py --file scan.json --asset-name "custom"
python phoenix_multi_scanner_enhanced.py --folder scans/ --assessment "test"
python phoenix_multi_scanner_enhanced.py --file scan.json --just-tags
```

---

## 💡 Best Practices

### For Container Assets
```
Good examples:
✅ production-webapp:v2024.12.14
✅ api-service:staging-v1.2.3
✅ nginx:1.21.0-prod

Less descriptive:
⚠️ myapp
⚠️ container1
⚠️ test
```

### For Infrastructure Assets
```
Good examples:
✅ webserver-prod-01.company.com
✅ db-primary.internal.aws.com
✅ 192.168.1.100

Less descriptive:
⚠️ server1
⚠️ host
⚠️ machine
```

### For Build Assets
```
Good examples:
✅ frontend-app:v2.5.1
✅ auth-service:release-candidate
✅ mobile-app:build-12345

Less descriptive:
⚠️ build
⚠️ app
⚠️ project
```

---

## 🚀 Complete Examples

### Scenario 1: I Want to Specify a Name Every Time
```bash
# Method: Use command line parameter
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --asset-name "production-webapp:v1.0" \
  --assessment "prod-scan"
```
**No prompt appears** - uses your specified name

---

### Scenario 2: I Want to Be Asked Each Time
```bash
# Method: Omit --asset-name
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --assessment "prod-scan"
```
**Prompt appears** - you can decide at runtime

---

### Scenario 3: I Want to Use JSON File Name Always
```bash
# Method 1: Add "image" field to JSON
{
  "image": "my-permanent-name:v1.0",
  ...
}

# Then run without --asset-name and press Enter at prompt
python phoenix_multi_scanner_enhanced.py --file scan.json
```
**Prompt appears but press Enter** - uses JSON field

```bash
# Method 2: Pass empty string to skip prompt (automation)
echo "" | python phoenix_multi_scanner_enhanced.py --file scan.json
```
**Prompt bypassed** - uses JSON field

---

### Scenario 4: Automation (No Interactive Prompts)
```bash
# Method 1: Always provide --asset-name
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --asset-name "automated-scan-$(date +%Y%m%d)"

# Method 2: Pipe empty input
echo "" | python phoenix_multi_scanner_enhanced.py --file scan.json

# Method 3: Use folder mode (no prompts)
python phoenix_multi_scanner_enhanced.py --folder scans/
```

---

## 🔧 Troubleshooting

### Issue: Prompt appears but I don't want it
**Solution:** Provide `--asset-name` parameter:
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --asset-name "my-asset"
```

### Issue: I pressed Ctrl+C during prompt
**Result:** Script exits safely with message:
```
ℹ️  Skipping custom asset name
```
**What to do:** Run script again

### Issue: I entered wrong name at prompt
**Result:** Import will use the wrong name
**What to do:** Run import again with correct `--asset-name`:
```bash
python phoenix_multi_scanner_enhanced.py \
  --file scan.json \
  --asset-name "correct-name" \
  --import-type merge  # Update the asset
```

### Issue: Prompt doesn't appear
**Check:**
1. Are you using `--folder`? → Prompts disabled in folder mode
2. Did you provide `--asset-name`? → Prompt skipped
3. Are you using `--just-tags`? → Prompt skipped

---

## 📋 Quick Reference

| What You Want | What To Do |
|---------------|------------|
| **Use a specific name** | `--asset-name "my-name"` |
| **Decide at runtime** | Omit `--asset-name` (prompt appears) |
| **Use JSON file name** | Add `"image": "name"` to JSON + press Enter at prompt |
| **Automate (no prompts)** | Always use `--asset-name` OR pipe empty input |
| **Skip prompt quickly** | Press Enter (uses JSON/auto-detected name) |

---

## 📚 Related Documentation

- **Complete Guide:** [`ASSET_NAME_CUSTOMIZATION.md`](ASSET_NAME_CUSTOMIZATION.md)
- **Asset Types:** [`ASSET_NAMING_GUIDE.md`](ASSET_NAMING_GUIDE.md)
- **What Changed:** `CHANGES_SUMMARY.md`
- **Main README:** [`README.md`](../../README.md)

---

## ✅ Quick Test

Try it now:

```bash
cd {PROJECT_ROOT}

python phoenix_multi_scanner_enhanced.py \
  --file reference_source/react2shell/aqua_react2shell.json \
  --scanner aqua \
  --assessment "test-prompt"

# When prompt appears, try entering:
# test-asset-name:v1.0
```

**Expected result:**
- Prompt appears with instructions
- You enter: `test-asset-name:v1.0`
- Script confirms: `✅ Using custom asset name: test-asset-name:v1.0`
- Import proceeds with your custom name

---

**That's it! The interactive prompt makes it easy to customize asset names on the fly.** 🎉





