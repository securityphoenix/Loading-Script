# Phoenix Multi-Scanner Import Script

A unified script to import scan results from multiple scanner types (Aqua, Snyk, Trivy) into Phoenix Security Platform.

## Features

- 📁 **Configuration File Support**: Store API credentials and settings in `config.ini`
- 🔄 **Multi-Scanner Support**: Import from Aqua, Snyk, and Trivy scanners
- 🎯 **Dynamic Target Generation**: Automatically generates scan targets based on client name
- ✅ **Error Handling**: Comprehensive error checking and validation
- 📊 **Progress Reporting**: Clear status messages and summaries

## Setup

### 1. Install Requirements

```bash
pip install requests
```

### 2. Configure Settings

Copy the example configuration file and update it with your credentials:

```bash
cp config.ini.example config.ini
```

Edit `config.ini` and update:
- `client_id`: Your Phoenix API client ID
- `client_secret`: Your Phoenix API client secret
- `api_url`: Your Phoenix API URL (if different)
- File paths to your scanner result files

### 3. Prepare Scanner Files

Ensure your scanner result files are in the correct location (default: `scanner-sample/` directory):
- `aqua_example2.json` - Aqua scan results
- `snyk_example.json` - Snyk scan results
- `trivy_mix.json` - Trivy scan results

## Usage

### Import All Scanners

Run all scanner imports in sequence:

```bash
python phoenix_multi_import.py
```

The script will:
1. Authenticate with Phoenix API
2. Prompt for client name (e.g., TV, EPIC, Q2)
3. Import Aqua scan results (5 assessments)
4. Import Snyk scan results (2 assessments)
5. Import Trivy scan results (1 assessment)
6. Display summary of results

### Import Specific Scanner

Import from a single scanner type:

```bash
# Import only Aqua scans
python phoenix_multi_import.py aqua

# Import only Snyk scans
python phoenix_multi_import.py snyk

# Import only Trivy scans
python phoenix_multi_import.py trivy
```

## Client Name Convention

When prompted for a client name (e.g., "TV"), the script automatically generates scan targets:

### Aqua Scan Targets
- Assessment: `Container_pipeline_TV_1`
- Target: `TST.PHX.TEST/POC1_CD_TV_app_backend:latest`

### Snyk Scan Targets
- Assessment: `Snyk_TV_Frontend`
- Target: `com.tv.phx.test/Frontend/subrepo:latest`

### Trivy Scan Targets
- Assessment: `Trivy_TV_Container`
- Target: `com.tv.tests/example:latest`

## Configuration File Structure

```ini
[phoenix]
api_url = https://api.poc1.appsecphx.io
client_id = YOUR_CLIENT_ID
client_secret = YOUR_SECRET

[scan_files]
aqua_file = scanner-sample/aqua_example2.json
snyk_file = scanner-sample/snyk_example.json
trivy_file = scanner-sample/trivy_mix.json

[scan_settings]
import_type = new
auto_import = true
```

## Example Output

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

[... more imports ...]

============================================================
Import Summary
============================================================
Aqua Scan:  ✓ Success
Snyk Scan:  ✓ Success
Trivy Scan: ✓ Success
============================================================
```

## Troubleshooting

### "Configuration file not found"
- Ensure `config.ini` exists in the same directory as the script
- Copy from `config.ini.example` if needed

### "File not found" errors
- Check that scanner result files exist in the configured paths
- Update paths in `config.ini` if files are in different locations

### Authentication failures
- Verify `client_id` and `client_secret` in `config.ini`
- Ensure you have network access to the Phoenix API
- Check that the API URL is correct

### Import failures
- Ensure scan files are in the correct format
- Check that scan targets follow the expected naming convention
- Review the error message for specific details

## Security Notes

⚠️ **Important**: The `config.ini` file contains sensitive credentials. 

- **DO NOT** commit `config.ini` to version control
- Add `config.ini` to `.gitignore`
- Use `config.ini.example` as a template for documentation
- Restrict file permissions: `chmod 600 config.ini`

## Advanced Usage

### Customizing Scan Targets

To customize how scan targets are generated, modify the `generate_scan_targets()` method in `phoenix_multi_import.py`.

### Adding New Scanner Types

1. Add the scanner file path to `config.ini`
2. Add a new method like `run_<scanner>_import()` in the `PhoenixImporter` class
3. Add target generation logic in `generate_scan_targets()`
4. Update the main function to handle the new scanner type

## Migration from Old Scripts

### From aqua_import2-1.py
```python
# Old way
send_results('aqua_example2.json', 'Aqua Scan', 'Container_pipeline_assesm1', 'new', client_id, client_secret, "TST.PHX.TEST/...")

# New way
python phoenix_multi_import.py aqua
# Enter "TV" when prompted
```

### From snyk_import.py
```python
# Old way
send_results('scanner-sample/Snyk_example.json', 'Snyk Scan', 'SnykTestAssessment3', 'new', client_id, client_secret, "com.tv...")

# New way
python phoenix_multi_import.py snyk
# Enter "TV" when prompted
```

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the example configuration
3. Verify scanner file formats match expected structure
4. Check Phoenix API documentation


