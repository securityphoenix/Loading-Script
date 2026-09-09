# Phoenix Scanner Client - Quick Start

Get up and running in 5 minutes!

## Step 1: Prerequisites

Ensure you have:
- Python 3.8 or higher
- Phoenix Scanner Service running (see `../phoenix-scanner-service/`)

## Step 2: Install

```bash
cd phoenix-scanner-client
pip install -r requirements.txt
```

## Step 3: Configure

Choose one of these methods:

### Option A: Configuration File (Recommended)

```bash
# Copy example config
cp examples/config.example.yaml config.yaml

# Edit with your credentials
nano config.yaml
```

```yaml
api_url: http://localhost:8000
api_key: your-api-key-here
```

### Option B: Environment Variables

```bash
export PHOENIX_SCANNER_API_URL=http://localhost:8000
export PHOENIX_SCANNER_API_KEY=your-api-key
```

## Step 4: Test Connection

```bash
python test_client.py
```

## Step 5: Upload Your First Scan

```bash
python actions/upload_single.py --file your-scan.json
```

## Common Workflows

### Single File Upload

```bash
python actions/upload_single.py \
  --file trivy-scan.json \
  --scanner-type trivy \
  --wait
```

### Batch Upload

Create `batch.yaml`:

```yaml
batches:
  - name: "My Scans"
    scanner_type: auto
    files:
      - scan1.json
      - scan2.json
```

Upload:

```bash
python actions/upload_batch.py --batch-config batch.yaml
```

### Folder Upload

```bash
python actions/upload_folder.py --folder ./scans --pattern "*.json"
```

### Check Status

```bash
python actions/check_status.py --list
```

## Troubleshooting

**Connection Refused?**
```bash
# Start the API service
cd ../phoenix-scanner-service
docker-compose up -d
```

**Authentication Failed?**
```bash
# Verify your API key in config.yaml or environment variables
echo $PHOENIX_SCANNER_API_KEY
```

**Need Help?**
- See [README.md](README.md) for complete documentation
- See [USAGE_GUIDE.md](USAGE_GUIDE.md) for detailed examples

## Next Steps

1. Review supported scanners: `cat scanner_list_actual.txt`
2. Set up CI/CD integration: `ci/github/`, `ci/jenkins/`, `ci/azure/`
3. Explore batch configurations: `examples/batch_config.example.yaml`

---

**Ready to go!** 🚀

For questions or issues, contact the Phoenix Security Team.



