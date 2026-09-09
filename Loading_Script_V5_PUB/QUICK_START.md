# Quick Start — Phoenix Multi-Scanner Import Tool (V5)

Get one scan file into Phoenix Security. Four steps, about five minutes.

For what the tool does and how it works, see [`README.md`](README.md).
For everything else, see [`docs/`](docs/README.md).

## Step 1 — Install

```bash
pip install -r requirements.txt
```

Python 3.9 or newer. Core dependencies: `requests`, `PyYAML`, `colorama`, `python-dateutil`.

## Step 2 — Add your credentials

Get a client ID and a personal access token from your Phoenix Security tenant.

**Option A — environment variables.** Best for CI, because nothing lands on disk.

```bash
export PHOENIX_CLIENT_ID="your-client-id"
export PHOENIX_CLIENT_SECRET="your-personal-access-token"
export PHOENIX_API_BASE_URL="https://api.appsecphx.io"
```

**Option B — a config file.**

```bash
cp config_multi_scanner.ini.TEMPLATE config_multi_scanner.ini
```

Then edit it:

```ini
[phoenix]
client_id = your-client-id
client_secret = your-personal-access-token
api_base_url = https://api.appsecphx.io
```

> **Never commit `config_multi_scanner.ini`.** It is in [`.gitignore`](.gitignore).
> Commit the `.TEMPLATE` file instead.

Pick the right `api_base_url` for your tenant:

| Environment | URL |
|---|---|
| Production | `https://api.appsecphx.io` |
| Demo | `https://api.demo.appsecphx.io` |
| Your own tenant | `https://api.<your-tenant>.appsecphx.io` |

## Step 3 — Run the import

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --config config_multi_scanner.ini \
  --file trivy-results.json \
  --assessment "My first import"
```

The tool works out which scanner produced the file. If it guesses wrong, name it:

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --config config_multi_scanner.ini \
  --file scan-results.json \
  --scanner trivy \
  --asset-type CONTAINER \
  --assessment "Container scan Q4"
```

A whole folder works too — swap `--file` for `--folder scans/`.

## Step 4 — Check it worked

You should see something like this:

```
[INFO] Scanner detected: Trivy
[INFO] Processing batch 1/1 (23 assets)
[INFO] Import job created: <request-id>
[INFO] Import complete: 23 assets, 147 vulnerabilities imported
```

Then open Phoenix Security, go to **Assessments**, and find your assessment name.

To have the tool check for you, add `--verify-import`. It reads the assets back and
compares the counts against what it sent.

## When something goes wrong

| Message | Cause | Fix |
|---|---|---|
| `Authentication failed (401)` | Wrong credentials | Check `client_id` and `client_secret` |
| `Could not detect scanner type` | Format not recognised | Pass `--scanner <name>` |
| `File not found` | Wrong path | Check the `--file` path |
| `Connection refused` | Wrong URL or no network | Check `api_base_url` |
| `Payload too large (413)` | Batch still too big | Lower `--max-batch-size` (default 500) |
| `At least one of Dockerfile or Repository is required` | Wrong asset type | Add `--asset-type CONTAINER` |

Add `--debug` to save every request and response under `debug/`.
Add `--error-log report.json` to get a JSON report of what failed.

Longer runbook: [`docs/guides/TROUBLESHOOTING.md`](docs/guides/TROUBLESHOOTING.md).

## Where to go next

| I want to... | Read |
|---|---|
| See every scanner supported | [`docs/reference/SCANNER_SUPPORT_MATRIX.md`](docs/reference/SCANNER_SUPPORT_MATRIX.md) |
| See every command-line flag | [`docs/guides/MULTI_SCANNER_COMMAND_GUIDE.md`](docs/guides/MULTI_SCANNER_COMMAND_GUIDE.md) |
| Understand `new` vs `merge` vs `delta` | [`docs/guides/BATCHING_AND_IMPORT_TYPES.md`](docs/guides/BATCHING_AND_IMPORT_TYPES.md) |
| Attach CI metadata as tags | [`docs/guides/TAG_CONFIGURATION_GUIDE.md`](docs/guides/TAG_CONFIGURATION_GUIDE.md) |
| Run it as a shared service | [`docs/guides/CLIENT_SERVER_VS_DIRECT_UPLOAD_GUIDE.md`](docs/guides/CLIENT_SERVER_VS_DIRECT_UPLOAD_GUIDE.md) |
| Browse all documentation | [`docs/README.md`](docs/README.md) |
