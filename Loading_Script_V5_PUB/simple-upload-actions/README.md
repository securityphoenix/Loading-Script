# Simple Upload Actions (Option 2)

This folder provides CI/CD templates and helper scripts to use:

- `phoenix_multi_scanner_enhanced.py` (direct upload to Phoenix)

without the scanner service/client stack.

## Can GitHub Actions + CI be replicated with Option 2?

Yes. This setup replicates CI upload behavior by:

1. collecting pipeline metadata from environment variables,
2. converting it into a Phoenix tag YAML file,
3. passing the tag file to `phoenix_multi_scanner_enhanced.py` with `--tag-file`.

That metadata is added into imported assets as tag-based metadata.

## Included Files

- `generate_pipeline_tag_file.py`  
  Collects CI metadata and writes:
  - `pipeline-tags.yaml` (for `--tag-file`)
  - `pipeline-metadata.json` (audit/debug artifact)

- `github-actions-direct-upload.yml`  
  Example GitHub Actions workflow using direct upload.

- `Jenkinsfile.direct-upload`  
  Example Jenkins pipeline using direct upload.

- `run_direct_upload.sh`  
  Generic CI shell entrypoint for direct upload.

- `github-actions-direct-upload-minimal.yml`  
  Minimal GitHub Actions example calling only `phoenix_multi_scanner_enhanced.py`.

- `Jenkinsfile.direct-upload-minimal`  
  Minimal Jenkins example calling only `phoenix_multi_scanner_enhanced.py`.

- `pipeline-tags.template.yaml`  
  Manual tag file template for teams that do not want metadata auto-generation.

## Required Secrets/Environment

- `PHOENIX_CLIENT_ID`
- `PHOENIX_CLIENT_SECRET`
- `PHOENIX_API_BASE_URL`

## Metadata Captured

The generator extracts what is available from the CI platform and writes tags such as:

- `ci_provider`
- `ci_repo`
- `ci_branch`
- `ci_commit`
- `ci_run_id`
- `ci_job`
- `ci_actor`
- `ci_workflow`
- `ci_pipeline_url`

## Option A: Automated Metadata (recommended)

From `Loading_Script_V5/`:

```bash
python -m pip install -r requirements.txt

./simple-upload-actions/run_direct_upload.sh \
  --file scan-results.json \
  --scanner auto \
  --asset-type INFRA \
  --import-type delta
```

## Option B: Minimal Direct Command (no helper scripts)

If you want to use only `phoenix_multi_scanner_enhanced.py`, use:

```bash
python -m pip install -r requirements.txt

python phoenix_multi_scanner_enhanced.py \
  --file scan-results.json \
  --scanner auto \
  --asset-type INFRA \
  --import-type delta \
  --assessment "ci-${BUILD_ID}" \
  --tag-file simple-upload-actions/pipeline-tags.template.yaml \
  --fix-data \
  --enable-batching \
  --verify-import
```

You can edit `pipeline-tags.template.yaml` manually (or generate your own in CI) to control which pipeline metadata is sent as asset tags.

## Notes

- Use `--import-type delta` as the safe CI default for partial scan data.
- `--tag-file` support is required to inject pipeline metadata tags into assets.
- Keep secrets in CI secret stores, never in source files.
