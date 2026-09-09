#!/usr/bin/env bash
set -euo pipefail

# Simple direct upload runner for any CI platform.
# Required env:
#   PHOENIX_CLIENT_ID
#   PHOENIX_CLIENT_SECRET
#   PHOENIX_API_BASE_URL
#
# Usage:
#   ./simple-upload-actions/run_direct_upload.sh \
#     --file scan-results.json \
#     --scanner auto \
#     --asset-type INFRA \
#     --import-type delta

SCAN_FILE=""
SCANNER_TYPE="auto"
ASSET_TYPE="INFRA"
IMPORT_TYPE="delta"
ASSESSMENT_NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) SCAN_FILE="$2"; shift 2 ;;
    --scanner) SCANNER_TYPE="$2"; shift 2 ;;
    --asset-type) ASSET_TYPE="$2"; shift 2 ;;
    --import-type) IMPORT_TYPE="$2"; shift 2 ;;
    --assessment) ASSESSMENT_NAME="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "${SCAN_FILE}" ]]; then
  echo "Missing required argument: --file" >&2
  exit 1
fi

if [[ -z "${ASSESSMENT_NAME}" ]]; then
  TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
  ASSESSMENT_NAME="ci-direct-upload-${TIMESTAMP}"
fi

python simple-upload-actions/generate_pipeline_tag_file.py \
  --output pipeline-tags.yaml \
  --metadata-json pipeline-metadata.json

python phoenix_multi_scanner_enhanced.py \
  --file "${SCAN_FILE}" \
  --scanner "${SCANNER_TYPE}" \
  --asset-type "${ASSET_TYPE}" \
  --import-type "${IMPORT_TYPE}" \
  --assessment "${ASSESSMENT_NAME}" \
  --tag-file pipeline-tags.yaml \
  --fix-data \
  --enable-batching \
  --verify-import
