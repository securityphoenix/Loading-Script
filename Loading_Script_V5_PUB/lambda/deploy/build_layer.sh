#!/bin/bash
# =============================================================================
# Phoenix Lambda Layer Build Script
# =============================================================================
# This script packages the Phoenix Scanner Import tool and its dependencies
# as an AWS Lambda Layer.
#
# Usage:
#   ./build_layer.sh [--clean] [--upload BUCKET]
#
# Options:
#   --clean     Remove build artifacts before building
#   --upload    Upload layer to S3 bucket after building
#
# Output:
#   build/phoenix-scanner-layer.zip
# =============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAMBDA_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$LAMBDA_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
LAYER_DIR="$BUILD_DIR/layer"
PYTHON_DIR="$LAYER_DIR/python"
OUTPUT_ZIP="$BUILD_DIR/phoenix-scanner-layer.zip"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}Phoenix Lambda Layer Build Script${NC}"
echo -e "${GREEN}==============================================================================${NC}"

# Parse arguments
CLEAN=false
UPLOAD_BUCKET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --upload)
            UPLOAD_BUCKET="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
fi

# Create directories
echo -e "${GREEN}Creating build directories...${NC}"
mkdir -p "$PYTHON_DIR"

# Install dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
pip install \
    requests \
    pyyaml \
    boto3 \
    -t "$PYTHON_DIR" \
    --upgrade \
    --quiet

# Copy Phoenix scanner code
echo -e "${GREEN}Copying Phoenix scanner code...${NC}"

# Create lambda subdirectory in layer (matches import path)
mkdir -p "$PYTHON_DIR/lambda"

# Lambda handler (in lambda subfolder)
cp "$LAMBDA_DIR/phoenix_lambda_handler.py" "$PYTHON_DIR/lambda/"

# Core files (in root for imports)
cp "$PROJECT_DIR/phoenix_import_refactored.py" "$PYTHON_DIR/"
cp "$PROJECT_DIR/phoenix_multi_scanner_import.py" "$PYTHON_DIR/"
cp "$PROJECT_DIR/phoenix_multi_scanner_enhanced.py" "$PYTHON_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/phoenix_import_enhanced.py" "$PYTHON_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/data_validator_enhanced.py" "$PYTHON_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/scanner_field_mapper.py" "$PYTHON_DIR/"
cp "$PROJECT_DIR/file_extractors.py" "$PYTHON_DIR/" 2>/dev/null || true

# Create __init__.py for lambda package
touch "$PYTHON_DIR/lambda/__init__.py"

# Scanner translators directory
if [ -d "$PROJECT_DIR/scanner_translators" ]; then
    echo -e "${GREEN}Copying scanner translators...${NC}"
    cp -r "$PROJECT_DIR/scanner_translators" "$PYTHON_DIR/"
fi

# Format handlers directory
if [ -d "$PROJECT_DIR/format_handlers" ]; then
    echo -e "${GREEN}Copying format handlers...${NC}"
    cp -r "$PROJECT_DIR/format_handlers" "$PYTHON_DIR/"
fi

# YAML configuration files
if [ -f "$PROJECT_DIR/scanner_field_mappings.yaml" ]; then
    echo -e "${GREEN}Copying YAML configurations...${NC}"
    cp "$PROJECT_DIR/scanner_field_mappings.yaml" "$PYTHON_DIR/"
fi

# Remove unnecessary files to reduce size
echo -e "${GREEN}Cleaning up unnecessary files...${NC}"
find "$PYTHON_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$PYTHON_DIR" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "$PYTHON_DIR" -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find "$PYTHON_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true
find "$PYTHON_DIR" -type f -name "*.pyo" -delete 2>/dev/null || true

# Remove boto3/botocore if present (included in Lambda runtime)
rm -rf "$PYTHON_DIR/boto3" 2>/dev/null || true
rm -rf "$PYTHON_DIR/botocore" 2>/dev/null || true
rm -rf "$PYTHON_DIR/s3transfer" 2>/dev/null || true

# Create ZIP file
echo -e "${GREEN}Creating ZIP archive...${NC}"
cd "$LAYER_DIR"
zip -r "$OUTPUT_ZIP" . -x "*.pyc" -x "*__pycache__*" -q

# Get file size
ZIP_SIZE=$(du -h "$OUTPUT_ZIP" | cut -f1)
echo -e "${GREEN}Layer ZIP created: $OUTPUT_ZIP ($ZIP_SIZE)${NC}"

# Check size limit (250MB unzipped, ~50MB zipped recommended)
ZIP_SIZE_BYTES=$(stat -f%z "$OUTPUT_ZIP" 2>/dev/null || stat -c%s "$OUTPUT_ZIP")
MAX_SIZE=$((50 * 1024 * 1024))  # 50MB

if [ "$ZIP_SIZE_BYTES" -gt "$MAX_SIZE" ]; then
    echo -e "${YELLOW}WARNING: Layer ZIP is larger than recommended 50MB${NC}"
    echo -e "${YELLOW}Consider splitting into multiple layers or optimizing dependencies${NC}"
fi

# Upload to S3 if requested
if [ -n "$UPLOAD_BUCKET" ]; then
    echo -e "${GREEN}Uploading to S3...${NC}"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    S3_KEY="layers/phoenix-scanner-layer-${TIMESTAMP}.zip"
    
    aws s3 cp "$OUTPUT_ZIP" "s3://$UPLOAD_BUCKET/$S3_KEY"
    
    echo -e "${GREEN}Uploaded to: s3://$UPLOAD_BUCKET/$S3_KEY${NC}"
    
    # Publish layer version
    echo -e "${GREEN}Publishing Lambda layer...${NC}"
    LAYER_ARN=$(aws lambda publish-layer-version \
        --layer-name "phoenix-scanner-deps" \
        --description "Phoenix Scanner Import dependencies" \
        --content "S3Bucket=$UPLOAD_BUCKET,S3Key=$S3_KEY" \
        --compatible-runtimes python3.9 python3.10 python3.11 \
        --query 'LayerVersionArn' \
        --output text)
    
    echo -e "${GREEN}Layer ARN: $LAYER_ARN${NC}"
fi

echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}Build complete!${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Deploy with SAM: sam deploy --template-file template.yaml --guided"
echo "  2. Or upload layer manually: aws lambda publish-layer-version ..."
echo "  3. Upload config to S3: aws s3 cp $LAMBDA_DIR/lambda_config_template.ini s3://BUCKET/config/lambda_config.ini"
echo ""
echo "Test locally:"
echo "  cd $PROJECT_DIR && python -m lambda.phoenix_lambda_handler '{\"mode\": \"single\", \"bucket\": \"test\", \"file_key\": \"scanners/trivy/new/test.json\"}'"
