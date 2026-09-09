#!/bin/bash
# Phoenix & Rapid7 CSV Import Examples
# Usage: ./phoenix_csv_examples.sh

# Set paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
CSV_DIR="$PARENT_DIR/scanner_test_files/phoenix-csv/results"

echo "🔹 Phoenix CSV & Rapid7 Import Examples"
echo "=========================================="
echo ""

# =============================================================================
# EXAMPLE 1: Phoenix INFRA CSV (Auto-detect)
# =============================================================================
echo "📋 Example 1: Phoenix INFRA CSV - Auto-detection"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/demo_infra.csv" \
  --scanner phoenix_csv \
  --assessment "Infrastructure Scan - Auto" \
  --import-type new \
  --debug

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 2: Phoenix INFRA CSV with Asset Name Override
# =============================================================================
echo "📋 Example 2: Phoenix INFRA CSV - Custom asset name"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/demo_infra.csv" \
  --scanner phoenix_csv \
  --asset-name "production-server-01" \
  --assessment "Production Server Scan" \
  --import-type delta

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 3: Phoenix CLOUD CSV
# =============================================================================
echo "📋 Example 3: Phoenix CLOUD CSV"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/test_cloud.csv" \
  --scanner phoenix_csv_cloud \
  --asset-type CLOUD \
  --assessment "AWS Cloud Security Scan"

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 4: Phoenix WEB CSV
# =============================================================================
echo "📋 Example 4: Phoenix WEB CSV"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/demo_web.csv" \
  --scanner phoenix_csv_web \
  --asset-type WEB \
  --assessment "Web Application Scan"

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 5: Phoenix SOFTWARE CSV
# =============================================================================
echo "📋 Example 5: Phoenix SOFTWARE CSV"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/test_software.csv" \
  --scanner phoenix_csv_software \
  --asset-type BUILD \
  --assessment "Software Component Scan"

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 6: Rapid7 VM CSV Export
# =============================================================================
echo "📋 Example 6: Rapid7 VM CSV Export"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$PARENT_DIR/../csv_translator/source/vuln_report_2_hosts.csv" \
  --scanner rapid7_csv \
  --assessment "Rapid7 VM Scan - Q4 2025" \
  --import-type new

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 7: Force CSV Upload (Batched)
# =============================================================================
echo "📋 Example 7: Phoenix CSV - Force CSV Upload (Batched)"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/demo_infra.csv" \
  --scanner phoenix_csv \
  --import-csv-force \
  --assessment "CSV Direct Import" \
  --import-type new

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 8: Folder Processing - Multiple CSV Files
# =============================================================================
echo "📋 Example 8: Process Entire Folder"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --folder "$CSV_DIR" \
  --scanner phoenix_csv \
  --file-types csv \
  --import-type delta \
  --enable-batching

echo ""
echo "---"
echo ""

# =============================================================================
# EXAMPLE 9: Debug Mode with Error Logging
# =============================================================================
echo "📋 Example 9: Debug Mode with Error Logging"
python "$PARENT_DIR/phoenix_multi_scanner_enhanced.py" \
  --file "$CSV_DIR/demo_infra.csv" \
  --scanner phoenix_csv \
  --assessment "Debug Test Scan" \
  --debug \
  --error-log "errors_$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "✅ All examples completed!"
echo ""


