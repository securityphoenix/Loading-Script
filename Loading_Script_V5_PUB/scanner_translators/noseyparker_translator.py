#!/usr/bin/env python3
"""
NoseyParker Translator
=====================

Translator for NoseyParker secrets scanner JSONL format.

Supported Formats:
------------------
- **NoseyParker JSONL** - Newline-delimited JSON format
  - Structure: One JSON object per line
  - Fields: rule_name, blob_metadata, matches

Scanner Detection:
-----------------
- File extension: .jsonl or .json
- Each line is valid JSON with 'rule_name' and 'blob_metadata' keys

Asset Type: CODE
Grouping: Single asset with all secrets
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base_translator import ScannerTranslator
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class NoseyParkerTranslator(ScannerTranslator):
    """
    Translator for NoseyParker secrets scanner JSONL format
    
    Handles newline-delimited JSON with secret findings including
    repository and blob metadata.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """
        Detect NoseyParker JSONL format
        
        Args:
            file_path: Path to the scan file
            file_content: Optional pre-loaded file content
            
        Returns:
            True if file is NoseyParker format
        """
        if not file_path.lower().endswith(('.jsonl', '.json')):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if not first_line:
                    return False
                
                try:
                    obj = json.loads(first_line)
                except json.JSONDecodeError:
                    return False
                
                # NoseyParker format: has "rule_name", "blob_metadata"
                if isinstance(obj, dict):
                    if 'rule_name' in obj and 'blob_metadata' in obj:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"NoseyParkerTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """
        Parse NoseyParker JSONL file
        
        Args:
            file_path: Path to the NoseyParker JSONL file
            
        Returns:
            List containing single AssetData object with all secrets
        """
        logger.info(f"Parsing NoseyParker file: {file_path}")
        
        secrets = []
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                        continue
                    
                    vuln = self._parse_finding(finding)
                    if vuln:
                        secrets.append(vuln)
            
            if not secrets:
                logger.info("No secrets found in NoseyParker output")
                return []
            
            # Create single asset
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': 'NoseyParker Scan Results',
                    'scanner': 'NoseyParker'
                },
                tags=tags + [{"key": "scanner", "value": "noseyparker"}]
            )
            
            for vuln in secrets:
                asset.findings.append(vuln)
            
            assets = [self.ensure_asset_has_findings(asset)]
            
            logger.info(f"Parsed {len(secrets)} secrets from NoseyParker")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing NoseyParker file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """
        Parse a NoseyParker finding
        
        Args:
            finding: Finding dictionary from NoseyParker
            
        Returns:
            Vulnerability dictionary or None
        """
        try:
            rule_name = finding.get('rule_name', 'Secret Found')
            
            # Get blob metadata for location
            blob_metadata = finding.get('blob_metadata', [])
            if blob_metadata and len(blob_metadata) > 0:
                first_blob = blob_metadata[0]
                repo = first_blob.get('repository', {})
                repo_name = repo.get('name', 'unknown')
                blob_path = first_blob.get('blob_path', 'unknown')
                location = f"{repo_name}:{blob_path}"
            else:
                location = "unknown"
            
            # Get match info
            matches = finding.get('matches', [])
            match_count = len(matches)
            
            return {
                'name': f"{rule_name}",
                'description': f"Secret detected: {rule_name} ({match_count} matches)",
                'remedy': "Rotate the exposed secret immediately and remove from repository history",
                'severity': self.normalize_severity('High'),  # All secrets are high severity
                'location': location,
                'reference_ids': [rule_name],
                'details': {
                    'rule': rule_name,
                    'match_count': match_count,
                    'blob_metadata': blob_metadata if blob_metadata else []
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing NoseyParker finding: {e}")
            return None

