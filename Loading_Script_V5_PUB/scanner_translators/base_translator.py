#!/usr/bin/env python3
"""
Base Scanner Translator
=======================

Base class for all scanner translators. Provides common functionality for:
- Scanner detection (can_handle)
- File parsing (parse_file)
- Severity normalization
- CVE/CWE extraction
- Asset creation with proper tagging
- Empty asset handling for inventory mode

All scanner-specific translators should inherit from ScannerTranslator.
"""

import configparser
import re
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from phoenix_import_refactored import (
    PhoenixConfig, TagConfig, AssetData, VulnerabilityData
)

logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Configuration for scanner-specific settings"""
    scanner_type: str
    asset_type: str = "INFRA"
    default_severity_mapping: Dict[str, str] = field(default_factory=dict)
    custom_field_mappings: Dict[str, str] = field(default_factory=dict)
    vulnerability_filters: List[str] = field(default_factory=list)
    custom_options: Dict[str, str] = field(default_factory=dict)


def load_scanner_configs_from_ini(config_path: str) -> Dict[str, "ScannerConfig"]:
    """Load per-scanner overrides from ``[scanner_*]`` INI sections."""
    path = Path(config_path)
    if not path.exists():
        return {}

    parser = configparser.ConfigParser()
    parser.read(path)

    configs: Dict[str, ScannerConfig] = {}
    for section_name in parser.sections():
        if not section_name.startswith("scanner_"):
            continue

        section = parser[section_name]
        key = section_name[len("scanner_"):]
        severity_mapping: Dict[str, str] = {}
        custom_field_mappings: Dict[str, str] = {}
        custom_options: Dict[str, str] = {}
        vulnerability_filters: List[str] = []

        for option, value in section.items():
            if option.startswith("severity_mapping_"):
                severity_mapping[option[len("severity_mapping_"):]] = value
            elif option.startswith("field_mapping_"):
                custom_field_mappings[option[len("field_mapping_"):]] = value
            elif option == "vulnerability_filters":
                vulnerability_filters = [item.strip() for item in value.split(",") if item.strip()]
            elif option not in ("scanner_type", "asset_type"):
                custom_options[option] = value

        configs[key] = ScannerConfig(
            scanner_type=section.get("scanner_type", ""),
            asset_type=section.get("asset_type", ""),
            default_severity_mapping=severity_mapping,
            custom_field_mappings=custom_field_mappings,
            vulnerability_filters=vulnerability_filters,
            custom_options=custom_options,
        )

    return configs


def merge_scanner_configs(
    defaults: Dict[str, ScannerConfig],
    overrides: Dict[str, ScannerConfig],
) -> Dict[str, ScannerConfig]:
    """Merge INI-loaded scanner configs onto code defaults."""
    merged = dict(defaults)
    for key, ini_cfg in overrides.items():
        base = merged.get(key)
        if base is None:
            merged[key] = ini_cfg
            continue

        merged[key] = ScannerConfig(
            scanner_type=ini_cfg.scanner_type or base.scanner_type,
            asset_type=ini_cfg.asset_type or base.asset_type,
            default_severity_mapping={**base.default_severity_mapping, **ini_cfg.default_severity_mapping},
            custom_field_mappings={**base.custom_field_mappings, **ini_cfg.custom_field_mappings},
            vulnerability_filters=ini_cfg.vulnerability_filters or base.vulnerability_filters,
            custom_options={**base.custom_options, **ini_cfg.custom_options},
        )

    return merged


class ScannerTranslator(ABC):
    """Abstract base class for scanner-specific translators"""
    
    def __init__(self, scanner_config: ScannerConfig, tag_config: TagConfig, 
                 create_empty_assets: bool = False, create_inventory_assets: bool = False):
        self.scanner_config = scanner_config
        self.tag_config = tag_config
        self.create_empty_assets = create_empty_assets  # Zero out vulnerability risk but keep vulnerabilities
        self.create_inventory_assets = create_inventory_assets  # Create truly empty assets with placeholder
        self.severity_mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '2.0',
            'info': '1.0',
            'informational': '1.0',
            'negligible': '1.0'
        }
        self.severity_mapping.update(scanner_config.default_severity_mapping)
    
    @abstractmethod
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this translator can handle the given file"""
        pass
    
    @abstractmethod
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse the scanner file and return Phoenix assets"""
        pass
    
    @staticmethod
    def promote_oci_labels(
        target_info: Any,
        label_to_attribute: Optional[Dict[str, str]] = None,
        label_value_transforms: Optional[Dict[str, Callable[[str], str]]] = None,
    ) -> tuple:
        """Map OCI image labels into Phoenix asset attributes and tags.

        All non-empty labels become Phoenix tag dicts (verbatim key/value).
        Labels whose keys appear in *label_to_attribute* are also placed in
        the returned attributes dict (with the mapped camelCase key).

        Returns:
            (label_attributes, label_tags)
        """
        if label_to_attribute is None:
            label_to_attribute = {
                "org.opencontainers.image.base.digest": "baseImageDigest",
                "org.opencontainers.image.base.name":   "baseImageName",
            }

        label_tags: List[Dict[str, str]] = []
        label_attributes: Dict[str, str] = {}
        labels = target_info.get('labels') if isinstance(target_info, dict) else None
        if isinstance(labels, dict) and labels:
            for k, v in labels.items():
                if not k or v is None:
                    continue
                value_str = str(v).strip()
                if not value_str:
                    continue
                if label_value_transforms and k in label_value_transforms:
                    value_str = label_value_transforms[k](value_str)
                    if not value_str:
                        continue
                label_tags.append({"key": str(k), "value": value_str})
                if k in label_to_attribute:
                    label_attributes[label_to_attribute[k]] = value_str
            logger.info(
                "OCI labels: %d -> attributes, %d -> tags",
                len(label_attributes), len(label_tags),
            )
            logger.debug("Attribute keys from labels: %s", list(label_attributes.keys()))
            logger.debug("Tag keys from labels: %s", [t['key'] for t in label_tags])
        return label_attributes, label_tags

    def normalize_severity(self, severity: str) -> str:
        """Normalize severity to Phoenix format (1.0-10.0)"""
        if not severity:
            return "5.0"
        
        severity_lower = str(severity).lower().strip()
        
        # Handle numeric scores
        try:
            score = float(severity_lower)
            if 0 <= score <= 10:
                return str(score)
            elif score > 10:
                return "10.0"
            else:
                return "1.0"
        except ValueError:
            pass
        
        # Handle text severities
        return self.severity_mapping.get(severity_lower, "5.0")
    
    def extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        if not text:
            return []
        
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(cve_pattern, text, re.IGNORECASE)
    
    def extract_cwes(self, text: str) -> List[str]:
        """Extract CWE IDs from text"""
        if not text:
            return []
        
        cwe_pattern = r'CWE-\d+'
        return re.findall(cwe_pattern, text, re.IGNORECASE)
    
    def create_empty_asset_placeholder(self, asset_attributes: Dict[str, str]) -> Dict[str, Any]:
        """Create a zero-risk placeholder vulnerability for truly empty assets (inventory mode)"""
        # Get vulnerability tags from config
        vuln_tags = self.tag_config.get_vulnerability_tags() if self.tag_config else []
        
        # Add default inventory tags
        inventory_tags = [
            {"key": "asset-inventory", "value": "true"},
            {"key": "vulnerability-status", "value": "clean"},
            {"key": "risk-level", "value": "zero"},
            {"key": "scanner-type", "value": self.scanner_config.scanner_type.lower().replace(' ', '-')}
        ]
        
        return {
            "name": "Asset Inventory - No Vulnerabilities Found",
            "description": f"This asset was scanned by {self.scanner_config.scanner_type} and no vulnerabilities were detected. This is a placeholder entry for asset inventory purposes.",
            "remedy": "No action required. Continue monitoring for future vulnerabilities.",
            "severity": "1.0",  # Minimum risk/CVSS score (Phoenix requires 1-10)
            "location": "Asset-wide scan",
            "reference_ids": [],
            "cwes": [],
            "published_date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": {
                "asset_inventory": True,
                "zero_risk_placeholder": True,
                "scan_status": "clean",
                "scan_timestamp": datetime.now().isoformat(),
                "scanner_type": self.scanner_config.scanner_type,
                "asset_type": self.scanner_config.asset_type,
                "vulnerability_count": 0
            },
            "tags": inventory_tags + vuln_tags
        }
    
    def apply_vulnerability_tags(self, vulnerability: Dict[str, Any], severity: str = None) -> Dict[str, Any]:
        """Apply vulnerability tags from configuration"""
        if not self.tag_config:
            logger.debug(f"No tag_config available for vulnerability tagging")
            return vulnerability
        
        # Get vulnerability tags (including severity-specific ones)
        vuln_tags = self.tag_config.get_vulnerability_tags(severity)
        logger.debug(f"Got {len(vuln_tags)} vulnerability tags for severity '{severity}': {vuln_tags}")
        
        # Ensure tags field exists
        if "tags" not in vulnerability:
            vulnerability["tags"] = []
        
        # Add vulnerability tags
        vulnerability["tags"].extend(vuln_tags)
        logger.debug(f"Applied tags to vulnerability '{vulnerability.get('name', 'unknown')}': {len(vulnerability['tags'])} total tags")
        
        return vulnerability
    
    def zero_out_vulnerability_risk(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Zero out vulnerability risk while keeping the vulnerability data"""
        # Set severity to minimum (1.0) but keep all other data
        vulnerability["severity"] = "1.0"
        
        # Add a tag to indicate this was zeroed out
        if "tags" not in vulnerability:
            vulnerability["tags"] = []
        
        vulnerability["tags"].append({"key": "risk-zeroed", "value": "true"})
        vulnerability["tags"].append({"key": "original-severity", "value": str(vulnerability.get("original_severity", "unknown"))})
        
        # Update details to indicate risk was zeroed
        if "details" not in vulnerability:
            vulnerability["details"] = {}
        
        vulnerability["details"]["risk_zeroed"] = True
        vulnerability["details"]["zero_risk_reason"] = "Risk zeroed by --create-empty-assets flag"
        vulnerability["details"]["zero_risk_timestamp"] = datetime.now().isoformat()
        
        return vulnerability
    
    def ensure_asset_has_findings(self, asset: AssetData) -> AssetData:
        """Handle asset findings based on create_empty_assets and create_inventory_assets flags"""
        
        if self.create_empty_assets and asset.findings:
            # Mode 1: Zero out vulnerability risk but keep vulnerabilities
            for i, finding in enumerate(asset.findings):
                # Store original severity before zeroing
                if "severity" in finding:
                    finding["original_severity"] = finding["severity"]
                
                # Zero out the risk
                asset.findings[i] = self.zero_out_vulnerability_risk(finding)
                
                # Apply vulnerability tags
                asset.findings[i] = self.apply_vulnerability_tags(asset.findings[i], finding.get("original_severity"))
            
            logger.info(f"Zeroed risk for {len(asset.findings)} vulnerabilities in asset from {self.scanner_config.scanner_type}")
        
        elif self.create_inventory_assets and not asset.findings:
            # Mode 2: Create truly empty assets with inventory placeholder
            placeholder = self.create_empty_asset_placeholder(asset.attributes)
            asset.findings.append(placeholder)
            logger.info(f"Added inventory placeholder to empty asset from {self.scanner_config.scanner_type}")
        
        elif asset.findings:
            # Normal mode: Apply vulnerability tags to existing vulnerabilities
            for i, finding in enumerate(asset.findings):
                asset.findings[i] = self.apply_vulnerability_tags(finding, finding.get("severity"))
        
        # Apply asset-type specific tags to the asset itself
        if self.tag_config:
            asset_type_tags = self.tag_config.get_asset_type_tags(asset.asset_type)
            asset.tags.extend(asset_type_tags)
        
        return asset


__all__ = [
    'ScannerTranslator',
    'ScannerConfig',
    'load_scanner_configs_from_ini',
    'merge_scanner_configs',
]

