#!/usr/bin/env python3
"""
Phoenix Security Multi-Scanner Import Tool
==========================================

A comprehensive tool for importing assets and vulnerabilities from multiple scanner formats
into Phoenix Security. Supports automatic scanner detection and format-specific parsing.

Supported Scanners:
- Aqua Scan (JSON)
- JFrog Xray (JSON - multiple formats)
- Qualys (CSV, XML)
- SonarQube (JSON, HTML)
- Tenable/Nessus (CSV)
- And many more...

Author: Senior Developer
Version: 2.0.0
Date: September 2025
"""

import argparse
import csv
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
import yaml
from requests.auth import HTTPBasicAuth

# Import base classes from the refactored tool
from phoenix_import_refactored import (
    PhoenixConfig, TagConfig, AssetData, VulnerabilityData,
    DataAnonymizer, PhoenixAPIClient, PhoenixImportManager,
    setup_logging, DebugLogger, ErrorTracker, error_tracker,
    DEBUG_MODE, ERROR_LOG_FILE, RUN_ID, create_logging_directories
)

# Import the new universal scanner system
from scanner_field_mapper import FieldMapper, ScannerFormatDetector, UniversalScannerTranslator

# Use the enhanced logging from the refactored tool
logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Configuration for scanner-specific settings"""
    scanner_type: str
    asset_type: str = "INFRA"
    default_severity_mapping: Dict[str, str] = field(default_factory=dict)
    custom_field_mappings: Dict[str, str] = field(default_factory=dict)
    vulnerability_filters: List[str] = field(default_factory=list)


class ScannerTranslator(ABC):
    """Abstract base class for scanner-specific translators"""
    
    def __init__(self, scanner_config: ScannerConfig, tag_config: TagConfig, create_empty_assets: bool = False, create_inventory_assets: bool = False):
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
    ) -> tuple:
        """Split OCI image labels into Phoenix asset attributes and tags.

        Labels whose keys appear in *label_to_attribute* are placed in the
        returned attributes dict (with the mapped camelCase key).
        All remaining non-empty labels become Phoenix tag dicts.

        Returns:
            (label_attributes, label_tags)
        """
        if label_to_attribute is None:
            label_to_attribute = {
                "org.opencontainers.image.base.digest": "imageDigest",
                "org.opencontainers.image.base.name":   "imageName",
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
                if k in label_to_attribute:
                    label_attributes[label_to_attribute[k]] = value_str
                else:
                    label_tags.append({"key": str(k), "value": value_str})
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
        
        # Filter out tags with empty values before adding them
        filtered_vuln_tags = [
            tag for tag in vuln_tags 
            if tag.get("value") and str(tag.get("value")).strip()
        ]
        
        # Add filtered vulnerability tags
        vulnerability["tags"].extend(filtered_vuln_tags)
        logger.debug(f"Applied {len(filtered_vuln_tags)} tags to vulnerability '{vulnerability.get('name', 'unknown')}': {len(vulnerability['tags'])} total tags")
        
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
            # Filter out empty tags before extending
            filtered_asset_type_tags = [
                tag for tag in asset_type_tags 
                if tag.get("value") and str(tag.get("value")).strip()
            ]
            logger.debug(f"🔍 Asset type tags before filter: {asset_type_tags}")
            logger.debug(f"🔍 Asset type tags after filter: {filtered_asset_type_tags}")
            asset.tags.extend(filtered_asset_type_tags)

        return asset


class AnchoreGrypeTranslator(ScannerTranslator):
    """Translator for Anchore Grype scanner results"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Grype scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Grype-specific structure
            # Grype has 'matches', 'source', 'descriptor' at root level
            # and descriptor.name == 'grype'
            if isinstance(file_content, dict):
                has_matches = 'matches' in file_content
                has_descriptor = 'descriptor' in file_content
                
                if has_descriptor:
                    descriptor = file_content.get('descriptor', {})
                    if isinstance(descriptor, dict) and descriptor.get('name', '').lower() == 'grype':
                        return True
                
                # Check if it has matches array with Grype-style structure
                if has_matches:
                    matches = file_content.get('matches', [])
                    if matches and isinstance(matches, list):
                        first_match = matches[0] if len(matches) > 0 else {}
                        # Grype matches have 'vulnerability', 'artifact', 'matchDetails'
                        if 'vulnerability' in first_match and 'artifact' in first_match:
                            return True
                        # Some Grype files have just 'vulnerability' without 'artifact'
                        if 'vulnerability' in first_match:
                            vuln = first_match.get('vulnerability', {})
                            # Check for Grype-specific vulnerability fields
                            if 'dataSource' in vuln or 'namespace' in vuln or 'fix' in vuln:
                                return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Grype scan results"""
        logger.info(f"Parsing Anchore Grype scan file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "Grype File Parsing", file_path, "parse_file")
            raise
        
        assets = []
        
        # Extract source information
        source = data.get('source', {})
        source_type = source.get('type', 'unknown')
        target_info = source.get('target', {})
        
        # Get image/repo name
        if isinstance(target_info, dict):
            image_name = target_info.get('userInput', target_info.get('imageID', 'unknown'))
        else:
            image_name = str(target_info) if target_info else 'unknown'

        label_attributes, label_tags = self.promote_oci_labels(target_info)

        # Create container asset
        asset_attributes = {
            'dockerfile': 'Dockerfile',
            'origin': 'anchore-grype',
            'repository': image_name,
            **label_attributes,
        }

        asset = AssetData(
            asset_type="CONTAINER",
            attributes=asset_attributes,
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "anchore-grype"},
                {"key": "source-type", "value": source_type},
            ] + label_tags
        )
        
        # Process matches (vulnerabilities)
        matches = data.get('matches', [])
        for match in matches:
            vuln_data = match.get('vulnerability', {})
            artifact_data = match.get('artifact', {})
            
            # Skip if this is not a real vulnerability
            vuln_id = vuln_data.get('id', '')
            if not vuln_id:
                continue
            
            # Get severity
            severity = vuln_data.get('severity', 'Unknown')
            
            # Get CVSS scores
            cvss_list = vuln_data.get('cvss', [])
            cvss_v2_score = None
            cvss_v3_score = None
            for cvss in cvss_list:
                version = cvss.get('version', '')
                metrics = cvss.get('metrics', {})
                if version.startswith('2'):
                    cvss_v2_score = metrics.get('baseScore')
                elif version.startswith('3'):
                    cvss_v3_score = metrics.get('baseScore')
            
            # Get fix information
            fix_info = vuln_data.get('fix', {})
            fix_versions = fix_info.get('versions', [])
            fix_state = fix_info.get('state', 'unknown')
            
            # Create vulnerability
            vulnerability = VulnerabilityData(
                name=vuln_id,
                description=vuln_data.get('description', '') or f"Vulnerability {vuln_id} found in {artifact_data.get('name', 'package')}",
                remedy=f"Update {artifact_data.get('name', 'package')} to fixed version: {', '.join(fix_versions)}" if fix_versions else "No fix available",
                severity=self.normalize_severity(severity),
                location=f"{artifact_data.get('name', '')}@{artifact_data.get('version', '')}",
                reference_ids=[vuln_id] if vuln_id.startswith('CVE-') or vuln_id.startswith('GHSA-') else [],
                details={
                    'package_name': artifact_data.get('name', ''),
                    'package_version': artifact_data.get('version', ''),
                    'package_type': artifact_data.get('type', ''),
                    'package_language': artifact_data.get('language', ''),
                    'fix_versions': fix_versions,
                    'fix_state': fix_state,
                    'cvss_v2_score': cvss_v2_score,
                    'cvss_v3_score': cvss_v3_score,
                    'data_source': vuln_data.get('dataSource', ''),
                    'namespace': vuln_data.get('namespace', ''),
                    'urls': vuln_data.get('urls', [])
                }
            )
            
            asset.findings.append(vulnerability.__dict__)
        
        assets.append(self.ensure_asset_has_findings(asset))
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


class TrivyTranslator(ScannerTranslator):
    """Translator for Trivy scanner results - handles multiple Trivy formats"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Trivy scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Trivy-specific structures
            if isinstance(file_content, dict):
                # New format: Has "Results" array
                if 'Results' in file_content and isinstance(file_content.get('Results'), list):
                    return True
                # Kubernetes format: Has "Resources" array with "Results" nested
                if 'Resources' in file_content and isinstance(file_content.get('Resources'), list):
                    resources = file_content.get('Resources', [])
                    if resources and 'Results' in resources[0]:
                        return True
            elif isinstance(file_content, list):
                # Legacy format: Root is an array with Target, Type, Vulnerabilities
                if file_content and isinstance(file_content[0], dict):
                    first_item = file_content[0]
                    if 'Target' in first_item and ('Vulnerabilities' in first_item or 'Results' in first_item):
                        return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Trivy scan results - supports multiple formats"""
        logger.info(f"Parsing Trivy scan file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "Trivy File Parsing", file_path, "parse_file")
            raise
        
        assets = []
        
        # Detect format and parse accordingly
        if isinstance(data, dict):
            if 'Results' in data:
                # New format: Results[] → Vulnerabilities[] or Misconfigurations[]
                assets = self._parse_new_format(data, file_path)
            elif 'Resources' in data:
                # Kubernetes format: Resources[] → Results[] → Misconfigurations[] or Vulnerabilities[]
                assets = self._parse_kubernetes_format(data, file_path)
        elif isinstance(data, list):
            # Legacy format: Array of targets with Vulnerabilities[]
            assets = self._parse_legacy_format(data, file_path)
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_new_format(self, data: Dict, file_path: str) -> List[AssetData]:
        """Parse new Trivy format: Results[] → Vulnerabilities[]"""
        assets = []
        
        # Get artifact info
        artifact_name = data.get('ArtifactName', data.get('ArtifactPath', 'unknown'))
        artifact_type = data.get('ArtifactType', 'CONTAINER')
        
        # Create asset
        asset_attributes = {
            'dockerfile': artifact_name if 'Dockerfile' not in artifact_name else 'Dockerfile',
            'origin': 'trivy',
            'repository': artifact_name
        }
        
        asset = AssetData(
            asset_type="CONTAINER",
            attributes=asset_attributes,
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "trivy"},
                {"key": "artifact_type", "value": artifact_type}
            ]
        )
        
        # Process Results[] → Vulnerabilities[]
        results = data.get('Results', [])
        for result in results:
            target = result.get('Target', '')
            result_class = result.get('Class', '')
            
            # Process vulnerabilities
            vulnerabilities = result.get('Vulnerabilities', [])
            if vulnerabilities:
                for vuln_data in vulnerabilities:
                    vuln = self._create_vulnerability(vuln_data, target)
                    if vuln:
                        asset.findings.append(vuln)
            
            # Process misconfigurations
            misconfigs = result.get('Misconfigurations', [])
            if misconfigs:
                for misconfig_data in misconfigs:
                    vuln = self._create_misconfiguration_finding(misconfig_data, target)
                    if vuln:
                        asset.findings.append(vuln)
        
        assets.append(self.ensure_asset_has_findings(asset))
        return assets
    
    def _parse_legacy_format(self, data: List, file_path: str) -> List[AssetData]:
        """Parse legacy Trivy format: Array → Vulnerabilities[]"""
        assets = []
        
        for item in data:
            target = item.get('Target', 'unknown')
            target_type = item.get('Type', 'unknown')
            
            # Create asset
            asset_attributes = {
                'dockerfile': 'Dockerfile' if 'Dockerfile' in target else target,
                'origin': 'trivy',
                'repository': target
            }
            
            asset = AssetData(
                asset_type="CONTAINER",
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy"},
                    {"key": "target_type", "value": target_type}
                ]
            )
            
            # Process vulnerabilities
            vulnerabilities = item.get('Vulnerabilities', [])
            if vulnerabilities:
                for vuln_data in vulnerabilities:
                    vuln = self._create_vulnerability(vuln_data, target)
                    if vuln:
                        asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_kubernetes_format(self, data: Dict, file_path: str) -> List[AssetData]:
        """Parse Kubernetes Trivy format: Resources[] → Results[] → Misconfigurations[]"""
        assets = []
        
        resources = data.get('Resources', [])
        for resource in resources:
            namespace = resource.get('Namespace', 'default')
            kind = resource.get('Kind', 'unknown')
            name = resource.get('Name', 'unknown')
            
            # Create asset - INFRA type requires hostname
            asset_attributes = {
                'dockerfile': f"{kind}/{name}",
                'origin': 'trivy-kubernetes',
                'repository': f"{namespace}/{kind}/{name}",
                'hostname': f"{name}.{namespace}.k8s"  # Add hostname for INFRA assets
            }
            
            asset = AssetData(
                asset_type="INFRA",
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy"},
                    {"key": "kubernetes_namespace", "value": namespace},
                    {"key": "kubernetes_kind", "value": kind}
                ]
            )
            
            # Process Results[] → Misconfigurations[] or Vulnerabilities[]
            results = resource.get('Results', [])
            for result in results:
                target = result.get('Target', '')
                
                # Process misconfigurations
                misconfigs = result.get('Misconfigurations', [])
                if misconfigs:
                    for misconfig_data in misconfigs:
                        vuln = self._create_misconfiguration_finding(misconfig_data, target)
                        if vuln:
                            asset.findings.append(vuln)
                
                # Process vulnerabilities
                vulnerabilities = result.get('Vulnerabilities', [])
                if vulnerabilities:
                    for vuln_data in vulnerabilities:
                        vuln = self._create_vulnerability(vuln_data, target)
                        if vuln:
                            asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _create_vulnerability(self, vuln_data: Dict, target: str) -> Optional[Dict]:
        """Create a vulnerability finding from Trivy data"""
        vuln_id = vuln_data.get('VulnerabilityID', '')
        if not vuln_id:
            return None
        
        # Get severity
        severity = vuln_data.get('Severity', 'UNKNOWN')
        
        # Get package info
        pkg_name = vuln_data.get('PkgName', '')
        installed_version = vuln_data.get('InstalledVersion', '')
        fixed_version = vuln_data.get('FixedVersion', '')
        
        # Get dates
        published_date = vuln_data.get('PublishedDate', '')
        last_modified_date = vuln_data.get('LastModifiedDate', '')
        
        # Format published date to Phoenix format (ISO-8601 with T separator)
        if published_date:
            try:
                dt = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                published_date = dt.strftime("%Y-%m-%dT%H:%M:%S")
            except:
                published_date = None
        
        # Get CWE IDs
        cwe_ids = vuln_data.get('CweIDs', [])
        
        # Create remedy
        if fixed_version:
            remedy = f"Update {pkg_name} from {installed_version} to {fixed_version}"
        else:
            remedy = "No fix available"
        
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=vuln_data.get('Description', vuln_data.get('Title', 'No description available')),
            remedy=remedy,
            severity=self.normalize_severity(severity),
            location=f"{pkg_name}@{installed_version}" if pkg_name else target,
            reference_ids=[vuln_id] if vuln_id.startswith('CVE-') else [],
            published_date_time=published_date,
            details={
                'package_name': pkg_name,
                'installed_version': installed_version,
                'fixed_version': fixed_version,
                'target': target,
                'severity_source': vuln_data.get('SeveritySource', ''),
                'primary_url': vuln_data.get('PrimaryURL', ''),
                'references': vuln_data.get('References', []),
                'cwe_ids': cwe_ids,
                'last_modified_date': last_modified_date
            }
        )
        
        return vulnerability.__dict__
    
    def _create_misconfiguration_finding(self, misconfig_data: Dict, target: str) -> Optional[Dict]:
        """Create a misconfiguration finding from Trivy data"""
        vuln_id = misconfig_data.get('ID', misconfig_data.get('AVDID', ''))
        if not vuln_id:
            return None
        
        # Get severity
        severity = misconfig_data.get('Severity', 'UNKNOWN')
        
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=misconfig_data.get('Description', misconfig_data.get('Message', 'No description available')),
            remedy=misconfig_data.get('Resolution', 'No remedy provided'),
            severity=self.normalize_severity(severity),
            location=target,
            reference_ids=[vuln_id],
            details={
                'type': misconfig_data.get('Type', ''),
                'title': misconfig_data.get('Title', ''),
                'message': misconfig_data.get('Message', ''),
                'primary_url': misconfig_data.get('PrimaryURL', ''),
                'references': misconfig_data.get('References', []),
                'status': misconfig_data.get('Status', ''),
                'namespace': misconfig_data.get('Namespace', ''),
                'query': misconfig_data.get('Query', '')
            }
        )
        
        return vulnerability.__dict__


class AquaScanTranslator(ScannerTranslator):
    """Translator for Aqua Security scanner results"""
    
    def __init__(self, scanner_config: ScannerConfig, tag_config: TagConfig, create_empty_assets: bool = False, create_inventory_assets: bool = False):
        super().__init__(scanner_config, tag_config, create_empty_assets, create_inventory_assets)
        self.asset_name_override = None  # Add support for asset name override
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is an Aqua scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Aqua-specific fields (but NOT Grype fields)
            if isinstance(file_content, dict):
                # Exclude Grype files
                if 'descriptor' in file_content:
                    descriptor = file_content.get('descriptor', {})
                    if isinstance(descriptor, dict) and descriptor.get('name', '').lower() == 'grype':
                        return False
                
                # Check for Aqua-specific fields
                aqua_indicators = ['image', 'resources', 'vulnerability_summary', 'aqua_score', 'aqua_severity']
                return any(indicator in str(file_content) for indicator in aqua_indicators)
            
            return False
        except:
            return False
    
    def _convert_date_to_iso8601(self, date_str: str) -> str:
        """Convert date string to ISO-8601 format with time (YYYY-MM-DDTHH:MM:SS)"""
        if not date_str or date_str.strip() in ['N/A', '', 'NULL', 'null', 'None']:
            return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        
        # Clean the date string
        date_str = date_str.strip()
        
        # Common date formats to handle
        date_formats = [
            '%Y-%m-%dT%H:%M:%S',      # ISO format with time
            '%Y-%m-%d %H:%M:%S',      # Standard datetime
            '%Y-%m-%d',               # Date only (YYYY-MM-DD)
            '%m/%d/%Y %H:%M:%S',      # US format with time
            '%m/%d/%Y',               # US format
            '%d/%m/%Y %H:%M:%S',      # EU format with time
            '%d/%m/%Y',               # EU format
            '%b %d, %Y %H:%M:%S',     # Text month with time
            '%b %d, %Y',              # Text month
            '%Y/%m/%d',               # Alternative format
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                continue
        
        # If no format matches, log warning and return current time
        logger.warning(f"Could not parse date '{date_str}', using current time")
        return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    
    def parse_file(self, file_path: str, asset_name_override: Optional[str] = None) -> List[AssetData]:
        """Parse Aqua scan results
        
        Args:
            file_path: Path to Aqua scan file
            asset_name_override: Optional custom asset name to override default detection
        """
        logger.info(f"Parsing Aqua scan file: {file_path}")
        
        # Log file processing start
        DebugLogger.log_file_processing(file_path, "Aqua Parse Start", {
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "scanner_type": "Aqua"
        })
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "Aqua File Parsing", file_path, "parse_file")
            raise
        
        assets = []
        
        # Extract image information
        # Priority: command-line override > JSON 'image' field > resource.name > fallback
        if asset_name_override or self.asset_name_override:
            image_name = asset_name_override or self.asset_name_override
            logger.info(f"🏷️ Using custom asset name: {image_name}")
        else:
            # Try multiple sources for the image/asset name
            image_name = (
                data.get('image') or  # Standard Aqua image field
                (data.get('resource', {}).get('name') if data.get('resource') else None) or  # NPM package name
                'unknown-image'
            )
            
            # Include version if available for better asset identification (only if not custom override)
            if data.get('resource', {}).get('version') and ':' not in image_name:
                image_name = f"{image_name}:{data['resource']['version']}"
        
        image_digest = data.get('digest', '')
        os_info = f"{data.get('os', '')} {data.get('version', '')}".strip()
        
        # Create container asset
        asset_attributes = {
            'dockerfile': 'Dockerfile',
            'origin': 'aqua-scan'
        }
        
        if image_name:
            asset_attributes['repository'] = image_name
        
        # Build tags, filtering out empty values
        aqua_tags = [
            {"key": "scanner", "value": "aqua"}
        ]

        # Debug: Log what we have
        logger.info(f"🔍 DEBUG: image_digest = '{image_digest}' (type: {type(image_digest)}, bool: {bool(image_digest)})")
        logger.info(f"🔍 DEBUG: os_info = '{os_info}' (type: {type(os_info)}, bool: {bool(os_info)})")

        # Only add image-digest tag if it has a value
        if image_digest:
            aqua_tags.append({"key": "image-digest", "value": image_digest[:16]})
            logger.info(f"✅ Added image-digest tag with value: '{image_digest[:16]}'")

        # Only add os tag if it has a meaningful value
        if os_info:
            aqua_tags.append({"key": "os", "value": os_info})
            logger.info(f"✅ Added os tag with value: '{os_info}'")

        # Combine all tags and filter out any with empty values
        all_tags = self.tag_config.get_all_tags() + aqua_tags
        logger.info(f"🔍 DEBUG: all_tags before filtering = {all_tags}")
        
        filtered_tags = [
            tag for tag in all_tags 
            if tag.get("value") and str(tag.get("value")).strip()
        ]
        logger.info(f"🔍 DEBUG: filtered_tags after filtering = {filtered_tags}")

        asset = AssetData(
            asset_type="CONTAINER",
            attributes=asset_attributes,
            tags=filtered_tags
        )
        
        # Process vulnerabilities from resources
        resources = data.get('resources', [])
        for resource in resources:
            resource_info = resource.get('resource', {})
            vulnerabilities = resource.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                # Convert publish_date to ISO-8601 format with time
                publish_date = vuln.get('publish_date', '')
                published_date_time = self._convert_date_to_iso8601(publish_date) if publish_date else None
                
                # Create vulnerability
                vulnerability = VulnerabilityData(
                    name=vuln.get('name', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    remedy=vuln.get('solution', 'No solution provided'),
                    severity=self.normalize_severity(vuln.get('aqua_severity', vuln.get('nvd_severity', 'medium'))),
                    location=f"{resource_info.get('name', '')}:{resource_info.get('version', '')}",
                    reference_ids=[vuln.get('name', '')] if vuln.get('name', '').startswith('CVE-') else [],
                    published_date_time=published_date_time,
                    details={
                        'package_name': resource_info.get('name', ''),
                        'package_version': resource_info.get('version', ''),
                        'package_format': resource_info.get('format', ''),
                        'package_arch': resource_info.get('arch', ''),
                        'nvd_score': vuln.get('nvd_score', ''),
                        'nvd_score_v3': vuln.get('nvd_score_v3', ''),
                        'aqua_score': vuln.get('aqua_score', ''),
                        'fix_version': vuln.get('fix_version', ''),
                        'nvd_url': vuln.get('nvd_url', ''),
                        'vendor_severity': vuln.get('vendor_severity', ''),
                        'modification_date': self._convert_date_to_iso8601(vuln.get('modification_date', '')) if vuln.get('modification_date') else ''
                    }
                )
                
                asset.findings.append(vulnerability.__dict__)
        
        assets.append(self.ensure_asset_has_findings(asset))
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


class JFrogXrayTranslator(ScannerTranslator):
    """Translator for JFrog Xray scanner results (multiple formats)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a JFrog Xray scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for JFrog-specific fields
            jfrog_indicators = ['artifacts', 'issues', 'xray', 'jfrog', 'impact_path', 'issue_id']
            return any(indicator in str(file_content).lower() for indicator in jfrog_indicators)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse JFrog Xray scan results"""
        logger.info(f"Parsing JFrog Xray scan file: {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        assets = []
        
        # Handle different JFrog Xray formats
        if 'artifacts' in data:
            assets.extend(self._parse_artifacts_format(data))
        elif 'vulnerabilities' in data:
            assets.extend(self._parse_vulnerabilities_format(data))
        elif 'runs' in data:
            assets.extend(self._parse_sarif_format(data))
        else:
            # Try to parse as generic format
            assets.extend(self._parse_generic_format(data))
        
        # Ensure all assets have findings if create_empty_assets is enabled
        assets = [self.ensure_asset_has_findings(asset) for asset in assets]
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_artifacts_format(self, data: Dict) -> List[AssetData]:
        """Parse JFrog Xray artifacts format"""
        assets = []
        
        for artifact in data.get('artifacts', []):
            general = artifact.get('general', {})
            
            # Create asset based on package type
            pkg_type = general.get('pkg_type', 'Unknown')
            asset_type = "CONTAINER" if pkg_type.lower() in ['docker', 'oci'] else "BUILD"
            
            asset_attributes = {
                'repository': general.get('name', 'unknown-artifact'),
                'origin': 'jfrog-xray'
            }
            
            if asset_type == "BUILD":
                asset_attributes['buildFile'] = general.get('path', 'build.json')
            elif asset_type == "CONTAINER":
                asset_attributes['dockerfile'] = 'Dockerfile'
            
            asset = AssetData(
                asset_type=asset_type,
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "package-type", "value": pkg_type},
                    {"key": "component-id", "value": general.get('component_id', '')},
                    {"key": "sha256", "value": general.get('sha256', '')[:16] if general.get('sha256') else ""}
                ]
            )
            
            # Process issues (vulnerabilities)
            for issue in artifact.get('issues', []):
                vulnerability = VulnerabilityData(
                    name=issue.get('issue_id', issue.get('summary', 'Unknown Issue')),
                    description=issue.get('description', issue.get('summary', '')),
                    remedy='Review and update affected components',
                    severity=self.normalize_severity(issue.get('severity', 'medium')),
                    location=', '.join(issue.get('impact_path', [])),
                    reference_ids=self.extract_cves(str(issue)),
                    published_date_time=issue.get('created', datetime.now().strftime("%Y-%m-%d")),
                    details={
                        'issue_id': issue.get('issue_id', ''),
                        'issue_type': issue.get('issue_type', ''),
                        'provider': issue.get('provider', ''),
                        'impact_path': issue.get('impact_path', []),
                        'cves': issue.get('cves', [])
                    }
                )
                
                asset.findings.append(vulnerability.__dict__)
            
            assets.append(asset)
        
        return assets
    
    def _parse_vulnerabilities_format(self, data: Dict) -> List[AssetData]:
        """Parse JFrog Xray vulnerabilities format"""
        assets = []
        
        # Create a generic asset for vulnerabilities
        asset = AssetData(
            asset_type="BUILD",
            attributes={
                'repository': 'jfrog-xray-scan',
                'buildFile': 'scan-results.json',
                'origin': 'jfrog-xray'
            },
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "jfrog-xray"}
            ]
        )
        
        for vuln in data.get('vulnerabilities', []):
            vulnerability = VulnerabilityData(
                name=vuln.get('cve', vuln.get('issue_id', 'Unknown Vulnerability')),
                description=vuln.get('description', ''),
                remedy=vuln.get('fix_version', 'Update to latest version'),
                severity=self.normalize_severity(vuln.get('severity', 'medium')),
                location=vuln.get('component', ''),
                reference_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                details=vuln
            )
            
            asset.findings.append(vulnerability.__dict__)
        
        if asset.findings:
            assets.append(asset)
        
        return assets
    
    def _parse_sarif_format(self, data: Dict) -> List[AssetData]:
        """Parse SARIF format from JFrog Xray"""
        assets = []
        
        for run in data.get('runs', []):
            # Create asset for each run
            asset = AssetData(
                asset_type="CODE",
                attributes={
                    'scannerSource': 'jfrog-xray-sarif',
                    'origin': 'jfrog-xray'
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "format", "value": "sarif"}
                ]
            )
            
            for result in run.get('results', []):
                rule_id = result.get('ruleId', 'unknown-rule')
                message = result.get('message', {}).get('text', '')
                
                vulnerability = VulnerabilityData(
                    name=rule_id,
                    description=message,
                    remedy='Review and fix the identified issue',
                    severity=self.normalize_severity(result.get('level', 'warning')),
                    location=str(result.get('locations', [])),
                    details=result
                )
                
                asset.findings.append(vulnerability.__dict__)
            
            if asset.findings:
                assets.append(asset)
        
        return assets
    
    def _parse_generic_format(self, data: Dict) -> List[AssetData]:
        """Parse generic JFrog Xray format"""
        assets = []
        
        # Create a generic asset
        asset = AssetData(
            asset_type="BUILD",
            attributes={
                'repository': 'jfrog-xray-generic',
                'buildFile': 'scan-results.json',
                'origin': 'jfrog-xray'
            },
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "jfrog-xray"},
                {"key": "format", "value": "generic"}
            ]
        )
        
        # Try to extract vulnerabilities from various possible structures
        vulnerabilities = []
        
        # Check for direct vulnerabilities array
        if isinstance(data, list):
            vulnerabilities = data
        elif 'vulnerabilities' in data:
            vulnerabilities = data['vulnerabilities']
        elif 'issues' in data:
            vulnerabilities = data['issues']
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vulnerability = VulnerabilityData(
                    name=vuln.get('id', vuln.get('name', 'Unknown Vulnerability')),
                    description=vuln.get('description', vuln.get('summary', '')),
                    remedy=vuln.get('solution', 'Review and update'),
                    severity=self.normalize_severity(vuln.get('severity', 'medium')),
                    location=vuln.get('location', vuln.get('component', '')),
                    reference_ids=self.extract_cves(str(vuln)),
                    details=vuln
                )
                
                asset.findings.append(vulnerability.__dict__)
        
        if asset.findings:
            assets.append(asset)
        
        return assets


class QualysTranslator(ScannerTranslator):
    """Translator for Qualys scanner results (CSV and XML)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Qualys scan file"""
        file_lower = file_path.lower()
        
        if file_lower.endswith('.csv'):
            # Check for Qualys CSV headers
            try:
                with open(file_path, 'r') as f:
                    first_line = f.readline().lower()
                    qualys_indicators = ['qid', 'qualys', 'vuln status', 'cvss', 'netbios']
                    return any(indicator in first_line for indicator in qualys_indicators)
            except:
                return False
        
        elif file_lower.endswith('.xml'):
            # Check for Qualys XML structure
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                qualys_indicators = ['was_scan_report', 'qualys', 'qid', 'vuln']
                return any(indicator in root.tag.lower() or 
                          any(indicator in elem.tag.lower() for elem in root.iter()) 
                          for indicator in qualys_indicators)
            except:
                return False
        
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Qualys scan results"""
        logger.info(f"Parsing Qualys scan file: {file_path}")
        
        if file_path.lower().endswith('.csv'):
            return self._parse_csv_format(file_path)
        elif file_path.lower().endswith('.xml'):
            return self._parse_xml_format(file_path)
        else:
            raise ValueError(f"Unsupported Qualys file format: {file_path}")
    
    def _parse_csv_format(self, file_path: str) -> List[AssetData]:
        """Parse Qualys CSV format"""
        assets_map = {}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Extract asset information
                ip_address = row.get('IP', row.get('IP Address', '')).strip()
                hostname = row.get('DNS', row.get('DNS Name', row.get('FQDN', ''))).strip()
                netbios = row.get('NetBIOS', row.get('NetBIOS Name', '')).strip()
                os_info = row.get('OS', '').strip()
                
                # Create asset key
                asset_key = ip_address or hostname or netbios or 'unknown-host'
                
                if asset_key not in assets_map:
                    # Create new asset
                    attributes = {}
                    if ip_address:
                        attributes['ip'] = ip_address
                    if hostname:
                        attributes['hostname'] = hostname
                        attributes['fqdn'] = hostname
                    if netbios:
                        attributes['netbios'] = netbios
                    if os_info:
                        attributes['os'] = os_info
                    
                    # Ensure required fields
                    if not attributes.get('ip') and not attributes.get('hostname'):
                        attributes['hostname'] = f"qualys-host-{asset_key}"
                    
                    asset = AssetData(
                        asset_type="INFRA",
                        attributes=attributes,
                        tags=self.tag_config.get_all_tags() + [
                            {"key": "scanner", "value": "qualys"},
                            {"key": "scan-type", "value": "infrastructure"}
                        ]
                    )
                    assets_map[asset_key] = asset
                
                # Extract vulnerability information
                qid = row.get('QID', row.get('Plugin', '')).strip()
                title = row.get('Title', row.get('Name', row.get('Plugin Name', ''))).strip()
                severity = row.get('Severity', row.get('Risk', row.get('Risk Factor', ''))).strip()
                
                if qid and title and severity and severity.lower() not in ['info', 'informational', 'none']:
                    vulnerability = VulnerabilityData(
                        name=f"QID-{qid}: {title}",
                        description=row.get('Description', row.get('Threat', '')),
                        remedy=row.get('Solution', 'No solution provided'),
                        severity=self.normalize_severity(severity),
                        location=f"{ip_address}:{row.get('Port', '')}",
                        reference_ids=self.extract_cves(row.get('CVE ID', row.get('CVE', ''))),
                        published_date_time=row.get('First Detected', row.get('First Discovered', row.get('Plugin Publication Date', datetime.now().strftime("%Y-%m-%d")))),
                        details={
                            'qid': qid,
                            'port': row.get('Port', ''),
                            'protocol': row.get('Protocol', ''),
                            'cvss_base': row.get('CVSS Base', row.get('CVSS3 Base', row.get('CVSS V2 Base Score', row.get('CVSS V3 Base Score', '')))),
                            'cvss_vector': row.get('CVSS Vector', row.get('CVSS3 Vector', row.get('CVSS V2 Vector', row.get('CVSS V3 Vector', '')))),
                            'first_detected': row.get('First Detected', row.get('First Discovered', '')),
                            'last_detected': row.get('Last Detected', row.get('Last Observed', '')),
                            'vuln_status': row.get('Vuln Status', ''),
                            'category': row.get('Category', row.get('Family', '')),
                            'pci_vuln': row.get('PCI Vuln', ''),
                            'plugin_output': row.get('Plugin Output', ''),
                            'synopsis': row.get('Synopsis', ''),
                            'exploit_available': row.get('Exploit?', ''),
                            'stig_severity': row.get('STIG Severity', ''),
                            'vpr': row.get('Vulnerability Priority Rating', '')
                        }
                    )
                    
                    assets_map[asset_key].findings.append(vulnerability.__dict__)
        
        # Ensure all assets have findings if create_empty_assets is enabled
        assets = [self.ensure_asset_has_findings(asset) for asset in assets_map.values()]
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_xml_format(self, file_path: str) -> List[AssetData]:
        """Parse Qualys XML format"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        assets = []
        
        # Handle different Qualys XML formats
        if root.tag == 'WAS_SCAN_REPORT':
            # Web Application Scan format
            assets.extend(self._parse_webapp_xml(root))
        else:
            # Infrastructure scan format
            assets.extend(self._parse_infra_xml(root))
        
        # Ensure all assets have findings if create_empty_assets is enabled
        assets = [self.ensure_asset_has_findings(asset) for asset in assets]
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_webapp_xml(self, root: ET.Element) -> List[AssetData]:
        """Parse Qualys Web Application XML format"""
        assets = []
        
        # Extract target information
        target = root.find('.//TARGET')
        if target is not None:
            target_url = target.find('URL')
            target_url_text = target_url.text if target_url is not None else 'unknown-webapp'
            
            # Create web asset
            asset = AssetData(
                asset_type="WEB",
                attributes={
                    'fqdn': target_url_text,
                    'origin': 'qualys-webapp'
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "qualys"},
                    {"key": "scan-type", "value": "web-application"}
                ]
            )
            
            # Extract vulnerabilities
            for vuln in root.findall('.//VULNERABILITY'):
                qid_elem = vuln.find('QID')
                title_elem = vuln.find('TITLE')
                severity_elem = vuln.find('SEVERITY')
                
                if qid_elem is not None and title_elem is not None:
                    vulnerability = VulnerabilityData(
                        name=f"QID-{qid_elem.text}: {title_elem.text}",
                        description=self._get_xml_text(vuln.find('DESCRIPTION')),
                        remedy=self._get_xml_text(vuln.find('SOLUTION')),
                        severity=self.normalize_severity(self._get_xml_text(severity_elem)),
                        location=target_url_text,
                        reference_ids=self.extract_cves(self._get_xml_text(vuln.find('CVE_ID_LIST'))),
                        details={
                            'qid': qid_elem.text,
                            'category': self._get_xml_text(vuln.find('CATEGORY')),
                            'group': self._get_xml_text(vuln.find('GROUP')),
                            'cvss_base': self._get_xml_text(vuln.find('CVSS_BASE')),
                            'cvss_temporal': self._get_xml_text(vuln.find('CVSS_TEMPORAL'))
                        }
                    )
                    
                    asset.findings.append(vulnerability.__dict__)
            
            assets.append(asset)
        
        return assets
    
    def _parse_infra_xml(self, root: ET.Element) -> List[AssetData]:
        """Parse Qualys Infrastructure XML format"""
        assets_map = {}
        
        # Extract host information and vulnerabilities
        for host in root.findall('.//HOST'):
            ip_elem = host.find('IP')
            if ip_elem is None:
                continue
            
            ip_address = ip_elem.text
            hostname = self._get_xml_text(host.find('HOSTNAME'))
            netbios = self._get_xml_text(host.find('NETBIOS'))
            os_elem = host.find('OS')
            os_info = os_elem.text if os_elem is not None else ''
            
            # Create asset
            attributes = {'ip': ip_address}
            if hostname:
                attributes['hostname'] = hostname
                attributes['fqdn'] = hostname
            if netbios:
                attributes['netbios'] = netbios
            if os_info:
                attributes['os'] = os_info
            
            asset = AssetData(
                asset_type="INFRA",
                attributes=attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "qualys"},
                    {"key": "scan-type", "value": "infrastructure"}
                ]
            )
            
            # Extract vulnerabilities for this host
            for vuln in host.findall('.//VULN'):
                qid_elem = vuln.find('QID')
                title_elem = vuln.find('TITLE')
                severity_elem = vuln.find('SEVERITY')
                
                if qid_elem is not None and title_elem is not None:
                    vulnerability = VulnerabilityData(
                        name=f"QID-{qid_elem.text}: {title_elem.text}",
                        description=self._get_xml_text(vuln.find('DIAGNOSIS')),
                        remedy=self._get_xml_text(vuln.find('SOLUTION')),
                        severity=self.normalize_severity(self._get_xml_text(severity_elem)),
                        location=f"{ip_address}:{self._get_xml_text(vuln.find('PORT'))}",
                        reference_ids=self.extract_cves(self._get_xml_text(vuln.find('CVE_ID'))),
                        details={
                            'qid': qid_elem.text,
                            'port': self._get_xml_text(vuln.find('PORT')),
                            'protocol': self._get_xml_text(vuln.find('PROTOCOL')),
                            'category': self._get_xml_text(vuln.find('CATEGORY')),
                            'cvss_base': self._get_xml_text(vuln.find('CVSS_BASE')),
                            'cvss_temporal': self._get_xml_text(vuln.find('CVSS_TEMPORAL'))
                        }
                    )
                    
                    asset.findings.append(vulnerability.__dict__)
            
            assets_map[ip_address] = asset
        
        return list(assets_map.values())
    
    def _get_xml_text(self, element: Optional[ET.Element]) -> str:
        """Safely get text from XML element"""
        return element.text if element is not None else ''


class SonarQubeTranslator(ScannerTranslator):
    """Translator for SonarQube scanner results"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a SonarQube scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for SonarQube-specific fields
            sonar_indicators = ['sonarBaseURL', 'sonarComponent', 'rules', 'issues', 'projectName']
            return any(indicator in file_content for indicator in sonar_indicators)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse SonarQube scan results"""
        logger.info(f"Parsing SonarQube scan file: {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Create code asset
        project_name = data.get('projectName', data.get('sonarComponent', 'unknown-project'))
        
        asset = AssetData(
            asset_type="CODE",
            attributes={
                'scannerSource': project_name,
                'origin': 'sonarqube'
            },
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "sonarqube"},
                {"key": "project", "value": project_name},
                {"key": "sonar-url", "value": data.get('sonarBaseURL', '')[:50]}
            ]
        )
        
        # Process issues
        for issue in data.get('issues', []):
            rule_key = issue.get('rule', '')
            rule_info = data.get('rules', {}).get(rule_key, {})
            
            vulnerability = VulnerabilityData(
                name=rule_info.get('name', issue.get('message', 'SonarQube Issue')),
                description=issue.get('message', rule_info.get('htmlDesc', '')),
                remedy='Review and fix the code issue according to SonarQube recommendations',
                severity=self.normalize_severity(issue.get('severity', 'MEDIUM')),
                location=f"{issue.get('component', '')}:{issue.get('line', '')}",
                reference_ids=[rule_key] if rule_key else [],
                cwes=self.extract_cwes(rule_info.get('htmlDesc', '')),
                details={
                    'rule': rule_key,
                    'component': issue.get('component', ''),
                    'line': issue.get('line', ''),
                    'status': issue.get('status', ''),
                    'type': issue.get('type', ''),
                    'effort': issue.get('effort', ''),
                    'debt': issue.get('debt', ''),
                    'tags': issue.get('tags', [])
                }
            )
            
            asset.findings.append(vulnerability.__dict__)
        
        # Ensure asset has findings if create_empty_assets is enabled
        asset = self.ensure_asset_has_findings(asset)
        assets = [asset] if asset.findings else []
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


class TenableTranslator(ScannerTranslator):
    """Translator for Tenable/Nessus scanner results"""
    
    def _convert_date_to_iso8601(self, date_str: str) -> str:
        """Convert date string to ISO-8601 format, handling N/A and various formats"""
        if not date_str or date_str.strip() in ['N/A', '', 'NULL', 'null', 'None']:
            return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        
        # Clean the date string
        date_str = date_str.strip()
        
        # Common date formats to handle
        date_formats = [
            '%Y-%m-%dT%H:%M:%S',      # ISO format
            '%Y-%m-%d %H:%M:%S',      # Standard datetime
            '%Y-%m-%d',               # Date only
            '%m/%d/%Y %H:%M:%S',      # US format with time
            '%m/%d/%Y',               # US format
            '%d/%m/%Y %H:%M:%S',      # EU format with time
            '%d/%m/%Y',               # EU format
            '%b %d, %Y %H:%M:%S',     # Text month with time
            '%b %d, %Y',              # Text month
            '%Y/%m/%d',               # Alternative format
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                continue
        
        # If no format matches, log warning and return current time
        logger.warning(f"Could not parse date '{date_str}', using current time")
        return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Tenable scan file"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().lower()
                tenable_indicators = ['plugin id', 'nessus', 'tenable', 'cvss', 'risk', 'synopsis']
                return any(indicator in first_line for indicator in tenable_indicators)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Tenable scan results"""
        logger.info(f"Parsing Tenable scan file: {file_path}")
        
        assets_map = {}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Extract asset information
                ip_address = row.get('IP Address', row.get('Host', '')).strip()
                hostname = row.get('FQDN', row.get('DNS Name', '')).strip()
                netbios = row.get('NetBios', '').strip()
                
                # Create asset key
                asset_key = ip_address or hostname or netbios or 'unknown-host'
                
                if asset_key not in assets_map:
                    # Create new asset
                    attributes = {}
                    if ip_address:
                        attributes['ip'] = ip_address
                    if hostname:
                        attributes['hostname'] = hostname
                        attributes['fqdn'] = hostname
                    if netbios:
                        attributes['netbios'] = netbios
                    
                    # Ensure required fields
                    if not attributes.get('ip') and not attributes.get('hostname'):
                        attributes['hostname'] = f"tenable-host-{asset_key}"
                    
                    asset = AssetData(
                        asset_type="INFRA",
                        attributes=attributes,
                        tags=self.tag_config.get_all_tags() + [
                            {"key": "scanner", "value": "tenable"},
                            {"key": "scan-type", "value": "network"}
                        ]
                    )
                    assets_map[asset_key] = asset
                
                # Extract vulnerability information
                plugin_id = row.get('Plugin ID', '').strip()
                name = row.get('Name', '').strip()
                risk = row.get('Risk', '').strip()
                
                if plugin_id and name and risk and risk.lower() not in ['none', 'info']:
                    vulnerability = VulnerabilityData(
                        name=f"Plugin-{plugin_id}: {name}",
                        description=row.get('Description', row.get('Synopsis', '')),
                        remedy=row.get('Solution', 'No solution provided'),
                        severity=self.normalize_severity(risk),
                        location=f"{ip_address}:{row.get('Port', '')}",
                        reference_ids=self.extract_cves(row.get('CVE', '')),
                        published_date_time=self._convert_date_to_iso8601(row.get('Plugin Publication Date', '')),
                        details={
                            'plugin_id': plugin_id,
                            'plugin_family': row.get('Plugin Family', ''),
                            'port': row.get('Port', ''),
                            'protocol': row.get('Protocol', ''),
                            'cvss_base_score': row.get('CVSS Base Score', row.get('CVSS3 Base Score', '')),
                            'cvss_vector': row.get('CVSS Vector', row.get('CVSS3 Vector', '')),
                            'exploit_available': row.get('Exploit Available', ''),
                            'patch_available': row.get('Patch Available', ''),
                            'first_found': self._convert_date_to_iso8601(row.get('First Found', row.get('First Discovered', ''))),
                            'last_found': self._convert_date_to_iso8601(row.get('Last Found', row.get('Last Observed', ''))),
                            'vuln_publication_date': self._convert_date_to_iso8601(row.get('Vuln Publication Date', '')),
                            'security_end_of_life_date': self._convert_date_to_iso8601(row.get('Security End of Life Date', '')),
                            'patch_publication_date': self._convert_date_to_iso8601(row.get('Patch Publication Date', '')),
                            'plugin_modification_date': self._convert_date_to_iso8601(row.get('Plugin Modification Date', '')),
                            'severity': row.get('Severity', ''),
                            'vpr_score': row.get('Vulnerability Priority Rating (VPR)', '')
                        }
                    )
                    
                    assets_map[asset_key].findings.append(vulnerability.__dict__)
        
        # Ensure all assets have findings if create_empty_assets is enabled
        assets = [self.ensure_asset_has_findings(asset) for asset in assets_map.values()]
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


class ConfigurableScannerTranslator(ScannerTranslator):
    """Universal translator that uses YAML configuration for field mapping"""
    
    def __init__(self, scanner_config: ScannerConfig, tag_config: TagConfig, create_empty_assets: bool = False, create_inventory_assets: bool = False):
        super().__init__(scanner_config, tag_config, create_empty_assets, create_inventory_assets)
        self.field_mapper = FieldMapper()
        self.format_detector = ScannerFormatDetector(self.field_mapper)
        self.universal_translator = UniversalScannerTranslator(self.field_mapper, self.format_detector)
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this translator can handle the file using universal detection"""
        return self.universal_translator.can_handle(file_path, file_content)
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse file using universal translator and convert to AssetData format"""
        logger.info(f"Parsing file with configurable translator: {file_path}")
        
        # Log file processing start
        DebugLogger.log_file_processing(file_path, "Configurable Parse Start", {
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "scanner_type": "Universal"
        })
        
        try:
            # Get scanner info
            scanner_info = self.universal_translator.get_scanner_info(file_path)
            if not scanner_info:
                raise ValueError(f"Cannot detect scanner format for {file_path}")
            
            # Parse using universal translator
            raw_assets = self.universal_translator.parse_file(file_path, scanner_info)
            
            # Convert to AssetData format
            assets = []
            for raw_asset in raw_assets:
                # Create AssetData object
                asset = AssetData(
                    asset_type=raw_asset.get('asset_type', 'INFRA'),
                    attributes=raw_asset.get('attributes', {}),
                    tags=self.tag_config.get_all_tags() + raw_asset.get('tags', [])
                )
                
                # Add findings
                for finding in raw_asset.get('findings', []):
                    asset.findings.append(finding)
                
                # Ensure asset has findings if create_empty_assets is enabled
                asset = self.ensure_asset_has_findings(asset)
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
            return assets
            
        except Exception as e:
            error_tracker.log_error(e, "Configurable Scanner Parsing", file_path, "parse_file")
            raise


class MultiScannerImportManager(PhoenixImportManager):
    """Enhanced import manager with multi-scanner support"""
    
    def __init__(self, config_file: Optional[str] = None):
        # Set default config file for multi-scanner tool
        if config_file is None:
            config_file = "config_multi_scanner.ini"
        super().__init__(config_file)
        self.translators = []
        self.scanner_configs = {}
        self._initialize_translators()
    
    def _initialize_translators(self):
        """Initialize all scanner translators"""
        # Default scanner configurations
        default_configs = {
            'aqua': ScannerConfig('Aqua Scan', 'CONTAINER'),
            'anchore_grype': ScannerConfig('Anchore Grype', 'CONTAINER'),
            'trivy': ScannerConfig('Trivy', 'CONTAINER'),
            'jfrog': ScannerConfig('JFrog Xray Scan', 'BUILD'),
            'blackduck': ScannerConfig('BlackDuck', 'BUILD'),
            'prowler': ScannerConfig('AWS Prowler', 'CLOUD'),
            'qualys': ScannerConfig('Qualys Scan', 'INFRA'),
            'qualys_webapp': ScannerConfig('Qualys WebApp', 'WEB'),
            'sonarqube': ScannerConfig('SonarQube Scan', 'CODE'),
            'tenable': ScannerConfig('Tenable Scan', 'INFRA'),
            'dependency_check': ScannerConfig('OWASP Dependency Check', 'BUILD'),
            'cyclonedx': ScannerConfig('CycloneDX SBOM', 'BUILD'),
            'npm_audit': ScannerConfig('npm audit', 'BUILD'),
            'pip_audit': ScannerConfig('pip-audit', 'BUILD'),
            'burp_api': ScannerConfig('Burp Suite API', 'WEB'),
            'checkmarx_osa': ScannerConfig('Checkmarx OSA', 'BUILD'),
            'snyk_issue_api': ScannerConfig('Snyk Issues API', 'BUILD'),
            'universal': ScannerConfig('Universal Scanner', 'INFRA')  # Universal translator
        }
        
        self.scanner_configs.update(default_configs)
        
        # Initialize translators with default tag config
        tag_config = self.tag_config or TagConfig()
        
        self.translators = [
            # Add the universal configurable translator first (highest priority)
            ConfigurableScannerTranslator(self.scanner_configs['universal'], tag_config),
            # Keep existing translators as fallbacks
            AnchoreGrypeTranslator(self.scanner_configs['anchore_grype'], tag_config),
            TrivyTranslator(self.scanner_configs['trivy'], tag_config),
            AquaScanTranslator(self.scanner_configs['aqua'], tag_config),
            JFrogXrayTranslator(self.scanner_configs['jfrog'], tag_config),
            QualysTranslator(self.scanner_configs['qualys'], tag_config),
            SonarQubeTranslator(self.scanner_configs['sonarqube'], tag_config),
            TenableTranslator(self.scanner_configs['tenable'], tag_config)
        ]
    
    def load_configuration(self) -> Tuple[PhoenixConfig, TagConfig]:
        """Load configuration from file and environment with multi-scanner fallbacks"""
        logger.info(f"Loading configuration from {self.config_file}")
        
        # Check if default config file exists, if not, try fallback options
        config_path = Path(self.config_file)
        if not config_path.exists() and self.config_file == "config_multi_scanner.ini":
            # Try fallback config files specific to multi-scanner
            fallback_configs = ["config.ini", "config_multi_scanner EXAMPLE.ini", "config_refactored.ini"]
            for fallback in fallback_configs:
                fallback_path = Path(fallback)
                if fallback_path.exists():
                    logger.info(f"Default multi-scanner config not found, using fallback: {fallback}")
                    self.config_file = fallback
                    config_path = fallback_path
                    break
        
        # Call parent method to do the actual loading
        return super().load_configuration()
    
    def detect_scanner_type(self, file_path: str) -> Optional[ScannerTranslator]:
        """Automatically detect scanner type from file"""
        logger.info(f"Detecting scanner type for: {file_path}")
        
        for translator in self.translators:
            if translator.can_handle(file_path):
                scanner_name = translator.__class__.__name__.replace('Translator', '')
                logger.info(f"Detected scanner type: {scanner_name}")
                return translator
        
        logger.warning(f"Could not detect scanner type for: {file_path}")
        return None
    
    def process_scanner_file(self, file_path: str, scanner_type: Optional[str] = None,
                           asset_type: Optional[str] = None, assessment_name: Optional[str] = None,
                           import_type: str = "new", anonymize: bool = False,
                           just_tags: bool = False, create_empty_assets: bool = False,
                           create_inventory_assets: bool = False, verify_import: bool = False) -> Dict[str, Any]:
        """Process a scanner file with automatic or specified scanner detection"""
        
        # Get translator
        if scanner_type:
            # Use specified scanner type
            translator = None
            for t in self.translators:
                if scanner_type.lower() in t.__class__.__name__.lower():
                    translator = t
                    break
            
            if not translator:
                raise ValueError(f"Unsupported scanner type: {scanner_type}")
        else:
            # Auto-detect scanner type
            translator = self.detect_scanner_type(file_path)
            if not translator:
                raise ValueError(f"Could not detect scanner type for file: {file_path}")
        
        # Override asset type if specified
        if asset_type:
            translator.scanner_config.asset_type = asset_type
        
        # Set asset creation options
        translator.create_empty_assets = create_empty_assets
        translator.create_inventory_assets = create_inventory_assets
        
        # Parse file
        assets = translator.parse_file(file_path)
        
        if not assets:
            return {
                'file': file_path,
                'success': False,
                'error': 'No assets created from scanner file'
            }
        
        # Apply anonymization if requested
        if anonymize:
            if not self.anonymizer:
                self.anonymizer = DataAnonymizer()
            
            for asset in assets:
                # Anonymize asset attributes
                for key, value in asset.attributes.items():
                    if key in ['ip', 'hostname', 'fqdn']:
                        if key == 'ip':
                            asset.attributes[key] = self.anonymizer.anonymize_ip(value)
                        else:
                            asset.attributes[key] = self.anonymizer.anonymize_hostname(value)
                
                # Anonymize vulnerability details
                for finding in asset.findings:
                    if 'location' in finding:
                        # Anonymize IPs and hostnames in location field
                        location = finding['location']
                        # Simple regex-based anonymization for location field
                        import re
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        location = re.sub(ip_pattern, lambda m: self.anonymizer.anonymize_ip(m.group(0)), location)
                        finding['location'] = location
        
        # Generate assessment name
        if not assessment_name:
            file_name = Path(file_path).stem
            scanner_name = translator.__class__.__name__.replace('Translator', '').lower()
            assessment_name = f"{scanner_name}_{file_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Update Phoenix config
        self.phoenix_config.import_type = import_type
        
        # Import assets
        api_client = PhoenixAPIClient(self.phoenix_config)
        
        if just_tags:
            # Only add tags to existing assets
            asset_ids = [asset.asset_id for asset in assets if asset.asset_id]
            if asset_ids and self.tag_config.get_all_tags():
                success = api_client.add_tags_to_assets(asset_ids, self.tag_config.get_all_tags())
                return {
                    'file': file_path,
                    'success': success,
                    'operation': 'tags_only',
                    'scanner_type': translator.__class__.__name__.replace('Translator', ''),
                    'assets_tagged': len(asset_ids),
                    'tags_applied': len(self.tag_config.get_all_tags())
                }
            else:
                return {
                    'file': file_path,
                    'success': False,
                    'error': 'No asset IDs or tags available for tag-only operation'
                }
        else:
            # Full import
            request_id, final_status = api_client.import_assets(assets, assessment_name)
            
            success = False
            if final_status:
                if isinstance(final_status, dict):
                    # Check for various success indicators
                    success = (final_status.get('status') in ['IMPORTED', 'success'] or 
                              final_status.get('message') == 'Import completed')
                else:
                    success = request_id is not None
            elif request_id is not None:
                # If we have a request_id, consider it successful
                success = True
            
            result = {
                'file': file_path,
                'success': success,
                'scanner_type': translator.__class__.__name__.replace('Translator', ''),
                'assessment_name': assessment_name,
                'assets_imported': len(assets),
                'vulnerabilities_imported': sum(len(asset.findings) for asset in assets),
                'request_id': request_id,
                'final_status': final_status,
                'import_type': import_type
            }
            
            # Add tags after import if configured
            if success and self.tag_config.apply_tags_after_import and self.tag_config.get_all_tags():
                asset_ids = [asset.asset_id for asset in assets]
                tag_success = api_client.add_tags_to_assets(asset_ids, self.tag_config.get_all_tags())
                result['tags_added'] = tag_success
            
            # Verify import if requested and successful
            if success and verify_import:
                logger.info("🔍 Verifying import...")
                verification_results = api_client.verify_import(assets, assessment_name)
                result['verification'] = verification_results
                
                # Update success status based on verification
                if verification_results['asset_success_rate'] < 100:
                    logger.warning(f"⚠️ Import verification incomplete: {verification_results['asset_success_rate']:.1f}% assets verified")
                if verification_results['vulnerability_success_rate'] < 100:
                    logger.warning(f"⚠️ Vulnerability verification incomplete: {verification_results['vulnerability_success_rate']:.1f}% vulnerabilities verified")
            
            return result
    


def main():
    """Main entry point for the multi-scanner import tool"""
    parser = argparse.ArgumentParser(
        description='Phoenix Security Multi-Scanner Import Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect scanner and process file
  python phoenix_multi_scanner_import.py --file aqua_scan.json
  
  # Specify scanner type explicitly
  python phoenix_multi_scanner_import.py --file scan_results.csv --scanner tenable
  
  # Process folder with specific scanner type
  python phoenix_multi_scanner_import.py --folder /scans/qualys --scanner qualys
  
  # Process with custom assessment name and import type
  python phoenix_multi_scanner_import.py --file scan.json --assessment "Q4 Security Scan" --import-type merge
  
  # Process with anonymization
  python phoenix_multi_scanner_import.py --file sensitive_scan.csv --anonymize
  
  # Only add tags to existing assets
  python phoenix_multi_scanner_import.py --file assets.json --just-tags
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Process a single scanner file')
    input_group.add_argument('--folder', type=str, help='Process all scanner files in folder')
    
    # Scanner options
    parser.add_argument('--scanner', type=str, 
                       choices=[
                           'anchore_grype', 'trivy', 'aqua', 'jfrog', 'blackduck', 
                           'prowler', 'tenable', 'dependency_check', 'sonarqube',
                           'cyclonedx', 'npm_audit', 'pip_audit', 'qualys', 'qualys_webapp',
                           'burp_api', 'checkmarx_osa', 'snyk_issue_api', 'universal', 'auto'
                       ],
                       default='auto', 
                       help='Scanner type. Use "auto" for automatic detection (supports 203+ scanner types). ' +
                            'Explicitly specify scanner for: Prowler (v3/v4/v5), Trivy, Grype, JFrog, BlackDuck, etc.')
    parser.add_argument('--asset-type', 
                       choices=['INFRA', 'WEB', 'CLOUD', 'CONTAINER', 'REPOSITORY', 'CODE', 'BUILD'],
                       help='Override asset type for imported assets')
    
    # Import options
    parser.add_argument('--assessment', type=str, help='Assessment name (default: auto-generated)')
    parser.add_argument('--import-type', choices=['new', 'merge', 'delta'], default='new',
                       help='Import type (default: new)')
    parser.add_argument('--anonymize', action='store_true', help='Anonymize sensitive data')
    parser.add_argument('--just-tags', action='store_true', help='Only add tags, do not import')
    parser.add_argument('--create-empty-assets', action='store_true', 
                       help='Zero out vulnerability risk while keeping vulnerability data (for testing/staging)')
    parser.add_argument('--create-inventory-assets', action='store_true', 
                       help='Create assets even if no vulnerabilities found (with zero risk placeholder for inventory)')
    parser.add_argument('--verify-import', action='store_true', 
                       help='Verify imported assets and vulnerabilities exist in Phoenix after import')
    # Configuration options
    parser.add_argument('--config', type=str, default='config_multi_scanner.ini', help='Configuration file (default: config_multi_scanner.ini)')
    parser.add_argument('--tag-file', type=str, help='Tag configuration file')
    parser.add_argument('--client-id', type=str, help='Phoenix API client ID')
    parser.add_argument('--client-secret', type=str, help='Phoenix API client secret')
    parser.add_argument('--api-url', type=str, help='Phoenix API base URL')
    
    # Processing options
    parser.add_argument('--file-types', nargs='+', choices=['json', 'csv', 'xml'], 
                       default=['json', 'csv', 'xml'], help='File types to process in folder mode')
    
    # Logging options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug mode with detailed HTTP request/response logging')
    parser.add_argument('--error-log', type=str, 
                       help='File to log errors to (in addition to main log)')
    
    args = parser.parse_args()
    
    # Setup enhanced logging
    setup_logging(
        log_level=args.log_level,
        debug_mode=args.debug,
        error_log_file=args.error_log,
        tool_name="phoenix_multi_scanner"
    )
    
    try:
        # Initialize manager
        manager = MultiScannerImportManager(args.config)
        
        # Load configuration
        phoenix_config, tag_config = manager.load_configuration()
        
        # Override with command line arguments
        if args.client_id:
            phoenix_config.client_id = args.client_id
        if args.client_secret:
            phoenix_config.client_secret = args.client_secret
        if args.api_url:
            phoenix_config.api_base_url = args.api_url
        
        # Load tag configuration
        if args.tag_file:
            tag_config = manager.load_tag_configuration(args.tag_file)
        else:
            tag_config = manager.load_tag_configuration()
        
        manager.tag_config = tag_config
        
        # Re-initialize translators with updated tag config
        manager._initialize_translators()
        
        logger.info(f"🚀 Starting Phoenix Multi-Scanner Import")
        logger.info(f"   API URL: {phoenix_config.api_base_url}")
        logger.info(f"   Scanner: {args.scanner}")
        logger.info(f"   Import Type: {args.import_type}")
        logger.info(f"   Anonymize: {args.anonymize}")
        logger.info(f"   Just Tags: {args.just_tags}")
        
        if args.file:
            # Process single file
            scanner_type = None if args.scanner == 'auto' else args.scanner
            
            result = manager.process_scanner_file(
                args.file,
                scanner_type=scanner_type,
                asset_type=args.asset_type,
                assessment_name=args.assessment,
                import_type=args.import_type,
                anonymize=args.anonymize,
                just_tags=args.just_tags,
                create_empty_assets=args.create_empty_assets,
                create_inventory_assets=args.create_inventory_assets,
                verify_import=args.verify_import
            )
            
            if result['success']:
                print(f"✅ Successfully processed {args.file}")
                print(f"   Scanner: {result['scanner_type']}")
                if not args.just_tags:
                    print(f"   Assessment: {result['assessment_name']}")
                    print(f"   Assets: {result['assets_imported']}")
                    print(f"   Vulnerabilities: {result['vulnerabilities_imported']}")
                    print(f"   Request ID: {result['request_id']}")
                    print(f"   Import Type: {result['import_type']}")
                    
                    # Show verification results if available
                    if 'verification' in result:
                        verification = result['verification']
                        print(f"   🔍 Verification Results:")
                        print(f"      Assets: {verification['verified_assets']}/{verification['total_assets']} ({verification['asset_success_rate']:.1f}%)")
                        print(f"      Vulnerabilities: {verification['verified_vulnerabilities']}/{verification['total_expected_vulnerabilities']} ({verification['vulnerability_success_rate']:.1f}%)")
                        if verification['errors']:
                            print(f"      ⚠️ Errors: {len(verification['errors'])}")
                else:
                    print(f"   Assets tagged: {result['assets_tagged']}")
                    print(f"   Tags applied: {result['tags_applied']}")
            else:
                print(f"❌ Failed to process {args.file}: {result.get('error', 'Unknown error')}")
                return 1
        
        elif args.folder:
            # Process folder
            folder_path = Path(args.folder)
            if not folder_path.exists():
                raise ValueError(f"Folder does not exist: {args.folder}")
            
            # Find all matching files
            files_to_process = []
            for file_type in args.file_types:
                pattern = f"*.{file_type}"
                files_to_process.extend(folder_path.glob(pattern))
                files_to_process.extend(folder_path.rglob(pattern))  # Recursive search
            
            if not files_to_process:
                raise ValueError(f"No {'/'.join(args.file_types)} files found in {args.folder}")
            
            logger.info(f"Found {len(files_to_process)} files to process")
            
            results = []
            successful = 0
            failed = 0
            
            for file_path in files_to_process:
                try:
                    scanner_type = None if args.scanner == 'auto' else args.scanner
                    
                    result = manager.process_scanner_file(
                        str(file_path),
                        scanner_type=scanner_type,
                        asset_type=args.asset_type,
                        assessment_name=args.assessment,
                        import_type=args.import_type,
                        anonymize=args.anonymize,
                        just_tags=args.just_tags,
                        create_empty_assets=args.create_empty_assets,
                        create_inventory_assets=args.create_inventory_assets,
                        verify_import=args.verify_import
                    )
                    
                    results.append(result)
                    
                    if result['success']:
                        successful += 1
                        print(f"   ✅ {file_path.name} ({result['scanner_type']})")
                    else:
                        failed += 1
                        print(f"   ❌ {file_path.name}: {result.get('error', 'Unknown error')}")
                    
                    # Add delay between files if configured
                    if len(files_to_process) > 1 and manager.phoenix_config.batch_delay > 0:
                        import time
                        time.sleep(manager.phoenix_config.batch_delay)
                        
                except Exception as e:
                    failed += 1
                    logger.error(f"Error processing {file_path}: {e}")
                    print(f"   ❌ {file_path.name}: {str(e)}")
            
            print(f"\n📁 Processed folder: {args.folder}")
            print(f"   Total files: {len(files_to_process)}")
            print(f"   ✅ Successful: {successful}")
            print(f"   ❌ Failed: {failed}")
            
            if failed > 0:
                return 1
        
        print("🎉 Multi-scanner import process completed!")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        error_tracker.log_error(e, "Multi-Scanner Main Process", operation="main")
        print(f"❌ Error: {e}")
        return 1
    
    finally:
        # Generate error summary and report
        if error_tracker.errors:
            error_summary = error_tracker.get_summary()
            logger.warning(f"⚠️ Multi-scanner session completed with {error_summary['total_errors']} errors")
            logger.warning(f"   Files with errors: {error_summary['files_with_errors']}")
            logger.warning(f"   Error types: {', '.join(error_summary['error_types'])}")
            
            # Save detailed error report if there were errors
            if args.debug or args.error_log:
                error_report_file = os.path.join('errors', f"multi_scanner_error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                error_tracker.save_error_report(error_report_file)
            
            print(f"\n📊 Error Summary:")
            print(f"   Total Errors: {error_summary['total_errors']}")
            print(f"   Files with Errors: {error_summary['files_with_errors']}")
            if error_summary['error_types']:
                print(f"   Error Types: {', '.join(error_summary['error_types'])}")
        else:
            logger.info("✅ Multi-scanner session completed successfully with no errors")
    
    return 1 if error_tracker.errors else 0


if __name__ == "__main__":
    exit(main())
