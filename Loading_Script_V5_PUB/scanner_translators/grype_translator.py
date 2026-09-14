#!/usr/bin/env python3
"""
Anchore Grype Scanner Translator
=================================

Translator for Anchore Grype container vulnerability scanner.

Supported Formats:
- JSON output from Grype scanner

Scanner Detection:
- Looks for 'descriptor.name' == 'grype'
- Checks for 'matches' array with vulnerability/artifact structure

Asset Type: CONTAINER

Tagging / Attributes:
- org.opencontainers.image.base.digest -> asset_attributes['imageDigest']
- org.opencontainers.image.base.name   -> asset_attributes['imageName']
- All other labels -> Phoenix asset tags (verbatim key/value).
- Missing / null / empty labels are tolerated; the translator never crashes.
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from finding_reference_normalizer import (
    _dedupe_preserve_order,
    extract_cwes_from_text,
    extract_vulnerability_ids_from_text,
    extract_vulnerability_ids_from_urls,
    is_cwe_reference,
    normalize_cwe_list,
)
from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def build_packages_from_component(component_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build Phoenix finding.packages from a component or Grype artifact dict."""
    name = (component_data.get("name") or "").strip()
    version = (component_data.get("version") or "").strip()
    if not name or not version:
        return []

    pkg: Dict[str, str] = {"name": name, "version": version}

    cpe = component_data.get("cpe")
    if isinstance(cpe, str) and cpe.strip():
        pkg["cpe"] = cpe.strip()
    else:
        cpes = component_data.get("cpes") or []
        if cpes:
            first = cpes[0]
            if isinstance(first, str) and first.strip():
                pkg["cpe"] = first.strip()

    return [pkg]


def build_packages_from_artifact(artifact_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build Phoenix finding.packages from a Grype match artifact."""
    return build_packages_from_component(artifact_data)


def collect_grype_reference_ids(vuln_data: Dict[str, Any], match: Dict[str, Any]) -> List[str]:
    """Collect CVE/GHSA and related vulnerability IDs for Phoenix referenceIds."""
    refs: List[str] = []

    def add_ref(value: Any) -> None:
        text = str(value or "").strip()
        if not text or is_cwe_reference(text) or text in refs:
            return
        refs.append(text)

    add_ref(vuln_data.get("id", ""))

    for rel in match.get("relatedVulnerabilities", []) or []:
        if not isinstance(rel, dict):
            continue
        add_ref(rel.get("id", ""))
        for vid in extract_vulnerability_ids_from_urls(rel.get("urls", [])):
            add_ref(vid)
        for vid in extract_vulnerability_ids_from_text(rel.get("description", "")):
            add_ref(vid)

    for vid in extract_vulnerability_ids_from_urls(vuln_data.get("urls", [])):
        add_ref(vid)

    for adv in vuln_data.get("advisories", []) or []:
        if isinstance(adv, dict):
            add_ref(adv.get("id", ""))
            for vid in extract_vulnerability_ids_from_urls([adv.get("url", "")]):
                add_ref(vid)
        else:
            for vid in extract_vulnerability_ids_from_text(str(adv)):
                add_ref(vid)

    for vid in extract_vulnerability_ids_from_text(vuln_data.get("description", "")):
        add_ref(vid)

    return _dedupe_preserve_order(refs)


def collect_grype_cwes(vuln_data: Dict[str, Any], match: Dict[str, Any]) -> List[str]:
    """Collect normalized CWE identifiers for Phoenix cwes field."""
    cwes: List[str] = []

    def collect_from_record(record: Dict[str, Any]) -> None:
        for field in ("cweIDs", "cweIds", "cwes"):
            cwes.extend(normalize_cwe_list(record.get(field)))
        cwes.extend(extract_cwes_from_text(record.get("description", "")))

    collect_from_record(vuln_data)
    for rel in match.get("relatedVulnerabilities", []) or []:
        if isinstance(rel, dict):
            collect_from_record(rel)

    return _dedupe_preserve_order(cwes)


class GrypeTranslator(ScannerTranslator):
    """Translator for Anchore Grype scanner results"""

    def __init__(self, scanner_config: ScannerConfig, tag_config, create_empty_assets: bool = False,
                 create_inventory_assets: bool = False):
        super().__init__(scanner_config, tag_config, create_empty_assets, create_inventory_assets)
        self.label_value_transforms: Optional[Dict[str, Callable[[str], str]]] = None
    
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
        except Exception as e:
            logger.debug(f"GrypeTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Grype scan results"""
        logger.info(f"Parsing Anchore Grype scan file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse Grype file: {e}")
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

        label_attributes, label_tags = self.promote_oci_labels(
            target_info,
            label_value_transforms=self.label_value_transforms,
        )

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

            reference_ids = collect_grype_reference_ids(vuln_data, match)
            cwes = collect_grype_cwes(vuln_data, match)

            # Create vulnerability
            vulnerability = VulnerabilityData(
                name=vuln_id,
                description=vuln_data.get('description', '') or f"Vulnerability {vuln_id} found in {artifact_data.get('name', 'package')}",
                remedy=f"Update {artifact_data.get('name', 'package')} to fixed version: {', '.join(fix_versions)}" if fix_versions else "No fix available",
                severity=self.normalize_severity(severity),
                location=f"{artifact_data.get('name', '')}@{artifact_data.get('version', '')}",
                reference_ids=reference_ids,
                cwes=cwes,
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

            finding = vulnerability.__dict__
            packages = build_packages_from_artifact(artifact_data)
            if packages:
                finding["packages"] = packages
            asset.findings.append(finding)
        
        assets.append(self.ensure_asset_has_findings(asset))
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


__all__ = [
    'GrypeTranslator',
    'build_packages_from_artifact',
    'build_packages_from_component',
    'collect_grype_reference_ids',
    'collect_grype_cwes',
]
