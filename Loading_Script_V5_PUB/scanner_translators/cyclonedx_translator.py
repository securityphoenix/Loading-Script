#!/usr/bin/env python3
"""
CycloneDX SBOM Translator
==========================

Translator for CycloneDX SBOM (Software Bill of Materials) standard.

Supported Formats:
- JSON format with 'bomFormat': 'CycloneDX'
- XML format with cyclonedx namespace

Scanner Detection:
- JSON: 'bomFormat' == 'CycloneDX' OR ('specVersion' AND 'components')
- XML: 'cyclonedx' in root tag or xmlns attribute

Asset Type: BUILD (default) or CONTAINER (when --asset-type CONTAINER is passed)

Asset Type Behaviour:
- BUILD     : one asset per vulnerable component; 'buildFile' = purl or name@version;
              project name from metadata.component.name or filename stem.
- CONTAINER : one asset per scan target; 'dockerfile' + 'repository' from
              metadata.component.name, falling back to filename stem.
"""

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from finding_reference_normalizer import (
    _dedupe_preserve_order,
    _split_cwes_from_refs,
    extract_vulnerability_ids_from_text,
    extract_vulnerability_ids_from_urls,
    normalize_cwe_list,
)
from .base_translator import ScannerTranslator, ScannerConfig
from .grype_translator import build_packages_from_component

logger = logging.getLogger(__name__)


def get_tags_safely(tag_config):
    """Safely get tags from tag_config"""
    if not tag_config:
        return []
    if hasattr(tag_config, 'get_all_tags'):
        return tag_config.get_all_tags()
    return []


class CycloneDXTranslator(ScannerTranslator):
    """Translator for CycloneDX SBOM format (Software Bill of Materials)"""

    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect CycloneDX JSON/XML format"""
        if file_path.lower().endswith('.json'):
            try:
                if file_content is None:
                    with open(file_path, 'r') as f:
                        file_content = json.load(f)

                if isinstance(file_content, dict):
                    if file_content.get('bomFormat') == 'CycloneDX' or \
                       'specVersion' in file_content and 'components' in file_content:
                        return True

                return False
            except Exception as e:
                logger.debug(f"CycloneDXTranslator.can_handle failed for {file_path}: {e}")
                return False

        elif file_path.lower().endswith('.xml'):
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()

                if 'cyclonedx' in root.tag.lower() or \
                   any('cyclonedx' in str(ns).lower() for ns in (root.attrib.get('xmlns', ''),)):
                    return True

                return False
            except Exception as e:
                logger.debug(f"CycloneDXTranslator.can_handle failed for {file_path}: {e}")
                return False

        return False

    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse CycloneDX SBOM file.

        When self.asset_type == 'CONTAINER' (set by --asset-type CONTAINER), produces
        one CONTAINER asset per scan target. Otherwise produces one BUILD asset per
        vulnerable component (default behaviour).
        """
        logger.info(f"Parsing CycloneDX SBOM file: {file_path}")

        forced_type = getattr(self, 'asset_type', None)

        try:
            if file_path.lower().endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                if forced_type == 'CONTAINER':
                    assets = self._parse_json_as_container(data, file_path)
                else:
                    assets = self._parse_json(data, file_path)
            elif file_path.lower().endswith('.xml'):
                tree = ET.parse(file_path)
                root = tree.getroot()
                assets = self._parse_xml(root)
            else:
                assets = []

            logger.info(f"Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities from CycloneDX SBOM")
            return assets

        except Exception as e:
            logger.error(f"Error parsing CycloneDX: {e}")
            import traceback
            traceback.print_exc()
            return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_name_from_file(file_path: str) -> str:
        """Strip known scanner suffixes from filename to produce a clean asset name."""
        stem = Path(file_path).stem
        for suffix in ('-grype', '-trivy', '-anchore', '-snyk', '-cyclonedx'):
            if stem.lower().endswith(suffix):
                stem = stem[:len(stem) - len(suffix)]
                break
        return stem

    @staticmethod
    def _format_component_location(name: str, version: str = "") -> str:
        """Phoenix subcomponent location: always component@version (Grype-aligned)."""
        return f"{(name or '').strip()}@{(version or '').strip()}"

    # ------------------------------------------------------------------
    # CONTAINER mode: one asset per scan target
    # ------------------------------------------------------------------

    def _parse_json_as_container(self, data: Dict, file_path: str) -> List[AssetData]:
        """Parse CycloneDX JSON as a single CONTAINER asset.

        All vulnerabilities in the SBOM are attached to one asset whose name
        comes from metadata.component.name, falling back to the filename stem.
        """
        metadata = data.get('metadata', {})
        override_name = getattr(self, 'asset_name_override', None)
        target_name = (override_name or metadata.get('component', {}).get('name', '')).strip()
        if not target_name:
            target_name = self._resolve_name_from_file(file_path)

        logger.info(f"CycloneDX CONTAINER mode - target: {target_name}")

        # Build component lookup for resolving 'affects' refs
        comp_index: Dict[str, dict] = {}
        for comp in data.get('components', []):
            ref = comp.get('bom-ref', '')
            if ref:
                comp_index[ref] = comp
            purl = comp.get('purl', '')
            if purl and purl not in comp_index:
                comp_index[purl] = comp

        asset = AssetData(
            asset_type='CONTAINER',
            attributes={
                'dockerfile': 'Dockerfile',
                'repository': target_name,
                'origin': 'cyclonedx',
            },
            tags=get_tags_safely(self.tag_config) + [
                {"key": "scanner", "value": "cyclonedx"},
                {"key": "sbom-type", "value": "cyclonedx"},
            ]
        )

        for vuln in data.get('vulnerabilities', []):
            comp: dict = {}
            affects = vuln.get('affects', [])
            if affects:
                ref = affects[0].get('ref', '')
                comp = comp_index.get(ref, {})
                if not comp:
                    base_ref = ref.split('?')[0]
                    for k, v in comp_index.items():
                        if k.split('?')[0] == base_ref:
                            comp = v
                            break

            comp_name = comp.get('name', target_name) if comp else target_name
            comp_version = comp.get('version', '') if comp else ''
            vuln_data = self._parse_vulnerability_json(vuln, comp_name, comp_version)
            if vuln_data:
                if comp:
                    vuln_data.setdefault('details', {})
                    vuln_data['details']['package_name'] = comp.get('name', '')
                    vuln_data['details']['package_version'] = comp.get('version', '')
                    vuln_data['details']['package_purl'] = comp.get('purl', '')
                self._attach_component_packages(vuln_data, comp)
                packages = vuln_data.pop("packages", None)
                vuln_obj = VulnerabilityData(**vuln_data)
                finding = vuln_obj.__dict__
                if packages:
                    finding["packages"] = packages
                asset.findings.append(finding)

        return [self.ensure_asset_has_findings(asset)]

    # ------------------------------------------------------------------
    # BUILD mode (default): one asset per vulnerable component
    # ------------------------------------------------------------------

    def _parse_json(self, data: Dict, file_path: str = '') -> List[AssetData]:
        """Parse CycloneDX JSON as BUILD assets (one per vulnerable component)."""
        assets = []

        metadata = data.get('metadata', {})
        project_name = (
            metadata.get('component', {}).get('name', '').strip()
            or (self._resolve_name_from_file(file_path) if file_path else 'Application')
        )

        components = data.get('components', [])
        vulnerabilities = data.get('vulnerabilities', [])

        # Group vulnerabilities by component bom-ref
        vuln_by_component: Dict[str, list] = {}
        for vuln in vulnerabilities:
            for affect in vuln.get('affects', []):
                ref = affect.get('ref', '')
                if ref:
                    vuln_by_component.setdefault(ref, []).append(vuln)

        for component in components:
            bom_ref = component.get('bom-ref', '')
            vulns = vuln_by_component.get(bom_ref, [])
            if not vulns:
                continue

            comp_name = component.get('name', 'unknown')
            comp_version = component.get('version', '')
            comp_type = component.get('type', 'library')
            purl = component.get('purl', '')

            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': purl if purl else f"{comp_name}@{comp_version}",
                    'origin': 'cyclonedx',
                    'component': comp_name,
                    'version': comp_version,
                    'component_type': comp_type,
                    'application': project_name,
                },
                tags=get_tags_safely(self.tag_config) + [
                    {"key": "scanner", "value": "cyclonedx"},
                    {"key": "sbom-type", "value": "cyclonedx"},
                ]
            )

            for vuln in vulns:
                vuln_data = self._parse_vulnerability_json(vuln, comp_name, comp_version)
                if vuln_data:
                    self._attach_component_packages(vuln_data, component)
                    packages = vuln_data.pop("packages", None)
                    vuln_obj = VulnerabilityData(**vuln_data)
                    finding = vuln_obj.__dict__
                    if packages:
                        finding["packages"] = packages
                    asset.findings.append(finding)

            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))

        return assets

    @staticmethod
    def _attach_component_packages(vuln_data: Dict, component: Dict) -> None:
        packages = build_packages_from_component(component)
        if packages:
            vuln_data["packages"] = packages

    @staticmethod
    def _collect_cyclonedx_reference_ids(vuln: Dict) -> List[str]:
        refs: List[str] = []
        vuln_id = (vuln.get("id") or "").strip()
        if vuln_id:
            refs.append(vuln_id)

        for ref in vuln.get("references", []) or []:
            if isinstance(ref, dict):
                ref_id = (ref.get("id") or "").strip()
                if ref_id:
                    refs.append(ref_id)

        advisory_urls = []
        for adv in vuln.get("advisories", []) or []:
            if isinstance(adv, dict):
                if adv.get("url"):
                    advisory_urls.append(adv["url"])
                if adv.get("id"):
                    refs.append(str(adv["id"]).strip())
            elif adv:
                advisory_urls.append(str(adv))
        refs.extend(extract_vulnerability_ids_from_urls(advisory_urls))

        for alias in vuln.get("aliases", []) or []:
            text = str(alias).strip()
            if text:
                refs.append(text)
        refs.extend(extract_vulnerability_ids_from_text(vuln.get("description", "")))

        return _dedupe_preserve_order(refs)

    def _parse_vulnerability_json(self, vuln: Dict, component_name: str, component_version: str = "") -> Optional[Dict]:
        """Parse a CycloneDX vulnerability"""
        try:
            vuln_id = vuln.get('id', 'UNKNOWN')
            if not vuln_id:
                return None

            location = self._format_component_location(component_name, component_version)
            description = vuln.get('description', f"Vulnerability {vuln_id} in {component_name}")
            if len(description) > 500:
                description = description[:497] + "..."

            ratings = vuln.get('ratings', [])
            severity = 'Medium'
            cvss_score = None

            for rating in ratings:
                if 'severity' in rating:
                    severity = self._normalize_cyclone_severity(rating['severity'])
                if 'score' in rating:
                    try:
                        cvss_score = float(rating['score'])
                    except Exception:
                        pass

            recommendation = vuln.get('recommendation', "See SBOM for remediation details")
            if len(recommendation) > 500:
                recommendation = recommendation[:497] + "..."

            cwes = normalize_cwe_list(vuln.get("cwes"))
            reference_ids = self._collect_cyclonedx_reference_ids(vuln)
            clean_refs, extracted_cwes = _split_cwes_from_refs(reference_ids)
            cwes = _dedupe_preserve_order(cwes + extracted_cwes)

            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': recommendation,
                'severity': severity,
                'location': location,
                'reference_ids': clean_refs,
                'cwes': cwes,
            }

            if cvss_score:
                vuln_dict['details'] = {'cvss_score': cvss_score}

            return vuln_dict

        except Exception as e:
            logger.debug(f"Error parsing CycloneDX vulnerability: {e}")
            return None

    def _parse_xml(self, root: ET.Element) -> List[AssetData]:
        """Parse CycloneDX XML format"""
        assets = []

        ns = {'cdx': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

        components = {}
        components_elem = root.find('cdx:components', ns) if ns else root.find('components')
        if components_elem is not None:
            for comp in components_elem.findall('cdx:component', ns) if ns else components_elem.findall('component'):
                bom_ref = comp.get('bom-ref')
                name = comp.findtext('cdx:name', default='', namespaces=ns) if ns else comp.findtext('name', default='')
                version = comp.findtext('cdx:version', default='', namespaces=ns) if ns else comp.findtext('version', default='')
                purl = comp.findtext('cdx:purl', default='', namespaces=ns) if ns else comp.findtext('purl', default='')

                if name:
                    key = bom_ref if bom_ref else f"{name}@{version}" if version else name
                    components[key] = {'name': name, 'version': version, 'purl': purl}

        vulns_elem = root.find('cdx:vulnerabilities', ns) if ns else root.find('vulnerabilities')
        if vulns_elem is None:
            logger.info("No vulnerabilities section found in CycloneDX XML")
            return assets

        comp_vulns: Dict[str, dict] = {}
        for vuln_elem in vulns_elem.findall('cdx:vulnerability', ns) if ns else vulns_elem.findall('vulnerability'):
            vuln_id = vuln_elem.findtext('cdx:id', default='UNKNOWN', namespaces=ns) if ns else vuln_elem.findtext('id', default='UNKNOWN')
            description = vuln_elem.findtext('cdx:description', default='', namespaces=ns) if ns else vuln_elem.findtext('description', default='')
            recommendation = vuln_elem.findtext('cdx:recommendation', default='', namespaces=ns) if ns else vuln_elem.findtext('recommendation', default='')

            severity = 'Medium'
            cvss_score = None
            ratings_elem = vuln_elem.find('cdx:ratings', ns) if ns else vuln_elem.find('ratings')
            if ratings_elem is not None:
                rating_elem = ratings_elem.find('cdx:rating', ns) if ns else ratings_elem.find('rating')
                if rating_elem is not None:
                    sev_text = rating_elem.findtext('cdx:severity', default='', namespaces=ns) if ns else rating_elem.findtext('severity', default='')
                    if sev_text:
                        severity = self._normalize_cyclone_severity(sev_text)
                    score_text = rating_elem.findtext('cdx:score', default='', namespaces=ns) if ns else rating_elem.findtext('score', default='')
                    if score_text:
                        try:
                            cvss_score = float(score_text)
                        except Exception:
                            pass

            cwes = []
            cwes_elem = vuln_elem.find('cdx:cwes', ns) if ns else vuln_elem.find('cwes')
            if cwes_elem is not None:
                for cwe_elem in cwes_elem.findall('cdx:cwe', ns) if ns else cwes_elem.findall('cwe'):
                    if cwe_elem.text:
                        cwes.append(f"CWE-{cwe_elem.text}")

            affects_elem = vuln_elem.find('cdx:affects', ns) if ns else vuln_elem.find('affects')
            if affects_elem is not None:
                for target_elem in affects_elem.findall('cdx:target', ns) if ns else affects_elem.findall('target'):
                    ref = target_elem.findtext('cdx:ref', default='', namespaces=ns) if ns else target_elem.findtext('ref', default='')
                    if ref and ref in components:
                        comp_info = components[ref]
                        comp_name = f"{comp_info['name']}@{comp_info['version']}" if comp_info['version'] else comp_info['name']

                        if comp_name not in comp_vulns:
                            comp_vulns[comp_name] = {'component': comp_info, 'vulns': []}

                        vuln_dict: Dict = {
                            'name': vuln_id,
                            'description': description[:500] if description else f"Vulnerability {vuln_id}",
                            'remedy': recommendation[:500] if recommendation else "See SBOM for remediation",
                            'severity': severity,
                            'location': comp_name,
                            'reference_ids': [vuln_id]
                        }

                        if cwes:
                            vuln_dict['cwes'] = cwes
                        if cvss_score:
                            vuln_dict['details'] = {'cvss_score': cvss_score}

                        comp_vulns[comp_name]['vulns'].append(vuln_dict)

        for comp_name, entry in comp_vulns.items():
            comp_info = entry['component']

            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': comp_info.get('purl', comp_name),
                    'origin': 'cyclonedx',
                    'component': comp_info['name'],
                    'version': comp_info.get('version', '')
                },
                tags=get_tags_safely(self.tag_config) + [
                    {"key": "scanner", "value": "cyclonedx"},
                    {"key": "sbom-type", "value": "cyclonedx"}
                ]
            )

            for vuln_data in entry['vulns']:
                vuln_obj = VulnerabilityData(**vuln_data)
                asset.findings.append(vuln_obj.__dict__)

            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))

        logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities from CycloneDX XML")
        return assets

    def _normalize_cyclone_severity(self, severity: str) -> str:
        """Normalize CycloneDX severity to Phoenix format"""
        severity_lower = severity.lower()

        if severity_lower in ['critical']:
            return 'Critical'
        elif severity_lower in ['high']:
            return 'High'
        elif severity_lower in ['medium', 'moderate']:
            return 'Medium'
        elif severity_lower in ['low']:
            return 'Low'
        else:
            return 'Info'


__all__ = ['CycloneDXTranslator']
