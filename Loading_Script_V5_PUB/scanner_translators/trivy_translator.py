#!/usr/bin/env python3
"""
Trivy Scanner Translator
=========================

Translator for Aqua Security Trivy vulnerability scanner.

Supported Formats:
- New format: dict with 'Results' array
- Legacy format: array with 'Target', 'Type', 'Vulnerabilities'
- Kubernetes format: dict with 'Resources' array

Scanner Detection:
- Checks for 'Results' in dict (new format)
- Checks for 'Resources' in dict (Kubernetes format)
- Checks for 'Target' + 'Vulnerabilities'/'Results' in array items (legacy)

Asset Type Determination:
The translator determines asset_type per-file from JSON content:
- Top-level 'Resources' (k8s scan) -> INFRA
- ArtifactType=container_image -> CONTAINER
- ArtifactType=aws_account -> CLOUD
- ArtifactType=vm -> INFRA
- ArtifactType=repository -> REPOSITORY
- ArtifactType=filesystem|cyclonedx|spdx with lang-pkgs/os-pkgs Class -> BUILD
- ArtifactType=filesystem|cyclonedx|spdx with secret Class only -> REPOSITORY
- ArtifactType=filesystem|cyclonedx|spdx without dep/secret Class -> REPOSITORY
- Legacy/ambiguous -> CLI override if provided, else CONTAINER

Finding Types Handled:
- Vulnerabilities[] -> CVE/package vulnerability findings
- Misconfigurations[] -> infrastructure misconfiguration findings
- Secrets[] -> exposed secret/credential findings (RuleID, Category, Severity)

Assets with no findings after full translation are skipped — they are never
sent to Phoenix with an empty findings array, preventing phantom assets with
no risk score. Use --create-inventory-assets to override this behaviour.

The CLI --asset-type is passed in as `asset_type_override` and is used only
as a fallback for ambiguous files (legacy format or unknown ArtifactType).
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig
from .grype_translator import build_packages_from_component

logger = logging.getLogger(__name__)


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
                # Empty scan: Trivy found no findings — Results key is absent but
                # SchemaVersion identifies this as a Trivy file unambiguously.
                if 'SchemaVersion' in file_content and (
                    'ArtifactName' in file_content or 'ArtifactType' in file_content
                ):
                    return True
            elif isinstance(file_content, list):
                # Legacy format: Root is an array with Target, Type, Vulnerabilities
                if file_content and isinstance(file_content[0], dict):
                    first_item = file_content[0]
                    if 'Target' in first_item and ('Vulnerabilities' in first_item or 'Results' in first_item):
                        return True

            return False
        except Exception as e:
            logger.debug(f"TrivyTranslator.can_handle failed: {e}")
            return False

    def parse_file(
        self,
        file_path: str,
        asset_type_override: Optional[str] = None,
    ) -> List[AssetData]:
        """Parse Trivy scan results - supports multiple formats.

        asset_type_override: CLI --asset-type value. Used as fallback only when
        the JSON content does not provide enough signal (legacy array format or
        unknown ArtifactType). Detected types win over the override.
        """
        logger.info(f"Parsing Trivy scan file: {file_path}")

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse Trivy file: {e}")
            raise

        assets = []

        # Detect format and parse accordingly
        if isinstance(data, dict):
            if 'Results' in data:
                # New format: Results[] → Vulnerabilities[] or Misconfigurations[]
                assets = self._parse_new_format(data, file_path, asset_type_override)
            elif 'Resources' in data:
                # Kubernetes format: Resources[] → Results[] → Misconfigurations[] or Vulnerabilities[]
                assets = self._parse_kubernetes_format(data, file_path, asset_type_override)
            else:
                # Empty scan: valid Trivy output with no findings (Results key absent).
                artifact_name = data.get('ArtifactName') or data.get('ArtifactPath') or Path(file_path).stem
                logger.warning(
                    "Trivy file '%s' contains no Results — scan produced zero findings for '%s'. Skipping.",
                    file_path, artifact_name,
                )
        elif isinstance(data, list):
            # Legacy format: Array of targets with Vulnerabilities[]
            assets = self._parse_legacy_format(data, file_path, asset_type_override)

        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets

    def _determine_asset_type(
        self,
        artifact_type: str,
        results: List[Dict[str, Any]],
        cli_override: Optional[str],
    ) -> Tuple[str, str]:
        """Map Trivy JSON signals to a Phoenix asset type.

        Returns (asset_type, source) where source is 'detected' (chosen from
        JSON content) or 'cli_override' (fell back to the CLI --asset-type).
        """
        artifact_type = (artifact_type or '').lower()
        if artifact_type == 'container_image':
            return 'CONTAINER', 'detected'
        if artifact_type == 'aws_account':
            return 'CLOUD', 'detected'
        if artifact_type == 'vm':
            return 'INFRA', 'detected'
        if artifact_type == 'repository':
            return 'REPOSITORY', 'detected'
        if artifact_type in ('filesystem', 'cyclonedx', 'spdx'):
            classes = {(r.get('Class') or '').lower() for r in results if isinstance(r, dict)}
            if classes & {'os-pkgs', 'lang-pkgs'}:
                return 'BUILD', 'detected'
            return 'REPOSITORY', 'detected'
        # ArtifactType missing or unknown — defer to CLI override, else default to CONTAINER
        if cli_override:
            return cli_override, 'cli_override'
        return 'CONTAINER', 'detected'

    def _build_attributes_for_type(
        self,
        asset_type: str,
        artifact_name: str,
        file_path: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Populate the validator-required attribute(s) for asset_type.

        Field names verified against ImportRestApiValidator.kt in the backend:
        CONTAINER->dockerfile, REPOSITORY->repository, BUILD->buildFile,
        SOURCE_CODE->scannerSource, INFRA->one of ip/hostname/fqdn,
        CLOUD->providerType+providerAccountId (region only when AZURE).
        """
        extra = extra or {}
        fallback_name = artifact_name or Path(file_path).stem
        base: Dict[str, Any] = {'origin': 'trivy'}
        if asset_type == 'CONTAINER':
            base['dockerfile'] = 'Dockerfile' if artifact_name and 'Dockerfile' in artifact_name else (artifact_name or 'Dockerfile')
            base['repository'] = artifact_name or fallback_name
            if extra.get('image_id'):
                base['imageDigest'] = extra['image_id']
            if extra.get('image_name'):
                base['imageName'] = extra['image_name']
        elif asset_type == 'INFRA':
            base['hostname'] = fallback_name
        elif asset_type == 'REPOSITORY':
            base['repository'] = fallback_name
        elif asset_type == 'BUILD':
            base['buildFile'] = artifact_name or Path(file_path).name
        elif asset_type == 'CLOUD':
            provider_type = (extra.get('provider_type') or 'AWS').upper()
            base['providerType'] = provider_type
            base['providerAccountId'] = extra.get('account_id') or fallback_name
            if provider_type == 'AZURE':
                base['region'] = extra.get('region') or 'eastus'
            elif extra.get('region'):
                base['region'] = extra['region']
        elif asset_type in ('SOURCE_CODE', 'CODE'):
            base['scannerSource'] = 'trivy'
        return base

    def _parse_new_format(
        self,
        data: Dict,
        file_path: str,
        asset_type_override: Optional[str] = None,
    ) -> List[AssetData]:
        """Parse new Trivy format: Results[] → Vulnerabilities[]"""
        assets = []

        # Get artifact info — fall back to first Result's Target when ArtifactName is empty
        artifact_name = data.get('ArtifactName', '') or data.get('ArtifactPath', '')
        results = data.get('Results', [])
        if not artifact_name:
            artifact_name = results[0].get('Target', '') if results and isinstance(results[0], dict) else ''
        artifact_name = artifact_name or 'unknown'
        artifact_type_raw = data.get('ArtifactType', '') or ''

        asset_type, type_source = self._determine_asset_type(
            artifact_type_raw, results, asset_type_override
        )
        asset_attributes = self._build_attributes_for_type(
            asset_type,
            artifact_name,
            file_path,
            extra={
                'image_id': data.get('Metadata', {}).get('ImageID') if isinstance(data.get('Metadata'), dict) else None,
                'image_name': data.get('ArtifactName'),
            },
        )

        asset = AssetData(
            asset_type=asset_type,
            attributes=asset_attributes,
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "trivy"},
                {"key": "artifact_type", "value": artifact_type_raw or 'unknown'},
                {"key": "asset_type_source", "value": type_source},
            ]
        )

        # Process Results[] → Vulnerabilities[], Misconfigurations[], Secrets[]
        for result in results:
            target = result.get('Target', '')

            for vuln_data in result.get('Vulnerabilities') or []:
                vuln = self._create_vulnerability(vuln_data, target)
                if vuln:
                    asset.findings.append(vuln)

            for misconfig_data in result.get('Misconfigurations') or []:
                finding = self._create_misconfiguration_finding(misconfig_data, target)
                if finding:
                    asset.findings.append(finding)

            for secret_data in result.get('Secrets') or []:
                finding = self._create_secret_finding(secret_data, target)
                if finding:
                    asset.findings.append(finding)

        processed = self.ensure_asset_has_findings(asset)
        if not processed.findings:
            logger.warning(
                "Trivy asset '%s' (%s) produced no findings after translation — skipping. "
                "Pass --create-inventory-assets to create it anyway.",
                artifact_name, asset_type,
            )
            return assets
        assets.append(processed)
        return assets

    def _parse_legacy_format(
        self,
        data: List,
        file_path: str,
        asset_type_override: Optional[str] = None,
    ) -> List[AssetData]:
        """Parse legacy Trivy format: Array → Vulnerabilities[]

        Legacy format carries no ArtifactType, so we honor the CLI override
        when provided; otherwise default to CONTAINER (preserves prior
        behavior).
        """
        assets = []

        for item in data:
            target = item.get('Target', 'unknown')
            target_type = item.get('Type', 'unknown')

            # Legacy items have no ArtifactType — pass empty string and an
            # empty results list so _determine_asset_type takes the fallback
            # branch (CLI override, else CONTAINER default).
            asset_type, type_source = self._determine_asset_type(
                '', [], asset_type_override
            )
            asset_attributes = self._build_attributes_for_type(
                asset_type, target, file_path
            )

            asset = AssetData(
                asset_type=asset_type,
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy"},
                    {"key": "target_type", "value": target_type},
                    {"key": "asset_type_source", "value": type_source},
                ]
            )

            for vuln_data in item.get('Vulnerabilities') or []:
                vuln = self._create_vulnerability(vuln_data, target)
                if vuln:
                    asset.findings.append(vuln)

            for secret_data in item.get('Secrets') or []:
                finding = self._create_secret_finding(secret_data, target)
                if finding:
                    asset.findings.append(finding)

            processed = self.ensure_asset_has_findings(asset)
            if not processed.findings:
                logger.warning(
                    "Trivy legacy asset '%s' produced no findings after translation — skipping.",
                    target,
                )
                continue
            assets.append(processed)

        return assets

    def _parse_kubernetes_format(
        self,
        data: Dict,
        file_path: str,
        asset_type_override: Optional[str] = None,
    ) -> List[AssetData]:
        """Parse Kubernetes Trivy format: Resources[] → Results[] → Misconfigurations[]

        Kubernetes scans (top-level 'Resources') are unambiguously INFRA — the
        CLI override is ignored here because the data signal is unambiguous.
        """
        assets = []

        resources = data.get('Resources', [])
        for resource in resources:
            namespace = resource.get('Namespace', 'default')
            kind = resource.get('Kind', 'unknown')
            name = resource.get('Name', 'unknown')

            hostname = f"{name}.{namespace}.k8s"
            asset_attributes = self._build_attributes_for_type(
                'INFRA', hostname, file_path
            )
            # Preserve historical attributes useful for downstream lookups.
            asset_attributes['origin'] = 'trivy-kubernetes'
            asset_attributes['repository'] = f"{namespace}/{kind}/{name}"

            asset = AssetData(
                asset_type='INFRA',
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy"},
                    {"key": "kubernetes_namespace", "value": namespace},
                    {"key": "kubernetes_kind", "value": kind},
                    {"key": "asset_type_source", "value": "detected"},
                ]
            )

            for result in resource.get('Results') or []:
                target = result.get('Target', '')

                for misconfig_data in result.get('Misconfigurations') or []:
                    finding = self._create_misconfiguration_finding(misconfig_data, target)
                    if finding:
                        asset.findings.append(finding)

                for vuln_data in result.get('Vulnerabilities') or []:
                    vuln = self._create_vulnerability(vuln_data, target)
                    if vuln:
                        asset.findings.append(vuln)

                for secret_data in result.get('Secrets') or []:
                    finding = self._create_secret_finding(secret_data, target)
                    if finding:
                        asset.findings.append(finding)

            processed = self.ensure_asset_has_findings(asset)
            if not processed.findings:
                logger.warning(
                    "Trivy k8s asset '%s' (%s/%s) produced no findings — skipping.",
                    name, namespace, kind,
                )
                continue
            assets.append(processed)

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

        # Get dates — omit blank strings; Phoenix BE rejects publishedDateTime=""
        published_date_raw = vuln_data.get('PublishedDate')
        last_modified_date = vuln_data.get('LastModifiedDate', '')

        published_date = None
        if published_date_raw and str(published_date_raw).strip():
            try:
                dt = datetime.fromisoformat(str(published_date_raw).replace('Z', '+00:00'))
                published_date = dt.strftime("%Y-%m-%dT%H:%M:%S")
            except Exception:
                published_date = None

        # Get CWE IDs
        cwe_ids = vuln_data.get('CweIDs', [])
        cwes = []
        for cwe_id in cwe_ids:
            cwe_text = str(cwe_id).strip()
            if not cwe_text:
                continue
            if cwe_text.upper().startswith('CWE-'):
                cwes.append(cwe_text.upper())
            else:
                cwes.append(f"CWE-{cwe_text}")

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
            reference_ids=[vuln_id] if vuln_id else [],
            cwes=cwes,
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

        finding = vulnerability.__dict__
        package_source = {"name": pkg_name, "version": installed_version}
        cpe = vuln_data.get("CPE")
        if isinstance(cpe, str) and cpe.strip():
            package_source["cpe"] = cpe.strip()
        packages = build_packages_from_component(package_source)
        if packages:
            finding["packages"] = packages
        return finding

    def _create_secret_finding(self, secret_data: Dict, target: str) -> Optional[Dict]:
        """Create a finding from a Trivy Secrets[] entry.

        Trivy secret fields:
          RuleID   - machine-readable rule identifier (e.g. "private-key")
          Category - broad category (e.g. "AsymmetricPrivateKey")
          Severity - HIGH / MEDIUM / LOW / CRITICAL
          Title    - human-readable label
          StartLine / EndLine - line range in the file
          Match    - redacted matched text (already masked by Trivy)
          Offset   - byte offset in the file
        """
        rule_id = secret_data.get('RuleID', '')
        if not rule_id:
            return None

        severity = secret_data.get('Severity', 'HIGH')
        title = secret_data.get('Title', rule_id)
        category = secret_data.get('Category', '')
        start_line = secret_data.get('StartLine')
        end_line = secret_data.get('EndLine')

        if start_line is not None and end_line is not None:
            location = f"{target}:{start_line}-{end_line}"
        else:
            location = target

        description = (
            f"{title}. "
            f"A secret of category '{category}' was detected in '{target}'. "
            "Exposed secrets must be rotated immediately — simply removing them "
            "from the current commit is insufficient if the repository history "
            "is accessible."
        )
        remedy = (
            "1. Immediately revoke/rotate the exposed credential. "
            "2. Remove the secret from all branches and rewrite git history "
            "(git filter-repo or BFG Repo Cleaner). "
            "3. Audit access logs for the exposed credential. "
            "4. Use a secrets manager or environment variables for future credentials."
        )

        finding = VulnerabilityData(
            name=f"SECRET-{rule_id}",
            description=description,
            remedy=remedy,
            severity=self.normalize_severity(severity),
            location=location,
            reference_ids=[],
            details={
                'rule_id': rule_id,
                'category': category,
                'title': title,
                'target': target,
                'start_line': start_line,
                'end_line': end_line,
                'offset': secret_data.get('Offset'),
                'finding_type': 'secret',
            }
        )
        return finding.__dict__

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


__all__ = ['TrivyTranslator']