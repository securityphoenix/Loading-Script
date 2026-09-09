#!/usr/bin/env python3
"""
Phoenix Security Scanner Field Mapping System
==============================================

This module provides a comprehensive field mapping system for converting
scanner outputs to Phoenix Security format. It supports YAML-based configuration
for easy extension and maintenance.

Author: Senior Developer
Version: 2.0.0
Date: September 2025
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
import csv
from datetime import datetime
import logging

from finding_reference_normalizer import normalize_finding_reference_fields

logger = logging.getLogger(__name__)


class FieldMapper:
    """Handles field mapping between scanner formats and Phoenix Security format with hot-reload support"""
    
    def __init__(self, config_file: str = "scanner_field_mappings.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self.phoenix_fields = self.config.get('phoenix_fields', {})
        self.scanners = self.config.get('scanners', {})
        self.default_severity_mappings = self.config.get('default_severity_mappings', {})
        self._last_modified = self._get_config_modified_time()
        self._validation_cache = {}  # Cache for validation results
    
    def _load_config(self) -> Dict[str, Any]:
        """Load scanner field mapping configuration"""
        try:
            config_path = Path(self.config_file)
            if not config_path.exists():
                logger.warning(f"Config file {self.config_file} not found, using defaults")
                return {}
            
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config file {self.config_file}: {e}")
            return {}
    
    def _get_config_modified_time(self) -> float:
        """Get the last modified time of the config file"""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                return config_path.stat().st_mtime
        except Exception:
            pass
        return 0.0
    
    def check_and_reload_config(self) -> bool:
        """Check if config file has been modified and reload if necessary"""
        try:
            current_modified = self._get_config_modified_time()
            if current_modified > self._last_modified:
                logger.info(f"Config file {self.config_file} has been modified, reloading...")
                
                # Validate new config before applying
                new_config = self._load_config()
                if self._validate_config(new_config):
                    self.config = new_config
                    self.phoenix_fields = self.config.get('phoenix_fields', {})
                    self.scanners = self.config.get('scanners', {})
                    self.default_severity_mappings = self.config.get('default_severity_mappings', {})
                    self._last_modified = current_modified
                    self._validation_cache.clear()  # Clear validation cache
                    logger.info("Configuration reloaded successfully")
                    return True
                else:
                    logger.error("New configuration validation failed, keeping current config")
                    return False
        except Exception as e:
            logger.error(f"Error checking/reloading config: {e}")
        return False
    
    def _validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration structure and content"""
        try:
            # Check basic structure
            if not isinstance(config, dict):
                logger.error("Config must be a dictionary")
                return False
            
            # Validate scanners section
            scanners = config.get('scanners', {})
            if not isinstance(scanners, dict):
                logger.error("'scanners' section must be a dictionary")
                return False
            
            # Validate each scanner configuration
            for scanner_name, scanner_config in scanners.items():
                if not self._validate_scanner_config(scanner_name, scanner_config):
                    return False
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Error validating config: {e}")
            return False
    
    def _validate_scanner_config(self, scanner_name: str, scanner_config: Dict[str, Any]) -> bool:
        """Validate individual scanner configuration"""
        try:
            if not isinstance(scanner_config, dict):
                logger.error(f"Scanner '{scanner_name}' config must be a dictionary")
                return False
            
            formats = scanner_config.get('formats', [])
            if not isinstance(formats, list):
                logger.error(f"Scanner '{scanner_name}' formats must be a list")
                return False
            
            for i, format_config in enumerate(formats):
                if not self._validate_format_config(scanner_name, i, format_config):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating scanner '{scanner_name}' config: {e}")
            return False
    
    def _validate_format_config(self, scanner_name: str, format_index: int, format_config: Dict[str, Any]) -> bool:
        """Validate individual format configuration"""
        try:
            required_fields = ['name', 'format_type', 'asset_type', 'field_mappings']
            
            for field in required_fields:
                if field not in format_config:
                    logger.error(f"Scanner '{scanner_name}' format {format_index} missing required field '{field}'")
                    return False
            
            # Validate format_type
            valid_formats = ['json', 'xml', 'csv']
            if format_config['format_type'] not in valid_formats:
                logger.error(f"Scanner '{scanner_name}' format {format_index} has invalid format_type")
                return False
            
            # Validate asset_type
            valid_asset_types = ['INFRA', 'WEB', 'CLOUD', 'CONTAINER', 'REPOSITORY', 'CODE', 'BUILD']
            if format_config['asset_type'] not in valid_asset_types:
                logger.error(f"Scanner '{scanner_name}' format {format_index} has invalid asset_type")
                return False
            
            # Validate field_mappings structure
            field_mappings = format_config['field_mappings']
            if not isinstance(field_mappings, dict):
                logger.error(f"Scanner '{scanner_name}' format {format_index} field_mappings must be a dictionary")
                return False
            
            if 'asset' not in field_mappings or 'vulnerability' not in field_mappings:
                logger.error(f"Scanner '{scanner_name}' format {format_index} field_mappings must have 'asset' and 'vulnerability' sections")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating format config for scanner '{scanner_name}': {e}")
            return False
    
    def reload_config(self) -> bool:
        """Force reload configuration from file"""
        try:
            new_config = self._load_config()
            if self._validate_config(new_config):
                self.config = new_config
                self.phoenix_fields = self.config.get('phoenix_fields', {})
                self.scanners = self.config.get('scanners', {})
                self.default_severity_mappings = self.config.get('default_severity_mappings', {})
                self._last_modified = self._get_config_modified_time()
                self._validation_cache.clear()
                logger.info("Configuration force-reloaded successfully")
                return True
            else:
                logger.error("Configuration validation failed during force reload")
                return False
        except Exception as e:
            logger.error(f"Error force-reloading config: {e}")
            return False
    
    def get_nested_value(self, data: Dict[str, Any], path: str, default: Any = None) -> Any:
        """Get nested value from dictionary using dot notation path"""
        if not path:
            return default
        
        keys = path.split('.')
        current = data
        
        try:
            for key in keys:
                # Handle array notation like "matches[0]" or "matches[]"
                if '[' in key and ']' in key:
                    array_key, index_part = key.split('[', 1)
                    index_part = index_part.rstrip(']')
                    
                    if array_key:
                        current = current[array_key]
                    
                    if index_part == '':
                        # Return the whole array for "matches[]" notation
                        return current if isinstance(current, list) else default
                    elif index_part.isdigit():
                        # Specific index like "matches[0]"
                        index = int(index_part)
                        if isinstance(current, list) and 0 <= index < len(current):
                            current = current[index]
                        else:
                            return default
                    else:
                        return default
                else:
                    current = current[key]
            
            return current
        except (KeyError, TypeError, IndexError):
            return default
    
    def extract_array_values(self, data: Dict[str, Any], path: str) -> List[Any]:
        """Extract values from array using path notation - supports multi-level nested arrays"""
        if not path or '[]' not in path:
            value = self.get_nested_value(data, path)
            return [value] if value is not None else []
        
        # Handle multi-level array paths like "Results[].Vulnerabilities[].VulnerabilityID"
        parts = path.split('[]', 1)
        array_path = parts[0]
        remaining_path = parts[1].lstrip('.') if len(parts) > 1 else ''
        
        array_data = self.get_nested_value(data, array_path)
        if not isinstance(array_data, list):
            return []
        
        results = []
        for item in array_data:
            if remaining_path:
                # Check if there's another array notation in the remaining path
                if '[]' in remaining_path:
                    # Recursively handle nested arrays (e.g., "Vulnerabilities[].VulnerabilityID")
                    nested_results = self.extract_array_values(item, remaining_path)
                    results.extend(nested_results)
                else:
                    # Simple nested path (e.g., "vulnerability.id")
                    value = self.get_nested_value(item, remaining_path)
                    if value is not None:
                        results.append(value)
            else:
                results.append(item)
        
        return results
    
    def map_severity(self, severity: Any, severity_mapping: Dict[str, str]) -> str:
        """Map scanner severity to Phoenix severity (1.0-10.0)"""
        if not severity:
            return "5.0"
        
        severity_str = str(severity).strip()
        
        # Try direct mapping first
        if severity_str in severity_mapping:
            return severity_mapping[severity_str]
        
        # Try case-insensitive mapping
        severity_lower = severity_str.lower()
        for key, value in severity_mapping.items():
            if key.lower() == severity_lower:
                return value
        
        # Try numeric conversion for CVSS scores
        try:
            score = float(severity_str)
            if 0 <= score <= 10:
                return str(score)
            elif score > 10:
                return "10.0"
            else:
                return "1.0"
        except ValueError:
            pass
        
        # Default mapping
        return "5.0"
    
    def extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        if not text:
            return []
        
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(cve_pattern, str(text), re.IGNORECASE)
    
    def extract_cwes(self, text: str) -> List[str]:
        """Extract CWE IDs from text"""
        if not text:
            return []
        
        cwe_pattern = r'CWE-\d+'
        cwes = re.findall(cwe_pattern, str(text), re.IGNORECASE)
        return [cwe.upper() for cwe in cwes]
    
    def map_asset_attributes(self, data: Dict[str, Any], field_mappings: Dict[str, str], 
                           asset_type: str) -> Dict[str, str]:
        """Map scanner data to Phoenix asset attributes"""
        attributes = {}
        
        for phoenix_field, scanner_path in field_mappings.items():
            if scanner_path.startswith('"') and scanner_path.endswith('"'):
                # Static value
                attributes[phoenix_field] = scanner_path.strip('"')
            else:
                # Dynamic value from data
                value = self.get_nested_value(data, scanner_path)
                if value is not None:
                    attributes[phoenix_field] = str(value)
        
        # Ensure required fields are present
        required_fields = self.phoenix_fields.get('asset_attributes', {}).get('required', {}).get(asset_type, [])
        
        # Handle alternative required fields (like "ip, hostname" where one is required)
        if asset_type == "INFRA":
            if not attributes.get('ip') and not attributes.get('hostname'):
                # Generate a default hostname if neither is present
                attributes['hostname'] = f"scanner-host-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        elif asset_type == "WEB":
            if not attributes.get('ip') and not attributes.get('fqdn'):
                # Generate a default FQDN if neither is present
                attributes['fqdn'] = f"scanner-web-{datetime.now().strftime('%Y%m%d%H%M%S')}.local"
        
        return attributes
    
    def _strip_array_notation(self, path: str) -> str:
        """Strip array notations from path to get the field name relative to the current context
        
        Example: 'Results[].Vulnerabilities[].VulnerabilityID' -> 'VulnerabilityID'
        """
        if '[]' not in path:
            return path
        
        # Split by '[]' and get the last part
        parts = path.split('[]')
        last_part = parts[-1].lstrip('.')
        return last_part if last_part else path
    
    def map_vulnerability(self, vuln_data: Dict[str, Any], field_mappings: Dict[str, Any], 
                         severity_mapping: Dict[str, str], global_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Map scanner vulnerability data to Phoenix vulnerability format"""
        vulnerability = {}
        
        # Map basic fields
        basic_mappings = field_mappings.get('vulnerability', {})
        for phoenix_field, scanner_path in basic_mappings.items():
            if phoenix_field == 'details':
                continue  # Handle details separately
            
            if scanner_path.startswith('"') and scanner_path.endswith('"'):
                # Static value
                vulnerability[phoenix_field] = scanner_path.strip('"')
            else:
                # Strip array notations to get relative path for current context
                relative_path = self._strip_array_notation(scanner_path)
                
                # Dynamic value - check both vuln_data and global_data
                value = self.get_nested_value(vuln_data, relative_path)
                if value is None and global_data:
                    value = self.get_nested_value(global_data, scanner_path)
                
                if value is not None:
                    if phoenix_field == 'severity':
                        vulnerability[phoenix_field] = self.map_severity(value, severity_mapping)
                    elif phoenix_field == 'reference_ids':
                        # Handle CVE extraction
                        if isinstance(value, list):
                            vulnerability[phoenix_field] = value
                        else:
                            vulnerability[phoenix_field] = self.extract_cves(str(value))
                    elif phoenix_field == 'cwes':
                        # Handle CWE extraction
                        if isinstance(value, list):
                            vulnerability[phoenix_field] = [f"CWE-{cwe}" if not str(cwe).startswith('CWE-') else str(cwe) for cwe in value]
                        else:
                            vulnerability[phoenix_field] = self.extract_cwes(str(value))
                    elif phoenix_field == 'published_date_time':
                        # Handle date formatting
                        vulnerability[phoenix_field] = self._format_date(value)
                    else:
                        vulnerability[phoenix_field] = str(value)
        
        # Map details object
        details_mappings = field_mappings.get('vulnerability', {}).get('details', {})
        if details_mappings:
            details = {}
            for detail_field, scanner_path in details_mappings.items():
                if scanner_path.startswith('"') and scanner_path.endswith('"'):
                    details[detail_field] = scanner_path.strip('"')
                else:
                    # Strip array notations for relative path
                    relative_path = self._strip_array_notation(scanner_path)
                    value = self.get_nested_value(vuln_data, relative_path)
                    if value is None and global_data:
                        value = self.get_nested_value(global_data, scanner_path)
                    
                    if value is not None:
                        details[detail_field] = value
            
            if details:
                vulnerability['details'] = details
        
        # Ensure required fields
        if 'name' not in vulnerability:
            vulnerability['name'] = "Unknown Vulnerability"
        if 'description' not in vulnerability:
            vulnerability['description'] = "No description available"
        if 'remedy' not in vulnerability:
            vulnerability['remedy'] = "No remedy provided"
        if 'severity' not in vulnerability:
            vulnerability['severity'] = "5.0"
        if 'location' not in vulnerability:
            vulnerability['location'] = "Unknown location"

        return normalize_finding_reference_fields(vulnerability)
    
    def _format_date(self, date_value: Any) -> str:
        """Format date to Phoenix format (YYYY-MM-DD HH:MM:SS)"""
        if not date_value:
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        date_str = str(date_value)
        
        # Try common date formats
        date_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ"
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
        
        # If no format matches, return current time
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ScannerFormatDetector:
    """Advanced scanner format detector with confidence scoring and multi-format support"""
    
    def __init__(self, field_mapper: FieldMapper):
        self.field_mapper = field_mapper
        self.scanners = field_mapper.scanners
        self.detection_cache = {}  # Cache for performance
        self.confidence_threshold = 0.25  # Minimum confidence for detection (lowered from 0.3 for Round 11 - ultra-aggressive)
    
    def detect_scanner_format(self, file_path: str, file_content: Any = None) -> Optional[Dict[str, Any]]:
        """Detect scanner format from file with confidence scoring"""
        try:
            # Check cache first
            cache_key = f"{file_path}_{hash(str(file_content))}"
            if cache_key in self.detection_cache:
                return self.detection_cache[cache_key]
            
            file_path_obj = Path(file_path)
            file_name = file_path_obj.name.lower()
            file_ext = file_path_obj.suffix.lower()
            
            # Score all possible formats
            format_scores = []
            
            # Try each scanner configuration
            for scanner_name, scanner_config in self.scanners.items():
                for format_config in scanner_config.get('formats', []):
                    confidence = self._calculate_format_confidence(
                        file_path, file_name, file_ext, format_config, file_content
                    )
                    if confidence > 0:
                        format_scores.append({
                            'scanner': scanner_name,
                            'format': format_config['name'],
                            'config': format_config,
                            'asset_type': format_config.get('asset_type', 'INFRA'),
                            'confidence': confidence
                        })
            
            # Sort by confidence and return the best match
            if format_scores:
                format_scores.sort(key=lambda x: x['confidence'], reverse=True)
                best_match = format_scores[0]
                
                # Only return if confidence is above threshold
                if best_match['confidence'] >= self.confidence_threshold:
                    # Cache the result
                    result = {k: v for k, v in best_match.items() if k != 'confidence'}
                    self.detection_cache[cache_key] = result
                    logger.info(f"Detected {best_match['scanner']} format with {best_match['confidence']:.2f} confidence")
                    return result
                else:
                    logger.warning(f"Best match confidence {best_match['confidence']:.2f} below threshold {self.confidence_threshold}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error detecting scanner format for {file_path}: {e}")
            return None
    
    def get_all_possible_formats(self, file_path: str, file_content: Any = None) -> List[Dict[str, Any]]:
        """Get all possible formats with confidence scores (useful for debugging)"""
        try:
            file_path_obj = Path(file_path)
            file_name = file_path_obj.name.lower()
            file_ext = file_path_obj.suffix.lower()
            
            format_scores = []
            
            for scanner_name, scanner_config in self.scanners.items():
                for format_config in scanner_config.get('formats', []):
                    confidence = self._calculate_format_confidence(
                        file_path, file_name, file_ext, format_config, file_content
                    )
                    if confidence > 0:
                        format_scores.append({
                            'scanner': scanner_name,
                            'format': format_config['name'],
                            'confidence': confidence,
                            'format_type': format_config.get('format_type', 'json')
                        })
            
            return sorted(format_scores, key=lambda x: x['confidence'], reverse=True)
            
        except Exception as e:
            logger.error(f"Error getting possible formats for {file_path}: {e}")
            return []
    
    def _calculate_format_confidence(self, file_path: str, file_name: str, file_ext: str,
                                   format_config: Dict[str, Any], file_content: Any = None) -> float:
        """Calculate confidence score for a format match"""
        confidence = 0.0
        max_confidence = 0.0
        
        try:
            # File pattern matching (30% weight)
            pattern_score = self._score_file_patterns(file_name, format_config.get('file_patterns', []))
            confidence += pattern_score * 0.3
            max_confidence += 0.3
            
            # Content-based detection (70% weight)
            content_score = self._score_content_detection(file_path, format_config, file_content)
            confidence += content_score * 0.7
            max_confidence += 0.7
            
            # Normalize confidence to 0-1 range
            return confidence / max_confidence if max_confidence > 0 else 0.0
            
        except Exception as e:
            logger.debug(f"Error calculating confidence for format {format_config.get('name', 'unknown')}: {e}")
            return 0.0
    
    def _score_file_patterns(self, file_name: str, patterns: List[str]) -> float:
        """Score file name against patterns"""
        if not patterns:
            return 0.0
        
        for pattern in patterns:
            pattern_lower = pattern.lower()
            if self._matches_pattern(file_name, pattern_lower):
                return 1.0
        
        return 0.0
    
    def _score_content_detection(self, file_path: str, format_config: Dict[str, Any], 
                               file_content: Any = None) -> float:
        """Score content against detection rules"""
        format_type = format_config.get('format_type', 'json')
        detection_config = format_config.get('detection', {})
        
        try:
            if format_type == 'json':
                return self._score_json_detection(file_path, detection_config, file_content)
            elif format_type == 'xml':
                return self._score_xml_detection(file_path, detection_config)
            elif format_type == 'csv':
                return self._score_csv_detection(file_path, detection_config)
            else:
                return 0.0
        except Exception as e:
            logger.debug(f"Error scoring content detection: {e}")
            return 0.0
    
    def _score_json_detection(self, file_path: str, detection_config: Dict[str, Any], 
                            file_content: Any = None) -> float:
        """Score JSON content against detection rules"""
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            score = 0.0
            total_checks = 0
            
            # Check for required JSON keys (higher weight)
            required_keys = detection_config.get('required_keys', [])
            if required_keys:
                total_checks += len(required_keys) * 2  # Double weight
                for key in required_keys:
                    if self.field_mapper.get_nested_value(file_content, key):
                        score += 2.0
            
            # Check for JSON keys presence
            json_keys = detection_config.get('json_keys', [])
            if json_keys:
                total_checks += len(json_keys)
                content_str = json.dumps(file_content).lower()
                for key in json_keys:
                    if key.lower() in content_str:
                        score += 1.0
            
            return score / total_checks if total_checks > 0 else 0.0
            
        except Exception:
            return 0.0
    
    def _score_xml_detection(self, file_path: str, detection_config: Dict[str, Any]) -> float:
        """Score XML content against detection rules"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            score = 0.0
            total_checks = 0
            
            # Check XML root element (higher weight)
            xml_root = detection_config.get('xml_root')
            if xml_root:
                total_checks += 2
                if root.tag.lower() == xml_root.lower():
                    score += 2.0
            
            # Check for required elements
            required_elements = detection_config.get('required_elements', [])
            if required_elements:
                total_checks += len(required_elements)
                for element_path in required_elements:
                    if root.find(f".//{element_path}") is not None:
                        score += 1.0
            
            return score / total_checks if total_checks > 0 else 0.0
            
        except Exception:
            return 0.0
    
    def _score_csv_detection(self, file_path: str, detection_config: Dict[str, Any]) -> float:
        """Score CSV content against detection rules"""
        try:
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader, [])
                headers_lower = [h.lower().strip() for h in headers]
            
            if not headers:
                return 0.0
            
            score = 0.0
            total_checks = 0
            
            # Check required headers (higher weight)
            required_headers = detection_config.get('required_headers', [])
            if required_headers:
                total_checks += len(required_headers) * 2
                for header in required_headers:
                    if header.lower().strip() in headers_lower:
                        score += 2.0
            
            # Check CSV headers presence
            csv_headers = detection_config.get('csv_headers', [])
            if csv_headers:
                total_checks += len(csv_headers)
                for header in csv_headers:
                    if header.lower().strip() in headers_lower:
                        score += 1.0
            
            return score / total_checks if total_checks > 0 else 0.0
            
        except Exception:
            return 0.0
    
    def _matches_format(self, file_path: str, file_name: str, file_ext: str, 
                       format_config: Dict[str, Any], file_content: Any = None) -> bool:
        """Check if file matches format configuration"""
        
        # Check file patterns
        file_patterns = format_config.get('file_patterns', [])
        for pattern in file_patterns:
            if self._matches_pattern(file_name, pattern.lower()):
                # Additional validation based on format type
                return self._validate_format_content(file_path, format_config, file_content)
        
        return False
    
    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches pattern (supports wildcards)"""
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
    
    def _validate_format_content(self, file_path: str, format_config: Dict[str, Any], 
                                file_content: Any = None) -> bool:
        """Validate file content matches format expectations"""
        format_type = format_config.get('format_type', 'json')
        detection_config = format_config.get('detection', {})
        
        try:
            if format_type == 'json':
                if file_content is None:
                    with open(file_path, 'r') as f:
                        file_content = json.load(f)
                
                # Check required JSON keys
                required_keys = detection_config.get('required_keys', [])
                for key in required_keys:
                    if not self.field_mapper.get_nested_value(file_content, key):
                        return False
                
                # Check JSON keys presence
                json_keys = detection_config.get('json_keys', [])
                if json_keys:
                    content_str = json.dumps(file_content).lower()
                    return any(key.lower() in content_str for key in json_keys)
            
            elif format_type == 'xml':
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Check XML root element
                xml_root = detection_config.get('xml_root')
                if xml_root and root.tag != xml_root:
                    return False
                
                # Check required elements
                required_elements = detection_config.get('required_elements', [])
                for element_path in required_elements:
                    if root.find(element_path) is None:
                        return False
            
            elif format_type == 'csv':
                with open(file_path, 'r') as f:
                    reader = csv.reader(f)
                    headers = next(reader, [])
                    headers_lower = [h.lower() for h in headers]
                
                # Check required headers
                required_headers = detection_config.get('required_headers', [])
                for header in required_headers:
                    if header.lower() not in headers_lower:
                        return False
                
                # Check CSV headers presence
                csv_headers = detection_config.get('csv_headers', [])
                if csv_headers:
                    return any(header.lower() in headers_lower for header in csv_headers)
            
            return True
            
        except Exception as e:
            logger.debug(f"Error validating format content for {file_path}: {e}")
            return False


class UniversalScannerTranslator:
    """Universal translator that uses field mapping configuration"""
    
    def __init__(self, field_mapper: FieldMapper, format_detector: ScannerFormatDetector):
        self.field_mapper = field_mapper
        self.format_detector = format_detector
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this translator can handle the file"""
        detection_result = self.format_detector.detect_scanner_format(file_path, file_content)
        return detection_result is not None
    
    def get_scanner_info(self, file_path: str, file_content: Any = None) -> Optional[Dict[str, Any]]:
        """Get scanner information for the file"""
        return self.format_detector.detect_scanner_format(file_path, file_content)
    
    def parse_file(self, file_path: str, scanner_info: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Parse file using detected format configuration"""
        if scanner_info is None:
            scanner_info = self.get_scanner_info(file_path)
            if not scanner_info:
                raise ValueError(f"Cannot detect scanner format for {file_path}")
        
        format_config = scanner_info['config']
        format_type = format_config.get('format_type', 'json')
        
        if format_type == 'json':
            return self._parse_json_file(file_path, format_config, scanner_info)
        elif format_type == 'xml':
            return self._parse_xml_file(file_path, format_config, scanner_info)
        elif format_type == 'csv':
            return self._parse_csv_file(file_path, format_config, scanner_info)
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
    
    def _parse_json_file(self, file_path: str, format_config: Dict[str, Any], 
                        scanner_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse JSON format file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        assets = []
        field_mappings = format_config.get('field_mappings', {})
        severity_mapping = format_config.get('severity_mapping', {})
        asset_type = scanner_info.get('asset_type', 'INFRA')
        
        # Map asset attributes
        asset_mappings = field_mappings.get('asset', {})
        asset_attributes = self.field_mapper.map_asset_attributes(data, asset_mappings, asset_type)
        
        # Create base asset
        asset = {
            'asset_type': asset_type,
            'attributes': asset_attributes,
            'findings': [],
            'tags': [
                {'key': 'scanner', 'value': scanner_info['scanner']},
                {'key': 'format', 'value': scanner_info['format']}
            ]
        }
        
        # Extract vulnerabilities - supports multi-level nested arrays
        vuln_mappings = field_mappings.get('vulnerability', {})
        
        # Find vulnerability array path(s) - may have multiple levels like "Results[].Vulnerabilities[]"
        vuln_array_path = None
        for field, path in vuln_mappings.items():
            if '[]' in path:
                vuln_array_path = path
                break
        
        if vuln_array_path:
            # Count the number of array levels in the path
            array_levels = vuln_array_path.count('[]')
            
            if array_levels == 1:
                # Single-level array (e.g., "vulnerabilities[].id")
                first_array_path = vuln_array_path.split('[]')[0]
                vulnerabilities = self.field_mapper.get_nested_value(data, first_array_path, [])
                if isinstance(vulnerabilities, list):
                    for vuln_data in vulnerabilities:
                        vulnerability = self.field_mapper.map_vulnerability(
                            vuln_data, field_mappings, severity_mapping, data
                        )
                        asset['findings'].append(vulnerability)
            
            elif array_levels >= 2:
                # Multi-level nested arrays (e.g., "Results[].Vulnerabilities[].VulnerabilityID")
                # Extract the outer array path and inner array path
                parts = vuln_array_path.split('[]', 2)
                outer_array_path = parts[0]  # e.g., "Results"
                inner_array_path = parts[1].lstrip('.').split('[]')[0]  # e.g., "Vulnerabilities"
                
                logger.debug(f"Multi-level array detected: outer={outer_array_path}, inner={inner_array_path}")
                
                # Get outer array
                outer_array = self.field_mapper.get_nested_value(data, outer_array_path, [])
                if isinstance(outer_array, list):
                    for outer_item in outer_array:
                        # Get inner array from each outer item
                        inner_array = self.field_mapper.get_nested_value(outer_item, inner_array_path, [])
                        if isinstance(inner_array, list):
                            for vuln_data in inner_array:
                                vulnerability = self.field_mapper.map_vulnerability(
                                    vuln_data, field_mappings, severity_mapping, outer_item
                                )
                                asset['findings'].append(vulnerability)
        else:
            # Single vulnerability or different structure
            vulnerability = self.field_mapper.map_vulnerability(
                data, field_mappings, severity_mapping
            )
            if vulnerability.get('name') != "Unknown Vulnerability":
                asset['findings'].append(vulnerability)
        
        assets.append(asset)
        return assets
    
    def _parse_xml_file(self, file_path: str, format_config: Dict[str, Any], 
                       scanner_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse XML format file"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        assets = []
        field_mappings = format_config.get('field_mappings', {})
        severity_mapping = format_config.get('severity_mapping', {})
        asset_type = scanner_info.get('asset_type', 'INFRA')
        
        # Convert XML to dict-like structure for mapping
        xml_data = self._xml_to_dict(root)
        
        # Map asset attributes
        asset_mappings = field_mappings.get('asset', {})
        asset_attributes = self.field_mapper.map_asset_attributes(xml_data, asset_mappings, asset_type)
        
        # Create base asset
        asset = {
            'asset_type': asset_type,
            'attributes': asset_attributes,
            'findings': [],
            'tags': [
                {'key': 'scanner', 'value': scanner_info['scanner']},
                {'key': 'format', 'value': scanner_info['format']}
            ]
        }
        
        # Extract vulnerabilities from XML
        vuln_mappings = field_mappings.get('vulnerability', {})
        
        # Find vulnerability elements
        vuln_elements = root.findall('.//ReportItem') or root.findall('.//Vulnerability') or root.findall('.//Issue')
        
        for vuln_elem in vuln_elements:
            vuln_data = self._xml_to_dict(vuln_elem)
            vulnerability = self.field_mapper.map_vulnerability(
                vuln_data, field_mappings, severity_mapping, xml_data
            )
            asset['findings'].append(vulnerability)
        
        assets.append(asset)
        return assets
    
    def _parse_csv_file(self, file_path: str, format_config: Dict[str, Any], 
                       scanner_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse CSV format file"""
        assets_map = {}
        field_mappings = format_config.get('field_mappings', {})
        severity_mapping = format_config.get('severity_mapping', {})
        asset_type = scanner_info.get('asset_type', 'INFRA')
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Map asset attributes
                asset_mappings = field_mappings.get('asset', {})
                asset_attributes = self.field_mapper.map_asset_attributes(row, asset_mappings, asset_type)
                
                # Create asset key
                asset_key = (asset_attributes.get('ip') or 
                           asset_attributes.get('hostname') or 
                           asset_attributes.get('fqdn') or 
                           f"asset-{len(assets_map)}")
                
                if asset_key not in assets_map:
                    assets_map[asset_key] = {
                        'asset_type': asset_type,
                        'attributes': asset_attributes,
                        'findings': [],
                        'tags': [
                            {'key': 'scanner', 'value': scanner_info['scanner']},
                            {'key': 'format', 'value': scanner_info['format']}
                        ]
                    }
                
                # Map vulnerability
                vulnerability = self.field_mapper.map_vulnerability(
                    row, field_mappings, severity_mapping
                )
                
                # Only add if it's a real vulnerability
                if (vulnerability.get('name') != "Unknown Vulnerability" and 
                    vulnerability.get('severity') not in ["1.0"] or 
                    any(field in row for field in ['QID', 'Plugin ID', 'CVE'])):
                    assets_map[asset_key]['findings'].append(vulnerability)
        
        return list(assets_map.values())
    
    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary"""
        result = {}
        
        # Add element text
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()
        
        # Add attributes
        if element.attrib:
            result.update(element.attrib)
        
        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                # Multiple elements with same tag
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        return result
