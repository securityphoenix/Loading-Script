"""
Utility functions for handling tag configurations across translators.

This module provides a consistent way to handle both TagConfig objects
and dict-based tag configurations, preventing AttributeError issues.
"""

from typing import List, Dict, Any


def get_tags_safely(tag_config: Any) -> List[Dict[str, str]]:
    """
    Safely extract tags from either a TagConfig object or a dict.
    
    Args:
        tag_config: Either a TagConfig object with get_all_tags() method,
                   a dict with 'tags' key, or None
    
    Returns:
        List of tag dictionaries, empty list if no tags
    """
    if not tag_config:
        return []
    
    # TagConfig object with get_all_tags() method
    if hasattr(tag_config, 'get_all_tags'):
        return tag_config.get_all_tags()
    
    # Dict with 'tags' key
    if isinstance(tag_config, dict):
        return tag_config.get('tags', [])
    
    # Unknown type, return empty
    return []


def get_vulnerability_tags_safely(tag_config: Any, severity: str = None) -> List[Dict[str, str]]:
    """
    Safely extract vulnerability-specific tags from either a TagConfig object or a dict.
    
    Args:
        tag_config: Either a TagConfig object with get_vulnerability_tags() method,
                   a dict with 'vulnerability_tags' key, or None
        severity: Optional severity level for severity-specific tags
    
    Returns:
        List of tag dictionaries, empty list if no tags
    """
    if not tag_config:
        return []
    
    # TagConfig object with get_vulnerability_tags() method
    if hasattr(tag_config, 'get_vulnerability_tags'):
        return tag_config.get_vulnerability_tags(severity)
    
    # Dict with 'vulnerability_tags' key
    if isinstance(tag_config, dict):
        vuln_tags = tag_config.get('vulnerability_tags', [])
        # Add severity-specific tags if available
        if severity and 'severity_tags' in tag_config:
            severity_specific = tag_config.get('severity_tags', {}).get(severity.lower(), [])
            vuln_tags.extend(severity_specific)
        return vuln_tags
    
    # Unknown type, return empty
    return []

