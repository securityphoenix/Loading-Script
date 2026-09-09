"""
Dummy format_handlers module for compatibility.
This module provides placeholder classes to prevent import errors
when the Phoenix scanner tries to import format_handlers.
"""


class ChefInspecTranslator:
    """
    Dummy Chef InSpec translator for compatibility.
    This is a placeholder to prevent import errors.
    If you need actual Chef InSpec support, implement this class properly.
    """
    def __init__(self, *args, **kwargs):
        """Initialize with any arguments (ignored)"""
        pass
        
    def translate(self, raw_finding):
        """Placeholder translate method"""
        return raw_finding
    
    def process(self, *args, **kwargs):
        """Placeholder process method"""
        return {}

