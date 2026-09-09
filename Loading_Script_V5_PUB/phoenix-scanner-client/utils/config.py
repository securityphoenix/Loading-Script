"""Configuration loader utility"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


def load_config(config_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file with fallback to defaults.
    
    Priority:
    1. Specified config file
    2. config.yaml in current directory
    3. config.yaml in script directory
    4. Empty dict (will use environment variables)
    
    Args:
        config_file: Path to config file
    
    Returns:
        Configuration dictionary
    """
    if config_file and Path(config_file).exists():
        with open(config_file, 'r') as f:
            return yaml.safe_load(f) or {}
    
    # Try default locations
    default_locations = [
        Path('config.yaml'),
        Path(__file__).parent.parent / 'config.yaml',
        Path.home() / '.phoenix-scanner' / 'config.yaml'
    ]
    
    for path in default_locations:
        if path.exists():
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
    
    return {}



