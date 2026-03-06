"""
Backward compatibility shim for old pickled models.

This file allows old models trained with the previous file structure
to be loaded with the new organized structure.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and re-export all names from the new location
from core.intrusion_detector import *  # noqa
from core.realtime_detector import *  # noqa
from core.ip_geolocation import *  # noqa

# Make this module behave like the old intrusion_detector module
__all__ = ['NetworkIntrusionDetector', 'COLUMN_NAMES', 'CATEGORICAL_COLS', 'ATTACK_TYPES']
