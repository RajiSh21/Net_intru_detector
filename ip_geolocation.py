"""
Backward compatibility shim for ip_geolocation module.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.ip_geolocation import *  # noqa

__all__ = ['IPGeocoder', 'ApplicationTracker', 'PORT_APPLICATIONS']
