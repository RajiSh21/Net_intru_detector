"""
Backward compatibility shim for realtime_detector module.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.realtime_detector import *  # noqa

__all__ = ['RealtimeNetworkMonitor', 'simulate_network_traffic']
