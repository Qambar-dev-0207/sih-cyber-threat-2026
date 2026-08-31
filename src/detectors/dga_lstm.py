"""
SIH26145 - Detector 4: DGA & DNS Tunnelling Detector Alias Module
Re-exports DGATunnelingDetector and DGALSTMDetector from dga_tunneling.py.
"""

from .dga_tunneling import (
    DGATunnelingDetector,
    DGALSTMDetector,
    HostDnsState,
    ONNXDGAClassifier,
)

__all__ = [
    "DGATunnelingDetector",
    "DGALSTMDetector",
    "HostDnsState",
    "ONNXDGAClassifier",
]
