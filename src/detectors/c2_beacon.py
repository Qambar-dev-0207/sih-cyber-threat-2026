"""
SIH26145 - Detector 6: Streaming C2 Beaconing Threat Detector Alias Module
Re-exports C2BeaconingDetector and C2BeaconDetector from c2_beaconing.py.
"""

from .c2_beaconing import (
    C2BeaconingDetector,
    C2BeaconDetector,
    FlowBeaconState,
    CircularDeltaTBuffer,
    compute_interarrival_stats,
)

__all__ = [
    "C2BeaconingDetector",
    "C2BeaconDetector",
    "FlowBeaconState",
    "CircularDeltaTBuffer",
    "compute_interarrival_stats",
]
