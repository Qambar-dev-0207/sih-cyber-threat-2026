"""
SIH26145 - Test Suite for Detector 6: Streaming C2 Beaconing Detector (C2 Alias)
Runs the test suite for Detector 6 under test_detector_c2.py naming convention.
"""

from .test_detector_beaconing import (
    TestInterarrivalStatsMath,
    TestCircularDeltaTBuffer,
    TestC2BeaconingDetector,
)

__all__ = [
    "TestInterarrivalStatsMath",
    "TestCircularDeltaTBuffer",
    "TestC2BeaconingDetector",
]
