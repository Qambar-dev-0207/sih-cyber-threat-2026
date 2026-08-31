"""
SIH26145 - Test Suite for Detector 5: Encrypted Malware Threat Detector (JA4 Alias)
Runs the test suite for Detector 5 under test_detector_ja4.py naming convention.
"""

from .test_detector_malware import (
    TestJA4ThreatIntelDB,
    TestTLSAnomalyScorer,
    TestEncryptedMalwareDetector,
)

__all__ = [
    "TestJA4ThreatIntelDB",
    "TestTLSAnomalyScorer",
    "TestEncryptedMalwareDetector",
]
