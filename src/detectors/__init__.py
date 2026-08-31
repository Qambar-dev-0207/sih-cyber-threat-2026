"""
SIH26145 - Parallel Streaming Threat Detectors Package
Exports base detector framework, multi-detector orchestrator, and all Phase 2 streaming detectors 1-6.
"""

from .base import BaseDetector
from .detector_manager import DetectorManager
from .ddos_entropy import (
    DDoSEntropyDetector,
    DifferentialEntropyTracker,
    RateEWMATracker,
    TargetHostDDoSState,
)
from .portscan_hll import (
    PortScanHLLDetector,
    HyperLogLog,
    SlottedRollingHLL,
    SourceHostScanState,
)
from .exfil_ratio import (
    ExfilRatioDetector,
    HostExfiltrationState,
    is_external_ip,
)
from .dga_tunneling import (
    DGATunnelingDetector,
    DGALSTMDetector,
    HostDnsState,
    ONNXDGAClassifier,
)
from .encrypted_malware import (
    EncryptedMalwareDetector,
    JA4MalwareDetector,
    JA4ThreatIntelDB,
    TLSAnomalyScorer,
    ThreatSignature,
)
from .c2_beaconing import (
    C2BeaconingDetector,
    C2BeaconDetector,
    FlowBeaconState,
    CircularDeltaTBuffer,
    compute_interarrival_stats,
)

__all__ = [
    # Base & Orchestrator
    "BaseDetector",
    "DetectorManager",
    # Detector 1: DDoS & Protocol Anomalies
    "DDoSEntropyDetector",
    "DifferentialEntropyTracker",
    "RateEWMATracker",
    "TargetHostDDoSState",
    # Detector 2: Port Scanning & Recon
    "PortScanHLLDetector",
    "HyperLogLog",
    "SlottedRollingHLL",
    "SourceHostScanState",
    # Detector 3: Data Exfiltration
    "ExfilRatioDetector",
    "HostExfiltrationState",
    "is_external_ip",
    # Detector 4: DGA & DNS Tunneling
    "DGATunnelingDetector",
    "DGALSTMDetector",
    "HostDnsState",
    "ONNXDGAClassifier",
    # Detector 5: Encrypted Malware & JA4/JA4S
    "EncryptedMalwareDetector",
    "JA4MalwareDetector",
    "JA4ThreatIntelDB",
    "TLSAnomalyScorer",
    "ThreatSignature",
    # Detector 6: C2 Beaconing
    "C2BeaconingDetector",
    "C2BeaconDetector",
    "FlowBeaconState",
    "CircularDeltaTBuffer",
    "compute_interarrival_stats",
]
