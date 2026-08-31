from __future__ import annotations

from typing import Any, Dict, List, Optional
from src.agentic_triage.state import MitreMapping


MITRE_TECHNIQUE_CATALOG: Dict[str, Dict[str, Any]] = {
    "PORT_SCAN_RECON": {
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Port Scanning",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "Adversary executing systematic network port probes across target IP ranges using TCP SYN/Connect or UDP scanning to identify active services.",
        "matched_detector": "portscan_hll",
        "detection_source": "HyperLogLog Cardinality & Failed SYN Connection Ratios",
    },
    "port_scan": {
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Port Scanning",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "Adversary executing systematic network port probes across target IP ranges.",
        "matched_detector": "portscan_hll",
        "detection_source": "HyperLogLog Cardinality & Failed SYN Connection Ratios",
    },
    "portscan_hll": {
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Port Scanning",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "Adversary executing systematic network port probes across target IP ranges.",
        "matched_detector": "portscan_hll",
        "detection_source": "HyperLogLog Cardinality & Failed SYN Connection Ratios",
    },
    "recon_sweep": {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "Adversary scanning for vulnerabilities and unpatched listening daemon signatures across the network enclave.",
        "matched_detector": "portscan_hll",
        "detection_source": "HyperLogLog Target Host Sweep",
    },
    "DGA_TUNNELLING": {
        "technique_id": "T1568.002",
        "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Weaponization & Delivery",
        "description": "Adversary utilizing pseudo-random algorithmically generated domain names (DGA) or DNS tunneling to evade static domain blacklists and establish resilient command channels.",
        "matched_detector": "dga_tunneling",
        "detection_source": "BiLSTM Sequence Classifier + Subdomain Shannon Entropy",
    },
    "dga_tunneling": {
        "technique_id": "T1568.002",
        "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Weaponization & Delivery",
        "description": "Adversary utilizing pseudo-random algorithmically generated domain names (DGA) or DNS tunneling to evade static domain blacklists.",
        "matched_detector": "dga_tunneling",
        "detection_source": "BiLSTM Sequence Classifier + Subdomain Shannon Entropy",
    },
    "dga_lstm": {
        "technique_id": "T1568.002",
        "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Weaponization & Delivery",
        "description": "Adversary utilizing pseudo-random algorithmically generated domain names (DGA) for command rendezvous.",
        "matched_detector": "dga_lstm",
        "detection_source": "BiLSTM Sequence Classifier + Subdomain Shannon Entropy",
    },
    "ENCRYPTED_MALWARE": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Installation & Execution",
        "description": "Adversary communicating with remote infrastructure using encrypted TLS sessions with client Hello parameters matching known threat actor profiles (e.g., Cobalt Strike, Sliver, Trickbot).",
        "matched_detector": "encrypted_malware",
        "detection_source": "JA4 Client Fingerprint Hash & ALPN/Cipher Signature Matching",
    },
    "encrypted_malware": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Installation & Execution",
        "description": "Adversary communicating with remote infrastructure using encrypted TLS sessions.",
        "matched_detector": "encrypted_malware",
        "detection_source": "JA4 Client Fingerprint Hash & ALPN/Cipher Signature Matching",
    },
    "ja4_malware": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Installation & Execution",
        "description": "Adversary TLS session matching known adversary JA4 fingerprints.",
        "matched_detector": "ja4_malware",
        "detection_source": "JA4 Client Fingerprint Hash Matching",
    },
    "C2_BEACONING": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Command and Control",
        "description": "Periodic outbound network heartbeat traffic (delta-T clustering, low jitter) indicating automated agent check-in with an external Command & Control server.",
        "matched_detector": "c2_beaconing",
        "detection_source": "Inter-Arrival Time (Delta-T) Clustering, FFT & Jitter Analysis",
    },
    "c2_beaconing": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Command and Control",
        "description": "Periodic outbound network heartbeat traffic indicating automated agent check-in.",
        "matched_detector": "c2_beaconing",
        "detection_source": "Inter-Arrival Time (Delta-T) Clustering, FFT & Jitter Analysis",
    },
    "c2_beacon": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "kill_chain_phase": "Command and Control",
        "description": "Periodic outbound network heartbeat traffic indicating automated agent check-in.",
        "matched_detector": "c2_beaconing",
        "detection_source": "Inter-Arrival Time (Delta-T) Clustering & Jitter Analysis",
    },
    "DATA_EXFILTRATION": {
        "technique_id": "T1048.002",
        "technique_name": "Exfiltration Over Alternative Protocol: Asymmetric Flow",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "kill_chain_phase": "Actions on Objectives",
        "description": "Anomalous outbound data volume or asymmetric byte ratio crossing historical $P^2$ quantile baselines, indicating unauthorized egress of internal files or records.",
        "matched_detector": "exfil_ratio",
        "detection_source": "P² Dynamic Quantile Estimation & Egress/Ingress Ratio Tracking",
    },
    "exfil_ratio": {
        "technique_id": "T1048.002",
        "technique_name": "Exfiltration Over Alternative Protocol: Asymmetric Flow",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "kill_chain_phase": "Actions on Objectives",
        "description": "Anomalous outbound data volume crossing statistical baseline thresholds.",
        "matched_detector": "exfil_ratio",
        "detection_source": "P² Dynamic Quantile Estimation & Egress/Ingress Ratio Tracking",
    },
    "VOLUMETRIC_DDOS": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "kill_chain_phase": "Impact",
        "description": "High-volume flood of network packets (SYN flood, UDP blast, ICMP sweep) causing Shannon entropy collapse across header distributions and service degradation.",
        "matched_detector": "ddos_entropy",
        "detection_source": "Rolling Shannon Entropy & Token-Bucket Rate Deviation",
    },
    "PROTOCOL_DDOS": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "kill_chain_phase": "Impact",
        "description": "Protocol-specific resource exhaustion attacks designed to disrupt network stack processing capacity.",
        "matched_detector": "ddos_entropy",
        "detection_source": "Rolling Shannon Entropy & Protocol State Tracking",
    },
    "ddos_entropy": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "kill_chain_phase": "Impact",
        "description": "Volumetric denial-of-service traffic flooding target endpoints.",
        "matched_detector": "ddos_entropy",
        "detection_source": "Rolling Shannon Entropy & Token-Bucket Rate Deviation",
    },
}


def get_mitre_entry(threat_class_or_detector: str, confidence: float = 0.8) -> Optional[MitreMapping]:
    """Retrieve curated MITRE ATT&CK mapping for a given threat class or detector key."""
    if not threat_class_or_detector:
        return None
    key = str(threat_class_or_detector).strip()
    entry = MITRE_TECHNIQUE_CATALOG.get(key)
    if entry is None:
        entry = MITRE_TECHNIQUE_CATALOG.get(key.upper())
    if entry is None:
        entry = MITRE_TECHNIQUE_CATALOG.get(key.lower())

    if entry is None:
        # Fallback for unrecognized threat types
        return MitreMapping(
            technique_id="T1595",
            technique_name="Active Scanning",
            tactic_id="TA0043",
            tactic_name="Reconnaissance",
            kill_chain_phase="Reconnaissance",
            confidence=confidence,
            matched_detector=key,
            description="Unclassified network anomaly detected via passive sensor.",
        )

    return MitreMapping(
        technique_id=entry["technique_id"],
        technique_name=entry["technique_name"],
        tactic_id=entry["tactic_id"],
        tactic_name=entry["tactic_name"],
        kill_chain_phase=entry["kill_chain_phase"],
        confidence=confidence,
        matched_detector=entry["matched_detector"],
        description=entry.get("description", ""),
    )


def lookup_mitre_techniques(
    threat_classes: List[str],
    detector_names: Optional[List[str]] = None,
    confidences: Optional[Dict[str, float]] = None,
) -> List[MitreMapping]:
    """Look up MITRE techniques for a list of observed threat classes and detectors, deduplicating by technique_id."""
    mappings: List[MitreMapping] = []
    seen_techniques: set[str] = set()
    conf_map = confidences or {}

    keys_to_search: List[str] = list(threat_classes or [])
    if detector_names:
        keys_to_search.extend(detector_names)

    for k in keys_to_search:
        conf = conf_map.get(k, 0.8)
        entry = get_mitre_entry(k, confidence=conf)
        if entry and entry.technique_id not in seen_techniques:
            seen_techniques.add(entry.technique_id)
            mappings.append(entry)

    return mappings
