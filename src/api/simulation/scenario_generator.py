"""
SIH26145 - Deterministic Threat Scenario Generator
Generates synthetic multi-stage security alerts for live hackathon judge demonstrations.
"""

from __future__ import annotations

import time
import uuid
from typing import List, Optional
from src.ingestion.models import RawAlert


def generate_apt_scenario(
    attacker_ip: str = "198.51.100.42",
    target_ip: str = "192.168.1.100",
    base_timestamp: Optional[float] = None,
) -> List[RawAlert]:
    """
    Generates a 5-stage Advanced Persistent Threat (APT) multi-vector kill-chain:
    1. Reconnaissance (Port Scanning via HLL)
    2. Weaponization & DNS Query (DGA Tunneling)
    3. Exploitation & Payload Delivery (JA4 CobaltStrike Fingerprint)
    4. Command & Control (Periodic Heartbeat Beaconing)
    5. Data Exfiltration (High Out/In Byte Ratio)
    """
    t0 = base_timestamp or time.time()
    alerts: List[RawAlert] = []

    # Stage 1: Port Scan Reconnaissance (t0)
    alerts.append(
        RawAlert(
            alert_id=f"ALT-APT-1-{uuid.uuid4().hex[:6]}",
            timestamp=t0,
            detector_name="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            severity="MEDIUM",
            confidence=0.91,
            source_ip=attacker_ip,
            target_ip=target_ip,
            target_port=443,
            protocol="tcp",
            flow_id=f"flow_scan_{uuid.uuid4().hex[:8]}",
            window_duration_sec=30.0,
            title=f"Horizontal Port Scan against {target_ip} (5 unique ports)",
            evidence={
                "distinct_ports_cardinality": 5,
                "probed_ports": [22, 80, 443, 4444, 8080],
                "hll_register_fill_pct": 14.5,
                "scan_rate_pps": 18.4,
            },
            mitre_technique="T1595.001",
            recommended_mitigation=f"Drop traffic from {attacker_ip} via edge firewall ACL.",
        )
    )

    # Stage 2: DGA & DNS Staging (t0 + 2s)
    alerts.append(
        RawAlert(
            alert_id=f"ALT-APT-2-{uuid.uuid4().hex[:6]}",
            timestamp=t0 + 2.0,
            detector_name="dga_lstm",
            threat_class="DGA_TUNNELLING",
            severity="HIGH",
            confidence=0.94,
            source_ip=attacker_ip,
            target_ip="8.8.8.8",
            target_port=53,
            protocol="udp",
            flow_id=f"flow_dns_{uuid.uuid4().hex[:8]}",
            window_duration_sec=10.0,
            title=f"Algorithmic DGA Query c948df2a10.tunnel.darknet.org from {attacker_ip}",
            evidence={
                "query": "c948df2a10.tunnel.darknet.org",
                "shannon_entropy": 4.45,
                "consonant_vowel_ratio": 3.8,
                "lstm_probability": 0.965,
                "qtype": "TXT",
            },
            mitre_technique="T1568.002",
            recommended_mitigation="Sinkhole darknet.org domain via DNS RPZ response policy.",
        )
    )

    # Stage 3: Encrypted Malware JA4 Delivery (t0 + 4s)
    alerts.append(
        RawAlert(
            alert_id=f"ALT-APT-3-{uuid.uuid4().hex[:6]}",
            timestamp=t0 + 4.0,
            detector_name="ja4_malware",
            threat_class="ENCRYPTED_MALWARE",
            severity="HIGH",
            confidence=0.96,
            source_ip=attacker_ip,
            target_ip=target_ip,
            target_port=443,
            protocol="tcp",
            flow_id=f"flow_tls_{uuid.uuid4().hex[:8]}",
            window_duration_sec=15.0,
            title=f"CobaltStrike HTTPS Stager Detected (JA4: t13d1516h2_8daaf6152771)",
            evidence={
                "ja4": "t13d1516h2_8daaf6152771",
                "ja4s": "t130200_1301_a564da129a00",
                "matched_threat": "CobaltStrike Malleable C2 HTTPS Profile",
                "tls_version": "TLSv1.3",
                "cipher_count": 16,
            },
            mitre_technique="T1071.001",
            recommended_mitigation="Terminate TLS session and block JA4 client fingerprint.",
        )
    )

    # Stage 4: Command & Control Beaconing (t0 + 6s)
    alerts.append(
        RawAlert(
            alert_id=f"ALT-APT-4-{uuid.uuid4().hex[:6]}",
            timestamp=t0 + 6.0,
            detector_name="c2_beacon",
            threat_class="C2_BEACONING",
            severity="HIGH",
            confidence=0.97,
            source_ip=attacker_ip,
            target_ip=target_ip,
            target_port=4444,
            protocol="tcp",
            flow_id=f"flow_c2_{uuid.uuid4().hex[:8]}",
            window_duration_sec=60.0,
            title=f"Periodic C2 Heartbeat Beaconing to {attacker_ip}:4444",
            evidence={
                "interval_mean_sec": 30.0,
                "interval_std_sec": 1.25,
                "coefficient_of_variation": 0.0417,
                "observed_pulses": 8,
                "beacon_certainty": 0.98,
            },
            mitre_technique="T1071.001",
            recommended_mitigation="Isolate target host from internal network segment.",
        )
    )

    # Stage 5: Data Exfiltration (t0 + 8s)
    alerts.append(
        RawAlert(
            alert_id=f"ALT-APT-5-{uuid.uuid4().hex[:6]}",
            timestamp=t0 + 8.0,
            detector_name="exfil_ratio",
            threat_class="DATA_EXFILTRATION",
            severity="CRITICAL",
            confidence=0.98,
            source_ip=attacker_ip,
            target_ip=target_ip,
            target_port=443,
            protocol="tcp",
            flow_id=f"flow_exfil_{uuid.uuid4().hex[:8]}",
            window_duration_sec=45.0,
            title=f"Asymmetric Outbound Data Exfiltration (Ratio: 14.8x, 4.8MB)",
            evidence={
                "outbound_bytes": 4820000,
                "inbound_bytes": 325000,
                "out_in_ratio": 14.83,
                "destination_asn": "AS9009 (M247 Ltd)",
                "duration_sec": 24.5,
            },
            mitre_technique="T1048",
            recommended_mitigation="Immediately revoke host egress gateway routing.",
        )
    )

    return alerts


def generate_ddos_scenario(
    target_ip: str = "192.168.10.50",
    primary_attacker: str = "203.0.113.88",
    burst_count: int = 50,
    base_timestamp: Optional[float] = None,
) -> List[RawAlert]:
    """
    Generates a volumetric SYN Flood DDoS storm collapsing into an AlertStormSummary.
    """
    t0 = base_timestamp or time.time()
    alerts: List[RawAlert] = []

    # Primary high-rate flood alert
    alerts.append(
        RawAlert(
            alert_id=f"ALT-DDOS-PRIMARY-{uuid.uuid4().hex[:6]}",
            timestamp=t0,
            detector_name="ddos_entropy",
            threat_class="VOLUMETRIC_DDOS",
            severity="CRITICAL",
            confidence=0.96,
            source_ip=primary_attacker,
            target_ip=target_ip,
            target_port=80,
            protocol="tcp",
            flow_id=f"flow_synflood_{uuid.uuid4().hex[:8]}",
            window_duration_sec=5.0,
            title=f"Volumetric SYN Flood against {target_ip}:80 (>45,000 PPS)",
            evidence={
                "syn_rate_pps": 48500.0,
                "entropy_dip": 1.82,
                "source_entropy": 0.42,
                "flag_distribution": {"SYN": 48500, "ACK": 12, "FIN": 0},
            },
            mitre_technique="T1498.001",
            recommended_mitigation="Enable SYN cookies and deploy edge BGP Flowspec drop rule.",
        )
    )

    # Additional burst flood alerts to trigger rate limiter
    for i in range(burst_count):
        spoofed_src = f"172.16.{i % 250}.{(i * 7) % 250 + 1}"
        alerts.append(
            RawAlert(
                alert_id=f"ALT-DDOS-BURST-{i:03d}-{uuid.uuid4().hex[:4]}",
                timestamp=t0 + (i * 0.05),
                detector_name="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                severity="HIGH",
                confidence=0.88,
                source_ip=primary_attacker if i % 2 == 0 else spoofed_src,
                target_ip=target_ip,
                target_port=80,
                protocol="tcp",
                flow_id=f"flow_burst_{i}",
                window_duration_sec=1.0,
                title=f"SYN Flood fragment {i+1}/{burst_count}",
                evidence={"burst_index": i, "pps": 52000.0},
                mitre_technique="T1498.001",
                recommended_mitigation=f"Drop {primary_attacker} traffic.",
            )
        )

    return alerts


def generate_c2_scenario(
    attacker_ip: str = "198.51.100.99",
    compromised_ip: str = "10.0.0.85",
    base_timestamp: Optional[float] = None,
) -> List[RawAlert]:
    """
    Generates Sliver / CobaltStrike C2 beaconing scenario with JA4 fingerprint matching.
    """
    t0 = base_timestamp or time.time()
    alerts: List[RawAlert] = []

    # JA4 TLS Anomaly
    alerts.append(
        RawAlert(
            alert_id=f"ALT-C2-TLS-{uuid.uuid4().hex[:6]}",
            timestamp=t0,
            detector_name="ja4_malware",
            threat_class="ENCRYPTED_MALWARE",
            severity="HIGH",
            confidence=0.93,
            source_ip=compromised_ip,
            target_ip=attacker_ip,
            target_port=8443,
            protocol="tcp",
            flow_id=f"flow_c2_tls_{uuid.uuid4().hex[:8]}",
            window_duration_sec=30.0,
            title=f"Sliver C2 TLS Handshake Fingerprint (JA4: t13d1516h2_8daaf6152771)",
            evidence={
                "ja4": "t13d1516h2_8daaf6152771",
                "matched_threat": "Sliver C2 Framework",
                "server_name": "api.cloud-cdn-edge.com",
            },
            mitre_technique="T1071.001",
            recommended_mitigation=f"Block destination IP {attacker_ip} and sinkhole domain.",
        )
    )

    # Periodic Beaconing Heartbeat
    alerts.append(
        RawAlert(
            alert_id=f"ALT-C2-BEACON-{uuid.uuid4().hex[:6]}",
            timestamp=t0 + 2.5,
            detector_name="c2_beacon",
            threat_class="C2_BEACONING",
            severity="HIGH",
            confidence=0.96,
            source_ip=compromised_ip,
            target_ip=attacker_ip,
            target_port=8443,
            protocol="tcp",
            flow_id=f"flow_c2_beacon_{uuid.uuid4().hex[:8]}",
            window_duration_sec=60.0,
            title=f"C2 Heartbeat Beaconing detected from {compromised_ip} to {attacker_ip}",
            evidence={
                "interval_mean_sec": 30.0,
                "interval_std_sec": 0.85,
                "coefficient_of_variation": 0.028,
                "observed_pulses": 12,
            },
            mitre_technique="T1071.001",
            recommended_mitigation="Quarantine host 10.0.0.85 and terminate active sessions.",
        )
    )

    return alerts


def generate_dns_tunnel_scenario(
    compromised_ip: str = "10.0.0.120",
    nameserver_ip: str = "8.8.8.8",
    base_timestamp: Optional[float] = None,
) -> List[RawAlert]:
    """
    Generates DGA & DNS Data Exfiltration tunneling queries with high Shannon entropy.
    """
    t0 = base_timestamp or time.time()
    alerts: List[RawAlert] = []

    domains = [
        "x92kd9100.tunnel.exfil-c2.net",
        "b77fa882c.tunnel.exfil-c2.net",
        "8ff210a9c.tunnel.exfil-c2.net",
    ]

    for idx, d in enumerate(domains):
        alerts.append(
            RawAlert(
                alert_id=f"ALT-DNS-{idx}-{uuid.uuid4().hex[:6]}",
                timestamp=t0 + (idx * 1.5),
                detector_name="dga_lstm",
                threat_class="DGA_TUNNELLING",
                severity="HIGH",
                confidence=0.95,
                source_ip=compromised_ip,
                target_ip=nameserver_ip,
                target_port=53,
                protocol="udp",
                flow_id=f"flow_dns_tunnel_{idx}",
                window_duration_sec=15.0,
                title=f"High-Entropy DGA Query ({d}) from {compromised_ip}",
                evidence={
                    "query": d,
                    "shannon_entropy": 4.65,
                    "subdomain_length": 32,
                    "consonant_ratio": 4.1,
                    "lstm_score": 0.98,
                },
                mitre_technique="T1568.002",
                recommended_mitigation="Add exfil-c2.net to BIND 9 RPZ sinkhole blocklist.",
            )
        )

    return alerts


def generate_scenario_alerts(scenario_name: str) -> List[RawAlert]:
    """
    Dispatcher returning deterministic synthetic alerts for a given scenario identifier.
    Supported scenarios: 'apt', 'ddos', 'c2', 'dns_tunnel', 'dns'.
    """
    normalized = scenario_name.strip().lower()
    if normalized in ("apt", "apt_multi_stage", "apt_intrusion"):
        return generate_apt_scenario()
    elif normalized in ("ddos", "syn_flood", "volumetric_ddos"):
        return generate_ddos_scenario()
    elif normalized in ("c2", "c2_beacon", "c2_beaconing", "sliver"):
        return generate_c2_scenario()
    elif normalized in ("dns", "dns_tunnel", "dns_tunneling", "dga"):
        return generate_dns_tunnel_scenario()
    else:
        # Default fallback to APT
        return generate_apt_scenario()
