"""
iptables / ip6tables DROP rule generator for SIH26145 SENTINEL.

Generates copy-pasteable Linux netfilter rules targeting the threat source.
ALL output is a RECOMMENDATION ARTIFACT requiring authorized human deployment.
requires_human_approval: true
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def generate_iptables(incident: Dict[str, Any]) -> str:
    """
    Generate iptables + ip6tables DROP rules from a triage incident dict.

    Args:
        incident: Dict containing keys: source_ip, target_ips, target_ports,
                  incident_id, primary_threat_class, severity, risk_score.

    Returns:
        A multi-line string of valid iptables/ip6tables shell commands.
    """
    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    source_ip: str = incident.get("source_ip", "0.0.0.0")
    target_ips: List[str] = incident.get("target_ips", [])
    target_ports: List[int] = incident.get("target_ports", [])
    threat_class: str = incident.get("primary_threat_class", "UNKNOWN")
    severity: str = incident.get("severity", "HIGH")
    risk_score: float = incident.get("risk_score", 0.0)
    subnet: str = incident.get("subnet", "")

    now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines: List[str] = [
        "#!/bin/bash",
        "# =============================================================",
        "# SIH26145 SENTINEL — iptables Countermeasure Artifact",
        f"# Incident ID   : {incident_id}",
        f"# Generated     : {now_utc}",
        f"# Threat Class  : {threat_class}",
        f"# Severity      : {severity}  |  Risk Score: {risk_score:.1f}/100",
        "#",
        "# requires_human_approval: true",
        "# IMPORTANT: Review, approve, and deploy via authorised change",
        "# management process. DO NOT execute automatically.",
        "# This monitoring enclave operates under a strict data-diode",
        "# read-only boundary — no automated execution occurs.",
        "# =============================================================",
        "",
        "# --- Block source IP on all INPUT chains ---",
        f'iptables  -I INPUT  1 -s {source_ip} -m comment --comment "SIH26145-{incident_id}" -j DROP',
        f'ip6tables -I INPUT  1 -s {source_ip} -m comment --comment "SIH26145-{incident_id}" -j DROP',
        "",
        "# --- Block source IP on FORWARD chain (gateway/router deployments) ---",
        f'iptables  -I FORWARD 1 -s {source_ip} -m comment --comment "SIH26145-{incident_id}" -j DROP',
        f'ip6tables -I FORWARD 1 -s {source_ip} -m comment --comment "SIH26145-{incident_id}" -j DROP',
    ]

    # Add subnet block if available and distinct from host
    if subnet and subnet != source_ip and "/" in subnet:
        lines += [
            "",
            f"# --- Block entire subnet {subnet} (high-confidence multi-source threat) ---",
            f'iptables  -I INPUT  2 -s {subnet} -m comment --comment "SIH26145-{incident_id}-subnet" -j DROP',
            f'ip6tables -I INPUT  2 -s {subnet} -m comment --comment "SIH26145-{incident_id}-subnet" -j DROP',
        ]

    # Add OUTPUT/FORWARD blocks toward known C2 targets
    if target_ips:
        lines += ["", "# --- Block outbound connections to known threat targets ---"]
        for tip in target_ips[:10]:  # cap to 10 for readability
            lines.append(
                f'iptables  -I OUTPUT 1 -d {tip} -m comment --comment "SIH26145-{incident_id}-c2" -j DROP'
            )

    # Port-specific blocks if available
    if target_ports:
        port_list = ",".join(str(p) for p in target_ports[:15])
        lines += [
            "",
            f"# --- Block suspicious destination ports: {port_list} ---",
            f'iptables  -I INPUT 1 -p tcp -m multiport --dports {port_list} -s {source_ip} -j DROP',
            f'iptables  -I INPUT 1 -p udp -m multiport --dports {port_list} -s {source_ip} -j DROP',
        ]

    lines += [
        "",
        "# --- Persist rules (Debian/Ubuntu) ---",
        "# netfilter-persistent save",
        "",
        "# --- Persist rules (RHEL/CentOS) ---",
        "# service iptables save",
        "",
        "echo 'SIH26145 iptables rules staged. Awaiting authorised deployment.'",
    ]

    return "\n".join(lines) + "\n"
