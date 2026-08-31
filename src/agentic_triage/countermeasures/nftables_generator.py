"""
nftables ruleset generator for SIH26145 SENTINEL.

Generates copy-pasteable nftables nft(8) commands (set-based IP blocklist)
targeting the threat source.
requires_human_approval: true
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_nftables(incident: Dict[str, Any]) -> str:
    """
    Generate nftables blocking rules from a triage incident dict.

    Returns a valid nft(8) script string using set-based IP blocklists.
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

    # Build blocked IP set elements
    blocked_ips = [source_ip]
    if subnet and subnet != source_ip and "/" in subnet:
        blocked_ips.append(subnet)
    blocked_ips_str = ", ".join(f'"{ip}"' for ip in blocked_ips)

    # Build C2 target set
    c2_ips = target_ips[:10]
    c2_ips_str = ", ".join(f'"{ip}"' for ip in c2_ips) if c2_ips else '""'

    # Build port set
    ports_str = ", ".join(str(p) for p in target_ports[:15]) if target_ports else ""

    lines: List[str] = [
        "#!/usr/sbin/nft -f",
        "# =============================================================",
        "# SIH26145 SENTINEL — nftables Countermeasure Artifact",
        f"# Incident ID   : {incident_id}",
        f"# Generated     : {now_utc}",
        f"# Threat Class  : {threat_class}",
        f"# Severity      : {severity}  |  Risk Score: {risk_score:.1f}/100",
        "#",
        "# requires_human_approval: true",
        "# IMPORTANT: Review and deploy via authorised change management.",
        "# DO NOT execute automatically from the monitoring enclave.",
        "# =============================================================",
        "",
        "# Ensure base filter table exists",
        "add table inet sentinel_filter",
        "",
        "# --- Threat source blocklist set ---",
        "add set inet sentinel_filter sih26145_blocked_src {",
        "    type ipv4_addr ;",
        "    flags interval ;",
        "    comment \"SIH26145 blocked source IPs\" ;",
        f"    elements = {{ {blocked_ips_str} }}",
        "}",
        "",
        "# --- C2 target blocklist set ---",
    ]

    if c2_ips:
        lines += [
            "add set inet sentinel_filter sih26145_c2_targets {",
            "    type ipv4_addr ;",
            "    flags interval ;",
            "    comment \"SIH26145 C2/target IPs\" ;",
            f"    elements = {{ {c2_ips_str} }}",
            "}",
            "",
        ]

    lines += [
        "# --- Drop INPUT from blocked sources ---",
        "add chain inet sentinel_filter input { type filter hook input priority 0 ; policy accept ; }",
        f'add rule inet sentinel_filter input ip saddr @sih26145_blocked_src log prefix "SIH26145-DROP-IN: " drop',
        "",
        "# --- Drop FORWARD from blocked sources ---",
        "add chain inet sentinel_filter forward { type filter hook forward priority 0 ; policy accept ; }",
        f'add rule inet sentinel_filter forward ip saddr @sih26145_blocked_src log prefix "SIH26145-DROP-FWD: " drop',
    ]

    if c2_ips:
        lines += [
            "",
            "# --- Drop OUTPUT to C2 targets ---",
            "add chain inet sentinel_filter output { type filter hook output priority 0 ; policy accept ; }",
            f'add rule inet sentinel_filter output ip daddr @sih26145_c2_targets log prefix "SIH26145-DROP-OUT: " drop',
        ]

    if ports_str:
        lines += [
            "",
            f"# --- Block suspicious ports: {ports_str} from threat source ---",
            f'add rule inet sentinel_filter input ip saddr {source_ip} tcp dport {{ {ports_str} }} drop',
            f'add rule inet sentinel_filter input ip saddr {source_ip} udp dport {{ {ports_str} }} drop',
        ]

    lines += [
        "",
        "# Apply: nft -f <this_file>",
        "# List:  nft list ruleset",
        "# Flush: nft flush ruleset",
    ]

    return "\n".join(lines) + "\n"
