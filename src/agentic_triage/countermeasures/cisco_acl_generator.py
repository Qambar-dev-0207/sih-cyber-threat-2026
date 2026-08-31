"""
Cisco IOS Extended Named ACL generator for SIH26145 SENTINEL.

Generates valid Cisco IOS extended named ACL definitions for layer 3/4 blocking.
requires_human_approval: true
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_cisco_acl(incident: Dict[str, Any]) -> str:
    """
    Generate Cisco IOS extended named ACL commands from a triage incident dict.

    Returns IOS-syntax configuration lines suitable for pasting into a privileged
    exec session or a Cisco configuration file.
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
    acl_name = f"SENTINEL-BLOCK-{incident_id.replace('INC-', '').replace('-', '')}"

    def _wildcard(cidr: str) -> str:
        """Convert CIDR prefix length to IOS wildcard mask."""
        try:
            if "/" in cidr:
                ip_part, prefix = cidr.split("/")
                prefix_len = int(prefix)
                wc_int = (1 << (32 - prefix_len)) - 1
                octets = [(wc_int >> (8 * i)) & 0xFF for i in reversed(range(4))]
                return f"{ip_part} {'.'.join(str(o) for o in octets)}"
        except Exception:
            pass
        return f"{cidr} 0.0.0.0"

    lines: List[str] = [
        "!",
        "! =============================================================",
        "! SIH26145 SENTINEL — Cisco IOS ACL Countermeasure Artifact",
        f"! Incident ID   : {incident_id}",
        f"! Generated     : {now_utc}",
        f"! Threat Class  : {threat_class}",
        f"! Severity      : {severity}  |  Risk Score: {risk_score:.1f}/100",
        "!",
        "! requires_human_approval: true",
        "! IMPORTANT: Review and apply via authorised change management.",
        "! DO NOT deploy automatically from the monitoring enclave.",
        "! =============================================================",
        "!",
        f"ip access-list extended {acl_name}",
        " remark SIH26145 SENTINEL auto-generated block — REQUIRES HUMAN APPROVAL",
        f" remark Incident: {incident_id} | Threat: {threat_class} | Severity: {severity}",
        " remark Generated: " + now_utc,
        "!",
    ]

    # Block source IP (host entry)
    lines.append(f" 10 deny ip host {source_ip} any log")

    # Block subnet if available
    if subnet and "/" in subnet:
        wc = _wildcard(subnet)
        lines.append(f" 20 deny ip {wc} any log")

    # Block specific port pairs toward any destination
    seq = 30
    for port in target_ports[:10]:
        lines.append(f" {seq} deny tcp host {source_ip} any eq {port} log")
        seq += 10
        lines.append(f" {seq} deny udp host {source_ip} any eq {port} log")
        seq += 10

    # Block known C2 targets (permit from internal -> C2 is suspicious)
    for tip in target_ips[:5]:
        lines.append(f" {seq} deny ip any host {tip} log")
        seq += 10

    lines += [
        f" {seq} permit ip any any",
        "!",
        "! --- Apply ACL to WAN-facing interface (example) ---",
        "! interface GigabitEthernet0/0/0",
        f"!  ip access-group {acl_name} in",
        "!",
        "! Verify: show ip access-lists " + acl_name,
    ]

    return "\n".join(lines) + "\n"
