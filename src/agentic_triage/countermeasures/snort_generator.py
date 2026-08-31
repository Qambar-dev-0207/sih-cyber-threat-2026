"""
Snort 3 / Suricata IDS rule generator for SIH26145 SENTINEL.

Generates valid Snort 3-syntax alert rules targeting specific attack signatures
derived from the triage incident context.
requires_human_approval: true
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


# SID base offset reserved for SIH26145 SENTINEL rules
_SENTINEL_SID_BASE = 9_700_000


def generate_snort_rules(incident: Dict[str, Any]) -> str:
    """
    Generate Snort 3 / Suricata IDS alert rules from a triage incident dict.

    Each generated rule is syntax-valid Snort 3 format and includes:
    - msg, sid, rev, classtype, priority, metadata fields
    - requires_human_approval marker in the metadata field

    Returns:
        A multi-line string of Snort 3 alert rules.
    """
    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    source_ip: str = incident.get("source_ip", "0.0.0.0")
    target_ips: List[str] = incident.get("target_ips", [])
    target_ports: List[int] = incident.get("target_ports", [])
    threat_class: str = incident.get("primary_threat_class", "UNKNOWN")
    severity: str = incident.get("severity", "HIGH")
    risk_score: float = incident.get("risk_score", 0.0)
    mitre_technique: str = incident.get("primary_mitre_technique", "T1595")
    ja4_fingerprint: str = incident.get("ja4_fingerprint", "")

    now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Map severity to Snort priority
    priority_map = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    priority = priority_map.get(severity.upper(), 2)

    # Determine classtype
    classtype_map = {
        "DDOS": "attempted-dos",
        "RECON": "network-scan",
        "PORT_SCAN": "network-scan",
        "DGA": "trojan-activity",
        "MALWARE": "trojan-activity",
        "C2": "command-and-control",
        "EXFIL": "policy-violation",
        "APT": "trojan-activity",
    }
    classtype = "suspicious-login"
    for key, ct in classtype_map.items():
        if key in threat_class.upper():
            classtype = ct
            break

    src_addr = f"[{source_ip}]"
    dst_addr = "any"
    if target_ips:
        dst_addr = "[" + ",".join(target_ips[:5]) + "]"

    port_str = "any"
    if target_ports:
        port_str = "[" + ",".join(str(p) for p in target_ports[:10]) + "]"

    sid = _SENTINEL_SID_BASE + abs(hash(incident_id)) % 100_000

    meta_base = (
        f'metadata: affected_system "Network", '
        f'attack_target "Host", '
        f'created_at "{now_utc}", '
        f'deployment "Perimeter", '
        f'mitre_technique "{mitre_technique}", '
        f'requires_human_approval "true", '
        f'sentinel_incident "{incident_id}", '
        f'severity "{severity}", '
        f'risk_score "{risk_score:.1f}"'
    )

    header = "\n".join([
        "# =============================================================",
        "# SIH26145 SENTINEL — Snort 3 / Suricata IDS Rules",
        f"# Incident ID   : {incident_id}",
        f"# Generated     : {now_utc}",
        f"# Threat Class  : {threat_class}",
        f"# Severity      : {severity}  |  Risk Score: {risk_score:.1f}/100",
        "#",
        "# requires_human_approval: true",
        "# IMPORTANT: Review rules before loading into production IDS.",
        "# DO NOT auto-deploy from the monitoring enclave.",
        "# =============================================================",
        "",
    ])

    rules: List[str] = [header]

    # Rule 1: Primary TCP alert for source IP
    rules.append(
        f'alert tcp {src_addr} any -> any any '
        f'(msg:"SIH26145 {incident_id} {threat_class} TCP from threat actor"; '
        f'flow:established; '
        f'classtype:{classtype}; priority:{priority}; '
        f'sid:{sid}; rev:1; '
        f'{meta_base};)'
    )

    # Rule 2: UDP variant
    rules.append(
        f'alert udp {src_addr} any -> any any '
        f'(msg:"SIH26145 {incident_id} {threat_class} UDP from threat actor"; '
        f'classtype:{classtype}; priority:{priority}; '
        f'sid:{sid + 1}; rev:1; '
        f'{meta_base};)'
    )

    # Rule 3: Port-specific rule if target ports available
    if target_ports:
        rules.append(
            f'alert tcp {src_addr} any -> {dst_addr} {port_str} '
            f'(msg:"SIH26145 {incident_id} {threat_class} targeted port activity"; '
            f'flow:to_server,established; '
            f'classtype:{classtype}; priority:{priority}; '
            f'sid:{sid + 2}; rev:1; '
            f'{meta_base};)'
        )

    # Rule 4: JA4 TLS fingerprint rule (Snort 3 tls keyword)
    if ja4_fingerprint:
        rules.append(
            f'alert tls any any -> any any '
            f'(msg:"SIH26145 {incident_id} Malicious JA4 fingerprint {ja4_fingerprint}"; '
            f'tls.ja4:"{ja4_fingerprint}"; '
            f'classtype:trojan-activity; priority:{priority}; '
            f'sid:{sid + 3}; rev:1; '
            f'{meta_base};)'
        )

    # Rule 5: ICMP flood (for DDoS classification)
    if "DDOS" in threat_class.upper() or "DENIAL_OF_SERVICE" in threat_class.upper() or "DENIAL" in threat_class.upper():
        rules.append(
            f'alert icmp {src_addr} any -> any any '
            f'(msg:"SIH26145 {incident_id} ICMP Flood from threat actor"; '
            f'classtype:attempted-dos; priority:1; '
            f'threshold:type both,track by_src,count 500,seconds 10; '
            f'sid:{sid + 4}; rev:1; '
            f'{meta_base};)'
        )

    rules.append("")
    rules.append(f"# Load into Snort 3: snort -c snort.lua --plugin-path /path/to/rules/")
    rules.append(f"# Load into Suricata: suricata-update add-source sentinel-{incident_id} <rule_file>")

    return "\n".join(rules) + "\n"
