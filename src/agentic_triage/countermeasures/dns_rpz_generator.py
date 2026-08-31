"""
BIND 9 / Unbound DNS Response Policy Zone (RPZ) generator for SIH26145 SENTINEL.

Generates RPZ zone entries that sinkhole malicious domains and reverse-map
threat actor IPs to NXDOMAIN.
requires_human_approval: true
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_dns_rpz(incident: Dict[str, Any]) -> str:
    """
    Generate BIND 9 / Unbound DNS RPZ blocklist entries from a triage incident dict.

    The output is a partial zone-file snippet suitable for inclusion in an RPZ
    policy zone (e.g., rpz.sentinel.local). Malicious domains and IPs are
    sinkholed via CNAME . (NXDOMAIN action).

    Args:
        incident: Triage incident dict. May include 'malicious_domains' and/or
                  'target_ips' in addition to standard keys.

    Returns:
        A valid DNS zone-file text snippet.
    """
    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    source_ip: str = incident.get("source_ip", "0.0.0.0")
    target_ips: List[str] = incident.get("target_ips", [])
    threat_class: str = incident.get("primary_threat_class", "UNKNOWN")
    severity: str = incident.get("severity", "HIGH")
    risk_score: float = incident.get("risk_score", 0.0)
    malicious_domains: List[str] = incident.get("malicious_domains", [])

    now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # If no explicit domains, derive placeholder from threat class
    if not malicious_domains and "DGA" in threat_class.upper():
        malicious_domains = ["*.dga-threat.invalid", "dga-c2.invalid"]

    def _ip_to_rpz_ptr(ip: str) -> str:
        """Convert IPv4 address to RPZ IP-trigger format (reversed octet notation)."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return f"{'.'.join(reversed(parts))}.rpz-ip"
        except Exception:
            pass
        return f"{ip}.rpz-ip"

    lines: List[str] = [
        ";",
        "; =============================================================",
        "; SIH26145 SENTINEL — DNS RPZ Countermeasure Artifact",
        f"; Incident ID   : {incident_id}",
        f"; Generated     : {now_utc}",
        f"; Threat Class  : {threat_class}",
        f"; Severity      : {severity}  |  Risk Score: {risk_score:.1f}/100",
        ";",
        "; requires_human_approval: true",
        "; IMPORTANT: Validate entries and load into RPZ zone via",
        "; authorised change management. Do NOT auto-apply.",
        ";",
        "; BIND 9 named.conf snippet:",
        ";   zone \"rpz.sentinel.local\" {",
        ";     type master;",
        ";     file \"/etc/bind/rpz.sentinel.local.db\";",
        ";     allow-query { none; };",
        ";   };",
        "; =============================================================",
        "",
        f"$ORIGIN rpz.sentinel.local.",
        f"$TTL 300",
        "",
        "; --- SOA (include at top of full zone file) ---",
        f"; @ SOA ns1.sentinel.local. soc.sentinel.local. {int(datetime.now().timestamp())} 3600 900 86400 300",
        "",
    ]

    # Domain-based triggers
    if malicious_domains:
        lines.append("; --- Domain NXDOMAIN sinkhole entries ---")
        for domain in malicious_domains[:50]:
            d = domain.rstrip(".")
            lines.append(f"{d}        CNAME    .    ; requires_human_approval: true")
            lines.append(f"*.{d}     CNAME    .    ; wildcard subdomain block")
        lines.append("")

    # IP-based triggers (RPZ rpz-ip)
    block_ips = [source_ip] + list(target_ips[:10])
    if block_ips:
        lines.append("; --- IP NXDOMAIN triggers (rpz-ip) ---")
        for ip in block_ips:
            rpz_ptr = _ip_to_rpz_ptr(ip)
            lines.append(f"{rpz_ptr}  CNAME    .    ; block {ip} | requires_human_approval: true")
        lines.append("")

    lines += [
        "; --- Reload BIND after update ---",
        "; rndc reconfig && rndc zonestatus rpz.sentinel.local",
        "",
        "; --- Unbound RPZ import (if using Unbound 1.16+) ---",
        "; unbound-control rpz-enable rpz.sentinel.local",
    ]

    return "\n".join(lines) + "\n"
