from __future__ import annotations

import datetime
import time
from typing import Any, Dict, List
import jinja2

EXECUTIVE_NARRATIVE_TEMPLATE = """================================================================================
EXECUTIVE INCIDENT SUMMARY: {{ incident_id }}
CLASSIFICATION: {{ primary_threat_class }} ({{ severity }} — Risk Score: {{ "%.2f"|format(risk_score) }}/100)
PRIMARY ATTACKER / COMPROMISED HOST: {{ source_ip }}{% if asset_role %} ({{ asset_role }}){% endif %}
TARGETED ENDPOINTS: {{ target_endpoints_str }}
================================================================================

1. INCIDENT OVERVIEW
Between {{ start_iso }} and {{ end_iso }} (Duration: {{ "%.1f"|format(duration_sec) }}s), 
host {{ source_ip }} exhibited {{ severity|lower }}-confidence {{ attack_nature_desc }}.
The passive detection system correlated {{ threat_vector_count }} distinct threat vector(s) across {{ raw_alert_count }} raw alert event(s), 
transitioning through the following operational kill-chain phases: {{ kill_chain_summary }}.

2. CHRONOLOGICAL ATTACK TIMELINE & KILL-CHAIN PHASES
{% for step in timeline %}
• [T+{{ "%.1f"|format(step.relative_time_offset_sec) }}s] [{{ step.stage }} - {{ step.technique_id|default('T1595') }}] {{ step.detector }}: {{ step.summary }}
{% endfor %}

3. IMPACT & RISK ASSESSMENT
Asset Role: {{ asset_role|default('INTERNAL_WORKSTATION') }} (Asset Criticality Multiplier: {{ "%.2f"|format(asset_criticality) }}x)
Base Risk: {{ "%.2f"|format(risk_breakdown.base_risk_sum|default(0.0)) }} | Synergy Bonus: +{{ "%.2f"|format(risk_breakdown.synergy_bonus|default(0.0)) }} | Final Score: {{ "%.2f"|format(risk_score) }} ({{ severity }})
Exposure: {{ exposure_summary }}

4. RECOMMENDED COUNTERMEASURES (REQUIRES HUMAN AUTHORIZATION)
• Perimeter Defense: Block traffic associated with {{ source_ip }} / target endpoints.
• Host Isolation: Quarantine or isolate compromised host {{ source_ip }} pending forensic inspection.
• Threat Intelligence: Ingest indicators into defensive security tooling and SIEM.
• Policy Enforcement: Verify zero return-path data diode integrity.
================================================================================"""


def _format_iso_time(ts: float) -> str:
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def render_executive_narrative(context: Dict[str, Any]) -> str:
    """Render an executive-level attack narrative from triage state context using Jinja2 or deterministic string formatting."""
    # Populate default/derived values
    incident_id = context.get("incident_id", "INC-UNKNOWN")
    primary_threat_class = context.get("primary_threat_class", "SUSPICIOUS_NETWORK_ACTIVITY")
    severity = context.get("severity", "MEDIUM")
    risk_score = float(context.get("risk_score", 50.0))
    source_ip = context.get("source_ip", "0.0.0.0")
    asset_role = context.get("asset_role", "INTERNAL_WORKSTATION")
    asset_criticality = float(context.get("asset_criticality", 1.0))
    raw_alert_count = int(context.get("raw_alert_count", len(context.get("fused_alerts", []))))
    
    target_ips = context.get("target_ips", [])
    target_ports = context.get("target_ports", [])
    if target_ips:
        if target_ports:
            ports_str = ",".join(str(p) for p in target_ports[:3])
            target_endpoints_str = ", ".join(f"{ip}:{ports_str}" for ip in target_ips[:3])
        else:
            target_endpoints_str = ", ".join(target_ips[:3])
    else:
        target_endpoints_str = "Internal Subnet Broadcast"

    created_at = float(context.get("created_at", time.time()))
    updated_at = float(context.get("updated_at", created_at))
    duration_sec = max(0.0, updated_at - created_at)
    start_iso = _format_iso_time(created_at)
    end_iso = _format_iso_time(updated_at)

    timeline = context.get("timeline", [])
    threat_classes_observed = context.get("threat_classes_observed", [primary_threat_class])
    threat_vector_count = max(1, len(threat_classes_observed))

    if len(threat_classes_observed) >= 3:
        attack_nature_desc = "multi-stage advanced persistent threat (APT) intrusion activity"
    elif len(threat_classes_observed) == 2:
        attack_nature_desc = f"correlated multi-vector adversary activity ({' + '.join(threat_classes_observed)})"
    else:
        attack_nature_desc = f"focused adversary activity ({primary_threat_class})"

    kill_chain_stages = sorted(list({step.get("stage", "EXECUTION") for step in timeline if isinstance(step, dict)}))
    kill_chain_summary = " -> ".join(kill_chain_stages) if kill_chain_stages else "DETECTED_ANOMALY"

    exposure_summary = f"Risk of persistent access, lateral movement, or data loss across asset {source_ip} (Subnet: {context.get('subnet', '192.168.1.0/24')})."

    risk_breakdown = context.get("risk_breakdown", {})

    render_ctx = {
        "incident_id": incident_id,
        "primary_threat_class": primary_threat_class,
        "severity": severity,
        "risk_score": risk_score,
        "source_ip": source_ip,
        "asset_role": asset_role,
        "target_endpoints_str": target_endpoints_str,
        "start_iso": start_iso,
        "end_iso": end_iso,
        "duration_sec": duration_sec,
        "attack_nature_desc": attack_nature_desc,
        "threat_vector_count": threat_vector_count,
        "raw_alert_count": raw_alert_count,
        "kill_chain_summary": kill_chain_summary,
        "timeline": timeline,
        "asset_criticality": asset_criticality,
        "risk_breakdown": risk_breakdown,
        "exposure_summary": exposure_summary,
    }

    try:
        env = jinja2.Environment(undefined=jinja2.Undefined)
        template = env.from_string(EXECUTIVE_NARRATIVE_TEMPLATE)
        return template.render(**render_ctx)
    except Exception:
        # Robust string fallback
        lines = [
            "=" * 80,
            f"EXECUTIVE INCIDENT SUMMARY: {incident_id}",
            f"CLASSIFICATION: {primary_threat_class} ({severity} — Risk Score: {risk_score:.2f}/100)",
            f"PRIMARY ATTACKER / COMPROMISED HOST: {source_ip} ({asset_role})",
            f"TARGETED ENDPOINTS: {target_endpoints_str}",
            "=" * 80,
            "",
            "1. INCIDENT OVERVIEW",
            f"Between {start_iso} and {end_iso} (Duration: {duration_sec:.1f}s), host {source_ip} exhibited {severity.lower()} adversary activity.",
            f"Correlated {threat_vector_count} threat vector(s) across {raw_alert_count} alert event(s).",
            "",
            "2. CHRONOLOGICAL ATTACK TIMELINE",
        ]
        for step in timeline:
            rel = step.get("relative_time_offset_sec", 0.0)
            stg = step.get("stage", "RECONNAISSANCE")
            det = step.get("detector", "")
            sum_txt = step.get("summary", "")
            lines.append(f"• [T+{rel:.1f}s] [{stg}] {det}: {sum_txt}")
        lines.extend([
            "",
            "3. IMPACT & RISK ASSESSMENT",
            f"Asset Criticality Multiplier: {asset_criticality:.2f}x | Final Score: {risk_score:.2f} ({severity})",
            exposure_summary,
            "",
            "4. RECOMMENDED COUNTERMEASURES (REQUIRES HUMAN AUTHORIZATION)",
            f"• Perimeter Defense: Block {source_ip} on boundary firewalls.",
            f"• Host Isolation: Quarantine {source_ip} pending investigation.",
            "=" * 80,
        ])
        return "\n".join(lines)
