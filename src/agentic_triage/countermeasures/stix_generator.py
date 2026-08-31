"""
STIX 2.1 JSON Threat Intelligence Bundle generator for SIH26145 SENTINEL.

Generates valid STIX 2.1 bundles containing:
- Indicator SDOs (IP and domain pattern indicators)
- Attack Pattern SDOs (MITRE ATT&CK references)
- Threat Actor SDO (adversary attribution stub)
- Relationship SROs linking objects

requires_human_approval: true
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _stix_ts(dt: Optional[datetime] = None) -> str:
    """Return a STIX 2.1 compliant timestamp string (RFC 3339, UTC, millisecond precision)."""
    if dt is None:
        dt = datetime.now(tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _uuid5_stix(namespace: str, name: str) -> str:
    """Generate a deterministic UUID5 for STIX object IDs."""
    ns = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # STIX namespace
    return str(uuid.uuid5(ns, f"{namespace}:{name}"))


def generate_stix_bundle(incident: Dict[str, Any]) -> str:
    """
    Generate a STIX 2.1 JSON Threat Intelligence Bundle from a triage incident dict.

    Args:
        incident: Triage incident dict with keys: incident_id, source_ip, target_ips,
                  primary_threat_class, primary_mitre_technique, mitre_mappings,
                  risk_score, severity, malicious_domains (optional).

    Returns:
        A JSON-serialized STIX 2.1 bundle string (valid json.loads() target).
    """
    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    source_ip: str = incident.get("source_ip", "0.0.0.0")
    target_ips: List[str] = incident.get("target_ips", [])
    target_ports: List[int] = incident.get("target_ports", [])
    threat_class: str = incident.get("primary_threat_class", "UNKNOWN")
    severity: str = incident.get("severity", "HIGH")
    risk_score: float = incident.get("risk_score", 0.0)
    mitre_technique: str = incident.get("primary_mitre_technique", "T1595")
    mitre_mappings: List[Dict[str, Any]] = incident.get("mitre_mappings", [])
    malicious_domains: List[str] = incident.get("malicious_domains", [])

    now = datetime.now(tz=timezone.utc)
    now_ts = _stix_ts(now)
    # Validity: 90 days
    valid_until_ts = _stix_ts(datetime(now.year, now.month, now.day, tzinfo=timezone.utc).replace(
        day=min(now.day + 90, 28)
    ))

    objects: List[Dict[str, Any]] = []

    # ── 1. Identity SDO (reporting organisation) ─────────────────────────────
    identity_id = f"identity--{_uuid5_stix('identity', 'SIH26145-SENTINEL')}"
    identity_obj: Dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_ts,
        "modified": now_ts,
        "name": "SIH26145 SENTINEL",
        "description": "Passive network monitoring system — NTRO SIH 2026",
        "identity_class": "system",
        "labels": ["automated-triage", "sentinel", "requires_human_approval"],
    }
    objects.append(identity_obj)

    # ── 2. Threat Actor SDO ───────────────────────────────────────────────────
    actor_id = f"threat-actor--{_uuid5_stix('threat-actor', source_ip)}"
    actor_obj: Dict[str, Any] = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": actor_id,
        "created": now_ts,
        "modified": now_ts,
        "name": f"Unattributed Threat Actor [{source_ip}]",
        "description": (
            f"Source of {threat_class} threat activity observed in incident {incident_id}. "
            f"Risk Score: {risk_score:.1f}/100, Severity: {severity}. "
            f"requires_human_approval: true — attribution is unconfirmed."
        ),
        "threat_actor_types": ["unknown"],
        "sophistication": "intermediate" if risk_score >= 60 else "novice",
        "resource_level": "individual",
        "primary_motivation": "organizational-gain",
        "labels": ["sih26145", incident_id, "requires_human_approval"],
        "created_by_ref": identity_id,
    }
    objects.append(actor_obj)

    # ── 3. Attack Pattern SDOs (MITRE ATT&CK) ────────────────────────────────
    attack_pattern_ids: List[str] = []
    seen_techniques = set()

    # Primary technique first
    all_mitre = [{"technique_id": mitre_technique, "technique_name": threat_class}]
    for m in mitre_mappings[:5]:
        tid = m.get("technique_id", "")
        if tid and tid not in seen_techniques:
            all_mitre.append(m)

    for m_entry in all_mitre[:6]:
        technique_id = m_entry.get("technique_id", mitre_technique) if isinstance(m_entry, dict) else mitre_technique
        technique_name = m_entry.get("technique_name", threat_class) if isinstance(m_entry, dict) else threat_class
        if technique_id in seen_techniques:
            continue
        seen_techniques.add(technique_id)

        ap_id = f"attack-pattern--{_uuid5_stix('attack-pattern', technique_id)}"
        attack_pattern_ids.append(ap_id)
        ap_obj: Dict[str, Any] = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now_ts,
            "modified": now_ts,
            "name": technique_name,
            "description": f"MITRE ATT&CK Technique {technique_id}: {technique_name}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": m_entry.get("kill_chain_phase", "unknown").lower().replace(" ", "-")
                    if isinstance(m_entry, dict) else "unknown",
                }
            ],
            "created_by_ref": identity_id,
        }
        objects.append(ap_obj)

    # ── 4. Indicator SDOs ─────────────────────────────────────────────────────
    indicator_ids: List[str] = []

    # Source IP indicator
    src_indicator_id = f"indicator--{_uuid5_stix('indicator-ip', source_ip)}"
    indicator_ids.append(src_indicator_id)
    port_context = f" (ports: {', '.join(str(p) for p in target_ports[:5])})" if target_ports else ""
    objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": src_indicator_id,
        "created": now_ts,
        "modified": now_ts,
        "name": f"Malicious IP: {source_ip}",
        "description": (
            f"Source IP {source_ip} observed conducting {threat_class} activity{port_context}. "
            f"Incident {incident_id}. requires_human_approval: true"
        ),
        "indicator_types": ["malicious-activity", "anomalous-activity"],
        "pattern": f"[ipv4-addr:value = '{source_ip}']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now_ts,
        "valid_until": valid_until_ts,
        "confidence": min(100, int(risk_score)),
        "labels": ["sih26145", "requires_human_approval", severity.lower()],
        "created_by_ref": identity_id,
    })

    # C2 target indicators
    for tip in target_ips[:5]:
        tip_ind_id = f"indicator--{_uuid5_stix('indicator-ip', f'c2-{tip}')}"
        indicator_ids.append(tip_ind_id)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": tip_ind_id,
            "created": now_ts,
            "modified": now_ts,
            "name": f"C2/Target IP: {tip}",
            "description": f"IP {tip} involved in {threat_class} incident {incident_id}. requires_human_approval: true",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{tip}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now_ts,
            "valid_until": valid_until_ts,
            "confidence": min(80, int(risk_score * 0.8)),
            "labels": ["sih26145", "requires_human_approval"],
            "created_by_ref": identity_id,
        })

    # Domain indicators
    for domain in malicious_domains[:10]:
        dom_id = f"indicator--{_uuid5_stix('indicator-domain', domain)}"
        indicator_ids.append(dom_id)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": dom_id,
            "created": now_ts,
            "modified": now_ts,
            "name": f"Malicious Domain: {domain}",
            "description": f"DGA/C2 domain {domain} associated with incident {incident_id}. requires_human_approval: true",
            "indicator_types": ["malicious-activity", "compromised"],
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now_ts,
            "valid_until": valid_until_ts,
            "confidence": min(90, int(risk_score * 0.9)),
            "labels": ["sih26145", "dga", "requires_human_approval"],
            "created_by_ref": identity_id,
        })

    # ── 5. Relationship SROs ──────────────────────────────────────────────────
    # Threat Actor → Attack Patterns
    for ap_id in attack_pattern_ids:
        rel_id = f"relationship--{_uuid5_stix('rel', f'{actor_id}-uses-{ap_id}')}"
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": now_ts,
            "modified": now_ts,
            "relationship_type": "uses",
            "source_ref": actor_id,
            "target_ref": ap_id,
            "created_by_ref": identity_id,
        })

    # Indicators → Attack Patterns (indicates)
    for ind_id in indicator_ids[:3]:
        for ap_id in attack_pattern_ids[:2]:
            rel_id = f"relationship--{_uuid5_stix('rel', f'{ind_id}-indicates-{ap_id}')}"
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now_ts,
                "modified": now_ts,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": ap_id,
                "created_by_ref": identity_id,
            })

    # ── 6. Note SDO (human approval requirement) ──────────────────────────────
    note_id = f"note--{_uuid5_stix('note', incident_id)}"
    objects.append({
        "type": "note",
        "spec_version": "2.1",
        "id": note_id,
        "created": now_ts,
        "modified": now_ts,
        "abstract": "SENTINEL Triage Artifact — Requires Human Approval",
        "content": (
            f"This STIX 2.1 bundle was automatically generated by SIH26145 SENTINEL "
            f"for incident {incident_id} (Risk: {risk_score:.1f}/100, Severity: {severity}). "
            f"The monitoring system operates under a strict data-diode read-only boundary. "
            f"All countermeasures require authorised human review and deployment. "
            f"requires_human_approval: true."
        ),
        "object_refs": indicator_ids[:3] + attack_pattern_ids[:2],
        "created_by_ref": identity_id,
        "labels": ["requires_human_approval", "sentinel-triage"],
    })

    # ── Assemble Bundle ───────────────────────────────────────────────────────
    bundle: Dict[str, Any] = {
        "type": "bundle",
        "id": f"bundle--{_uuid5_stix('bundle', incident_id)}",
        "spec_version": "2.1",
        "objects": objects,
    }

    return json.dumps(bundle, indent=2, ensure_ascii=False)
