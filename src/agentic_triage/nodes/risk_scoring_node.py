from __future__ import annotations

from typing import Any, Dict, List, Optional
from src.agentic_triage.state import RiskBreakdown, RiskEvidenceItem, TriageStateDict


BASE_THREAT_WEIGHTS: Dict[str, float] = {
    "C2_BEACONING": 40.0,
    "c2_beaconing": 40.0,
    "c2_beacon": 40.0,
    "ENCRYPTED_MALWARE": 40.0,
    "encrypted_malware": 40.0,
    "ja4_malware": 40.0,
    "DATA_EXFILTRATION": 35.0,
    "exfil_ratio": 35.0,
    "DGA_TUNNELLING": 30.0,
    "dga_tunneling": 30.0,
    "dga_lstm": 30.0,
    "VOLUMETRIC_DDOS": 30.0,
    "PROTOCOL_DDOS": 30.0,
    "ddos_entropy": 30.0,
    "PORT_SCAN_RECON": 15.0,
    "portscan_hll": 15.0,
    "port_scan": 15.0,
    "recon_sweep": 15.0,
}

CANONICAL_THREAT_CLASS: Dict[str, str] = {
    "c2_beaconing": "C2_BEACONING",
    "c2_beacon": "C2_BEACONING",
    "encrypted_malware": "ENCRYPTED_MALWARE",
    "ja4_malware": "ENCRYPTED_MALWARE",
    "exfil_ratio": "DATA_EXFILTRATION",
    "dga_tunneling": "DGA_TUNNELLING",
    "dga_lstm": "DGA_TUNNELLING",
    "ddos_entropy": "VOLUMETRIC_DDOS",
    "portscan_hll": "PORT_SCAN_RECON",
    "port_scan": "PORT_SCAN_RECON",
    "recon_sweep": "PORT_SCAN_RECON",
}


class RiskScoringNode:
    """Node 2: Explainable mathematical risk score computation with transparent evidence weighting."""

    def __init__(self):
        pass

    def __call__(self, state: TriageStateDict) -> TriageStateDict:
        return self.execute(state)

    def execute(self, state: TriageStateDict) -> TriageStateDict:
        # Collect threat classes and maximum confidence per threat class
        threat_evidence_map: Dict[str, Dict[str, Any]] = {}

        # 1. From timeline or raw alerts
        alerts = state.get("timeline") or state.get("fused_alerts") or []
        for item in alerts:
            threat = item.get("threat_class") or "UNKNOWN"
            canonical_threat = CANONICAL_THREAT_CLASS.get(threat, threat)
            detector = item.get("detector") or item.get("detector_name") or "detector"
            conf = float(item.get("confidence", 0.8))
            summary = item.get("summary", "")

            if canonical_threat not in threat_evidence_map:
                threat_evidence_map[canonical_threat] = {
                    "detector": detector,
                    "max_confidence": conf,
                    "summary": summary,
                }
            else:
                if conf > threat_evidence_map[canonical_threat]["max_confidence"]:
                    threat_evidence_map[canonical_threat]["max_confidence"] = conf
                    threat_evidence_map[canonical_threat]["detector"] = detector
                    if summary:
                        threat_evidence_map[canonical_threat]["summary"] = summary

        # If no timeline/alerts, fall back to threat_classes_observed or incident
        if not threat_evidence_map:
            observed = state.get("threat_classes_observed", [])
            for threat in observed:
                canonical_threat = CANONICAL_THREAT_CLASS.get(threat, threat)
                threat_evidence_map[canonical_threat] = {
                    "detector": "detector",
                    "max_confidence": 0.8,
                    "summary": f"Observed {canonical_threat}",
                }

        # If still empty, check primary_threat_class
        if not threat_evidence_map:
            pt = state.get("primary_threat_class", "UNKNOWN")
            canonical_threat = CANONICAL_THREAT_CLASS.get(pt, pt)
            threat_evidence_map[canonical_threat] = {
                "detector": "detector",
                "max_confidence": 0.5,
                "summary": f"Observed {canonical_threat}",
            }

        # 2. Compute Base Risk Sum w_i * c_i
        evidence_items: List[RiskEvidenceItem] = []
        base_risk_sum = 0.0

        for threat_cls, ev in sorted(threat_evidence_map.items()):
            base_w = BASE_THREAT_WEIGHTS.get(threat_cls, 20.0)
            conf = ev["max_confidence"]
            weighted_score = round(base_w * conf, 2)
            base_risk_sum += weighted_score

            evidence_items.append(
                RiskEvidenceItem(
                    threat_class=threat_cls,
                    detector=ev["detector"],
                    base_weight=base_w,
                    confidence=conf,
                    weighted_score=weighted_score,
                    metric_summary=ev.get("summary", ""),
                )
            )

        base_risk_sum = round(base_risk_sum, 2)
        k = len(evidence_items)

        # 3. Multi-Detector Synergy Bonus
        if k >= 3:
            synergy_bonus = 20.0
            synergy_reason = f"{k} distinct threat classes observed resulting in +20.0 synergy bonus (multi-stage kill-chain)"
        elif k == 2:
            synergy_bonus = 10.0
            threat_names = " + ".join(i.threat_class for i in evidence_items)
            synergy_reason = f"2 distinct threat classes observed ({threat_names}) resulting in +10.0 synergy bonus"
        else:
            synergy_bonus = 0.0
            synergy_reason = "Single threat vector observed; 0.0 synergy bonus"

        # 4. Asset Criticality Multiplier
        alpha = float(state.get("asset_criticality", 1.0))
        alpha = max(1.0, min(2.0, alpha))

        # 5. Adjusted & Final Risk Score
        base_risk = base_risk_sum + synergy_bonus
        adjusted_risk = base_risk * alpha
        final_risk_score = round(min(100.0, max(0.0, adjusted_risk)), 2)

        # 6. Severity Classification
        if final_risk_score >= 85.0:
            severity = "CRITICAL"
        elif final_risk_score >= 65.0:
            severity = "HIGH"
        elif final_risk_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        formula_str = f"min(100.0, ({base_risk_sum:.2f} [Base Sum] + {synergy_bonus:.2f} [Synergy]) * {alpha:.2f} [Asset Alpha])"

        risk_breakdown = RiskBreakdown(
            base_risk_sum=base_risk_sum,
            synergy_bonus=synergy_bonus,
            asset_criticality_multiplier=alpha,
            final_risk_score=final_risk_score,
            severity=severity,
            formula=formula_str,
            evidence_breakdown=evidence_items,
            synergy_reason=synergy_reason,
        )

        state["risk_score"] = final_risk_score
        state["severity"] = severity
        state["risk_breakdown"] = risk_breakdown.model_dump()

        return state
