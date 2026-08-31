from __future__ import annotations

import datetime
import time
from typing import Any, Dict, List, Optional
from src.agentic_triage.knowledge.mitre_catalog import get_mitre_entry
from src.agentic_triage.state import TimelineStep, TriageStateDict


ASSET_ROLE_CRITICALITY: Dict[str, float] = {
    "INTERNAL_WORKSTATION": 1.0,
    "WORKSTATION": 1.0,
    "USER_ENDPOINT": 1.0,
    "APP_SERVER": 1.25,
    "INTERNAL_SERVER": 1.25,
    "WEB_SERVER": 1.25,
    "DATABASE_SERVER": 1.5,
    "PROD_DB": 1.5,
    "DOMAIN_CONTROLLER": 1.75,
    "AUTH_SERVER": 1.75,
    "LDAP_SERVER": 1.75,
    "GATEWAY_FIREWALL": 2.0,
    "DIODE_ROOT": 2.0,
    "CRITICAL_ENCLAVE": 2.0,
    "INFRASTRUCTURE_ROUTER": 2.0,
}


STAGE_BY_THREAT_CLASS: Dict[str, str] = {
    "PORT_SCAN_RECON": "RECONNAISSANCE",
    "port_scan": "RECONNAISSANCE",
    "recon_sweep": "RECONNAISSANCE",
    "DGA_TUNNELLING": "WEAPONIZATION",
    "dga_lstm": "WEAPONIZATION",
    "ENCRYPTED_MALWARE": "COMMAND_AND_CONTROL",
    "ja4_malware": "COMMAND_AND_CONTROL",
    "C2_BEACONING": "COMMAND_AND_CONTROL",
    "c2_beacon": "COMMAND_AND_CONTROL",
    "DATA_EXFILTRATION": "EXFILTRATION",
    "exfil_ratio": "EXFILTRATION",
    "VOLUMETRIC_DDOS": "IMPACT",
    "PROTOCOL_DDOS": "IMPACT",
    "ddos_entropy": "IMPACT",
}


class CorrelationNode:
    """Node 1: Chronological timeline synthesis, temporal interval grouping, and host telemetry enrichment."""

    def __init__(self, db: Any = None):
        self.db = db

    def __call__(self, state: TriageStateDict) -> TriageStateDict:
        return self.execute(state)

    def execute(self, state: TriageStateDict) -> TriageStateDict:
        raw_alerts_data = self._extract_raw_alerts(state)

        if not raw_alerts_data:
            # Empty fallback
            now = time.time()
            state["timeline"] = []
            state["timeline_summary"] = "No alert events observed in incident buffer."
            state["threat_classes_observed"] = state.get("threat_classes_observed", [])
            state["is_multi_stage"] = False
            state["asset_criticality"] = float(state.get("asset_criticality", 1.0))
            state["asset_role"] = state.get("asset_role", "INTERNAL_WORKSTATION")
            return state

        # 1. Chronological sorting t1 <= t2 <= ... <= tn
        sorted_alerts = sorted(
            raw_alerts_data,
            key=lambda a: float(a.get("timestamp", 0.0) or 0.0)
        )

        t_0 = float(sorted_alerts[0].get("timestamp", time.time()))
        t_end = float(sorted_alerts[-1].get("timestamp", t_0))

        # 2. Timeline Step Synthesis & Deduplication
        timeline_steps: List[Dict[str, Any]] = []
        observed_threats: set[str] = set()
        target_ips: set[str] = set(state.get("target_ips", []))
        target_ports: set[int] = set(state.get("target_ports", []))
        protocols: set[str] = set(state.get("protocols", []))

        step_idx = 1
        for alert in sorted_alerts:
            ts = float(alert.get("timestamp", t_0))
            rel_offset = max(0.0, ts - t_0)
            threat_cls = str(alert.get("threat_class", "UNKNOWN"))
            observed_threats.add(threat_cls)

            det_name = str(alert.get("detector_name") or alert.get("detector_id") or alert.get("detector") or "detector")
            stage = alert.get("stage") or STAGE_BY_THREAT_CLASS.get(threat_cls, "EXECUTION")
            
            tgt_ip = alert.get("target_ip")
            if tgt_ip:
                target_ips.add(str(tgt_ip))
            tgt_port = alert.get("target_port")
            if tgt_port is not None:
                try:
                    target_ports.add(int(tgt_port))
                except (ValueError, TypeError):
                    pass
            proto = alert.get("protocol") or alert.get("proto")
            if proto:
                protocols.add(str(proto).upper())

            evidence = alert.get("evidence") or {}
            confidence = float(alert.get("confidence", 0.8))
            summary_txt = self._generate_step_summary(threat_cls, det_name, alert, evidence)

            mitre_info = get_mitre_entry(threat_cls, confidence=confidence)
            tech_id = mitre_info.technique_id if mitre_info else "T1595"

            dt_iso = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            step_model = TimelineStep(
                step_number=step_idx,
                timestamp=ts,
                iso_time=dt_iso,
                relative_time_offset_sec=rel_offset,
                stage=stage,
                detector=det_name,
                threat_class=threat_cls,
                summary=summary_txt,
                evidence_snapshot=evidence,
                target_ip=tgt_ip,
                target_port=int(tgt_port) if tgt_port is not None and str(tgt_port).isdigit() else None,
                alert_id=alert.get("alert_id"),
                confidence=confidence,
            )
            step_dict = step_model.model_dump()
            step_dict["technique_id"] = tech_id
            timeline_steps.append(step_dict)
            step_idx += 1

        # 3. Asset Criticality Multiplier Alpha in [1.0, 2.0]
        asset_role = state.get("asset_role")
        if not asset_role:
            asset_role = self._lookup_host_role(state.get("source_ip", ""))
        
        explicit_alpha = state.get("asset_criticality")
        if explicit_alpha is not None:
            alpha = float(explicit_alpha)
        else:
            alpha = ASSET_ROLE_CRITICALITY.get(str(asset_role).upper(), 1.0)
        
        # Enforce bounds alpha in [1.0, 2.0]
        alpha = max(1.0, min(2.0, alpha))

        # 4. Multi-Stage APT Detection
        unique_stages = {s["stage"] for s in timeline_steps}
        is_multi_stage = len(observed_threats) >= 2 or len(unique_stages) >= 2

        # 5. Timeline summary text
        duration_sec = max(0.0, t_end - t_0)
        summary_line = (
            f"Synthesized {len(timeline_steps)} chronological attack step(s) spanning {duration_sec:.1f}s "
            f"across {len(observed_threats)} distinct threat class(es)."
        )

        state["created_at"] = float(state.get("created_at") or t_0)
        state["updated_at"] = float(state.get("updated_at") or t_end)
        state["timeline"] = timeline_steps
        state["timeline_summary"] = summary_line
        state["threat_classes_observed"] = sorted(list(observed_threats))
        state["is_multi_stage"] = is_multi_stage
        state["target_ips"] = sorted(list(target_ips))
        state["target_ports"] = sorted(list(target_ports))
        state["protocols"] = sorted(list(protocols))
        state["asset_role"] = asset_role
        state["asset_criticality"] = alpha

        return state

    def _extract_raw_alerts(self, state: TriageStateDict) -> List[Dict[str, Any]]:
        raw_alerts: List[Dict[str, Any]] = []

        if "fused_alerts" in state and state["fused_alerts"]:
            for a in state["fused_alerts"]:
                if isinstance(a, dict):
                    raw_alerts.append(a)
                elif hasattr(a, "model_dump"):
                    raw_alerts.append(a.model_dump())
                elif hasattr(a, "__dict__"):
                    raw_alerts.append(vars(a))

        if not raw_alerts and "incident" in state and state["incident"]:
            inc = state["incident"]
            alerts_src = getattr(inc, "alerts", None) or getattr(inc, "attack_timeline", None)
            if alerts_src:
                for a in alerts_src:
                    if isinstance(a, dict):
                        raw_alerts.append(a)
                    elif hasattr(a, "model_dump"):
                        raw_alerts.append(a.model_dump())
                    elif hasattr(a, "__dict__"):
                        raw_alerts.append(vars(a))

        return raw_alerts

    def _generate_step_summary(
        self, threat_class: str, detector: str, alert: Dict[str, Any], evidence: Dict[str, Any]
    ) -> str:
        tgt_ip = alert.get("target_ip", "target")
        tgt_port = alert.get("target_port")
        port_txt = f":{tgt_port}" if tgt_port is not None else ""

        if threat_class in ("PORT_SCAN_RECON", "port_scan", "recon_sweep"):
            ports_probed = evidence.get("ports_probed") or evidence.get("cardinality") or "multiple"
            return f"Reconnaissance sweep detected probing {ports_probed} ports on {tgt_ip}{port_txt}."

        elif threat_class in ("DGA_TUNNELLING", "dga_lstm"):
            domain = evidence.get("domain") or evidence.get("query") or "algorithmic-domain"
            prob = evidence.get("dga_probability") or evidence.get("score")
            prob_txt = f" (Prob: {prob:.3f})" if prob is not None else ""
            return f"DGA / DNS tunneling query for '{domain}'{prob_txt}."

        elif threat_class in ("ENCRYPTED_MALWARE", "ja4_malware"):
            ja4 = evidence.get("ja4") or evidence.get("ja4_fingerprint") or "known_malware_hash"
            malware = evidence.get("threat_actor") or evidence.get("malware_family") or "Malware Signature"
            return f"Encrypted TLS session matching {malware} (JA4: {ja4}) on {tgt_ip}{port_txt}."

        elif threat_class in ("C2_BEACONING", "c2_beacon"):
            interval = evidence.get("mean_delta_t") or evidence.get("interval_sec") or "periodic"
            jitter = evidence.get("jitter_pct") or 0.0
            return f"C2 beaconing pulse to {tgt_ip}{port_txt} (interval: {interval}s, jitter: {jitter}%)."

        elif threat_class in ("DATA_EXFILTRATION", "exfil_ratio"):
            ratio = evidence.get("out_in_ratio") or evidence.get("ratio")
            bytes_out = evidence.get("bytes_out") or evidence.get("outbound_bytes")
            ratio_txt = f", Out/In Ratio: {ratio:.1f}x" if ratio is not None else ""
            bytes_txt = f" ({bytes_out} bytes)" if bytes_out is not None else ""
            return f"Anomalous outbound data exfiltration to {tgt_ip}{port_txt}{ratio_txt}{bytes_txt}."

        elif threat_class in ("VOLUMETRIC_DDOS", "PROTOCOL_DDOS", "ddos_entropy"):
            entropy = evidence.get("entropy") or evidence.get("shannon_entropy")
            pps = evidence.get("pps") or evidence.get("packet_rate")
            entropy_txt = f", Entropy: {entropy:.2f}" if entropy is not None else ""
            pps_txt = f", Rate: {pps} pps" if pps is not None else ""
            return f"Denial of Service flood targeting {tgt_ip}{port_txt}{entropy_txt}{pps_txt}."

        return f"Passive threat activity detected ({threat_class}) targeting {tgt_ip}{port_txt}."

    def _lookup_host_role(self, source_ip: str) -> str:
        ip = str(source_ip).strip()
        if not ip or ip == "0.0.0.0":
            return "INTERNAL_WORKSTATION"
        if ip.endswith(".1") or ip.endswith(".254"):
            return "GATEWAY_FIREWALL"
        elif ip.endswith(".10") or ip.endswith(".11"):
            return "DOMAIN_CONTROLLER"
        elif ip.endswith(".50") or ip.endswith(".51"):
            return "DATABASE_SERVER"
        elif ip.endswith(".80") or ip.endswith(".443"):
            return "APP_SERVER"
        return "INTERNAL_WORKSTATION"
