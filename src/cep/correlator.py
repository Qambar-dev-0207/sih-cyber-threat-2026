from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from src.cep.models import (
    AttackStage,
    DeduplicationRecord,
    FusedIncident,
    IncidentTimelineEntry,
    SlidingWindowConfig,
)
from src.cep.sliding_window import HostSlidingWindow, SubnetSlidingWindow, extract_subnet

logger = logging.getLogger('cep.correlator')

SEVERITY_RANKS: Dict[str, int] = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}
RANK_TO_SEVERITY: Dict[int, str] = {
    1: 'LOW',
    2: 'MEDIUM',
    3: 'HIGH',
    4: 'CRITICAL',
}

# Mapping of detector ids and threat classes to Kill-Chain Attack Stages and MITRE Tactics/Techniques
DETECTOR_STAGE_MAP: Dict[str, AttackStage] = {
    # Stage 1: Reconnaissance
    'portscan_hll': AttackStage.RECONNAISSANCE,
    'port_scan': AttackStage.RECONNAISSANCE,
    'recon_sweep': AttackStage.RECONNAISSANCE,
    'PORT_SCAN_RECON': AttackStage.RECONNAISSANCE,

    # Stage 2: Delivery & DNS
    'dga_lstm': AttackStage.DELIVERY,
    'dga_tunneling': AttackStage.DELIVERY,
    'DGA_TUNNELLING': AttackStage.DELIVERY,
    'dns_tunnel': AttackStage.DELIVERY,

    # Stage 3: Command & Control / Encrypted Malware
    'ja4_malware': AttackStage.COMMAND_AND_CONTROL,
    'encrypted_malware': AttackStage.COMMAND_AND_CONTROL,
    'ENCRYPTED_MALWARE': AttackStage.COMMAND_AND_CONTROL,
    'c2_beacon': AttackStage.COMMAND_AND_CONTROL,
    'c2_beaconing': AttackStage.COMMAND_AND_CONTROL,
    'C2_BEACONING': AttackStage.COMMAND_AND_CONTROL,

    # Stage 4: Exfiltration & Actions on Objectives / Impact
    'exfil_ratio': AttackStage.EXFILTRATION,
    'data_exfiltration': AttackStage.EXFILTRATION,
    'DATA_EXFILTRATION': AttackStage.EXFILTRATION,
    'ddos_entropy': AttackStage.ACTIONS_ON_OBJECTIVES,
    'volumetric_ddos': AttackStage.ACTIONS_ON_OBJECTIVES,
    'VOLUMETRIC_DDOS': AttackStage.ACTIONS_ON_OBJECTIVES,
    'protocol_ddos': AttackStage.ACTIONS_ON_OBJECTIVES,
}

MITRE_TECHNIQUE_DEFAULTS: Dict[str, str] = {
    'portscan_hll': 'T1595',
    'port_scan': 'T1595',
    'recon_sweep': 'T1595.002',
    'PORT_SCAN_RECON': 'T1595',
    'dga_lstm': 'T1568.002',
    'dga_tunneling': 'T1568.002',
    'DGA_TUNNELLING': 'T1568.002',
    'ja4_malware': 'T1071.001',
    'encrypted_malware': 'T1071.001',
    'ENCRYPTED_MALWARE': 'T1071.001',
    'c2_beacon': 'T1071',
    'c2_beaconing': 'T1071',
    'C2_BEACONING': 'T1071',
    'exfil_ratio': 'T1048',
    'data_exfiltration': 'T1048',
    'DATA_EXFILTRATION': 'T1048',
    'ddos_entropy': 'T1498',
    'volumetric_ddos': 'T1498',
    'VOLUMETRIC_DDOS': 'T1498',
    'protocol_ddos': 'T1499',
}


STAGE_SEQUENCE: List[AttackStage] = [
    AttackStage.RECONNAISSANCE,
    AttackStage.DELIVERY,
    AttackStage.COMMAND_AND_CONTROL,
    AttackStage.EXFILTRATION,
    AttackStage.ACTIONS_ON_OBJECTIVES,
]


class ConfidenceFuser:
    """
    Mathematical Confidence Fusion Engine based on probabilistic union
    and multi-detector synergy corroboration.
    """

    @staticmethod
    def compute_fused_confidence(
        confidences: List[float],
        unique_detector_count: int,
        config: SlidingWindowConfig,
    ) -> float:
        """
        Computes C = 1 - prod(l - c_i) with synergy boost.
        Synergy boost:
        - 2 detectors: +0.05
        - 3+ detectors: +0.10
        Clamped to [0.0, 1.0].
        """
        if not confidences:
            return 0.8

        # Base probabilistic fusion
        prod_uncertainty = 1.0
        for c in confidences:
            clamped_c = max(0.0, min(1.0, float(c)))
            prod_uncertainty *= (1.0 - clamped_c)

        c_base = 1.0 - prod_uncertainty


        # Apply multi-detector synergy boost
        if unique_detector_count == 2:
            boost = config.multi_detector_synergy_2
        elif unique_detector_count >= 3:
            boost = config.multi_detector_synergy_3_plus
        else:
            boost = 0.0

        c_fused = min(config.max_confidence_clamp, c_base + boost)
        return round(max(0.0, c_fused), 4)


class SignalCorrelator:
    """
    Multi-detector signal fusion engine that forms structured incidents across
    cyber kill-chain stages with confidence-weighted scoring and severity escalation.
    """

    def __init__(self, config: Optional[SlidingWindowConfig] = None):
        self.config: SlidingWindowConfig = config or SlidingWindowConfig()

    def classify_stage(self, detector_name: str, threat_class: str) -> AttackStage:
        """Maps detector and threat class to an AttackStage enum."""
        det_key = detector_name.strip().lower()
        threat_key = threat_class.strip().upper()

        stage = DETECTOR_STAGE_MAP.get(threat_key) or DETECTOR_STAGE_MAP.get(det_key)
        if stage:
            return stage
        return AttackStage.RECONNAISSANCE

    def correlate_host(
        self,
        host_window: HostSlidingWindow,
        subnet_window: Optional[SubnetSlidingWindow] = None,
        current_time: Optional[float] = None,
    ) -> Optional[FusedIncident]:
        """
        Analyzes the sliding window records for a host and synthesizes a FusedIncident.
        """
        records = host_window.get_records()
        if not records:
            return None

        now = current_time if current_time is not None else time.time()

        # 1. Extract detectors, threats, targets, stages
        detectors = host_window.get_participating_detectors()
        threat_classes = host_window.get_threat_classes()
        target_ips = host_window.get_target_ips()
        target_ports = host_window.get_target_ports()
        total_raw_alerts = host_window.get_total_raw_alerts()
        sample_alerts = host_window.get_sample_alerts()
        alert_ids = host_window.get_all_alert_ids()

        # Detector contributions
        detector_contributions: Dict[str, int] = {}
        for r in records:
            dname = r.detector_name
            detector_contributions[dname] = detector_contributions.get(dname, 0) + r.occurrence_count

        # Stage classification
        observed_stages: Set[AttackStage] = set()
        for r in records:
            stage = self.classify_stage(r.detector_name, r.threat_class)
            observed_stages.add(stage)

        stage_names = [stg.value for stg in STAGE_SEQUENCE if stg in observed_stages]

        # 2. Compute Fused Confidence
        confidences = [r.confidence for r in records]
        fused_confidence = ConfidenceFuser.compute_fused_confidence(
            confidences=confidences,
            unique_detector_count=len(detectors),
            config=self.config,
        )

        # 3. Severity Escalation
        base_sev = host_window.get_max_severity()
        base_rank = SEVERITY_RANKS.get(base_sev, 2)

        escalated_rank = base_rank
        if len(observed_stages) >= 4 or len(detectors) >= 3:
            escalated_rank = 4  # CRITICAL
        elif len(observed_stages) >= 2 or len(detectors) >= 2:
            escalated_rank = min(4, base_rank + 1)
        elif base_sev == 'CRITICAL' and host_window.get_max_confidence() >= self.config.escalation_confidence_threshold:
            escalated_rank = 4

        final_severity = RANK_TO_SEVERITY.get(escalated_rank, 'MEDIUM')

        # 4. Threat Classification & Attack Stage Naming
        if len(observed_stages) >= 2 or len(detectors) >= 2:
            composite_threat = 'APT_MULTI_STAGE_ATTACK'
            primary_stage = stage_names[-1] if stage_names else AttackStage.MULTI_STAGE_APT.value
        else:
            composite_threat = threat_classes[0] if threat_classes else 'PORT_SCAN_RECON'
            primary_stage = stage_names[0] if stage_names else AttackStage.RECONNAISSANCE.value

        # 5. Chronological Attack Timeline
        sorted_records = sorted(records, key=lambda r: r.first_seen)
        timeline: List[IncidentTimelineEntry] = []
        for r in sorted_records:
            stg = self.classify_stage(r.detector_name, r.threat_class).value
            desc = f'[{stg}] {r.threat_class} detected by {r.detector_name} (conf={r.confidence:.2f}, count={r.occurrence_count})'
            mitre = r.mitre_techniques[0] if r.mitre_techniques else MITRE_TECHNIQUE_DEFAULTS.get(r.detector_name, 'T1595')
            timeline.append(
                IncidentTimelineEntry(
                    timestamp=r.first_seen,
                    stage=stg,
                    detector_name=r.detector_name,
                    threat_class=r.threat_class,
                    severity=r.severity,
                    confidence=r.confidence,
                    description=desc,
                    target_ip=r.target_ip,
                    target_port=r.target_port,
                    alert_id=r.alert_ids[0] if r.alert_ids else None,
                    mitre_technique=mitre,
                    evidence=dict(r.evidence),
                )
            )


        # 6. Evidence Summary & MITRE Hints
        evidence_summary: Dict[str, Any] = {
            'participating_detectors': detectors,
            'threat_classes': threat_classes,
            'observed_stages': stage_names,
            'total_raw_alerts': total_raw_alerts,
            'unique_targets': len(target_ips),
            'unique_target_ports': len(target_ports),
        }

        mitre_hints: Set[str] = set()
        for r in records:
            mitre_hints.update(r.mitre_techniques)
            if not r.mitre_techniques:
                hint = MITRE_TECHNIQUE_DEFAULTS.get(r.detector_name)
                if hint:
                    mitre_hints.add(hint)


        subnet_cidr = extract_subnet(
            host_window.source_ip,
            prefix_v4=self.config.subnet_cidr_prefix_v4,
            prefix_v6=self.config.subnet_cidr_prefix_v6,
        )

        return FusedIncident(
            primary_source_ip=host_window.source_ip,
            source_subnet=subnet_cidr,
            target_ips=target_ips,
            target_ports=target_ports,
            participating_detectors=detectors,
            threat_classes=threat_classes,
            threat_class=composite_threat,
            raw_alert_count=total_raw_alerts,
            total_raw_alerts_collapsed=total_raw_alerts,
            fused_confidence=fused_confidence,
            overall_confidence=fused_confidence,
            severity=final_severity,
            attack_stage=primary_stage,
            kill_chain_stages=stage_names,
            alerts=sample_alerts,
            raw_alert_ids=alert_ids,
            attack_timeline=timeline,
            detector_contributions=detector_contributions,
            evidence_summary=evidence_summary,
            mitre_attack_hints=sorted(list(mitre_hints)),
            requires_agentic_triage=True,
            requires_human_approval=True,
            status='PENDING_REVIEW',
        )
