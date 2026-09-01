"""
SIH26145 - Pipeline Coordinator & Triage Bridge Service
Bridges streaming CEP aggregation output with the LangGraph 5-node agentic triage engine,
transforms triage results into API models, updates in-memory ring buffers, and triggers WebSocket broadcast.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.agentic_triage.graph import triage_incident
from src.api.models import (
    CountermeasureArtifactSchema,
    IncidentDetailResponse,
    IncidentTimelineItem,
    MitreMappingSchema,
    RiskBreakdownSchema,
    RiskEvidenceItemSchema,
)
from src.api.simulation.scenario_generator import generate_scenario_alerts
from src.api.state import AppState, get_app_state
from src.cep.models import FusedIncident, RawAlert

logger = logging.getLogger("sih.api.pipeline_service")


def triage_state_to_incident_detail(
    state: Dict[str, Any],
    raw_incident: Optional[FusedIncident] = None,
) -> IncidentDetailResponse:
    """
    Transforms LangGraph TriageStateDict into the strongly-typed API IncidentDetailResponse model.
    """
    now = time.time()
    inc_id = str(state.get("incident_id") or (raw_incident.incident_id if raw_incident else f"INC-{uuid.uuid4().hex[:8].upper()}"))
    created_at = float(state.get("created_at") or (raw_incident.created_at if raw_incident else now))
    updated_at = float(state.get("updated_at") or now)
    source_ip = str(state.get("source_ip") or (raw_incident.primary_source_ip if raw_incident else "0.0.0.0"))
    subnet = str(state.get("subnet") or (raw_incident.source_subnet if raw_incident else ""))
    target_ips = list(state.get("target_ips") or (raw_incident.target_ips if raw_incident else []))
    target_ports = list(state.get("target_ports") or (raw_incident.target_ports if raw_incident else []))

    primary_threat = str(
        state.get("primary_threat_class")
        or (raw_incident.threat_class if raw_incident else "UNKNOWN")
    )
    threat_classes = list(
        state.get("threat_classes_observed")
        or (raw_incident.threat_classes if raw_incident else [primary_threat])
    )
    participating_detectors = list(
        raw_incident.participating_detectors if raw_incident else []
    )
    if not participating_detectors:
        participating_detectors = list(
            set(
                m.get("matched_detector") or m.get("detector", "")
                for m in state.get("mitre_mappings", [])
                if m.get("matched_detector") or m.get("detector")
            )
        )

    severity = str(state.get("severity") or (raw_incident.severity if raw_incident else "MEDIUM")).upper()
    risk_score = float(state.get("risk_score") or 0.0)

    # Convert Risk Breakdown
    risk_breakdown: Optional[RiskBreakdownSchema] = None
    rb_raw = state.get("risk_breakdown")
    if isinstance(rb_raw, dict):
        ev_items: List[RiskEvidenceItemSchema] = []
        for ev in rb_raw.get("evidence_breakdown", []):
            if isinstance(ev, dict):
                ev_items.append(
                    RiskEvidenceItemSchema(
                        threat_class=str(ev.get("threat_class", "")),
                        detector=str(ev.get("detector", "")),
                        base_weight=float(ev.get("base_weight", 0.0)),
                        confidence=float(ev.get("confidence", 0.8)),
                        weighted_score=float(ev.get("weighted_score", 0.0)),
                        metric_summary=str(ev.get("metric_summary", "")),
                    )
                )
        risk_breakdown = RiskBreakdownSchema(
            base_risk_sum=float(rb_raw.get("base_risk_sum", 0.0)),
            synergy_bonus=float(rb_raw.get("synergy_bonus", 0.0)),
            asset_criticality_multiplier=float(rb_raw.get("asset_criticality_multiplier", 1.0)),
            final_risk_score=float(rb_raw.get("final_risk_score", risk_score)),
            severity=str(rb_raw.get("severity", severity)),
            formula=str(rb_raw.get("formula", "min(100.0, (sum(w_i * conf_i) + synergy_bonus) * asset_criticality)")),
            evidence_breakdown=ev_items,
            synergy_reason=rb_raw.get("synergy_reason"),
        )

    # Convert Timeline
    timeline_items: List[IncidentTimelineItem] = []
    for idx, t_step in enumerate(state.get("timeline", [])):
        if isinstance(t_step, dict):
            timeline_items.append(
                IncidentTimelineItem(
                    step_number=int(t_step.get("step_number", idx + 1)),
                    timestamp=float(t_step.get("timestamp", now)),
                    iso_time=str(t_step.get("iso_time", "")),
                    relative_time_offset_sec=float(t_step.get("relative_time_offset_sec", 0.0)),
                    stage=str(t_step.get("stage", "RECONNAISSANCE")),
                    detector=str(t_step.get("detector", "")),
                    threat_class=str(t_step.get("threat_class", "")),
                    summary=str(t_step.get("summary", "")),
                    target_ip=t_step.get("target_ip"),
                    target_port=t_step.get("target_port"),
                    confidence=float(t_step.get("confidence", 0.8)),
                    evidence_snapshot=dict(t_step.get("evidence_snapshot", {})),
                )
            )

    # Convert MITRE Mappings
    mitre_mappings: List[MitreMappingSchema] = []
    for m in state.get("mitre_mappings", []):
        if isinstance(m, dict):
            mitre_mappings.append(
                MitreMappingSchema(
                    technique_id=str(m.get("technique_id", "")),
                    technique_name=str(m.get("technique_name", "")),
                    tactic_id=str(m.get("tactic_id", "")),
                    tactic_name=str(m.get("tactic_name", "")),
                    kill_chain_phase=str(m.get("kill_chain_phase", "")),
                    confidence=float(m.get("confidence", 0.8)),
                    matched_detector=str(m.get("matched_detector", "")),
                    description=m.get("description"),
                )
            )

    # Convert Countermeasures
    countermeasures: List[CountermeasureArtifactSchema] = []
    for cm in state.get("countermeasures", []):
        if isinstance(cm, dict):
            countermeasures.append(
                CountermeasureArtifactSchema(
                    countermeasure_type=str(cm.get("countermeasure_type", "")),
                    target_entity=str(cm.get("target_entity", source_ip)),
                    artifact_content=str(cm.get("artifact_content", "")),
                    syntax_valid=bool(cm.get("syntax_valid", True)),
                    requires_human_approval=bool(cm.get("requires_human_approval", True)),
                )
            )

    # Evidence summary collection
    evidence_summary: Dict[str, Any] = {}
    if raw_incident and raw_incident.evidence_summary:
        evidence_summary.update(raw_incident.evidence_summary)
    if "fused_alerts" in state:
        evidence_summary["fused_alerts_count"] = len(state["fused_alerts"])

    raw_alert_count = int(
        raw_incident.total_raw_alerts_collapsed
        if raw_incident and raw_incident.total_raw_alerts_collapsed > 0
        else (len(state.get("fused_alerts", [])) or 1)
    )

    return IncidentDetailResponse(
        incident_id=inc_id,
        created_at=created_at,
        updated_at=updated_at,
        source_ip=source_ip,
        subnet=subnet,
        target_ips=target_ips,
        target_ports=target_ports,
        primary_threat_class=primary_threat,
        threat_classes=threat_classes,
        participating_detectors=participating_detectors,
        severity=severity,
        risk_score=risk_score,
        risk_breakdown=risk_breakdown,
        timeline=timeline_items,
        attack_narrative=str(state.get("attack_narrative", "")),
        mitre_mappings=mitre_mappings,
        primary_mitre_technique=state.get("primary_mitre_technique"),
        primary_mitre_tactic=state.get("primary_mitre_tactic"),
        kill_chain_phase=state.get("kill_chain_phase"),
        countermeasures=countermeasures,
        primary_countermeasure_type=state.get("primary_countermeasure_type"),
        primary_countermeasure_artifact=state.get("primary_countermeasure_artifact"),
        requires_human_approval=True,
        status=str(state.get("status", "PENDING_REVIEW")),
        execution_latency_ms=float(state.get("execution_latency_ms", 0.0)),
        raw_alert_count=raw_alert_count,
        evidence_summary=evidence_summary,
    )


async def process_and_triage_incident(
    incident: FusedIncident,
    app_state: Optional[AppState] = None,
) -> IncidentDetailResponse:
    """
    Executes LangGraph agentic triage on a FusedIncident asynchronously,
    indexes into in-memory ring buffer, and broadcasts over WebSockets.
    """
    state_mgr = app_state or get_app_state()
    graph = state_mgr.get_triage_graph()

    # Run LangGraph synchronous execution in worker threadpool to avoid event loop blocking
    triage_state = await asyncio.to_thread(
        triage_incident,
        incident,
        compiled_graph=graph,
        db=state_mgr.db,
        execution_mode="deterministic",
    )

    incident_detail = triage_state_to_incident_detail(triage_state, raw_incident=incident)

    # Store in memory ring buffer
    state_mgr.incident_buffer.add_incident(incident_detail)

    # Broadcast to WebSocket subscribers
    await state_mgr.connection_manager.broadcast_incident(incident_detail)

    return incident_detail


async def run_simulation_scenario(
    scenario_name: str,
    app_state: Optional[AppState] = None,
) -> Tuple[str, int, IncidentDetailResponse]:
    """
    Generates synthetic alerts for the requested scenario, feeds through CEP aggregation,
    triages the resulting incident, saves to memory, and broadcasts to WebSocket clients.
    """
    state_mgr = app_state or get_app_state()
    alerts = generate_scenario_alerts(scenario_name)

    # Ingest alerts through CEP Aggregator in thread pool
    def _run_cep() -> Tuple[List[FusedIncident], Optional[FusedIncident]]:
        fused_list: List[FusedIncident] = []
        last_fused: Optional[FusedIncident] = None
        for a in alerts:
            f = state_mgr.cep_engine.ingest_alert(a)
            if f is not None:
                last_fused = f
                if f not in fused_list:
                    fused_list.append(f)
        return fused_list, last_fused

    fused_list, last_fused = await asyncio.to_thread(_run_cep)

    # If no incident was formed by CEP (e.g. single alert), construct an incident context
    target_incident = last_fused or (fused_list[0] if fused_list else None)
    if target_incident is None and alerts:
        first_alert = alerts[0]
        target_incident = FusedIncident(
            primary_source_ip=first_alert.source_ip,
            target_ips=[first_alert.target_ip] if first_alert.target_ip else [],
            target_ports=[first_alert.target_port] if first_alert.target_port is not None else [],
            participating_detectors=[a.detector_name for a in alerts],
            threat_classes=list(set(a.threat_class for a in alerts)),
            threat_class=first_alert.threat_class,
            raw_alert_count=len(alerts),
            total_raw_alerts_collapsed=len(alerts),
            fused_confidence=first_alert.confidence,
            overall_confidence=first_alert.confidence,
            severity=(first_alert.severity or "HIGH").upper(),
            attack_stage="RECONNAISSANCE",
            kill_chain_stages=["RECONNAISSANCE"],
            alerts=alerts,
            raw_alert_ids=[a.alert_id for a in alerts if a.alert_id],
        )

    # Triage and broadcast
    incident_detail = await process_and_triage_incident(target_incident, app_state=state_mgr)
    return scenario_name, len(alerts), incident_detail
