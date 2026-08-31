from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, TypedDict, Union
from pydantic import BaseModel, ConfigDict, Field


class TimelineStep(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    step_number: int = Field(default=1, ge=1)
    timestamp: float = Field(default_factory=time.time)
    iso_time: str = ""
    relative_time_offset_sec: float = 0.0
    stage: str = "RECONNAISSANCE"
    detector: str = ""
    threat_class: str = ""
    summary: str = ""
    evidence_snapshot: Dict[str, Any] = Field(default_factory=dict)
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    alert_id: Optional[str] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class RiskEvidenceItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    threat_class: str
    detector: str
    base_weight: float
    confidence: float
    weighted_score: float
    metric_summary: str = ""


class RiskBreakdown(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    base_risk_sum: float = 0.0
    synergy_bonus: float = 0.0
    asset_criticality_multiplier: float = 1.0
    final_risk_score: float = 0.0
    severity: str = "MEDIUM"
    formula: str = "min(100.0, (sum(w_i * conf_i) + synergy_bonus) * asset_criticality)"
    evidence_breakdown: List[RiskEvidenceItem] = Field(default_factory=list)
    synergy_reason: Optional[str] = None


class MitreMapping(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    kill_chain_phase: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    matched_detector: str = ""
    description: Optional[str] = None


class CountermeasureItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    countermeasure_type: str
    target_entity: str
    artifact_content: str
    syntax_valid: bool = True
    requires_human_approval: bool = True


class TriageStateDict(TypedDict, total=False):
    # Incident Identifiers & Temporal Bounds
    incident_id: str
    incident: Any
    created_at: float
    updated_at: float
    source_ip: str
    subnet: str
    target_ips: List[str]
    target_ports: List[int]
    protocols: List[str]

    # Raw Ingested Alerts & Historical Context
    fused_alerts: List[Dict[str, Any]]
    historical_metrics: Dict[str, Any]
    asset_role: str
    asset_criticality: float

    # Node 1 Outputs (Correlation & Timeline)
    timeline: List[Dict[str, Any]]
    timeline_summary: str
    threat_classes_observed: List[str]
    is_multi_stage: bool

    # Node 2 Outputs (Explainable Risk)
    risk_score: float
    severity: str
    risk_breakdown: Dict[str, Any]

    # Node 3 Outputs (Classification & MITRE Mapping)
    primary_threat_class: str
    primary_mitre_technique: str
    primary_mitre_tactic: str
    kill_chain_phase: str
    mitre_mappings: List[Dict[str, Any]]
    attack_narrative: str

    # Node 4 Outputs (Countermeasures)
    countermeasures: List[Dict[str, Any]]
    primary_countermeasure_type: str
    primary_countermeasure_artifact: str
    requires_human_approval: bool

    # Node 5 Outputs (Handoff & Metadata)
    execution_mode: str
    start_time: float
    execution_latency_ms: float
    db_persisted: bool
    out_of_band_dispatched: bool
    persisted_id: str
    status: str
    errors: List[str]
