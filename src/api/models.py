"""
SIH26145 - Pydantic v2 Models & Schemas for REST and WebSocket Payloads
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


# =====================================================================
# Health & Status Schemas
# =====================================================================

class DataDiodeStatus(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    status: str = Field(default="ENFORCED", description="Data diode enforcement state")
    requires_human_approval: bool = Field(
        default=True,
        description="Enforce out-of-band human confirmation for all countermeasures",
    )
    return_path: str = Field(default="DISABLED", description="Active probing return path status")
    enclave_mode: str = Field(default="AIR_GAPPED_PASSIVE", description="Deployment enclave mode")


class HealthResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    status: str = Field(default="healthy", description="Overall system health status")
    uptime_seconds: float = Field(default=0.0, description="Uptime in seconds since startup")
    version: str = Field(default="1.0.0", description="Backend service version")
    detectors: Dict[str, bool] = Field(
        default_factory=lambda: {
            "ddos_entropy": True,
            "portscan_hll": True,
            "exfil_ratio": True,
            "dga_lstm": True,
            "ja4_malware": True,
            "c2_beacon": True,
        },
        description="Active threat detector operational status",
    )
    data_diode: DataDiodeStatus = Field(
        default_factory=DataDiodeStatus,
        description="Physical hardware data diode enclave status",
    )
    data_diode_status: Optional[DataDiodeStatus] = None
    active_connections: Dict[str, int] = Field(
        default_factory=lambda: {"telemetry": 0, "incidents": 0},
        description="Current active WebSocket connection counts",
    )
    total_incidents_stored: int = Field(
        default=0,
        description="Total triaged incidents residing in ring buffer",
    )

    @model_validator(mode="after")
    def sync_data_diode_fields(self) -> HealthResponse:
        if self.data_diode_status is None:
            self.data_diode_status = self.data_diode
        return self


# =====================================================================
# Telemetry & Line-Rate Metrics Schemas
# =====================================================================

class MetricsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    timestamp: float = Field(default_factory=time.time, description="Metric sample timestamp")
    events_per_second: float = Field(default=0.0, description="Instantaneous processed events per second (EPS)")
    megabits_per_second: float = Field(default=0.0, description="Line-rate throughput in Mbps")
    packets_per_second: float = Field(default=0.0, description="Packet ingest rate in PPS")
    packet_drop_rate: float = Field(default=0.0, description="Packet drop/loss percentage")
    packet_loss_pct: float = Field(default=0.0, description="Packet loss percentage alias")
    latency_p50_ms: float = Field(default=0.02, description="Median pipeline latency in milliseconds")
    latency_p90_ms: float = Field(default=0.04, description="90th percentile latency in milliseconds")
    latency_p99_ms: float = Field(default=0.08, description="99th percentile latency in milliseconds")
    active_flows: int = Field(default=0, description="Currently tracked active network flows")
    buffer_utilization_pct: float = Field(default=0.0, description="CEP sliding window buffer capacity utilization")

    @model_validator(mode="after")
    def sync_loss_pct(self) -> MetricsResponse:
        if self.packet_loss_pct == 0.0 and self.packet_drop_rate > 0.0:
            self.packet_loss_pct = self.packet_drop_rate
        elif self.packet_drop_rate == 0.0 and self.packet_loss_pct > 0.0:
            self.packet_drop_rate = self.packet_loss_pct
        return self


class TelemetryStreamMessage(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    timestamp: float = Field(default_factory=time.time)
    events_per_sec: float = Field(default=0.0)
    events_per_second: float = Field(default=0.0)
    mbps: float = Field(default=0.0)
    megabits_per_second: float = Field(default=0.0)
    pps: float = Field(default=0.0)
    packets_per_second: float = Field(default=0.0)
    packet_loss_pct: float = Field(default=0.0)
    packet_drop_rate: float = Field(default=0.0)
    latency_p50_ms: float = Field(default=0.02)
    latency_p90_ms: float = Field(default=0.04)
    latency_p99_ms: float = Field(default=0.08)
    pipeline_latency_ms: float = Field(default=0.03)
    buffer_utilization_pct: float = Field(default=0.0)
    active_detectors: Dict[str, bool] = Field(default_factory=dict)
    active_hosts: int = Field(default=0)
    active_flows: int = Field(default=0)

    @model_validator(mode="after")
    def sync_aliases(self) -> TelemetryStreamMessage:
        if self.events_per_sec == 0.0 and self.events_per_second > 0.0:
            self.events_per_sec = self.events_per_second
        elif self.events_per_second == 0.0 and self.events_per_sec > 0.0:
            self.events_per_second = self.events_per_sec

        if self.mbps == 0.0 and self.megabits_per_second > 0.0:
            self.mbps = self.megabits_per_second
        elif self.megabits_per_second == 0.0 and self.mbps > 0.0:
            self.megabits_per_second = self.mbps

        if self.pps == 0.0 and self.packets_per_second > 0.0:
            self.pps = self.packets_per_second
        elif self.packets_per_second == 0.0 and self.pps > 0.0:
            self.packets_per_second = self.pps

        if self.packet_loss_pct == 0.0 and self.packet_drop_rate > 0.0:
            self.packet_loss_pct = self.packet_drop_rate
        elif self.packet_drop_rate == 0.0 and self.packet_loss_pct > 0.0:
            self.packet_drop_rate = self.packet_loss_pct
        return self


# =====================================================================
# Incident Investigation & Detail Schemas
# =====================================================================

class IncidentTimelineItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    step_number: int = Field(default=1, ge=1)
    timestamp: float = Field(default_factory=time.time)
    iso_time: str = ""
    relative_time_offset_sec: float = 0.0
    stage: str = "RECONNAISSANCE"
    detector: str = ""
    threat_class: str = ""
    summary: str = ""
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_snapshot: Dict[str, Any] = Field(default_factory=dict)


class RiskEvidenceItemSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    threat_class: str
    detector: str
    base_weight: float
    confidence: float
    weighted_score: float
    metric_summary: str = ""


class RiskBreakdownSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    base_risk_sum: float = 0.0
    synergy_bonus: float = 0.0
    asset_criticality_multiplier: float = 1.0
    final_risk_score: float = 0.0
    severity: str = "MEDIUM"
    formula: str = "min(100.0, (sum(w_i * conf_i) + synergy_bonus) * asset_criticality)"
    evidence_breakdown: List[RiskEvidenceItemSchema] = Field(default_factory=list)
    synergy_reason: Optional[str] = None


class MitreMappingSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    kill_chain_phase: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    matched_detector: str = ""
    description: Optional[str] = None


class CountermeasureArtifactSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    countermeasure_type: str = Field(
        ...,
        description="Type: iptables | nftables | cisco_acl | dns_rpz | snort3 | stix_bundle",
    )
    target_entity: str = Field(..., description="Target IP, subnet, or domain to block/isolate")
    artifact_content: str = Field(..., description="Copy-pasteable rule syntax or STIX JSON payload")
    syntax_valid: bool = Field(default=True)
    requires_human_approval: bool = Field(default=True)


class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    incident_id: str
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    source_ip: str
    subnet: str = ""
    target_ips: List[str] = Field(default_factory=list)
    target_ports: List[int] = Field(default_factory=list)
    primary_threat_class: str = "UNKNOWN"
    threat_classes: List[str] = Field(default_factory=list)
    participating_detectors: List[str] = Field(default_factory=list)
    severity: str = "MEDIUM"
    risk_score: float = 0.0
    risk_breakdown: Optional[RiskBreakdownSchema] = None
    timeline: List[IncidentTimelineItem] = Field(default_factory=list)
    attack_narrative: str = ""
    mitre_mappings: List[MitreMappingSchema] = Field(default_factory=list)
    primary_mitre_technique: Optional[str] = None
    primary_mitre_tactic: Optional[str] = None
    kill_chain_phase: Optional[str] = None
    countermeasures: List[CountermeasureArtifactSchema] = Field(default_factory=list)
    primary_countermeasure_type: Optional[str] = None
    primary_countermeasure_artifact: Optional[str] = None
    requires_human_approval: bool = True
    status: str = "PENDING_REVIEW"
    execution_latency_ms: float = 0.0
    raw_alert_count: int = 0
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)


class IncidentSummaryResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    incident_id: str
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    source_ip: str
    subnet: str = ""
    target_ips: List[str] = Field(default_factory=list)
    target_ports: List[int] = Field(default_factory=list)
    primary_threat_class: str = "UNKNOWN"
    severity: str = "MEDIUM"
    risk_score: float = 0.0
    attack_stage: str = "RECONNAISSANCE"
    status: str = "PENDING_REVIEW"
    requires_human_approval: bool = True
    raw_alert_count: int = 0
    mitre_techniques: List[str] = Field(default_factory=list)


class PaginatedIncidentsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    items: List[IncidentDetailResponse] = Field(default_factory=list)
    incidents: List[IncidentDetailResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    limit: int = 20
    pages: int = 1

    @model_validator(mode="after")
    def sync_items_and_incidents(self) -> PaginatedIncidentsResponse:
        if not self.incidents and self.items:
            self.incidents = self.items
        elif not self.items and self.incidents:
            self.items = self.incidents
        return self


# =====================================================================
# Action, Simulation & WebSocket Schemas
# =====================================================================

class IncidentActionRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    action: str = Field(
        ...,
        description="Analyst action to execute (e.g. 'APPROVE', 'DISMISS', 'RESOLVE')",
    )
    analyst_notes: Optional[str] = Field(
        default="",
        description="Analyst notes and justification",
    )
    analyst_id: Optional[str] = Field(
        default="soc-analyst-local",
        description="SOC analyst identifier",
    )


class IncidentActionResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    incident_id: str
    action: str
    status: str
    updated_at: float = Field(default_factory=time.time)
    analyst_notes: str = ""
    requires_human_approval: bool = True
    message: str = "Action recorded successfully."


class SimulationResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    status: str = "triggered"
    scenario: str
    incident_id: str
    alerts_count: int = 0
    incident: Optional[IncidentDetailResponse] = None
    message: str = "Synthetic attack scenario executed through CEP aggregator and LangGraph triage."


class IncidentBroadcastMessage(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    event_type: str = "NEW_INCIDENT"
    incident_id: str
    severity: str
    risk_score: float
    threat_class: str
    summary: str
    incident: IncidentDetailResponse
