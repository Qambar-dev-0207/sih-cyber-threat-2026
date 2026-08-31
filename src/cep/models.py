from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.ingestion.models import RawAlert


class AttackStage(str, Enum):
    RECONNAISSANCE = 'RECONNAISSANCE'
    WEAPONIZATION = 'WEAPONIZATION'
    DELIVERY = 'DELIVERY'
    DELIVERY_DNS = 'DELIVERY_DNS'
    EXPLOITATION = 'EXPLOITATION'
    INSTALLATION = 'INSTALLATION'
    COMMAND_AND_CONTROL = 'COMMAND_AND_CONTROL'
    C2_COMMUNICATION = 'C2_COMMUNICATION'
    EXFILTRATION = 'EXFILTRATION'
    ACTIONS_ON_OBJECTIVES = 'ACTIONS_ON_OBJECTIVES'
    VOLUMETRIC_ATTACK = 'VOLUMETRIC_ATTACK'
    MULTI_STAGE_APT = 'MULTI_STAGE_APT'


class IncidentTimelineEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='allow')

    timestamp: float = Field(default_factory=time.time)
    stage: str
    detector_name: str
    threat_class: str
    severity: str = 'MEDIUM'
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    description: str = ''
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    alert_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)


class DeduplicationRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='allow')

    fingerprint: str
    source_ip: str
    detector_name: str = Field(..., alias='detector_id')
    threat_class: str
    severity: str = 'MEDIUM'
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    occurrence_count: int = Field(default=1, ge=1)
    flow_ids: List[str] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    stage: Optional[str] = None
    sample_alerts: List[RawAlert] = Field(default_factory=list)


DeduplicatedAlert = DeduplicationRecord


class SlidingWindowConfig(BaseModel):
    model_config = ConfigDict(extra='allow')

    window_duration_sec: float = Field(default=60.0, ge=1.0, le=3600.0)
    dedup_coalesce_sec: float = Field(default=5.0, ge=0.1, le=300.0)
    rate_limit_capacity: float = Field(default=10.0, ge=1.0)
    rate_limit_refill_rate: float = Field(default=5.0, ge=0.1)
    max_tracked_hosts: int = Field(default=50000, ge=10)
    host_inactivity_ttl_sec: float = Field(default=300.0, ge=1.0, le=86400.0)
    subnet_cidr_prefix_v4: int = Field(default=24, ge=8, le=32)
    subnet_cidr_prefix_v6: int = Field(default=48, ge=16, le=128)
    multi_detector_synergy_2: float = Field(default=0.05, ge=0.0, le=0.5)
    multi_detector_synergy_3_plus: float = Field(default=0.10, ge=0.0, le=0.5)
    synergy_multiplier_step: float = Field(default=0.08, ge=0.0, le=0.5)
    max_confidence_clamp: float = Field(default=1.0, ge=0.5, le=1.0)
    escalation_confidence_threshold: float = Field(default=0.90, ge=0.0, le=1.0)
    subnet_campaign_threshold: int = Field(default=3, ge=2)


class SubnetAggregation(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='allow')

    subnet_cidr: str
    active_hosts: List[str] = Field(default_factory=list)
    total_alerts: int = Field(default=0, ge=0)
    threat_classes: List[str] = Field(default_factory=list)
    participating_detectors: List[str] = Field(default_factory=list)
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    is_campaign: bool = False


class AggregationBuffer(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='allow')

    source_ip: str
    subnet_cidr: str = ''
    alert_count: int = Field(default=0, ge=0)
    deduplicated_record_count: int = Field(default=0, ge=0)
    unique_detectors: List[str] = Field(default_factory=list)
    unique_threat_classes: List[str] = Field(default_factory=list)
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    is_storm_active: bool = False
    storm_alert_count: int = Field(default=0, ge=0)


class AlertStormSummary(BaseModel):
    model_config = ConfigDict(extra='allow')

    source_ip: str
    alert_count: int = Field(..., ge=1)
    duration_sec: float = Field(default=1.0, ge=0.0)
    peak_pps: float = Field(default=0.0, ge=0.0)
    primary_threat: str = 'VOLUMETRIC_FLOOD'
    dropped_duplicates: int = Field(default=0, ge=0)
    threat_classes: List[str] = Field(default_factory=list)
    sample_alert_ids: List[str] = Field(default_factory=list)


def _default_incident_id() -> str:
    date_str = time.strftime('%Y%m%d')
    rand_str = uuid.uuid4().hex[:8].upper()
    return f'INC-{date_str}-{rand_str}'


class FusedIncident(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='allow')

    incident_id: str = Field(default_factory=_default_incident_id)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    primary_source_ip: str
    source_subnet: str = ''
    target_ips: List[str] = Field(default_factory=list)
    target_ports: List[int] = Field(default_factory=list)
    participating_detectors: List[str] = Field(default_factory=list)
    threat_classes: List[str] = Field(default_factory=list)
    threat_class: str = 'UNKNOWN'
    raw_alert_count: int = Field(default=0, ge=0)
    total_raw_alerts_collapsed: int = Field(default=0, ge=0)
    fused_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    overall_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    severity: str = 'MEDIUM'
    attack_stage: str = 'RECONNAISSANCE'
    kill_chain_stages: List[str] = Field(default_factory=list)
    alerts: List[RawAlert] = Field(default_factory=list)
    raw_alert_ids: List[str] = Field(default_factory=list)
    attack_timeline: List[IncidentTimelineEntry] = Field(default_factory=list)
    detector_contributions: Dict[str, int] = Field(default_factory=dict)
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    mitre_attack_hints: List[str] = Field(default_factory=list)
    requires_agentic_triage: bool = True
    requires_human_approval: bool = True
    status: str = 'PENDING_REVIEW'

    @model_validator(mode='after')
    def sync_confidence_and_counts(self) -> FusedIncident:
        if self.fused_confidence and not self.overall_confidence:
            self.overall_confidence = self.fused_confidence
        elif self.overall_confidence and not self.fused_confidence:
            self.fused_confidence = self.overall_confidence
        if self.raw_alert_count == 0 and self.total_raw_alerts_collapsed > 0:
            self.raw_alert_count = self.total_raw_alerts_collapsed
        elif self.total_raw_alerts_collapsed == 0 and self.raw_alert_count > 0:
            self.total_raw_alerts_collapsed = self.raw_alert_count
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    def to_json(self) -> str:
        return self.model_dump_json()
