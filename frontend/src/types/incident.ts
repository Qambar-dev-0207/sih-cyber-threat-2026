import { CountermeasureItem } from './countermeasures';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type IncidentStatus = 'PENDING_REVIEW' | 'APPROVED' | 'DISPATCHED' | 'RESOLVED';

export interface RiskEvidenceItem {
  threat_class: string;
  detector: string;
  base_weight: number;
  confidence: number;
  weighted_score: number;
  metric_summary: string;
}

export interface RiskBreakdown {
  base_risk_sum: number;
  synergy_bonus: number;
  asset_criticality_multiplier: number;
  final_risk_score: number;
  severity: SeverityLevel;
  formula: string;
  evidence_breakdown: RiskEvidenceItem[];
  synergy_reason?: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic_id: string;
  tactic_name: string;
  kill_chain_phase: string;
  confidence: number;
  matched_detector: string;
  description?: string;
}

export interface TimelineStep {
  step_number: number;
  timestamp: number;
  iso_time: string;
  relative_time_offset_sec: number;
  stage: string;
  detector: string;
  threat_class: string;
  summary: string;
  evidence_snapshot: Record<string, any>;
  target_ip?: string;
  target_port?: number;
  confidence: number;
}

export interface FusedIncident {
  incident_id: string;
  created_at: number;
  updated_at: number;
  source_ip: string;
  subnet: string;
  target_ips: string[];
  target_ports: number[];
  severity: SeverityLevel;
  risk_score: number;
  risk_breakdown: RiskBreakdown;
  primary_threat_class: string;
  primary_mitre_technique: string;
  mitre_mappings: MitreMapping[];
  attack_narrative: string;
  timeline: TimelineStep[];
  countermeasures: CountermeasureItem[];
  raw_alert_count: number;
  requires_human_approval: boolean;
  status: IncidentStatus;
  execution_latency_ms: number;
}
