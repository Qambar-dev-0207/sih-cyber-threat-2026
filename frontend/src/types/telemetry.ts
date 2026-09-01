export interface ActiveDetectors {
  portscan_hll: boolean;
  dga_tunneling: boolean;
  encrypted_malware: boolean;
  c2_beaconing: boolean;
  exfil_ratio: boolean;
  ddos_entropy: boolean;
}

export type DetectorKey = keyof ActiveDetectors;

export interface DetectorMetadata {
  id: DetectorKey;
  name: string;
  shortName: string;
  category: string;
  algorithm: string;
  targetMetric: string;
  mitreTechnique: string;
}

export interface TelemetryMetrics {
  timestamp: number;
  events_per_sec: number;
  mbps: number;
  packet_loss_pct: number;
  pipeline_latency_ms: number;
  buffer_utilization_pct: number;
  total_events_processed: number;
  active_detectors: ActiveDetectors;
}

export interface TelemetryHistoryPoint {
  time: string;
  timestamp: number;
  eps: number;
  mbps: number;
  latency_ms: number;
  loss_pct: number;
  buffer_util_pct: number;
}

export interface SystemHealth {
  status: 'OPTIMAL' | 'DEGRADED' | 'CRITICAL' | 'OFFLINE';
  uptime_seconds: number;
  active_detectors_count: number;
  total_detectors: number;
  version: string;
  mode: 'DIODE_ENCLAVE_LIVE' | 'DIODE_ENCLAVE_SIMULATED' | 'STANDALONE_DEMO';
}
