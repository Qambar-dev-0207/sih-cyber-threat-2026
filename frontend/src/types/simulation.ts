import { FusedIncident } from './incident';

export type ScenarioId = 'apt' | 'ddos' | 'c2' | 'dns_tunnel' | 'portscan';

export interface SimulationScenario {
  id: ScenarioId;
  name: string;
  shortCode: string;
  description: string;
  threatClasses: string[];
  expectedMitre: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  stagesCount: number;
}

export interface SimulationResponse {
  status: 'triggered' | 'completed' | 'failed';
  scenario: ScenarioId;
  incident_id?: string;
  incident?: FusedIncident;
  alerts_injected: number;
  duration_ms: number;
  message: string;
}
