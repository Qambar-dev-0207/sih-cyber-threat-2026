import { useState, useCallback } from 'react';
import { ScenarioId, SimulationResponse, FusedIncident } from '../types';
import { generateSyntheticIncident } from '../utils/mockData';

interface UseSimulationProps {
  onIncidentGenerated?: (incident: FusedIncident) => void;
  onSelectIncident?: (incidentId: string) => void;
}

export function useSimulation({ onIncidentGenerated, onSelectIncident }: UseSimulationProps = {}) {
  const [isSimulating, setIsSimulating] = useState(false);
  const [activeScenario, setActiveScenario] = useState<ScenarioId | null>(null);
  const [lastResult, setLastResult] = useState<SimulationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const triggerSimulation = useCallback(
    async (scenario: ScenarioId) => {
      setIsSimulating(true);
      setActiveScenario(scenario);
      setLastResult(null);
      setError(null);

      const startTime = performance.now();

      try {
        const response = await fetch(`/api/simulate/${scenario}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });

        if (response.ok) {
          const result = (await response.json()) as SimulationResponse;
          const duration = Math.round(performance.now() - startTime);
          const fullResult = { ...result, duration_ms: duration };
          setLastResult(fullResult);

          if (result.incident) {
            onIncidentGenerated?.(result.incident);
            onSelectIncident?.(result.incident.incident_id);
          }
          setIsSimulating(false);
          setActiveScenario(null);
          return fullResult;
        } else {
          throw new Error(`Server returned status ${response.status}`);
        }
      } catch (err: any) {
        // Standalone presentation fallback
        await new Promise((resolve) => setTimeout(resolve, 380));
        const syntheticIncident = generateSyntheticIncident(scenario);
        const duration = Math.round(performance.now() - startTime);

        const syntheticResponse: SimulationResponse = {
          status: 'completed',
          scenario,
          incident_id: syntheticIncident.incident_id,
          incident: syntheticIncident,
          alerts_injected: syntheticIncident.raw_alert_count,
          duration_ms: duration,
          message: `Synthetic ${scenario.toUpperCase()} scenario executed in offline presentation mode.`,
        };

        setLastResult(syntheticResponse);
        onIncidentGenerated?.(syntheticIncident);
        onSelectIncident?.(syntheticIncident.incident_id);
        setIsSimulating(false);
        setActiveScenario(null);
        return syntheticResponse;
      }
    },
    [onIncidentGenerated, onSelectIncident]
  );

  return {
    triggerSimulation,
    isSimulating,
    activeScenario,
    lastResult,
    error,
  };
}
