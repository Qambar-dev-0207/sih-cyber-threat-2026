import React from 'react';
import { SIMULATION_SCENARIOS } from '../../utils/constants';
import { ScenarioId, SimulationResponse } from '../../types';

interface DemoControlBarProps {
  onTrigger: (scenario: ScenarioId) => void;
  isSimulating: boolean;
  activeScenario: ScenarioId | null;
  lastResult: SimulationResponse | null;
}

const SCENARIO_COLORS: Record<string, string> = {
  apt:        'var(--critical)',
  ddos:       'var(--high)',
  c2:         '#60A5FA',
  dns_tunnel: 'var(--accent)',
  portscan:   '#A78BFA',
};

export const DemoControlBar: React.FC<DemoControlBarProps> = ({
  onTrigger, isSimulating, activeScenario, lastResult,
}) => {
  return (
    <div className="card">
      <div
        className="flex items-center justify-between px-4 py-2.5"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--text-secondary)' }}>
          Scenario Injection
        </span>
        {lastResult && (
          <div className="flex items-center gap-2 font-mono text-[10px]">
            <span style={{ color: 'var(--text-dim)' }}>last:</span>
            <span style={{ color: 'var(--accent)' }}>{lastResult.scenario?.toUpperCase()}</span>
            <span style={{ color: 'var(--text-dim)' }}>·</span>
            <span style={{ color: 'var(--low)' }}>{lastResult.alerts_injected} alerts</span>
            <span style={{ color: 'var(--text-dim)' }}>·</span>
            <span style={{ color: 'var(--text-secondary)' }}>{lastResult.duration_ms}ms</span>
          </div>
        )}
      </div>

      <div className="px-4 py-3 flex flex-wrap gap-2">
        {SIMULATION_SCENARIOS.map((sc) => {
          const isActive = isSimulating && activeScenario === sc.id;
          const color = SCENARIO_COLORS[sc.id] ?? 'var(--accent)';

          return (
            <button
              key={sc.id}
              onClick={() => !isSimulating && onTrigger(sc.id)}
              disabled={isSimulating}
              className="flex items-center gap-2 px-3 py-1.5 rounded font-mono text-[11px] font-semibold transition-all disabled:opacity-40"
              style={{
                background: isActive ? `${color}14` : 'var(--bg-0)',
                border: `1px solid ${isActive ? `${color}50` : 'var(--border)'}`,
                color: isActive ? color : 'var(--text-secondary)',
              }}
              onMouseEnter={e => {
                if (!isSimulating) {
                  e.currentTarget.style.borderColor = `${color}50`;
                  e.currentTarget.style.color = color;
                }
              }}
              onMouseLeave={e => {
                if (!isActive) {
                  e.currentTarget.style.borderColor = 'var(--border)';
                  e.currentTarget.style.color = 'var(--text-secondary)';
                }
              }}
            >
              {isActive && (
                <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: color }} />
              )}
              {sc.name}
              <span className="font-mono text-[9px]" style={{ color: 'var(--text-dim)' }}>
                [{sc.shortCode}]
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
