import React from 'react';
import { SIMULATION_SCENARIOS } from '../../utils/constants';
import { ScenarioId, SimulationResponse } from '../../types';
import { CyberButton } from '../common/CyberButton';
import { Play, Sparkles, AlertTriangle, ShieldCheck, Flame, Radio, Globe, Terminal } from 'lucide-react';

interface DemoControlBarProps {
  onTrigger: (scenario: ScenarioId) => void;
  isSimulating: boolean;
  activeScenario: ScenarioId | null;
  lastResult: SimulationResponse | null;
}

export const DemoControlBar: React.FC<DemoControlBarProps> = ({
  onTrigger,
  isSimulating,
  activeScenario,
  lastResult,
}) => {
  const getScenarioIcon = (id: ScenarioId) => {
    switch (id) {
      case 'apt':
        return <Flame className="w-3.5 h-3.5 text-red-400" />;
      case 'ddos':
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />;
      case 'c2':
        return <Radio className="w-3.5 h-3.5 text-cyan-400" />;
      case 'dns_tunnel':
        return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      case 'portscan':
        return <Terminal className="w-3.5 h-3.5 text-blue-400" />;
      default:
        return <Play className="w-3.5 h-3.5 text-cyan-400" />;
    }
  };

  return (
    <div className="w-full bg-[#080D1A] border border-cyan-500/40 rounded-lg p-3.5 shadow-panel relative overflow-hidden">
      {/* Background cyber accent */}
      <div className="absolute top-0 right-0 w-64 h-full bg-gradient-to-l from-cyan-500/5 to-transparent pointer-events-none" />

      <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="font-mono text-xs sm:text-sm font-bold tracking-wider text-slate-100 uppercase">
            Live Presentation & Scenario Control Bar
          </h3>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
            1-CLICK DEMO
          </span>
        </div>

        {/* Last Simulation Status Feedback */}
        {lastResult && (
          <div className="flex items-center gap-2 font-mono text-[11px] bg-[#0C1222] px-3 py-1 rounded border border-cyan-500/30 animate-fadeIn">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">Triggered:</span>
            <strong className="text-cyan-300 uppercase">{lastResult.scenario}</strong>
            <span className="text-slate-500">|</span>
            <span className="text-emerald-400 font-semibold">{lastResult.alerts_injected} Alerts</span>
            <span className="text-slate-500">|</span>
            <span className="text-amber-400">{lastResult.duration_ms}ms</span>
          </div>
        )}
      </div>

      {/* 1-Click Scenario Trigger Buttons */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
        {SIMULATION_SCENARIOS.map((sc) => {
          const isCurrentActive = isSimulating && activeScenario === sc.id;

          const variant =
            sc.id === 'apt'
              ? 'red'
              : sc.id === 'ddos'
              ? 'amber'
              : sc.id === 'c2'
              ? 'cyan'
              : sc.id === 'dns_tunnel'
              ? 'emerald'
              : 'outline';

          return (
            <CyberButton
              key={sc.id}
              variant={variant}
              size="sm"
              loading={isCurrentActive}
              disabled={isSimulating}
              onClick={() => onTrigger(sc.id)}
              icon={!isCurrentActive ? getScenarioIcon(sc.id) : undefined}
              className="w-full flex flex-col items-start text-left p-2.5 h-auto"
            >
              <div className="flex items-center justify-between w-full">
                <span className="font-bold text-xs">{sc.name}</span>
                <span className="text-[9px] opacity-75 font-normal">[{sc.shortCode}]</span>
              </div>
              <span className="text-[9px] text-slate-300 normal-case line-clamp-1 mt-1 opacity-80">
                {sc.description}
              </span>
            </CyberButton>
          );
        })}
      </div>
    </div>
  );
};
