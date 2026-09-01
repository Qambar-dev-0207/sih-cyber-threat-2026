import React from 'react';
import { FusedIncident } from '../../types';
import { Terminal } from 'lucide-react';
import { formatISODate } from '../../utils/formatters';

interface NarrativeCardProps {
  incident: FusedIncident;
}

export const NarrativeCard: React.FC<NarrativeCardProps> = ({ incident }) => {
  return (
    <div className="p-4 bg-[#080D1A] border border-cyan-500/30 rounded-lg shadow-panel space-y-3 font-mono">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h4 className="text-xs sm:text-sm font-bold tracking-wider text-slate-100 uppercase">
            AI Incident Triage & Executive Attack Narrative
          </h4>
        </div>
        <span className="text-[10px] text-slate-400">
          Synthesized: {formatISODate(incident.created_at)}
        </span>
      </div>

      {/* Narrative Body */}
      <div className="p-3.5 bg-[#050811] rounded border border-slate-800/80 font-sans text-xs text-slate-200 leading-relaxed">
        <p className="font-mono text-cyan-300 font-bold mb-1.5 text-[11px] uppercase flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
          [CORRELATED ATTACK VECTOR: {incident.primary_threat_class}]
        </p>
        <p>{incident.attack_narrative}</p>
      </div>

      {/* Quick Summary Pill Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
        <div className="bg-[#0B1020] p-2 rounded border border-slate-800">
          <span className="text-slate-500 block text-[10px]">SOURCE IP</span>
          <strong className="text-amber-300 truncate block">{incident.source_ip}</strong>
        </div>
        <div className="bg-[#0B1020] p-2 rounded border border-slate-800">
          <span className="text-slate-500 block text-[10px]">CORRELATED STAGES</span>
          <strong className="text-cyan-300">{incident.timeline.length} Stages</strong>
        </div>
        <div className="bg-[#0B1020] p-2 rounded border border-slate-800">
          <span className="text-slate-500 block text-[10px]">RISK SCORE</span>
          <strong className="text-red-400">{incident.risk_score.toFixed(1)} / 100.0</strong>
        </div>
        <div className="bg-[#0B1020] p-2 rounded border border-slate-800">
          <span className="text-slate-500 block text-[10px]">DIODE APPROVAL</span>
          <strong className={incident.status === 'APPROVED' ? 'text-emerald-400' : 'text-amber-400'}>
            {incident.status === 'APPROVED' ? 'APPROVED' : 'REQUIRED'}
          </strong>
        </div>
      </div>
    </div>
  );
};
