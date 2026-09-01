import React from 'react';
import { FusedIncident } from '../../types';
import { SeverityBadge } from './SeverityBadge';
import { formatTimestamp, getSeverityColor } from '../../utils/formatters';
import { ArrowRight, ShieldCheck, Clock, Network, AlertCircle, Layers } from 'lucide-react';

interface IncidentCardProps {
  incident: FusedIncident;
  isSelected: boolean;
  onSelect: (id: string) => void;
}

export const IncidentCard: React.FC<IncidentCardProps> = ({ incident, isSelected, onSelect }) => {
  const styles = getSeverityColor(incident.severity);

  return (
    <div
      onClick={() => onSelect(incident.incident_id)}
      className={`relative p-4 rounded-lg border transition-all duration-200 cursor-pointer select-none font-mono ${
        isSelected
          ? `${styles.bg} ${styles.border} ${styles.glow} ring-1 ring-cyan-400`
          : 'bg-[#090E1B] border-slate-800/80 hover:border-slate-700 hover:bg-[#0D1426]'
      }`}
    >
      {/* Top Bar: Severity Badge, Incident ID, Risk Score, Time */}
      <div className="flex items-center justify-between gap-2 mb-2.5">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={incident.severity} size="sm" />
          <span className="text-xs font-bold text-slate-100 tracking-wider">
            {incident.incident_id}
          </span>
        </div>

        {/* Risk Score Pill */}
        <div className="flex items-center gap-2">
          <div className="flex items-baseline gap-1 bg-black/40 px-2 py-0.5 rounded border border-slate-800 text-xs">
            <span className="text-slate-400 text-[10px]">RISK:</span>
            <span className={`font-extrabold text-sm tabular-nums ${styles.text}`}>
              {incident.risk_score.toFixed(1)}
            </span>
            <span className="text-slate-500 text-[9px]">/100</span>
          </div>

          <div className="text-[11px] text-slate-400 flex items-center gap-1">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>{formatTimestamp(incident.created_at)}</span>
          </div>
        </div>
      </div>

      {/* Primary Narrative Summary */}
      <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed mb-3 font-sans">
        {incident.attack_narrative}
      </p>

      {/* Forensic Entities: Source IP, Threat Class, Targets */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-[#050811] p-2.5 rounded border border-slate-900 mb-3">
        <div className="flex items-center gap-1.5 truncate">
          <Network className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
          <span className="text-slate-400">SRC:</span>
          <strong className="text-amber-300 font-semibold truncate">{incident.source_ip}</strong>
          <span className="text-slate-500 text-[10px]">({incident.subnet})</span>
        </div>

        <div className="flex items-center gap-1.5 truncate">
          <Layers className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
          <span className="text-slate-400">DST:</span>
          <span className="text-cyan-300 font-semibold truncate">
            {incident.target_ips.slice(0, 2).join(', ')}
            {incident.target_ips.length > 2 ? ` +${incident.target_ips.length - 2}` : ''}
          </span>
        </div>
      </div>

      {/* Footer: MITRE pill, Timeline stages, Diode Approval State */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-[11px]">
        {/* MITRE Technique & Threat Badge */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 text-[10px] font-bold">
            {incident.primary_mitre_technique}
          </span>

          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
            {incident.timeline.length} {incident.timeline.length === 1 ? 'Stage' : 'Stages'}
          </span>

          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
            {incident.raw_alert_count} Raw Alerts
          </span>
        </div>

        {/* Status Badge */}
        <div className="flex items-center gap-1">
          {incident.status === 'APPROVED' ? (
            <span className="flex items-center gap-1 text-emerald-400 text-[10px] font-bold bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
              <ShieldCheck className="w-3 h-3" />
              HUMAN APPROVED
            </span>
          ) : (
            <span className="flex items-center gap-1 text-amber-400 text-[10px] font-bold bg-amber-950/60 px-2 py-0.5 rounded border border-amber-500/40 animate-pulse">
              <AlertCircle className="w-3 h-3" />
              PENDING OPERATOR
            </span>
          )}

          <span className="text-cyan-400 ml-1 flex items-center text-[10px] font-bold">
            INSPECT <ArrowRight className="w-3 h-3 ml-0.5" />
          </span>
        </div>
      </div>
    </div>
  );
};
