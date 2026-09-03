import React from 'react';
import { FusedIncident } from '../../types';
import { formatTimestamp } from '../../utils/formatters';

interface IncidentCardProps {
  incident: FusedIncident;
  isSelected: boolean;
  onSelect: (id: string) => void;
}

function severityColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'var(--critical)';
    case 'HIGH':     return 'var(--high)';
    case 'MEDIUM':   return 'var(--medium)';
    case 'LOW':      return 'var(--low)';
    default:         return 'var(--text-secondary)';
  }
}

export const IncidentCard: React.FC<IncidentCardProps> = ({ incident, isSelected, onSelect }) => {
  const color = severityColor(incident.severity);

  return (
    <div
      onClick={() => onSelect(incident.incident_id)}
      className="relative rounded-lg cursor-pointer transition-all duration-150 select-none"
      style={{
        background: isSelected ? `${color}08` : 'var(--bg-card)',
        border: `1px solid ${isSelected ? `${color}40` : 'var(--border)'}`,
        padding: '12px 14px',
      }}
    >
      {/* Severity accent left bar */}
      <div
        className="absolute left-0 top-3 bottom-3 w-0.5 rounded-r"
        style={{ background: color, opacity: isSelected ? 1 : 0.4 }}
      />

      {/* Top row */}
      <div className="flex items-center justify-between gap-2 mb-1.5 pl-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] font-bold tracking-wider" style={{ color }}>
            {incident.severity}
          </span>
          <span className="font-mono text-xs font-bold" style={{ color: 'var(--text-primary)' }}>
            {incident.incident_id}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-lg font-bold tabular-nums" style={{ color }}>
            {(incident.risk_score ?? 0).toFixed(0)}
          </span>
          <span className="font-mono text-[9px]" style={{ color: 'var(--text-dim)' }}>
            {formatTimestamp(incident.created_at)}
          </span>
        </div>
      </div>

      {/* Narrative */}
      <p className="text-[11px] leading-relaxed line-clamp-2 mb-2 pl-2" style={{ color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
        {incident.attack_narrative}
      </p>

      {/* Data row */}
      <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono pl-2">
        <div className="flex items-center gap-1">
          <span style={{ color: 'var(--text-dim)' }}>SRC</span>
          <span style={{ color: 'var(--medium)' }}>{incident.source_ip ?? 'n/a'}</span>
        </div>
        <div className="w-px h-3" style={{ background: 'var(--border)' }} />
        <div className="flex items-center gap-1">
          <span style={{ color: 'var(--text-dim)' }}>DST</span>
          <span style={{ color: 'var(--text-primary)' }}>
            {(incident.target_ips ?? []).slice(0, 2).join(', ') || 'n/a'}
            {(incident.target_ips?.length ?? 0) > 2 ? ` +${incident.target_ips.length - 2}` : ''}
          </span>
        </div>
        <div className="w-px h-3" style={{ background: 'var(--border)' }} />
        {incident.primary_mitre_technique && (
          <span className="chip chip-teal">{incident.primary_mitre_technique}</span>
        )}
        <span className="chip chip-slate">{incident.timeline?.length ?? 0} stages</span>
        <span
          className="ml-auto font-mono text-[10px] font-semibold"
          style={{ color: incident.status === 'APPROVED' ? 'var(--low)' : 'var(--medium)' }}
        >
          {incident.status === 'APPROVED' ? '✓ APPROVED' : '⏳ PENDING'}
        </span>
      </div>
    </div>
  );
};
