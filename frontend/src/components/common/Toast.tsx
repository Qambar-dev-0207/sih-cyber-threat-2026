import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import { FusedIncident } from '../../types';

interface ToastProps {
  incident: FusedIncident | null;
  onClose: () => void;
  onInvestigate: (id: string) => void;
}

function severityColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'var(--critical)';
    case 'HIGH':     return 'var(--high)';
    case 'MEDIUM':   return 'var(--medium)';
    default:         return 'var(--accent)';
  }
}

export const Toast: React.FC<ToastProps> = ({ incident, onClose, onInvestigate }) => {
  useEffect(() => {
    if (!incident) return;
    const t = setTimeout(onClose, 7000);
    return () => clearTimeout(t);
  }, [incident, onClose]);

  if (!incident) return null;

  const color = severityColor(incident.severity);

  return (
    <div className="fixed bottom-6 right-6 z-50 w-80 animate-fadeUp">
      <div
        className="rounded-lg p-4"
        style={{
          background: 'var(--bg-2)',
          border: `1px solid ${color}40`,
          boxShadow: `0 0 24px ${color}20`,
        }}
      >
        <div className="flex items-start justify-between gap-2 mb-2">
          <div>
            <div className="font-mono text-[9px] tracking-widest mb-0.5" style={{ color: 'var(--text-dim)' }}>
              NEW THREAT DETECTED
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-bold" style={{ color }}>
                {incident.severity}
              </span>
              <span className="font-mono text-xs font-bold" style={{ color: 'var(--text-primary)' }}>
                {incident.primary_threat_class}
              </span>
            </div>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-dim)' }}>
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        <p className="font-mono text-[10px] leading-relaxed line-clamp-2 mb-3" style={{ color: 'var(--text-secondary)' }}>
          {incident.attack_narrative}
        </p>

        <div className="flex items-center justify-between" style={{ borderTop: '1px solid var(--border)', paddingTop: 8 }}>
          <span className="font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
            src <span style={{ color: 'var(--medium)' }}>{incident.source_ip}</span>
          </span>
          <button
            onClick={() => { onInvestigate(incident.incident_id); onClose(); }}
            className="font-mono text-[10px] font-semibold px-2.5 py-1 rounded transition-all"
            style={{
              background: 'var(--accent-dim)',
              border: '1px solid var(--accent-border)',
              color: 'var(--accent)',
            }}
          >
            Investigate →
          </button>
        </div>
      </div>
    </div>
  );
};
