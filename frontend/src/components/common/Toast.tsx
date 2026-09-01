import React, { useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Info, X } from 'lucide-react';
import { FusedIncident } from '../../types';

interface ToastProps {
  incident: FusedIncident | null;
  onClose: () => void;
  onInvestigate: (id: string) => void;
}

export const Toast: React.FC<ToastProps> = ({ incident, onClose, onInvestigate }) => {
  useEffect(() => {
    if (!incident) return;
    const timer = setTimeout(() => {
      onClose();
    }, 8000);
    return () => clearTimeout(timer);
  }, [incident, onClose]);

  if (!incident) return null;

  const isCritical = incident.severity === 'CRITICAL';
  const isHigh = incident.severity === 'HIGH';

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-full animate-slideUp">
      <div
        className={`p-4 rounded-lg border shadow-2xl backdrop-blur-md ${
          isCritical
            ? 'bg-red-950/90 border-red-500/70 shadow-[0_0_25px_rgba(239,68,68,0.5)]'
            : isHigh
            ? 'bg-amber-950/90 border-amber-500/70 shadow-[0_0_20px_rgba(249,115,22,0.4)]'
            : 'bg-slate-900/95 border-cyan-500/50 shadow-[0_0_20px_rgba(6,182,212,0.3)]'
        }`}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            {isCritical ? (
              <ShieldAlert className="w-5 h-5 text-red-400 animate-pulse" />
            ) : isHigh ? (
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            ) : (
              <Info className="w-5 h-5 text-cyan-400" />
            )}
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-slate-300">
                INCOMING THREAT DETECTED
              </span>
              <h4 className="font-mono text-sm font-bold text-white tracking-wide">
                [{incident.severity}] {incident.primary_threat_class}
              </h4>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-0.5 rounded hover:bg-slate-800/60"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="mt-2 text-xs text-slate-300 line-clamp-2 font-mono">
          {incident.attack_narrative}
        </p>

        <div className="mt-3 flex items-center justify-between pt-2 border-t border-white/10 font-mono text-xs">
          <span className="text-slate-400">
            Source: <strong className="text-amber-300">{incident.source_ip}</strong>
          </span>
          <button
            onClick={() => {
              onInvestigate(incident.incident_id);
              onClose();
            }}
            className="px-2.5 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[11px] font-semibold tracking-wider uppercase transition-colors"
          >
            Investigate &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};
