import React from 'react';
import { Lock, Unlock, ShieldAlert, ShieldCheck } from 'lucide-react';

interface ApprovalLockProps {
  isApproved: boolean;
  onToggle: () => void;
  incidentId: string;
}

export const ApprovalLock: React.FC<ApprovalLockProps> = ({ isApproved, onToggle, incidentId }) => {
  return (
    <div
      data-incident-id={incidentId}
      className={`p-3.5 rounded-lg border font-mono text-xs transition-all duration-200 ${
        isApproved
          ? 'bg-emerald-950/40 border-emerald-500/60 shadow-[0_0_15px_rgba(16,185,129,0.25)]'
          : 'bg-amber-950/40 border-amber-500/60 shadow-[0_0_15px_rgba(249,115,22,0.25)]'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Status Text & Explanatory Label */}
        <div className="flex items-center gap-3">
          <div
            className={`w-8 h-8 rounded flex items-center justify-center border ${
              isApproved
                ? 'bg-emerald-500/20 border-emerald-400 text-emerald-300'
                : 'bg-amber-500/20 border-amber-400 text-amber-300'
            }`}
          >
            {isApproved ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4 animate-pulse" />}
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 uppercase text-xs">
                {isApproved ? 'OPERATOR AUTHORIZATION GRANTED' : 'HUMAN AUTHORIZATION REQUIRED'}
              </span>
              <span
                className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                  isApproved
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                }`}
              >
                {isApproved ? 'UNLOCKED' : 'DIODE LOCKED'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {isApproved
                ? 'Countermeasures validated and authorized for out-of-band enclave deployment.'
                : 'Physical diode restricts automated network deployment. Operator must authorize rules before export.'}
            </p>
          </div>
        </div>

        {/* Toggle Button */}
        <button
          onClick={onToggle}
          className={`px-4 py-2 rounded text-xs font-bold uppercase tracking-wider flex items-center gap-2 border transition-all ${
            isApproved
              ? 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.5)]'
              : 'bg-amber-600 hover:bg-amber-500 text-white border-amber-400 shadow-[0_0_12px_rgba(249,115,22,0.5)]'
          }`}
        >
          {isApproved ? (
            <>
              <ShieldCheck className="w-4 h-4" />
              <span>Revoke Approval</span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-4 h-4" />
              <span>Authorize Countermeasures</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
