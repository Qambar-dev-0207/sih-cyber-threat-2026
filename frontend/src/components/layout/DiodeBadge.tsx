import React, { useState } from 'react';
import { ShieldCheck, ArrowRight, Lock, Info, AlertOctagon } from 'lucide-react';

export const DiodeBadge: React.FC = () => {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div className="relative w-full bg-gradient-to-r from-red-950/60 via-slate-900/90 to-cyan-950/60 border-y border-red-500/40 py-2 px-4 shadow-[0_0_20px_rgba(239,68,68,0.2)] select-none">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        {/* Left Badge with Diode Icon */}
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center w-6 h-6 rounded bg-red-500/20 border border-red-500/60 shadow-[0_0_10px_rgba(239,68,68,0.5)]">
            <Lock className="w-3.5 h-3.5 text-red-400 animate-pulse" />
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-red-500/30 border border-red-400/80 text-red-200 font-bold tracking-wider text-[11px] uppercase shadow-[0_0_8px_rgba(239,68,68,0.4)]">
              PHYSICAL DIODE ENCLAVE
            </span>
            <span className="text-slate-200 font-semibold tracking-wide hidden sm:inline">
              Human Authorization Required — Zero Automated Return Path
            </span>
            <span className="text-slate-200 font-semibold tracking-wide sm:hidden">
              Human Authorization Enforced
            </span>
          </div>
        </div>

        {/* Middle Hardware Flow Indicator */}
        <div className="hidden lg:flex items-center gap-3 bg-black/40 px-3 py-1 rounded border border-slate-800 text-[11px]">
          <span className="text-slate-400 flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            TX TAP
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-emerald-400 font-bold flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            ONE-WAY OPTICAL DIODE
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-slate-500 flex items-center gap-1 line-through">
            <AlertOctagon className="w-3 h-3 text-red-400" />
            RX FEEDBACK
          </span>
        </div>

        {/* Right Info Trigger */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <button
              onMouseEnter={() => setShowTooltip(true)}
              onMouseLeave={() => setShowTooltip(false)}
              onClick={() => setShowTooltip((p) => !p)}
              className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/50 transition-colors text-[11px]"
            >
              <Info className="w-3 h-3 text-cyan-400" />
              <span>Diode Specs</span>
            </button>

            {showTooltip && (
              <div className="absolute right-0 top-full mt-2 w-80 p-3.5 bg-[#0A0E1A] border border-cyan-500/60 rounded-lg shadow-2xl z-50 text-[11px] text-slate-300 space-y-2 backdrop-blur-md">
                <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 font-bold text-cyan-300">
                  <span>HARDWARE DIODE PROTOCOL</span>
                  <span className="text-[10px] text-emerald-400">AIR-GAPPED</span>
                </div>
                <p className="text-slate-300 leading-relaxed">
                  The SIH26145 sensor operates strictly on passive physical line taps. Countermeasures (iptables, nftables, Cisco ACL, DNS RPZ, Snort, STIX) cannot be executed back over the network without explicit human verification and out-of-band deployment.
                </p>
                <div className="pt-1 text-[10px] text-slate-400 border-t border-slate-800 flex justify-between">
                  <span>Hardware Hash: <strong className="text-cyan-300">0x7F2A..91E4</strong></span>
                  <span>Safety: <strong className="text-emerald-300">PASSIVE</strong></span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
