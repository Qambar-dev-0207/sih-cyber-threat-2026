import React from 'react';
import { ActiveDetectors } from '../../types';
import { DETECTORS_LIST } from '../../utils/constants';
import { Cpu, ShieldCheck, Radio } from 'lucide-react';

interface DetectorGridProps {
  activeDetectors: ActiveDetectors;
}

export const DetectorGrid: React.FC<DetectorGridProps> = ({ activeDetectors }) => {
  return (
    <div className="w-full bg-[#080D1A] border border-slate-800 rounded-lg p-4 shadow-panel">
      {/* Section Header */}
      <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <h3 className="font-mono text-xs sm:text-sm font-bold tracking-wider text-slate-200 uppercase">
            Streaming Threat Detectors (6-Engine Matrix)
          </h3>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="flex items-center gap-1 text-emerald-400 font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#10b981]" />
            ALL ENGINES ONLINE
          </span>
        </div>
      </div>

      {/* Grid of 6 Streaming Detectors */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {DETECTORS_LIST.map((det) => {
          const isActive = activeDetectors[det.id] ?? true;

          return (
            <div
              key={det.id}
              className={`p-3 rounded border transition-all duration-200 relative overflow-hidden group ${
                isActive
                  ? 'bg-[#0B1020] border-cyan-500/30 hover:border-cyan-400 hover:shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                  : 'bg-slate-900/40 border-slate-800 opacity-60'
              }`}
            >
              {/* Scanline top highlight */}
              <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />

              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isActive
                          ? 'bg-emerald-400 animate-pulse shadow-[0_0_8px_#10b981]'
                          : 'bg-slate-600'
                      }`}
                    />
                    <span className="font-mono font-bold text-xs text-cyan-300 tracking-wide">
                      {det.shortName}
                    </span>
                  </div>
                  <h4 className="font-mono text-[11px] font-medium text-slate-300 mt-1 leading-snug">
                    {det.name}
                  </h4>
                </div>

                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
                  {det.mitreTechnique}
                </span>
              </div>

              <div className="mt-2 text-[10px] font-mono text-slate-400 space-y-1">
                <div className="text-slate-500 truncate">
                  <span className="text-slate-400 font-medium">Algo:</span> {det.algorithm}
                </div>
                <div className="text-cyan-400/80 truncate">
                  <span className="text-slate-400 font-medium">Trigger:</span> {det.targetMetric}
                </div>
              </div>

              <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono">
                <span className="text-slate-500 flex items-center gap-1">
                  <Radio className="w-3 h-3 text-cyan-400 animate-pulse" />
                  <span>PASSIVE TAP</span>
                </span>
                <span className="text-emerald-400 font-semibold flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" />
                  <span>HEALTHY</span>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
