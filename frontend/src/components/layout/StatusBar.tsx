import React from 'react';
import { ShieldCheck, HardDrive, Cpu, Terminal, GitCommit } from 'lucide-react';
import { formatNumber } from '../../utils/formatters';

interface StatusBarProps {
  totalEvents: number;
  activeDetectorsCount: number;
  bufferUtilization: number;
  pipelineLatency: number;
}

export const StatusBar: React.FC<StatusBarProps> = ({
  totalEvents,
  activeDetectorsCount,
  bufferUtilization,
  pipelineLatency,
}) => {
  return (
    <footer className="w-full bg-[#05070D] border-t border-slate-800/80 py-2 px-4 text-slate-400 font-mono text-[11px] select-none mt-auto">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
        {/* Left Side System Information */}
        <div className="flex items-center flex-wrap gap-4">
          <span className="flex items-center gap-1.5 text-slate-300">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>ENCLAVE CORE:</span>
            <strong className="text-cyan-300 font-semibold">ACTIVE</strong>
          </span>

          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span>STREAM DETECTORS:</span>
            <strong className="text-emerald-300">{activeDetectorsCount}/6 ONLINE</strong>
          </span>

          <span className="hidden sm:flex items-center gap-1.5">
            <HardDrive className="w-3.5 h-3.5 text-purple-400" />
            <span>EVENTS PROCESSED:</span>
            <strong className="text-slate-200 tabular-nums">{formatNumber(totalEvents)}</strong>
          </span>
        </div>

        {/* Right Side Diode & Hardware Hash */}
        <div className="flex items-center flex-wrap gap-4">
          <span className="hidden md:flex items-center gap-1.5">
            <span>RING BUFFER:</span>
            <span
              className={`font-semibold tabular-nums ${
                bufferUtilization > 50 ? 'text-amber-400' : 'text-emerald-400'
              }`}
            >
              {bufferUtilization.toFixed(1)}%
            </span>
          </span>

          <span className="hidden md:flex items-center gap-1.5">
            <span>LATENCY:</span>
            <span className="text-cyan-300 font-semibold tabular-nums">
              {pipelineLatency.toFixed(2)} ms
            </span>
          </span>

          <span className="flex items-center gap-1.5 text-slate-400">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>DIODE:</span>
            <code className="text-[10px] text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-500/30">
              SHA256:7F2A..91E4
            </code>
          </span>

          <span className="hidden lg:flex items-center gap-1 text-slate-500">
            <GitCommit className="w-3 h-3" />
            <span>BUILD: 2026.09.01</span>
          </span>
        </div>
      </div>
    </footer>
  );
};
