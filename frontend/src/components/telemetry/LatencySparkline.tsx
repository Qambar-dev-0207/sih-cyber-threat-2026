import React, { useMemo } from 'react';
import { TelemetryHistoryPoint } from '../../types';
import { Activity } from 'lucide-react';

interface LatencySparklineProps {
  history: TelemetryHistoryPoint[];
  currentLatency: number;
}

export const LatencySparkline: React.FC<LatencySparklineProps> = ({ history, currentLatency }) => {
  const width = 320;
  const height = 90;
  const padding = 10;

  const latencies = useMemo(() => {
    if (history.length === 0) return [currentLatency, currentLatency];
    return history.map((h) => h.latency_ms);
  }, [history, currentLatency]);

  const stats = useMemo(() => {
    if (latencies.length === 0) return { min: 0.2, max: 0.8, avg: 0.4, p99: 0.6 };
    const min = Math.min(...latencies);
    const max = Math.max(...latencies);
    const sum = latencies.reduce((acc, v) => acc + v, 0);
    const avg = sum / latencies.length;
    const sorted = [...latencies].sort((a, b) => a - b);
    const p99 = sorted[Math.floor(sorted.length * 0.95)] || max;
    return { min, max, avg, p99 };
  }, [latencies]);

  const points = useMemo(() => {
    if (latencies.length < 2) return '';
    const minVal = Math.max(0.1, stats.min * 0.8);
    const maxVal = Math.max(minVal + 0.2, stats.max * 1.2);
    const effectiveWidth = width - padding * 2;
    const effectiveHeight = height - padding * 2;

    return latencies
      .map((val, idx) => {
        const x = padding + (idx / (latencies.length - 1)) * effectiveWidth;
        const normalized = (val - minVal) / (maxVal - minVal);
        const y = height - padding - normalized * effectiveHeight;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }, [latencies, stats, width, height, padding]);

  return (
    <div className="flex flex-col p-3 bg-[#0A0F1D] border border-slate-800 rounded-lg shadow-panel relative group hover:border-slate-700 transition-all flex-1 min-w-[280px]">
      {/* Header */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5 text-[11px] font-mono font-semibold tracking-wider text-slate-400 uppercase">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>Pipeline Latency</span>
        </div>
        <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
          SUB-MS TARGET
        </span>
      </div>

      {/* Latency Digital Readout */}
      <div className="flex items-baseline gap-2 mb-1">
        <span className="font-mono text-xl sm:text-2xl font-extrabold text-cyan-300 tabular-nums">
          {currentLatency < 1 ? (currentLatency * 1000).toFixed(0) : currentLatency.toFixed(2)}
        </span>
        <span className="font-mono text-xs text-slate-400 font-semibold uppercase">
          {currentLatency < 1 ? 'µs (sub-ms)' : 'ms'}
        </span>
      </div>

      {/* SVG Sparkline Waveform */}
      <div className="relative w-full h-[65px] bg-[#060913] rounded border border-slate-900 overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-full preserve-3d"
        >
          <defs>
            <linearGradient id="latencyGlow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06B6D4" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="#1E293B" strokeDasharray="3 3" />

          {/* Area Fill */}
          {points && (
            <polygon
              points={`${padding},${height - padding} ${points} ${width - padding},${height - padding}`}
              fill="url(#latencyGlow)"
            />
          )}

          {/* Sparkline Stroke */}
          {points && (
            <polyline
              points={points}
              fill="none"
              stroke="#06B6D4"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ filter: 'drop-shadow(0 0 6px rgba(6,182,212,0.8))' }}
            />
          )}
        </svg>

        {/* Pulse Dot on Current Point */}
        <div className="absolute right-2 top-2 flex items-center gap-1 font-mono text-[9px] text-cyan-400">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
          <span>REAL-TIME</span>
        </div>
      </div>

      {/* Stats Summary Footer */}
      <div className="mt-2 grid grid-cols-4 gap-1 text-[10px] font-mono text-center pt-1 border-t border-slate-900">
        <div>
          <span className="text-slate-500 block">MIN</span>
          <span className="text-emerald-400 font-semibold">{stats.min.toFixed(2)}ms</span>
        </div>
        <div>
          <span className="text-slate-500 block">AVG</span>
          <span className="text-cyan-300 font-semibold">{stats.avg.toFixed(2)}ms</span>
        </div>
        <div>
          <span className="text-slate-500 block">P99</span>
          <span className="text-amber-400 font-semibold">{stats.p99.toFixed(2)}ms</span>
        </div>
        <div>
          <span className="text-slate-500 block">PEAK</span>
          <span className="text-red-400 font-semibold">{stats.max.toFixed(2)}ms</span>
        </div>
      </div>
    </div>
  );
};
