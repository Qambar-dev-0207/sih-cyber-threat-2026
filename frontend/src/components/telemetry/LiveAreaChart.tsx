import React, { useMemo } from 'react';
import { TelemetryHistoryPoint } from '../../types';

interface LiveAreaChartProps {
  history: TelemetryHistoryPoint[];
  field: 'eps' | 'mbps' | 'latency_ms';
  label: string;
  unit: string;
  color: string;
  height?: number;
}

function smooth(data: number[], k = 3): number[] {
  return data.map((_, i) => {
    const slice = data.slice(Math.max(0, i - k), i + k + 1);
    return slice.reduce((a, b) => a + b, 0) / slice.length;
  });
}

export const LiveAreaChart: React.FC<LiveAreaChartProps> = ({
  history,
  field,
  label,
  unit,
  color,
  height = 72,
}) => {
  const W = 320;
  const H = height;
  const PAD = { top: 8, bottom: 20, left: 8, right: 8 };

  const { polyPoints, areaPoints, minVal, maxVal, current, avg } = useMemo(() => {
    const raw = history.map((h) => {
      const v = h[field];
      return typeof v === 'number' && isFinite(v) ? v : 0;
    });
    const data = raw.length < 2 ? [0, 0] : smooth(raw, 2);
    const minV = Math.min(...data);
    const maxV = Math.max(...data);
    const range = maxV - minV || 1;
    const innerW = W - PAD.left - PAD.right;
    const innerH = H - PAD.top - PAD.bottom;

    const pts = data.map((v, i) => {
      const x = PAD.left + (i / (data.length - 1)) * innerW;
      const y = PAD.top + innerH - ((v - minV) / range) * innerH;
      return [x, y] as [number, number];
    });

    const polyStr = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');

    const first = pts[0];
    const last = pts[pts.length - 1];
    const bottomY = PAD.top + innerH;
    const areaStr = [
      `${first[0].toFixed(1)},${bottomY}`,
      polyStr,
      `${last[0].toFixed(1)},${bottomY}`,
    ].join(' ');

    const cur = raw[raw.length - 1] ?? 0;
    const avgVal = raw.length ? raw.reduce((a, b) => a + b, 0) / raw.length : 0;

    return {
      polyPoints: polyStr,
      areaPoints: areaStr,
      minVal: minV,
      maxVal: maxV,
      current: cur,
      avg: avgVal,
    };
  }, [history, field]);

  const fmt = (v: number) => {
    if (field === 'eps') return v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v.toFixed(0);
    if (field === 'mbps') return v.toFixed(1);
    return (v * 1000).toFixed(0); // to µs
  };

  return (
    <div
      className="card flex flex-col"
      style={{ padding: '10px 14px' }}
    >
      {/* Header row */}
      <div className="flex items-baseline justify-between mb-1">
        <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--text-secondary)' }}>
          {label}
        </span>
        <div className="flex items-baseline gap-1.5">
          <span className="font-mono text-xl font-bold tabular-nums" style={{ color }}>
            {fmt(current)}
          </span>
          <span className="font-mono text-[9px]" style={{ color: 'var(--text-dim)' }}>{unit}</span>
        </div>
      </div>

      {/* SVG area chart */}
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id={`grad-${field}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.2" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Area fill */}
        <polygon
          points={areaPoints}
          fill={`url(#grad-${field})`}
        />

        {/* Line */}
        <polyline
          points={polyPoints}
          fill="none"
          stroke={color}
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />

        {/* Current value dot */}
        {polyPoints && (() => {
          const lastPt = polyPoints.split(' ').pop()?.split(',');
          if (!lastPt) return null;
          return (
            <circle
              cx={parseFloat(lastPt[0])}
              cy={parseFloat(lastPt[1])}
              r="3"
              fill={color}
              style={{ filter: `drop-shadow(0 0 4px ${color})` }}
            />
          );
        })()}

        {/* Bottom axis line */}
        <line
          x1={PAD.left} y1={H - PAD.bottom}
          x2={W - PAD.right} y2={H - PAD.bottom}
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="1"
        />
      </svg>

      {/* Min / Avg / Max */}
      <div className="flex items-center justify-between font-mono text-[9px] mt-0.5" style={{ color: 'var(--text-dim)' }}>
        <span>MIN {fmt(minVal)}</span>
        <span>AVG <span style={{ color: 'var(--text-secondary)' }}>{fmt(avg)}</span></span>
        <span>MAX {fmt(maxVal)}</span>
      </div>
    </div>
  );
};
