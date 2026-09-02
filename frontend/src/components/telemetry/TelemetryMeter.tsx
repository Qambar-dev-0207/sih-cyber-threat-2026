import React from 'react';
import { TelemetryMetrics, TelemetryHistoryPoint } from '../../types';

// Inline mini sparkline
const MiniSparkline: React.FC<{ data: number[]; color: string; width?: number; height?: number }> = ({
  data,
  color,
  width = 80,
  height = 28,
}) => {
  if (data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const pts = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - ((v - min) / range) * (height - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <svg width={width} height={height} className="overflow-visible">
      <polyline
        points={pts}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        opacity="0.8"
      />
    </svg>
  );
};

interface TelemetryMeterProps {
  metrics: TelemetryMetrics;
  history: TelemetryHistoryPoint[];
}

interface GaugeBarProps {
  label: string;
  valueStr: string;
  pct: number;
  color: string;
  subLabel?: string;
}

const GaugeBar: React.FC<GaugeBarProps> = ({ label, valueStr, pct, color, subLabel }) => (
  <div className="space-y-1.5">
    <div className="flex items-baseline justify-between">
      <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </span>
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-base font-bold tabular-nums" style={{ color }}>
          {valueStr}
        </span>
        {subLabel && (
          <span className="font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
            {subLabel}
          </span>
        )}
      </div>
    </div>
    <div className="h-px w-full rounded-full" style={{ background: 'var(--border)' }}>
      <div
        className="h-px rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, pct)}%`, background: color, boxShadow: `0 0 6px ${color}60` }}
      />
    </div>
  </div>
);

export const TelemetryMeter: React.FC<TelemetryMeterProps> = ({ metrics, history }) => {
  const epsHistory = history.map((h) => h.eps);
  const mbpsHistory = history.map((h) => h.mbps);
  const latHistory = history.map((h) => h.latency_ms * 1000); // to µs

  const epsPct = Math.min(100, ((metrics?.events_per_sec ?? 0) / 35000) * 100);
  const mbpsPct = Math.min(100, ((metrics?.mbps ?? 0) / 300) * 100);
  const lossPct = Math.min(100, ((metrics?.packet_loss_pct ?? 0) / 5) * 100);
  const bufPct = metrics?.buffer_utilization_pct ?? 0;

  const detectors = metrics?.active_detectors ?? {};
  const detectorKeys = Object.keys(detectors);
  const activeCount = detectorKeys.filter((k) => detectors[k as keyof typeof detectors]).length;

  return (
    <div className="card grid-bg">
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-2">
          <span className="dot-live animate-pulse-accent" />
          <span className="font-mono text-xs font-semibold tracking-widest uppercase" style={{ color: 'var(--text-primary)' }}>
            Line-Rate Telemetry
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="chip chip-teal">{activeCount}/6 DETECTORS</span>
          <span className="font-mono text-[10px]" style={{ color: 'var(--text-dim)' }}>
            500ms ticker
          </span>
        </div>
      </div>

      <div className="px-4 py-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* EPS */}
        <div className="space-y-3">
          <GaugeBar
            label="Ingest Rate"
            valueStr={(metrics?.events_per_sec ?? 0).toLocaleString()}
            pct={epsPct}
            color="var(--accent)"
            subLabel="EPS"
          />
          <div className="flex items-end justify-between">
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-dim)' }}>
              target &gt;20k
            </span>
            <MiniSparkline data={epsHistory} color="var(--accent)" />
          </div>
        </div>

        {/* Mbps */}
        <div className="space-y-3">
          <GaugeBar
            label="Line Bandwidth"
            valueStr={(metrics?.mbps ?? 0).toFixed(1)}
            pct={mbpsPct}
            color="#60A5FA"
            subLabel="Mbps"
          />
          <div className="flex items-end justify-between">
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-dim)' }}>
              100–300 mbps
            </span>
            <MiniSparkline data={mbpsHistory} color="#60A5FA" />
          </div>
        </div>

        {/* Latency */}
        <div className="space-y-3">
          <GaugeBar
            label="Pipeline Latency"
            valueStr={((metrics?.pipeline_latency_ms ?? 0) * 1000).toFixed(0)}
            pct={Math.min(100, ((metrics?.pipeline_latency_ms ?? 0) / 1) * 100)}
            color="#A78BFA"
            subLabel="µs"
          />
          <div className="flex items-end justify-between">
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-dim)' }}>
              sub-ms target
            </span>
            <MiniSparkline data={latHistory} color="#A78BFA" />
          </div>
        </div>

        {/* Buffer & Loss */}
        <div className="space-y-3">
          <GaugeBar
            label="Packet Loss"
            valueStr={(metrics?.packet_loss_pct ?? 0).toFixed(3)}
            pct={lossPct}
            color={lossPct > 1 ? 'var(--critical)' : 'var(--low)'}
            subLabel="%"
          />
          <GaugeBar
            label="Buffer Util"
            valueStr={bufPct.toFixed(1)}
            pct={bufPct}
            color={bufPct > 70 ? 'var(--medium)' : 'var(--accent)'}
            subLabel="%"
          />
        </div>
      </div>
    </div>
  );
};
