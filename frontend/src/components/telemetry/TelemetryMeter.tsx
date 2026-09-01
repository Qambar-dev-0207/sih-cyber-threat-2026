import React from 'react';
import { TelemetryMetrics, TelemetryHistoryPoint } from '../../types';
import { RadialGauge } from './RadialGauge';
import { LatencySparkline } from './LatencySparkline';
import { Gauge } from 'lucide-react';

interface TelemetryMeterProps {
  metrics: TelemetryMetrics;
  history: TelemetryHistoryPoint[];
}

export const TelemetryMeter: React.FC<TelemetryMeterProps> = ({ metrics, history }) => {
  return (
    <div className="w-full bg-[#080D1A] border border-slate-800 rounded-lg p-4 shadow-panel space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
        <div className="flex items-center gap-2">
          <Gauge className="w-4 h-4 text-cyan-400" />
          <h3 className="font-mono text-xs sm:text-sm font-bold tracking-wider text-slate-200 uppercase">
            Live Line-Rate Telemetry Meter
          </h3>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-slate-400 hidden sm:inline">RING BUFFER:</span>
          <span className="text-cyan-300 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30 tabular-nums">
            {metrics.buffer_utilization_pct.toFixed(1)}% UTILIZED
          </span>
        </div>
      </div>

      {/* 4-Metric Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 items-stretch">
        {/* Metric 1: Ingest EPS */}
        <RadialGauge
          label="INGEST RATE"
          value={metrics.events_per_sec}
          min={0}
          max={35000}
          unit="EVENTS / SEC"
          color="emerald"
          targetBenchmark="> 20,000 EPS"
        />

        {/* Metric 2: Throughput Mbps */}
        <RadialGauge
          label="LINE BANDWIDTH"
          value={metrics.mbps}
          min={0}
          max={300}
          unit="MBPS"
          color="cyan"
          targetBenchmark="100-300 MBPS"
        />

        {/* Metric 3: Packet Loss */}
        <RadialGauge
          label="PACKET DROP"
          value={metrics.packet_loss_pct}
          min={0}
          max={5}
          unit="% PACKET LOSS"
          color="emerald"
          targetBenchmark="0.000% LOSS"
        />

        {/* Metric 4: Pipeline Latency Sparkline */}
        <LatencySparkline
          history={history}
          currentLatency={metrics.pipeline_latency_ms}
        />
      </div>
    </div>
  );
};
