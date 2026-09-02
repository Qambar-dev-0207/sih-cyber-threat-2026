import React from 'react';
import { formatNumber } from '../../utils/formatters';

interface StatusBarProps {
  totalEvents: number;
  activeDetectorsCount: number;
  bufferUtilization: number;
  pipelineLatency: number;
}

export const StatusBar: React.FC<StatusBarProps> = ({
  totalEvents = 0,
  activeDetectorsCount = 6,
  bufferUtilization = 0,
  pipelineLatency = 0,
}) => {
  const items = [
    { label: 'EVENTS', value: formatNumber(totalEvents ?? 0) },
    { label: 'DETECTORS', value: `${activeDetectorsCount ?? 6}/6` },
    { label: 'BUFFER', value: `${(bufferUtilization ?? 0).toFixed(1)}%` },
    { label: 'LATENCY', value: `${((pipelineLatency ?? 0) * 1000).toFixed(0)} µs` },
    { label: 'DIODE HASH', value: 'SHA256:7F2A..91E4' },
    { label: 'BUILD', value: '2026.09.01' },
  ];

  return (
    <footer
      className="w-full py-2 px-5"
      style={{ background: 'var(--bg-1)', borderTop: '1px solid var(--border)' }}
    >
      <div className="max-w-7xl mx-auto flex flex-wrap items-center gap-5 font-mono text-[10px]">
        {items.map((item, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <span style={{ color: 'var(--text-dim)' }}>{item.label}</span>
            <span style={{ color: 'var(--text-secondary)' }}>{item.value}</span>
          </div>
        ))}
      </div>
    </footer>
  );
};
