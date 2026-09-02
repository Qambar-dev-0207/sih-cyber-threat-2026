import React from 'react';
import { ActiveDetectors } from '../../types';
import { DETECTORS_LIST } from '../../utils/constants';

interface DetectorGridProps {
  activeDetectors: ActiveDetectors;
}

const DETECTOR_COLORS: Record<string, string> = {
  portscan_hll:    '#60A5FA',
  dga_tunneling:   '#A78BFA',
  encrypted_malware: '#F472B6',
  c2_beaconing:    'var(--critical)',
  exfil_ratio:     'var(--medium)',
  ddos_entropy:    'var(--accent)',
};

export const DetectorGrid: React.FC<DetectorGridProps> = ({ activeDetectors }) => {
  return (
    <div className="card">
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <span className="font-mono text-xs font-semibold tracking-widest uppercase" style={{ color: 'var(--text-primary)' }}>
          Streaming Detectors
        </span>
        <span className="chip chip-teal">6-ENGINE MATRIX</span>
      </div>

      <div className="px-4 py-3 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {DETECTORS_LIST.map((det) => {
          const isActive = activeDetectors ? (activeDetectors[det.id] ?? true) : true;
          const color = DETECTOR_COLORS[det.id] ?? 'var(--accent)';

          return (
            <div
              key={det.id}
              className="flex flex-col items-center gap-2 p-3 rounded-lg"
              style={{
                background: isActive ? `${color}08` : 'rgba(255,255,255,0.02)',
                border: `1px solid ${isActive ? `${color}25` : 'var(--border)'}`,
              }}
            >
              {/* Status indicator */}
              <div className="flex items-center gap-1.5 w-full">
                <span
                  className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isActive ? 'animate-pulse' : ''}`}
                  style={{ background: isActive ? color : 'var(--text-dim)', boxShadow: isActive ? `0 0 6px ${color}` : 'none' }}
                />
                <span
                  className="font-mono text-[10px] font-bold tracking-wider truncate uppercase"
                  style={{ color: isActive ? color : 'var(--text-dim)' }}
                >
                  {det.shortName}
                </span>
              </div>

              {/* Algorithm tag */}
              <span className="font-mono text-[9px] text-center leading-tight" style={{ color: 'var(--text-secondary)' }}>
                {det.algorithm}
              </span>

              {/* Status text */}
              <span
                className="font-mono text-[9px] font-semibold tracking-widest"
                style={{ color: isActive ? color : 'var(--text-dim)' }}
              >
                {isActive ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
