import React, { useState, useEffect } from 'react';
import { ConnectionStatus } from '../../hooks/useWebSocket';
import { Radio, RefreshCw, Activity } from 'lucide-react';

interface HeaderProps {
  connectionStatus: ConnectionStatus;
  streamMode: 'WEBSOCKET' | 'REST_POLLING' | 'OFFLINE_MOCK';
  onReconnect: () => void;
  eps: number;
  mbps: number;
  totalEvents: number;
}

export const Header: React.FC<HeaderProps> = ({
  connectionStatus,
  streamMode,
  onReconnect,
  eps,
  mbps,
  totalEvents,
}) => {
  const [time, setTime] = useState<string>('');

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  const isLive = streamMode === 'WEBSOCKET' && connectionStatus === 'CONNECTED';

  return (
    <header
      style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}
      className="sticky top-0 z-40 w-full"
    >
      <div className="max-w-7xl mx-auto px-5 py-3 flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          {/* Live dot */}
          <span className={`dot-live ${isLive ? 'animate-pulse-accent' : 'opacity-30'}`} />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-sm tracking-widest uppercase" style={{ color: 'var(--accent)' }}>
                SIH26145
              </span>
              <span className="font-mono text-xs" style={{ color: 'var(--text-dim)' }}>
                DEFENSE ENCLAVE
              </span>
            </div>
            <div className="font-mono text-[10px] tracking-wider" style={{ color: 'var(--text-secondary)' }}>
              Autonomous Passive SOC · Air-Gap Enforced
            </div>
          </div>
        </div>

        {/* Metrics Row */}
        <div className="hidden md:flex items-center gap-5 font-mono text-xs">
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3" style={{ color: 'var(--accent)' }} />
            <span style={{ color: 'var(--text-secondary)' }}>EPS</span>
            <span className="font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
              {(eps ?? 0).toLocaleString()}
            </span>
          </div>
          <div className="w-px h-3" style={{ background: 'var(--border)' }} />
          <div className="flex items-center gap-2">
            <span style={{ color: 'var(--text-secondary)' }}>MBPS</span>
            <span className="font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
              {(mbps ?? 0).toFixed(1)}
            </span>
          </div>
          <div className="w-px h-3" style={{ background: 'var(--border)' }} />
          <div className="flex items-center gap-2">
            <span style={{ color: 'var(--text-secondary)' }}>EVENTS</span>
            <span className="font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
              {(totalEvents ?? 0).toLocaleString()}
            </span>
          </div>
        </div>

        {/* Status & Controls */}
        <div className="flex items-center gap-3">
          <span className="font-mono text-[11px] tabular-nums hidden lg:block" style={{ color: 'var(--text-secondary)' }}>
            {time}
          </span>

          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            {isLive ? (
              <span className="flex items-center gap-1.5" style={{ color: 'var(--accent)' }}>
                <Radio className="w-3 h-3" />
                <span className="font-semibold">WS LIVE</span>
              </span>
            ) : streamMode === 'REST_POLLING' ? (
              <span className="flex items-center gap-1.5" style={{ color: 'var(--medium)' }}>
                <RefreshCw className="w-3 h-3 animate-spin" />
                <span>REST POLL</span>
              </span>
            ) : (
              <span className="flex items-center gap-1.5" style={{ color: 'var(--text-secondary)' }}>
                <span>OFFLINE MOCK</span>
              </span>
            )}
          </div>

          <button
            onClick={onReconnect}
            title="Reconnect"
            className="p-1.5 rounded transition-colors"
            style={{ color: 'var(--text-secondary)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--accent)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
