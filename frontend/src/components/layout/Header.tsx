import React, { useState, useEffect } from 'react';
import { Shield, Radio, RefreshCw, Cpu, Activity, Clock, Zap } from 'lucide-react';
import { ConnectionStatus } from '../../hooks/useWebSocket';

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
    const updateTime = () => {
      const now = new Date();
      setTime(
        now.toISOString().replace('T', ' ').substring(0, 19) +
          '.' +
          String(now.getMilliseconds()).padStart(3, '0') +
          ' UTC'
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 100);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="w-full bg-[#070A12] border-b border-cyan-500/30 sticky top-0 z-40 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Classification */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.4)]">
            <Shield className="w-6 h-6 text-cyan-400" />
            <span className="absolute -bottom-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-mono text-base sm:text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-cyan-200 to-slate-100 uppercase">
                SIH26145 DEFENSE ENCLAVE
              </h1>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                v2.6.4
              </span>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
              <span className="text-cyan-400 font-semibold tracking-widest">AIR-GAPPED PASSIVE SOC</span>
              <span>//</span>
              <span className="text-amber-400">CLASSIFIED ENCLAVE</span>
              <span>//</span>
              <span className="text-emerald-400 flex items-center gap-1">
                <Cpu className="w-3 h-3" /> ZERO RETURN PATH
              </span>
            </div>
          </div>
        </div>

        {/* Real-time Status & Live Stream Indicator */}
        <div className="flex items-center flex-wrap gap-3 font-mono text-xs">
          {/* UTC Tactical Clock */}
          <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0B101D] border border-slate-800 text-slate-300">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="tabular-nums font-mono text-[11px] text-cyan-200">{time}</span>
          </div>

          {/* Quick Line-rate Pill */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded bg-[#0B101D] border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400 text-[11px]">Line Rate:</span>
            <span className="text-emerald-300 font-bold text-[11px] tabular-nums">
              {eps.toLocaleString()} EPS
            </span>
            <span className="text-slate-500">|</span>
            <span className="text-cyan-300 font-bold text-[11px] tabular-nums">
              {mbps.toFixed(1)} Mbps
            </span>
            <span className="text-slate-500">|</span>
            <span className="text-purple-300 font-bold text-[11px] tabular-nums">
              {totalEvents.toLocaleString()} Total
            </span>
          </div>

          {/* Connection Status Pill */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-[#0B101D] border border-slate-800">
            {streamMode === 'WEBSOCKET' && connectionStatus === 'CONNECTED' ? (
              <div className="flex items-center gap-1.5 text-emerald-400">
                <Radio className="w-3.5 h-3.5 animate-pulse" />
                <span className="text-[11px] font-bold">WS LIVE</span>
              </div>
            ) : streamMode === 'REST_POLLING' ? (
              <div className="flex items-center gap-1.5 text-amber-400">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span className="text-[11px] font-bold">REST POLL</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-cyan-400">
                <Zap className="w-3.5 h-3.5 animate-pulse" />
                <span className="text-[11px] font-bold">OFFLINE MOCK</span>
              </div>
            )}

            <button
              onClick={onReconnect}
              title="Refresh / Reconnect stream"
              className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
