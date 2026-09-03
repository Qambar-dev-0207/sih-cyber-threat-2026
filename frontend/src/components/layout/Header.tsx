import React, { useEffect, useState } from 'react';
import { Activity, RefreshCw, Radio, ShieldCheck } from 'lucide-react';
import { ConnectionStatus } from '../../hooks/useWebSocket';

interface HeaderProps {
  connectionStatus: ConnectionStatus;
  streamMode: 'WEBSOCKET' | 'REST_POLLING' | 'OFFLINE_MOCK';
  onReconnect: () => void;
  eps: number;
  mbps: number;
  totalEvents: number;
}

export const Header: React.FC<HeaderProps> = ({ connectionStatus, streamMode, onReconnect, eps, mbps, totalEvents }) => {
  const [time, setTime] = useState('');
  useEffect(() => {
    const update = () => setTime(`${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC`);
    update();
    const id = window.setInterval(update, 1000);
    return () => window.clearInterval(id);
  }, []);
  const isLive = streamMode === 'WEBSOCKET' && connectionStatus === 'CONNECTED';
  const connectionLabel = isLive ? 'Stream live' : streamMode === 'REST_POLLING' ? 'Rest polling' : 'Local simulation';

  return <header className="topbar">
    <div className="topbar-inner">
      <div className="topbar-brand"><div className="topbar-mark"><ShieldCheck size={16} /></div><div><strong>SIH26145</strong><span>Defense enclave</span></div></div>
      <div className="topbar-telemetry" aria-label="Live infrastructure telemetry">
        <div className="telemetry-readout"><Activity size={14} /><span>EPS</span><strong>{(eps ?? 0).toLocaleString()}</strong></div><div className="topbar-divider" />
        <div className="telemetry-readout"><span>Bandwidth</span><strong>{(mbps ?? 0).toFixed(1)} <small>Mbps</small></strong></div><div className="topbar-divider" />
        <div className="telemetry-readout"><span>Events</span><strong>{(totalEvents ?? 0).toLocaleString()}</strong></div>
      </div>
      <div className="topbar-status"><span className={`status-dot ${isLive ? 'pulse' : ''}`} /><span>{connectionLabel}</span><time>{time}</time><button onClick={onReconnect} aria-label="Reconnect telemetry stream" title="Reconnect telemetry stream"><RefreshCw size={15} /></button><span className="topbar-live"><Radio size={14} /> UTC</span></div>
    </div>
  </header>;
};
