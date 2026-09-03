import React from 'react';
import { formatNumber } from '../../utils/formatters';

interface StatusBarProps { totalEvents: number; activeDetectorsCount: number; bufferUtilization: number; pipelineLatency: number; }

export const StatusBar: React.FC<StatusBarProps> = ({ totalEvents = 0, activeDetectorsCount = 6, bufferUtilization = 0, pipelineLatency = 0 }) => <footer className="statusbar"><div className="statusbar-inner"><span><b>Events</b>{formatNumber(totalEvents)}</span><span><b>Engines</b>{activeDetectorsCount}/6 online</span><span><b>Buffer</b>{bufferUtilization.toFixed(1)}%</span><span><b>Latency</b>{(pipelineLatency * 1000).toFixed(0)} μs</span><span><b>Data diode</b><i className="status-dot" /> SHA256:7F2A..91E4</span><span className="statusbar-build">Build 2026.09.01</span></div></footer>;
