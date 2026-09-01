import { SeverityLevel } from '../types';

export function formatTimestamp(timestamp: number | string): string {
  const date = typeof timestamp === 'number' 
    ? new Date(timestamp > 1e11 ? timestamp : timestamp * 1000) 
    : new Date(timestamp);
  
  if (isNaN(date.getTime())) return '--:--:--';
  return date.toTimeString().split(' ')[0] + '.' + String(date.getMilliseconds()).padStart(3, '0');
}

export function formatISODate(timestamp: number | string): string {
  const date = typeof timestamp === 'number' 
    ? new Date(timestamp > 1e11 ? timestamp : timestamp * 1000) 
    : new Date(timestamp);
  
  if (isNaN(date.getTime())) return 'UNKNOWN';
  return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

export function formatRelativeTime(seconds: number): string {
  if (seconds < 0.001) return '+0.00s';
  if (seconds < 60) return `+${seconds.toFixed(2)}s`;
  const mins = Math.floor(seconds / 60);
  const remSec = (seconds % 60).toFixed(1);
  return `+${mins}m ${remSec}s`;
}

export function formatNumber(num: number): string {
  return new Intl.NumberFormat('en-US').format(Math.round(num));
}

export function formatDecimal(num: number, decimals: number = 2): string {
  return Number(num || 0).toFixed(decimals);
}

export function formatBps(mbps: number): string {
  if (mbps >= 1000) {
    return `${(mbps / 1000).toFixed(2)} Gbps`;
  }
  return `${mbps.toFixed(1)} Mbps`;
}

export function formatLatency(latencyMs: number): string {
  if (latencyMs < 0.001) return '< 1 µs';
  if (latencyMs < 1) return `${(latencyMs * 1000).toFixed(0)} µs (${latencyMs.toFixed(2)} ms)`;
  return `${latencyMs.toFixed(2)} ms`;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function getSeverityColor(severity: SeverityLevel): {
  text: string;
  bg: string;
  border: string;
  glow: string;
  badge: string;
  dot: string;
} {
  switch (severity) {
    case 'CRITICAL':
      return {
        text: 'text-red-400',
        bg: 'bg-red-950/40',
        border: 'border-red-500/60',
        glow: 'shadow-[0_0_15px_rgba(239,68,68,0.35)]',
        badge: 'bg-red-500/20 text-red-300 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.3)]',
        dot: 'bg-red-500 shadow-[0_0_8px_#ef4444]',
      };
    case 'HIGH':
      return {
        text: 'text-amber-400',
        bg: 'bg-amber-950/40',
        border: 'border-amber-500/60',
        glow: 'shadow-[0_0_15px_rgba(249,115,22,0.35)]',
        badge: 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-[0_0_10px_rgba(249,115,22,0.3)]',
        dot: 'bg-amber-500 shadow-[0_0_8px_#f97316]',
      };
    case 'MEDIUM':
      return {
        text: 'text-yellow-400',
        bg: 'bg-yellow-950/40',
        border: 'border-yellow-500/50',
        glow: 'shadow-[0_0_12px_rgba(234,179,8,0.25)]',
        badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50',
        dot: 'bg-yellow-400 shadow-[0_0_8px_#eab308]',
      };
    case 'LOW':
    default:
      return {
        text: 'text-cyan-400',
        bg: 'bg-cyan-950/30',
        border: 'border-cyan-500/40',
        glow: 'shadow-[0_0_10px_rgba(6,182,212,0.25)]',
        badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
        dot: 'bg-cyan-400 shadow-[0_0_8px_#06b6d4]',
      };
  }
}
