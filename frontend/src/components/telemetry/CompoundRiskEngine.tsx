import React from 'react';
import { FusedIncident } from '../../types';

interface CompoundRiskEngineProps {
  incident: FusedIncident | null;
  metrics?: {
    events_per_sec?: number;
    mbps?: number;
    packet_loss_pct?: number;
    buffer_utilization_pct?: number;
  } | null;
}

function sevColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return '#FF4D4D';
    case 'HIGH':     return '#FF8C42';
    case 'MEDIUM':   return '#FFD166';
    case 'LOW':      return '#06D6A0';
    default:         return '#00C9A7';
  }
}

const Connector: React.FC<{ x1: number; y1: number; x2: number; y2: number; color?: string; delay?: number }> = ({
  x1, y1, x2, y2, color = '#00C9A7', delay = 0,
}) => {
  const midX = (x1 + x2) / 2;
  const path = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
  return (
    <g>
      <path d={path} fill="none" stroke={color} strokeWidth="1" strokeOpacity="0.12" strokeDasharray="4 4" />
      <path
        d={path} fill="none" stroke={color} strokeWidth="1.5"
        strokeDasharray="6 10" strokeLinecap="round"
        style={{ animation: `dash-flow 1.8s linear ${delay}s infinite`, opacity: 0.75 }}
      />
      <polygon points={`${x2},${y2} ${x2 - 6},${y2 - 3} ${x2 - 6},${y2 + 3}`} fill={color} opacity="0.85" />
    </g>
  );
};

const InputNode: React.FC<{ label: string; value: string; sub: string; color: string }> = ({
  label, value, sub, color,
}) => (
  <div
    className="font-mono rounded-lg p-3"
    style={{ background: `${color}0D`, border: `1px solid ${color}45`, minWidth: 165 }}
  >
    <div className="text-[9px] tracking-widest uppercase mb-1.5" style={{ color: `${color}90` }}>{label}</div>
    <div className="text-base font-bold tabular-nums leading-none" style={{ color }}>{value}</div>
    <div className="text-[10px] mt-1 leading-snug" style={{ color: 'rgba(255,255,255,0.32)' }}>{sub}</div>
  </div>
);

const CentralNode: React.FC<{ label: string; sublabel: string; color: string; score: number }> = ({
  label, sublabel, color, score,
}) => (
  <div
    className="flex flex-col items-center justify-center font-mono rounded-full"
    style={{
      width: 110, height: 110, flexShrink: 0,
      background: `radial-gradient(circle, ${color}1A 0%, ${color}07 70%, transparent 100%)`,
      border: `2px solid ${color}55`,
      boxShadow: `0 0 30px ${color}28, inset 0 0 18px ${color}10`,
    }}
  >
    <div className="text-[9px] tracking-widest text-center mb-0.5" style={{ color: `${color}80` }}>{sublabel}</div>
    <div className="text-2xl font-black tabular-nums" style={{ color }}>{score}</div>
    <div className="text-[9px] font-bold tracking-wider text-center leading-tight" style={{ color }}>{label}</div>
  </div>
);

const AssessmentNode: React.FC<{ verdict: string; detail: string; color: string; action: string }> = ({
  verdict, detail, color, action,
}) => (
  <div
    className="font-mono rounded-lg p-4 flex flex-col gap-1.5"
    style={{ background: `${color}0D`, border: `1px solid ${color}40`, minWidth: 175 }}
  >
    <div className="text-[9px] tracking-widest uppercase" style={{ color: `${color}70` }}>ASSESSMENT</div>
    <div className="text-base font-bold leading-tight" style={{ color }}>{verdict}</div>
    <div className="text-[10px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.38)' }}>{detail}</div>
    <div
      className="mt-2 text-center text-[10px] font-bold tracking-widest py-1 rounded"
      style={{ background: `${color}1A`, color, border: `1px solid ${color}35` }}
    >
      {action}
    </div>
  </div>
);

export const CompoundRiskEngine: React.FC<CompoundRiskEngineProps> = ({ incident, metrics }) => {
  const isBlocking = incident
    ? (incident.severity === 'CRITICAL' || incident.severity === 'HIGH')
    : (metrics?.packet_loss_pct ?? 0) > 0.5;

  const color = incident ? sevColor(incident.severity) : '#00C9A7';
  const riskScore = Math.round(incident?.risk_score ?? 0);
  const statusColor = isBlocking ? '#FF4D4D' : (incident ? '#FFD166' : '#00C9A7');
  const statusLabel = incident ? (isBlocking ? 'BLOCKING' : 'WATCHING') : 'NOMINAL';

  const inputs = incident?.risk_breakdown?.evidence_breakdown?.slice(0, 3).map((ev) => ({
    label: ev.detector?.toUpperCase() ?? 'DETECTOR',
    value: `${(ev.weighted_score ?? 0).toFixed(1)} pts`,
    sub: (ev.metric_summary ?? '').slice(0, 42),
    color: ev.weighted_score > 25 ? '#FF4D4D' : ev.weighted_score > 15 ? '#FF8C42' : '#FFD166',
  })) ?? [
    {
      label: 'EPS MONITOR',
      value: `${(metrics?.events_per_sec ?? 0).toLocaleString()}`,
      sub: 'Events per second, nominal',
      color: '#00C9A7',
    },
    {
      label: 'BANDWIDTH TAP',
      value: `${(metrics?.mbps ?? 0).toFixed(1)} Mb`,
      sub: 'Line rate, within threshold',
      color: '#60A5FA',
    },
    {
      label: 'PACKET LOSS',
      value: `${(metrics?.packet_loss_pct ?? 0).toFixed(3)}%`,
      sub: (metrics?.packet_loss_pct ?? 0) < 0.1 ? 'Below alarm line' : 'Elevated, inspect',
      color: (metrics?.packet_loss_pct ?? 0) > 0.1 ? '#FF4D4D' : '#06D6A0',
    },
  ];

  const centralLabel = incident
    ? (incident.primary_threat_class?.split('_').slice(0, 2).join(' ') ?? 'THREAT')
    : 'STREAM';
  const centralSub = incident ? 'THREAT FUSION' : 'PIPELINE';

  const assessmentDetail = incident
    ? (isBlocking
        ? `${incident.timeline?.length ?? 0} correlated stages · requires human approval`
        : `Risk ${riskScore}/100, continue monitoring`)
    : `Buffer ${(metrics?.buffer_utilization_pct ?? 0).toFixed(1)}% · no threshold crossed`;

  const action = incident
    ? (isBlocking ? 'REQUIRE OPERATOR SIGN-OFF' : 'AUTO-MONITOR ACTIVE')
    : 'ALL SYSTEMS PASSIVE';

  // Connector Y positions for 3 inputs, evenly spaced over 190px height
  const NODE_HEIGHTS = [32, 95, 158];

  return (
    <div className="card relative overflow-hidden">
      <style>{`@keyframes dash-flow { from { stroke-dashoffset: 0; } to { stroke-dashoffset: -32; } }`}</style>

      {/* grid bg */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.022) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.022) 1px,transparent 1px)',
          backgroundSize: '28px 28px',
        }}
      />

      {/* Header */}
      <div className="relative flex items-center justify-between px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2.5">
          <span
            className="w-2 h-2 rounded-full"
            style={{
              background: statusColor,
              boxShadow: `0 0 8px ${statusColor}`,
              animation: isBlocking ? 'pulse-accent 1.2s ease-in-out infinite' : 'none',
            }}
          />
          <span className="font-mono text-sm font-bold tracking-widest" style={{ color: 'var(--text-primary)' }}>
            COMPOUND RISK ENGINE
          </span>
          {incident && (
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-dim)' }}>
              {incident.source_ip} · {incident.subnet}
            </span>
          )}
        </div>
        <div
          className="font-mono text-xs font-bold tracking-widest px-3 py-1 rounded-full"
          style={{ color: statusColor, border: `1px solid ${statusColor}55`, background: `${statusColor}12` }}
        >
          {statusLabel}
        </div>
      </div>

      {/* Workflow canvas */}
      <div className="relative px-5 py-6">
        <div className="flex items-center">

          {/* ── Left: Input Nodes ── */}
          <div className="flex flex-col gap-3 flex-shrink-0" style={{ width: 175 }}>
            {inputs.map((inp, i) => <InputNode key={i} {...inp} />)}
          </div>

          {/* ── SVG: Left connectors ── */}
          <svg width="110" height="190" viewBox="0 0 110 190" className="flex-shrink-0">
            {NODE_HEIGHTS.map((srcY, i) => (
              <Connector
                key={i}
                x1={4} y1={srcY}
                x2={106} y2={95}
                color={inputs[i]?.color ?? '#00C9A7'}
                delay={i * 0.45}
              />
            ))}
          </svg>

          {/* ── Center: Fusion Node ── */}
          <div className="flex-shrink-0 flex items-center justify-center" style={{ width: 118 }}>
            <CentralNode label={centralLabel} sublabel={centralSub} color={color} score={riskScore} />
          </div>

          {/* ── SVG: Right connector ── */}
          <svg width="80" height="190" viewBox="0 0 80 190" className="flex-shrink-0">
            <Connector x1={4} y1={95} x2={76} y2={95} color={statusColor} delay={0.6} />
          </svg>

          {/* ── Right: Assessment ── */}
          <div className="flex-shrink-0" style={{ width: 180 }}>
            <AssessmentNode verdict={isBlocking ? 'Do not proceed' : (incident ? 'Monitor & Wait' : 'Stream Nominal')}
              detail={assessmentDetail} color={statusColor} action={action} />
          </div>
        </div>

        {/* ── Bottom legend ── */}
        <div
          className="mt-5 pt-3 flex flex-wrap items-center gap-5 font-mono text-[10px]"
          style={{ borderTop: '1px solid var(--border)', color: 'var(--text-dim)' }}
        >
          {[
            { label: 'Evidence signal', color: inputs[0]?.color ?? '#00C9A7' },
            { label: 'Compound output', color: statusColor },
          ].map(({ label, color: c }) => (
            <div key={label} className="flex items-center gap-2">
              <svg width="20" height="4"><line x1="0" y1="2" x2="20" y2="2" stroke={c} strokeWidth="1.5" strokeDasharray="3 3" /></svg>
              <span>{label}</span>
            </div>
          ))}
          <span style={{ color: 'var(--text-secondary)' }}>
            {incident
              ? `${incident.risk_breakdown?.evidence_breakdown?.length ?? 0} detectors fused · synergy bonus +${(incident.risk_breakdown?.synergy_bonus ?? 0).toFixed(1)}`
              : 'No single sensor crossed its own threshold, compound analysis nominal'}
          </span>
        </div>
      </div>
    </div>
  );
};
