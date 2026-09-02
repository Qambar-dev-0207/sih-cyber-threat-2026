import React, { useMemo } from 'react';
import { FusedIncident } from '../../types';

interface IncidentHeatmapProps {
  incidents: FusedIncident[];
}

// 24 columns (hours 0-23), 7 rows (days Mon-Sun)
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function severityToWeight(sev: string): number {
  switch (sev) {
    case 'CRITICAL': return 4;
    case 'HIGH':     return 3;
    case 'MEDIUM':   return 2;
    case 'LOW':      return 1;
    default:         return 1;
  }
}

function weightToColor(w: number, max: number): string {
  if (max === 0 || w === 0) return 'rgba(255,255,255,0.04)';
  const pct = w / max;
  if (pct < 0.25) return 'rgba(0,201,167,0.18)';
  if (pct < 0.5)  return 'rgba(0,201,167,0.4)';
  if (pct < 0.75) return 'rgba(0,201,167,0.65)';
  return 'rgba(0,201,167,0.9)';
}

function weightToGlow(w: number, max: number): string {
  if (max === 0 || w === 0) return 'none';
  const pct = w / max;
  if (pct > 0.6) return '0 0 6px rgba(0,201,167,0.6)';
  return 'none';
}

export const IncidentHeatmap: React.FC<IncidentHeatmapProps> = ({ incidents }) => {
  const { grid, maxWeight, totalByHour, totalByDay } = useMemo(() => {
    // grid[day][hour] = weight
    const g: number[][] = Array.from({ length: 7 }, () => Array(24).fill(0));
    const hourTotals = Array(24).fill(0);
    const dayTotals = Array(7).fill(0);

    incidents.forEach((inc) => {
      if (!inc?.created_at) return;
      const d = new Date(inc.created_at);
      if (isNaN(d.getTime())) return;           // skip invalid dates
      const day = (d.getDay() + 6) % 7;         // Mon=0..Sun=6
      const hour = d.getHours();
      if (day < 0 || day > 6 || hour < 0 || hour > 23) return;
      const w = severityToWeight(inc.severity ?? 'LOW');
      g[day][hour] += w;
      hourTotals[hour] += w;
      dayTotals[day] += w;
    });

    const flat = g.flat();
    const maxW = Math.max(...flat, 1);
    return { grid: g, maxWeight: maxW, totalByHour: hourTotals, totalByDay: dayTotals };
  }, [incidents]);

  const peakHour = totalByHour.indexOf(Math.max(...totalByHour));
  const peakDay = DAYS[totalByDay.indexOf(Math.max(...totalByDay))];

  return (
    <div className="card">
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-2">
          <span className="dot-live" style={{ background: 'var(--accent)', boxShadow: '0 0 6px var(--accent)' }} />
          <span className="font-mono text-xs font-semibold tracking-widest uppercase" style={{ color: 'var(--text-primary)' }}>
            Attack Intensity Heatmap
          </span>
        </div>
        <div className="flex items-center gap-4 font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
          <span>PEAK HOUR <span style={{ color: 'var(--accent)' }}>{String(peakHour).padStart(2,'0')}:00</span></span>
          <span>PEAK DAY <span style={{ color: 'var(--accent)' }}>{peakDay}</span></span>
          <div className="flex items-center gap-1 ml-2">
            <span style={{ color: 'var(--text-dim)' }}>LOW</span>
            {[0.18, 0.4, 0.65, 0.9].map((a) => (
              <div
                key={a}
                className="w-3 h-3 rounded-sm"
                style={{ background: `rgba(0,201,167,${a})` }}
              />
            ))}
            <span style={{ color: 'var(--text-dim)' }}>HIGH</span>
          </div>
        </div>
      </div>

      <div className="px-4 py-4">
        {/* Hour labels */}
        <div className="flex mb-1" style={{ paddingLeft: 32 }}>
          {HOURS.map((h) => (
            <div
              key={h}
              className="font-mono text-center"
              style={{
                width: 20,
                fontSize: 8,
                color: h === peakHour ? 'var(--accent)' : 'var(--text-dim)',
                fontWeight: h === peakHour ? 700 : 400,
              }}
            >
              {h % 4 === 0 ? String(h).padStart(2, '0') : ''}
            </div>
          ))}
        </div>

        {/* Grid rows */}
        {DAYS.map((day, di) => (
          <div key={day} className="flex items-center mb-1">
            {/* Day label */}
            <div
              className="font-mono text-[9px] text-right pr-2 flex-shrink-0"
              style={{
                width: 32,
                color: day === peakDay ? 'var(--accent)' : 'var(--text-dim)',
                fontWeight: day === peakDay ? 700 : 400,
              }}
            >
              {day}
            </div>

            {/* Hour cells */}
            {HOURS.map((h) => {
              const w = grid[di][h];
              const bg = weightToColor(w, maxWeight);
              const glow = weightToGlow(w, maxWeight);
              return (
                <div
                  key={h}
                  title={`${day} ${String(h).padStart(2,'0')}:00 — weight ${w}`}
                  className="rounded-sm transition-all duration-300 cursor-default"
                  style={{
                    width: 18,
                    height: 14,
                    margin: '0 1px',
                    background: bg,
                    boxShadow: glow,
                    border: '1px solid rgba(255,255,255,0.03)',
                  }}
                />
              );
            })}
          </div>
        ))}

        {/* Summary row */}
        <div
          className="mt-3 pt-3 grid grid-cols-3 gap-4 font-mono text-[10px]"
          style={{ borderTop: '1px solid var(--border)' }}
        >
          <div>
            <span style={{ color: 'var(--text-dim)' }}>TOTAL INCIDENTS </span>
            <span className="font-bold" style={{ color: 'var(--text-primary)' }}>{incidents.length}</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)' }}>CRITICAL </span>
            <span className="font-bold" style={{ color: 'var(--critical)' }}>
              {incidents.filter(i => i.severity === 'CRITICAL').length}
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)' }}>HIGH </span>
            <span className="font-bold" style={{ color: 'var(--high)' }}>
              {incidents.filter(i => i.severity === 'HIGH').length}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
