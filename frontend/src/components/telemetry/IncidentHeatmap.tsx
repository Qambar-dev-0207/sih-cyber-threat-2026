import React, { useMemo, useState } from 'react';
import { FusedIncident } from '../../types';

interface IncidentHeatmapProps { incidents: FusedIncident[]; }
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);
const weight = (severity: string) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[severity as keyof Record<string, number>] ?? 1);

export const IncidentHeatmap: React.FC<IncidentHeatmapProps> = ({ incidents }) => {
  const [hovered, setHovered] = useState<{ day: string; hour: number; count: number } | null>(null);
  const { grid, max } = useMemo(() => {
    const data = DAYS.map(() => HOURS.map(() => 0));
    incidents.forEach((incident) => { const date = new Date(incident.created_at); if (Number.isNaN(date.getTime())) return; const day = (date.getDay() + 6) % 7; data[day][date.getHours()] += weight(incident.severity); });
    return { grid: data, max: Math.max(1, ...data.flat()) };
  }, [incidents]);
  const peak = grid.flat().indexOf(max);
  const peakDay = DAYS[Math.floor(peak / 24)] ?? 'Mon';
  const peakHour = peak % 24;
  return <div className="card activity-heatmap">
    <div className="heatmap-header"><div><strong>Attack intensity</strong><span>Severity weighted · UTC · trailing 7 days</span></div><div className="heatmap-peaks"><span>Peak window <b>{peakDay} {String(peakHour).padStart(2, '0')}:00</b></span><span>Active records <b>{incidents.length}</b></span></div></div>
    <div className="heatmap-body"><div className="heatmap-hours"><span />{HOURS.map((hour) => <span key={hour}>{hour % 4 === 0 ? String(hour).padStart(2, '0') : ''}</span>)}</div>{DAYS.map((day, dayIndex) => <div className="heatmap-row" key={day}><span className={day === peakDay ? 'peak-label' : ''}>{day}</span>{HOURS.map((hour) => { const value = grid[dayIndex][hour]; const level = value ? Math.max(1, Math.ceil((value / max) * 4)) : 0; return <button key={hour} className={`heat-cell level-${level}`} aria-label={`${day} ${hour}:00, ${value} weighted incidents`} onMouseEnter={() => setHovered({ day, hour, count: value })} onMouseLeave={() => setHovered(null)} />; })}</div>)}{hovered && <div className="heatmap-tooltip" role="status"><strong>{hovered.day} · {String(hovered.hour).padStart(2, '0')}:00 UTC</strong><span>{hovered.count} weighted incident signals</span></div>}</div>
    <div className="heatmap-footer"><span><i className="legend-swatch low" /> low</span><span><i className="legend-swatch medium" /> medium</span><span><i className="legend-swatch high" /> high</span><span><i className="legend-swatch critical" /> critical</span><span className="heatmap-note">Intensity combines count and severity</span></div>
  </div>;
};
