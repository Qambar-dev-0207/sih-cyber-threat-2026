import React from 'react';
import { Activity, ArrowUpRight, CircleAlert, Clock3, Filter, ShieldCheck } from 'lucide-react';
import { FusedIncident, SeverityLevel } from '../../types';
import { ThreatFeed } from './ThreatFeed';
import { InvestigationDrawer } from '../investigation/InvestigationDrawer';

interface IncidentsPageProps {
  incidents: FusedIncident[];
  selectedIncident: FusedIncident | null;
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onCloseIncident: () => void;
  severityFilter: SeverityLevel | 'ALL';
  onSelectSeverity: (severity: SeverityLevel | 'ALL') => void;
  threatClassFilter: string;
  onSelectThreatClass: (value: string) => void;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  severityCounts: Record<string, number>;
  onToggleApproval: (id: string) => void;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({ incidents, selectedIncident, selectedIncidentId, onSelectIncident, onCloseIncident, severityFilter, onSelectSeverity, threatClassFilter, onSelectThreatClass, searchQuery, onSearchChange, severityCounts, onToggleApproval }) => {
  const pending = incidents.filter((incident) => incident.status === 'PENDING_REVIEW').length;
  const critical = severityCounts.CRITICAL ?? 0;
  const approved = incidents.filter((incident) => incident.status === 'APPROVED').length;

  return <main className="incidents-page"><div className="incidents-wrap">
    <div className="incidents-page-head"><div><div className="eyebrow">Incident command</div><h1>Investigate what needs attention.</h1><p>Every alert is grouped, scored, and held here until an operator decides what happens next.</p></div><div className="incident-live-state"><span className="status-ring" /> LIVE QUEUE <strong>{incidents.length} open</strong></div></div>
    <div className="incident-stat-grid"><div><span><CircleAlert size={14} /> Critical</span><strong>{critical}</strong><small>needs immediate review</small></div><div><span><Clock3 size={14} /> Pending review</span><strong>{pending}</strong><small>waiting for an operator</small></div><div><span><ShieldCheck size={14} /> Approved</span><strong>{approved}</strong><small>ready for controlled response</small></div><div><span><Activity size={14} /> Active stream</span><strong>ON</strong><small>new incidents appear live</small></div></div>
    <div className="incident-toolbar"><div className="toolbar-title"><Filter size={15} /><strong>Threat queue</strong><span>{incidents.length} records in current view</span></div><div className="toolbar-hint">Select any row to open the full evidence trail <ArrowUpRight size={14} /></div></div>
    <div className="incidents-layout"><ThreatFeed incidents={incidents} selectedIncidentId={selectedIncidentId} onSelectIncident={onSelectIncident} severityFilter={severityFilter} onSelectSeverity={onSelectSeverity} threatClassFilter={threatClassFilter} onSelectThreatClass={onSelectThreatClass} searchQuery={searchQuery} onSearchChange={onSearchChange} severityCounts={severityCounts} />{selectedIncident ? <InvestigationDrawer incident={selectedIncident} onClose={onCloseIncident} onToggleApproval={onToggleApproval} /> : <div className="incident-empty-large"><CircleAlert size={27} /><strong>Select an incident to begin triage</strong><span>Evidence, risk math, timeline, and response controls will appear here.</span></div>}</div>
  </div></main>;
};
