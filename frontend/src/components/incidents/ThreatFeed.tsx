import React from 'react';
import { FusedIncident, SeverityLevel } from '../../types';
import { IncidentCard } from './IncidentCard';
import { IncidentFilters } from './IncidentFilters';

interface ThreatFeedProps {
  incidents: FusedIncident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  severityFilter: SeverityLevel | 'ALL';
  onSelectSeverity: (sev: SeverityLevel | 'ALL') => void;
  threatClassFilter: string;
  onSelectThreatClass: (tc: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  severityCounts: Record<string, number>;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  severityFilter,
  onSelectSeverity,
  threatClassFilter,
  onSelectThreatClass,
  searchQuery,
  onSearchChange,
  severityCounts,
}) => {
  return (
    <div className="card flex flex-col h-full">
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-2">
          <span className="dot-live animate-pulse-accent" />
          <span className="font-mono text-xs font-semibold tracking-widest uppercase" style={{ color: 'var(--text-primary)' }}>
            Live Threat Feed
          </span>
        </div>
        <span className="font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>
          {incidents.length} incidents
        </span>
      </div>

      <div className="px-4 py-3 flex-shrink-0">
        <IncidentFilters
          severityFilter={severityFilter}
          onSelectSeverity={onSelectSeverity}
          threatClassFilter={threatClassFilter}
          onSelectThreatClass={onSelectThreatClass}
          searchQuery={searchQuery}
          onSearchChange={onSearchChange}
          severityCounts={severityCounts}
        />
      </div>

      {/* Cards */}
      <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-2">
        {incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <span className="font-mono text-xs" style={{ color: 'var(--text-dim)' }}>
              No incidents matching current filters
            </span>
          </div>
        ) : (
          incidents.map((inc) => (
            <IncidentCard
              key={inc.incident_id}
              incident={inc}
              isSelected={selectedIncidentId === inc.incident_id}
              onSelect={onSelectIncident}
            />
          ))
        )}
      </div>
    </div>
  );
};
