import React from 'react';
import { FusedIncident, SeverityLevel } from '../../types';
import { IncidentCard } from './IncidentCard';
import { IncidentFilters } from './IncidentFilters';
import { ShieldAlert, Radio, Activity } from 'lucide-react';

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
    <div className="w-full bg-[#080D1A] border border-slate-800 rounded-lg p-4 shadow-panel space-y-3 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 animate-pulse" />
          <h3 className="font-mono text-xs sm:text-sm font-bold tracking-wider text-slate-100 uppercase">
            Live Threat Feed & Incident Matrix
          </h3>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="flex items-center gap-1 text-cyan-400">
            <Radio className="w-3 h-3 animate-pulse" />
            <span>REAL-TIME STREAM</span>
          </span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-300 font-bold bg-slate-800 px-2 py-0.5 rounded">
            {incidents.length} Fused Incidents
          </span>
        </div>
      </div>

      {/* Filter Component */}
      <IncidentFilters
        severityFilter={severityFilter}
        onSelectSeverity={onSelectSeverity}
        threatClassFilter={threatClassFilter}
        onSelectThreatClass={onSelectThreatClass}
        searchQuery={searchQuery}
        onSearchChange={onSearchChange}
        severityCounts={severityCounts}
      />

      {/* Incident Cards Stream */}
      <div className="space-y-3 overflow-y-auto max-h-[620px] pr-1 scrollbar-thin">
        {incidents.length === 0 ? (
          <div className="p-8 text-center bg-[#050811] border border-slate-800 rounded-lg font-mono text-slate-500 text-xs">
            <Activity className="w-8 h-8 text-slate-600 mx-auto mb-2 animate-pulse" />
            <p className="font-bold text-slate-400">NO ACTIVE INCIDENTS MATCHING FILTERS</p>
            <p className="text-[11px] text-slate-500 mt-1">
              Adjust filters or trigger a synthetic attack scenario from the Demo Control Bar.
            </p>
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
