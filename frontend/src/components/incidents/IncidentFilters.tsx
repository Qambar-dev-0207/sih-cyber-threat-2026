import React from 'react';
import { SeverityLevel } from '../../types';
import { Search, Filter, X } from 'lucide-react';

interface IncidentFiltersProps {
  severityFilter: SeverityLevel | 'ALL';
  onSelectSeverity: (sev: SeverityLevel | 'ALL') => void;
  threatClassFilter: string;
  onSelectThreatClass: (tc: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  severityCounts: Record<string, number>;
}

export const IncidentFilters: React.FC<IncidentFiltersProps> = ({
  severityFilter,
  onSelectSeverity,
  threatClassFilter,
  onSelectThreatClass,
  searchQuery,
  onSearchChange,
  severityCounts,
}) => {
  const severities: Array<SeverityLevel | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  const threatClasses = [
    'ALL',
    'APT_MULTI_STAGE',
    'MALWARE_C2',
    'DDOS_VOLUMETRIC',
    'DGA_TUNNELING',
    'RECON',
    'EXFILTRATION',
  ];

  return (
    <div className="flex flex-col gap-2.5 bg-[#080D1A] p-3 rounded-lg border border-slate-800 font-mono text-xs">
      {/* Search Input Bar */}
      <div className="relative w-full">
        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 transform -translate-y-1/2" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter by Incident ID, Source IP, MITRE Technique, or Payload Signature..."
          className="w-full bg-[#050811] text-slate-200 placeholder-slate-500 pl-9 pr-8 py-2 rounded border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 focus:outline-none transition-all text-xs"
        />
        {searchQuery && (
          <button
            onClick={() => onSearchChange('')}
            className="absolute right-2.5 top-1/2 transform -translate-y-1/2 text-slate-500 hover:text-slate-300"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Severity Filter Buttons + Threat Class Select */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        {/* Severity Tabs */}
        <div className="flex flex-wrap items-center gap-1.5">
          {severities.map((sev) => {
            const count = severityCounts[sev] || 0;
            const isSelected = severityFilter === sev;

            let colorClasses =
              'bg-slate-900/80 text-slate-400 border-slate-800 hover:border-slate-600 hover:text-slate-200';

            if (isSelected) {
              if (sev === 'CRITICAL') {
                colorClasses = 'bg-red-950/80 text-red-300 border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.4)]';
              } else if (sev === 'HIGH') {
                colorClasses = 'bg-amber-950/80 text-amber-300 border-amber-500 shadow-[0_0_10px_rgba(249,115,22,0.4)]';
              } else if (sev === 'MEDIUM') {
                colorClasses = 'bg-yellow-950/80 text-yellow-300 border-yellow-500';
              } else if (sev === 'LOW') {
                colorClasses = 'bg-cyan-950/80 text-cyan-300 border-cyan-500';
              } else {
                colorClasses = 'bg-slate-800 text-cyan-300 border-cyan-500/80 shadow-[0_0_8px_rgba(6,182,212,0.3)]';
              }
            }

            return (
              <button
                key={sev}
                onClick={() => onSelectSeverity(sev)}
                className={`px-2.5 py-1 rounded border text-[11px] font-semibold transition-all flex items-center gap-1.5 ${colorClasses}`}
              >
                <span>{sev}</span>
                <span
                  className={`text-[9px] px-1 py-0.2 rounded ${
                    isSelected ? 'bg-black/40 text-white font-bold' : 'bg-slate-800/80 text-slate-400'
                  }`}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Threat Class Dropdown */}
        <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Class:</span>
          <select
            value={threatClassFilter}
            onChange={(e) => onSelectThreatClass(e.target.value)}
            className="bg-[#050811] text-slate-200 border border-slate-800 rounded px-2 py-1 focus:border-cyan-500 focus:outline-none text-[11px]"
          >
            {threatClasses.map((tc) => (
              <option key={tc} value={tc}>
                {tc}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
};
