import React from 'react';
import { SeverityLevel } from '../../types';
import { Search, X } from 'lucide-react';

interface IncidentFiltersProps {
  severityFilter: SeverityLevel | 'ALL';
  onSelectSeverity: (sev: SeverityLevel | 'ALL') => void;
  threatClassFilter: string;
  onSelectThreatClass: (tc: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  severityCounts: Record<string, number>;
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
  ALL: 'var(--accent)',
};

const THREAT_CLASSES = ['ALL', 'APT_MULTI_STAGE', 'MALWARE_C2', 'DDOS_VOLUMETRIC', 'DGA_TUNNELING', 'RECON', 'EXFILTRATION'];

export const IncidentFilters: React.FC<IncidentFiltersProps> = ({
  severityFilter, onSelectSeverity,
  threatClassFilter, onSelectThreatClass,
  searchQuery, onSearchChange,
  severityCounts,
}) => {
  return (
    <div className="space-y-2">
      {/* Search */}
      <div className="relative">
        <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-dim)' }} />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search incidents, IPs, MITRE..."
          className="w-full pl-8 pr-7 py-2 rounded-lg font-mono text-[11px] outline-none transition-all"
          style={{
            background: 'var(--bg-0)',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
          }}
          onFocus={e => (e.target.style.borderColor = 'var(--accent-border)')}
          onBlur={e => (e.target.style.borderColor = 'var(--border)')}
        />
        {searchQuery && (
          <button onClick={() => onSearchChange('')} className="absolute right-2.5 top-1/2 -translate-y-1/2">
            <X className="w-3 h-3" style={{ color: 'var(--text-secondary)' }} />
          </button>
        )}
      </div>

      {/* Severity Tabs & Class */}
      <div className="flex flex-wrap items-center gap-2">
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
          const isSelected = severityFilter === sev;
          const color = SEV_COLORS[sev];
          return (
            <button
              key={sev}
              onClick={() => onSelectSeverity(sev)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded transition-all font-mono text-[10px] font-semibold"
              style={{
                background: isSelected ? `${color}14` : 'transparent',
                border: `1px solid ${isSelected ? `${color}50` : 'var(--border)'}`,
                color: isSelected ? color : 'var(--text-secondary)',
              }}
            >
              {sev}
              <span
                className="text-[9px] font-bold"
                style={{ color: isSelected ? color : 'var(--text-dim)' }}
              >
                {severityCounts[sev] ?? 0}
              </span>
            </button>
          );
        })}

        <div className="ml-auto">
          <select
            value={threatClassFilter}
            onChange={(e) => onSelectThreatClass(e.target.value)}
            className="font-mono text-[10px] px-2 py-1 rounded outline-none"
            style={{
              background: 'var(--bg-0)',
              border: '1px solid var(--border)',
              color: 'var(--text-secondary)',
            }}
          >
            {THREAT_CLASSES.map((tc) => (
              <option key={tc} value={tc}>{tc}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
};
