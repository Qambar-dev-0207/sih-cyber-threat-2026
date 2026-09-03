import React, { useState } from 'react';
import { FusedIncident } from '../../types';
import { NarrativeCard } from './NarrativeCard';
import { AttackTimeline } from './AttackTimeline';
import { EvidenceViewer } from './EvidenceViewer';
import { RiskMathCard } from './RiskMathCard';
import { MitreAttackPills } from './MitreAttackPills';
import { CountermeasureCenter } from '../countermeasures/CountermeasureCenter';
import { X } from 'lucide-react';

interface InvestigationDrawerProps {
  incident: FusedIncident | null;
  onClose: () => void;
  onToggleApproval: (id: string) => void;
}

type DrawerTab = 'overview' | 'timeline' | 'evidence' | 'risk_math' | 'countermeasures';

function severityColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'var(--critical)';
    case 'HIGH':     return 'var(--high)';
    case 'MEDIUM':   return 'var(--medium)';
    case 'LOW':      return 'var(--low)';
    default:         return 'var(--text-secondary)';
  }
}

const TABS: Array<{ id: DrawerTab; label: string }> = [
  { id: 'overview',        label: 'Overview' },
  { id: 'timeline',        label: 'Timeline' },
  { id: 'evidence',        label: 'Evidence' },
  { id: 'risk_math',       label: 'Risk Math' },
  { id: 'countermeasures', label: 'Response' },
];

export const InvestigationDrawer: React.FC<InvestigationDrawerProps> = ({
  incident,
  onClose,
  onToggleApproval,
}) => {
  const [activeTab, setActiveTab] = useState<DrawerTab>('overview');

  if (!incident) return null;

  const color = severityColor(incident.severity);

  return (
    <div
      className="card investigation-drawer flex flex-col h-full animate-fadeUp"
      style={{ borderColor: `${color}30` }}
    >
      {/* Top bar */}
      <div
        className="flex items-start justify-between gap-3 px-4 py-3 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <div className="flex items-start gap-3">
          {/* Severity indicator */}
          <div
            className="mt-0.5 w-1.5 h-full min-h-[2rem] rounded"
            style={{ background: color, minHeight: '2rem', minWidth: '3px' }}
          />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-bold tracking-wider" style={{ color }}>
                {incident.severity}
              </span>
              <span className="font-mono text-xs font-bold" style={{ color: 'var(--text-primary)' }}>
                {incident.incident_id}
              </span>
              <span className="font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                // {incident.primary_threat_class}
              </span>
            </div>
            <div className="font-mono text-[10px] mt-0.5" style={{ color: 'var(--text-secondary)' }}>
              src <span style={{ color: 'var(--medium)' }}>{incident.source_ip}</span>
              <span className="ml-2" style={{ color: 'var(--text-dim)' }}>({incident.subnet})</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="risk-score-ring" style={{ '--risk': `${Math.min(100, incident.risk_score ?? 0)}%`, '--risk-color': color } as React.CSSProperties} aria-label={`Risk score ${(incident.risk_score ?? 0).toFixed(1)} out of 100`}>
            <div><strong>{(incident.risk_score ?? 0).toFixed(0)}</strong><span>/ 100</span></div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded transition-colors"
            style={{ color: 'var(--text-secondary)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--critical)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Tab Row */}
      <div
        className="flex items-center gap-1 px-4 py-2 flex-shrink-0 overflow-x-auto"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="px-3 py-1 rounded font-mono text-[11px] font-semibold whitespace-nowrap transition-all"
              style={{
                background: isActive ? 'var(--accent-dim)' : 'transparent',
                border: `1px solid ${isActive ? 'var(--accent-border)' : 'transparent'}`,
                color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-4 py-4">
        {activeTab === 'overview' && (
          <div className="space-y-4">
            <NarrativeCard incident={incident} />
            <MitreAttackPills mitreMappings={incident.mitre_mappings} />
            <AttackTimeline timeline={incident.timeline} />
          </div>
        )}
        {activeTab === 'timeline' && <AttackTimeline timeline={incident.timeline} />}
        {activeTab === 'evidence' && <EvidenceViewer incident={incident} />}
        {activeTab === 'risk_math' && (
          <RiskMathCard riskBreakdown={incident.risk_breakdown} riskScore={incident.risk_score} />
        )}
        {activeTab === 'countermeasures' && (
          <CountermeasureCenter incident={incident} onToggleApproval={onToggleApproval} />
        )}
      </div>
    </div>
  );
};
