import React, { useState } from 'react';
import { FusedIncident } from '../../types';
import { SeverityBadge } from '../incidents/SeverityBadge';
import { NarrativeCard } from './NarrativeCard';
import { AttackTimeline } from './AttackTimeline';
import { EvidenceViewer } from './EvidenceViewer';
import { RiskMathCard } from './RiskMathCard';
import { MitreAttackPills } from './MitreAttackPills';
import { CountermeasureCenter } from '../countermeasures/CountermeasureCenter';
import {
  X,
  Clock,
  Key,
  Calculator,
  Shield,
  FileText,
  Maximize2,
  Minimize2,
} from 'lucide-react';
import { getSeverityColor } from '../../utils/formatters';

interface InvestigationDrawerProps {
  incident: FusedIncident | null;
  onClose: () => void;
  onToggleApproval: (id: string) => void;
}

type DrawerTab = 'overview' | 'timeline' | 'evidence' | 'risk_math' | 'countermeasures';

export const InvestigationDrawer: React.FC<InvestigationDrawerProps> = ({
  incident,
  onClose,
  onToggleApproval,
}) => {
  const [activeTab, setActiveTab] = useState<DrawerTab>('overview');
  const [isExpanded, setIsExpanded] = useState(false);

  if (!incident) return null;

  const styles = getSeverityColor(incident.severity);

  const tabs: Array<{ id: DrawerTab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: 'Overview', icon: <FileText className="w-3.5 h-3.5" /> },
    { id: 'timeline', label: 'Attack Timeline', icon: <Clock className="w-3.5 h-3.5" /> },
    { id: 'evidence', label: 'Deep Evidence', icon: <Key className="w-3.5 h-3.5" /> },
    { id: 'risk_math', label: 'Explainable Risk', icon: <Calculator className="w-3.5 h-3.5" /> },
    { id: 'countermeasures', label: 'Countermeasures', icon: <Shield className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="w-full bg-[#080D1A] border border-cyan-500/40 rounded-lg p-4 shadow-panel space-y-4 font-mono">
      {/* Drawer Top Title Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-3">
          <SeverityBadge severity={incident.severity} size="md" />
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm sm:text-base font-bold text-white tracking-wider">
                {incident.incident_id}
              </h3>
              <span className="text-xs text-slate-400 font-semibold">
                // {incident.primary_threat_class}
              </span>
            </div>
            <span className="text-[11px] text-slate-400">
              Source: <strong className="text-amber-300">{incident.source_ip}</strong> ({incident.subnet})
            </span>
          </div>
        </div>

        {/* Risk Score Pill & Controls */}
        <div className="flex items-center gap-2">
          <div className="bg-[#050811] px-3 py-1 rounded border border-slate-800 flex items-baseline gap-1.5">
            <span className="text-slate-400 text-xs">FINAL RISK:</span>
            <span className={`font-extrabold text-base tabular-nums ${styles.text}`}>
              {incident.risk_score.toFixed(1)}
            </span>
            <span className="text-slate-500 text-[10px]">/ 100</span>
          </div>

          <button
            onClick={() => setIsExpanded((p) => !p)}
            title={isExpanded ? 'Normal View' : 'Expand View'}
            className="p-1.5 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition-colors hidden md:block"
          >
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>

          <button
            onClick={onClose}
            title="Close Drawer"
            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/20 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 bg-[#050811] p-1.5 rounded-lg border border-slate-800">
        {tabs.map((tab) => {
          const isSelected = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold transition-all ${
                isSelected
                  ? 'bg-cyan-950/90 text-cyan-200 border border-cyan-500/80 shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                  : 'bg-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Content Display */}
      <div className="pt-1">
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
          <RiskMathCard
            riskBreakdown={incident.risk_breakdown}
            riskScore={incident.risk_score}
          />
        )}

        {activeTab === 'countermeasures' && (
          <CountermeasureCenter
            incident={incident}
            onToggleApproval={onToggleApproval}
          />
        )}
      </div>
    </div>
  );
};
