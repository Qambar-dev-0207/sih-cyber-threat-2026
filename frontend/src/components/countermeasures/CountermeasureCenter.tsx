import React, { useState } from 'react';
import { CountermeasureType, FusedIncident } from '../../types';
import { ArtifactViewer } from './ArtifactViewer';
import { ApprovalLock } from './ApprovalLock';
import { StixExportModal } from './StixExportModal';
import { Shield, FileCode, Share2, Layers, Cpu, Server, Network } from 'lucide-react';

interface CountermeasureCenterProps {
  incident: FusedIncident;
  onToggleApproval: (incidentId: string) => void;
}

export const CountermeasureCenter: React.FC<CountermeasureCenterProps> = ({
  incident,
  onToggleApproval,
}) => {
  const [activeTab, setActiveTab] = useState<CountermeasureType>('iptables');
  const [showStixModal, setShowStixModal] = useState(false);

  const tabs: Array<{ id: CountermeasureType; label: string; icon: React.ReactNode }> = [
    { id: 'iptables', label: 'iptables', icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'nftables', label: 'nftables', icon: <Layers className="w-3.5 h-3.5" /> },
    { id: 'cisco_acl', label: 'Cisco ACL', icon: <Server className="w-3.5 h-3.5" /> },
    { id: 'dns_rpz', label: 'DNS RPZ', icon: <Cpu className="w-3.5 h-3.5" /> },
    { id: 'snort3', label: 'Snort 3', icon: <FileCode className="w-3.5 h-3.5" /> },
    { id: 'stix_bundle', label: 'STIX 2.1 JSON', icon: <Share2 className="w-3.5 h-3.5" /> },
  ];

  const currentArtifact =
    incident.countermeasures.find((cm) => cm.countermeasure_type === activeTab) ||
    incident.countermeasures[0];

  const isApproved = incident.status === 'APPROVED';

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h4 className="font-bold text-slate-200 tracking-wider uppercase flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Automated Countermeasure Action Center (6-Engine Matrix)</span>
        </h4>
        <span className="text-[11px] text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
          6 Artifacts Generated
        </span>
      </div>

      {/* Human Approval Data Diode Enclave Lock */}
      <ApprovalLock
        isApproved={isApproved}
        onToggle={() => onToggleApproval(incident.incident_id)}
        incidentId={incident.incident_id}
      />

      {/* 6-Tab Selection Bar */}
      <div className="flex flex-wrap items-center gap-1.5 bg-[#080D1A] p-1.5 rounded-lg border border-slate-800">
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

      {/* Active Artifact Code Block */}
      {currentArtifact ? (
        <ArtifactViewer
          content={currentArtifact.artifact_content}
          type={currentArtifact.countermeasure_type}
          targetEntity={currentArtifact.target_entity}
          syntaxValid={currentArtifact.syntax_valid}
          incidentId={incident.incident_id}
        />
      ) : (
        <div className="p-6 text-center text-slate-500 bg-[#050811] rounded border border-slate-800">
          No artifact generated for this type.
        </div>
      )}

      {/* STIX Modal Trigger if active is STIX */}
      {activeTab === 'stix_bundle' && (
        <div className="flex justify-end pt-1">
          <button
            onClick={() => setShowStixModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 rounded border border-cyan-500/40 text-xs font-semibold"
          >
            <Share2 className="w-3.5 h-3.5" />
            <span>Open STIX 2.1 Fullscreen Inspector</span>
          </button>
        </div>
      )}

      {/* STIX Fullscreen Modal */}
      {showStixModal && currentArtifact && (
        <StixExportModal
          isOpen={showStixModal}
          onClose={() => setShowStixModal(false)}
          stixContent={currentArtifact.artifact_content}
          incidentId={incident.incident_id}
        />
      )}
    </div>
  );
};
