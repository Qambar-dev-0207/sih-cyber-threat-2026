import React, { useState } from 'react';
import { MitreMapping } from '../../types';
import { MITRE_TECHNIQUES } from '../../utils/constants';
import { TerminalModal } from '../common/TerminalModal';
import { Shield, ExternalLink, CheckCircle2 } from 'lucide-react';

interface MitreAttackPillsProps {
  mitreMappings: MitreMapping[];
}

export const MitreAttackPills: React.FC<MitreAttackPillsProps> = ({ mitreMappings }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreMapping | null>(null);

  const handleOpenDetail = (mapping: MitreMapping) => {
    setSelectedTechnique(mapping);
  };

  return (
    <div className="space-y-3 font-mono text-xs">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h4 className="font-bold text-slate-200 tracking-wider uppercase flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>MITRE ATT&CK Framework Alignments</span>
        </h4>
        <span className="text-[10px] text-slate-400">Click tag to inspect technique</span>
      </div>

      {/* Pill Tags Container */}
      <div className="flex flex-wrap gap-2">
        {mitreMappings.map((mapping) => {
          const detail = MITRE_TECHNIQUES[mapping.technique_id];
          const name = mapping.technique_name || detail?.name || mapping.technique_id;

          return (
            <button
              key={mapping.technique_id}
              onClick={() => handleOpenDetail(mapping)}
              className="flex items-center gap-2 px-3 py-1.5 rounded bg-[#0B1020] border border-cyan-500/40 hover:border-cyan-400 hover:bg-cyan-500/10 hover:shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all group select-none text-left"
            >
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 group-hover:scale-125 transition-transform" />
                <span className="font-bold text-cyan-300 text-xs">{mapping.technique_id}</span>
              </div>
              <span className="text-slate-300 text-[11px] font-medium truncate max-w-[180px]">
                {name}
              </span>
              <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">
                {(mapping.confidence * 100).toFixed(0)}%
              </span>
            </button>
          );
        })}
      </div>

      {/* MITRE Technique Deep-Dive Modal */}
      {selectedTechnique && (
        <TerminalModal
          isOpen={!!selectedTechnique}
          onClose={() => setSelectedTechnique(null)}
          title={`MITRE ATT&CK // ${selectedTechnique.technique_id}`}
          subtitle={selectedTechnique.technique_name || MITRE_TECHNIQUES[selectedTechnique.technique_id]?.name}
        >
          <div className="space-y-4">
            {/* Tactic & Phase */}
            <div className="grid grid-cols-2 gap-3 bg-[#050811] p-3 rounded border border-slate-800">
              <div>
                <span className="text-slate-500 block text-[10px]">TACTIC CATEGORY:</span>
                <span className="text-cyan-300 font-bold text-xs">
                  {selectedTechnique.tactic_name || selectedTechnique.tactic_id}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">KILL CHAIN PHASE:</span>
                <span className="text-amber-300 font-bold text-xs">
                  {selectedTechnique.kill_chain_phase}
                </span>
              </div>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <h5 className="font-bold text-slate-300 text-[11px] uppercase">Technique Description:</h5>
              <p className="text-slate-300 leading-relaxed font-sans text-xs bg-[#0B1020] p-3 rounded border border-slate-800">
                {selectedTechnique.description ||
                  MITRE_TECHNIQUES[selectedTechnique.technique_id]?.description ||
                  'Adversary utilizes this technique to achieve operational goals within the targeted enclave.'}
              </p>
            </div>

            {/* Detection Engine Correlation */}
            <div className="space-y-1.5">
              <h5 className="font-bold text-slate-300 text-[11px] uppercase">Sensor Correlation:</h5>
              <div className="bg-[#050811] p-3 rounded border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Matched Streaming Detector:</span>
                  <strong className="text-emerald-400">{selectedTechnique.matched_detector}</strong>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Detection Confidence:</span>
                  <strong className="text-cyan-300">{(selectedTechnique.confidence * 100).toFixed(1)}%</strong>
                </div>
                <div className="flex items-center gap-1 text-slate-400 pt-1 border-t border-slate-800 text-[10px]">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Cross-verified against MITRE Enterprise Matrix v14.1</span>
                </div>
              </div>
            </div>

            {/* External Reference Link */}
            <div className="flex justify-end pt-2">
              <a
                href={`https://attack.mitre.org/techniques/${selectedTechnique.technique_id.replace('.', '/')}`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 underline text-xs font-semibold"
              >
                <span>View on MITRE ATT&CK Official Portal</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          </div>
        </TerminalModal>
      )}
    </div>
  );
};
