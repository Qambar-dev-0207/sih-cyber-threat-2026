import React, { useState } from 'react';
import { TerminalModal } from '../common/TerminalModal';
import { Copy, Check, Download, Share2 } from 'lucide-react';

interface StixExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  stixContent: string;
  incidentId: string;
}

export const StixExportModal: React.FC<StixExportModalProps> = ({
  isOpen,
  onClose,
  stixContent,
  incidentId,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(stixContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleDownload = () => {
    const filename = `${incidentId}_stix21_bundle.json`;
    const blob = new Blob([stixContent], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <TerminalModal
      isOpen={isOpen}
      onClose={onClose}
      title="STIX 2.1 Threat Intelligence Bundle"
      subtitle={`Incident Target: ${incidentId} // OASIS STIX 2.1 Standard Specification`}
      maxWidth="max-w-4xl"
    >
      <div className="space-y-3 font-mono text-xs">
        {/* Top Control Strip */}
        <div className="flex items-center justify-between bg-[#050811] p-2.5 rounded border border-slate-800">
          <div className="flex items-center gap-2">
            <Share2 className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300 font-bold">OASIS CTI STIX 2.1 Compliant</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 rounded border border-cyan-500/40 text-xs font-semibold"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 rounded border border-emerald-500/40 text-xs font-semibold"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export .json</span>
            </button>
          </div>
        </div>

        {/* JSON Code Viewer */}
        <pre className="p-4 bg-[#030509] border border-slate-900 rounded-lg text-slate-200 overflow-x-auto max-h-[450px] font-mono text-[11px] leading-relaxed select-text">
          {stixContent}
        </pre>
      </div>
    </TerminalModal>
  );
};
