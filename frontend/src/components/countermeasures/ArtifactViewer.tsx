import React, { useState } from 'react';
import { CountermeasureType } from '../../types';
import { tokenizeCode, getTokenColor } from '../../utils/syntaxHighlight';
import { Copy, Check, Download, ShieldCheck, Terminal } from 'lucide-react';

interface ArtifactViewerProps {
  content: string;
  type: CountermeasureType;
  targetEntity: string;
  syntaxValid: boolean;
  incidentId: string;
}

export const ArtifactViewer: React.FC<ArtifactViewerProps> = ({
  content,
  type,
  targetEntity,
  syntaxValid,
  incidentId,
}) => {
  const [copied, setCopied] = useState(false);

  const lines = tokenizeCode(content, type);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleDownload = () => {
    const extensions: Record<CountermeasureType, string> = {
      iptables: 'sh',
      nftables: 'nft',
      cisco_acl: 'cfg',
      dns_rpz: 'rpz',
      snort3: 'rules',
      stix_bundle: 'json',
    };
    const ext = extensions[type] || 'txt';
    const filename = `${incidentId}_${type}.${ext}`;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
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
    <div className="bg-[#050811] border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2.5 bg-[#090E1B] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-200 font-bold uppercase text-xs">{type} Artifact</span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400 text-[11px]">
            Target: <strong className="text-amber-300">{targetEntity}</strong>
          </span>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            {syntaxValid ? 'SYNTAX VALID' : 'SYNTAX CHECK PENDING'}
          </span>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 transition-colors text-[11px]"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
            <span>{copied ? 'Copied!' : 'Copy Rule'}</span>
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 transition-colors text-[11px]"
          >
            <Download className="w-3.5 h-3.5 text-amber-400" />
            <span>Download</span>
          </button>
        </div>
      </div>

      {/* Code Editor Preview */}
      <div className="p-3 overflow-x-auto max-h-[340px] text-xs leading-relaxed bg-[#030509]">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((tokens, lineIdx) => (
              <tr key={lineIdx} className="hover:bg-slate-900/40">
                <td className="w-8 pr-4 text-right text-slate-600 select-none font-mono text-[10px] align-top py-0.5">
                  {lineIdx + 1}
                </td>
                <td className="font-mono text-xs py-0.5 whitespace-pre">
                  {tokens.map((token, tIdx) => (
                    <span key={tIdx} className={getTokenColor(token.type)}>
                      {token.text}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
