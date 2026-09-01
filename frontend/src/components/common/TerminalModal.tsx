import React, { useEffect } from 'react';
import { X, ShieldAlert } from 'lucide-react';

interface TerminalModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  maxWidth?: 'max-w-lg' | 'max-w-2xl' | 'max-w-4xl';
}

export const TerminalModal: React.FC<TerminalModalProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = 'max-w-2xl',
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      {/* Backdrop click */}
      <div className="fixed inset-0" onClick={onClose} />

      <div
        className={`relative w-full ${maxWidth} bg-[#080C14] border border-cyan-500/40 rounded-lg shadow-[0_0_30px_rgba(6,182,212,0.25)] overflow-hidden z-10`}
      >
        {/* Terminal Header */}
        <div className="flex items-center justify-between px-4 py-3 bg-[#0D1322] border-b border-cyan-500/30">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="font-mono text-sm font-bold tracking-wider text-cyan-300 uppercase">{title}</h3>
              {subtitle && <p className="font-mono text-[11px] text-slate-400">{subtitle}</p>}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-cyan-500/20 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 max-h-[80vh] overflow-y-auto font-mono text-xs">{children}</div>
      </div>
    </div>
  );
};
