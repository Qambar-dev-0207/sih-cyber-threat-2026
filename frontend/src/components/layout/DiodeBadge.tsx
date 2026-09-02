import React from 'react';
import { ShieldCheck, ArrowRight, Lock } from 'lucide-react';

export const DiodeBadge: React.FC = () => {
  return (
    <div
      className="w-full px-5 py-2"
      style={{
        background: 'var(--bg-1)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 text-[10px] font-mono">
        {/* Left */}
        <div className="flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
          <Lock className="w-3 h-3" style={{ color: 'var(--accent)' }} />
          <span className="tracking-widest" style={{ color: 'var(--accent)' }}>PHYSICAL DATA DIODE</span>
          <span style={{ color: 'var(--text-dim)' }}>·</span>
          <span>Human Authorization Required</span>
          <span style={{ color: 'var(--text-dim)' }}>·</span>
          <span>Zero Automated Return Path</span>
        </div>

        {/* Right */}
        <div className="hidden lg:flex items-center gap-2" style={{ color: 'var(--text-dim)' }}>
          <span>TX TAP</span>
          <ArrowRight className="w-3 h-3" style={{ color: 'var(--accent)' }} />
          <span className="flex items-center gap-1" style={{ color: 'var(--accent)' }}>
            <ShieldCheck className="w-3 h-3" />
            ONE-WAY OPTICAL
          </span>
          <ArrowRight className="w-3 h-3" />
          <span className="line-through">RX FEEDBACK</span>
        </div>
      </div>
    </div>
  );
};
