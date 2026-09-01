import React from 'react';

interface CyberButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'cyan' | 'red' | 'amber' | 'emerald' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  loading?: boolean;
}

export const CyberButton: React.FC<CyberButtonProps> = ({
  children,
  variant = 'cyan',
  size = 'md',
  icon,
  loading = false,
  className = '',
  disabled,
  ...props
}) => {
  const baseStyles =
    'relative inline-flex items-center justify-center font-mono font-medium tracking-wide uppercase transition-all duration-200 focus:outline-none focus:ring-1 disabled:opacity-50 disabled:cursor-not-allowed select-none group';

  const sizeStyles = {
    sm: 'px-2.5 py-1 text-xs gap-1.5 rounded-sm',
    md: 'px-4 py-2 text-xs gap-2 rounded',
    lg: 'px-6 py-2.5 text-sm gap-2.5 rounded',
  };

  const variantStyles = {
    cyan: 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-cyan-100 hover:shadow-[0_0_15px_rgba(6,182,212,0.4)] focus:ring-cyan-400',
    red: 'bg-red-950/80 text-red-300 border border-red-500/60 hover:bg-red-500/20 hover:border-red-400 hover:text-red-100 hover:shadow-[0_0_15px_rgba(239,68,68,0.4)] focus:ring-red-400',
    amber: 'bg-amber-950/80 text-amber-300 border border-amber-500/60 hover:bg-amber-500/20 hover:border-amber-400 hover:text-amber-100 hover:shadow-[0_0_15px_rgba(249,115,22,0.4)] focus:ring-amber-400',
    emerald: 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/50 hover:bg-emerald-500/20 hover:border-emerald-400 hover:text-emerald-100 hover:shadow-[0_0_15px_rgba(16,185,129,0.4)] focus:ring-emerald-400',
    outline: 'bg-transparent text-slate-300 border border-slate-700 hover:border-slate-500 hover:text-white hover:bg-slate-800/40 focus:ring-slate-400',
    ghost: 'bg-transparent text-slate-400 border border-transparent hover:text-slate-200 hover:bg-slate-800/40 focus:ring-slate-600',
  };

  return (
    <button
      className={`${baseStyles} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
      ) : (
        icon && <span className="flex-shrink-0 transition-transform group-hover:scale-110">{icon}</span>
      )}
      <span>{children}</span>
    </button>
  );
};
