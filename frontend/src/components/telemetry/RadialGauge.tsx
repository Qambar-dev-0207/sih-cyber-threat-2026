import React from 'react';

interface RadialGaugeProps {
  value: number;
  min: number;
  max: number;
  label: string;
  unit: string;
  color?: 'cyan' | 'emerald' | 'amber' | 'red';
  targetBenchmark?: string;
}

export const RadialGauge: React.FC<RadialGaugeProps> = ({
  value,
  min,
  max,
  label,
  unit,
  color = 'cyan',
  targetBenchmark,
}) => {
  const percentage = Math.min(100, Math.max(0, ((value - min) / (max - min)) * 100));

  // Gauge geometry
  const size = 130;
  const strokeWidth = 8;
  const center = size / 2;
  const radius = center - strokeWidth - 2;
  const circumference = 2 * Math.PI * radius;
  // Arc angle of 240 degrees (open at bottom)
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (percentage / 100) * arcLength;

  const colorStyles = {
    cyan: {
      stroke: '#06B6D4',
      glow: 'rgba(6, 182, 212, 0.5)',
      text: 'text-cyan-400',
    },
    emerald: {
      stroke: '#10B981',
      glow: 'rgba(16, 185, 129, 0.5)',
      text: 'text-emerald-400',
    },
    amber: {
      stroke: '#F97316',
      glow: 'rgba(249, 115, 22, 0.5)',
      text: 'text-amber-400',
    },
    red: {
      stroke: '#EF4444',
      glow: 'rgba(239, 68, 68, 0.5)',
      text: 'text-red-400',
    },
  };

  const currentStyle = colorStyles[color];

  return (
    <div className="flex flex-col items-center justify-center p-3 bg-[#0A0F1D] border border-slate-800 rounded-lg shadow-panel relative group hover:border-slate-700 transition-all">
      {/* Title */}
      <div className="text-[11px] font-mono font-semibold tracking-wider text-slate-400 uppercase text-center mb-1">
        {label}
      </div>

      {/* SVG Arc Gauge */}
      <div className="relative flex items-center justify-center" style={{ width: size, height: size - 15 }}>
        <svg
          width={size}
          height={size}
          className="transform -rotate-[135deg] overflow-visible"
        >
          {/* Background Track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="transparent"
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />

          {/* Active Value Arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="transparent"
            stroke={currentStyle.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 6px ${currentStyle.glow})`,
              transition: 'stroke-dashoffset 0.4s ease, stroke 0.4s ease',
            }}
          />
        </svg>

        {/* Center Digital Value */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center mt-2">
          <span className={`font-mono text-lg sm:text-xl font-extrabold tracking-tight tabular-nums ${currentStyle.text}`}>
            {typeof value === 'number' && value >= 1000 ? value.toLocaleString() : value.toFixed(value < 10 ? 2 : 0)}
          </span>
          <span className="font-mono text-[10px] text-slate-400 uppercase font-semibold">
            {unit}
          </span>
        </div>
      </div>

      {/* Benchmark Target Info */}
      {targetBenchmark && (
        <div className="mt-1 text-[10px] font-mono text-slate-500 flex items-center gap-1">
          <span>TARGET:</span>
          <span className="text-slate-300 font-semibold">{targetBenchmark}</span>
        </div>
      )}
    </div>
  );
};
