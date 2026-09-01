import React, { useState } from 'react';
import { TimelineStep } from '../../types';
import { formatTimestamp, formatRelativeTime } from '../../utils/formatters';
import { ChevronDown, ChevronRight, Clock, ShieldCheck, Cpu, Code2, Database } from 'lucide-react';

interface AttackTimelineProps {
  timeline: TimelineStep[];
}

export const AttackTimeline: React.FC<AttackTimelineProps> = ({ timeline }) => {
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({
    1: true,
    2: true,
    3: true,
    4: true,
  });

  const toggleStep = (stepNumber: number) => {
    setExpandedSteps((prev) => ({
      ...prev,
      [stepNumber]: !prev[stepNumber],
    }));
  };

  return (
    <div className="space-y-4 font-mono text-xs">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h4 className="font-bold text-slate-200 tracking-wider uppercase flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Chronological Multi-Stage Attack Timeline ($t_1 \to t_n$)</span>
        </h4>
        <span className="text-[11px] text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
          {timeline.length} Correlated Stages
        </span>
      </div>

      <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-amber-500 before:to-red-500">
        {timeline.map((step) => {
          const isExpanded = expandedSteps[step.step_number] ?? false;

          return (
            <div key={step.step_number} className="relative group">
              {/* Timeline Marker Dot */}
              <div className="absolute -left-6 top-1.5 w-5 h-5 rounded-full bg-[#080D1A] border-2 border-cyan-400 flex items-center justify-center shadow-[0_0_8px_rgba(6,182,212,0.8)] z-10">
                <span className="text-[9px] font-bold text-cyan-200">{step.step_number}</span>
              </div>

              {/* Step Card */}
              <div className="bg-[#0B1020] border border-slate-800 group-hover:border-cyan-500/40 rounded-lg p-3.5 transition-all">
                {/* Step Header */}
                <div
                  onClick={() => toggleStep(step.step_number)}
                  className="flex items-center justify-between gap-2 cursor-pointer select-none"
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 font-bold text-[10px] border border-cyan-500/30">
                      STAGE {step.step_number}: {step.stage.toUpperCase()}
                    </span>

                    <span className="text-amber-400 font-semibold text-[11px]">
                      {formatRelativeTime(step.relative_time_offset_sec)}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-[10px] hidden sm:inline">
                      {formatTimestamp(step.timestamp)}
                    </span>
                    <button className="text-slate-400 hover:text-cyan-300">
                      {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Summary */}
                <p className="text-slate-200 mt-2 text-xs leading-relaxed font-sans font-medium">
                  {step.summary}
                </p>

                {/* Detector and Target Info */}
                <div className="mt-2.5 flex flex-wrap items-center gap-3 text-[11px] text-slate-400 pt-2 border-t border-slate-800/80">
                  <span className="flex items-center gap-1">
                    <Cpu className="w-3 h-3 text-emerald-400" />
                    <span>Detector:</span>
                    <strong className="text-emerald-300">{step.detector}</strong>
                  </span>

                  {step.target_ip && (
                    <span className="flex items-center gap-1">
                      <Database className="w-3 h-3 text-amber-400" />
                      <span>Target:</span>
                      <strong className="text-amber-300">
                        {step.target_ip}
                        {step.target_port ? `:${step.target_port}` : ''}
                      </strong>
                    </span>
                  )}

                  <span className="flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3 text-cyan-400" />
                    <span>Confidence:</span>
                    <strong className="text-cyan-300">{(step.confidence * 100).toFixed(0)}%</strong>
                  </span>
                </div>

                {/* Expandable Evidence Snapshot */}
                {isExpanded && step.evidence_snapshot && (
                  <div className="mt-3 bg-[#050811] p-2.5 rounded border border-slate-900 font-mono text-[11px] text-slate-300 space-y-1.5">
                    <div className="flex items-center gap-1.5 text-cyan-400 font-bold border-b border-slate-800 pb-1 text-[10px]">
                      <Code2 className="w-3 h-3" />
                      <span>EVIDENCE SNAPSHOT PAYLOAD</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
                      {Object.entries(step.evidence_snapshot).map(([k, v]) => (
                        <div key={k} className="flex items-baseline justify-between gap-2">
                          <span className="text-slate-500 uppercase text-[10px]">{k}:</span>
                          <span className="text-amber-300 font-bold truncate max-w-[200px]">
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
