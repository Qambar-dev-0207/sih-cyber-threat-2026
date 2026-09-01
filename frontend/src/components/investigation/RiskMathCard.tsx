import React from 'react';
import { RiskBreakdown } from '../../types';
import { Calculator, Sparkles, Cpu } from 'lucide-react';
import { getSeverityColor } from '../../utils/formatters';

interface RiskMathCardProps {
  riskBreakdown: RiskBreakdown;
  riskScore: number;
}

export const RiskMathCard: React.FC<RiskMathCardProps> = ({ riskBreakdown, riskScore }) => {
  const styles = getSeverityColor(riskBreakdown.severity);

  return (
    <div className="space-y-4 font-mono text-xs">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h4 className="font-bold text-slate-200 tracking-wider uppercase flex items-center gap-2">
          <Calculator className="w-4 h-4 text-cyan-400" />
          <span>Explainable Mathematical Risk Formula Breakdown</span>
        </h4>
        <span className={`px-2.5 py-0.5 rounded font-bold uppercase text-[11px] ${styles.badge}`}>
          {riskBreakdown.severity} (Score: {riskScore.toFixed(1)})
        </span>
      </div>

      {/* Formula Readout Box */}
      <div className="p-3.5 bg-[#050811] border border-cyan-500/40 rounded-lg space-y-2">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="text-cyan-400 font-bold uppercase">Mathematical Formulation:</span>
          <span>Bounded Range: [0.0, 100.0]</span>
        </div>

        <div className="p-2.5 bg-black/60 rounded border border-slate-800 text-cyan-300 font-bold text-xs sm:text-sm tracking-wide overflow-x-auto">
          Risk = min(100.0, ( ∑(Weight_i × Conf_i) + Synergy_Bonus ) × Asset_Multiplier)
        </div>

        {/* Dynamic Calculation Instance */}
        <div className="text-[11px] text-slate-300 space-y-1 pt-1">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Evaluated Equation:</span>
            <code className="text-amber-300 font-bold">{riskBreakdown.formula}</code>
          </div>
          {riskBreakdown.synergy_reason && (
            <div className="flex items-center gap-1.5 text-emerald-400 text-[10px] mt-1 bg-emerald-950/40 p-1.5 rounded border border-emerald-500/20">
              <Sparkles className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{riskBreakdown.synergy_reason}</span>
            </div>
          )}
        </div>
      </div>

      {/* 3 Component Pillars */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-center">
        {/* Base Risk Sum */}
        <div className="p-3 bg-[#0B1020] border border-slate-800 rounded-lg space-y-1">
          <span className="text-slate-500 block text-[10px] uppercase">Base Weight Sum</span>
          <span className="text-slate-100 font-extrabold text-lg tabular-nums">
            {riskBreakdown.base_risk_sum.toFixed(1)}
          </span>
          <span className="text-slate-400 text-[10px] block">Sum of Raw Detectors</span>
        </div>

        {/* Synergy Bonus */}
        <div className="p-3 bg-[#0B1020] border border-slate-800 rounded-lg space-y-1">
          <span className="text-slate-500 block text-[10px] uppercase">Synergy Bonus</span>
          <span className="text-emerald-400 font-extrabold text-lg tabular-nums">
            +{riskBreakdown.synergy_bonus.toFixed(1)}
          </span>
          <span className="text-slate-400 text-[10px] block">Multi-Stage Correlation</span>
        </div>

        {/* Asset Multiplier */}
        <div className="p-3 bg-[#0B1020] border border-slate-800 rounded-lg space-y-1">
          <span className="text-slate-500 block text-[10px] uppercase">Criticality Multiplier</span>
          <span className="text-amber-400 font-extrabold text-lg tabular-nums">
            {riskBreakdown.asset_criticality_multiplier.toFixed(2)}x
          </span>
          <span className="text-slate-400 text-[10px] block">Core DMZ Asset Tier</span>
        </div>
      </div>

      {/* Detailed Evidence Breakdown Table */}
      <div className="bg-[#0B1020] border border-slate-800 rounded-lg p-3 space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-300 font-bold border-b border-slate-800 pb-1.5">
          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Detector Weight Contributions</span>
          </span>
          <span className="text-[10px] text-slate-400">
            {riskBreakdown.evidence_breakdown.length} Evidence Items
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-[11px]">
            <thead>
              <tr className="text-slate-500 border-b border-slate-900">
                <th className="pb-1.5 font-medium">Threat Class</th>
                <th className="pb-1.5 font-medium">Detector</th>
                <th className="pb-1.5 font-medium text-right">Base Weight</th>
                <th className="pb-1.5 font-medium text-right">Confidence</th>
                <th className="pb-1.5 font-medium text-right">Weighted Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900/60">
              {riskBreakdown.evidence_breakdown.map((item, idx) => (
                <tr key={idx} className="hover:bg-white/5 transition-colors">
                  <td className="py-2 text-cyan-300 font-semibold">{item.threat_class}</td>
                  <td className="py-2 text-slate-300">{item.detector}</td>
                  <td className="py-2 text-right text-slate-400">{item.base_weight.toFixed(1)}</td>
                  <td className="py-2 text-right text-emerald-400">{(item.confidence * 100).toFixed(0)}%</td>
                  <td className="py-2 text-right text-amber-300 font-bold">{item.weighted_score.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
