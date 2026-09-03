import React, { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, ArrowRight, Check, CircleAlert, FileSearch, Gauge, LockKeyhole, Radio, ShieldCheck, Sparkles, Waves, X } from 'lucide-react';
import { FusedIncident, ScenarioId, SimulationResponse } from '../../types';
import { SIMULATION_SCENARIOS } from '../../utils/constants';

interface SimulationWalkthroughProps {
  scenario: ScenarioId;
  incident: FusedIncident | null;
  result: SimulationResponse | null;
  isSimulating: boolean;
  onBack: () => void;
  onToggleApproval: (incidentId: string) => void;
}

const steps = [
  { title: 'Capture traffic', label: 'Passive intake', description: 'A one-way copy of network traffic enters the enclave. The monitored network has no return path.', icon: Waves },
  { title: 'Normalize evidence', label: 'Zeek + JA4', description: 'Packets become structured flow records with IPs, ports, TLS fingerprints, and DNS properties.', icon: FileSearch },
  { title: 'Run detectors', label: 'Six engines', description: 'Streaming detectors test the signal for scanning, beaconing, tunnelling, malware, exfiltration, and pressure.', icon: Gauge },
  { title: 'Fuse the signal', label: 'Compound risk', description: 'Related alerts become one incident. Confidence, asset criticality, and detector synergy shape the score.', icon: Sparkles },
  { title: 'Request approval', label: 'Human gate', description: 'A response is prepared, then held at the data diode until an operator authorizes the countermeasure.', icon: LockKeyhole },
  { title: 'Apply response', label: 'Controlled action', description: 'The approved artifact crosses the one-way boundary and is recorded for audit and replay.', icon: ShieldCheck },
];
const STEP_DURATION_MS = 2100;

export const SimulationWalkthrough: React.FC<SimulationWalkthroughProps> = ({ scenario, incident, result, isSimulating, onBack, onToggleApproval }) => {
  const [activeStep, setActiveStep] = useState(0);
  const [approvalDecision, setApprovalDecision] = useState<'pending' | 'approved' | 'rejected'>('pending');
  const scenarioInfo = useMemo(() => SIMULATION_SCENARIOS.find((item) => item.id === scenario), [scenario]);
  const current = steps[activeStep];
  const CurrentIcon = current.icon;
  const finished = Boolean(result && !isSimulating && activeStep === steps.length - 1 && approvalDecision === 'approved');
  const visibleEvents = incident?.timeline.slice(0, Math.min(activeStep + 1, incident.timeline.length)) ?? [];

  useEffect(() => {
    setActiveStep(0);
    setApprovalDecision('pending');
  }, [scenario]);

  useEffect(() => {
    if (activeStep >= steps.length - 1 || (activeStep === 4 && approvalDecision !== 'approved') || finished) return;
    const timer = window.setTimeout(() => setActiveStep((step) => Math.min(step + 1, steps.length - 1)), STEP_DURATION_MS);
    return () => window.clearTimeout(timer);
  }, [activeStep, approvalDecision, finished]);

  const decideApproval = (decision: 'approved' | 'rejected') => {
    setApprovalDecision(decision);
    if (decision === 'approved' && incident) {
      onToggleApproval(incident.incident_id);
      setActiveStep(5);
    }
  };

  return <div className="walkthrough-page">
    <header className="walkthrough-topbar">
      <button className="back-button" onClick={onBack}><ArrowLeft size={16} /> Back to command center</button>
      <div className="walkthrough-brand"><span className="status-ring" /> SIH26145 <span>/</span> DEMO RUNNER</div>
      <div className="walkthrough-status"><Radio size={14} /> <span className={isSimulating ? 'status-live' : ''}>{isSimulating ? 'executing' : finished ? 'resolved' : 'presentation mode'}</span></div>
    </header>

    <main className="walkthrough-main">
      <section className="walkthrough-heading">
        <div className="heading-copy"><p className="walkthrough-overline">Scenario replay</p><h1>{scenarioInfo?.name ?? 'Security scenario'}</h1><p className="walkthrough-summary">{scenarioInfo?.description ?? 'A controlled security event moving through the defense pipeline.'}</p></div>
        <div className="run-badge"><span>Active scenario</span><strong>{scenarioInfo?.shortCode ?? scenario.toUpperCase()}</strong><small>{scenarioInfo?.stagesCount ?? 1} detection stages</small></div>
      </section>

      <section className="walkthrough-storyboard" aria-label="Simulation storyboard">
        <aside className="storyboard-rail">
          <div className="rail-heading"><span>Storyline</span><b>{String(activeStep + 1).padStart(2, '0')} / {String(steps.length).padStart(2, '0')}</b></div>
          <div className="rail-line"><span style={{ height: `${((activeStep + 1) / steps.length) * 100}%` }} /></div>
          <div className="storyboard-frames">{steps.map((step, index) => { const Icon = step.icon; const done = index < activeStep || finished; const selected = index === activeStep; const locked = index === 5 && approvalDecision !== 'approved'; return <button key={step.title} className={`storyboard-frame ${selected ? 'selected' : ''} ${done ? 'done' : ''} ${locked ? 'locked' : ''}`} aria-current={selected ? 'step' : undefined} aria-disabled={locked} disabled={locked} onClick={() => setActiveStep(index)}><span className="frame-number">{String(index + 1).padStart(2, '0')}</span><span className="frame-icon"><Icon size={16} /></span><span className="frame-copy"><strong>{step.title}</strong><em>{done ? 'complete' : locked ? 'approval required' : selected ? 'playing now' : step.label}</em></span></button>; })}</div>
          <div className="rail-footer"><span className="status-ring" /> <span>{isSimulating ? 'Live simulation' : 'Replay ready'}</span></div>
        </aside>

        <article className={`walkthrough-stage stage-${activeStep} ${finished ? 'resolved' : ''}`}>
          <div className="stage-topline"><span>Live execution trace</span><span>{scenarioInfo?.shortCode ?? scenario.toUpperCase()}</span></div>
          <div className="stage-visual">
            <div className="stage-grid" />
            <div className="stage-coordinate coordinate-one">NODE 04 <b>+</b></div><div className="stage-coordinate coordinate-two">{incident ? incident.source_ip : 'SENSOR BUS'} <b>+</b></div>
            <div className="stage-core"><div className="core-ring"><CurrentIcon size={35} /></div><strong>{current.label}</strong><small>{finished ? 'response recorded' : isSimulating ? 'signal streaming' : 'ready to replay'}</small></div>
            <div className="stage-orbit orbit-a" /><div className="stage-orbit orbit-b" /><div className="stage-orbit orbit-c" /><div className="stage-wave"><i /><i /><i /><i /><i /><i /><i /></div><div className="stage-scanline" />
            <div className="stage-caption"><span>{current.title}</span><b>{incident ? `${visibleEvents.length} events correlated` : 'Awaiting telemetry'}</b></div>
          </div>

          <div className="stage-content">
            <div className="stage-kicker"><span>Now processing</span><b>{finished ? 'COMPLETE' : `0${activeStep + 1} OF 0${steps.length}`}</b></div><h2>{current.title}</h2><p>{current.description}</p>
            <div className="evidence-strip"><div><span>{evidenceLabel(activeStep)}</span><strong>{evidenceValue(activeStep, scenarioInfo?.threatClasses, incident, finished)}</strong></div><code>{evidenceCode(activeStep, scenarioInfo?.expectedMitre, incident, finished)}</code></div>
            {activeStep === 4 && <div className={`approval-gate ${approvalDecision}`}><div className="approval-copy"><div className="approval-icon">{approvalDecision === 'rejected' ? <X size={17} /> : approvalDecision === 'approved' ? <Check size={17} /> : <LockKeyhole size={17} />}</div><div><strong>{approvalDecision === 'rejected' ? 'Response rejected' : approvalDecision === 'approved' ? 'Response approved' : 'Operator decision required'}</strong><span>{approvalDecision === 'rejected' ? 'The response remains blocked. Reconsider it to continue.' : approvalDecision === 'approved' ? 'The controlled response can now cross the one-way boundary.' : 'Review the generated artifact before allowing the next step.'}</span></div></div><div className="approval-actions"><button className="approval-reject" onClick={() => decideApproval('rejected')}><X size={14} /> Reject</button><button className="approval-approve" disabled={!incident} onClick={() => decideApproval('approved')}><Check size={14} /> Approve response</button></div></div>}
            <div className="stage-detail-grid">
              <section className="trace-panel"><div className="detail-panel-heading"><span>Event trace</span><b>{incident ? `${incident.timeline.length} signals` : 'Awaiting signal'}</b></div>{visibleEvents.length ? visibleEvents.map((event) => <div className="trace-event" key={`${event.step_number}-${event.iso_time}`}><span className="trace-index">{String(event.step_number).padStart(2, '0')}</span><div><strong>{event.stage}</strong><p>{event.summary}</p></div><code>{`${(event.confidence * 100).toFixed(0)}%`}</code></div>) : <div className="trace-empty"><Radio size={15} /><span>Detector output will appear here as the simulation runs.</span></div>}</section>
              <section className="decision-panel"><div className="detail-panel-heading"><span>Decision context</span><b>{incident?.severity ?? scenarioInfo?.severity ?? 'PENDING'}</b></div><div className="decision-facts"><div><span>Source</span><strong>{incident?.source_ip ?? 'Sensor bus'}</strong></div><div><span>Targets</span><strong>{incident ? incident.target_ips.length : 'Queued'}</strong></div><div><span>Techniques</span><strong>{incident?.mitre_mappings.length ?? scenarioInfo?.expectedMitre.length ?? 0}</strong></div><div><span>Approval</span><strong>{incident?.requires_human_approval ? 'Required' : 'Pending'}</strong></div></div>{incident && <div className="countermeasure-line"><ShieldCheck size={14} /><span>{incident.countermeasures[0] ? `${incident.countermeasures[0].countermeasure_type} for ${incident.countermeasures[0].target_entity}` : 'Response artifact prepared'}</span></div>}</section>
            </div>
            {finished && incident && <div className="completion-card"><div className="completion-icon"><Check size={18} /></div><div><strong>Scenario solved and recorded</strong><span>{incident.incident_id} is available in the investigation workspace.</span></div><b>{incident.risk_score.toFixed(0)}<small> risk</small></b></div>}
          </div>
          <footer className="stage-footer"><span>{finished ? <><Check size={14} /> Process complete</> : incident ? <><CircleAlert size={14} /> {incident.primary_threat_class} identified</> : <><Radio size={14} /> Listening for the next event</>}</span>{activeStep < steps.length - 1 && activeStep !== 4 && <button onClick={() => setActiveStep((step) => Math.min(step + 1, steps.length - 1))}>Next step <ArrowRight size={14} /></button>}</footer>
        </article>
      </section>
    </main>
  </div>;
};

function evidenceLabel(step: number) { return ['Input', 'Enrichment', 'Detection', 'Risk score', 'Decision', 'Outcome'][step]; }
function evidenceValue(step: number, threatClasses: string[] | undefined, incident: FusedIncident | null, finished: boolean) { return ['Passive traffic stream', 'Flow record + JA4 fingerprint', threatClasses?.join(' + ') ?? 'Threat patterns', incident ? `${incident.risk_score.toFixed(0)} / 100` : 'Calculating compound score', 'Human authorization required', finished ? 'Countermeasure artifact prepared' : 'Awaiting approval gate'][step]; }
function evidenceCode(step: number, mitre: string[] | undefined, incident: FusedIncident | null, finished: boolean) { return ['TX TAP / ONE-WAY', 'ZEEK / TLS / DNS', mitre?.[0] ?? 'MITRE MATCH', incident ? `${incident.raw_alert_count} ALERTS FUSED` : 'WAITING FOR ALERTS', 'RETURN PATH: BLOCKED', finished ? 'AUDIT LOGGED' : 'DIODE LOCKED'][step]; }
