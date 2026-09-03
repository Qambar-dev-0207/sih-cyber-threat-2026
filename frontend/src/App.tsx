import React, { useState } from 'react';
import { Activity, ArrowRight, Check, CircleAlert, Gauge, LayoutDashboard, LockKeyhole, Play, Radio, ShieldCheck, Sparkles, Waves, X } from 'lucide-react';
import { Header } from './components/layout/Header';
import { StatusBar } from './components/layout/StatusBar';
import { DemoControlBar } from './components/simulation/DemoControlBar';
import { LiveAreaChart } from './components/telemetry/LiveAreaChart';
import { DetectorGrid } from './components/telemetry/DetectorGrid';
import { IncidentHeatmap } from './components/telemetry/IncidentHeatmap';
import { ThreatFeed } from './components/incidents/ThreatFeed';
import { IncidentsPage } from './components/incidents/IncidentsPage';
import { InvestigationDrawer } from './components/investigation/InvestigationDrawer';
import { Toast } from './components/common/Toast';
import { SimulationWalkthrough } from './components/simulation/SimulationWalkthrough';
import { useTelemetryStream } from './hooks/useTelemetryStream';
import { useIncidentStream } from './hooks/useIncidentStream';
import { useSimulation } from './hooks/useSimulation';
import { ScenarioId } from './types';

const pipelineStages = [
  { id: '01', name: 'Capture', detail: 'Passive traffic intake', icon: Waves },
  { id: '02', name: 'Normalize', detail: 'Zeek + JA4 enrichment', icon: Activity },
  { id: '03', name: 'Detect', detail: 'Six streaming engines', icon: Gauge },
  { id: '04', name: 'Fuse', detail: 'Compound risk score', icon: Sparkles },
  { id: '05', name: 'Review', detail: 'Human approval gate', icon: LockKeyhole },
  { id: '06', name: 'Respond', detail: 'One-way countermeasure', icon: ShieldCheck },
];

function Pipeline({ incident, isSimulating }: { incident: any; isSimulating: boolean }) {
  const activeIndex = incident ? 4 : isSimulating ? 2 : 3;
  return (
    <section className="pipeline-panel" aria-labelledby="pipeline-heading">
      <div className="pipeline-heading-row">
        <div><div className="eyebrow light">Operational flow</div><h2 id="pipeline-heading">From raw signal to controlled response.</h2></div>
        <div className="pipeline-state"><span className="status-ring" /> {isSimulating ? 'SCENARIO RUNNING' : 'PIPELINE NOMINAL'}</div>
      </div>
      <div className="pipeline-track">
        {pipelineStages.map((stage, index) => {
          const Icon = stage.icon;
          const isComplete = index < activeIndex;
          const isActive = index === activeIndex;
          return <React.Fragment key={stage.id}>
            <div className={`pipeline-step ${isComplete ? 'complete' : ''} ${isActive ? 'active' : ''}`}>
              <div className="pipeline-icon">{isComplete ? <Check size={16} /> : <Icon size={16} />}</div>
              <div className="pipeline-number">{stage.id}</div><div className="pipeline-name">{stage.name}</div><div className="pipeline-detail">{stage.detail}</div>
            </div>
            {index < pipelineStages.length - 1 && <div className={`pipeline-connector ${index < activeIndex ? 'complete' : ''}`}><ArrowRight size={15} /></div>}
          </React.Fragment>;
        })}
      </div>
      <div className="pipeline-footer"><span><Radio size={13} /> Passive capture remains isolated</span><span>{incident ? `${incident.incident_id} selected for investigation` : 'Select a threat below to walk the response path'}</span></div>
    </section>
  );
}

export const App: React.FC = () => {
  const { metrics, history, connectionStatus, streamMode, reconnect } = useTelemetryStream();
  const { filteredIncidents, selectedIncident, selectedIncidentId, setSelectedIncidentId, severityFilter, setSeverityFilter, threatClassFilter, setThreatClassFilter, searchQuery, setSearchQuery, severityCounts, upsertIncident, toggleHumanApproval, newIncidentAlert, clearAlert } = useIncidentStream();
  const { triggerSimulation, isSimulating, activeScenario, lastResult } = useSimulation({
    onIncidentGenerated: (inc) => { upsertIncident(inc); setSelectedIncidentId(inc.incident_id); },
    onSelectIncident: (id) => setSelectedIncidentId(id),
  });
  const [showWalkthrough, setShowWalkthrough] = useState(false);
  const [activeView, setActiveView] = useState<'overview' | 'incidents'>('overview');
  const [walkthroughScenario, setWalkthroughScenario] = useState<ScenarioId>('apt');
  const runScenario = (scenario: ScenarioId) => {
    setWalkthroughScenario(scenario);
    setSelectedIncidentId(null);
    setShowWalkthrough(true);
    void triggerSimulation(scenario);
  };
  const activeDetectorsCount = Object.values(metrics?.active_detectors ?? {}).filter(Boolean).length;

  if (showWalkthrough) {
    return <SimulationWalkthrough scenario={walkthroughScenario} incident={selectedIncident} result={lastResult} isSimulating={isSimulating} onBack={() => setShowWalkthrough(false)} onToggleApproval={toggleHumanApproval} />;
  }

  if (activeView === 'incidents') {
    return <div className="app-shell"><Header connectionStatus={connectionStatus} streamMode={streamMode} onReconnect={reconnect} eps={metrics?.events_per_sec ?? 0} mbps={metrics?.mbps ?? 0} totalEvents={metrics?.total_events_processed ?? 0} /><div className="incidents-page-shell"><aside className="workspace-rail incidents-rail"><div className="rail-mark">S</div><div className="rail-caption">Workspace</div><nav aria-label="Workspace navigation"><button className="rail-link" onClick={() => setActiveView('overview')}><LayoutDashboard size={16} /><span>Overview</span></button><button className="rail-link active"><CircleAlert size={16} /><span>Incidents</span><b>{filteredIncidents.length}</b></button></nav><div className="rail-bottom"><span className="status-ring" /><span>Air-gapped<br />enclave</span></div></aside><IncidentsPage incidents={filteredIncidents} selectedIncident={selectedIncident} selectedIncidentId={selectedIncidentId} onSelectIncident={setSelectedIncidentId} onCloseIncident={() => setSelectedIncidentId(null)} severityFilter={severityFilter} onSelectSeverity={setSeverityFilter} threatClassFilter={threatClassFilter} onSelectThreatClass={setThreatClassFilter} searchQuery={searchQuery} onSearchChange={setSearchQuery} severityCounts={severityCounts} onToggleApproval={toggleHumanApproval} /></div><StatusBar totalEvents={metrics?.total_events_processed ?? 0} activeDetectorsCount={activeDetectorsCount} bufferUtilization={metrics?.buffer_utilization_pct ?? 0} pipelineLatency={metrics?.pipeline_latency_ms ?? 0} /><Toast incident={newIncidentAlert} onClose={clearAlert} onInvestigate={(id) => { setSelectedIncidentId(id); clearAlert(); }} /></div>;
  }

  return <div className="app-shell">
    <Header connectionStatus={connectionStatus} streamMode={streamMode} onReconnect={reconnect} eps={metrics?.events_per_sec ?? 0} mbps={metrics?.mbps ?? 0} totalEvents={metrics?.total_events_processed ?? 0} />
    <main>
      <section className="hero-shell" id="overview"><div className="hero-inner">
        <div className="hero-copy"><div className="eyebrow">SIH26145 / defense enclave</div><h1>See the whole defense system at a glance.</h1><p>Passive telemetry, compound detection, and human-controlled response in one live operating view.</p><div className="hero-actions"><button className="hero-action" onClick={() => runScenario('apt')} disabled={isSimulating}><Play size={15} /> {isSimulating ? 'Running scenario' : 'Run demo scenario'}</button><span className="hero-note"><span className="status-ring dark" /> {streamMode === 'OFFLINE_MOCK' ? 'Local simulation active' : 'Telemetry stream connected'}</span></div></div>
        <div className="hero-metric-grid"><div className="hero-metric hero-metric-wide"><span>Events processed</span><strong>{(metrics?.total_events_processed ?? 0).toLocaleString()}</strong><small><Activity size={12} /> line rate stable</small></div><div className="hero-metric"><span>Risk queue</span><strong>{filteredIncidents.length}</strong><small><CircleAlert size={12} /> open incidents</small></div><div className="hero-metric"><span>Healthy engines</span><strong>{activeDetectorsCount}/6</strong><small><Check size={12} /> all systems ready</small></div></div>
      </div></section>
      <div className="dashboard-shell"><aside className="workspace-rail"><div className="rail-mark">S</div><div className="rail-caption">Workspace</div><nav aria-label="Workspace navigation"><button className="rail-link active" onClick={() => setActiveView('overview')}><LayoutDashboard size={16} /><span>Overview</span></button><button className="rail-link" onClick={() => setActiveView('incidents')}><CircleAlert size={16} /><span>Incidents</span><b>{filteredIncidents.length}</b></button></nav><div className="rail-bottom"><span className="status-ring" /><span>Air-gapped<br />enclave</span></div></aside><div className="content-wrap">
        <Pipeline incident={selectedIncident} isSimulating={isSimulating} />
        <section className="section-block" id="telemetry" aria-labelledby="telemetry-heading"><div className="section-title-row"><div><div className="eyebrow">Live telemetry</div><h2 id="telemetry-heading">The system is moving.</h2></div><div className="section-readout"><span className="status-ring" /> updates every 500ms</div></div><div className="chart-grid"><LiveAreaChart history={history} field="eps" label="Events / second" unit="EPS" color="#111111" /><LiveAreaChart history={history} field="mbps" label="Line bandwidth" unit="Mbps" color="#555555" /><LiveAreaChart history={history} field="latency_ms" label="Pipeline latency" unit="us" color="#888888" /><div className="metric-tile"><span>Buffer utilization</span><strong>{(metrics?.buffer_utilization_pct ?? 0).toFixed(1)}<small>%</small></strong><div className="tile-rule"><i style={{ width: `${Math.min(100, metrics?.buffer_utilization_pct ?? 0)}%` }} /></div><small>packet loss {(metrics?.packet_loss_pct ?? 0).toFixed(3)}%</small></div></div></section>
        <div className="demo-strip"><div><span className="eyebrow">Demonstration controls</span><strong>Inject a known scenario into the live path.</strong></div><DemoControlBar onTrigger={runScenario} isSimulating={isSimulating} activeScenario={activeScenario} lastResult={lastResult} /></div>
        <section className="section-block compact-block"><div className="section-title-row"><div><div className="eyebrow">Detection fabric</div><h2>Six engines. One decision surface.</h2></div></div><DetectorGrid activeDetectors={metrics?.active_detectors} /></section>
        <section className="section-block compact-block"><div className="section-title-row"><div><div className="eyebrow">Threat activity</div><h2>Where pressure is building.</h2></div></div><IncidentHeatmap incidents={filteredIncidents} /></section>
        <section className="incident-workspace" id="incidents" aria-label="Incident feed and investigation"><ThreatFeed incidents={filteredIncidents} selectedIncidentId={selectedIncidentId} onSelectIncident={setSelectedIncidentId} severityFilter={severityFilter} onSelectSeverity={setSeverityFilter} threatClassFilter={threatClassFilter} onSelectThreatClass={setThreatClassFilter} searchQuery={searchQuery} onSearchChange={setSearchQuery} severityCounts={severityCounts} />{selectedIncident ? <InvestigationDrawer incident={selectedIncident} onClose={() => setSelectedIncidentId(null)} onToggleApproval={toggleHumanApproval} /> : <div className="empty-investigation"><X size={22} /><strong>Choose an incident to investigate</strong><span>The selected threat will stay visible as it moves through review and response.</span></div>}</section>
      </div></div>
    </main>
    <StatusBar totalEvents={metrics?.total_events_processed ?? 0} activeDetectorsCount={activeDetectorsCount} bufferUtilization={metrics?.buffer_utilization_pct ?? 0} pipelineLatency={metrics?.pipeline_latency_ms ?? 0} />
    <Toast incident={newIncidentAlert} onClose={clearAlert} onInvestigate={(id) => { setSelectedIncidentId(id); clearAlert(); }} />
  </div>;
};

export default App;
