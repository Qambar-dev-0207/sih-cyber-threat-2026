import React, { useState } from 'react';
import {
  Activity, ArrowRight, Check, CircleAlert, Command, Gauge, LayoutDashboard,
  LockKeyhole, Play, Radio, Search, ShieldCheck, Sparkles, Waves,
} from 'lucide-react';
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
      <div className="section-kicker-row">
        <div><div className="eyebrow light">Operational flow</div><h2 id="pipeline-heading">From raw signal to controlled response.</h2></div>
        <div className="pipeline-state" aria-live="polite"><span className="status-dot pulse" /> {isSimulating ? 'Scenario running' : incident ? 'Review gate active' : 'Pipeline nominal'}</div>
      </div>
      <div className="pipeline-track">
        {pipelineStages.map((stage, index) => {
          const Icon = stage.icon;
          const isComplete = index < activeIndex;
          const isActive = index === activeIndex;
          return <React.Fragment key={stage.id}>
            <div className={`pipeline-step ${isComplete ? 'complete' : ''} ${isActive ? 'active' : ''}`} aria-current={isActive ? 'step' : undefined}>
              <div className="pipeline-icon">{isComplete ? <Check size={16} /> : <Icon size={16} />}</div><div className="pipeline-number">{stage.id}</div><div className="pipeline-name">{stage.name}</div><div className="pipeline-detail">{stage.detail}</div>
            </div>
            {index < pipelineStages.length - 1 && <div className={`pipeline-connector ${index < activeIndex ? 'complete' : ''}`}><ArrowRight size={15} /></div>}
          </React.Fragment>;
        })}
      </div>
      <div className="pipeline-footer"><span><Radio size={13} /> Passive capture remains isolated</span><span>{incident ? `${incident.incident_id} selected for investigation` : 'Human review gates every response'}</span></div>
    </section>
  );
}

function HealthOverview({ events, incidents, detectors }: { events: number; incidents: number; detectors: number }) {
  return <div className="health-overview" aria-label="System health summary">
    <div className="health-visual"><div className="health-ring"><div><strong>98.7</strong><span>health</span></div></div><div className="health-caption"><span className="status-dot pulse" /> Enclave operating within guardrails</div></div>
    <div className="health-readouts">
      <div><span>Events processed</span><strong>{events.toLocaleString()}</strong><small>+2.4% vs baseline</small></div>
      <div><span>Active incidents</span><strong className={incidents ? 'critical-text' : ''}>{incidents}</strong><small>{incidents ? 'operator attention required' : 'no open incidents'}</small></div>
      <div><span>Detection engines</span><strong>{detectors}<em>/6</em></strong><small>all streaming online</small></div>
      <div><span>Current risk</span><strong className={incidents ? 'critical-text' : ''}>{incidents ? 'Elevated' : 'Nominal'}</strong><small>derived from compound signals</small></div>
    </div>
  </div>;
}

export const App: React.FC = () => {
  const { metrics, history, connectionStatus, streamMode, reconnect } = useTelemetryStream();
  const { filteredIncidents, selectedIncident, selectedIncidentId, setSelectedIncidentId, severityFilter, setSeverityFilter, threatClassFilter, setThreatClassFilter, searchQuery, setSearchQuery, severityCounts, upsertIncident, toggleHumanApproval, newIncidentAlert, clearAlert } = useIncidentStream();
  const { triggerSimulation, isSimulating, activeScenario, lastResult } = useSimulation({ onIncidentGenerated: (inc) => { upsertIncident(inc); setSelectedIncidentId(inc.incident_id); }, onSelectIncident: (id) => setSelectedIncidentId(id) });
  const [showWalkthrough, setShowWalkthrough] = useState(false);
  const [activeView, setActiveView] = useState<'overview' | 'incidents'>('overview');
  const [walkthroughScenario, setWalkthroughScenario] = useState<ScenarioId>('apt');
  const runScenario = (scenario: ScenarioId) => { setWalkthroughScenario(scenario); setSelectedIncidentId(null); setShowWalkthrough(true); void triggerSimulation(scenario); };
  const activeDetectorsCount = Object.values(metrics?.active_detectors ?? {}).filter(Boolean).length;
  const totalEvents = metrics?.total_events_processed ?? 0;

  if (showWalkthrough) return <SimulationWalkthrough scenario={walkthroughScenario} incident={selectedIncident} result={lastResult} isSimulating={isSimulating} onBack={() => setShowWalkthrough(false)} onToggleApproval={toggleHumanApproval} />;

  const nav = <aside className="workspace-rail">
    <div className="brand-mark" aria-label="SIH26145 defense enclave">S<span>+</span></div><div className="rail-caption">Command center</div>
    <nav aria-label="Workspace navigation">
      <button className={`rail-link ${activeView === 'overview' ? 'active' : ''}`} onClick={() => setActiveView('overview')}><LayoutDashboard size={17} /><span>Overview</span></button>
      <button className={`rail-link ${activeView === 'incidents' ? 'active' : ''}`} onClick={() => setActiveView('incidents')}><CircleAlert size={17} /><span>Incidents</span>{filteredIncidents.length > 0 && <b>{filteredIncidents.length}</b>}</button>
      <button className="rail-link" onClick={() => document.getElementById('telemetry')?.scrollIntoView({ behavior: 'smooth' })}><Activity size={17} /><span>Telemetry</span></button>
    </nav>
    <div className="rail-shortcuts"><span><Command size={13} /> Command palette</span><span><Search size={13} /> Search incidents</span></div>
    <div className="rail-bottom"><span className="status-dot pulse" /><span><strong>Air-gapped enclave</strong><small>System health 98.7%</small></span></div>
  </aside>;

  if (activeView === 'incidents') return <div className="app-shell"><Header connectionStatus={connectionStatus} streamMode={streamMode} onReconnect={reconnect} eps={metrics?.events_per_sec ?? 0} mbps={metrics?.mbps ?? 0} totalEvents={totalEvents} /><div className="incidents-page-shell">{nav}<IncidentsPage incidents={filteredIncidents} selectedIncident={selectedIncident} selectedIncidentId={selectedIncidentId} onSelectIncident={setSelectedIncidentId} onCloseIncident={() => setSelectedIncidentId(null)} severityFilter={severityFilter} onSelectSeverity={setSeverityFilter} threatClassFilter={threatClassFilter} onSelectThreatClass={setThreatClassFilter} searchQuery={searchQuery} onSearchChange={setSearchQuery} severityCounts={severityCounts} onToggleApproval={toggleHumanApproval} /></div><StatusBar totalEvents={totalEvents} activeDetectorsCount={activeDetectorsCount} bufferUtilization={metrics?.buffer_utilization_pct ?? 0} pipelineLatency={metrics?.pipeline_latency_ms ?? 0} /><Toast incident={newIncidentAlert} onClose={clearAlert} onInvestigate={(id) => { setSelectedIncidentId(id); clearAlert(); }} /></div>;

  return <div className="app-shell">
    <Header connectionStatus={connectionStatus} streamMode={streamMode} onReconnect={reconnect} eps={metrics?.events_per_sec ?? 0} mbps={metrics?.mbps ?? 0} totalEvents={totalEvents} />
    <main>
      <section className="hero-shell" id="overview"><div className="hero-inner"><div className="hero-copy"><div className="eyebrow accent-label">SIH26145 / defense enclave</div><h1>See the whole defense system at a glance.</h1><p>Passive telemetry · compound detection · human-controlled response</p><div className="hero-actions"><button className="primary-action" onClick={() => runScenario('apt')} disabled={isSimulating}><Play size={15} /> {isSimulating ? 'Running scenario' : 'Run demo scenario'}</button><span className="hero-note"><span className="status-dot pulse" /> {streamMode === 'OFFLINE_MOCK' ? 'Local simulation active' : 'Telemetry stream connected'}</span></div></div><HealthOverview events={totalEvents} incidents={filteredIncidents.length} detectors={activeDetectorsCount} /></div></section>
      <div className="dashboard-shell">{nav}<div className="content-wrap">
        <Pipeline incident={selectedIncident} isSimulating={isSimulating} />
        <section className="section-block" id="telemetry" aria-labelledby="telemetry-heading"><div className="section-title-row"><div><div className="eyebrow">Live telemetry</div><h2 id="telemetry-heading">The system is moving.</h2></div><div className="section-readout"><span className="status-dot pulse" /> Updates every 500 ms</div></div><div className="chart-grid"><LiveAreaChart history={history} field="eps" label="Events / second" unit="EPS" color="#B7F34A" /><LiveAreaChart history={history} field="mbps" label="Line bandwidth" unit="Mbps" color="#7CC7FF" /><LiveAreaChart history={history} field="latency_ms" label="Pipeline latency" unit="μs" color="#A7AEA9" /><div className="metric-tile"><div><span>Buffer utilization</span><strong>{(metrics?.buffer_utilization_pct ?? 0).toFixed(1)}<small>%</small></strong></div><div className="tile-rule"><i style={{ width: `${Math.min(100, metrics?.buffer_utilization_pct ?? 0)}%` }} /></div><div className="metric-foot"><span>Packet loss</span><strong>{(metrics?.packet_loss_pct ?? 0).toFixed(3)}%</strong></div></div></div></section>
        <div className="demo-strip"><div><span className="eyebrow">Demonstration controls</span><strong>Inject a known scenario into the live path.</strong></div><DemoControlBar onTrigger={runScenario} isSimulating={isSimulating} activeScenario={activeScenario} lastResult={lastResult} /></div>
        <section className="section-block compact-block" aria-labelledby="fabric-heading"><div className="section-title-row"><div><div className="eyebrow">Detection fabric</div><h2 id="fabric-heading">Six engines. One decision surface.</h2></div><div className="section-readout">Weak signals become correlated evidence</div></div><DetectorGrid activeDetectors={metrics?.active_detectors} /></section>
        <section className="section-block compact-block" aria-labelledby="threat-activity-heading"><div className="section-title-row"><div><div className="eyebrow">Threat activity</div><h2 id="threat-activity-heading">Where pressure is building.</h2></div><div className="section-readout"><span className="legend-dot critical" /> critical <span className="legend-dot high" /> high <span className="legend-dot medium" /> medium</div></div><IncidentHeatmap incidents={filteredIncidents} /></section>
        <section className="incident-workspace" id="incidents" aria-label="Incident feed and investigation"><div className="workspace-heading"><div><div className="eyebrow">Incident center</div><h2>What needs attention now.</h2></div><button className="text-action" onClick={() => setActiveView('incidents')}>Open full incident center <ArrowRight size={15} /></button></div><div className="workspace-grid"><ThreatFeed incidents={filteredIncidents} selectedIncidentId={selectedIncidentId} onSelectIncident={setSelectedIncidentId} severityFilter={severityFilter} onSelectSeverity={setSeverityFilter} threatClassFilter={threatClassFilter} onSelectThreatClass={setThreatClassFilter} searchQuery={searchQuery} onSearchChange={setSearchQuery} severityCounts={severityCounts} />{selectedIncident ? <InvestigationDrawer incident={selectedIncident} onClose={() => setSelectedIncidentId(null)} onToggleApproval={toggleHumanApproval} /> : <div className="empty-investigation"><CircleAlert size={22} /><strong>Choose an incident to investigate</strong><span>The selected threat will stay visible as it moves through review and response.</span></div>}</div></section>
      </div></div>
    </main>
    <StatusBar totalEvents={totalEvents} activeDetectorsCount={activeDetectorsCount} bufferUtilization={metrics?.buffer_utilization_pct ?? 0} pipelineLatency={metrics?.pipeline_latency_ms ?? 0} /><Toast incident={newIncidentAlert} onClose={clearAlert} onInvestigate={(id) => { setSelectedIncidentId(id); clearAlert(); }} />
  </div>;
};

export default App;
