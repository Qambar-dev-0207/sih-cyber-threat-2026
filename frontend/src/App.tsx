import React from 'react';
import { Header } from './components/layout/Header';
import { DiodeBadge } from './components/layout/DiodeBadge';
import { StatusBar } from './components/layout/StatusBar';
import { DemoControlBar } from './components/simulation/DemoControlBar';
import { DetectorGrid } from './components/telemetry/DetectorGrid';
import { LiveAreaChart } from './components/telemetry/LiveAreaChart';
import { IncidentHeatmap } from './components/telemetry/IncidentHeatmap';
import { CompoundRiskEngine } from './components/telemetry/CompoundRiskEngine';
import { ThreatFeed } from './components/incidents/ThreatFeed';
import { InvestigationDrawer } from './components/investigation/InvestigationDrawer';
import { Toast } from './components/common/Toast';
import { useTelemetryStream } from './hooks/useTelemetryStream';
import { useIncidentStream } from './hooks/useIncidentStream';
import { useSimulation } from './hooks/useSimulation';

export const App: React.FC = () => {
  const { metrics, history, connectionStatus, streamMode, reconnect } = useTelemetryStream();

  const {
    filteredIncidents,
    selectedIncident,
    selectedIncidentId,
    setSelectedIncidentId,
    severityFilter,
    setSeverityFilter,
    threatClassFilter,
    setThreatClassFilter,
    searchQuery,
    setSearchQuery,
    severityCounts,
    upsertIncident,
    toggleHumanApproval,
    newIncidentAlert,
    clearAlert,
  } = useIncidentStream();

  const { triggerSimulation, isSimulating, activeScenario, lastResult } = useSimulation({
    onIncidentGenerated: (inc) => {
      upsertIncident(inc);
      setSelectedIncidentId(inc.incident_id);
    },
    onSelectIncident: (id) => setSelectedIncidentId(id),
  });

  const activeDetectorsCount = Object.values(metrics?.active_detectors ?? {}).filter(Boolean).length;

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--bg-0)', color: 'var(--text-primary)' }}>
      {/* Global grid overlay — SIH teal-tinted */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(to right, rgba(5,245,215,0.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(5,245,215,0.03) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
        }}
      />

      <Header
        connectionStatus={connectionStatus}
        streamMode={streamMode}
        onReconnect={reconnect}
        eps={metrics?.events_per_sec ?? 0}
        mbps={metrics?.mbps ?? 0}
        totalEvents={metrics?.total_events_processed ?? 0}
      />
      <DiodeBadge />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-4 space-y-3 relative z-10">

        {/* ── Row 1: Scenario Injection ── */}
        <DemoControlBar
          onTrigger={triggerSimulation}
          isSimulating={isSimulating}
          activeScenario={activeScenario}
          lastResult={lastResult}
        />

        {/* ── Row 2: Live Area Charts (EPS · Bandwidth · Latency · Buffer) ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <LiveAreaChart history={history} field="eps"        label="Events / Sec"      unit="EPS"  color="var(--accent)" />
          <LiveAreaChart history={history} field="mbps"       label="Line Bandwidth"    unit="Mbps" color="#60A5FA" />
          <LiveAreaChart history={history} field="latency_ms" label="Pipeline Latency"  unit="µs"   color="#A78BFA" />
          {/* 4th slot: compact buffer/loss tile */}
          <div className="card flex flex-col items-center justify-center py-5 font-mono text-center gap-1">
            <div className="text-3xl font-black tabular-nums" style={{ color: 'var(--accent)' }}>
              {(metrics?.buffer_utilization_pct ?? 0).toFixed(1)}<span className="text-lg">%</span>
            </div>
            <div className="text-[9px] tracking-widest" style={{ color: 'var(--text-dim)' }}>BUFFER UTIL</div>
            <div
              className="text-[10px] font-semibold mt-1"
              style={{ color: (metrics?.packet_loss_pct ?? 0) > 0.1 ? 'var(--critical)' : 'var(--low)' }}
            >
              LOSS {(metrics?.packet_loss_pct ?? 0).toFixed(3)}%
            </div>
          </div>
        </div>

        {/* ── Row 3: Compound Risk Engine (workflow visualization) ── */}
        <CompoundRiskEngine incident={selectedIncident} metrics={metrics} />

        {/* ── Row 4: Detector Matrix ── */}
        <DetectorGrid activeDetectors={metrics?.active_detectors} />

        {/* ── Row 5: Attack Intensity Heatmap ── */}
        <IncidentHeatmap incidents={filteredIncidents} />

        {/* ── Row 6: Threat Feed + Investigation Drawer ── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3" style={{ minHeight: 520 }}>
          <div className="lg:col-span-5 flex flex-col">
            <ThreatFeed
              incidents={filteredIncidents}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={(id) => setSelectedIncidentId(id)}
              severityFilter={severityFilter}
              onSelectSeverity={setSeverityFilter}
              threatClassFilter={threatClassFilter}
              onSelectThreatClass={setThreatClassFilter}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityCounts={severityCounts}
            />
          </div>
          <div className="lg:col-span-7 flex flex-col">
            {selectedIncident ? (
              <InvestigationDrawer
                incident={selectedIncident}
                onClose={() => setSelectedIncidentId(null)}
                onToggleApproval={toggleHumanApproval}
              />
            ) : (
              <div className="card flex-1 flex flex-col items-center justify-center py-16 text-center" style={{ minHeight: 200 }}>
                <div className="font-mono text-[11px] mb-1" style={{ color: 'var(--text-dim)' }}>SELECT AN INCIDENT</div>
                <div className="font-mono text-[10px]" style={{ color: 'var(--text-dim)' }}>
                  Click any threat card to open investigation · The Compound Risk Engine updates automatically
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      <StatusBar
        totalEvents={metrics?.total_events_processed ?? 0}
        activeDetectorsCount={activeDetectorsCount}
        bufferUtilization={metrics?.buffer_utilization_pct ?? 0}
        pipelineLatency={metrics?.pipeline_latency_ms ?? 0}
      />

      <Toast
        incident={newIncidentAlert}
        onClose={clearAlert}
        onInvestigate={(id) => { setSelectedIncidentId(id); clearAlert(); }}
      />
    </div>
  );
};

export default App;
