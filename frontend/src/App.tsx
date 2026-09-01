import React from 'react';
import { Header } from './components/layout/Header';
import { DiodeBadge } from './components/layout/DiodeBadge';
import { StatusBar } from './components/layout/StatusBar';
import { DemoControlBar } from './components/simulation/DemoControlBar';
import { TelemetryMeter } from './components/telemetry/TelemetryMeter';
import { DetectorGrid } from './components/telemetry/DetectorGrid';
import { ThreatFeed } from './components/incidents/ThreatFeed';
import { InvestigationDrawer } from './components/investigation/InvestigationDrawer';
import { Toast } from './components/common/Toast';
import { useTelemetryStream } from './hooks/useTelemetryStream';
import { useIncidentStream } from './hooks/useIncidentStream';
import { useSimulation } from './hooks/useSimulation';

export const App: React.FC = () => {
  // Real-time telemetry stream
  const { metrics, history, connectionStatus, streamMode, reconnect } = useTelemetryStream();

  // Incidents stream & drawer management
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

  // Simulation execution triggers
  const { triggerSimulation, isSimulating, activeScenario, lastResult } = useSimulation({
    onIncidentGenerated: (inc) => {
      upsertIncident(inc);
      setSelectedIncidentId(inc.incident_id);
    },
    onSelectIncident: (id) => setSelectedIncidentId(id),
  });

  return (
    <div className="min-h-screen bg-[#04060B] text-slate-100 flex flex-col font-sans relative overflow-x-hidden selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background Cyber Ambient Glows */}
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-red-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* 1. Master Header with Live System Status */}
      <Header
        connectionStatus={connectionStatus}
        streamMode={streamMode}
        onReconnect={reconnect}
        eps={metrics.events_per_sec}
        mbps={metrics.mbps}
        totalEvents={metrics.total_events_processed}
      />

      {/* 2. Permanent Hardware Data Diode Safety Badge */}
      <DiodeBadge />

      {/* Main Command Center Body */}
      <main className="max-w-7xl mx-auto w-full px-4 py-4 space-y-4 flex-1">
        {/* 3. Live Presentation & Demo Scenario Control Bar */}
        <DemoControlBar
          onTrigger={triggerSimulation}
          isSimulating={isSimulating}
          activeScenario={activeScenario}
          lastResult={lastResult}
        />

        {/* 4. Live Line-Rate Telemetry Meter (EPS, Mbps, Loss, Latency Sparkline) */}
        <TelemetryMeter metrics={metrics} history={history} />

        {/* 5. 6-Engine Matrix Streaming Threat Detectors */}
        <DetectorGrid activeDetectors={metrics.active_detectors} />

        {/* 6. Primary Operations Grid: Live Threat Feed & Investigation Drawer */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Left Column: Live Threat Feed (5 cols on lg) */}
          <div className="lg:col-span-5 h-full">
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

          {/* Right Column: Deep Forensic Investigation Drawer & Countermeasure Center (7 cols on lg) */}
          <div className="lg:col-span-7 h-full">
            {selectedIncident ? (
              <InvestigationDrawer
                incident={selectedIncident}
                onClose={() => setSelectedIncidentId(null)}
                onToggleApproval={toggleHumanApproval}
              />
            ) : (
              <div className="bg-[#080D1A] border border-slate-800 rounded-lg p-12 text-center font-mono text-slate-500 flex flex-col items-center justify-center space-y-2">
                <span className="w-3 h-3 rounded-full bg-cyan-500 animate-ping mb-2" />
                <h4 className="font-bold text-slate-300 uppercase text-sm">NO INCIDENT SELECTED</h4>
                <p className="text-xs max-w-sm text-slate-400">
                  Select an incident card from the live threat feed to open forensic investigation tools, view attack timelines, and inspect generated countermeasures.
                </p>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* 7. Bottom Status Bar */}
      <StatusBar
        totalEvents={metrics.total_events_processed}
        activeDetectorsCount={6}
        bufferUtilization={metrics.buffer_utilization_pct}
        pipelineLatency={metrics.pipeline_latency_ms}
      />

      {/* 8. Toast Alerts for Incoming Threats */}
      <Toast
        incident={newIncidentAlert}
        onClose={clearAlert}
        onInvestigate={(id) => {
          setSelectedIncidentId(id);
          clearAlert();
        }}
      />
    </div>
  );
};

export default App;
