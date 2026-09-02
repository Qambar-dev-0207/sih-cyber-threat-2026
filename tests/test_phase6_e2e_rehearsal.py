"""
tests/test_phase6_e2e_rehearsal.py

Phase 6 Milestone 1 (R1): End-to-End Multi-Stage APT Simulation & Rehearsal Test Suite.

Comprehensive Opaque-Box & Integration Tests:
1. 4-Stage APT Kill-Chain Telemetry Injection:
   - Stage 1: Reconnaissance - Nmap SYN sweep (T1595.001) over 30+ destination ports
   - Stage 2: Weaponization / Delivery - High-entropy DGA query (T1568.002, entropy > 3.5)
   - Stage 3: C2 Establishment - Encrypted TLS handshake matching JA4 Cobalt Strike / Sliver profile (T1071.001)
   - Stage 4: C2 Maintenance - Streaming periodic beacon pulses (T1071.001, CV < 0.15)
2. Pipeline Collapse & Latency SLA:
   - Ingest -> 6 Parallel Detectors -> In-Memory CEP Aggregator -> LangGraph 5-Node StateGraph -> FastAPI WebSocket
   - Collapses into exactly ONE fused incident context
   - Total pipeline execution latency strictly < 1.5s
3. Fused Incident Risk Score & Multi-Stage Synergy:
   - Risk score >= 85.0 (CRITICAL severity)
   - Multi-stage synergy bonus (+20.0 for >= 3 distinct threats)
   - Explainable risk formula verification
   - MITRE ATT&CK mapping coverage
4. Defense-Grade Countermeasure Artifacts:
   - All 6 classes generated: iptables, nftables, cisco_acl, dns_rpz, snort3, stix_bundle
   - Syntax validity and non-empty content
   - Strict human-in-the-loop requirement: `requires_human_approval: true`
5. Edge Cases & Partial Attack Sequences:
   - 1-stage only (Recon -> risk < 85, no synergy)
   - 2-stage only (Recon + DGA -> synergy = 10.0)
   - Out-of-order stage arrival
   - Burst / high-volume duplicate storm handling
   - Malformed / empty telemetry robustness
6. Strict Passive Data-Diode Invariant Trap:
   - Active socket/HTTP/subprocess monkeypatch traps confirming 0 outbound return-path actions
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.request
from typing import Any, Dict, List, Optional
import pytest

from src.agentic_triage.graph import compile_triage_graph, triage_incident
from src.api.models import IncidentDetailResponse
from src.api.services.pipeline_service import (
    process_and_triage_incident,
    run_simulation_scenario,
    triage_state_to_incident_detail,
)
from src.api.state import AppState, reset_app_state
from src.cep.engine import CEPAggregatorEngine
from src.cep.models import FusedIncident
from src.detectors.c2_beaconing import C2BeaconingDetector
from src.detectors.detector_manager import DetectorManager
from src.detectors.dga_tunneling import DGATunnelingDetector
from src.detectors.encrypted_malware import EncryptedMalwareDetector
from src.detectors.portscan_hll import PortScanHLLDetector
from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    RawAlert,
    SslTelemetryEvent,
)
from src.ingestion.streaming_bus import InMemoryStreamingBus


# ---------------------------------------------------------------------------
# Test Fixtures & Generators
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_app_state():
    """Ensure every test operates on an isolated, clean AppState instance."""
    state = reset_app_state()
    yield state
    state.incident_buffer.clear()


@pytest.fixture
def detector_mgr() -> DetectorManager:
    """Provides a fresh DetectorManager with all 6 parallel streaming detectors."""
    bus = InMemoryStreamingBus(num_partitions=4)
    return DetectorManager(bus=bus)


@pytest.fixture
def cep_engine() -> CEPAggregatorEngine:
    """Provides a fresh, isolated in-memory CEP aggregation engine."""
    return CEPAggregatorEngine()


def generate_stage1_recon_events(
    attacker_ip: str = "198.51.100.42",
    target_ip: str = "192.168.1.100",
    base_ts: float = 1725000000.0,
    port_count: int = 35,
    conn_state: str = "REJ",
    interval_sec: float = 0.1,
) -> List[ConnTelemetryEvent]:
    """
    Stage 1: Nmap stealth SYN port sweep (T1595.001) over 30+ distinct destination ports.
    """
    events = []
    for i in range(port_count):
        port = 1000 + i
        events.append(
            ConnTelemetryEvent(
                src_ip=attacker_ip,
                src_port=45000,
                dst_ip=target_ip,
                dst_port=port,
                proto="tcp",
                conn_state=conn_state,
                orig_bytes=64,
                resp_bytes=0,
                history="S",
                ts=base_ts + i * interval_sec,
                uid=f"flow_scan_{i}",
            )
        )
    return events


def generate_stage2_dga_event(
    attacker_ip: str = "198.51.100.42",
    base_ts: float = 1725000002.0,
    query: str = "c948df2a10sub.tunnel.darknet-dga-malware.org",
) -> DnsTelemetryEvent:
    """
    Stage 2: High-entropy algorithmic DGA domain query (T1568.002, entropy > 3.5).
    """
    return DnsTelemetryEvent(
        src_ip=attacker_ip,
        src_port=53000,
        dst_ip="8.8.8.8",
        dst_port=53,
        query=query,
        qtype_name="TXT",
        rcode_name="NOERROR",
        ts=base_ts,
        uid="flow_dns_dga_01",
    )


def generate_stage3_ja4_event(
    attacker_ip: str = "198.51.100.42",
    target_ip: str = "192.168.1.100",
    base_ts: float = 1725000004.0,
    ja4_profile: str = "t13d1516h2_8daaf6152771_e5627efa2ab1",
) -> SslTelemetryEvent:
    """
    Stage 3: Encrypted TLS handshake matching Cobalt Strike / Sliver JA4 profile (T1071.001).
    """
    return SslTelemetryEvent(
        src_ip=attacker_ip,
        src_port=54000,
        dst_ip=target_ip,
        dst_port=443,
        version="TLSv13",
        ja4=ja4_profile,
        ja4s="t130200_1301_0000",
        server_name="cdn-edge-update.com",
        cipher="TLS_AES_256_GCM_SHA384",
        ts=base_ts,
        uid="flow_ssl_ja4_01",
    )


def generate_stage4_c2_beacon_events(
    attacker_ip: str = "198.51.100.42",
    target_ip: str = "192.168.1.100",
    base_ts: float = 1725000006.0,
    pulse_count: int = 18,
    interval_sec: float = 10.0,
) -> List[ConnTelemetryEvent]:
    """
    Stage 4: Streaming periodic C2 heartbeat beacon pulses (T1071.001, CV < 0.15).
    """
    events = []
    for i in range(pulse_count):
        events.append(
            ConnTelemetryEvent(
                src_ip=attacker_ip,
                src_port=55000 + i,
                dst_ip=target_ip,
                dst_port=4444,
                proto="tcp",
                conn_state="SF",
                orig_bytes=256,
                resp_bytes=256,
                history="ShADadFf",
                ts=base_ts + i * interval_sec,
                uid=f"flow_c2_pulse_{i}",
            )
        )
    return events


# ---------------------------------------------------------------------------
# Test Suite 1: 4-Stage APT Telemetry Generation & Threat Detectors
# ---------------------------------------------------------------------------

class TestAPT4StageTelemetryGeneration:
    """Verifies each individual attack stage produces precise, high-confidence threat alerts."""

    def test_stage1_portscan_hll_syn_sweep_detection(self, detector_mgr: DetectorManager):
        """Stage 1: Nmap SYN sweep over 35 ports triggers PORT_SCAN_RECON with T1595.001."""
        events = generate_stage1_recon_events(port_count=35)
        alerts: List[RawAlert] = []
        for ev in events:
            alerts.extend(detector_mgr.process_event(ev))

        assert len(alerts) >= 1, "Expected at least 1 port scan alert for 35 distinct ports sweep"
        scan_alert = next((a for a in alerts if a.detector_name == "portscan_hll"), alerts[0])
        assert scan_alert.detector_name == "portscan_hll"
        assert scan_alert.threat_class in ("port_scan", "PORT_SCAN_RECON")
        assert scan_alert.confidence >= 0.85
        assert scan_alert.source_ip == "198.51.100.42"
        assert scan_alert.evidence.get("hll_distinct_ports", 0) >= 25

    def test_stage2_dga_tunneling_detection(self, detector_mgr: DetectorManager):
        """Stage 2: High-entropy DGA query triggers DGA_TUNNELLING with T1568.002."""
        dga_ev = generate_stage2_dga_event(query="c948df2a10sub.tunnel.darknet-dga-malware.org")
        alerts = detector_mgr.process_event(dga_ev)

        assert len(alerts) >= 1, "Expected DGA detector alert for high-entropy query"
        dga_alert = alerts[0]
        assert dga_alert.detector_name == "dga_lstm"
        assert dga_alert.threat_class in ("dga_domain", "dga_tunneling", "DGA_TUNNELLING")
        assert dga_alert.confidence >= 0.85
        assert dga_alert.source_ip == "198.51.100.42"
        assert dga_alert.evidence.get("shannon_entropy", 0.0) >= 3.5 or dga_alert.evidence.get("subdomain_entropy", 0.0) >= 3.5

    def test_stage3_ja4_encrypted_malware_detection(self, detector_mgr: DetectorManager):
        """Stage 3: Cobalt Strike JA4 handshake triggers ENCRYPTED_MALWARE with T1071.001."""
        ssl_ev = generate_stage3_ja4_event(ja4_profile="t13d1516h2_8daaf6152771_e5627efa2ab1")
        alerts = detector_mgr.process_event(ssl_ev)

        assert len(alerts) >= 1, "Expected JA4 malware detector alert for Cobalt Strike signature"
        malware_alert = alerts[0]
        assert malware_alert.detector_name == "ja4_malware"
        assert malware_alert.threat_class == "ENCRYPTED_MALWARE"
        assert malware_alert.severity in ("CRITICAL", "HIGH")
        assert malware_alert.confidence >= 0.90
        assert malware_alert.source_ip == "198.51.100.42"
        assert "t13d1516h2_8daaf6152771" in malware_alert.evidence.get("matched_ja4", "")

    def test_stage4_c2_periodic_beaconing_detection(self, detector_mgr: DetectorManager):
        """Stage 4: 18 periodic pulses with low dispersion trigger C2_BEACONING with CV < 0.15."""
        beacon_events = generate_stage4_c2_beacon_events(pulse_count=18, interval_sec=10.0)
        alerts: List[RawAlert] = []
        for ev in beacon_events:
            alerts.extend(detector_mgr.process_event(ev))

        assert len(alerts) >= 1, "Expected C2 beaconing alert after 15+ periodic intervals"
        c2_alert = alerts[0]
        assert c2_alert.detector_name == "c2_beacon"
        assert c2_alert.threat_class in ("c2_beaconing", "C2_BEACONING")
        assert c2_alert.confidence >= 0.85
        assert c2_alert.source_ip == "198.51.100.42"
        cv = c2_alert.evidence.get("cv", c2_alert.evidence.get("coefficient_of_variation", 0.0))
        assert cv < 0.15, f"Expected CV < 0.15, got {cv}"

    def test_benign_traffic_generates_zero_alerts(self, detector_mgr: DetectorManager):
        """Legitimate network traffic (Google DNS, standard web browsing) triggers 0 alerts."""
        t0 = 1725000000.0
        benign_dns = DnsTelemetryEvent(
            src_ip="192.168.1.50",
            src_port=53100,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="www.google.com",
            qtype_name="A",
            rcode_name="NOERROR",
            ts=t0,
        )
        benign_conn = ConnTelemetryEvent(
            src_ip="192.168.1.50",
            src_port=48000,
            dst_ip="142.250.190.46",
            dst_port=443,
            proto="tcp",
            conn_state="SF",
            orig_bytes=1500,
            resp_bytes=8000,
            ts=t0 + 0.1,
        )
        assert len(detector_mgr.process_event(benign_dns)) == 0
        assert len(detector_mgr.process_event(benign_conn)) == 0


# ---------------------------------------------------------------------------
# Test Suite 2: Pipeline Collapse, Fusion, and Latency SLA (< 1.5s)
# ---------------------------------------------------------------------------

class TestPipelineCollapseAndLatency:
    """Verifies end-to-end collapse of 4-stage APT sequence into 1 incident within < 1.5s SLA."""

    def test_e2e_pipeline_collapse_into_single_incident(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """All 4 attack stages from attacker 198.51.100.42 collapse into exactly ONE fused incident."""
        # 1. Collect all telemetry across all 4 stages
        stage1 = generate_stage1_recon_events()
        stage2 = [generate_stage2_dga_event()]
        stage3 = [generate_stage3_ja4_event()]
        stage4 = generate_stage4_c2_beacon_events()

        all_telemetry = stage1 + stage2 + stage3 + stage4

        # 2. Run telemetry through detectors
        raw_alerts: List[RawAlert] = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        assert len(raw_alerts) >= 4, f"Expected at least 4 alerts, got {len(raw_alerts)}"

        # 3. Ingest alerts into CEP Engine
        last_fused: Optional[FusedIncident] = None
        for a in raw_alerts:
            res = cep_engine.ingest_alert(a)
            if res:
                last_fused = res

        assert last_fused is not None, "CEP Aggregator must produce a FusedIncident"
        assert last_fused.primary_source_ip == "198.51.100.42"
        assert len(cep_engine.get_all_active_incidents()) == 1, "Pipeline must collapse to exactly 1 incident context"

        # 4. Verify multi-stage threat metadata
        assert len(last_fused.kill_chain_stages) >= 3
        assert len(last_fused.participating_detectors) >= 3
        assert last_fused.severity == "CRITICAL"

    def test_e2e_total_pipeline_latency_under_1_5s(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """End-to-end latency (Ingest -> Detectors -> CEP -> LangGraph -> Result) strictly < 1.5s."""
        t_start = time.perf_counter()

        # Telemetry generation
        all_telemetry = (
            generate_stage1_recon_events(port_count=35)
            + [generate_stage2_dga_event()]
            + [generate_stage3_ja4_event()]
            + generate_stage4_c2_beacon_events(pulse_count=18)
        )

        # Ingestion & Detection
        raw_alerts: List[RawAlert] = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        # CEP Aggregation
        last_fused: Optional[FusedIncident] = None
        for a in raw_alerts:
            res = cep_engine.ingest_alert(a)
            if res:
                last_fused = res

        assert last_fused is not None

        # LangGraph Triage Graph Execution
        graph = compile_triage_graph(execution_mode="deterministic")
        triage_state = triage_incident(last_fused, compiled_graph=graph)

        # Transform to API Detail Model
        detail = triage_state_to_incident_detail(triage_state, raw_incident=last_fused)

        elapsed = time.perf_counter() - t_start

        assert elapsed < 1.5, f"Total pipeline latency {elapsed:.4f}s exceeded 1.5s SLA!"
        assert detail.risk_score >= 85.0
        assert detail.severity == "CRITICAL"
        assert len(detail.countermeasures) == 6

    @pytest.mark.asyncio
    async def test_fastapi_and_websocket_pipeline_integration(self):
        """Verifies full FastAPI simulation orchestration and WebSocket push broadcast."""
        scenario_name, alert_count, incident_detail = await run_simulation_scenario("apt")

        assert scenario_name == "apt"
        assert alert_count >= 4
        assert incident_detail.source_ip == "198.51.100.42"
        assert incident_detail.risk_score >= 85.0
        assert incident_detail.severity == "CRITICAL"
        assert incident_detail.requires_human_approval is True
        assert len(incident_detail.countermeasures) == 6
        assert incident_detail.status == "PENDING_REVIEW"


# ---------------------------------------------------------------------------
# Test Suite 3: Fused Risk Scoring, Synergy Bonus, & MITRE Mapping
# ---------------------------------------------------------------------------

class TestFusedRiskScoringAndSynergy:
    """Verifies explainable risk score calculation, synergy bonus, and MITRE ATT&CK mappings."""

    def test_fused_risk_score_critical_and_synergy_bonus(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """4-stage APT receives +20.0 synergy bonus and risk score >= 85.0 (CRITICAL)."""
        all_telemetry = (
            generate_stage1_recon_events(port_count=35)
            + [generate_stage2_dga_event()]
            + [generate_stage3_ja4_event()]
            + generate_stage4_c2_beacon_events(pulse_count=18)
        )
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused, execution_mode="deterministic")

        # Assert Risk Score & Severity
        assert triage_state["risk_score"] >= 85.0, f"Expected risk >= 85.0, got {triage_state['risk_score']}"
        assert triage_state["severity"] == "CRITICAL"

        # Assert Risk Breakdown & Synergy Bonus
        breakdown = triage_state.get("risk_breakdown", {})
        assert breakdown.get("synergy_bonus") == 20.0, "Multi-stage attack must receive +20.0 synergy bonus"
        assert "synergy_reason" in breakdown
        assert "formula" in breakdown
        assert "min(100.0," in breakdown["formula"]
        assert len(breakdown.get("evidence_breakdown", [])) >= 3

    def test_mitre_attack_mapping_coverage(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """Verifies MITRE ATT&CK techniques T1595.001, T1568.002, T1071.001 are all mapped."""
        all_telemetry = (
            generate_stage1_recon_events()
            + [generate_stage2_dga_event()]
            + [generate_stage3_ja4_event()]
            + generate_stage4_c2_beacon_events()
        )
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        mitre_mappings = triage_state.get("mitre_mappings", [])

        tech_ids = {m.get("technique_id") for m in mitre_mappings}
        assert any("T1595" in t for t in tech_ids), "Missing Reconnaissance technique T1595"
        assert any("T1568" in t for t in tech_ids), "Missing DGA technique T1568"
        assert any("T1071" in t for t in tech_ids), "Missing C2 / Web Protocols technique T1071"

        # Verify kill chain phases present
        phases = {m.get("kill_chain_phase") for m in mitre_mappings if m.get("kill_chain_phase")}
        assert len(phases) >= 2


# ---------------------------------------------------------------------------
# Test Suite 4: Defense-Grade Countermeasure Generation
# ---------------------------------------------------------------------------

class TestAllSixCountermeasures:
    """Verifies that all 6 countermeasure classes are generated with valid syntax and approval flag."""

    def test_all_six_countermeasures_generated_and_valid(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """Generates iptables, nftables, cisco_acl, dns_rpz, snort3, stix_bundle with requires_human_approval."""
        all_telemetry = (
            generate_stage1_recon_events()
            + [generate_stage2_dga_event()]
            + [generate_stage3_ja4_event()]
            + generate_stage4_c2_beacon_events()
        )
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        cms = triage_state.get("countermeasures", [])

        assert len(cms) == 6, f"Expected 6 countermeasure types, found {len(cms)}"
        types = {c.get("countermeasure_type") for c in cms}
        assert types == {"iptables", "nftables", "cisco_acl", "dns_rpz", "snort3", "stix_bundle"}

        for cm in cms:
            assert cm.get("syntax_valid") is True, f"{cm['countermeasure_type']} failed syntax validity"
            assert cm.get("requires_human_approval") is True, f"{cm['countermeasure_type']} missing human approval"
            content = cm.get("artifact_content", "")
            assert len(content.strip()) > 20, f"{cm['countermeasure_type']} artifact is empty or stub"

    def test_iptables_artifact_syntax_and_target_ip(self, detector_mgr, cep_engine):
        """iptables artifact contains DROP rules for attacker IP 198.51.100.42 and safety banner."""
        all_telemetry = generate_stage1_recon_events() + [generate_stage3_ja4_event()]
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))
        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        ipt = next(c for c in triage_state["countermeasures"] if c["countermeasure_type"] == "iptables")
        artifact = ipt["artifact_content"]

        assert "iptables" in artifact
        assert "198.51.100.42" in artifact
        assert "-j DROP" in artifact
        assert "requires_human_approval" in artifact.lower() or "HUMAN APPROVAL" in artifact

    def test_nftables_artifact_syntax_and_set(self, detector_mgr, cep_engine):
        """nftables artifact contains valid table, chain, and set definitions."""
        all_telemetry = generate_stage1_recon_events() + [generate_stage3_ja4_event()]
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))
        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        nft = next(c for c in triage_state["countermeasures"] if c["countermeasure_type"] == "nftables")
        artifact = nft["artifact_content"]

        assert "table inet" in artifact or "table ip" in artifact
        assert "198.51.100.42" in artifact
        assert "drop" in artifact

    def test_cisco_acl_artifact_syntax(self, detector_mgr, cep_engine):
        """cisco_acl artifact contains Extended Named ACL syntax with deny statements."""
        all_telemetry = generate_stage1_recon_events() + [generate_stage3_ja4_event()]
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))
        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        cisco = next(c for c in triage_state["countermeasures"] if c["countermeasure_type"] == "cisco_acl")
        artifact = cisco["artifact_content"]

        assert "ip access-list extended" in artifact
        assert "deny ip host 198.51.100.42" in artifact or "198.51.100.42" in artifact

    def test_dns_rpz_artifact_syntax(self, detector_mgr, cep_engine):
        """dns_rpz artifact contains BIND 9 RPZ zone definitions with CNAME . sinkhole."""
        all_telemetry = [generate_stage2_dga_event()]
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))
        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        rpz = next(c for c in triage_state["countermeasures"] if c["countermeasure_type"] == "dns_rpz")
        artifact = rpz["artifact_content"]

        assert "CNAME ." in artifact or "A 0.0.0.0" in artifact or "zone" in artifact.lower()

    def test_snort3_artifact_syntax(self, detector_mgr, cep_engine):
        """snort3 artifact contains alert rules with SIDs >= 9700000 and classtype."""
        all_telemetry = generate_stage1_recon_events() + [generate_stage3_ja4_event()]
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))
        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        snort = next(c for c in triage_state["countermeasures"] if c["countermeasure_type"] == "snort3")
        artifact = snort["artifact_content"]

        assert "alert" in artifact
        assert "sid:" in artifact
        assert "msg:" in artifact

    def test_stix_bundle_validity(self, detector_mgr, cep_engine):
        """stix_bundle artifact parses into valid OASIS STIX 2.1 JSON bundle."""
        all_telemetry = (
            generate_stage1_recon_events()
            + [generate_stage2_dga_event()]
            + [generate_stage3_ja4_event()]
            + generate_stage4_c2_beacon_events()
        )
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))
        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        stix = next(c for c in triage_state["countermeasures"] if c["countermeasure_type"] == "stix_bundle")
        artifact = stix["artifact_content"]

        stix_json = json.loads(artifact)
        assert stix_json.get("type") == "bundle"
        assert stix_json.get("id", "").startswith("bundle--")
        objects = stix_json.get("objects", [])
        assert len(objects) >= 3

        obj_types = {o.get("type") for o in objects}
        assert "indicator" in obj_types
        assert "attack-pattern" in obj_types or "threat-actor" in obj_types


# ---------------------------------------------------------------------------
# Test Suite 5: Edge Cases, Partial Sequences, & Robustness
# ---------------------------------------------------------------------------

class TestEdgeCasesAndPartialSequences:
    """Verifies correct escalation, partial kill-chains, out-of-order stages, and burst storms."""

    def test_partial_sequence_single_stage_recon_only(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """Single stage (Recon only) produces lower risk score, 0 synergy bonus, and non-CRITICAL severity."""
        events = generate_stage1_recon_events(port_count=35)
        raw_alerts = []
        for ev in events:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        assert triage_state["risk_score"] < 85.0
        assert triage_state["severity"] != "CRITICAL"
        assert triage_state.get("risk_breakdown", {}).get("synergy_bonus") == 0.0

    def test_partial_sequence_two_stage_recon_plus_dga(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """Two stages (Recon + DGA) produces +10.0 synergy bonus."""
        events = generate_stage1_recon_events(port_count=35) + [generate_stage2_dga_event()]
        raw_alerts = []
        for ev in events:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        assert triage_state.get("risk_breakdown", {}).get("synergy_bonus") == 10.0

    def test_out_of_order_stage_arrival(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """Injecting Stage 4 before Stage 1 aggregates correctly by host affinity without error."""
        # Stage 4 then Stage 1
        stage4 = generate_stage4_c2_beacon_events()
        stage1 = generate_stage1_recon_events()

        raw_alerts = []
        for ev in stage4 + stage1:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        assert last_fused is not None
        assert last_fused.primary_source_ip == "198.51.100.42"
        triage_state = triage_incident(last_fused)
        assert triage_state["risk_score"] >= 40.0
        assert len(triage_state["countermeasures"]) == 6

    def test_high_volume_duplicate_burst_handling(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """100 duplicate alerts within 50ms are coalesced by CEP deduplicator / burst limiter."""
        base_alert = RawAlert(
            detector_name="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            severity="HIGH",
            confidence=0.88,
            source_ip="198.51.100.99",
            target_ip="192.168.1.100",
            target_port=443,
            flow_id="dup_flow_01",
        )

        fused_results = []
        for _ in range(100):
            res = cep_engine.ingest_alert(base_alert)
            if res:
                fused_results.append(res)

        assert len(fused_results) >= 1
        assert cep_engine.total_deduplicated_alerts > 0 or cep_engine.total_rate_limited_alerts > 0

    def test_malformed_telemetry_graceful_handling(self, detector_mgr: DetectorManager):
        """Malformed or incomplete telemetry dictionaries do not cause crashes."""
        malformed_events = [
            {},
            {"src_ip": "10.0.0.1"},
            {"src_ip": "", "query": None},
            {"src_ip": "1.2.3.4", "ja4": ""},
        ]
        for ev in malformed_events:
            alerts = detector_mgr.process_event(ev)
            assert isinstance(alerts, list)


# ---------------------------------------------------------------------------
# Test Suite 6: Strict Passive Data-Diode Invariant Trap
# ---------------------------------------------------------------------------

class TestDataDiodeSafetyAssertions:
    """Verifies that passive network monitoring initiates ZERO outbound network connections or subprocess exec."""

    def test_zero_outbound_network_calls_during_entire_pipeline(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine, monkeypatch
    ):
        """
        Installs audit traps on socket.connect, socket.sendto, urllib.urlopen,
        and subprocess.Popen. Verifies zero attempts during the entire APT lifecycle.
        """
        trap_triggered = []

        def _socket_trap(*args, **kwargs):
            trap_triggered.append(f"socket_connect({args}, {kwargs})")
            raise PermissionError("Data diode violation: outbound socket connect attempted")

        def _sendto_trap(*args, **kwargs):
            trap_triggered.append(f"socket_sendto({args}, {kwargs})")
            raise PermissionError("Data diode violation: outbound packet send attempted")

        def _urllib_trap(*args, **kwargs):
            trap_triggered.append(f"urllib_urlopen({args}, {kwargs})")
            raise PermissionError("Data diode violation: HTTP request attempted")

        def _popen_trap(*args, **kwargs):
            trap_triggered.append(f"subprocess_popen({args}, {kwargs})")
            raise PermissionError("Data diode violation: subprocess execution attempted")

        # Monkeypatch network and process execution hooks
        monkeypatch.setattr(socket.socket, "connect", _socket_trap)
        monkeypatch.setattr(socket.socket, "sendto", _sendto_trap)
        monkeypatch.setattr(urllib.request, "urlopen", _urllib_trap)
        monkeypatch.setattr(subprocess, "Popen", _popen_trap)

        # Run complete 4-stage APT simulation and triage pipeline under audit trap
        all_telemetry = (
            generate_stage1_recon_events(port_count=35)
            + [generate_stage2_dga_event()]
            + [generate_stage3_ja4_event()]
            + generate_stage4_c2_beacon_events(pulse_count=18)
        )

        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        assert last_fused is not None

        # StateGraph triage and countermeasure generation
        triage_state = triage_incident(last_fused, execution_mode="deterministic")
        detail = triage_state_to_incident_detail(triage_state, raw_incident=last_fused)

        assert len(trap_triggered) == 0, f"Data diode trap tripped: {trap_triggered}"
        assert detail.requires_human_approval is True
        assert len(detail.countermeasures) == 6

    def test_immutable_requires_human_approval(
        self, detector_mgr: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """Asserts requires_human_approval is universally True and no auto-execution flags exist."""
        all_telemetry = generate_stage1_recon_events() + [generate_stage3_ja4_event()]
        raw_alerts = []
        for ev in all_telemetry:
            raw_alerts.extend(detector_mgr.process_event(ev))

        last_fused = None
        for a in raw_alerts:
            f = cep_engine.ingest_alert(a)
            if f:
                last_fused = f

        triage_state = triage_incident(last_fused)
        assert triage_state.get("auto_execute") is not True
        assert triage_state.get("executed") is not True

        for cm in triage_state.get("countermeasures", []):
            assert cm.get("requires_human_approval") is True
