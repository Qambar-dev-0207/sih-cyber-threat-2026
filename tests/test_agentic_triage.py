from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List
import pytest

from src.agentic_triage import (
    ClassificationNode,
    CorrelationNode,
    CountermeasureNode,
    HandoffNode,
    MitreMapping,
    RiskBreakdown,
    RiskEvidenceItem,
    RiskScoringNode,
    TimelineStep,
    TriageStateDict,
    build_triage_graph,
    compile_triage_graph,
    get_mitre_entry,
    lookup_mitre_techniques,
    render_executive_narrative,
    triage_incident,
)
from src.cep import (
    DeduplicationRecord,
    FusedIncident,
    HostSlidingWindow,
    SubnetSlidingWindow,
)
from src.ingestion.models import RawAlert


# ---------------------------------------------------------------------------
# 1. CEP OBJECT IDENTITY REFINEMENT TESTS
# ---------------------------------------------------------------------------


def test_sliding_window_recurring_flow_distinct_instances_preserved():
    """Verify that multi-window distinct DeduplicationRecord instances across time

    for the same flow signature are preserved without premature eviction or dropping.
    """
    hw = HostSlidingWindow("192.168.1.50", window_duration_sec=60.0)

    # Burst 1 at t=0.0 (5 alerts)
    rec1 = DeduplicationRecord(
        fingerprint="fp_scan_1",
        source_ip="192.168.1.50",
        detector_name="portscan_hll",
        threat_class="PORT_SCAN_RECON",
        first_seen=0.0,
        last_seen=0.4,
        occurrence_count=5,
    )
    hw.add_record(rec1, current_time=0.4)

    # In-place coalesce simulation at t=2.0 (same object id(rec1))
    rec1.occurrence_count = 8
    rec1.last_seen = 2.0
    hw.add_record(rec1, current_time=2.0)
    assert len(hw.get_records()) == 1
    assert hw.get_total_raw_alerts() == 8

    # Burst 2 at t=15.0 (new DeduplicationRecord object)
    rec2 = DeduplicationRecord(
        fingerprint="fp_scan_1",  # Same signature hash
        source_ip="192.168.1.50",
        detector_name="portscan_hll",
        threat_class="PORT_SCAN_RECON",
        first_seen=15.0,
        last_seen=15.4,
        occurrence_count=5,
    )
    hw.add_record(rec2, current_time=15.4)

    # Burst 3 at t=30.0 (new DeduplicationRecord object)
    rec3 = DeduplicationRecord(
        fingerprint="fp_scan_1",
        source_ip="192.168.1.50",
        detector_name="portscan_hll",
        threat_class="PORT_SCAN_RECON",
        first_seen=30.0,
        last_seen=30.4,
        occurrence_count=5,
    )
    hw.add_record(rec3, current_time=30.4)

    # Verify all 3 distinct records are retained
    records_at_30 = hw.get_records()
    assert len(records_at_30) == 3
    assert hw.get_total_raw_alerts() == 18  # 8 + 5 + 5

    # At t=65.0, rec1 expires (last_seen=2.0 < 5.0), rec2 and rec3 must survive!
    hw.evict_expired(65.0)
    records_at_65 = hw.get_records()
    assert len(records_at_65) == 2
    assert hw.get_total_raw_alerts() == 10
    assert not hw.is_empty()


def test_subnet_sliding_window_multi_burst_aggregation():
    """Verify SubnetSlidingWindow correctly retains and aggregates recurring bursts."""
    subnet_win = SubnetSlidingWindow("192.168.1.0/24", window_duration_sec=60.0)

    rec1 = DeduplicationRecord(
        fingerprint="fp1",
        source_ip="192.168.1.10",
        detector_name="c2_beaconing",
        threat_class="C2_BEACONING",
        first_seen=0.0,
        last_seen=0.0,
        occurrence_count=3,
    )
    subnet_win.update_host_activity("192.168.1.10", rec1, current_time=0.0)

    rec2 = DeduplicationRecord(
        fingerprint="fp1",
        source_ip="192.168.1.10",
        detector_name="c2_beaconing",
        threat_class="C2_BEACONING",
        first_seen=20.0,
        last_seen=20.0,
        occurrence_count=3,
    )
    subnet_win.update_host_activity("192.168.1.10", rec2, current_time=20.0)

    agg = subnet_win.get_aggregation()
    assert agg.total_alerts == 6
    assert agg.active_hosts == ["192.168.1.10"]


# ---------------------------------------------------------------------------
# 2. MITRE CATALOG & KNOWLEDGE BASE TESTS
# ---------------------------------------------------------------------------


def test_mitre_catalog_mappings():
    """Verify all 6 canonical threat classes map to accurate MITRE ATT&CK techniques."""
    test_cases = [
        ("PORT_SCAN_RECON", "T1595.001", "TA0043", "Reconnaissance"),
        ("DGA_TUNNELLING", "T1568.002", "TA0011", "Command and Control"),
        ("ENCRYPTED_MALWARE", "T1071.001", "TA0011", "Command and Control"),
        ("C2_BEACONING", "T1071.001", "TA0011", "Command and Control"),
        ("DATA_EXFILTRATION", "T1048.002", "TA0010", "Exfiltration"),
        ("VOLUMETRIC_DDOS", "T1498.001", "TA0040", "Impact"),
    ]
    for threat_cls, exp_tech, exp_tactic_id, exp_tactic_name in test_cases:
        entry = get_mitre_entry(threat_cls)
        assert entry is not None
        assert entry.technique_id == exp_tech
        assert entry.tactic_id == exp_tactic_id
        assert entry.tactic_name == exp_tactic_name

    # Test multi-lookup deduplication
    techniques = lookup_mitre_techniques(["PORT_SCAN_RECON", "portscan_hll", "DGA_TUNNELLING"])
    tech_ids = [t.technique_id for t in techniques]
    assert tech_ids == ["T1595.001", "T1568.002"]


# ---------------------------------------------------------------------------
# 3. CORRELATION NODE TESTS
# ---------------------------------------------------------------------------


def test_correlation_node_timeline_synthesis():
    """Verify CorrelationNode sorts alerts chronologically, assigns relative time offsets, and enriches host metrics."""
    node = CorrelationNode()

    alerts = [
        {
            "alert_id": "a3",
            "timestamp": 1050.0,
            "threat_class": "DATA_EXFILTRATION",
            "detector_name": "exfil_ratio",
            "confidence": 0.92,
            "target_ip": "93.184.216.34",
            "target_port": 443,
            "evidence": {"out_in_ratio": 15.2, "bytes_out": 50000000},
        },
        {
            "alert_id": "a1",
            "timestamp": 1000.0,
            "threat_class": "PORT_SCAN_RECON",
            "detector_name": "portscan_hll",
            "confidence": 0.85,
            "target_ip": "10.0.0.1",
            "target_port": 80,
            "evidence": {"ports_probed": 50},
        },
        {
            "alert_id": "a2",
            "timestamp": 1020.0,
            "threat_class": "ENCRYPTED_MALWARE",
            "detector_name": "encrypted_malware",
            "confidence": 0.95,
            "target_ip": "93.184.216.34",
            "target_port": 443,
            "evidence": {"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "threat_actor": "Cobalt Strike"},
        },
    ]

    initial_state: TriageStateDict = {
        "incident_id": "INC-TEST-001",
        "source_ip": "192.168.1.50",
        "fused_alerts": alerts,
    }

    result = node.execute(initial_state)

    timeline = result["timeline"]
    assert len(timeline) == 3
    # Step 1 should be a1 at t=1000.0 (offset 0.0s)
    assert timeline[0]["alert_id"] == "a1"
    assert timeline[0]["relative_time_offset_sec"] == 0.0
    assert timeline[0]["stage"] == "RECONNAISSANCE"
    # Step 2 should be a2 at t=1020.0 (offset 20.0s)
    assert timeline[1]["alert_id"] == "a2"
    assert timeline[1]["relative_time_offset_sec"] == 20.0
    # Step 3 should be a3 at t=1050.0 (offset 50.0s)
    assert timeline[2]["alert_id"] == "a3"
    assert timeline[2]["relative_time_offset_sec"] == 50.0

    assert result["is_multi_stage"] is True
    assert result["target_ips"] == ["10.0.0.1", "93.184.216.34"]
    assert result["target_ports"] == [80, 443]
    # Default role for .50 is DATABASE_SERVER => alpha = 1.5
    assert result["asset_role"] == "DATABASE_SERVER"
    assert result["asset_criticality"] == 1.5


# ---------------------------------------------------------------------------
# 4. RISK SCORING NODE TESTS (MATHEMATICAL TRANSPARENCY)
# ---------------------------------------------------------------------------


def test_risk_scoring_single_detector():
    """Verify single detector risk scoring: Base Weight * Confidence with 0 synergy bonus."""
    node = RiskScoringNode()

    # Single Port Scan alert: w = 15.0, conf = 0.80, alpha = 1.0
    # Base sum = 15.0 * 0.8 = 12.0
    # Synergy = 0.0
    # Final = 12.0 (LOW)
    state: TriageStateDict = {
        "timeline": [
            {
                "threat_class": "PORT_SCAN_RECON",
                "detector": "portscan_hll",
                "confidence": 0.80,
                "summary": "Port scan 20 ports",
            }
        ],
        "asset_criticality": 1.0,
    }

    result = node.execute(state)
    assert result["risk_score"] == 12.0
    assert result["severity"] == "LOW"
    assert result["risk_breakdown"]["base_risk_sum"] == 12.0
    assert result["risk_breakdown"]["synergy_bonus"] == 0.0


def test_risk_scoring_multi_detector_synergy_and_alpha():
    """Verify 3-detector multi-stage attack: Base Sum + 20.0 Synergy Bonus scaled by Alpha = 1.25."""
    node = RiskScoringNode()

    # 1. C2_BEACONING: w = 40.0, conf = 0.90 => 36.0
    # 2. ENCRYPTED_MALWARE: w = 40.0, conf = 0.95 => 38.0
    # 3. DATA_EXFILTRATION: w = 35.0, conf = 0.90 => 31.5
    # Base Risk Sum = 36.0 + 38.0 + 31.5 = 105.5
    # Synergy Bonus (k=3) = +20.0 => 125.5
    # Scaled by alpha = 1.25 => 156.875
    # Clamped to 100.0 => 100.0 (CRITICAL)
    state: TriageStateDict = {
        "timeline": [
            {"threat_class": "C2_BEACONING", "detector": "c2_beaconing", "confidence": 0.90},
            {"threat_class": "ENCRYPTED_MALWARE", "detector": "encrypted_malware", "confidence": 0.95},
            {"threat_class": "DATA_EXFILTRATION", "detector": "exfil_ratio", "confidence": 0.90},
        ],
        "asset_criticality": 1.25,
    }

    result = node.execute(state)
    assert result["risk_score"] == 100.0
    assert result["severity"] == "CRITICAL"
    assert result["risk_breakdown"]["base_risk_sum"] == 105.5
    assert result["risk_breakdown"]["synergy_bonus"] == 20.0
    assert result["risk_breakdown"]["asset_criticality_multiplier"] == 1.25


def test_risk_scoring_two_detectors():
    """Verify 2-detector synergy bonus (+10.0) with intermediate score."""
    node = RiskScoringNode()

    # 1. DGA_TUNNELLING: w = 30.0, conf = 0.80 => 24.0
    # 2. ENCRYPTED_MALWARE: w = 40.0, conf = 0.85 => 34.0
    # Base Risk Sum = 58.0
    # Synergy Bonus (k=2) = +10.0 => 68.0
    # Alpha = 1.0 => 68.0 (HIGH)
    state: TriageStateDict = {
        "timeline": [
            {"threat_class": "DGA_TUNNELLING", "detector": "dga_tunneling", "confidence": 0.80},
            {"threat_class": "ENCRYPTED_MALWARE", "detector": "encrypted_malware", "confidence": 0.85},
        ],
        "asset_criticality": 1.0,
    }

    result = node.execute(state)
    assert result["risk_score"] == 68.0
    assert result["severity"] == "HIGH"
    assert result["risk_breakdown"]["synergy_bonus"] == 10.0


# ---------------------------------------------------------------------------
# 5. CLASSIFICATION & ATTACK NARRATIVE NODE TESTS
# ---------------------------------------------------------------------------


def test_classification_and_narrative_generation():
    """Verify ClassificationNode assigns multi-stage APT intent and renders military/SOC narrative."""
    node = ClassificationNode()

    state: TriageStateDict = {
        "incident_id": "INC-20260831-ABCD",
        "source_ip": "192.168.1.50",
        "asset_role": "INTERNAL_WORKSTATION",
        "asset_criticality": 1.25,
        "target_ips": ["93.184.216.34"],
        "target_ports": [443],
        "threat_classes_observed": ["PORT_SCAN_RECON", "ENCRYPTED_MALWARE", "DATA_EXFILTRATION"],
        "risk_score": 96.25,
        "severity": "CRITICAL",
        "risk_breakdown": {
            "base_risk_sum": 67.0,
            "synergy_bonus": 10.0,
        },
        "timeline": [
            {
                "relative_time_offset_sec": 0.0,
                "stage": "RECONNAISSANCE",
                "detector": "portscan_hll",
                "summary": "Port scan detected probing 50 ports.",
                "technique_id": "T1595.001",
            },
            {
                "relative_time_offset_sec": 25.0,
                "stage": "COMMAND_AND_CONTROL",
                "detector": "encrypted_malware",
                "summary": "Cobalt Strike TLS session established.",
                "technique_id": "T1071.001",
            },
            {
                "relative_time_offset_sec": 50.0,
                "stage": "EXFILTRATION",
                "detector": "exfil_ratio",
                "summary": "Outbound exfiltration of 45 MB payload.",
                "technique_id": "T1048.002",
            },
        ],
    }

    result = node.execute(state)

    assert result["primary_threat_class"] == "MULTI_STAGE_APT_INTRUSION"
    assert len(result["mitre_mappings"]) >= 2
    assert "EXECUTIVE INCIDENT SUMMARY: INC-20260831-ABCD" in result["attack_narrative"]
    assert "CRITICAL — Risk Score: 96.25/100" in result["attack_narrative"]
    assert "RECOMMENDED COUNTERMEASURES" in result["attack_narrative"]


def test_classification_intent_rules():
    """Verify individual intent classifications across all threat combinations."""
    node = ClassificationNode()

    # DDoS
    res_ddos = node.execute({"threat_classes_observed": ["VOLUMETRIC_DDOS"]})
    assert res_ddos["primary_threat_class"] == "DISTRIBUTED_DENIAL_OF_SERVICE"

    # Recon
    res_recon = node.execute({"threat_classes_observed": ["PORT_SCAN_RECON"]})
    assert res_recon["primary_threat_class"] == "RECONNAISSANCE_SWEEP"

    # C2 + Exfil
    res_c2_exfil = node.execute({"threat_classes_observed": ["C2_BEACONING", "DATA_EXFILTRATION"]})
    assert res_c2_exfil["primary_threat_class"] == "C2_DATA_EXFILTRATION_CAMPAIGN"

    # C2 only
    res_c2 = node.execute({"threat_classes_observed": ["C2_BEACONING"]})
    assert res_c2["primary_threat_class"] == "MALWARE_COMMAND_AND_CONTROL"


# ---------------------------------------------------------------------------
# 6. FULL GRAPH COMPILATION & END-TO-END EXECUTION TESTS
# ---------------------------------------------------------------------------


def test_full_graph_compilation_and_latency_sla():
    """Verify compiled LangGraph executes end-to-end well under the 2.0s latency SLA (typically < 50ms)."""
    compiled_graph = compile_triage_graph()

    raw_alerts = [
        {
            "alert_id": "alert-001",
            "timestamp": time.time() - 30.0,
            "threat_class": "PORT_SCAN_RECON",
            "detector_name": "portscan_hll",
            "confidence": 0.85,
            "target_ip": "10.0.0.1",
            "target_port": 80,
            "evidence": {"ports_probed": 100},
        },
        {
            "alert_id": "alert-002",
            "timestamp": time.time() - 15.0,
            "threat_class": "DGA_TUNNELLING",
            "detector_name": "dga_tunneling",
            "confidence": 0.95,
            "target_ip": "10.0.0.53",
            "target_port": 53,
            "evidence": {"domain": "xk79z2m1p0q.biz", "dga_probability": 0.967},
        },
        {
            "alert_id": "alert-003",
            "timestamp": time.time(),
            "threat_class": "C2_BEACONING",
            "detector_name": "c2_beaconing",
            "confidence": 0.90,
            "target_ip": "93.184.216.34",
            "target_port": 443,
            "evidence": {"mean_delta_t": 10.0, "jitter_pct": 2.5},
        },
    ]

    initial_state: TriageStateDict = {
        "incident_id": "INC-E2E-TEST-001",
        "source_ip": "192.168.1.50",
        "asset_role": "INTERNAL_WORKSTATION",
        "fused_alerts": raw_alerts,
    }

    t0 = time.time()
    result = compiled_graph.invoke(initial_state)
    elapsed_sec = time.time() - t0

    # Acceptance Criteria: Deterministic execution < 2.0s (in practice < 50ms)
    assert elapsed_sec < 2.0, f"Execution took {elapsed_sec:.4f}s which violates the 2.0s SLA!"
    
    assert result["incident_id"] == "INC-E2E-TEST-001"
    assert len(result["timeline"]) == 3
    assert result["risk_score"] > 50.0
    assert result["primary_threat_class"] == "MULTI_STAGE_APT_INTRUSION"
    assert result["requires_human_approval"] is True
    assert result["status"] == "PENDING_REVIEW"
    assert len(result["countermeasures"]) >= 1


def test_triage_incident_helper_with_fused_incident_model():
    """Verify triage_incident helper function seamlessly ingests FusedIncident Pydantic model."""
    raw_alert_1 = RawAlert(
        alert_id=str(uuid.uuid4()),
        timestamp=time.time() - 10.0,
        detector_name="ddos_entropy",
        threat_class="VOLUMETRIC_DDOS",
        severity="HIGH",
        confidence=0.92,
        source_ip="192.168.1.99",
        target_ip="10.0.0.1",
        target_port=80,
        evidence={"pps": 50000, "entropy": 0.12},
    )

    fused = FusedIncident(
        incident_id="INC-20260831-DDOS",
        primary_source_ip="192.168.1.99",
        source_subnet="192.168.1.0/24",
        target_ips=["10.0.0.1"],
        target_ports=[80],
        participating_detectors=["ddos_entropy"],
        threat_classes=["VOLUMETRIC_DDOS"],
        raw_alert_count=1,
        alerts=[raw_alert_1],
        fused_confidence=0.92,
        severity="HIGH",
    )

    result = triage_incident(fused)

    assert result["incident_id"] == "INC-20260831-DDOS"
    assert result["primary_threat_class"] == "DISTRIBUTED_DENIAL_OF_SERVICE"
    assert result["primary_mitre_technique"] == "T1498.001"
    assert result["requires_human_approval"] is True
    assert result["status"] == "PENDING_REVIEW"
    assert "DISTRIBUTED_DENIAL_OF_SERVICE" in result["attack_narrative"]


# ---------------------------------------------------------------------------
# 7. EDGE CASES & ERROR RESILIENCE TESTS
# ---------------------------------------------------------------------------


def test_triage_empty_state_resilience():
    """Verify triage pipeline handles empty/missing fields gracefully without crashing."""
    graph = compile_triage_graph()
    empty_state: TriageStateDict = {"incident_id": "INC-EMPTY"}

    result = graph.invoke(empty_state)
    assert result["incident_id"] == "INC-EMPTY"
    assert result["requires_human_approval"] is True
    assert result["status"] == "PENDING_REVIEW"
    assert isinstance(result["risk_score"], float)


def test_llm_mode_fallback_on_failure():
    """Verify classification node gracefully falls back to deterministic template when LLM fails."""
    class FailingLLMClient:
        def generate(self, prompt: str):
            raise RuntimeError("Air-gap network unreachable!")

    node = ClassificationNode(execution_mode="llm_enhanced", llm_client=FailingLLMClient())

    state: TriageStateDict = {
        "incident_id": "INC-FALLBACK-001",
        "source_ip": "192.168.1.100",
        "threat_classes_observed": ["PORT_SCAN_RECON"],
        "risk_score": 15.0,
        "severity": "LOW",
    }

    result = node.execute(state)
    assert "EXECUTIVE INCIDENT SUMMARY: INC-FALLBACK-001" in result["attack_narrative"]


def test_risk_scoring_all_threat_class_weights():
    """Verify exact mathematical weight mapping for every individual threat class."""
    node = RiskScoringNode()
    expected_weights = {
        "C2_BEACONING": 40.0,
        "ENCRYPTED_MALWARE": 40.0,
        "DATA_EXFILTRATION": 35.0,
        "DGA_TUNNELLING": 30.0,
        "VOLUMETRIC_DDOS": 30.0,
        "PORT_SCAN_RECON": 15.0,
    }

    for threat_cls, weight in expected_weights.items():
        state: TriageStateDict = {
            "timeline": [
                {"threat_class": threat_cls, "confidence": 1.0, "detector": "det"}
            ],
            "asset_criticality": 1.0,
        }
        res = node.execute(state)
        assert res["risk_score"] == weight
        assert res["risk_breakdown"]["base_risk_sum"] == weight
        assert res["risk_breakdown"]["synergy_bonus"] == 0.0


def test_risk_scoring_clamping_and_boundaries():
    """Verify risk scores never exceed 100.0 or fall below 0.0 under extreme alpha / weights."""
    node = RiskScoringNode()

    # Extreme scenario: all 6 threats at 1.0 confidence + alpha = 2.0
    # Base sum = 40 + 40 + 35 + 30 + 30 + 15 = 190.0
    # Synergy = 20.0 => 210.0
    # Scaled by alpha=2.0 => 420.0
    # Must clamp to 100.0
    all_threats = [
        {"threat_class": "C2_BEACONING", "confidence": 1.0},
        {"threat_class": "ENCRYPTED_MALWARE", "confidence": 1.0},
        {"threat_class": "DATA_EXFILTRATION", "confidence": 1.0},
        {"threat_class": "DGA_TUNNELLING", "confidence": 1.0},
        {"threat_class": "VOLUMETRIC_DDOS", "confidence": 1.0},
        {"threat_class": "PORT_SCAN_RECON", "confidence": 1.0},
    ]

    state: TriageStateDict = {
        "timeline": all_threats,
        "asset_criticality": 2.0,
    }

    res = node.execute(state)
    assert res["risk_score"] == 100.0
    assert res["severity"] == "CRITICAL"
    assert res["risk_breakdown"]["base_risk_sum"] == 190.0
    assert res["risk_breakdown"]["synergy_bonus"] == 20.0
    assert res["risk_breakdown"]["asset_criticality_multiplier"] == 2.0


def test_correlation_node_large_flood_handling():
    """Verify CorrelationNode efficiently digests 1,000 raw alert events in < 50ms."""
    node = CorrelationNode()

    base_time = time.time()
    flood_alerts = [
        {
            "alert_id": f"flood-{i}",
            "timestamp": base_time + (i * 0.01),
            "threat_class": "VOLUMETRIC_DDOS",
            "detector_name": "ddos_entropy",
            "confidence": 0.95,
            "target_ip": "10.0.0.1",
            "target_port": 80,
            "evidence": {"pps": 100000, "entropy": 0.05},
        }
        for i in range(1000)
    ]

    initial_state: TriageStateDict = {
        "incident_id": "INC-FLOOD-1000",
        "source_ip": "192.168.1.200",
        "fused_alerts": flood_alerts,
    }

    t0 = time.time()
    res = node.execute(initial_state)
    elapsed = time.time() - t0

    assert elapsed < 0.1, f"Correlation on 1,000 alerts took {elapsed:.4f}s"
    assert len(res["timeline"]) == 1000
    assert res["timeline"][0]["relative_time_offset_sec"] == 0.0
    assert res["timeline"][-1]["relative_time_offset_sec"] > 0.0


def test_countermeasure_node_safety_enforcement():
    """Verify CountermeasureNode strictly generates human approval flags across all threat types."""
    node = CountermeasureNode()

    for threat in ["VOLUMETRIC_DDOS", "DGA_TUNNELLING", "ENCRYPTED_MALWARE", "DATA_EXFILTRATION"]:
        state: TriageStateDict = {
            "incident_id": "INC-SAFETY-001",
            "source_ip": "192.168.1.10",
            "primary_threat_class": threat,
        }
        res = node.execute(state)
        assert res["requires_human_approval"] is True
        assert len(res["countermeasures"]) >= 1
        for cm in res["countermeasures"]:
            assert cm["requires_human_approval"] is True
            assert cm["syntax_valid"] is True


def test_handoff_node_mock_db_persistence():
    """Verify HandoffNode records execution latency and invokes DB upsert correctly."""
    class MockDatabase:
        def __init__(self):
            self.persisted_incidents = []

        def upsert_incident(self, **kwargs):
            self.persisted_incidents.append(kwargs)

    mock_db = MockDatabase()
    node = HandoffNode(db=mock_db)

    state: TriageStateDict = {
        "incident_id": "INC-HANDOFF-001",
        "source_ip": "192.168.1.50",
        "primary_threat_class": "MULTI_STAGE_APT_INTRUSION",
        "risk_score": 95.0,
        "severity": "CRITICAL",
        "start_time": time.time() - 0.02,
    }

    res = node.execute(state)
    assert res["db_persisted"] is True
    assert res["persisted_id"] == "INC-HANDOFF-001"
    assert res["status"] == "PENDING_REVIEW"
    assert res["requires_human_approval"] is True
    assert res["execution_latency_ms"] >= 10.0
    assert len(mock_db.persisted_incidents) == 1
    assert mock_db.persisted_incidents[0]["incident_id"] == "INC-HANDOFF-001"


def test_pydantic_state_models_strict_validation():
    """Verify strict Pydantic model validation across TimelineStep, RiskBreakdown, and MitreMapping."""
    step = TimelineStep(
        step_number=1,
        timestamp=100.0,
        iso_time="2026-08-31T12:00:00Z",
        relative_time_offset_sec=0.0,
        stage="RECONNAISSANCE",
        detector="portscan_hll",
        threat_class="PORT_SCAN_RECON",
        summary="Port scan",
        confidence=0.85,
    )
    dumped = step.model_dump()
    assert dumped["step_number"] == 1
    assert dumped["confidence"] == 0.85

    rb = RiskBreakdown(
        base_risk_sum=40.0,
        synergy_bonus=10.0,
        asset_criticality_multiplier=1.25,
        final_risk_score=62.5,
        severity="MEDIUM",
        formula="min(100.0, (40 + 10) * 1.25)",
        evidence_breakdown=[
            RiskEvidenceItem(
                threat_class="ENCRYPTED_MALWARE",
                detector="encrypted_malware",
                base_weight=40.0,
                confidence=1.0,
                weighted_score=40.0,
            )
        ],
    )
    assert rb.final_risk_score == 62.5
    assert len(rb.evidence_breakdown) == 1

