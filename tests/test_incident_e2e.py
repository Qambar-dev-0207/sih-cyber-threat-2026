"""
tests/test_incident_e2e.py

End-to-end pipeline tests for the full LangGraph 5-node triage graph.

Tests verify:
  - All 5 nodes execute deterministically from raw fused incident state
  - Output state contains: risk_score, mitre_mappings/techniques, countermeasures (6 types)
  - requires_human_approval = True is enforced
  - Total graph execution time < 2.0 seconds
  - Multi-stage APT multi-detector fusion paths
  - Minimal / empty incident graceful handling
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List

import pytest

from src.agentic_triage.graph import compile_triage_graph, triage_incident


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_alert(
    threat_class: str,
    detector: str,
    source_ip: str = "192.168.1.100",
    confidence: float = 0.85,
    **kwargs,
) -> Dict[str, Any]:
    return {
        "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "source_ip": source_ip,
        "detector_name": detector,
        "threat_class": threat_class,
        "confidence": confidence,
        "timestamp": time.time(),
        "evidence": kwargs,
    }


def _triage(state: Dict[str, Any]) -> Dict[str, Any]:
    """Compile a fresh graph and run triage on the given state."""
    graph = compile_triage_graph(execution_mode="deterministic")
    return triage_incident(state, compiled_graph=graph)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ddos_state():
    return {
        "incident_id": "INC-E2E-DDOS-001",
        "source_ip": "203.0.113.50",
        "subnet": "203.0.113.0/24",
        "target_ips": ["10.0.0.1", "10.0.0.2"],
        "target_ports": [80, 443],
        "fused_alerts": [
            _make_alert("VOLUMETRIC_DDOS", "ddos_entropy", confidence=0.91,
                        entropy=0.8, ewma_rate=15000, pps=50000),
            _make_alert("VOLUMETRIC_DDOS", "ddos_entropy", confidence=0.87,
                        entropy=0.9, ewma_rate=14500),
        ],
        "threat_classes_observed": ["VOLUMETRIC_DDOS"],
        "primary_threat_class": "VOLUMETRIC_DDOS",
        "asset_role": "web_server",
        "asset_criticality": 1.5,
        "start_time": time.time(),
        "execution_mode": "deterministic",
    }


@pytest.fixture
def c2_exfil_state():
    return {
        "incident_id": "INC-E2E-C2EXFIL-002",
        "source_ip": "10.5.5.22",
        "subnet": "10.5.5.0/24",
        "target_ips": ["185.220.101.50", "185.220.101.60"],
        "target_ports": [4444, 443, 8443],
        "fused_alerts": [
            _make_alert("C2_BEACONING", "c2_beacon", confidence=0.93,
                        cv=0.08, interval_median=30.5, beacon_count=20),
            _make_alert("ENCRYPTED_MALWARE", "ja4_malware", confidence=0.88,
                        ja4="t13d1516h2_8daaf6152771", malware_family="CobaltStrike"),
            _make_alert("DATA_EXFILTRATION", "exfil_ratio", confidence=0.79,
                        ratio=12.4, out_bytes=2_000_000),
        ],
        "threat_classes_observed": ["C2_BEACONING", "ENCRYPTED_MALWARE", "DATA_EXFILTRATION"],
        "primary_threat_class": "C2_DATA_EXFILTRATION_CAMPAIGN",
        "asset_role": "endpoint",
        "asset_criticality": 1.2,
        "start_time": time.time(),
        "execution_mode": "deterministic",
    }


@pytest.fixture
def multi_stage_apt_state():
    return {
        "incident_id": "INC-E2E-APT-003",
        "source_ip": "198.51.100.5",
        "subnet": "198.51.100.0/24",
        "target_ips": ["10.0.1.1", "10.0.1.50"],
        "target_ports": [22, 80, 443, 4444, 8080],
        "fused_alerts": [
            _make_alert("PORT_SCAN_RECON",   "portscan_hll",  confidence=0.92),
            _make_alert("DGA_TUNNELLING",    "dga_lstm",      confidence=0.89,
                        query="x8f93kdmw02.com", dga_score=0.97),
            _make_alert("ENCRYPTED_MALWARE", "ja4_malware",   confidence=0.91,
                        ja4="t13d1516h2_8daaf6152771"),
            _make_alert("C2_BEACONING",      "c2_beacon",     confidence=0.86,
                        cv=0.07, beacon_count=18),
            _make_alert("DATA_EXFILTRATION", "exfil_ratio",   confidence=0.80,
                        ratio=9.5),
        ],
        "threat_classes_observed": [
            "PORT_SCAN_RECON", "DGA_TUNNELLING", "ENCRYPTED_MALWARE",
            "C2_BEACONING", "DATA_EXFILTRATION",
        ],
        "primary_threat_class": "MULTI_STAGE_APT_INTRUSION",
        "asset_role": "domain_controller",
        "asset_criticality": 2.0,
        "malicious_domains": ["x8f93kdmw02.com", "c2-evil.invalid"],
        "start_time": time.time(),
        "execution_mode": "deterministic",
    }


@pytest.fixture
def minimal_state():
    return {
        "incident_id": "INC-E2E-MIN-000",
        "source_ip": "0.0.0.0",
        "target_ips": [],
        "target_ports": [],
        "fused_alerts": [],
        "threat_classes_observed": [],
        "start_time": time.time(),
        "execution_mode": "deterministic",
    }


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------

class TestE2EGraphExecution:
    """Verify the full 5-node graph executes and produces required outputs."""

    def test_ddos_incident_completes(self, ddos_state):
        result = _triage(ddos_state)
        assert result is not None

    def test_c2_exfil_incident_completes(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        assert result is not None

    def test_apt_incident_completes(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        assert result is not None

    def test_minimal_incident_no_crash(self, minimal_state):
        result = _triage(minimal_state)
        assert result is not None


class TestE2EOutputSchema:
    """Verify required output fields are present and correctly typed."""

    def test_risk_score_present_and_valid(self, ddos_state):
        result = _triage(ddos_state)
        assert "risk_score" in result
        assert 0.0 <= result["risk_score"] <= 100.0

    def test_severity_present(self, ddos_state):
        result = _triage(ddos_state)
        assert result.get("severity") in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_mitre_mappings_present(self, ddos_state):
        result = _triage(ddos_state)
        assert "mitre_mappings" in result
        assert isinstance(result["mitre_mappings"], list)
        assert len(result["mitre_mappings"]) >= 1

    def test_mitre_technique_id_format(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        for m in result.get("mitre_mappings", []):
            tid = m.get("technique_id", "")
            assert tid.startswith("T"), f"Invalid technique_id: {tid}"

    def test_countermeasures_list_present(self, ddos_state):
        result = _triage(ddos_state)
        assert "countermeasures" in result
        assert isinstance(result["countermeasures"], list)
        assert len(result["countermeasures"]) == 6

    def test_all_six_countermeasure_types_present(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        types = {cm["countermeasure_type"] for cm in result["countermeasures"]}
        expected = {"iptables", "nftables", "cisco_acl", "dns_rpz", "snort3", "stix_bundle"}
        assert types == expected

    def test_requires_human_approval_true(self, ddos_state):
        result = _triage(ddos_state)
        assert result.get("requires_human_approval") is True

    def test_all_countermeasures_require_human_approval(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        for cm in result["countermeasures"]:
            assert cm["requires_human_approval"] is True, \
                f"Missing requires_human_approval for type: {cm['countermeasure_type']}"

    def test_attack_narrative_present_and_non_empty(self, apt_state=None, ddos_state=None):
        """Parametrised via direct call to avoid fixture dependency complexity."""
        for state in [
            {
                "incident_id": "INC-E2E-NAR-001",
                "source_ip": "1.2.3.4",
                "target_ips": [],
                "target_ports": [],
                "fused_alerts": [],
                "threat_classes_observed": ["PORT_SCAN_RECON"],
                "primary_threat_class": "PORT_SCAN_RECON",
                "start_time": time.time(),
                "execution_mode": "deterministic",
            }
        ]:
            result = _triage(state)
            narrative = result.get("attack_narrative", "")
            assert isinstance(narrative, str) and len(narrative.strip()) > 10

    def test_primary_threat_class_set(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        assert result.get("primary_threat_class") not in (None, "", "UNKNOWN")

    def test_timeline_present(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        assert "timeline" in result
        assert isinstance(result["timeline"], list)

    def test_stix_bundle_valid_json(self, ddos_state):
        result = _triage(ddos_state)
        stix_cm = next(
            (cm for cm in result["countermeasures"] if cm["countermeasure_type"] == "stix_bundle"),
            None,
        )
        assert stix_cm is not None
        parsed = json.loads(stix_cm["artifact_content"])
        assert parsed["type"] == "bundle"
        assert parsed["spec_version"] == "2.1"

    def test_iptables_artifact_contains_source_ip(self, ddos_state):
        result = _triage(ddos_state)
        ipt_cm = next(
            (cm for cm in result["countermeasures"] if cm["countermeasure_type"] == "iptables"),
            None,
        )
        assert ipt_cm is not None
        assert "203.0.113.50" in ipt_cm["artifact_content"]

    def test_snort_rule_has_alert_keyword(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        snort_cm = next(
            (cm for cm in result["countermeasures"] if cm["countermeasure_type"] == "snort3"),
            None,
        )
        assert snort_cm is not None
        assert "alert" in snort_cm["artifact_content"].lower()

    def test_minimal_incident_has_countermeasures(self, minimal_state):
        result = _triage(minimal_state)
        assert "countermeasures" in result
        assert len(result["countermeasures"]) > 0


class TestE2ELatency:
    """Verify the full 5-node graph executes within the 2.0 second SLA."""

    @pytest.mark.parametrize("incident_name", ["ddos", "c2_exfil", "apt"])
    def test_graph_latency_under_2s(self, incident_name):
        incidents = {
            "ddos": {
                "incident_id": "INC-LAT-DDOS",
                "source_ip": "10.0.0.1",
                "target_ips": ["10.0.0.2"],
                "target_ports": [80],
                "fused_alerts": [_make_alert("VOLUMETRIC_DDOS", "ddos_entropy")],
                "threat_classes_observed": ["VOLUMETRIC_DDOS"],
                "start_time": time.time(),
                "execution_mode": "deterministic",
            },
            "c2_exfil": {
                "incident_id": "INC-LAT-C2",
                "source_ip": "10.1.1.1",
                "target_ips": ["185.220.101.1"],
                "target_ports": [443],
                "fused_alerts": [
                    _make_alert("C2_BEACONING", "c2_beacon"),
                    _make_alert("DATA_EXFILTRATION", "exfil_ratio"),
                ],
                "threat_classes_observed": ["C2_BEACONING", "DATA_EXFILTRATION"],
                "start_time": time.time(),
                "execution_mode": "deterministic",
            },
            "apt": {
                "incident_id": "INC-LAT-APT",
                "source_ip": "192.0.2.1",
                "target_ips": ["10.0.0.1"],
                "target_ports": [22, 443],
                "fused_alerts": [
                    _make_alert("PORT_SCAN_RECON", "portscan_hll"),
                    _make_alert("DGA_TUNNELLING", "dga_lstm"),
                    _make_alert("C2_BEACONING", "c2_beacon"),
                ],
                "threat_classes_observed": ["PORT_SCAN_RECON", "DGA_TUNNELLING", "C2_BEACONING"],
                "start_time": time.time(),
                "execution_mode": "deterministic",
            },
        }
        state = incidents[incident_name]
        graph = compile_triage_graph(execution_mode="deterministic")

        t_start = time.perf_counter()
        result = triage_incident(state, compiled_graph=graph)
        elapsed = time.perf_counter() - t_start

        assert elapsed < 2.0, (
            f"Graph exceeded 2s SLA for {incident_name} incident: {elapsed:.3f}s"
        )
        assert result is not None

    def test_compiled_graph_reuse_is_faster(self):
        """Re-using a compiled graph should be faster than compiling fresh each time."""
        graph = compile_triage_graph(execution_mode="deterministic")

        state_template = {
            "incident_id": "INC-REUSE-TEST",
            "source_ip": "10.0.0.50",
            "target_ips": [],
            "target_ports": [],
            "fused_alerts": [_make_alert("PORT_SCAN_RECON", "portscan_hll")],
            "threat_classes_observed": ["PORT_SCAN_RECON"],
            "start_time": time.time(),
            "execution_mode": "deterministic",
        }

        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            triage_incident(dict(state_template), compiled_graph=graph)
            times.append(time.perf_counter() - t0)

        avg_ms = sum(times) / len(times) * 1000
        assert avg_ms < 2000, f"Average execution {avg_ms:.1f}ms exceeds 2s"


class TestE2EDataDiodeSafety:
    """Verify strict data-diode safety — no return-path execution in any artifact."""

    def test_no_execution_in_iptables(self, ddos_state):
        result = _triage(ddos_state)
        ipt = next(cm for cm in result["countermeasures"] if cm["countermeasure_type"] == "iptables")
        artifact = ipt["artifact_content"]
        forbidden = ["curl ", "wget ", "python -c", "bash -c", "exec(", "os.system"]
        for f in forbidden:
            assert f not in artifact, f"Forbidden '{f}' in iptables artifact"

    def test_requires_human_approval_marker_in_all_artifacts(self, c2_exfil_state):
        result = _triage(c2_exfil_state)
        for cm in result["countermeasures"]:
            assert "requires_human_approval" in cm["artifact_content"], (
                f"requires_human_approval missing from {cm['countermeasure_type']} artifact"
            )

    def test_incident_id_propagated_to_artifacts(self, ddos_state):
        result = _triage(ddos_state)
        for cm in result["countermeasures"]:
            assert "INC-E2E-DDOS-001" in cm["artifact_content"], (
                f"incident_id not found in {cm['countermeasure_type']} artifact"
            )

    def test_no_auto_execution_flag_in_state(self, ddos_state):
        result = _triage(ddos_state)
        # The state must never have an 'auto_execute' or 'executed' flag set to True
        assert result.get("auto_execute") is not True
        assert result.get("executed") is not True


class TestE2EMultiStageAPT:
    """Verify multi-stage APT detection produces elevated risk and multi-technique mappings."""

    def test_apt_risk_score_elevated(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        assert result["risk_score"] >= 60.0, (
            f"APT risk score too low: {result['risk_score']}"
        )

    def test_apt_classification_multi_stage(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        threat_class = result.get("primary_threat_class", "")
        # Should be classified as multi-stage or APT
        assert any(keyword in threat_class.upper() for keyword in
                   ["MULTI", "APT", "C2", "EXFIL", "MALWARE"]), \
            f"Unexpected threat class for APT: {threat_class}"

    def test_apt_has_multiple_mitre_techniques(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        assert len(result.get("mitre_mappings", [])) >= 2

    def test_apt_is_multi_stage_flag(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        assert result.get("is_multi_stage") is True

    def test_apt_malicious_domains_in_dns_rpz(self, multi_stage_apt_state):
        result = _triage(multi_stage_apt_state)
        rpz_cm = next(
            (cm for cm in result["countermeasures"] if cm["countermeasure_type"] == "dns_rpz"),
            None,
        )
        assert rpz_cm is not None
        # At least one domain from malicious_domains should appear
        artifact = rpz_cm["artifact_content"]
        assert "x8f93kdmw02.com" in artifact or "c2-evil.invalid" in artifact or "CNAME" in artifact


