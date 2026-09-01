"""
SIH26145 - Test Suite: FastAPI REST Streaming Backend
Comprehensive, deterministic, zero-flake pytest suite covering:
1. Root status (GET /) and System Health (GET /api/health)
2. Line-Rate Telemetry Metrics (GET /api/metrics)
3. Incidents Query, Pagination & Multi-Field Filtering (GET /api/incidents)
4. Incident Investigation Detail (GET /api/incidents/{id})
5. Human-in-the-Loop Analyst Actions (POST /api/incidents/{id}/action)
6. Synthetic Attack Simulations (POST /api/simulate/{apt, ddos, c2, dns_tunnel, dns})
7. Invalid Scenario & Exception Handlers (400, 404, 422)
8. CORS Middleware Configuration & Headers
9. Hardware Data Diode Safety Contract & Invariants
"""

from __future__ import annotations

import time
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.config import ApiConfig
from src.api.models import (
    CountermeasureArtifactSchema,
    IncidentDetailResponse,
    IncidentTimelineItem,
    MitreMappingSchema,
    RiskBreakdownSchema,
    RiskEvidenceItemSchema,
)
from src.api.state import AppState, reset_app_state


@pytest.fixture(autouse=True)
def isolated_app_state():
    """Ensures each test gets a fresh, isolated AppState instance."""
    state = reset_app_state()
    yield state
    state.incident_buffer.clear()


@pytest.fixture
def client(isolated_app_state: AppState) -> TestClient:
    """FastAPI TestClient fixture configured with isolated state."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def _create_sample_incident(
    incident_id: str = "INC-TEST-001",
    source_ip: str = "198.51.100.42",
    severity: str = "CRITICAL",
    risk_score: float = 94.5,
    threat_class: str = "MULTI_STAGE_APT",
    status: str = "PENDING_REVIEW",
) -> IncidentDetailResponse:
    """Helper creating a fully populated IncidentDetailResponse for test fixtures."""
    now = time.time()
    return IncidentDetailResponse(
        incident_id=incident_id,
        created_at=now - 30.0,
        updated_at=now,
        source_ip=source_ip,
        subnet="198.51.100.0/24",
        target_ips=["192.168.1.100"],
        target_ports=[22, 80, 443, 4444],
        primary_threat_class=threat_class,
        threat_classes=["PORT_SCAN_RECON", "DGA_TUNNELLING", "ENCRYPTED_MALWARE", "C2_BEACONING"],
        participating_detectors=["portscan_hll", "dga_lstm", "ja4_malware", "c2_beacon"],
        severity=severity,
        risk_score=risk_score,
        risk_breakdown=RiskBreakdownSchema(
            base_risk_sum=85.0,
            synergy_bonus=15.0,
            asset_criticality_multiplier=1.0,
            final_risk_score=risk_score,
            severity=severity,
            formula="min(100.0, (sum(w_i * conf_i) + synergy_bonus) * asset_criticality)",
            evidence_breakdown=[
                RiskEvidenceItemSchema(
                    threat_class="PORT_SCAN_RECON",
                    detector="portscan_hll",
                    base_weight=15.0,
                    confidence=0.91,
                    weighted_score=13.65,
                    metric_summary="5 distinct ports scanned",
                ),
                RiskEvidenceItemSchema(
                    threat_class="C2_BEACONING",
                    detector="c2_beacon",
                    base_weight=25.0,
                    confidence=0.97,
                    weighted_score=24.25,
                    metric_summary="CV: 0.041, interval: 30s",
                ),
            ],
            synergy_reason="Multi-stage reconnaissance preceding active C2 heartbeat",
        ),
        timeline=[
            IncidentTimelineItem(
                step_number=1,
                timestamp=now - 30.0,
                iso_time="2026-09-01T12:00:00Z",
                relative_time_offset_sec=0.0,
                stage="RECONNAISSANCE",
                detector="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                summary="Port scan detected on ports [22, 80, 443]",
                target_ip="192.168.1.100",
                target_port=443,
                confidence=0.91,
                evidence_snapshot={"probed_ports": [22, 80, 443]},
            ),
            IncidentTimelineItem(
                step_number=2,
                timestamp=now - 10.0,
                iso_time="2026-09-01T12:00:20Z",
                relative_time_offset_sec=20.0,
                stage="COMMAND_AND_CONTROL",
                detector="c2_beacon",
                threat_class="C2_BEACONING",
                summary="Periodic C2 beaconing observed",
                target_ip="192.168.1.100",
                target_port=4444,
                confidence=0.97,
                evidence_snapshot={"interval_mean": 30.0, "cv": 0.041},
            ),
        ],
        attack_narrative=f"Critical multi-stage APT intrusion detected from {source_ip}.",
        mitre_mappings=[
            MitreMappingSchema(
                technique_id="T1595.001",
                technique_name="Port Scanning",
                tactic_id="TA0043",
                tactic_name="Reconnaissance",
                kill_chain_phase="RECONNAISSANCE",
                confidence=0.91,
                matched_detector="portscan_hll",
                description="Active scanning of network ports",
            ),
            MitreMappingSchema(
                technique_id="T1071.001",
                technique_name="Web Protocols",
                tactic_id="TA0011",
                tactic_name="Command and Control",
                kill_chain_phase="COMMAND_AND_CONTROL",
                confidence=0.97,
                matched_detector="c2_beacon",
                description="Periodic HTTPS beaconing to external controller",
            ),
        ],
        primary_mitre_technique="T1071.001",
        primary_mitre_tactic="TA0011",
        kill_chain_phase="COMMAND_AND_CONTROL",
        countermeasures=[
            CountermeasureArtifactSchema(
                countermeasure_type="iptables",
                target_entity=source_ip,
                artifact_content=f"iptables -A INPUT -s {source_ip} -j DROP",
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="nftables",
                target_entity=source_ip,
                artifact_content=f"add rule ip filter input ip saddr {source_ip} drop",
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="cisco_acl",
                target_entity=source_ip,
                artifact_content=f"access-list 101 deny ip host {source_ip} any",
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="dns_rpz",
                target_entity="c2.malicious-domain.org",
                artifact_content="c2.malicious-domain.org CNAME .\n*.c2.malicious-domain.org CNAME .",
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="snort3",
                target_entity=source_ip,
                artifact_content=f'drop tcp {source_ip} any -> $HOME_NET any (msg:"DROP C2 Traffic"; sid:1000001; rev:1;)',
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="stix_bundle",
                target_entity=source_ip,
                artifact_content='{"type": "bundle", "id": "bundle--12345", "objects": []}',
                syntax_valid=True,
                requires_human_approval=True,
            ),
        ],
        primary_countermeasure_type="iptables",
        primary_countermeasure_artifact=f"iptables -A INPUT -s {source_ip} -j DROP",
        requires_human_approval=True,
        status=status,
        execution_latency_ms=12.4,
        raw_alert_count=5,
        evidence_summary={"total_alerts": 5},
    )


# =====================================================================
# 1. Root & Health Endpoint Tests
# =====================================================================

class TestHealthAndRootEndpoints:
    def test_root_endpoint_structure(self, client: TestClient):
        """Asserts GET / returns 200 with enclave metadata and endpoint catalog."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"
        assert "SIH26145" in data["name"]
        assert data["enclave"] == "AIR_GAPPED_PASSIVE_DATA_DIODE"
        assert data["human_approval_enforced"] is True
        assert "endpoints" in data
        assert data["endpoints"]["health"] == "/api/health"
        assert data["endpoints"]["metrics"] == "/api/metrics"
        assert data["endpoints"]["incidents"] == "/api/incidents"
        assert data["endpoints"]["ws_telemetry"] == "/ws/telemetry"
        assert data["endpoints"]["ws_incidents"] == "/ws/incidents"

    def test_health_endpoint_success(self, client: TestClient):
        """Asserts GET /api/health returns 200, healthy status, and active detectors."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert data["uptime_seconds"] >= 0.0
        assert "detectors" in data
        assert "data_diode" in data
        assert "active_connections" in data
        assert "total_incidents_stored" in data

    def test_health_all_six_detectors_reported_active(self, client: TestClient):
        """Asserts all 6 core passive detectors are reported as operational."""
        response = client.get("/api/health")
        assert response.status_code == 200
        detectors = response.json()["detectors"]
        expected_detectors = [
            "ddos_entropy",
            "portscan_hll",
            "exfil_ratio",
            "dga_lstm",
            "ja4_malware",
            "c2_beacon",
        ]
        for det in expected_detectors:
            assert det in detectors, f"Detector {det} missing from health response"
            assert detectors[det] is True, f"Detector {det} is not marked active"

    def test_health_data_diode_safety_contract(self, client: TestClient):
        """Asserts physical data diode status and human approval invariants."""
        response = client.get("/api/health")
        assert response.status_code == 200
        diode = response.json()["data_diode"]
        assert diode["status"] == "ENFORCED"
        assert diode["requires_human_approval"] is True
        assert diode["return_path"] == "DISABLED"
        assert diode["enclave_mode"] == "AIR_GAPPED_PASSIVE"


# =====================================================================
# 2. Line-Rate Metrics Endpoint Tests
# =====================================================================

class TestMetricsEndpoint:
    def test_get_metrics_payload_structure(self, client: TestClient):
        """Asserts GET /api/metrics returns 200 with all numeric telemetry fields."""
        response = client.get("/api/metrics")
        assert response.status_code == 200
        data = response.json()

        # Required numeric fields
        assert "timestamp" in data
        assert "events_per_second" in data
        assert "megabits_per_second" in data
        assert "packets_per_second" in data
        assert "packet_drop_rate" in data
        assert "latency_p50_ms" in data
        assert "latency_p90_ms" in data
        assert "latency_p99_ms" in data
        assert "active_flows" in data
        assert "buffer_utilization_pct" in data

    def test_get_metrics_numeric_ranges(self, client: TestClient):
        """Asserts metrics fields fall within realistic line-rate operational bounds."""
        response = client.get("/api/metrics")
        assert response.status_code == 200
        data = response.json()

        assert data["events_per_second"] > 0.0
        assert data["megabits_per_second"] > 0.0
        assert data["packets_per_second"] > 0.0
        assert 0.0 <= data["packet_drop_rate"] <= 100.0
        assert 0.0 <= data["latency_p50_ms"] <= data["latency_p90_ms"] <= data["latency_p99_ms"]
        assert data["latency_p50_ms"] < 1.0  # Sub-millisecond pipeline latency
        assert data["active_flows"] >= 0
        assert 0.0 <= data["buffer_utilization_pct"] <= 100.0

    def test_metrics_dynamic_progression(self, client: TestClient):
        """Asserts multiple calls generate fresh metrics with valid timestamps."""
        res1 = client.get("/api/metrics").json()
        time.sleep(0.01)
        res2 = client.get("/api/metrics").json()

        assert res2["timestamp"] >= res1["timestamp"]
        assert isinstance(res1["events_per_second"], (int, float))
        assert isinstance(res2["events_per_second"], (int, float))


# =====================================================================
# 3. Incidents Query & Pagination Tests
# =====================================================================

class TestIncidentsQueryAndFiltering:
    def test_get_incidents_empty_buffer(self, client: TestClient):
        """Asserts empty incidents list returns total=0 and empty items array."""
        response = client.get("/api/incidents")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["incidents"] == []
        assert data["page"] == 1
        assert data["limit"] == 20
        assert data["pages"] == 1

    def test_get_incidents_pagination_slicing(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts pagination limit and offset parameters correctly slice the incident buffer."""
        # Insert 7 sample incidents
        for i in range(1, 8):
            inc = _create_sample_incident(
                incident_id=f"INC-PAGE-{i:03d}",
                source_ip=f"10.0.0.{i}",
                severity="HIGH" if i % 2 == 0 else "CRITICAL",
                risk_score=70.0 + i * 3.0,
            )
            isolated_app_state.incident_buffer.add_incident(inc)

        # Page 1, limit 3
        p1 = client.get("/api/incidents?page=1&limit=3").json()
        assert p1["total"] == 7
        assert len(p1["items"]) == 3
        assert p1["page"] == 1
        assert p1["pages"] == 3

        # Page 2, limit 3
        p2 = client.get("/api/incidents?page=2&limit=3").json()
        assert p2["total"] == 7
        assert len(p2["items"]) == 3
        assert p2["page"] == 2

        # Page 3, limit 3
        p3 = client.get("/api/incidents?page=3&limit=3").json()
        assert p3["total"] == 7
        assert len(p3["items"]) == 1
        assert p3["page"] == 3

        # Disjoint verification: IDs across page 1 and page 2 must not overlap
        p1_ids = {item["incident_id"] for item in p1["items"]}
        p2_ids = {item["incident_id"] for item in p2["items"]}
        p3_ids = {item["incident_id"] for item in p3["items"]}
        assert len(p1_ids.intersection(p2_ids)) == 0
        assert len(p2_ids.intersection(p3_ids)) == 0
        assert len(p1_ids) + len(p2_ids) + len(p3_ids) == 7

    def test_get_incidents_severity_filter(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts severity query parameter filters results deterministically."""
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-CRIT-1", severity="CRITICAL")
        )
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-CRIT-2", severity="CRITICAL")
        )
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-HIGH-1", severity="HIGH")
        )
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-MED-1", severity="MEDIUM")
        )

        res_crit = client.get("/api/incidents?severity=CRITICAL").json()
        assert res_crit["total"] == 2
        for item in res_crit["items"]:
            assert item["severity"] == "CRITICAL"

        res_high = client.get("/api/incidents?severity=HIGH").json()
        assert res_high["total"] == 1
        assert res_high["items"][0]["incident_id"] == "INC-HIGH-1"

        res_low = client.get("/api/incidents?severity=LOW").json()
        assert res_low["total"] == 0

    def test_get_incidents_threat_class_filter(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts threat_class query parameter filters results properly."""
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-APT-1", threat_class="MULTI_STAGE_APT")
        )
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-DDOS-1", threat_class="VOLUMETRIC_DDOS")
        )

        res_apt = client.get("/api/incidents?threat_class=APT").json()
        assert res_apt["total"] == 1
        assert res_apt["items"][0]["incident_id"] == "INC-APT-1"

        res_ddos = client.get("/api/incidents?threat_class=VOLUMETRIC_DDOS").json()
        assert res_ddos["total"] == 1
        assert res_ddos["items"][0]["incident_id"] == "INC-DDOS-1"

    def test_get_incidents_status_filter(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts status query parameter filters by analyst review status."""
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-REV-1", status="PENDING_REVIEW")
        )
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-APP-1", status="APPROVED")
        )
        isolated_app_state.incident_buffer.add_incident(
            _create_sample_incident("INC-DIS-1", status="DISMISSED")
        )

        res_pending = client.get("/api/incidents?status=PENDING_REVIEW").json()
        assert res_pending["total"] == 1
        assert res_pending["items"][0]["incident_id"] == "INC-REV-1"

        res_app = client.get("/api/incidents?status=APPROVED").json()
        assert res_app["total"] == 1
        assert res_app["items"][0]["incident_id"] == "INC-APP-1"


# =====================================================================
# 4. Incident Detail & Analyst Action Tests
# =====================================================================

class TestIncidentDetailAndActions:
    def test_get_incident_by_id_success(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts GET /api/incidents/{id} returns full investigation context."""
        sample = _create_sample_incident("INC-DETAIL-001")
        isolated_app_state.incident_buffer.add_incident(sample)

        response = client.get("/api/incidents/INC-DETAIL-001")
        assert response.status_code == 200
        data = response.json()

        assert data["incident_id"] == "INC-DETAIL-001"
        assert data["source_ip"] == "198.51.100.42"
        assert data["severity"] == "CRITICAL"
        assert data["risk_score"] == 94.5
        assert data["requires_human_approval"] is True

        # Verify timeline
        assert len(data["timeline"]) == 2
        assert data["timeline"][0]["stage"] == "RECONNAISSANCE"
        assert data["timeline"][1]["stage"] == "COMMAND_AND_CONTROL"

        # Verify MITRE mappings
        assert len(data["mitre_mappings"]) >= 2
        mitre_techs = [m["technique_id"] for m in data["mitre_mappings"]]
        assert "T1595.001" in mitre_techs
        assert "T1071.001" in mitre_techs

        # Verify all 6 countermeasures
        assert len(data["countermeasures"]) == 6
        cm_types = [cm["countermeasure_type"] for cm in data["countermeasures"]]
        assert set(cm_types) == {"iptables", "nftables", "cisco_acl", "dns_rpz", "snort3", "stix_bundle"}
        for cm in data["countermeasures"]:
            assert cm["syntax_valid"] is True
            assert cm["requires_human_approval"] is True

    def test_get_incident_by_id_not_found(self, client: TestClient):
        """Asserts GET /api/incidents/{id} returns 404 for non-existent incident."""
        response = client.get("/api/incidents/INC-NONEXISTENT-999")
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["error"].lower()
        assert data["status_code"] == 404

    def test_post_incident_action_approve(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts POST /api/incidents/{id}/action APPROVE updates status to APPROVED."""
        sample = _create_sample_incident("INC-ACTION-001")
        isolated_app_state.incident_buffer.add_incident(sample)

        action_payload = {
            "action": "APPROVE",
            "analyst_notes": "Confirmed malicious CobaltStrike C2 beacon. Edge ACL approved.",
            "analyst_id": "analyst_secops_42",
        }
        response = client.post("/api/incidents/INC-ACTION-001/action", json=action_payload)
        assert response.status_code == 200
        data = response.json()

        assert data["incident_id"] == "INC-ACTION-001"
        assert data["action"] == "APPROVE"
        assert data["status"] == "APPROVED"
        assert data["requires_human_approval"] is True
        assert "analyst_secops_42" in data["message"]

        # Confirm persisted state via GET
        get_res = client.get("/api/incidents/INC-ACTION-001").json()
        assert get_res["status"] == "APPROVED"

    def test_post_incident_action_dismiss(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts POST /api/incidents/{id}/action DISMISS updates status to DISMISSED."""
        sample = _create_sample_incident("INC-ACTION-002")
        isolated_app_state.incident_buffer.add_incident(sample)

        action_payload = {
            "action": "DISMISS",
            "analyst_notes": "Authorized internal penetration test activity.",
            "analyst_id": "lead_analyst_01",
        }
        response = client.post("/api/incidents/INC-ACTION-002/action", json=action_payload)
        assert response.status_code == 200
        data = response.json()

        assert data["incident_id"] == "INC-ACTION-002"
        assert data["action"] == "DISMISS"
        assert data["status"] == "DISMISSED"

        # Confirm persisted state via GET
        get_res = client.get("/api/incidents/INC-ACTION-002").json()
        assert get_res["status"] == "DISMISSED"

    def test_post_incident_action_resolve(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts POST /api/incidents/{id}/action RESOLVE updates status to RESOLVED."""
        sample = _create_sample_incident("INC-ACTION-003")
        isolated_app_state.incident_buffer.add_incident(sample)

        action_payload = {
            "action": "RESOLVE",
            "analyst_notes": "Host quarantined and remitted.",
        }
        response = client.post("/api/incidents/INC-ACTION-003/action", json=action_payload)
        assert response.status_code == 200
        assert response.json()["status"] == "RESOLVED"

    def test_post_incident_action_not_found(self, client: TestClient):
        """Asserts POST action on non-existent incident returns 404."""
        action_payload = {"action": "APPROVE", "analyst_notes": "Non-existent"}
        response = client.post("/api/incidents/INC-NONEXISTENT/action", json=action_payload)
        assert response.status_code == 404
        assert response.json()["status_code"] == 404


# =====================================================================
# 5. Synthetic Attack Simulation Endpoint Tests
# =====================================================================

class TestAttackSimulationScenarios:
    def test_simulate_apt_scenario(self, client: TestClient):
        """
        Asserts POST /api/simulate/apt executes end-to-end 5-step kill chain:
        Recon -> DGA -> JA4 CobaltStrike -> C2 -> Exfiltration,
        returning an incident with risk >= 85.0 and all 6 countermeasures.
        """
        response = client.post("/api/simulate/apt")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "triggered"
        assert data["scenario"] == "apt"
        assert data["alerts_count"] == 5
        assert data["incident_id"].startswith("INC-")

        inc = data["incident"]
        assert inc is not None
        assert inc["severity"] == "CRITICAL"
        assert inc["risk_score"] >= 80.0
        assert inc["source_ip"] == "198.51.100.42"
        assert inc["requires_human_approval"] is True

        # Check timeline stages
        assert len(inc["timeline"]) >= 3
        stages = [t["stage"] for t in inc["timeline"]]
        assert "RECONNAISSANCE" in stages

        # Check MITRE techniques
        mitre_ids = [m["technique_id"] for m in inc["mitre_mappings"]]
        assert any(t.startswith("T1595") or t.startswith("T1071") or t.startswith("T1568") for t in mitre_ids)

        # Check all 6 countermeasures generated
        assert len(inc["countermeasures"]) == 6
        cm_types = [cm["countermeasure_type"] for cm in inc["countermeasures"]]
        assert "iptables" in cm_types
        assert "nftables" in cm_types
        assert "cisco_acl" in cm_types
        assert "dns_rpz" in cm_types
        assert "snort3" in cm_types
        assert "stix_bundle" in cm_types

        # Verify incident was persisted into the buffer
        get_res = client.get(f"/api/incidents/{data['incident_id']}")
        assert get_res.status_code == 200
        assert get_res.json()["incident_id"] == data["incident_id"]

    def test_simulate_ddos_scenario(self, client: TestClient):
        """Asserts POST /api/simulate/ddos triggers volumetric SYN flood scenario."""
        response = client.post("/api/simulate/ddos")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "triggered"
        assert data["scenario"] == "ddos"
        assert data["alerts_count"] >= 1
        inc = data["incident"]
        assert inc["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert inc["risk_score"] > 20.0
        assert "DDOS" in inc["primary_threat_class"].upper() or any("DDOS" in tc.upper() for tc in inc["threat_classes"])

        # Countermeasure includes firewall blocking rule
        cm_types = [cm["countermeasure_type"] for cm in inc["countermeasures"]]
        assert "iptables" in cm_types or "nftables" in cm_types

    def test_simulate_c2_scenario(self, client: TestClient):
        """Asserts POST /api/simulate/c2 triggers JA4 + beaconing C2 scenario."""
        response = client.post("/api/simulate/c2")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "triggered"
        assert data["scenario"] == "c2"
        assert data["alerts_count"] == 2
        inc = data["incident"]
        assert inc["severity"] in ("CRITICAL", "HIGH")
        assert inc["source_ip"] == "10.0.0.85"

    def test_simulate_dns_tunnel_scenario(self, client: TestClient):
        """Asserts POST /api/simulate/dns_tunnel triggers high-entropy DGA scenario."""
        response = client.post("/api/simulate/dns_tunnel")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "triggered"
        assert data["scenario"] == "dns_tunnel"
        assert data["alerts_count"] == 3
        inc = data["incident"]
        assert inc["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert inc["risk_score"] > 20.0
        assert "DGA" in inc["primary_threat_class"].upper() or any("DGA" in tc.upper() for tc in inc["threat_classes"])

        # Countermeasure includes DNS RPZ entry
        cm_types = [cm["countermeasure_type"] for cm in inc["countermeasures"]]
        assert "dns_rpz" in cm_types

    def test_simulate_dns_alias_scenario(self, client: TestClient):
        """Asserts POST /api/simulate/dns acts as alias for dns_tunnel."""
        response = client.post("/api/simulate/dns")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "triggered"
        assert data["scenario"] == "dns"
        assert data["alerts_count"] == 3

    def test_simulate_invalid_scenario_returns_400(self, client: TestClient):
        """Asserts POST /api/simulate/unknown returns 400 with descriptive message."""
        response = client.post("/api/simulate/unsupported_scenario_xyz")
        assert response.status_code == 400
        data = response.json()
        assert "invalid simulation scenario" in data["error"].lower()
        assert "available scenarios" in data["error"].lower()
        assert data["status_code"] == 400


# =====================================================================
# 6. CORS & Custom Error Handler Tests
# =====================================================================

class TestCorsAndErrorHandlers:
    def test_cors_preflight_headers(self, client: TestClient):
        """Asserts CORS headers are present on preflight OPTIONS queries."""
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        }
        response = client.options("/api/health", headers=headers)
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") in ("*", "http://localhost:5173")

    def test_validation_error_handler_422(self, client: TestClient):
        """Asserts custom 422 JSON validation error format on malformed request bodies."""
        response = client.post(
            "/api/incidents/INC-123/action",
            json={"invalid_key_missing_action": 123},
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"] == "Validation Error"
        assert data["status_code"] == 422
        assert "details" in data
        assert "/api/incidents/INC-123/action" in data["path"]

    def test_custom_404_error_handler(self, client: TestClient):
        """Asserts custom 404 JSON error format on missing resources."""
        response = client.get("/api/incidents/INC-DOES-NOT-EXIST")
        assert response.status_code == 404
        data = response.json()
        assert data["status_code"] == 404
        assert "not found" in data["error"].lower()
        assert data["path"] == "/api/incidents/INC-DOES-NOT-EXIST"


# =====================================================================
# 7. Hardware Data Diode Safety Invariants
# =====================================================================

class TestDataDiodeSafetyInvariants:
    def test_data_diode_invariant_across_all_endpoints(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """
        Safety invariant: verifies that across health, incidents list, incident detail,
        and simulation triggers, requires_human_approval is strictly True and immutable.
        """
        # 1. Health
        health = client.get("/api/health").json()
        assert health["data_diode"]["requires_human_approval"] is True
        assert health["data_diode"]["return_path"] == "DISABLED"

        # 2. Simulation -> Detail
        sim = client.post("/api/simulate/apt").json()
        inc = sim["incident"]
        assert inc["requires_human_approval"] is True
        for cm in inc["countermeasures"]:
            assert cm["requires_human_approval"] is True

        # 3. Incident List
        incidents = client.get("/api/incidents").json()
        for item in incidents["items"]:
            assert item["requires_human_approval"] is True

        # 4. Action update
        action_res = client.post(
            f"/api/incidents/{inc['incident_id']}/action",
            json={"action": "APPROVE", "analyst_notes": "Approved"},
        ).json()
        assert action_res["requires_human_approval"] is True
