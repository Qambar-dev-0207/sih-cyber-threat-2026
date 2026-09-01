"""
SIH26145 - Test Suite: WebSocket Streaming & Real-Time Threat Broadcasting
Comprehensive, deterministic, zero-flake pytest suite covering:
1. Live line-rate telemetry WebSocket feed (/ws/telemetry)
2. Real-time incident push notification WebSocket feed (/ws/incidents)
3. Multi-client fan-out (3+ concurrent WebSocket subscribers receiving identical payloads)
4. Client lifecycle, graceful disconnection, and connection pool pruning
5. WebSocket ping/pong keep-alive protocol
6. Sub-500ms broadcast latency contract SLA
7. Incident action broadcast synchronization
"""

from __future__ import annotations

import time
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.models import (
    CountermeasureArtifactSchema,
    IncidentBroadcastMessage,
    IncidentDetailResponse,
    IncidentTimelineItem,
    MitreMappingSchema,
    RiskBreakdownSchema,
    TelemetryStreamMessage,
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


def _create_mock_incident(
    incident_id: str = "INC-WS-001",
    source_ip: str = "198.51.100.77",
    severity: str = "CRITICAL",
    risk_score: float = 96.0,
    threat_class: str = "MULTI_STAGE_APT",
) -> IncidentDetailResponse:
    """Helper creating a fully populated IncidentDetailResponse for WebSocket testing."""
    now = time.time()
    return IncidentDetailResponse(
        incident_id=incident_id,
        created_at=now,
        updated_at=now,
        source_ip=source_ip,
        subnet="198.51.100.0/24",
        target_ips=["192.168.1.50"],
        target_ports=[443, 8443],
        primary_threat_class=threat_class,
        threat_classes=["PORT_SCAN_RECON", "C2_BEACONING"],
        participating_detectors=["portscan_hll", "c2_beacon"],
        severity=severity,
        risk_score=risk_score,
        risk_breakdown=RiskBreakdownSchema(
            base_risk_sum=80.0,
            synergy_bonus=16.0,
            asset_criticality_multiplier=1.0,
            final_risk_score=risk_score,
            severity=severity,
            formula="min(100.0, (sum(w_i * conf_i) + synergy_bonus) * asset_criticality)",
            evidence_breakdown=[],
        ),
        timeline=[
            IncidentTimelineItem(
                step_number=1,
                timestamp=now,
                stage="COMMAND_AND_CONTROL",
                detector="c2_beacon",
                threat_class="C2_BEACONING",
                summary="Beaconing pulse observed",
                target_ip="192.168.1.50",
                target_port=8443,
                confidence=0.98,
            )
        ],
        attack_narrative=f"Multi-stage C2 beaconing intrusion detected from {source_ip}.",
        mitre_mappings=[
            MitreMappingSchema(
                technique_id="T1071.001",
                technique_name="Web Protocols",
                tactic_id="TA0011",
                tactic_name="Command and Control",
                kill_chain_phase="COMMAND_AND_CONTROL",
                confidence=0.98,
            )
        ],
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
                target_entity="c2.attacker.net",
                artifact_content="c2.attacker.net CNAME .",
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="snort3",
                target_entity=source_ip,
                artifact_content=f'drop tcp {source_ip} any -> $HOME_NET any (msg:"DROP C2"; sid:1000002; rev:1;)',
                syntax_valid=True,
                requires_human_approval=True,
            ),
            CountermeasureArtifactSchema(
                countermeasure_type="stix_bundle",
                target_entity=source_ip,
                artifact_content='{"type": "bundle", "id": "bundle--9999", "objects": []}',
                syntax_valid=True,
                requires_human_approval=True,
            ),
        ],
        requires_human_approval=True,
        status="PENDING_REVIEW",
        execution_latency_ms=15.0,
        raw_alert_count=2,
    )


# =====================================================================
# 1. Telemetry WebSocket Stream Tests (/ws/telemetry)
# =====================================================================

class TestTelemetryWebSocketStream:
    def test_ws_telemetry_connection_and_initial_frame(self, client: TestClient):
        """Asserts connecting to /ws/telemetry immediately delivers a valid line-rate telemetry frame."""
        with client.websocket_connect("/ws/telemetry") as ws:
            frame = ws.receive_json()

            assert "timestamp" in frame
            assert "events_per_second" in frame or "events_per_sec" in frame
            assert "megabits_per_second" in frame or "mbps" in frame
            assert "packets_per_second" in frame or "pps" in frame
            assert "packet_drop_rate" in frame or "packet_loss_pct" in frame
            assert "latency_p50_ms" in frame
            assert "active_detectors" in frame

            # Numeric assertions
            eps = frame.get("events_per_second", frame.get("events_per_sec", 0))
            assert eps > 0
            mbps = frame.get("megabits_per_second", frame.get("mbps", 0))
            assert mbps > 0
            latency = frame.get("latency_p50_ms", 0)
            assert latency > 0

    def test_ws_telemetry_continuous_stream(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts that broadcasting telemetry sends consecutive valid JSON frames."""
        with client.websocket_connect("/ws/telemetry") as ws:
            frame1 = ws.receive_json()

            # Trigger a manual broadcast
            telemetry_data = TelemetryStreamMessage(
                timestamp=time.time(),
                events_per_second=32000.0,
                megabits_per_second=210.5,
                packets_per_second=35000.0,
                packet_drop_rate=0.01,
                latency_p50_ms=0.024,
            )
            import asyncio
            asyncio.run(isolated_app_state.connection_manager.broadcast_telemetry(telemetry_data))

            frame2 = ws.receive_json()
            assert frame2["events_per_second"] == 32000.0
            assert frame2["megabits_per_second"] == 210.5
            assert frame2["timestamp"] >= frame1["timestamp"]

    def test_ws_telemetry_ping_pong_keepalive(self, client: TestClient):
        """Asserts client sending 'ping' text frame receives 'pong' keep-alive response."""
        with client.websocket_connect("/ws/telemetry") as ws:
            # Drain initial frame
            _ = ws.receive_json()

            # Send ping
            ws.send_text("ping")
            pong = ws.receive_text()
            assert pong == "pong"

    def test_ws_telemetry_disconnect_lifecycle(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts client connection and disconnection updates connection pool count cleanly."""
        assert isolated_app_state.connection_manager.telemetry_count == 0

        with client.websocket_connect("/ws/telemetry") as ws:
            assert isolated_app_state.connection_manager.telemetry_count == 1
            _ = ws.receive_json()

        # After context exit, wait briefly for ASGI disconnect handler to finalize
        for _ in range(25):
            if isolated_app_state.connection_manager.telemetry_count == 0:
                break
            time.sleep(0.02)

        assert isolated_app_state.connection_manager.telemetry_count == 0


# =====================================================================
# 2. Incidents WebSocket Stream Tests (/ws/incidents)
# =====================================================================

class TestIncidentsWebSocketStream:
    def test_ws_incidents_connection_and_ack(self, client: TestClient):
        """Asserts connecting to /ws/incidents returns initial CONNECTED acknowledgment message."""
        with client.websocket_connect("/ws/incidents") as ws:
            ack = ws.receive_json()
            assert ack["event_type"] == "CONNECTED"
            assert "Threat Feed" in ack["message"]
            assert "buffer_count" in ack

    def test_ws_incidents_broadcast_on_simulation(self, client: TestClient):
        """Asserts triggering POST /api/simulate/c2 pushes the triaged incident to the connected WebSocket."""
        with client.websocket_connect("/ws/incidents") as ws:
            # Drain CONNECTED ack
            ack = ws.receive_json()
            assert ack["event_type"] == "CONNECTED"

            # Trigger synthetic scenario
            sim_res = client.post("/api/simulate/c2")
            assert sim_res.status_code == 200
            sim_data = sim_res.json()
            expected_id = sim_data["incident_id"]

            # Receive real-time push frame on WebSocket
            push_msg = ws.receive_json()
            assert push_msg["event_type"] == "NEW_INCIDENT"
            assert push_msg["incident_id"] == expected_id
            assert push_msg["severity"] in ("CRITICAL", "HIGH")
            assert push_msg["risk_score"] > 50.0
            assert "incident" in push_msg
            assert push_msg["incident"]["incident_id"] == expected_id
            assert push_msg["incident"]["requires_human_approval"] is True

    def test_ws_incidents_broadcast_on_analyst_action(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts analyst approving an incident broadcasts INCIDENT_ACTION event over WebSocket."""
        # Add sample incident
        sample = _create_mock_incident("INC-WS-ACT-01")
        isolated_app_state.incident_buffer.add_incident(sample)

        with client.websocket_connect("/ws/incidents") as ws:
            # Drain CONNECTED ack
            _ = ws.receive_json()

            # Execute action
            action_res = client.post(
                "/api/incidents/INC-WS-ACT-01/action",
                json={"action": "APPROVE", "analyst_notes": "Edge ACL rule approved by SOC Lead."},
            )
            assert action_res.status_code == 200

            # Receive action broadcast
            action_broadcast = ws.receive_json()
            assert action_broadcast["event_type"] == "INCIDENT_ACTION"
            assert action_broadcast["incident_id"] == "INC-WS-ACT-01"
            assert action_broadcast["incident"]["status"] == "APPROVED"
            assert "SOC Lead" in action_broadcast["summary"]

    def test_ws_incidents_ping_pong_keepalive(self, client: TestClient):
        """Asserts sending 'ping' text frame to /ws/incidents receives 'pong' response."""
        with client.websocket_connect("/ws/incidents") as ws:
            _ = ws.receive_json()  # Drain CONNECTED ack

            ws.send_text("ping")
            pong = ws.receive_text()
            assert pong == "pong"

    def test_ws_incidents_disconnect_lifecycle(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Asserts incident stream connection and disconnection updates connection pool cleanly."""
        assert isolated_app_state.connection_manager.incident_count == 0

        with client.websocket_connect("/ws/incidents") as ws:
            assert isolated_app_state.connection_manager.incident_count == 1
            _ = ws.receive_json()

        # After context exit, wait briefly for ASGI disconnect handler to finalize
        for _ in range(25):
            if isolated_app_state.connection_manager.incident_count == 0:
                break
            time.sleep(0.02)

        assert isolated_app_state.connection_manager.incident_count == 0


# =====================================================================
# 3. Multi-Client Fan-Out & Resilience Tests
# =====================================================================

class TestMultiClientFanOutAndResilience:
    def test_multi_client_fanout_broadcast(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """
        Asserts that 3 concurrent WebSocket clients connected to /ws/incidents
        all receive identical broadcast payloads without drops.
        """
        import asyncio

        with client.websocket_connect("/ws/incidents") as ws1, \
             client.websocket_connect("/ws/incidents") as ws2, \
             client.websocket_connect("/ws/incidents") as ws3:

            # Drain CONNECTED ack for all 3 clients
            assert ws1.receive_json()["event_type"] == "CONNECTED"
            assert ws2.receive_json()["event_type"] == "CONNECTED"
            assert ws3.receive_json()["event_type"] == "CONNECTED"
            assert isolated_app_state.connection_manager.incident_count == 3

            # Broadcast an incident
            sample_incident = _create_mock_incident("INC-FANOUT-777", risk_score=98.5)
            delivered = asyncio.run(
                isolated_app_state.connection_manager.broadcast_incident(sample_incident)
            )
            assert delivered == 3

            # Read broadcast from all 3 clients
            msg1 = ws1.receive_json()
            msg2 = ws2.receive_json()
            msg3 = ws3.receive_json()

            for msg in [msg1, msg2, msg3]:
                assert msg["event_type"] == "NEW_INCIDENT"
                assert msg["incident_id"] == "INC-FANOUT-777"
                assert msg["risk_score"] == 98.5
                assert msg["incident"]["requires_human_approval"] is True

            # All 3 received identical incident payload
            assert msg1 == msg2 == msg3

    def test_broadcast_when_zero_subscribers(
        self, isolated_app_state: AppState
    ):
        """Asserts broadcasting when no clients are connected returns 0 delivered with zero exceptions."""
        import asyncio

        telemetry = TelemetryStreamMessage(timestamp=time.time(), events_per_second=25000.0)
        t_delivered = asyncio.run(isolated_app_state.connection_manager.broadcast_telemetry(telemetry))
        assert t_delivered == 0

        incident = _create_mock_incident("INC-NO-CLIENTS")
        i_delivered = asyncio.run(isolated_app_state.connection_manager.broadcast_incident(incident))
        assert i_delivered == 0


# =====================================================================
# 4. Broadcast Latency SLA Contract Tests
# =====================================================================

class TestWebSocketLatencyContract:
    def test_sub_500ms_broadcast_latency_sla(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """
        Asserts the broadcast dispatch and receipt latency over WebSocket
        is well below the 500ms SLA contract threshold (typically < 10ms in-memory).
        """
        import asyncio

        with client.websocket_connect("/ws/incidents") as ws:
            _ = ws.receive_json()  # Drain CONNECTED ack

            sample_incident = _create_mock_incident("INC-LATENCY-TEST")

            t_start = time.perf_counter()
            asyncio.run(isolated_app_state.connection_manager.broadcast_incident(sample_incident))
            msg = ws.receive_json()
            t_end = time.perf_counter()

            latency_sec = t_end - t_start
            assert latency_sec < 0.500, f"WebSocket broadcast latency {latency_sec*1000:.2f}ms exceeded 500ms SLA"
            assert msg["incident_id"] == "INC-LATENCY-TEST"
