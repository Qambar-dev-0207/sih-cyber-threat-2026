"""
SIH26145 - Empirical Challenger 1 Test Suite: Backend Stress and Adversarial Challenge
Adversarially stresses and verifies the FastAPI streaming backend (src/api/):
1. Rapid-fire successive and concurrent simulation triggers (/api/simulate/{scenario})
2. IncidentRingBuffer capacity, eviction semantics under 600+ items, and boundary pagination
3. Multi-threaded race condition stress (concurrent simulation, querying, filtering, action execution)
4. Multi-client WebSocket connections and broadcast fan-out (/ws/telemetry and /ws/incidents)
5. Rapid connection/disconnection lifecycle and connection pool pruning verification
6. Ping/pong flood and malformed/oversized WebSocket message resilience
7. Pathological, injection, and malformed query/body validation (SQLi, XSS, Path Traversal, 422/404)
8. Strict Physical Data Diode air-gap invariant: Zero Automated Execution Return Path
9. Latency percentiles monotonicity (p50 <= p90 <= p99) & telemetry metric integrity
10. Full incident action state transition lifecycle and WebSocket broadcast sync
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import time
import uuid
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
    TelemetryStreamMessage,
)
from src.api.state import AppState, IncidentRingBuffer, reset_app_state


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


def _make_dummy_incident(
    incident_id: str,
    severity: str = "HIGH",
    threat_class: str = "C2_BEACONING",
    status: str = "PENDING_REVIEW",
    risk_score: float = 85.0,
) -> IncidentDetailResponse:
    """Helper constructing a dummy IncidentDetailResponse."""
    now = time.time()
    return IncidentDetailResponse(
        incident_id=incident_id,
        created_at=now,
        updated_at=now,
        source_ip="198.51.100.55",
        subnet="198.51.100.0/24",
        target_ips=["192.168.1.10"],
        target_ports=[443],
        primary_threat_class=threat_class,
        threat_classes=[threat_class],
        participating_detectors=["c2_beacon"],
        severity=severity,
        risk_score=risk_score,
        attack_narrative=f"Test incident {incident_id}",
        countermeasures=[
            CountermeasureArtifactSchema(
                countermeasure_type="iptables",
                target_entity="198.51.100.55",
                artifact_content="iptables -A INPUT -s 198.51.100.55 -j DROP",
                syntax_valid=True,
                requires_human_approval=True,
            )
        ],
        requires_human_approval=True,
        status=status,
    )


# =====================================================================
# 1. Rapid Simulation Burst & Ring Buffer Stress
# =====================================================================

class TestRapidSimulationBurstStress:
    """Stress tests rapid simulation triggers and ring buffer boundaries."""

    def test_rapid_successive_all_scenarios(self, client: TestClient):
        """Executes 15 rapid successive simulation triggers cycling through all scenarios."""
        scenarios = ["apt", "ddos", "c2", "dns_tunnel", "dns"]
        incident_ids = []

        for i in range(15):
            scenario = scenarios[i % len(scenarios)]
            res = client.post(f"/api/simulate/{scenario}")
            assert res.status_code == 200, f"Iteration {i} ({scenario}) failed: {res.text}"
            data = res.json()
            assert data["status"] == "triggered"
            assert data["incident_id"].startswith("INC-")
            assert data["alerts_count"] > 0
            assert data["incident"] is not None
            assert data["incident"]["requires_human_approval"] is True
            incident_ids.append(data["incident_id"])

        # Check all unique host incidents stored in ring buffer (4 distinct hosts)
        list_res = client.get("/api/incidents?limit=50")
        assert list_res.status_code == 200
        stored_items = list_res.json()["items"]
        assert len(stored_items) >= 4
        # Verify all returned incidents are well-formed
        for item in stored_items:
            assert item["incident_id"].startswith("INC-")
            assert item["requires_human_approval"] is True

    def test_concurrent_parallel_simulations(self, client: TestClient):
        """Executes 16 parallel simulation triggers across worker threads concurrently."""
        scenarios = ["apt", "ddos", "c2", "dns_tunnel"]

        def _trigger_sim(idx: int):
            scenario = scenarios[idx % len(scenarios)]
            res = client.post(f"/api/simulate/{scenario}")
            return res.status_code, res.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_trigger_sim, i) for i in range(16)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        for status_code, data in results:
            assert status_code == 200
            assert data["status"] == "triggered"
            assert data["incident"]["requires_human_approval"] is True

        list_res = client.get("/api/incidents?limit=50")
        assert list_res.status_code == 200
        assert len(list_res.json()["items"]) >= 4

    def test_ring_buffer_overflow_600_items_eviction(self):
        """Validates that IncidentRingBuffer strictly caps at max_size=500 and evicts oldest items."""
        buffer = IncidentRingBuffer(max_size=500)
        assert buffer.count() == 0

        # Ingest 600 items with unique IDs
        for i in range(600):
            inc = _make_dummy_incident(
                incident_id=f"INC-OVF-{i:04d}",
                risk_score=float(i % 100),
            )
            buffer.add_incident(inc)

        # Capacity cap check
        assert buffer.count() == 500

        # Oldest 100 (0..99) must be evicted
        for i in range(100):
            assert buffer.get_incident(f"INC-OVF-{i:04d}") is None

        # Remaining (100..599) must be present
        for i in range(100, 600):
            assert buffer.get_incident(f"INC-OVF-{i:04d}") is not None

        # Newest item must be first in list
        items, total = buffer.list_incidents(page=1, limit=10)
        assert total == 500
        assert len(items) == 10
        assert items[0].incident_id == "INC-OVF-0599"

        # Boundary pagination testing: page 25 limit 20 -> items 480..500
        p25_items, p25_total = buffer.list_incidents(page=25, limit=20)
        assert p25_total == 500
        assert len(p25_items) == 20
        assert p25_items[-1].incident_id == "INC-OVF-0100"

        # Beyond page boundary: page 26 limit 20 -> empty
        p26_items, p26_total = buffer.list_incidents(page=26, limit=20)
        assert p26_total == 500
        assert len(p26_items) == 0

    def test_concurrent_read_write_thrash(self, client: TestClient, isolated_app_state: AppState):
        """Stresses simultaneous multi-threaded writing, reading, filtering and updating."""
        stop_flag = False
        errors = []

        # Seed initial buffer with 50 incidents
        for i in range(50):
            isolated_app_state.incident_buffer.add_incident(
                _make_dummy_incident(f"INC-SEED-{i:03d}", severity="CRITICAL" if i % 2 == 0 else "HIGH")
            )

        def _reader_task():
            while not stop_flag:
                try:
                    res = client.get("/api/incidents?page=1&limit=20&severity=CRITICAL")
                    if res.status_code != 200:
                        errors.append(f"Reader error: {res.status_code}")
                    time.sleep(0.01)
                except Exception as e:
                    errors.append(f"Reader exception: {e}")

        def _writer_task():
            for j in range(8):
                try:
                    res = client.post("/api/simulate/c2")
                    if res.status_code != 200:
                        errors.append(f"Writer error: {res.status_code}")
                    time.sleep(0.02)
                except Exception as e:
                    errors.append(f"Writer exception: {e}")

        def _updater_task():
            while not stop_flag:
                try:
                    res = client.post(
                        "/api/incidents/INC-SEED-010/action",
                        json={"action": "APPROVE", "analyst_notes": "Stress action test"},
                    )
                    if res.status_code not in (200, 404):
                        errors.append(f"Updater error: {res.status_code}")
                    time.sleep(0.01)
                except Exception as e:
                    errors.append(f"Updater exception: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            f1 = pool.submit(_reader_task)
            f2 = pool.submit(_reader_task)
            f3 = pool.submit(_updater_task)
            f4 = pool.submit(_writer_task)
            f4.result()
            time.sleep(0.5)
            stop_flag = True
            time.sleep(0.2)

        assert len(errors) == 0, f"Concurrent thrashing generated errors: {errors}"


# =====================================================================
# 2. WebSocket High Concurrency & Multi-Client Fan-Out Stress
# =====================================================================

class TestWebSocketHighConcurrencyStress:
    """Stress tests WebSocket endpoints under multi-client fan-out and rapid connect/disconnect."""

    def test_ws_telemetry_multi_client_fanout(self, client: TestClient):
        """Validates multiple concurrent WebSocket subscribers to /ws/telemetry receiving initial frame."""
        with client.websocket_connect("/ws/telemetry") as ws1, \
             client.websocket_connect("/ws/telemetry") as ws2, \
             client.websocket_connect("/ws/telemetry") as ws3:

            frame1 = ws1.receive_json()
            frame2 = ws2.receive_json()
            frame3 = ws3.receive_json()

            for frame in (frame1, frame2, frame3):
                assert "events_per_second" in frame or "events_per_sec" in frame
                assert "megabits_per_second" in frame or "mbps" in frame
                assert "latency_p50_ms" in frame

    def test_ws_incidents_multi_client_fanout_and_broadcast(self, client: TestClient):
        """Verifies 3 concurrent WebSocket clients connected to /ws/incidents all receive broadcast on simulation."""
        with client.websocket_connect("/ws/incidents") as ws1, \
             client.websocket_connect("/ws/incidents") as ws2, \
             client.websocket_connect("/ws/incidents") as ws3:

            ack1 = ws1.receive_json()
            ack2 = ws2.receive_json()
            ack3 = ws3.receive_json()

            assert ack1["event_type"] == "CONNECTED"
            assert ack2["event_type"] == "CONNECTED"
            assert ack3["event_type"] == "CONNECTED"

            # Trigger synthetic scenario
            sim_res = client.post("/api/simulate/apt")
            assert sim_res.status_code == 200
            sim_data = sim_res.json()
            inc_id = sim_data["incident_id"]

            for ws in (ws1, ws2, ws3):
                broadcast = ws.receive_json()
                assert broadcast["event_type"] == "NEW_INCIDENT"
                assert broadcast["incident_id"] == inc_id
                assert broadcast["incident"]["requires_human_approval"] is True

    def test_ws_rapid_connect_disconnect_cycle(
        self, client: TestClient, isolated_app_state: AppState
    ):
        """Tests 15 rapid consecutive connect/disconnect cycles verifying connection pool stays clean."""
        assert isolated_app_state.connection_manager.telemetry_count == 0
        assert isolated_app_state.connection_manager.incident_count == 0

        for _ in range(15):
            with client.websocket_connect("/ws/telemetry") as ws:
                _ = ws.receive_json()
                assert isolated_app_state.connection_manager.telemetry_count == 1

            with client.websocket_connect("/ws/incidents") as ws:
                _ = ws.receive_json()
                assert isolated_app_state.connection_manager.incident_count == 1

        for _ in range(25):
            if (
                isolated_app_state.connection_manager.telemetry_count == 0
                and isolated_app_state.connection_manager.incident_count == 0
            ):
                break
            time.sleep(0.02)

        assert isolated_app_state.connection_manager.telemetry_count == 0
        assert isolated_app_state.connection_manager.incident_count == 0

    def test_ws_rapid_ping_pong_flood(self, client: TestClient):
        """Sends 50 rapid ping frames to both telemetry and incident streams."""
        with client.websocket_connect("/ws/telemetry") as ws_tel:
            _ = ws_tel.receive_json()
            for _ in range(25):
                ws_tel.send_text("ping")
                resp = ws_tel.receive_text()
                assert resp == "pong"

        with client.websocket_connect("/ws/incidents") as ws_inc:
            _ = ws_inc.receive_json()
            for _ in range(25):
                ws_inc.send_text("ping")
                resp = ws_inc.receive_text()
                assert resp == "pong"

    def test_ws_unexpected_and_large_frames(self, client: TestClient):
        """Tests WebSocket handling of unexpected text strings, JSON payloads, and large messages."""
        with client.websocket_connect("/ws/telemetry") as ws:
            _ = ws.receive_json()

            ws.send_text("HELLO_UNEXPECTED_STRING")
            ws.send_text('{"cmd": "INVALID_CONTROL", "payload": 12345}')
            ws.send_text("A" * 16384)

            ws.send_text("ping")
            resp = ws.receive_text()
            assert resp == "pong"


# =====================================================================
# 3. Adversarial Inputs, Malformed Payloads & Security Boundaries
# =====================================================================

class TestAdversarialInputsAndValidation:
    """Tests adversarial input validation, SQLi/XSS parameters, bounds, and error handlers."""

    def test_incidents_invalid_page_bounds_422(self, client: TestClient):
        for bad_page in [0, -1, -50, "abc"]:
            res = client.get(f"/api/incidents?page={bad_page}")
            assert res.status_code == 422, f"Expected 422 for page={bad_page}, got {res.status_code}"
            data = res.json()
            assert "error" in data or "detail" in data

    def test_incidents_invalid_limit_bounds_422(self, client: TestClient):
        for bad_limit in [0, -5, 101, 500, "xyz"]:
            res = client.get(f"/api/incidents?limit={bad_limit}")
            assert res.status_code == 422, f"Expected 422 for limit={bad_limit}, got {res.status_code}"

    def test_incidents_sqli_xss_special_char_filters(self, client: TestClient):
        injections = [
            "' OR 1=1--",
            "<script>alert('xss')</script>",
            "; DROP TABLE incidents;--",
            "\\x00nullbyte",
            "../../etc/passwd",
            "%27%20OR%201=1--",
        ]
        for inj in injections:
            res = client.get(f"/api/incidents?severity={inj}&threat_class={inj}&status={inj}")
            assert res.status_code == 200
            data = res.json()
            assert data["total"] == 0
            assert len(data["items"]) == 0

    def test_incident_detail_nonexistent_and_pathological_ids(self, client: TestClient):
        bad_ids = [
            "INC-NONEXISTENT-99999",
            "../../etc/passwd",
            "..%2F..%2Fwin.ini",
            "INC-NULL-\\x00-BYTE",
            "A" * 500,
            "!@#$%^&*()_+",
        ]
        for bad_id in bad_ids:
            res = client.get(f"/api/incidents/{bad_id}")
            assert res.status_code == 404, f"Expected 404 for id={bad_id}, got {res.status_code}"
            data = res.json()
            assert "error" in data or "detail" in data

    def test_incident_action_nonexistent_returns_404(self, client: TestClient):
        res = client.post(
            "/api/incidents/INC-DOES-NOT-EXIST-404/action",
            json={"action": "APPROVE", "analyst_notes": "Test action on missing incident"},
        )
        assert res.status_code == 404
        assert "not found" in res.text.lower()

    def test_incident_action_malformed_json_422(self, client: TestClient):
        res1 = client.post("/api/incidents/INC-001/action", json={})
        assert res1.status_code == 422

        res2 = client.post("/api/incidents/INC-001/action", json={"analyst_notes": "notes only"})
        assert res2.status_code == 422

        res3 = client.post("/api/incidents/INC-001/action", content="NOT_JSON_STRING", headers={"Content-Type": "application/json"})
        assert res3.status_code == 422

    def test_incident_action_adversarial_action_values(self, client: TestClient, isolated_app_state: AppState):
        inc = _make_dummy_incident("INC-DIODE-TEST-001")
        isolated_app_state.incident_buffer.add_incident(inc)

        res = client.post(
            "/api/incidents/INC-DIODE-TEST-001/action",
            json={
                "action": "EXECUTE_AUTOMATED_COUNTERMEASURE",
                "analyst_notes": "Adversarial action test",
                "analyst_id": "attacker-attempt",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["requires_human_approval"] is True
        assert data["status"] == "EXECUTE_AUTOMATED_COUNTERMEASURE"

    def test_incident_action_oversized_payload_notes(self, client: TestClient, isolated_app_state: AppState):
        inc = _make_dummy_incident("INC-OVERSIZED-001")
        isolated_app_state.incident_buffer.add_incident(inc)

        large_notes = "SECURITY_AUDIT_LOG_NOTE_" + ("X" * 32000)
        res = client.post(
            "/api/incidents/INC-OVERSIZED-001/action",
            json={"action": "APPROVE", "analyst_notes": large_notes},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "APPROVED"
        assert res.json()["analyst_notes"] == large_notes

    def test_simulate_invalid_scenarios_returns_400_or_404(self, client: TestClient):
        bad_scenarios = [
            "ransomware",
            "mirai",
            "rootkit",
            "../../evil",
            "12345",
            "A" * 1000,
        ]
        for sc in bad_scenarios:
            res = client.post(f"/api/simulate/{sc}")
            assert res.status_code in (400, 404), f"Scenario '{sc}' returned unexpected {res.status_code}"
            data = res.json()
            assert "error" in data or "detail" in data


# =====================================================================
# 4. Data Diode Invariants & Zero Return Path Contract
# =====================================================================

class TestDataDiodeInvariantsAndExecutionDenial:
    """Verifies strict data diode safety invariants across all endpoints and generated artifacts."""

    def test_health_endpoint_data_diode_enclave_contract(self, client: TestClient):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()

        diode = data["data_diode"]
        assert diode["status"] == "ENFORCED"
        assert diode["requires_human_approval"] is True
        assert diode["return_path"] == "DISABLED"
        assert diode["enclave_mode"] == "AIR_GAPPED_PASSIVE"

    def test_root_endpoint_certifies_air_gap_and_human_approval(self, client: TestClient):
        res = client.get("/")
        assert res.status_code == 200
        data = res.json()
        assert data["enclave"] == "AIR_GAPPED_PASSIVE_DATA_DIODE"
        assert data["human_approval_enforced"] is True

    def test_simulated_incidents_and_countermeasures_strictly_passive(self, client: TestClient):
        scenarios = ["apt", "ddos", "c2", "dns_tunnel"]

        for sc in scenarios:
            res = client.post(f"/api/simulate/{sc}")
            assert res.status_code == 200
            data = res.json()
            inc = data["incident"]

            assert inc["requires_human_approval"] is True
            assert inc["status"] in ("PENDING_REVIEW", "NEW")

            assert len(inc["countermeasures"]) >= 1
            for cm in inc["countermeasures"]:
                assert cm["requires_human_approval"] is True
                assert cm["syntax_valid"] is True
                assert isinstance(cm["artifact_content"], str)
                assert len(cm["artifact_content"]) > 0

    def test_no_automated_execution_endpoints_exist(self, client: TestClient):
        forbidden_endpoints = [
            ("POST", "/api/execute"),
            ("POST", "/api/firewall/apply"),
            ("POST", "/api/mitigate"),
            ("POST", "/api/block"),
            ("POST", "/api/countermeasures/deploy"),
        ]
        for method, endpoint in forbidden_endpoints:
            if method == "POST":
                res = client.post(endpoint)
            else:
                res = client.get(endpoint)
            assert res.status_code in (404, 405), f"Forbidden active execution endpoint {endpoint} returned {res.status_code}"


# =====================================================================
# 5. Telemetry & Metrics Integrity Under Stress
# =====================================================================

class TestMetricsAndTelemetryIntegrity:
    """Verifies telemetry metrics mathematical monotonicity and stress polling."""

    def test_metrics_latency_percentiles_monotonicity(self, client: TestClient):
        for _ in range(20):
            res = client.get("/api/metrics")
            assert res.status_code == 200
            data = res.json()
            p50 = data["latency_p50_ms"]
            p90 = data["latency_p90_ms"]
            p99 = data["latency_p99_ms"]
            assert 0.0 <= p50 <= p90 <= p99, f"Latency monotonicity violated: p50={p50}, p90={p90}, p99={p99}"
            assert data["events_per_second"] >= 0.0
            assert data["megabits_per_second"] >= 0.0
            assert 0.0 <= data["packet_loss_pct"] <= 100.0
            assert 0.0 <= data["buffer_utilization_pct"] <= 100.0

    def test_rapid_successive_metrics_polling(self, client: TestClient):
        for _ in range(30):
            res = client.get("/api/metrics")
            assert res.status_code == 200


# =====================================================================
# 6. Incident State Transitions and Action Broadcast Sync
# =====================================================================

class TestIncidentActionLifecycleAndBroadcast:
    """Verifies incident action transitions (APPROVE, DISMISS, RESOLVE) and WebSocket sync."""

    def test_incident_action_lifecycle_transitions(self, client: TestClient, isolated_app_state: AppState):
        inc = _make_dummy_incident("INC-TRANS-001", status="PENDING_REVIEW")
        isolated_app_state.incident_buffer.add_incident(inc)

        # 1. Approve
        res1 = client.post(
            "/api/incidents/INC-TRANS-001/action",
            json={"action": "APPROVE", "analyst_notes": "Verified as malicious", "analyst_id": "analyst_alice"},
        )
        assert res1.status_code == 200
        assert res1.json()["status"] == "APPROVED"
        assert isolated_app_state.incident_buffer.get_incident("INC-TRANS-001").status == "APPROVED"

        # 2. Dismiss
        res2 = client.post(
            "/api/incidents/INC-TRANS-001/action",
            json={"action": "DISMISS", "analyst_notes": "False positive testing", "analyst_id": "analyst_bob"},
        )
        assert res2.status_code == 200
        assert res2.json()["status"] == "DISMISSED"
        assert isolated_app_state.incident_buffer.get_incident("INC-TRANS-001").status == "DISMISSED"

        # 3. Resolve
        res3 = client.post(
            "/api/incidents/INC-TRANS-001/action",
            json={"action": "RESOLVE", "analyst_notes": "Mitigation applied out-of-band", "analyst_id": "analyst_alice"},
        )
        assert res3.status_code == 200
        assert res3.json()["status"] == "RESOLVED"
        assert isolated_app_state.incident_buffer.get_incident("INC-TRANS-001").status == "RESOLVED"

    def test_action_websocket_broadcast_sync(self, client: TestClient, isolated_app_state: AppState):
        inc = _make_dummy_incident("INC-SYNC-001")
        isolated_app_state.incident_buffer.add_incident(inc)

        with client.websocket_connect("/ws/incidents") as ws:
            ack = ws.receive_json()
            assert ack["event_type"] == "CONNECTED"

            res = client.post(
                "/api/incidents/INC-SYNC-001/action",
                json={"action": "APPROVE", "analyst_notes": "Action broadcast test"},
            )
            assert res.status_code == 200

            msg = ws.receive_json()
            assert msg["event_type"] == "INCIDENT_ACTION"
            assert msg["incident_id"] == "INC-SYNC-001"
            assert msg["incident"]["status"] == "APPROVED"
