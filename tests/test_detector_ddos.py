"""
SIH26145 - Test Suite for Detector 1: Volumetric & Protocol DDoS Detector
Tests O(1) differential Shannon entropy, EWMA Z-scores, targeted floods,
UDP random sweeps, TCP SYN floods, benign traffic invariance, and schema conformance.
"""

import math
import random
import time
import pytest

from src.ingestion.models import ConnTelemetryEvent, RawAlert, calculate_shannon_entropy
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.ddos_entropy import (
    DDoSEntropyDetector,
    DifferentialEntropyTracker,
    RateEWMATracker,
    TargetHostDDoSState,
)


class TestDifferentialEntropyTracker:
    """Unit tests verifying mathematical accuracy and O(1) updates of DifferentialEntropyTracker."""

    def test_single_element_zero_entropy(self):
        """Single repeated port must yield 0.0 entropy."""
        tracker = DifferentialEntropyTracker(window_size=100)
        for _ in range(50):
            raw_ent, norm_ent = tracker.add(80)
        assert raw_ent == 0.0
        assert norm_ent == 0.0

    def test_uniform_distribution_maximum_entropy(self):
        """Uniform distribution across N distinct ports should reach log2(N)."""
        tracker = DifferentialEntropyTracker(window_size=64)
        for i in range(64):
            raw_ent, norm_ent = tracker.add(1000 + i)
        # log2(64) = 6.0
        assert math.isclose(raw_ent, 6.0, abs_tol=0.01)
        assert math.isclose(norm_ent, 1.0, abs_tol=0.01)

    def test_sliding_window_eviction_matches_static_entropy(self):
        """Streaming differential entropy must exactly match static Shannon calculation after eviction."""
        window_size = 50
        tracker = DifferentialEntropyTracker(window_size=window_size)

        # Feed 150 randomized ports
        ports = [random.choice([80, 443, 8080, 53, 22]) for _ in range(150)]
        for p in ports:
            raw_ent, norm_ent = tracker.add(p)

        # Static calculation over last window_size ports
        last_window = ports[-window_size:]
        length = len(last_window)
        counts = {}
        for x in last_window:
            counts[x] = counts.get(x, 0) + 1
        expected_entropy = 0.0
        for c in counts.values():
            prob = c / length
            expected_entropy -= prob * math.log2(prob)

        assert math.isclose(raw_ent, expected_entropy, abs_tol=1e-3)


class TestRateEWMATracker:
    """Unit tests for EWMA flow rate moving average, variance, and Z-score."""

    def test_stable_rate_baseline(self):
        """Constant rate should produce near-zero Z-score."""
        tracker = RateEWMATracker(alpha=0.1)
        t_base = 1725000000.0

        for sec in range(20):
            cur, ewma, z = tracker.record_event(t_base + sec, pkts=10)

        assert math.isclose(ewma, 10.0, abs_tol=2.0)
        assert abs(z) < 2.0

    def test_sudden_rate_spike_produces_high_z_score(self):
        """Sudden rate surge (10 pps -> 1000 pps) must trigger a high Z-score."""
        tracker = RateEWMATracker(alpha=0.08)
        t_base = 1725000000.0

        # Baseline training
        for sec in range(30):
            tracker.record_event(t_base + sec, pkts=10)

        # Spike at second 31
        cur, ewma, z = tracker.record_event(t_base + 31, pkts=1500)
        assert cur == 1500.0
        assert z > 5.0


class TestDDoSEntropyDetectorScenarios:
    """Scenario tests verifying detection of DDoS attacks and silence on benign traffic."""

    @pytest.fixture
    def bus(self):
        return InMemoryStreamingBus(num_partitions=4)

    @pytest.fixture
    def detector(self, bus):
        return DDoSEntropyDetector(
            window_size=200,
            rate_z_threshold=2.5,
            rate_min_pps=50.0,
            entropy_low_threshold=1.2,
            bus=bus,
        )

    def test_targeted_port_collapse_syn_flood(self, detector):
        """
        Targeted SYN flood on port 80 with high rate and low port entropy
        must trigger a volumetric_ddos or protocol_ddos alert.
        """
        target_ip = "192.168.10.50"
        alerts = []
        t0 = 1725000000.0

        # Establish modest baseline
        for i in range(10):
            conn = ConnTelemetryEvent(
                src_ip="10.0.0.1",
                src_port=10000 + i,
                dst_ip=target_ip,
                dst_port=80,
                ts=t0 + (i * 0.5),
                conn_state="SF",
            )
            detector.handle_event(conn)

        # Inundate with high-rate SYN flood on port 80 (concentrated port)
        flood_t = t0 + 10.0
        for i in range(250):
            conn = ConnTelemetryEvent(
                src_ip=f"172.16.{(i // 250)}.{i % 250 + 1}",
                src_port=20000 + i,
                dst_ip=target_ip,
                dst_port=80,
                ts=flood_t,
                conn_state="S0",
                orig_pkts=5,
                uid=f"C_SYN_FLOOD_{i}",
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        top_alert = alerts[0]
        assert top_alert.detector_name == "ddos_entropy"
        assert top_alert.target_ip == target_ip
        assert top_alert.target_port == 80
        assert top_alert.threat_class in ("volumetric_ddos", "protocol_ddos")
        assert top_alert.severity in ("HIGH", "CRITICAL")
        assert top_alert.confidence >= 0.85
        assert top_alert.evidence["port_entropy"] < 1.2
        assert top_alert.recommended_mitigation == "rate_limit"

    def test_random_port_udp_sweep_flood(self, detector):
        """
        High-rate UDP flood with randomized target ports (high port entropy)
        must trigger a volumetric_ddos alert with normalized entropy > 0.85.
        """
        target_ip = "192.168.10.60"
        alerts = []
        flood_t = 1725000100.0

        for i in range(200):
            rand_port = 10000 + (i * 250) % 55000
            conn = ConnTelemetryEvent(
                src_ip="172.16.1.100",
                src_port=50000 + (i % 1000),
                dst_ip=target_ip,
                dst_port=rand_port,
                proto="udp",
                ts=flood_t,
                conn_state="SF",
                orig_pkts=10,
                uid=f"C_UDP_FLOOD_{i}",
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.threat_class == "volumetric_ddos"
        assert alert.evidence["normalized_port_entropy"] >= 0.85

    def test_tcp_half_open_syn_flood_protocol_anomaly(self, detector):
        """
        Elevated connection rate with >70% S0 half-open states must trigger protocol_ddos.
        """
        target_ip = "192.168.10.70"
        alerts = []
        t = 1725000200.0

        for i in range(150):
            conn = ConnTelemetryEvent(
                src_ip=f"10.50.0.{i % 250 + 1}",
                src_port=30000 + i,
                dst_ip=target_ip,
                dst_port=443,
                ts=t,
                conn_state="S0",
                orig_pkts=2,
                resp_pkts=0,
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.threat_class == "protocol_ddos"
        assert alert.evidence["syn_only_ratio"] >= 0.70
        assert alert.severity == "CRITICAL"

    def test_benign_web_traffic_generates_zero_alerts(self, detector):
        """
        Normal, low-rate benign web browsing flows across various clients
        must generate 0 alerts (0% False Positive Rate).
        """
        target_ip = "192.168.10.80"
        alerts = []
        t = 1725000300.0

        for i in range(100):
            # Normal user requests over 50 seconds (2 reqs/sec)
            conn = ConnTelemetryEvent(
                src_ip=f"192.168.1.{i % 20 + 10}",
                src_port=40000 + i,
                dst_ip=target_ip,
                dst_port=443 if (i % 2 == 0) else 80,
                ts=t + (i * 0.5),
                conn_state="SF",
                duration=0.15,
                orig_bytes=1500,
                resp_bytes=25000,
                orig_pkts=6,
                resp_pkts=18,
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) == 0, f"Expected 0 alerts for benign traffic, got {len(alerts)}"

    def test_cooldown_and_state_reset(self, detector):
        """Alerts must be throttled by cooldown, and reset_state() must clear host cache."""
        target_ip = "192.168.10.90"
        t = 1725000400.0

        # Trigger first alert
        first_alert = None
        for i in range(150):
            conn = ConnTelemetryEvent(
                src_ip=f"10.0.0.{i+1}",
                src_port=1000 + i,
                dst_ip=target_ip,
                dst_port=80,
                ts=t,
                conn_state="S0",
                orig_pkts=5,
            )
            alt = detector.handle_event(conn)
            if alt and not first_alert:
                first_alert = alt

        assert first_alert is not None

        # Immediate next packet during cooldown should return None
        immediate_alt = detector.handle_event(
            ConnTelemetryEvent(
                src_ip="10.0.0.200",
                src_port=9999,
                dst_ip=target_ip,
                dst_port=80,
                ts=t + 1.0,
                conn_state="S0",
                orig_pkts=5,
            )
        )
        assert immediate_alt is None

        # Reset state and test metrics
        detector.reset_state()
        assert len(detector._target_states) == 0
        metrics = detector.get_metrics()
        assert metrics["detector_id"] == "ddos_entropy"
        assert metrics["dispatched_alerts"] >= 1
