"""
SIH26145 - Test Suite for Detector 3: Data Exfiltration Threat Detector
Tests P² quantile estimation, asymmetric byte ratios (R_out/in), massive egress flows,
rolling ratio spikes, sustained low-and-slow transfers, and benign baseline learning.
"""

import math
import random
import time
import pytest

from src.utils.p2_quantile import P2QuantileEstimator, MultiQuantileTracker
from src.ingestion.models import ConnTelemetryEvent, RawAlert
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.exfil_ratio import (
    ExfilRatioDetector,
    HostExfiltrationState,
    is_external_ip,
)


class TestP2QuantileEstimatorUnit:
    """Unit tests verifying mathematical correctness of the P² streaming quantile algorithm."""

    def test_p2_empty_and_small_sample(self):
        """Estimator must handle empty and <5 samples gracefully."""
        est = P2QuantileEstimator(p=0.95)
        assert est.get() == 0.0
        assert est.min_val == 0.0
        assert est.max_val == 0.0

        for val in [10.0, 20.0, 30.0]:
            est.add(val)
        assert 10.0 <= est.get() <= 30.0
        assert est.min_val == 10.0
        assert est.max_val == 30.0

    def test_p2_uniform_distribution_accuracy(self):
        """P² estimate of p95 on uniform [0, 1000] should approximate 950 within 5%."""
        est = P2QuantileEstimator(p=0.95)
        random.seed(42)
        samples = [random.uniform(0.0, 1000.0) for _ in range(2000)]
        for s in samples:
            est.add(s)

        p95_estimate = est.get()
        # Sort samples to compute exact sample quantile
        sorted_samples = sorted(samples)
        exact_p95 = sorted_samples[int(0.95 * len(samples))]

        assert math.isclose(p95_estimate, exact_p95, rel_tol=0.06), (
            f"P² estimate {p95_estimate:.2f} diverged from exact {exact_p95:.2f}"
        )

    def test_multi_quantile_tracker_statistics(self):
        """MultiQuantileTracker must track p50, p90, p95, p99, mean, and variance."""
        tracker = MultiQuantileTracker(quantiles=[0.50, 0.90, 0.95, 0.99])
        for x in range(1, 101):
            tracker.add(float(x))

        assert tracker.total_count == 100
        assert math.isclose(tracker.mean, 50.5, abs_tol=0.1)
        assert tracker.p50 > 40.0
        assert tracker.p95 > 85.0
        assert tracker.p99 >= tracker.p95

        summary = tracker.summary()
        assert summary["count"] == 100
        assert "p95" in summary


class TestExfilRatioDetectorScenarios:
    """Scenario tests verifying data exfiltration detection against benign baselines."""

    @pytest.fixture
    def bus(self):
        return InMemoryStreamingBus(num_partitions=4)

    @pytest.fixture
    def detector(self, bus):
        return ExfilRatioDetector(
            ratio_spike_threshold=5.0,
            volume_threshold_bytes=5 * 1024 * 1024,
            single_flow_catastrophic_bytes=10 * 1024 * 1024,
            bus=bus,
        )

    def test_external_ip_classification(self):
        """Test private vs public external IP classification."""
        assert is_external_ip("203.0.113.88") is True
        assert is_external_ip("8.8.8.8") is True
        assert is_external_ip("192.168.1.1") is False
        assert is_external_ip("10.0.0.5") is False
        assert is_external_ip("172.16.0.1") is False
        assert is_external_ip("127.0.0.1") is False
        assert is_external_ip("0.0.0.0") is False

    def test_massive_single_flow_exfiltration(self, detector):
        """
        Massive single flow transfer (50 MB out, 10 KB in) to an external public IP
        must immediately trigger a CRITICAL data_exfiltration alert.
        """
        source_ip = "192.168.1.55"
        external_dst = "203.0.113.88"
        t0 = 1725000000.0

        conn = ConnTelemetryEvent(
            src_ip=source_ip,
            src_port=45000,
            dst_ip=external_dst,
            dst_port=443,
            service="ssl",
            orig_bytes=52428800,  # 50 MB
            resp_bytes=10240,     # 10 KB
            duration=4.5,
            ts=t0,
            uid="C_EXFIL_MASSIVE_001",
        )

        alert = detector.handle_event(conn)
        assert alert is not None
        assert alert.detector_name == "exfil_ratio"
        assert alert.threat_class == "data_exfiltration"
        assert alert.severity == "CRITICAL"
        assert alert.confidence >= 0.90
        assert alert.source_ip == source_ip
        assert alert.target_ip == external_dst
        assert alert.evidence["orig_bytes"] == 52428800
        assert alert.evidence["is_external_destination"] is True
        assert alert.evidence["ratio_out_in"] > 100.0
        assert alert.recommended_mitigation == "isolate_host"

    def test_rolling_window_ratio_spike(self, detector):
        """
        Aggregated burst of high-outbound flows within 60 seconds totaling 8 MB
        must trigger a HIGH data_exfiltration alert.
        """
        source_ip = "192.168.1.65"
        external_dst = "198.51.100.42"
        alerts = []
        t0 = 1725000100.0

        # Send 8 consecutive flows of 1 MB out, 1 KB in
        for i in range(8):
            conn = ConnTelemetryEvent(
                src_ip=source_ip,
                src_port=50000 + i,
                dst_ip=external_dst,
                dst_port=443,
                orig_bytes=1048576,  # 1 MB
                resp_bytes=1024,     # 1 KB
                ts=t0 + (i * 2.0),
                uid=f"C_EXFIL_BURST_{i}",
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.threat_class == "data_exfiltration"
        assert alert.severity == "HIGH"
        assert alert.evidence["orig_bytes"] >= 5 * 1024 * 1024
        assert alert.evidence["ratio_out_in"] >= 5.0

    def test_sustained_low_and_slow_exfiltration(self, detector):
        """
        Sustained outbound trickle across 5 minutes totaling > 10 MB to external destination
        must trigger low-and-slow exfiltration alert.
        """
        source_ip = "192.168.1.75"
        external_dst = "198.51.100.99"
        alerts = []
        t0 = 1725000200.0

        # 30 flows spaced over 300 seconds, each 400 KB out, 1 KB in (Total = 12 MB)
        for i in range(30):
            conn = ConnTelemetryEvent(
                src_ip=source_ip,
                src_port=52000 + (i % 100),
                dst_ip=external_dst,
                dst_port=443,
                orig_bytes=409600,   # 400 KB
                resp_bytes=1024,     # 1 KB
                ts=t0 + (i * 10.0),  # spans 0 .. 290s
                uid=f"C_EXFIL_SLOW_{i}",
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[-1]
        assert alert.threat_class == "data_exfiltration"

    def test_benign_web_browsing_invariance(self, detector):
        """
        Standard asymmetric downstream web browsing (large resp_bytes, small orig_bytes)
        must produce 0 alerts.
        """
        source_ip = "192.168.1.85"
        alerts = []
        t0 = 1725000600.0

        for i in range(50):
            conn = ConnTelemetryEvent(
                src_ip=source_ip,
                src_port=40000 + i,
                dst_ip="203.0.113.5",
                dst_port=443,
                orig_bytes=1200,      # small request
                resp_bytes=250000,    # large web page / video response
                ts=t0 + (i * 1.0),
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) == 0, f"Expected 0 alerts for normal web browsing, got {len(alerts)}"
