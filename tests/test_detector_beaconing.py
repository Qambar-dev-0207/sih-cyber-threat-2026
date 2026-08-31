"""
SIH26145 - Test Suite for Detector 6: Streaming C2 Beaconing Threat Detector
Tests circular delta-T buffers, Coefficient of Variation (CV = sigma/mu),
MAD dispersion, jitter resilience, Poisson browsing rejection, sub-second burst filtering,
multi-host tracking, and sub-millisecond line-rate latency.
"""

import math
import random
import time
import pytest

from src.ingestion.models import ConnTelemetryEvent, RawAlert
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.c2_beaconing import (
    C2BeaconingDetector,
    C2BeaconDetector,
    CircularDeltaTBuffer,
    FlowBeaconState,
    compute_interarrival_stats,
)


class TestInterarrivalStatsMath:
    """Unit tests for statistical dispersion formulas."""

    def test_zero_variance_perfect_beacon(self):
        intervals = [10.0] * 20
        mean_val, std_dev, cv, median_val, mad_val, jitter_ratio = compute_interarrival_stats(intervals)
        assert mean_val == 10.0
        assert std_dev == 0.0
        assert cv == 0.0
        assert median_val == 10.0
        assert mad_val == 0.0
        assert jitter_ratio == 0.0

    def test_jittered_beacon_cv(self):
        # 10s intervals with +/- 0.5s jitter (5% jitter)
        random.seed(42)
        intervals = [10.0 + random.uniform(-0.5, 0.5) for _ in range(25)]
        mean_val, std_dev, cv, median_val, mad_val, jitter_ratio = compute_interarrival_stats(intervals)
        assert math.isclose(mean_val, 10.0, abs_tol=0.2)
        assert cv < 0.05
        assert jitter_ratio < 0.05

    def test_mad_outlier_resilience(self):
        # 20 regular 10s intervals + 2 massive delay spikes (dropped packet/retransmission)
        intervals = [10.0] * 20 + [85.0, 120.0]
        mean_val, std_dev, cv, median_val, mad_val, jitter_ratio = compute_interarrival_stats(intervals)
        assert median_val == 10.0
        assert mad_val == 0.0  # MAD remains immune to < 50% outliers

    def test_poisson_random_traffic_rejection(self):
        # Exponential distribution representing Poisson arrival process (CV ~= 1.0)
        random.seed(42)
        intervals = [random.expovariate(1.0 / 15.0) for _ in range(30)]
        mean_val, std_dev, cv, median_val, mad_val, jitter_ratio = compute_interarrival_stats(intervals)
        assert cv >= 0.50, f"Poisson traffic produced suspiciously low CV: {cv}"

    def test_insufficient_samples(self):
        assert compute_interarrival_stats([]) == (0.0, 0.0, 1.0, 0.0, 0.0, 1.0)
        assert compute_interarrival_stats([5.0]) == (0.0, 0.0, 1.0, 0.0, 0.0, 1.0)


class TestCircularDeltaTBuffer:
    """Unit tests for fixed-capacity circular buffer."""

    def test_buffer_capacity_eviction(self):
        buf = CircularDeltaTBuffer(maxlen=5)
        for i in range(10):
            buf.add(float(i))
        assert len(buf) == 5
        assert buf.get_intervals() == [5.0, 6.0, 7.0, 8.0, 9.0]


class TestC2BeaconingDetector:
    """Scenario and integration tests for C2BeaconingDetector."""

    @pytest.fixture
    def bus(self):
        return InMemoryStreamingBus(num_partitions=4)

    @pytest.fixture
    def detector(self, bus):
        return C2BeaconingDetector(bus=bus, min_samples=15, cv_threshold=0.15)

    def test_fixed_interval_beacon_detection(self, detector):
        src_ip = "192.168.1.100"
        dst_ip = "198.51.100.25"
        dst_port = 8443
        t0 = 1725000000.0
        interval = 30.0

        alert = None
        # Send 16 events (15 intervals)
        for i in range(16):
            event = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=49152 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                duration=0.05,
                orig_bytes=120,
                resp_bytes=240,
                ts=t0 + i * interval,
                uid=f"Cbeacon{i:04d}",
            )
            res = detector.handle_event(event)
            if res:
                alert = res

        assert alert is not None
        assert isinstance(alert, RawAlert)
        assert alert.threat_class == "C2_BEACONING"
        assert alert.confidence >= 0.90
        assert alert.detector_name == "c2_beacon"
        assert alert.source_ip == src_ip
        assert alert.target_ip == dst_ip
        assert alert.target_port == dst_port

        # Check evidence schema
        ev = alert.evidence
        assert "cv" in ev
        assert ev["cv"] < 0.01
        assert "mean_interval_sec" in ev
        assert math.isclose(ev["mean_interval_sec"], 30.0, abs_tol=0.1)
        assert "median_interval_sec" in ev
        assert "mad_sec" in ev
        assert "sample_count" in ev
        assert ev["sample_count"] >= 15
        assert "jitter_ratio" in ev

    def test_jittered_c2_beacon_detection(self, detector):
        src_ip = "192.168.1.105"
        dst_ip = "203.0.113.80"
        dst_port = 443
        t0 = 1725000000.0
        base_interval = 60.0

        random.seed(42)
        curr_ts = t0
        alert = None

        for i in range(20):
            event = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=50000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=curr_ts,
            )
            res = detector.handle_event(event)
            if res:
                alert = res
            jitter = random.uniform(-4.0, 4.0)  # ~6.6% jitter
            curr_ts += base_interval + jitter

        assert alert is not None
        assert alert.evidence["cv"] < 0.15

    def test_insufficient_samples_suppressed(self, detector):
        src_ip = "192.168.1.110"
        dst_ip = "198.51.100.30"
        dst_port = 443
        t0 = 1725000000.0

        # Send only 10 events (9 intervals < 15 min_samples)
        for i in range(10):
            event = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=51000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                ts=t0 + i * 20.0,
            )
            alert = detector.handle_event(event)
            assert alert is None

    def test_sporadic_human_browsing_suppressed(self, detector):
        src_ip = "192.168.1.115"
        dst_ip = "142.250.190.46"
        dst_port = 443
        t0 = 1725000000.0

        random.seed(42)
        curr_ts = t0
        for i in range(50):
            event = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=52000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                ts=curr_ts,
            )
            alert = detector.handle_event(event)
            assert alert is None
            # Random browsing delay between 1s and 120s
            curr_ts += random.uniform(1.0, 120.0)

    def test_rapid_burst_transfer_filtering(self, detector):
        src_ip = "192.168.1.120"
        dst_ip = "198.51.100.40"
        dst_port = 80
        t0 = 1725000000.0

        # Rapid chunked file transfer with 5ms spacing
        for i in range(30):
            event = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=53000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                ts=t0 + i * 0.005,
            )
            alert = detector.handle_event(event)
            # Burst transfer with mean < 0.5s must not trigger C2 beaconing
            assert alert is None

    def test_multi_host_concurrent_tracking(self, detector):
        t0 = 1725000000.0
        # Host A beacons at 15s, Host B is random
        host_a = "10.0.0.1"
        host_b = "10.0.0.2"
        dst = "198.51.100.50"

        random.seed(42)
        alerts_a = []
        alerts_b = []

        for i in range(20):
            # Host A event
            ev_a = ConnTelemetryEvent(
                src_ip=host_a,
                src_port=40000 + i,
                dst_ip=dst,
                dst_port=443,
                ts=t0 + i * 15.0,
            )
            res_a = detector.handle_event(ev_a)
            if res_a:
                alerts_a.append(res_a)

            # Host B event
            ev_b = ConnTelemetryEvent(
                src_ip=host_b,
                src_port=50000 + i,
                dst_ip=dst,
                dst_port=443,
                ts=t0 + random.uniform(0.1, 500.0),
            )
            res_b = detector.handle_event(ev_b)
            if res_b:
                alerts_b.append(res_b)

        assert len(alerts_a) >= 1
        assert len(alerts_b) == 0

    def test_alias_module_compatibility(self):
        alias_detector = C2BeaconDetector()
        assert isinstance(alias_detector, C2BeaconingDetector)

    def test_sub_millisecond_line_rate_latency(self, detector):
        event = ConnTelemetryEvent(
            src_ip="192.168.1.200",
            src_port=54000,
            dst_ip="198.51.100.88",
            dst_port=443,
            ts=1725000000.0,
        )
        # Warmup
        for _ in range(50):
            detector.handle_event(event)

        # Benchmark 5,000 events
        n_iters = 5000
        t0 = time.perf_counter()
        for i in range(n_iters):
            ev = ConnTelemetryEvent(
                src_ip="192.168.1.200",
                src_port=54000,
                dst_ip="198.51.100.88",
                dst_port=443,
                ts=1725000000.0 + i * 10.0,
            )
            detector.handle_event(ev)
        elapsed_sec = time.perf_counter() - t0
        avg_latency_us = (elapsed_sec / n_iters) * 1_000_000.0

        assert avg_latency_us < 100.0, f"Average latency {avg_latency_us:.2f} us exceeds 100 us SLA"
