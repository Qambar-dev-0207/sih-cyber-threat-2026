"""
SIH26145 - Empirical Adversarial Stress Test Suite for Detector 6 & Multi-Detector Pipeline
Evaluates:
1. Jitter Boundary Analysis: 0%, 5%, 10%, 14%, 20%, and 30% jitter.
2. Sample Threshold Boundary: 10, 14, 15, and 25 intervals.
3. Outlier Resilience: MAD robust dispersion under network latency spikes.
4. Noise Rejection: Poisson / Exponential human browsing zero false-positive verification.
5. Line-Rate Throughput & Memory Stress: 20,000 mixed stream events profiling sub-ms latency and memory stability.
"""

import math
import random
import time
import tracemalloc
import pytest
from typing import List

from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    RawAlert,
    SslTelemetryEvent,
)
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.c2_beaconing import (
    C2BeaconingDetector,
    compute_interarrival_stats,
    FlowBeaconState,
)
from src.detectors.detector_manager import DetectorManager


class TestJitterBoundaries:
    """
    Adversarial verification of jitter boundary conditions:
    0%, 5%, 10%, 14%, 20%, and 30% jitter.
    """

    @pytest.mark.parametrize(
        "jitter_pct,expected_alert,expected_cv_max,expected_cv_min",
        [
            (0.0, True, 0.001, 0.0),        # 0% jitter: CV = 0.00
            (5.0, True, 0.05, 0.01),        # 5% jitter: theoretical CV ~ 0.0289
            (10.0, True, 0.08, 0.04),       # 10% jitter: theoretical CV ~ 0.0577
            (14.0, True, 0.10, 0.06),       # 14% jitter: theoretical CV ~ 0.0808
            (20.0, True, 0.15, 0.09),       # 20% jitter: theoretical CV ~ 0.1155 < 0.15
            (30.0, False, 0.25, 0.15),      # 30% jitter: theoretical CV ~ 0.1732 > 0.15 (Must NOT trigger)
        ],
    )
    def test_jitter_gradient_trigger_boundary(
        self, jitter_pct, expected_alert, expected_cv_max, expected_cv_min
    ):
        random.seed(2026 + int(jitter_pct))
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        src_ip = f"10.100.1.{int(jitter_pct)}"
        dst_ip = "198.51.100.99"
        dst_port = 443
        t0 = 1725000000.0
        base_interval = 20.0  # 20s beacon

        curr_ts = t0
        alert = None
        intervals: List[float] = []

        # Send 25 events (24 intervals)
        for i in range(25):
            event = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=40000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=curr_ts,
                uid=f"Cjit_{int(jitter_pct)}_{i:03d}",
            )
            res = detector.handle_event(event)
            if res:
                alert = res

            offset_factor = (-1.0 if (i % 2 == 0) else 1.0) * (((i % 5) + 1) / 5.0)
            jitter_delta = offset_factor * (jitter_pct / 100.0) * base_interval
            next_interval = max(0.5, base_interval + jitter_delta)
            intervals.append(next_interval)
            curr_ts += next_interval

        stats = compute_interarrival_stats(intervals[:24])
        actual_cv = stats[2]

        if expected_alert:
            assert alert is not None, (
                f"Jitter {jitter_pct}% (actual CV={actual_cv:.4f}) failed to trigger alert"
            )
            assert alert.evidence["cv"] < 0.15
            assert expected_cv_min <= actual_cv <= expected_cv_max
        else:
            assert alert is None, (
                f"Jitter {jitter_pct}% (actual CV={actual_cv:.4f}) triggered false alert!"
            )
            assert actual_cv >= 0.15, f"Expected CV >= 0.15 for 30% jitter, got {actual_cv}"


class TestSampleThresholdBoundaries:
    """
    Adversarial verification of minimum interval sample threshold boundaries:
    10, 14, 15, and 25 intervals.
    """

    def test_sample_threshold_exact_boundaries(self):
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        src_ip = "192.168.10.50"
        dst_ip = "203.0.113.50"
        dst_port = 8443
        t0 = 1725000000.0
        interval = 10.0

        # Step 1: Exactly 10 intervals (11 events)
        alert_10 = None
        for i in range(11):
            ev = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=30000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=t0 + i * interval,
            )
            res = detector.handle_event(ev)
            if res:
                alert_10 = res
        assert alert_10 is None, "Detector fired prematurely at 10 intervals (min_samples=15)!"

        # Step 2: Advance to 14 intervals (15 events)
        alert_14 = None
        for i in range(11, 15):
            ev = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=30000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=t0 + i * interval,
            )
            res = detector.handle_event(ev)
            if res:
                alert_14 = res
        assert alert_14 is None, "Detector fired prematurely at 14 intervals (min_samples=15)!"

        # Step 3: Exactly 15 intervals (16 events) -> MUST FIRE
        ev_15 = ConnTelemetryEvent(
            src_ip=src_ip,
            src_port=30015,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto="tcp",
            ts=t0 + 15 * interval,
        )
        alert_15 = detector.handle_event(ev_15)
        assert alert_15 is not None, "Detector failed to fire at exactly 15 intervals!"
        assert alert_15.evidence["sample_count"] == 15
        assert alert_15.evidence["cv"] == 0.0

        # Step 4: Advance to 25 intervals (26 events) -> Circular buffer capacity check
        flow = detector._flow_states[(src_ip, dst_ip, dst_port)]
        for i in range(16, 30):
            ev = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=30000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=t0 + i * interval,
            )
            detector.handle_event(ev)

        assert len(flow.intervals) == 25, f"Circular buffer exceeded N=25: {len(flow.intervals)}"


class TestOutlierResilienceMAD:
    """
    Adversarial verification of Median Absolute Deviation (MAD) dispersion
    under network latency spikes (retransmissions, temporary packet loss).
    """

    def test_mad_vs_stddev_under_latency_spikes(self):
        # 20 regular intervals (10.0s) + 1-3 severe latency spikes
        base = [10.0] * 20

        # 0 spikes
        s0 = compute_interarrival_stats(base)
        assert s0[4] == 0.0  # MAD = 0.0
        assert s0[3] == 10.0 # Median = 10.0

        # 1 spike (e.g. 90.0s TCP retransmit timeout)
        spikes_1 = base + [90.0]
        s1 = compute_interarrival_stats(spikes_1)
        assert s1[3] == 10.0  # Median remains perfectly 10.0s
        assert s1[4] == 0.0   # MAD remains perfectly 0.0s
        assert s1[1] > 15.0   # Standard deviation spiked to >15s

        # 3 spikes (e.g. 75.0s, 95.0s, 130.0s) in 23 samples (< 50% breakdown)
        spikes_3 = base + [75.0, 95.0, 130.0]
        s3 = compute_interarrival_stats(spikes_3)
        assert s3[3] == 10.0  # Median remains 10.0s
        assert s3[4] == 0.0   # MAD remains 0.0s
        assert s3[1] > 25.0   # Standard deviation heavily distorted (>25s)
        assert s3[5] == 0.0   # Jitter ratio (MAD/Median) remains 0.0

    def test_flow_state_streaming_resilience_to_spikes(self):
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        src_ip = "192.168.1.222"
        dst_ip = "198.51.100.77"
        dst_port = 443
        t0 = 1725000000.0

        # Build baseline beacon with 18 regular intervals of 15.0s
        curr_ts = t0
        for i in range(18):
            ev = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=45000 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=curr_ts,
            )
            detector.handle_event(ev)
            curr_ts += 15.0

        flow = detector._flow_states[(src_ip, dst_ip, dst_port)]
        # Inject an isolated 120s network timeout spike
        curr_ts += 120.0
        ev_spike = ConnTelemetryEvent(
            src_ip=src_ip,
            src_port=45019,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto="tcp",
            ts=curr_ts,
        )
        detector.handle_event(ev_spike)

        stats = compute_interarrival_stats(flow.intervals)
        # Median and MAD should be invariant to single spike
        assert stats[3] == 15.0  # Median interval = 15.0s
        assert stats[4] == 0.0   # MAD = 0.0s


class TestNoiseRejection:
    """
    Adversarial verification of noise rejection:
    Poisson / Exponential inter-arrival processes and simulated human browsing.
    """

    def test_poisson_exponential_zero_false_positives(self):
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        random.seed(999)
        src_ip = "192.168.1.80"
        dst_ip = "172.217.16.206"
        dst_port = 443
        t0 = 1725000000.0

        curr_ts = t0
        alerts_generated = []

        # Simulate 200 Poisson-distributed connection events (rate = 1 every 15s)
        for i in range(200):
            ev = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=50000 + (i % 10000),
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=curr_ts,
                uid=f"Cpois_{i:04d}",
            )
            res = detector.handle_event(ev)
            if res:
                alerts_generated.append(res)

            # Exponential inter-arrival time
            delta = random.expovariate(1.0 / 15.0)
            curr_ts += max(0.01, delta)

        assert len(alerts_generated) == 0, (
            f"Poisson process triggered {len(alerts_generated)} false alerts!"
        )

    def test_realistic_human_web_browsing_model(self):
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        random.seed(2026)
        src_ip = "192.168.1.85"
        dst_ip = "140.82.121.4"  # GitHub
        dst_port = 443
        t0 = 1725000000.0

        curr_ts = t0
        alerts_generated = []

        # Simulate 10 browsing sessions with rapid page asset bursts followed by think time
        for session in range(10):
            # Page load burst: 5-15 requests spaced 0.05s - 1.5s
            burst_len = random.randint(5, 15)
            for b in range(burst_len):
                ev = ConnTelemetryEvent(
                    src_ip=src_ip,
                    src_port=random.randint(49152, 65535),
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    proto="tcp",
                    ts=curr_ts,
                )
                res = detector.handle_event(ev)
                if res:
                    alerts_generated.append(res)
                curr_ts += random.uniform(0.05, 1.5)

            # Human reading/think time: 10s to 120s
            curr_ts += random.uniform(10.0, 120.0)

        assert len(alerts_generated) == 0, (
            f"Human browsing traffic triggered {len(alerts_generated)} false alerts!"
        )


class TestLineRateThroughputAndMemoryStress:
    """
    Stress testing at line-rate: 20,000 mixed stream events through DetectorManager
    and C2BeaconingDetector, verifying sub-millisecond execution and memory safety.
    """

    def test_detector_c2_20k_events_latency_and_memory(self):
        detector = C2BeaconingDetector(
            min_samples=15,
            cv_threshold=0.15,
            max_tracked_hosts=10_000,
        )
        random.seed(42)
        n_events = 20_000
        t0 = 1725000000.0

        # Generate 20,000 events across 500 distinct source hosts
        events = []
        for i in range(n_events):
            host_id = i % 500
            src_ip = f"10.0.{host_id // 256}.{host_id % 256}"
            dst_ip = f"198.51.100.{(host_id * 3) % 254 + 1}"
            dst_port = 443 if (i % 2 == 0) else 8080
            # Mix periodic beacons and random traffic
            if host_id < 10:
                # Periodic beacon
                ts = t0 + (i // 500) * 15.0
            else:
                # Random traffic
                ts = t0 + random.uniform(0.1, 10000.0)

            ev = ConnTelemetryEvent(
                src_ip=src_ip,
                src_port=40000 + (i % 20000),
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="tcp",
                ts=ts,
                uid=f"C20k_{i:06d}",
            )
            events.append(ev)

        # Warmup
        for ev in events[:200]:
            detector.handle_event(ev)

        # Memory & Latency Profiling
        tracemalloc.start()
        mem_start, _ = tracemalloc.get_traced_memory()

        t_start = time.perf_counter()
        alerts_count = 0
        for ev in events:
            res = detector.handle_event(ev)
            if res:
                alerts_count += 1
        t_elapsed = time.perf_counter() - t_start

        mem_current, mem_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        avg_latency_us = (t_elapsed / n_events) * 1_000_000.0
        avg_latency_ms = avg_latency_us / 1000.0
        throughput_eps = n_events / t_elapsed
        mem_growth_kb = (mem_peak - mem_start) / 1024.0

        print(f"\\n[Detector 6 Stress Benchmark]")
        print(f"Total Events: {n_events}")
        print(f"Total Elapsed: {t_elapsed:.4f} s")
        print(f"Average Latency: {avg_latency_us:.2f} µs ({avg_latency_ms:.4f} ms)")
        print(f"Throughput: {throughput_eps:.0f} events/sec")
        print(f"Peak Memory Growth: {mem_growth_kb:.2f} KB")
        print(f"Alerts Triggered: {alerts_count}")

        # SLA Assertions
        assert avg_latency_ms < 1.0, f"Average latency {avg_latency_ms:.4f} ms exceeds 1.0 ms SLA!"
        assert avg_latency_us < 200.0, f"Average latency {avg_latency_us:.2f} µs exceeds 200 µs line rate!"
        assert throughput_eps >= 10_000, f"Throughput {throughput_eps:.0f} EPS is too low!"
        assert mem_growth_kb < 100_000, f"Memory growth {mem_growth_kb:.2f} KB suggests memory leak!"
        assert alerts_count > 0, "Periodic beacon hosts failed to generate any alerts!"

    def test_multi_detector_pipeline_concurrent_stream_stress(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        manager = DetectorManager(bus=bus)
        random.seed(777)
        n_events = 20_000
        t0 = 1725000000.0

        # Generate mixed telemetry: 50% Conn, 25% DNS, 25% SSL
        mixed_events = []
        for i in range(n_events):
            event_type = i % 4
            src_ip = f"192.168.1.{(i % 250) + 1}"
            ts = t0 + i * 0.1

            if event_type in (0, 1):  # Conn
                ev = ConnTelemetryEvent(
                    src_ip=src_ip,
                    src_port=30000 + (i % 30000),
                    dst_ip="198.51.100.1",
                    dst_port=443,
                    proto="tcp",
                    ts=ts,
                    uid=f"Cmix_{i:06d}",
                )
            elif event_type == 2:  # DNS
                ev = DnsTelemetryEvent(
                    src_ip=src_ip,
                    src_port=40000 + (i % 20000),
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    trans_id=i % 65535,
                    query=f"host{i%100}.example.com",
                    qtype_name="A",
                    rcode_name="NOERROR",
                    ts=ts,
                    uid=f"Dmix_{i:06d}",
                )
            else:  # SSL
                ev = SslTelemetryEvent(
                    src_ip=src_ip,
                    src_port=50000 + (i % 15000),
                    dst_ip="198.51.100.2",
                    dst_port=443,
                    version="TLSv13",
                    cipher="TLS_AES_128_GCM_SHA256",
                    server_name="example.com",
                    ja4="t13d1516h2_8daaf6152771_000000000000",
                    ts=ts,
                    uid=f"Smix_{i:06d}",
                )
            mixed_events.append(ev)

        # Warmup
        for ev in mixed_events[:100]:
            manager.process_event(ev)

        tracemalloc.start()
        mem_start, _ = tracemalloc.get_traced_memory()

        t_start = time.perf_counter()
        total_alerts = 0
        for ev in mixed_events:
            alerts = manager.process_event(ev)
            total_alerts += len(alerts)
        t_elapsed = time.perf_counter() - t_start

        mem_current, mem_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        avg_latency_us = (t_elapsed / n_events) * 1_000_000.0
        avg_latency_ms = avg_latency_us / 1000.0
        throughput_eps = n_events / t_elapsed
        mem_growth_kb = (mem_peak - mem_start) / 1024.0

        print(f"\\n[Multi-Detector Pipeline Stress Benchmark]")
        print(f"Total Mixed Events: {n_events}")
        print(f"Total Elapsed: {t_elapsed:.4f} s")
        print(f"Average Pipeline Latency: {avg_latency_us:.2f} µs ({avg_latency_ms:.4f} ms)")
        print(f"Pipeline Throughput: {throughput_eps:.0f} events/sec")
        print(f"Peak Memory Growth: {mem_growth_kb:.2f} KB")
        print(f"Alerts Dispatched: {total_alerts}")

        # Multi-detector pipeline must also maintain sub-millisecond per event
        assert avg_latency_us < 1000.0, f"Average pipeline latency {avg_latency_us:.2f} µs exceeded 1000 µs (1.0 ms) SLA!"
        assert throughput_eps >= 1500, f"Pipeline throughput {throughput_eps:.0f} EPS is too low!"
        assert mem_growth_kb < 150_000, f"Pipeline memory growth {mem_growth_kb:.2f} KB indicates leak!"
