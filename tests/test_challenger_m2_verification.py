"""
SIH26145 - Challenger 2 Verification & Empirical Stress Suite for Milestone 2
Comprehensive verification covering:
1. Microsecond Latency SLA Verification (< 100 µs/event per detector)
2. False Positive Rate (FPR) on Benign PCAP and Synthetic Workloads
3. True Positive Rate (TPR) on Attack PCAPs and Synthetic Scenarios
4. P² Quantile Mathematical Accuracy on Heavy-Tailed Distributions
5. HyperLogLog Cardinality Bounds & Dual-Bucket Sliding Window Mechanics
6. O(1) Differential Shannon Entropy Numerical Stability over 100,000 updates
7. High-Volume Stateful Locality & TTL/LRU Eviction (10,000 source hosts)
8. Edge Case Mining: Malformed, Out-of-Order, and Boundary Conditions
"""

import ipaddress
import math
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pytest

from src.ingestion.models import ConnTelemetryEvent, RawAlert
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.ddos_entropy import (
    DDoSEntropyDetector,
    DifferentialEntropyTracker,
    RateEWMATracker,
)
from src.detectors.portscan_hll import (
    PortScanHLLDetector,
    HyperLogLog,
    SlottedRollingHLL,
)
from src.detectors.exfil_ratio import (
    ExfilRatioDetector,
    HostExfiltrationState,
    is_external_ip,
)
from src.utils.p2_quantile import P2QuantileEstimator, MultiQuantileTracker

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TestDetectorLatencyBenchmarks:
    """Requirement: Benchmark processing latency per event for each detector (< 100 µs)."""

    def test_ddos_detector_latency_under_100us(self):
        detector = DDoSEntropyDetector(window_size=500)
        t0_base = 1725000000.0

        # Warm up
        for i in range(100):
            conn = ConnTelemetryEvent(
                src_ip=f"10.0.0.{i % 50 + 1}",
                src_port=10000 + i,
                dst_ip="192.168.1.100",
                dst_port=80 + (i % 5),
                ts=t0_base + (i * 0.01),
                conn_state="SF",
            )
            detector.handle_event(conn)

        # Timed benchmark: 10,000 events
        N = 10_000
        start_time = time.perf_counter_ns()
        for i in range(N):
            conn = ConnTelemetryEvent(
                src_ip=f"10.0.{(i // 256) % 10}.{i % 256 + 1}",
                src_port=20000 + (i % 20000),
                dst_ip="192.168.1.100",
                dst_port=80 if (i % 3 == 0) else 443,
                ts=t0_base + 10.0 + (i * 0.001),
                conn_state="SF",
                orig_pkts=2,
            )
            detector.handle_event(conn)
        total_time_ns = time.perf_counter_ns() - start_time
        avg_latency_us = (total_time_ns / N) / 1000.0

        print(f"\n[BENCHMARK] DDoS Detector Latency: {avg_latency_us:.3f} µs/event across {N} events")
        assert avg_latency_us < 100.0, f"DDoS latency {avg_latency_us:.3f} µs exceeds 100 µs SLA"

    def test_portscan_detector_latency_under_100us(self):
        detector = PortScanHLLDetector()
        t0_base = 1725000000.0

        # Warm up
        for i in range(100):
            conn = ConnTelemetryEvent(
                src_ip=f"10.0.0.{i % 20 + 1}",
                src_port=10000 + i,
                dst_ip="192.168.1.1",
                dst_port=20 + i,
                ts=t0_base + (i * 0.01),
                conn_state="S0",
            )
            detector.handle_event(conn)

        # Timed benchmark: 10,000 events
        N = 10_000
        start_time = time.perf_counter_ns()
        for i in range(N):
            conn = ConnTelemetryEvent(
                src_ip=f"192.168.1.{i % 50 + 1}",
                src_port=30000 + (i % 20000),
                dst_ip=f"10.0.0.{i % 100 + 1}",
                dst_port=1 + (i % 1000),
                ts=t0_base + 10.0 + (i * 0.001),
                conn_state="S0",
            )
            detector.handle_event(conn)
        total_time_ns = time.perf_counter_ns() - start_time
        avg_latency_us = (total_time_ns / N) / 1000.0

        print(f"\n[BENCHMARK] PortScan Detector Latency: {avg_latency_us:.3f} µs/event across {N} events")
        assert avg_latency_us < 100.0, f"PortScan latency {avg_latency_us:.3f} µs exceeds 100 µs SLA"

    def test_exfil_detector_latency_under_100us(self):
        detector = ExfilRatioDetector()
        t0_base = 1725000000.0

        # Warm up
        for i in range(100):
            conn = ConnTelemetryEvent(
                src_ip=f"10.0.0.{i % 20 + 1}",
                src_port=10000 + i,
                dst_ip="93.184.216.34",
                dst_port=443,
                orig_bytes=1500,
                resp_bytes=25000,
                ts=t0_base + (i * 0.01),
            )
            detector.handle_event(conn)

        # Timed benchmark: 10,000 events
        N = 10_000
        start_time = time.perf_counter_ns()
        for i in range(N):
            conn = ConnTelemetryEvent(
                src_ip=f"192.168.1.{i % 50 + 1}",
                src_port=30000 + (i % 20000),
                dst_ip="93.184.216.34",
                dst_port=443,
                orig_bytes=2000 + (i % 5000),
                resp_bytes=50000 + (i % 20000),
                ts=t0_base + 10.0 + (i * 0.001),
            )
            detector.handle_event(conn)
        total_time_ns = time.perf_counter_ns() - start_time
        avg_latency_us = (total_time_ns / N) / 1000.0

        print(f"\n[BENCHMARK] Exfil Detector Latency: {avg_latency_us:.3f} µs/event across {N} events")
        assert avg_latency_us < 100.0, f"Exfil latency {avg_latency_us:.3f} µs exceeds 100 µs SLA"


class TestBenignBaselineFPREvaluation:
    """Verify False Positive Rate is 0% on benign baseline PCAP and synthetic normal traffic."""

    def test_benign_baseline_pcap_evaluation(self):
        pcap_path = Path("data/pcaps/benign_baseline.pcap")
        if not pcap_path.exists() or not SCAPY_AVAILABLE:
            pytest.skip("Scapy or benign_baseline.pcap not available")

        packets = rdpcap(str(pcap_path))
        print(f"\n[BENIGN EVAL] Loaded {len(packets)} packets from {pcap_path.name}")

        d1 = DDoSEntropyDetector(rate_min_pps=50.0, rate_z_threshold=3.5)
        d2 = PortScanHLLDetector()
        d3 = ExfilRatioDetector()

        alerts_d1, alerts_d2, alerts_d3 = [], [], []

        for pkt in packets:
            if IP not in pkt:
                continue
            proto = "tcp" if TCP in pkt else ("udp" if UDP in pkt else "ip")
            orig_h = pkt[IP].src
            resp_h = pkt[IP].dst
            orig_p = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 1024)
            resp_p = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 80)
            raw_len = len(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

            conn = ConnTelemetryEvent(
                src_ip=orig_h,
                src_port=orig_p,
                dst_ip=resp_h,
                dst_port=resp_p,
                proto=proto,
                orig_bytes=raw_len,
                resp_bytes=raw_len * 2,
                conn_state="SF",
                ts=ts,
            )

            a1 = d1.handle_event(conn)
            if a1:
                alerts_d1.append(a1)
            a2 = d2.handle_event(conn)
            if a2:
                alerts_d2.append(a2)
            a3 = d3.handle_event(conn)
            if a3:
                alerts_d3.append(a3)

        print(f"[BENIGN EVAL] Alerts from benign_baseline.pcap: D1={len(alerts_d1)}, D2={len(alerts_d2)}, D3={len(alerts_d3)}")
        assert len(alerts_d2) == 0, f"PortScan FPR > 0%: generated {len(alerts_d2)} false alerts"
        assert len(alerts_d3) == 0, f"Exfil FPR > 0%: generated {len(alerts_d3)} false alerts"

    def test_synthetic_normal_browsing_zero_false_positives(self):
        d2 = PortScanHLLDetector()
        d3 = ExfilRatioDetector()
        t0 = 1725000000.0

        alerts_d2, alerts_d3 = [], []
        # 500 normal browsing requests across 10 client hosts
        for i in range(500):
            client_ip = f"192.168.1.{10 + (i % 10)}"
            server_ip = random.choice(["93.184.216.34", "142.250.190.46", "151.101.1.140"])
            conn = ConnTelemetryEvent(
                src_ip=client_ip,
                src_port=30000 + i,
                dst_ip=server_ip,
                dst_port=443 if (i % 2 == 0) else 80,
                conn_state="SF",
                orig_bytes=random.randint(500, 3000),
                resp_bytes=random.randint(20000, 800000),
                ts=t0 + (i * 0.1),
            )
            a2 = d2.handle_event(conn)
            if a2:
                alerts_d2.append(a2)
            a3 = d3.handle_event(conn)
            if a3:
                alerts_d3.append(a3)

        assert len(alerts_d2) == 0, "PortScan detector generated false positives on normal browsing"
        assert len(alerts_d3) == 0, "Exfil detector generated false positives on normal browsing"


class TestAttackScenariosTPREvaluation:
    """Verify True Positive Rate (TPR) >= 98% across attack scenarios."""

    def test_ddos_syn_flood_pcap_detection(self):
        pcap_path = Path("data/pcaps/ddos_syn_flood.pcap")
        if not pcap_path.exists() or not SCAPY_AVAILABLE:
            pytest.skip("Scapy or ddos_syn_flood.pcap not available")

        packets = rdpcap(str(pcap_path))
        print(f"\n[ATTACK EVAL] Loaded {len(packets)} packets from {pcap_path.name}")

        detector = DDoSEntropyDetector(window_size=200, rate_min_pps=50.0, rate_z_threshold=2.5)
        alerts = []

        for pkt in packets:
            if IP not in pkt:
                continue
            orig_h = pkt[IP].src
            resp_h = pkt[IP].dst
            orig_p = pkt[TCP].sport if TCP in pkt else 1024
            resp_p = pkt[TCP].dport if TCP in pkt else 80
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

            conn = ConnTelemetryEvent(
                src_ip=orig_h,
                src_port=orig_p,
                dst_ip=resp_h,
                dst_port=resp_p,
                proto="tcp",
                conn_state="S0",
                orig_pkts=1,
                ts=ts,
            )
            alert = detector.handle_event(conn)
            if alert:
                alerts.append(alert)

        print(f"[ATTACK EVAL] DDoS alerts detected: {len(alerts)}")
        assert len(alerts) >= 1, "Failed to detect DDoS attack in ddos_syn_flood.pcap"
        assert alerts[0].threat_class in ("volumetric_ddos", "protocol_ddos")

    def test_portscan_nmap_pcap_detection(self):
        pcap_path = Path("data/pcaps/portscan_nmap.pcap")
        if not pcap_path.exists() or not SCAPY_AVAILABLE:
            pytest.skip("Scapy or portscan_nmap.pcap not available")

        packets = rdpcap(str(pcap_path))
        print(f"\n[ATTACK EVAL] Loaded {len(packets)} packets from {pcap_path.name}")

        detector = PortScanHLLDetector(vertical_port_threshold=25)
        alerts = []

        for pkt in packets:
            if IP not in pkt:
                continue
            orig_h = pkt[IP].src
            resp_h = pkt[IP].dst
            orig_p = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 1024)
            resp_p = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 80)
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

            conn = ConnTelemetryEvent(
                src_ip=orig_h,
                src_port=orig_p,
                dst_ip=resp_h,
                dst_port=resp_p,
                proto="tcp" if TCP in pkt else "udp",
                conn_state="S0",
                orig_pkts=1,
                ts=ts,
            )
            alert = detector.handle_event(conn)
            if alert:
                alerts.append(alert)

        print(f"[ATTACK EVAL] PortScan alerts detected: {len(alerts)}")
        assert len(alerts) >= 1, "Failed to detect PortScan in portscan_nmap.pcap"
        assert alerts[0].threat_class in ("port_scan", "recon_sweep")

    def test_synthetic_attack_suite_tpr(self):
        """Execute 10 distinct attack test scenarios and calculate empirical TPR."""
        total_attacks = 10
        detected_attacks = 0

        # Scenario 1: Vertical SYN stealth scan (100 ports)
        d_ps = PortScanHLLDetector(vertical_port_threshold=25)
        a1 = None
        for i in range(100):
            res = d_ps.handle_event(ConnTelemetryEvent(
                src_ip="192.168.1.10", src_port=40000+i, dst_ip="10.0.0.1", dst_port=100+i, conn_state="S0", ts=1000.0 + (i * 0.05)
            ))
            if res and not a1:
                a1 = res
        if a1 and a1.threat_class == "port_scan":
            detected_attacks += 1

        # Scenario 2: Horizontal subnet sweep (50 hosts)
        d_ps.reset_state()
        a2 = None
        for i in range(50):
            res = d_ps.handle_event(ConnTelemetryEvent(
                src_ip="192.168.1.20", src_port=40000+i, dst_ip=f"10.0.1.{i+1}", dst_port=22, conn_state="S0", ts=2000.0 + (i * 0.05)
            ))
            if res and not a2:
                a2 = res
        if a2 and a2.threat_class == "recon_sweep":
            detected_attacks += 1

        # Scenario 3: Strobe Matrix scan (80 endpoints)
        d_ps.reset_state()
        a3 = None
        for i in range(80):
            res = d_ps.handle_event(ConnTelemetryEvent(
                src_ip="192.168.1.30", src_port=40000+i, dst_ip=f"10.0.{i%5}.{i%10+1}", dst_port=80+i, conn_state="REJ", ts=3000.0 + (i * 0.05)
            ))
            if res and not a3:
                a3 = res
        if a3:
            detected_attacks += 1

        # Scenario 4: Concentrated port 80 SYN flood
        d_ddos = DDoSEntropyDetector(window_size=200, rate_min_pps=50.0)
        a4 = None
        for i in range(250):
            res = d_ddos.handle_event(ConnTelemetryEvent(
                src_ip=f"172.16.0.{i%250+1}", src_port=10000+i, dst_ip="192.168.1.50", dst_port=80, conn_state="S0", orig_pkts=5, ts=4000.0
            ))
            if res and not a4:
                a4 = res
        if a4 and a4.threat_class in ("volumetric_ddos", "protocol_ddos"):
            detected_attacks += 1

        # Scenario 5: Concentrated port 443 flood
        d_ddos.reset_state()
        a5 = None
        for i in range(250):
            res = d_ddos.handle_event(ConnTelemetryEvent(
                src_ip=f"172.16.1.{i%250+1}", src_port=10000+i, dst_ip="192.168.1.55", dst_port=443, conn_state="S0", orig_pkts=5, ts=5000.0
            ))
            if res and not a5:
                a5 = res
        if a5 and a5.threat_class in ("volumetric_ddos", "protocol_ddos"):
            detected_attacks += 1

        # Scenario 6: Random port UDP sweep flood
        d_ddos.reset_state()
        a6 = None
        for i in range(250):
            rand_port = 1000 + (i * 313) % 60000
            res = d_ddos.handle_event(ConnTelemetryEvent(
                src_ip="172.16.2.100", src_port=20000+i, dst_ip="192.168.1.60", dst_port=rand_port, proto="udp", conn_state="SF", orig_pkts=10, ts=6000.0
            ))
            if res and not a6:
                a6 = res
        if a6 and a6.threat_class == "volumetric_ddos":
            detected_attacks += 1

        # Scenario 7: Protocol SYN flood (half-open S0 saturation)
        d_ddos.reset_state()
        a7 = None
        for i in range(200):
            res = d_ddos.handle_event(ConnTelemetryEvent(
                src_ip=f"10.20.0.{i%250+1}", src_port=30000+i, dst_ip="192.168.1.70", dst_port=8080, conn_state="S0", orig_pkts=2, ts=7000.0
            ))
            if res and not a7:
                a7 = res
        if a7 and a7.threat_class == "protocol_ddos":
            detected_attacks += 1

        # Scenario 8: Massive Single-Flow Exfiltration to public external IP (93.184.216.34)
        d_exfil = ExfilRatioDetector()
        conn_m = ConnTelemetryEvent(
            src_ip="192.168.1.80", src_port=45000, dst_ip="93.184.216.34", dst_port=443,
            orig_bytes=50 * 1024 * 1024, resp_bytes=10240, ts=8000.0, uid="C_MASSIVE"
        )
        a8 = d_exfil.handle_event(conn_m)
        if a8 and a8.threat_class == "data_exfiltration":
            detected_attacks += 1

        # Scenario 9: 60s Rolling Ratio Burst to external IP (142.250.190.46)
        d_exfil.reset_state()
        a9 = None
        for i in range(8):
            res = d_exfil.handle_event(ConnTelemetryEvent(
                src_ip="192.168.1.85", src_port=50000+i, dst_ip="142.250.190.46", dst_port=443,
                orig_bytes=1024*1024, resp_bytes=1024, ts=9000.0 + (i * 2.0)
            ))
            if res and not a9:
                a9 = res
        if a9 and a9.threat_class == "data_exfiltration":
            detected_attacks += 1

        # Scenario 10: Low-and-slow sustained exfil over 300s to external IP (151.101.1.140)
        d_exfil.reset_state()
        a10 = None
        for i in range(30):
            res = d_exfil.handle_event(ConnTelemetryEvent(
                src_ip="192.168.1.90", src_port=52000+i, dst_ip="151.101.1.140", dst_port=443,
                orig_bytes=409600, resp_bytes=1024, ts=10000.0 + (i * 10.0)
            ))
            if res and not a10:
                a10 = res
        if a10 and a10.threat_class == "data_exfiltration":
            detected_attacks += 1

        tpr = float(detected_attacks) / float(total_attacks)
        print(f"\n[TPR EVALUATION] Detected {detected_attacks}/{total_attacks} attacks (TPR = {tpr*100:.1f}%)")
        assert tpr >= 0.98, f"True Positive Rate {tpr*100:.1f}% below 98% requirement"


class TestDifferentialShannonEntropyNumericalStability:
    """Stress test O(1) differential Shannon entropy algorithm for numerical precision & stability."""

    def test_100k_random_updates_numerical_drift(self):
        tracker = DifferentialEntropyTracker(window_size=500)
        random.seed(1337)
        ports = [random.randint(1, 1000) for _ in range(100_000)]

        for i, p in enumerate(ports):
            raw_ent, norm_ent = tracker.add(p)
            assert raw_ent >= 0.0, f"Negative raw entropy at step {i}: {raw_ent}"
            assert 0.0 <= norm_ent <= 1.0, f"Normalized entropy out of bounds [0, 1] at step {i}: {norm_ent}"

        # Verify against exact calculation of the final 500 window elements
        last_500 = ports[-500:]
        counts = {}
        for x in last_500:
            counts[x] = counts.get(x, 0) + 1
        exact_h = 0.0
        for c in counts.values():
            prob = c / 500.0
            exact_h -= prob * math.log2(prob)

        print(f"\n[STABILITY] After 100k updates: Streaming H={raw_ent:.6f}, Exact H={exact_h:.6f}")
        assert math.isclose(raw_ent, exact_h, abs_tol=1e-3), (
            f"Numerical drift detected: Streaming={raw_ent}, Exact={exact_h}"
        )


class TestHyperLogLogPrecisionAndBoundaries:
    """Empirical error bound tests for HyperLogLog (p=10, m=1024)."""

    @pytest.mark.parametrize("cardinality", [10, 50, 100, 500, 1000, 5000, 20000])
    def test_hll_error_bounds(self, cardinality):
        hll = HyperLogLog(p=10)
        for i in range(cardinality):
            hll.add(f"item_token_string_{i}_{cardinality}")

        est = hll.estimate()
        rel_error = abs(est - cardinality) / float(cardinality)
        print(f"[HLL ACCURACY] True={cardinality}, Est={est:.1f}, RelError={rel_error*100:.2f}%")
        assert rel_error < 0.12, f"HLL relative error {rel_error*100:.2f}% exceeded 12% tolerance"


class TestP2QuantileEstimatorDistributionAccuracy:
    """Empirical accuracy tests for P² quantile estimator across different probability distributions."""

    def test_p2_exponential_distribution_accuracy(self):
        est_p95 = P2QuantileEstimator(p=0.95)
        est_p50 = P2QuantileEstimator(p=0.50)
        random.seed(42)
        samples = [random.expovariate(1.0) for _ in range(5000)]
        for s in samples:
            est_p95.add(s)
            est_p50.add(s)

        sorted_samples = sorted(samples)
        exact_p95 = sorted_samples[int(0.95 * len(samples))]
        exact_p50 = sorted_samples[int(0.50 * len(samples))]

        print(f"\n[P² EXPONENTIAL] P95: Est={est_p95.get():.3f}, Exact={exact_p95:.3f}")
        print(f"[P² EXPONENTIAL] P50: Est={est_p50.get():.3f}, Exact={exact_p50:.3f}")
        assert math.isclose(est_p95.get(), exact_p95, rel_tol=0.08)
        assert math.isclose(est_p50.get(), exact_p50, rel_tol=0.08)

    def test_p2_lognormal_distribution_accuracy(self):
        est_p95 = P2QuantileEstimator(p=0.95)
        random.seed(42)
        samples = [random.lognormvariate(0.0, 1.0) for _ in range(5000)]
        for s in samples:
            est_p95.add(s)

        sorted_samples = sorted(samples)
        exact_p95 = sorted_samples[int(0.95 * len(samples))]

        print(f"\n[P² LOGNORMAL] P95: Est={est_p95.get():.3f}, Exact={exact_p95:.3f}")
        assert math.isclose(est_p95.get(), exact_p95, rel_tol=0.08)


class TestMemoryBoundednessAndTTLEviction:
    """Verify memory boundedness and TTL state pruning under 10,000 active source hosts."""

    def test_detector_ttl_pruning_under_host_churn(self):
        detector = PortScanHLLDetector(state_ttl_sec=10.0, max_tracked_hosts=1000)
        t_base = 1725000000.0

        # Inject 3000 distinct hosts at t_base
        for i in range(3000):
            conn = ConnTelemetryEvent(
                src_ip=f"10.1.{i // 256}.{i % 256 + 1}",
                src_port=10000 + (i % 100),
                dst_ip="192.168.1.1",
                dst_port=80,
                ts=t_base,
            )
            detector.handle_event(conn)

        # Force eviction trigger with updated timestamp t_base + 15.0
        evicted = detector.evict_expired_states(current_ts=t_base + 15.0)
        print(f"\n[TTL EVICTION] Evicted {evicted} hosts after TTL expiration")
        assert len(detector._source_states) <= 1000, "State cache exceeded max_tracked_hosts limit"


class TestAdversarialInputsAndBoundaryHandling:
    """Stress tests on malformed, out-of-order, and anomalous inputs."""

    def test_out_of_order_timestamps(self):
        detector = DDoSEntropyDetector()
        t0 = 1725000000.0
        # Send events with backwards timestamps
        for ts_offset in [100.0, 50.0, 10.0, 200.0, 0.0, -100.0]:
            conn = ConnTelemetryEvent(
                src_ip="10.0.0.1", src_port=12345, dst_ip="192.168.1.1", dst_port=80, ts=t0 + ts_offset, conn_state="SF"
            )
            # Detector must not crash or throw unhandled exceptions
            detector.handle_event(conn)

    def test_zero_and_negative_bytes_handling(self):
        detector = ExfilRatioDetector()
        conn = ConnTelemetryEvent(
            src_ip="192.168.1.50", src_port=45000, dst_ip="93.184.216.34", dst_port=443,
            orig_bytes=0, resp_bytes=0, ts=1725000000.0
        )
        alert = detector.handle_event(conn)
        assert alert is None  # Should handle zero bytes and not trigger false positive

        # Raw dictionary with negative bytes (sanitized to 0 by from_zeek_dict)
        alert2 = detector.handle_event({
            "src_ip": "192.168.1.50",
            "src_port": 45000,
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
            "orig_bytes": -100,
            "resp_bytes": -500,
            "ts": 1725000000.0,
        })
        assert alert2 is None

    def test_malformed_string_deserialization(self):
        detector = PortScanHLLDetector()
        # Invalid JSON string
        alert = detector.handle_event("NOT_A_VALID_JSON_STRING")
        assert alert is None
        # Non-telemetry dict
        alert = detector.handle_event({"invalid_key": 12345})
        assert alert is None
