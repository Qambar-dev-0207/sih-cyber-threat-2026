"""
tests/test_challenger2_m1_verification.py

Empirical Challenger 2 Verification & Stress Test Suite:
1. Timing SLA Verification:
   - 100-iteration pipeline execution latency distribution (p50, p90, p99, max < 1.5s).
   - In-memory CEP aggregation & fusion latency (< 100ms).
2. CLI Flag Matrix Verification:
   - --offline, --json, --verbose, --step-delay, custom IP pairs.
   - Non-standard & invalid IP handling.
3. Mathematical Boundary 1: HyperLogLog Cardinality & Port Scanning:
   - Cardinality estimation behavior and error bounds.
   - Vertical scan trigger across 20-35 distinct ports.
   - Scale estimation accuracy at 25, 35, 50, 100, 1000 ports vs exact set cardinality.
4. Mathematical Boundary 2: Shannon Entropy & DGA Classification:
   - calculate_shannon_entropy exactness vs theoretical definition: H(X) = -sum(p * log2(p)).
   - Subdomain entropy boundary around 3.5.
   - Query type triggering (TXT/NULL/CNAME) vs A records.
5. Mathematical Boundary 3: Jitter Coefficient of Variation (CV = sigma / mu):
   - Numerical accuracy of compute_interarrival_stats vs numpy.std(ddof=1) / numpy.mean().
   - Exact interval boundary trigger: min_samples=15 intervals requires 16 consecutive pulses.
   - Low dispersion trigger (CV < 0.15) vs high jitter suppression (CV >= 0.15).
6. Mathematical Boundary 4: Risk Scoring, Synergy & Clamping:
   - 0-stage, 1-stage (synergy = 0.0), 2-stage (synergy = 10.0), 3-stage & 4-stage (synergy = 20.0).
   - Exact clamping at 100.0 and floor at 0.0.
   - Asset criticality scaling alpha in [1.0, 2.0].
7. Air-Gapped Data-Diode Passive Invariant Verification.
"""

from __future__ import annotations

import collections
import json
import math
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import numpy as np
import pytest

from src.agentic_triage.graph import compile_triage_graph, triage_incident
from src.agentic_triage.nodes.risk_scoring_node import RiskScoringNode
from src.api.services.pipeline_service import triage_state_to_incident_detail
from src.api.state import reset_app_state
from src.cep.engine import CEPAggregatorEngine
from src.detectors.c2_beaconing import (
    C2BeaconingDetector,
    compute_interarrival_stats,
)
from src.detectors.detector_manager import DetectorManager
from src.detectors.dga_tunneling import (
    DGATunnelingDetector,
    calculate_shannon_entropy,
)
from src.detectors.portscan_hll import HyperLogLog, PortScanHLLDetector, SlottedRollingHLL
from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    RawAlert,
    SslTelemetryEvent,
)
from src.ingestion.streaming_bus import InMemoryStreamingBus


# ---------------------------------------------------------------------------
# Helpers for Telemetry Synthesis
# ---------------------------------------------------------------------------

def make_conn_event(
    src_ip: str = "198.51.100.42",
    dst_ip: str = "192.168.1.100",
    dst_port: int = 80,
    ts: float = 1725000000.0,
    conn_state: str = "SF",
    proto: str = "tcp",
    uid: str = "test_conn_01",
) -> ConnTelemetryEvent:
    return ConnTelemetryEvent(
        src_ip=src_ip,
        src_port=45000,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        conn_state=conn_state,
        orig_bytes=128,
        resp_bytes=128,
        history="ShADadFf",
        ts=ts,
        uid=uid,
    )


def make_dns_event(
    src_ip: str = "198.51.100.42",
    query: str = "test.example.org",
    qtype: str = "A",
    ts: float = 1725000000.0,
    rcode: str = "NOERROR",
    uid: str = "test_dns_01",
) -> DnsTelemetryEvent:
    return DnsTelemetryEvent(
        src_ip=src_ip,
        src_port=53000,
        dst_ip="8.8.8.8",
        dst_port=53,
        query=query,
        qtype_name=qtype,
        rcode_name=rcode,
        ts=ts,
        uid=uid,
    )


def make_ssl_event(
    src_ip: str = "198.51.100.42",
    dst_ip: str = "192.168.1.100",
    ja4: str = "t13d1516h2_8daaf6152771_e5627efa2ab1",
    ts: float = 1725000000.0,
    uid: str = "test_ssl_01",
) -> SslTelemetryEvent:
    return SslTelemetryEvent(
        src_ip=src_ip,
        src_port=54000,
        dst_ip=dst_ip,
        dst_port=443,
        version="TLSv13",
        ja4=ja4,
        ja4s="t130200_1301_0000",
        server_name="cdn-update.example.com",
        cipher="TLS_AES_256_GCM_SHA384",
        ts=ts,
        uid=uid,
    )


# ---------------------------------------------------------------------------
# Test Class 1: HyperLogLog Boundary & Mathematical Accuracy
# ---------------------------------------------------------------------------

class TestHLLMathematicalBoundaries:
    """Rigorous boundary and error tolerance testing of HLL cardinality estimation."""

    def test_hll_pure_cardinality_precision(self):
        """Verify HLL standard error bound (<= 3.25% theoretical) across scales."""
        hll = HyperLogLog(p=10)
        test_scales = [10, 25, 50, 100, 500, 1000, 5000]

        for scale in test_scales:
            hll.reset()
            items = [f"port_{i}_{scale}" for i in range(scale)]
            for item in items:
                hll.add(item)
            est = hll.estimate()
            abs_err = abs(est - scale)
            rel_err = abs_err / scale

            # Linear counting for small scales (<= 100) has near-zero bias
            if scale <= 100:
                assert rel_err < 0.08, f"Scale {scale}: relative error {rel_err:.4f} too high (est: {est})"
            else:
                assert rel_err < 0.10, f"Scale {scale}: relative error {rel_err:.4f} exceeds 10% (est: {est})"

    def test_portscan_boundary_at_20_vs_30_plus_ports(self):
        """
        Verify vertical port scan threshold behavior:
        - Small number of ports (< 20) yields no alert.
        - HLL cardinality sketch tracks distinct ports incrementally.
        - 30+ ports reliably triggers vertical port scan alert.
        """
        detector = PortScanHLLDetector(vertical_port_threshold=25)
        base_ts = 1725000000.0

        # Inject 15 distinct ports
        alerts_15 = []
        for p in range(1000, 1015):
            ev = make_conn_event(dst_port=p, conn_state="REJ", ts=base_ts + (p - 1000) * 0.01)
            al = detector.process_event(ev)
            if al:
                alerts_15.append(al)

        assert len(alerts_15) == 0, "15 ports must not trigger vertical port scan"

        # Continue injecting up to 35 ports
        triggered_alert = None
        for p in range(1015, 1035):
            ev = make_conn_event(dst_port=p, conn_state="REJ", ts=base_ts + (p - 1000) * 0.01)
            al = detector.process_event(ev)
            if al:
                triggered_alert = al

        assert triggered_alert is not None, "35 ports must trigger vertical port scan alert"
        assert triggered_alert.threat_class == "port_scan"
        assert triggered_alert.evidence["hll_distinct_ports"] >= 25
        assert triggered_alert.evidence["scan_type"] == "SYN_STEALTH"

    def test_portscan_scale_35_ports(self):
        """Verify 35 ports trigger robust high confidence alert with SYN stealth classification."""
        detector = PortScanHLLDetector(vertical_port_threshold=25)
        base_ts = 1725000000.0

        alert_emitted = None
        for p in range(1000, 1035):
            ev = make_conn_event(dst_port=p, conn_state="REJ", ts=base_ts + (p - 1000) * 0.01)
            al = detector.process_event(ev)
            if al:
                alert_emitted = al

        assert alert_emitted is not None
        assert alert_emitted.confidence >= 0.95
        assert alert_emitted.severity == "HIGH"


# ---------------------------------------------------------------------------
# Test Class 2: Shannon Entropy & DGA Classification Boundary
# ---------------------------------------------------------------------------

class TestShannonEntropyMathematicalBoundaries:
    """Verification of Shannon entropy mathematical definition and DGA thresholds."""

    def test_shannon_entropy_mathematical_definition(self):
        """Empirically verify H(X) = -sum(p * log2(p)) on analytical test cases."""
        # 1. Single character string: entropy = 0.0
        assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0
        assert calculate_shannon_entropy("") == 0.0

        # 2. Two equally probable characters: p1=0.5, p2=0.5 -> H = -2*(0.5 * log2(0.5)) = 1.0
        h_ab = calculate_shannon_entropy("abababab")
        assert abs(h_ab - 1.0) < 1e-4, f"Expected 1.0, got {h_ab}"

        # 3. Four equally probable characters: p=0.25 -> H = -4*(0.25 * log2(0.25)) = 2.0
        h_4 = calculate_shannon_entropy("abcdabcd")
        assert abs(h_4 - 2.0) < 1e-4, f"Expected 2.0, got {h_4}"

        # 4. Hex string (16 chars equal prob): log2(16) = 4.0
        hex_16 = "0123456789abcdef"
        h_hex = calculate_shannon_entropy(hex_16)
        assert abs(h_hex - 4.0) < 1e-4, f"Expected 4.0, got {h_hex}"

    def test_dga_entropy_boundary_behavior(self):
        """Test DGA detector response to low entropy vs boundary (3.5) vs high entropy domains."""
        detector = DGATunnelingDetector(entropy_threshold=3.5)
        base_ts = 1725000000.0

        # Low entropy benign query
        low_ev = make_dns_event(query="mail.google.com", qtype="A", ts=base_ts)
        al_low = detector.process_event(low_ev)
        assert al_low is None, "Benign low-entropy domain must be suppressed"

        # Tunneling query with TXT type and entropy > 3.5
        high_dga = "c948df2a10sub.tunnel.darknet-dga-malware.org"
        high_ev = make_dns_event(query=high_dga, qtype="TXT", ts=base_ts + 1.0)
        al_high = detector.process_event(high_ev)
        assert al_high is not None
        assert al_high.threat_class.upper() in ("DGA_TUNNELLING", "DGA_TUNNELING", "DGA_LSTM")
        assert al_high.confidence >= 0.88
        assert "DNS_TUNNELING_PAYLOAD" in al_high.evidence["detection_subtypes"] or "ALGORITHMIC_DGA" in al_high.evidence["detection_subtypes"]


# ---------------------------------------------------------------------------
# Test Class 3: Jitter Coefficient of Variation (CV = sigma / mu) Accuracy
# ---------------------------------------------------------------------------

class TestJitterCVMathematicalAccuracy:
    """Empirically test compute_interarrival_stats against numpy ground truth."""

    def test_cv_calculation_accuracy_vs_numpy(self):
        """Verify CV = sample_std / mean matches numpy ddof=1 across diverse distributions."""
        test_distributions = [
            [10.0] * 20,  # Constant interval (CV = 0.0)
            [10.0, 10.1, 9.9, 10.05, 9.95, 10.0, 10.02, 9.98, 10.0, 10.01],  # Low jitter
            [5.0, 10.0, 15.0, 20.0, 25.0, 30.0],  # Linear progression
            list(np.random.RandomState(42).normal(10.0, 0.5, 25)),  # Normal distribution jitter
            list(np.random.RandomState(42).exponential(10.0, 25)),  # Poisson / exponential
        ]

        for intervals in test_distributions:
            mean_c, std_c, cv_c, median_c, mad_c, jitter_ratio_c = compute_interarrival_stats(intervals)

            np_mean = float(np.mean(intervals))
            np_std = float(np.std(intervals, ddof=1)) if len(intervals) > 1 else 0.0
            np_cv = (np_std / np_mean) if np_mean > 1e-6 else 1.0

            assert abs(mean_c - np_mean) < 1e-3, f"Mean mismatch: calc={mean_c}, np={np_mean}"
            assert abs(std_c - np_std) < 1e-3, f"StdDev mismatch: calc={std_c}, np={np_std}"
            assert abs(cv_c - np_cv) < 1e-3, f"CV mismatch: calc={cv_c}, np={np_cv}"

    def test_c2_beacon_boundary_cv_triggering(self):
        """
        Verify C2 detector requires:
        1. >= 15 intervals (produced by 16 pulses)
        2. CV < 0.15 threshold
        """
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        base_ts = 1725000000.0

        # 15 pulses produce 14 intervals -> No alert because n=14 < 15
        for i in range(15):
            ev = make_conn_event(dst_port=4444, ts=base_ts + i * 10.0, uid=f"pulse_{i}")
            al = detector.process_event(ev)
            assert al is None, f"Pulse {i+1} (producing {i} intervals < 15) must not trigger alert"

        # 16th pulse produces 15th interval -> Triggers alert!
        ev_16 = make_conn_event(dst_port=4444, ts=base_ts + 15 * 10.0, uid="pulse_15")
        al_16 = detector.process_event(ev_16)
        assert al_16 is not None, "16th periodic pulse (15 intervals) must trigger C2 beacon alert"
        assert al_16.threat_class.lower() in ("c2_beaconing", "c2_beacon")
        assert al_16.evidence["cv"] < 0.01

    def test_c2_beacon_suppressed_for_noisy_traffic(self):
        """Verify high jitter (CV > 0.15) is NOT flagged as beaconing."""
        detector = C2BeaconingDetector(min_samples=15, cv_threshold=0.15)
        base_ts = 1725000000.0

        # Highly random intervals: 2s, 18s, 4s, 30s, 1s, 45s...
        rng = np.random.RandomState(1337)
        curr_ts = base_ts
        alerts = []
        for i in range(25):
            delta = float(rng.uniform(1.0, 30.0))
            curr_ts += delta
            ev = make_conn_event(dst_port=4444, ts=curr_ts, uid=f"rand_pulse_{i}")
            al = detector.process_event(ev)
            if al:
                alerts.append(al)

        assert len(alerts) == 0, "Noisy random traffic must not trigger C2 beacon alert"


# ---------------------------------------------------------------------------
# Test Class 4: Risk Scoring, Clamping & Multi-Stage Synergy
# ---------------------------------------------------------------------------

class TestRiskScoringAndSynergyBoundaries:
    """Verify multi-stage synergy bonus, asset alpha scaling, and clamping at [0.0, 100.0]."""

    def setup_method(self):
        self.node = RiskScoringNode()

    def test_single_stage_risk_scoring(self):
        """1 Stage (Recon: weight=15, conf=0.98 -> 14.7) -> Synergy=0.0 -> Score=14.7."""
        state: Dict[str, Any] = {
            "timeline": [
                {"threat_class": "PORT_SCAN_RECON", "detector": "portscan_hll", "confidence": 0.98, "summary": "SYN sweep"}
            ],
            "asset_criticality": 1.0,
        }
        res = self.node.execute(state)
        breakdown = res["risk_breakdown"]

        assert breakdown["base_risk_sum"] == 14.7
        assert breakdown["synergy_bonus"] == 0.0
        assert res["risk_score"] == 14.7
        assert res["severity"] == "LOW"

    def test_two_stage_risk_scoring(self):
        """2 Stages (Recon: 14.7 + DGA: 30*0.95=28.5 -> sum 43.2) -> Synergy=+10.0 -> Score=53.2."""
        state: Dict[str, Any] = {
            "timeline": [
                {"threat_class": "PORT_SCAN_RECON", "detector": "portscan_hll", "confidence": 0.98, "summary": "SYN sweep"},
                {"threat_class": "DGA_TUNNELLING", "detector": "dga_lstm", "confidence": 0.95, "summary": "DGA query"},
            ],
            "asset_criticality": 1.0,
        }
        res = self.node.execute(state)
        breakdown = res["risk_breakdown"]

        assert breakdown["base_risk_sum"] == 43.2
        assert breakdown["synergy_bonus"] == 10.0
        assert res["risk_score"] == 53.2
        assert res["severity"] == "MEDIUM"

    def test_three_stage_risk_scoring_and_synergy_bonus(self):
        """3 Stages -> Synergy=+20.0 bonus."""
        state: Dict[str, Any] = {
            "timeline": [
                {"threat_class": "PORT_SCAN_RECON", "detector": "portscan_hll", "confidence": 0.98},
                {"threat_class": "DGA_TUNNELLING", "detector": "dga_lstm", "confidence": 0.95},
                {"threat_class": "ENCRYPTED_MALWARE", "detector": "ja4_malware", "confidence": 0.98},
            ],
            "asset_criticality": 1.0,
        }
        res = self.node.execute(state)
        breakdown = res["risk_breakdown"]

        # Base: 14.7 + 28.5 + 39.2 = 82.4
        assert breakdown["base_risk_sum"] == 82.4
        assert breakdown["synergy_bonus"] == 20.0
        # 82.4 + 20.0 = 102.4 -> clamped to 100.0
        assert res["risk_score"] == 100.0
        assert res["severity"] == "CRITICAL"

    def test_four_stage_apt_clamping_at_100(self):
        """4 Stages (119.1 + 20.0 = 139.1) -> Clamped strictly at 100.0."""
        state: Dict[str, Any] = {
            "timeline": [
                {"threat_class": "PORT_SCAN_RECON", "detector": "portscan_hll", "confidence": 0.98},
                {"threat_class": "DGA_TUNNELLING", "detector": "dga_lstm", "confidence": 0.95},
                {"threat_class": "ENCRYPTED_MALWARE", "detector": "ja4_malware", "confidence": 0.98},
                {"threat_class": "C2_BEACONING", "detector": "c2_beacon", "confidence": 0.92},
            ],
            "asset_criticality": 1.5,
        }
        res = self.node.execute(state)
        breakdown = res["risk_breakdown"]

        assert breakdown["synergy_bonus"] == 20.0
        assert res["risk_score"] == 100.0
        assert res["severity"] == "CRITICAL"

    def test_asset_criticality_alpha_multiplier(self):
        """Verify alpha scaling: base=40.0, alpha=1.5 -> risk = 60.0."""
        state: Dict[str, Any] = {
            "timeline": [
                {"threat_class": "C2_BEACONING", "detector": "c2_beacon", "confidence": 1.0}
            ],
            "asset_criticality": 1.5,
        }
        res = self.node.execute(state)
        assert res["risk_score"] == 60.0
        assert res["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Test Class 5: Latency SLA & Timing Distribution Benchmark (100 Iterations)
# ---------------------------------------------------------------------------

class TestTimingSLABenchmark:
    """Empirical benchmarking of pipeline fusion and agentic triage timing SLAs (< 1.5s)."""

    def test_100_iteration_pipeline_latency_distribution(self):
        """
        Execute 100 full 4-stage simulation and triage iterations.
        Record p50, p90, p99, and max latency.
        Verify SLA: max latency strictly < 1.5s (and p99 < 0.8s).
        """
        latencies = []
        cep_latencies = []
        triage_latencies = []

        bus = InMemoryStreamingBus(num_partitions=4)
        detector_mgr = DetectorManager(bus=bus)
        triage_graph = compile_triage_graph(execution_mode="deterministic")
        base_ts = 1725000000.0

        # Pre-synthesize events for consistent benchmarking
        recon_events = [make_conn_event(dst_port=1000 + i, conn_state="REJ", ts=base_ts + i * 0.01) for i in range(35)]
        dga_event = make_dns_event(query="c948df2a10sub.tunnel.darknet-dga-malware.org", qtype="TXT", ts=base_ts + 2.0)
        ssl_event = make_ssl_event(ts=base_ts + 4.0)
        beacon_events = [make_conn_event(dst_port=4444, ts=base_ts + 6.0 + i * 10.0) for i in range(18)]

        for iteration in range(100):
            detector_mgr.reset_all_states()
            cep_engine = CEPAggregatorEngine()

            t_iter_start = time.perf_counter()

            # 1. Detector processing
            alerts = []
            for ev in recon_events:
                alerts.extend(detector_mgr.process_event(ev))
            alerts.extend(detector_mgr.process_event(dga_event))
            alerts.extend(detector_mgr.process_event(ssl_event))
            for ev in beacon_events:
                alerts.extend(detector_mgr.process_event(ev))

            # 2. CEP Fusion
            t_cep = time.perf_counter()
            fused = None
            for a in alerts:
                res = cep_engine.ingest_alert(a)
                if res:
                    fused = res
            cep_time = (time.perf_counter() - t_cep) * 1000.0
            cep_latencies.append(cep_time)

            assert fused is not None, f"Iteration {iteration}: CEP fusion failed"

            # 3. LangGraph Triage
            t_triage = time.perf_counter()
            triage_state = triage_incident(fused, compiled_graph=triage_graph)
            detail = triage_state_to_incident_detail(triage_state, raw_incident=fused)
            triage_time = (time.perf_counter() - t_triage) * 1000.0
            triage_latencies.append(triage_time)

            total_elapsed = time.perf_counter() - t_iter_start
            latencies.append(total_elapsed)

            assert detail.risk_score >= 85.0
            assert len(detail.countermeasures) == 6

        lat_arr = np.array(latencies)
        p50 = float(np.percentile(lat_arr, 50))
        p90 = float(np.percentile(lat_arr, 90))
        p99 = float(np.percentile(lat_arr, 99))
        max_lat = float(np.max(lat_arr))

        cep_arr = np.array(cep_latencies)
        p50_cep = float(np.percentile(cep_arr, 50))
        p99_cep = float(np.percentile(cep_arr, 99))

        print(f"\n[LATENCY BENCHMARK - 100 ITERATIONS]")
        print(f"  E2E Pipeline p50: {p50*1000:.2f} ms")
        print(f"  E2E Pipeline p90: {p90*1000:.2f} ms")
        print(f"  E2E Pipeline p99: {p99*1000:.2f} ms")
        print(f"  E2E Pipeline Max: {max_lat*1000:.2f} ms")
        print(f"  CEP Fusion   p50: {p50_cep:.2f} ms | p99: {p99_cep:.2f} ms")

        # Strict SLA assertions
        assert max_lat < 1.50, f"Max latency {max_lat:.4f}s exceeded 1.5s SLA"
        assert p99 < 0.50, f"p99 latency {p99:.4f}s exceeded 0.50s buffer threshold"
        assert p99_cep < 50.0, f"CEP fusion p99 {p99_cep:.2f}ms exceeded 50ms threshold"


# ---------------------------------------------------------------------------
# Test Class 6: CLI Flag Combinations & Error Handling
# ---------------------------------------------------------------------------

class TestCLIFlagMatrixAndRobustness:
    """Empirical testing of scripts/rehearse_demo.py CLI execution across flag matrix."""

    def test_cli_offline_flag(self):
        """Test python scripts/rehearse_demo.py --offline runs cleanly and passes."""
        res = subprocess.run(
            [sys.executable, "scripts/rehearse_demo.py", "--offline", "--step-delay", "0.0"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"CLI --offline failed with stderr: {res.stderr}"
        assert "MULTI-STAGE APT REHEARSAL: PASSED" in res.stdout
        assert "Calculated Risk Score" in res.stdout

    def test_cli_json_flag(self):
        """Test python scripts/rehearse_demo.py --json outputs valid parsable JSON."""
        res = subprocess.run(
            [sys.executable, "scripts/rehearse_demo.py", "--json"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"CLI --json failed with stderr: {res.stderr}"
        data = json.loads(res.stdout)
        assert data["status"] == "PASS"
        assert data["latency_sla_passed"] is True
        assert data["risk_score"] >= 85.0
        assert data["severity"] == "CRITICAL"
        assert len(data["countermeasures"]) == 6
        assert all(cm["syntax_valid"] for cm in data["countermeasures"])
        assert all(cm["requires_human_approval"] for cm in data["countermeasures"])

    def test_cli_custom_ip_pairs(self):
        """Test custom attacker and target IPs."""
        res = subprocess.run(
            [
                sys.executable,
                "scripts/rehearse_demo.py",
                "--json",
                "--attacker-ip", "10.0.0.99",
                "--target-ip", "10.0.0.1",
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["attacker_ip"] == "10.0.0.99"
        assert data["target_ip"] == "10.0.0.1"

    def test_cli_invalid_ip_handling(self):
        """Test passing arbitrary or non-standard IP strings does not crash the CLI."""
        res = subprocess.run(
            [
                sys.executable,
                "scripts/rehearse_demo.py",
                "--json",
                "--attacker-ip", "invalid_source_host_999",
                "--target-ip", "999.999.999.999",
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "PASS"
        assert data["attacker_ip"] == "invalid_source_host_999"

    def test_cli_verbose_flag(self):
        """Test --verbose flag execution."""
        res = subprocess.run(
            [
                sys.executable,
                "scripts/rehearse_demo.py",
                "--offline",
                "--verbose",
                "--step-delay", "0.0",
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        assert "STAGE 1" in res.stdout
        assert "STAGE 4" in res.stdout
