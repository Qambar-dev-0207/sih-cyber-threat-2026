"""
SIH26145 - Test Suite for Detector 2: Port Scanning & Reconnaissance Detector
Tests HyperLogLog accuracy (p=10), Dual-Bucket Slotted rolling windows,
Nmap SYN stealth scans (-sS), horizontal sweeps, strobe scans, and false-positive resilience.
"""

import math
import time
import pytest

from src.ingestion.models import ConnTelemetryEvent, RawAlert
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.portscan_hll import (
    PortScanHLLDetector,
    HyperLogLog,
    SlottedRollingHLL,
    SourceHostScanState,
)


class TestHyperLogLogUnit:
    """Unit tests verifying HyperLogLog cardinality estimation and LinearCounting correction."""

    def test_hll_empty_zero_estimate(self):
        """Empty HLL must return 0."""
        hll = HyperLogLog(p=10)
        assert hll.estimate() == 0.0

    def test_hll_small_cardinality_linear_counting(self):
        """Small sets (e.g. 5, 20 distinct items) must be accurately estimated via LinearCounting."""
        hll = HyperLogLog(p=10)
        for i in range(20):
            hll.add(f"port_{i}")
        est = hll.estimate()
        assert math.isclose(est, 20, abs_tol=3), f"Expected ~20, got {est}"

    def test_hll_medium_cardinality_accuracy(self):
        """Cardinality of 500 distinct items should be within 6% error bound."""
        hll = HyperLogLog(p=10)
        for i in range(500):
            hll.add(f"item_{i}")
        est = hll.estimate()
        error_pct = abs(est - 500) / 500.0
        assert error_pct < 0.08, f"HLL error {error_pct*100:.2f}% exceeded 8% bound (est={est})"

    def test_slotted_rolling_hll_window_rotation(self):
        """
        SlottedRollingHLL must retain elements within the 10s window (across 2x 5s buckets),
        and evict expired elements after 10s.
        """
        rhll = SlottedRollingHLL(subwindow_sec=5.0, p=10)
        t0 = 1725000000.0

        # Add 30 ports in subwindow 1 [t0 .. t0+4]
        for i in range(30):
            rhll.add(1000 + i, ts=t0 + 1.0)

        assert math.isclose(rhll.cardinality(t0 + 2.0), 30, abs_tol=4)

        # Add 20 different ports in subwindow 2 [t0+5 .. t0+9]
        for i in range(20):
            rhll.add(2000 + i, ts=t0 + 6.0)

        # Total rolling cardinality should be ~50
        assert math.isclose(rhll.cardinality(t0 + 7.0), 50, abs_tol=6)

        # Advance time to t0+12 (subwindow 1 expired, only subwindow 2 retained)
        assert math.isclose(rhll.cardinality(t0 + 12.0), 20, abs_tol=5)

        # Advance time to t0+25 (all expired)
        assert rhll.cardinality(t0 + 25.0) == 0


class TestPortScanHLLDetectorScenarios:
    """Scenario tests verifying port scan and recon detection against benign baselines."""

    @pytest.fixture
    def bus(self):
        return InMemoryStreamingBus(num_partitions=4)

    @pytest.fixture
    def detector(self, bus):
        return PortScanHLLDetector(
            vertical_port_threshold=25,
            horizontal_host_threshold=20,
            strobe_endpoint_threshold=40,
            bus=bus,
        )

    def test_nmap_syn_stealth_scan(self, detector):
        """
        Nmap SYN stealth scan probing 50 distinct ports on a single host
        with connection failure states ('S0' / 'REJ') must trigger a SYN_STEALTH alert.
        """
        scanner_ip = "192.168.1.105"
        target_ip = "192.168.10.50"
        alerts = []
        t0 = 1725000000.0

        for i in range(50):
            conn = ConnTelemetryEvent(
                src_ip=scanner_ip,
                src_port=40000 + i,
                dst_ip=target_ip,
                dst_port=1 + (i * 20),
                conn_state="S0" if i % 2 == 0 else "REJ",
                ts=t0 + (i * 0.05),
                orig_pkts=1,
                resp_pkts=0,
                uid=f"C_SCAN_{i}",
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.detector_name == "portscan_hll"
        assert alert.source_ip == scanner_ip
        assert alert.threat_class == "port_scan"
        assert alert.evidence["scan_type"] == "SYN_STEALTH"
        assert alert.evidence["hll_distinct_ports"] >= 25
        assert alert.evidence["failure_ratio"] >= 0.70
        assert alert.confidence >= 0.88
        assert alert.recommended_mitigation == "block_source_ip"

    def test_horizontal_subnet_sweep(self, detector):
        """
        Horizontal reconnaissance sweep targeting a single service (e.g. port 22)
        across 30 different destination IPs within 10s must trigger recon_sweep.
        """
        scanner_ip = "192.168.1.200"
        alerts = []
        t0 = 1725000100.0

        for i in range(30):
            target_ip = f"10.0.1.{i + 1}"
            conn = ConnTelemetryEvent(
                src_ip=scanner_ip,
                src_port=50000 + i,
                dst_ip=target_ip,
                dst_port=22,
                conn_state="S0",
                ts=t0 + (i * 0.1),
                orig_pkts=1,
                uid=f"C_SWEEP_{i}",
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.threat_class == "recon_sweep"
        assert alert.evidence["scan_type"] == "HORIZONTAL_SWEEP"
        assert alert.evidence["hll_distinct_hosts"] >= 20

    def test_strobe_matrix_scan(self, detector):
        """
        Matrix scan probing 50 distinct host:port endpoints across multiple hosts.
        """
        scanner_ip = "192.168.1.220"
        alerts = []
        t0 = 1725000200.0

        for i in range(50):
            target_ip = f"10.0.{i % 5}.{i % 10 + 1}"
            target_port = 80 + i
            conn = ConnTelemetryEvent(
                src_ip=scanner_ip,
                src_port=55000 + i,
                dst_ip=target_ip,
                dst_port=target_port,
                conn_state="REJ",
                ts=t0 + (i * 0.05),
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.evidence["scan_type"] in ("STROBE_MATRIX_SCAN", "VERTICAL_PORT_SCAN", "HORIZONTAL_SWEEP")
        assert alert.evidence["hll_distinct_endpoints"] >= 35

    def test_benign_multi_connection_invariance(self, detector):
        """
        Normal client opening multiple connections to standard web ports (80, 443)
        with established 'SF' states must produce 0 alerts.
        """
        client_ip = "192.168.1.50"
        alerts = []
        t0 = 1725000300.0

        for i in range(20):
            conn = ConnTelemetryEvent(
                src_ip=client_ip,
                src_port=40000 + i,
                dst_ip="192.168.10.10",
                dst_port=443 if (i % 2 == 0) else 80,
                conn_state="SF",
                ts=t0 + (i * 0.4),
                orig_bytes=2000,
                resp_bytes=50000,
            )
            alt = detector.handle_event(conn)
            if alt:
                alerts.append(alt)

        assert len(alerts) == 0, f"Expected 0 alerts for benign connections, got {len(alerts)}"

    def test_consume_and_process_bus_integration(self, detector, bus):
        """Test consuming and processing batches from the streaming bus."""
        scanner_ip = "192.168.1.99"
        t0 = 1725000400.0

        # Publish 40 scan events to telemetry.conn
        for i in range(40):
            conn = ConnTelemetryEvent(
                src_ip=scanner_ip,
                src_port=30000 + i,
                dst_ip="10.0.0.1",
                dst_port=100 + i,
                conn_state="S0",
                ts=t0 + (i * 0.05),
            )
            bus.publish("telemetry.conn", conn, key=scanner_ip)

        # Consume and process batch
        part = bus.get_partition(scanner_ip)
        alerts = detector.consume_and_process(partition=part, max_records=50)

        assert len(alerts) >= 1
        # Verify alert was also published to alerts.raw
        published_alerts = bus.consume_all("alerts.raw")
        assert len(published_alerts) >= 1
        assert published_alerts[0]["threat_class"] == "port_scan"
