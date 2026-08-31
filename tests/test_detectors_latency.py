"""
SIH26145 - Latency & Performance Verification Suite
Benchmarks per-event processing latency across all 6 streaming threat detectors:
- Detector 1: Volumetric & Protocol DDoS (Differential Entropy & EWMA)
- Detector 2: Port Scanning & Recon (Slotted Rolling HLL)
- Detector 3: Data Exfiltration (Asymmetric Ratio & P² Quantile)
- Detector 4: DGA & DNS Tunnelling (Char-BiLSTM & NXDOMAIN Tracking)
- Detector 5: Encrypted Malware (JA4 Threat Intel & TLS Anomaly Scoring)
- Detector 6: C2 Beaconing (Delta-T Circular Buffer & Statistical Dispersion)

Verifies < 1.0 ms SLA per event under high-throughput streaming execution.
"""

import time
import pytest

from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
)
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors import (
    DDoSEntropyDetector,
    PortScanHLLDetector,
    ExfilRatioDetector,
    DGATunnelingDetector,
    EncryptedMalwareDetector,
    C2BeaconingDetector,
)


@pytest.fixture
def bus():
    return InMemoryStreamingBus(num_partitions=4)


def test_detector_1_ddos_latency(bus):
    detector = DDoSEntropyDetector(bus=bus)
    event = ConnTelemetryEvent(
        src_ip="192.168.1.10",
        src_port=12345,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        orig_bytes=64,
        resp_bytes=0,
        history="S",
    )
    for _ in range(50):
        detector.handle_event(event)

    n_iters = 5000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        detector.handle_event(event)
    avg_latency_us = ((time.perf_counter() - t0) / n_iters) * 1_000_000.0

    assert avg_latency_us < 500.0, f"Detector 1 avg latency {avg_latency_us:.2f} us exceeds SLA"


def test_detector_2_portscan_latency(bus):
    detector = PortScanHLLDetector(bus=bus)
    event = ConnTelemetryEvent(
        src_ip="192.168.1.10",
        src_port=12345,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        conn_state="REJ",
    )
    for _ in range(50):
        detector.handle_event(event)

    n_iters = 5000
    t0 = time.perf_counter()
    for i in range(n_iters):
        ev = ConnTelemetryEvent(
            src_ip="192.168.1.10",
            src_port=12345,
            dst_ip="10.0.0.1",
            dst_port=80 + (i % 100),
            proto="tcp",
            conn_state="REJ",
        )
        detector.handle_event(ev)
    avg_latency_us = ((time.perf_counter() - t0) / n_iters) * 1_000_000.0

    assert avg_latency_us < 500.0, f"Detector 2 avg latency {avg_latency_us:.2f} us exceeds SLA"


def test_detector_3_exfil_latency(bus):
    detector = ExfilRatioDetector(bus=bus)
    event = ConnTelemetryEvent(
        src_ip="192.168.1.10",
        src_port=12345,
        dst_ip="93.184.216.34",
        dst_port=443,
        proto="tcp",
        orig_bytes=5000,
        resp_bytes=200,
    )
    for _ in range(50):
        detector.handle_event(event)

    n_iters = 5000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        detector.handle_event(event)
    avg_latency_us = ((time.perf_counter() - t0) / n_iters) * 1_000_000.0

    assert avg_latency_us < 500.0, f"Detector 3 avg latency {avg_latency_us:.2f} us exceeds SLA"


def test_detector_4_dga_latency(bus):
    detector = DGATunnelingDetector(bus=bus)
    event = DnsTelemetryEvent(
        src_ip="192.168.1.10",
        src_port=53000,
        dst_ip="8.8.8.8",
        dst_port=53,
        query="x8f93kdmw02.com",
        qtype_name="A",
        rcode_name="NOERROR",
    )
    for _ in range(50):
        detector.handle_event(event)

    n_iters = 1000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        detector.handle_event(event)
    avg_latency_us = ((time.perf_counter() - t0) / n_iters) * 1_000_000.0

    assert avg_latency_us < 1000.0, f"Detector 4 avg latency {avg_latency_us:.2f} us exceeds 1000 us (1 ms) SLA"


def test_detector_5_encrypted_malware_latency(bus):
    detector = EncryptedMalwareDetector(bus=bus)
    event = SslTelemetryEvent(
        src_ip="192.168.1.10",
        src_port=49200,
        dst_ip="198.51.100.22",
        dst_port=443,
        version="TLSv13",
        ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        server_name="cdn-edge-update.com",
    )
    for _ in range(50):
        detector.handle_event(event)

    n_iters = 2000
    t0 = time.perf_counter()
    for _ in range(n_iters):
        detector.handle_event(event)
    avg_latency_us = ((time.perf_counter() - t0) / n_iters) * 1_000_000.0

    assert avg_latency_us < 200.0, f"Detector 5 avg latency {avg_latency_us:.2f} us exceeds 200 us SLA"


def test_detector_6_c2_beaconing_latency(bus):
    detector = C2BeaconingDetector(bus=bus)
    event = ConnTelemetryEvent(
        src_ip="192.168.1.10",
        src_port=49152,
        dst_ip="198.51.100.25",
        dst_port=8443,
        proto="tcp",
        ts=1725000000.0,
    )
    for _ in range(50):
        detector.handle_event(event)

    n_iters = 5000
    t0 = time.perf_counter()
    for i in range(n_iters):
        ev = ConnTelemetryEvent(
            src_ip="192.168.1.10",
            src_port=49152,
            dst_ip="198.51.100.25",
            dst_port=8443,
            proto="tcp",
            ts=1725000000.0 + i * 15.0,
        )
        detector.handle_event(ev)
    avg_latency_us = ((time.perf_counter() - t0) / n_iters) * 1_000_000.0

    assert avg_latency_us < 100.0, f"Detector 6 avg latency {avg_latency_us:.2f} us exceeds 100 us SLA"
