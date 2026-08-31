"""
SIH26145 - Test Suite for Detector 4: DGA & DNS Tunnelling Detector
Tests character-level BiLSTM inference, Shannon entropy calculations,
algorithmic DGA detection, DNS tunneling payload detection, NXDOMAIN sweeps,
benign traffic invariance, schema conformance, and sub-millisecond line-rate latency.
"""

import math
import time
import pytest

from src.ingestion.models import DnsTelemetryEvent, RawAlert, calculate_shannon_entropy, extract_subdomain
from src.ingestion.streaming_bus import InMemoryStreamingBus
from src.detectors.dga_tunneling import (
    DGATunnelingDetector,
    DGALSTMDetector,
    HostDnsState,
    ONNXDGAClassifier,
)


class TestDnsUnitMath:
    """Unit tests for DNS entropy and subdomain parsing helpers."""

    def test_extract_subdomain(self):
        assert extract_subdomain("xyz123.evil.corp.com") == "xyz123"
        assert extract_subdomain("mail.google.com") == "mail"
        assert extract_subdomain("google.com") == "google"
        assert extract_subdomain("") == ""

    def test_shannon_entropy_calculation(self):
        assert calculate_shannon_entropy("") == 0.0
        assert calculate_shannon_entropy("aaaaaa") == 0.0
        # High entropy random string
        ent = calculate_shannon_entropy("x8f93kdmw02")
        assert ent >= 3.2


class TestHostDnsState:
    """Unit tests for sliding 30-second window NXDOMAIN ratio tracker."""

    def test_nxdomain_ratio_computation(self):
        state = HostDnsState(src_ip="192.168.1.50", window_sec=30.0)
        t0 = 1000.0

        # Record 4 NOERROR, 6 NXDOMAIN
        for i in range(4):
            state.record_query(t0 + i, "NOERROR", f"good{i}.com", "A")
        for i in range(6):
            state.record_query(t0 + 4 + i, "NXDOMAIN", f"bad{i}.biz", "A")

        total, nx_cnt, ratio = state.record_query(t0 + 10, "NXDOMAIN", "bad_final.biz", "A")
        assert total == 11
        assert nx_cnt == 7
        assert math.isclose(ratio, 7.0 / 11.0, abs_tol=0.01)

    def test_window_eviction(self):
        state = HostDnsState(src_ip="192.168.1.50", window_sec=30.0)
        t0 = 1000.0

        # Add query at t0
        state.record_query(t0, "NXDOMAIN", "old.biz", "A")
        assert len(state.query_history) == 1

        # Add query at t0 + 35.0 (should evict query at t0)
        total, nx_cnt, ratio = state.record_query(t0 + 35.0, "NOERROR", "new.com", "A")
        assert total == 1
        assert nx_cnt == 0
        assert ratio == 0.0


class TestONNXDGAClassifier:
    """Unit tests for Character BiLSTM DGA classifier."""

    @pytest.fixture
    def classifier(self):
        return ONNXDGAClassifier()

    def test_tokenization_dimensions(self, classifier):
        tokens = classifier.tokenize("google.com")
        assert tokens.shape == (1, 75)
        assert tokens[0, 0] != 0  # Not padded at start

    def test_algorithmic_dga_domains_high_probability(self, classifier):
        dga_domains = [
            "x8f93kdmw02.com",
            "pqzxwertyuiop.biz",
            "zklmptqwx9876.net",
            "a1b2c3d4e5f6g7.cc",
            "vbnmqlkjhgfdsaz.org",
        ]
        for domain in dga_domains:
            prob = classifier.predict_dga_prob(domain)
            assert prob >= 0.80, f"DGA domain '{domain}' received low prob: {prob}"

    def test_benign_domains_low_probability(self, classifier):
        benign_domains = [
            "google.com",
            "youtube.com",
            "wikipedia.org",
            "microsoft.com",
            "github.com",
            "amazon.com",
            "mail.google.com",
            "assets.netflix.com",
        ]
        for domain in benign_domains:
            prob = classifier.predict_dga_prob(domain)
            assert prob <= 0.25, f"Benign domain '{domain}' received high prob: {prob}"


class TestDGATunnelingDetector:
    """Scenario and integration tests for DGATunnelingDetector."""

    @pytest.fixture
    def bus(self):
        return InMemoryStreamingBus(num_partitions=4)

    @pytest.fixture
    def detector(self, bus):
        return DGATunnelingDetector(bus=bus)

    def test_dga_detection_and_raw_alert_evidence(self, detector):
        event = DnsTelemetryEvent(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="x8f93kdmw02.com",
            qtype_name="A",
            rcode_name="NOERROR",
            trans_id=12345,
            ts=1725000000.0,
        )
        alert = detector.handle_event(event)
        assert alert is not None
        assert isinstance(alert, RawAlert)
        assert alert.threat_class == "DGA_TUNNELLING"
        assert alert.confidence >= 0.80
        assert alert.detector_name == "dga_lstm"
        assert alert.source_ip == "192.168.1.100"

        # Check evidence schema
        ev = alert.evidence
        assert "domain" in ev
        assert ev["domain"] == "x8f93kdmw02.com"
        assert "onnx_dga_prob" in ev
        assert ev["onnx_dga_prob"] >= 0.80
        assert "subdomain" in ev
        assert "subdomain_entropy" in ev
        assert "is_nxdomain" in ev
        assert "qtype" in ev
        assert "nxdomain_ratio_30s" in ev
        assert "detection_subtypes" in ev
        assert "ALGORITHMIC_DGA" in ev["detection_subtypes"]

    def test_benign_domain_suppressed(self, detector):
        event = DnsTelemetryEvent(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="www.google.com",
            qtype_name="A",
            rcode_name="NOERROR",
            ts=1725000000.0,
        )
        alert = detector.handle_event(event)
        assert alert is None

    def test_dns_tunneling_txt_payload_detection(self, detector):
        # Long payload TXT record (> 45 chars)
        tunneling_query = "v1-0-0-a8f93kdmw02-b7e19f4a6c8d2e5.tunnel.attacker.com"
        event = DnsTelemetryEvent(
            src_ip="192.168.1.105",
            src_port=49152,
            dst_ip="1.1.1.1",
            dst_port=53,
            query=tunneling_query,
            qtype_name="TXT",
            rcode_name="NOERROR",
            ts=1725000000.0,
        )
        alert = detector.handle_event(event)
        assert alert is not None
        assert alert.threat_class == "DGA_TUNNELLING"
        assert "DNS_TUNNELING_PAYLOAD" in alert.evidence["detection_subtypes"]
        assert alert.mitre_technique == "T1071.004"

    def test_nxdomain_hunting_sweep_detection(self, detector):
        t0 = 1725000000.0
        src_ip = "192.168.1.110"
        alerts = []

        # Send 10 consecutive NXDOMAIN queries
        for i in range(10):
            event = DnsTelemetryEvent(
                src_ip=src_ip,
                src_port=50000 + i,
                dst_ip="8.8.8.8",
                dst_port=53,
                query=f"dga-probe-{i}-qpwkdjf.xyz",
                qtype_name="A",
                rcode_name="NXDOMAIN",
                ts=t0 + i * 0.5,
            )
            alert = detector.handle_event(event)
            if alert:
                alerts.append(alert)

        assert len(alerts) >= 1
        last_alert = alerts[-1]
        assert "NXDOMAIN_DGA_SWEEP" in last_alert.evidence["detection_subtypes"]
        assert last_alert.evidence["nxdomain_ratio_30s"] >= 0.75

    def test_alert_cooldown_mechanism(self, detector):
        event = DnsTelemetryEvent(
            src_ip="192.168.1.120",
            src_port=53000,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="x8f93kdmw02.com",
            qtype_name="A",
            rcode_name="NOERROR",
            ts=1725000000.0,
        )
        # First query triggers alert
        alert1 = detector.handle_event(event)
        assert alert1 is not None

        # Immediate second identical query is suppressed by cooldown
        event2 = event.model_copy(update={"ts": 1725000001.0})
        alert2 = detector.handle_event(event2)
        assert alert2 is None

        # Query after cooldown period triggers alert
        event3 = event.model_copy(update={"ts": 1725000006.0})
        alert3 = detector.handle_event(event3)
        assert alert3 is not None

    def test_alias_module_compatibility(self):
        alias_detector = DGALSTMDetector()
        assert isinstance(alias_detector, DGATunnelingDetector)

    def test_sub_millisecond_latency_benchmark(self, detector):
        event = DnsTelemetryEvent(
            src_ip="192.168.1.200",
            src_port=54000,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="x8f93kdmw02.com",
            qtype_name="A",
            rcode_name="NOERROR",
            ts=1725000000.0,
        )
        # Warmup
        for _ in range(50):
            detector.handle_event(event)

        # Benchmark 1,000 queries
        n_iters = 1000
        t0 = time.perf_counter()
        for _ in range(n_iters):
            detector.handle_event(event)
        elapsed_sec = time.perf_counter() - t0
        avg_latency_ms = (elapsed_sec / n_iters) * 1000.0

        assert avg_latency_ms < 1.0, f"Average latency {avg_latency_ms:.3f} ms exceeds 1.0 ms SLA"
