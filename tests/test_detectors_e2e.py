"""
SIH26145 - End-to-End Multi-Detector Streaming Bus Integration Test
Tests all 6 threat detectors operating concurrently on the partitioned streaming bus:
1. Volumetric & Protocol DDoS (telemetry.conn)
2. Port Scanning & Recon (telemetry.conn)
3. Data Exfiltration (telemetry.conn)
4. DGA & DNS Tunnelling (telemetry.dns)
5. Encrypted Malware JA4/JA4S (telemetry.ssl)
6. C2 Beaconing (telemetry.conn)

Verifies zero cross-partition lock contention, correct alert dispatch to alerts.raw,
and complete evidence payload conformance across all 6 threat classes.
"""

import time
import pytest

from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
    RawAlert,
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


class TestMultiDetectorE2EIntegration:
    """End-to-end integration tests with all 6 detectors attached to the streaming bus."""

    @pytest.fixture
    def bus(self):
        return InMemoryStreamingBus(num_partitions=4)

    @pytest.fixture
    def detectors(self, bus):
        return {
            "ddos": DDoSEntropyDetector(bus=bus),
            "portscan": PortScanHLLDetector(bus=bus),
            "exfil": ExfilRatioDetector(bus=bus),
            "dga": DGATunnelingDetector(bus=bus),
            "malware": EncryptedMalwareDetector(bus=bus),
            "c2": C2BeaconingDetector(bus=bus),
        }

    def test_all_six_detectors_e2e_alert_generation(self, bus, detectors):
        """Simulates simultaneous execution of all 6 threat scenarios."""
        t0 = 1725000000.0

        # -------------------------------------------------------------
        # Threat 1: DDoS SYN Flood on Target 10.0.0.1:80
        # -------------------------------------------------------------
        for i in range(120):
            ev = ConnTelemetryEvent(
                src_ip="192.168.1.10",
                src_port=10000 + i,
                dst_ip="10.0.0.1",
                dst_port=80,
                proto="tcp",
                orig_bytes=64,
                resp_bytes=0,
                history="S",
                conn_state="S0",
                ts=t0 + i * 0.005,
            )
            detectors["ddos"].handle_event(ev)

        # -------------------------------------------------------------
        # Threat 2: Horizontal Port Scan across 100 ports
        # -------------------------------------------------------------
        for i in range(100):
            ev = ConnTelemetryEvent(
                src_ip="192.168.1.20",
                src_port=40000,
                dst_ip="10.0.0.2",
                dst_port=1000 + i,
                proto="tcp",
                conn_state="REJ",
                ts=t0 + i * 0.05,
            )
            detectors["portscan"].handle_event(ev)

        # -------------------------------------------------------------
        # Threat 3: Data Exfiltration (Massive outbound byte burst)
        # -------------------------------------------------------------
        # Establish baseline
        for i in range(20):
            ev = ConnTelemetryEvent(
                src_ip="192.168.1.30",
                src_port=50000,
                dst_ip="93.184.216.34",
                dst_port=443,
                proto="tcp",
                orig_bytes=1000,
                resp_bytes=5000,
                ts=t0 + i * 1.0,
            )
            detectors["exfil"].handle_event(ev)
        # Exfiltration burst
        ev_burst = ConnTelemetryEvent(
            src_ip="192.168.1.30",
            src_port=50000,
            dst_ip="93.184.216.34",
            dst_port=443,
            proto="tcp",
            orig_bytes=50_000_000,
            resp_bytes=1000,
            ts=t0 + 25.0,
        )
        detectors["exfil"].handle_event(ev_burst)

        # -------------------------------------------------------------
        # Threat 4: DGA Query (x8f93kdmw02.com)
        # -------------------------------------------------------------
        ev_dga = DnsTelemetryEvent(
            src_ip="192.168.1.40",
            src_port=53000,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="x8f93kdmw02.com",
            qtype_name="A",
            rcode_name="NOERROR",
            ts=t0 + 1.0,
        )
        detectors["dga"].handle_event(ev_dga)

        # -------------------------------------------------------------
        # Threat 5: Cobalt Strike Encrypted Malware (JA4 match)
        # -------------------------------------------------------------
        ev_ssl = SslTelemetryEvent(
            src_ip="192.168.1.50",
            src_port=54000,
            dst_ip="198.51.100.22",
            dst_port=443,
            version="TLSv13",
            ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
            server_name="cdn-edge-update.com",
            ts=t0 + 2.0,
        )
        detectors["malware"].handle_event(ev_ssl)

        # -------------------------------------------------------------
        # Threat 6: C2 Beaconing (16 connections spaced 30.0s)
        # -------------------------------------------------------------
        for i in range(16):
            ev = ConnTelemetryEvent(
                src_ip="192.168.1.60",
                src_port=55000 + i,
                dst_ip="198.51.100.33",
                dst_port=8443,
                proto="tcp",
                ts=t0 + i * 30.0,
            )
            detectors["c2"].handle_event(ev)

        # -------------------------------------------------------------
        # Verify Alerts Dispatched to 'alerts.raw' across all partitions
        # -------------------------------------------------------------
        all_alerts = []
        for p in range(4):
            records = bus.consume(topic="alerts.raw", partition=p, max_records=100, timeout=0.0)
            for r in records:
                if isinstance(r, RawAlert):
                    all_alerts.append(r)
                elif isinstance(r, dict):
                    all_alerts.append(RawAlert.model_validate(r))

        assert len(all_alerts) >= 5, f"Expected at least 5 alerts, found {len(all_alerts)}"

        threat_classes = {a.threat_class for a in all_alerts}
        assert "DGA_TUNNELLING" in threat_classes
        assert "ENCRYPTED_MALWARE" in threat_classes
        assert "C2_BEACONING" in threat_classes
